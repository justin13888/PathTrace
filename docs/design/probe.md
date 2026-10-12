# Probe and responder design

- requirements: REQ-PRB-001 … REQ-PRB-025, REQ-SEC-001, REQ-SEC-002
- adr: 0006, 0007, 0010, 0012
- research: R-0010 … R-0015 (Linux APIs)

The probe records everything observable about the path, in both directions, into crash-safe observation logs. It then merges them into one PTF trace. It never computes a path model while capturing: derivation runs afterwards and can be re-run.

## 1. Roles, processes, threads

`pathtrace serve` (responder, public VM) and `pathtrace probe` (initiator, laptop) share all measurement code. Inside each process:

| Thread | Job | Why separate |
|---|---|---|
| control | Noise session, reliable control messages, clock exchanges, phase orchestration (initiator drives, responder follows), feedback | Never blocked by data-path work |
| pacer | The **only** sender on UDP sockets. Executes the send schedule of every active UDP flow (light, trains, chirps, heavy, CBR, class, NAT, PMTU) and drains a queue of control/echo datagrams at least every 200 µs; sleeps until about 200 µs before the deadline, then spins; one `sendmmsg` per due batch. Records every send that fails or is skipped (§4.1) | One pacing clock, no cross-thread jitter, and OPT_ID numbering stays consistent (a single sender per socket) |
| receiver | `recvmmsg` on every UDP socket with kernel RX stamps, TOS, TTL and the socket's drop count; demultiplexes control frames (first byte `0xC1`–`0xC3`) to the control thread; drains the error queue (TX stamps, ICMP) on `POLLERR`; computes live feedback for the saturation controller | Receive timing is independent of sending |
| logger | Turns records into table chunks and appends an OBSV/CLOK/CTXS/EVNT section about once per second (`fsync`) | Disk I/O never stalls the data path |
| context (both endpoints; Wi-Fi on the initiator only) | Interface counters, UDP/softnet stack counters and egress qdisc counters at 10 Hz; nl80211 station info and clock pairs at 1 Hz; rtnetlink events | Slow syscalls kept off the data path |
| tcp | Reference flows and TCP class probes; `TCP_INFO` sampling every 10 ms on both ends | Kernel TCP blocks |

Records and events flow to the logger over one bounded `std::sync::mpsc` channel, and producers never block on it. If it is full, the record or event is counted per table; the logger writes a `channel_overflow {rows: {table: n}, events: n}` event with the new counts at its next flush and at the end. Records are never silently lost, and backpressure never stalls pacing.

## 2. Keys and pairing

- `pathtrace keygen` writes `$XDG_CONFIG_HOME/pathtrace/key` (X25519 private key, mode 0600) and prints the public key. The tool refuses private keys readable by group or other users (REQ-SEC-002).
- On the responder: `pathtrace authorize <initiator-pubkey> --name <label>` appends `<pubkey> <psk> <label>` to `authorized_keys` (0600) with a fresh 32-byte PSK. It prints a **pairing string** `pt1:<responder-pubkey>:<psk>`.
- On the initiator: `pathtrace responder add <name> <host[:port]> <pairing-string>` stores the responder in `responders.toml` (0600).
- Noise `IKpsk2_25519_ChaChaPoly_BLAKE2s` (snow). The initiator knows the responder's static key (IK). The PSK binds the session to one pairing, so a stolen initiator key alone is not enough.

## 3. Wire protocol (pt-wire), version 1

### 3.1 Transport of control messages
- UDP to responder port 4433 (`udp/high-port`).
- Handshake message 1 is padded to 1200 bytes. The responder's reply is at most 3× what it has received from an unvalidated address (REQ-PRB-004).
- After the handshake, control messages travel in Noise transport messages with an explicit 8-byte nonce (snow stateless transport), so loss and reordering do not break decryption.
- Reliability: per-message sequence numbers, cumulative acks, retransmission with RTO = max(50 ms, 3 × SRTT) capped at 1 s. Feedback and clock messages are unreliable (latest wins).
- The initiator repeats an unanswered handshake message up to 3 times, 1 s apart. The responder answers a repeat of the handshake message that opened the running session by resending the same reply (at most 3 times), so a lost reply costs one second and not the session.
- Fallback: if no handshake reply arrives within 3 s on UDP, the initiator retries over TCP 443 and then TCP 4433 (Noise over a u16-length-framed stream). UDP classes are then recorded as blocked, and the session continues with TCP-only phases (REQ-PRB-003).

### 3.2 Messages (CBOR maps, deterministic profile)
`hello {wire_major, wire_minor, tool_version, git_commit, capabilities, profile}` → `welcome {wire_major, wire_minor, session_id(u32), responder facts (os, kernel, ts support, cc), tls_cert_sha256}`; `phase {id, kind, params, start_at_offset_ns}`; `phase_done {id, status, reason?, counters}`; `feedback {flow, highest_seq, recv_count, recv_bytes, window_ns, qdelay_min_ns, qdelay_now_ns, delivery_rate_bps}`; `clock_req {t1}` → `clock_resp {t1, t2, t3}`; `nat_probe {...}`; `pmtu_ack {sizes}`; `bye {reason}`; `abort {reason, signal}` (wire minor 1, reliable, responder → initiator: the responder was stopped by a signal); `error {code, text}`.

Version rule: a major mismatch fails with a clear error naming both versions. A higher minor is accepted, and unknown keys are ignored (REQ-PRB-021).

### 3.3 Probe packets
UDP payload = 32-byte header + random padding + 8-byte tag.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version (high nibble = 1) and type (low nibble: 0 data, 1 nat-probe, 2 pmtu-probe, 3 class-probe, 4 echo) |
| 1 | 1 | flow_id |
| 2 | 2 | phase_id |
| 4 | 4 | session_id |
| 8 | 8 | seq (per flow) |
| 16 | 8 | t_intended_ns (sender CLOCK_MONOTONIC_RAW) |
| 24 | 4 | train_id |
| 28 | 2 | train_idx |
| 30 | 2 | flags (bit 0 last-of-train, bit 1 feedback-request) |

Tag = first 8 bytes of keyed BLAKE3 over everything before the tag. The key is `blake3::derive_key("pathtrace probe tag v1", noise_handshake_hash)`. Padding comes from a ChaCha stream so that packets do not compress (REQ-PRB-006). Packets with bad tags are counted (`bad` table, per second) and never logged as observations.

For `udp/443 QUIC-shaped`, the same payload is carried after a QUIC v1 header: the first packet of a flow uses a long header of type Initial, and the rest use short headers with the fixed bit set and an 8-byte DCID derived from the session (ADR 0006, `quic_shape = "header/1"`).

## 4. Clocks and timestamps (ADR 0012)

- Scheduling and intended times use CLOCK_MONOTONIC_RAW.
- Probe sockets enable `SO_TIMESTAMPING = RX_SOFTWARE | TX_SOFTWARE | TX_SCHED | SOFTWARE | OPT_ID | OPT_TSONLY`, falling back to `SO_TIMESTAMPNS` (RX only) where that fails.
- Kernel software stamps are CLOCK_REALTIME (R-0010). Each side therefore logs a **clock pair** about once per second: the minimum-width sandwich of MONO_RAW, REALTIME, MONO_RAW over 8 tries (~30 ns uncertainty). NTP slews and steps can be undone at derivation time.
- TX stamps: SND (driver, after the local qdisc) where the driver provides it, SCHED (qdisc enqueue) always on supporting kernels. Wi-Fi drivers commonly give SCHED only (R-0010). Both are logged when present, plus the user-space time just before `sendmmsg`. Hardware stamps are not used in 1.x.
- Every clock pair also reads CLOCK_BOOTTIME inside the same sandwich, so a suspend shows directly as a jump of BOOTTIME − MONO_RAW.

### 4.1 Transmit ids and failed sends (R-0015)

TX stamps are matched to transmissions by the socket's OPT_ID. The id of each datagram is set in one of two ways, recorded per socket in META (`endpoint.sockets[].tx_ids`):

| Mode | Kernel | Rule |
|---|---|---|
| `explicit` | ≥ 6.13 | Every datagram carries its id in an `SCM_TS_OPT_ID` cmsg. The pacer's counter advances on every attempt, so a failed attempt burns its own id and the join is exact. If the first send on the socket returns EINVAL (the kernel does not know the cmsg), the socket switches to `predicted` and logs `tx_id_mode` |
| `predicted` | < 6.13 | The kernel assigns ids from a per-socket counter, which the pacer predicts. Errors the kernel raises before taking an id (ENETUNREACH, EINVAL, EAFNOSUPPORT, EACCES, EDESTADDRREQ) consume none. Below 6.13 every other error is assumed to consume one; on 6.13 and later (predicted mode is then only forced, `PATHTRACE_TX_IDS=predicted`) only errors after the append stage (ENOBUFS, EPERM) do, since the kernel returns the id on append-stage errors (EAGAIN, EMSGSIZE, a pending ICMP error). A partial `sendmmsg` (errno unknown) is assumed to consume one; if the retry of that datagram then fails at once with an error that consumes none, the burn is undone (`unburned_id`) |

Each failed or skipped send is an event with the socket, flow, sequence number and the burned id (`burned_id`, null when none was consumed; `unburned_id` when the previous partial send's assumed burn was undone), so that a later merge can re-anchor predicted ids against the stamp times:
- `send_error {errno}`: the kernel reported an error for this datagram. It is not resent.
- `send_partial`: `sendmmsg` stopped at this datagram without an errno (it reports one only for the first datagram). The datagram is retried alone, so its errno becomes visible if it fails again.
- `send_eagain`: the send buffer is full. The rest of the batch is skipped and listed (`skipped: [[flow, seq], …]`); none of it gets a `tx` row.

A datagram without a `tx` row never left the host, so it is never counted as path loss. `merge` reports how many `tx`–`txts` joins are implausible in time and keeps every stamp it does not join (`txts_unmatched`: stamps that match no transmission, and repeats of a (sock, id, kind)). The time window cannot see ids that are off by one, since a neighbour's stamp is only microseconds away, so `merge` also checks ids per endpoint (`merge_checks`): `tx_unstamped_<ep>` counts `tx` rows without a SCHED stamp on sockets that have stamps, and `txts_unexplained_<ep>` counts SCHED stamp ids, from the socket's first `tx` id on, that match neither a `tx` row, a burned id nor a `raw_sent` id. A shifted id shows in both; aligned ids give 0 unexplained stamps (a lost or late stamp only adds to `tx_unstamped`).

### 4.2 Host drops (R-0015)

A packet the path delivered can still be lost inside a host. Each such place is recorded, so derivation can separate host drops from path loss:

| Where | Recorded as |
|---|---|
| Receiving socket (buffer full) | `SO_RXQ_OVFL`: the socket's cumulative drop count at the time each datagram was queued, per `rx` row (`rxq_drops`) |
| Receive stack | `netstack` table: UDP/UDP6 `InErrors`, `RcvbufErrors`, `SndbufErrors`, `InCsumErrors`; softnet backlog drops and squeezes |
| Egress qdisc | `qdisc` table: root qdisc of the egress interface (bytes, packets, qlen, backlog, drops, requeues, overlimits); its kind and `txqueuelen` in META |
| Recorder channel | `channel_overflow` events |

Receive buffers request 8 MiB with `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` (effective with CAP_NET_ADMIN), else `SO_RCVBUF`/`SO_SNDBUF`, which the kernel caps at `rmem_max`/`wmem_max`. The effective sizes of every socket are in META.
- Control-channel exchanges (`clock_req`/`clock_resp`) run five times at P0 and once per second afterwards: t1/t4 on the initiator and t2/t3 on the responder, all MONO_RAW user-space times. Each row also records the Noise nonces of the request and response datagrams, which identify them as flow 250/251 rows with kernel stamps, so derivation can use the kernel stamps instead.

## 5. What is logged (raw layer)

Per endpoint, in its observation log (`META.kind = "obslog"`, `META.role = "a" | "b"`):

| Table (section) | Rows | Columns |
|---|---|---|
| `tx` (OBSV) | every datagram sent (probes, control datagrams) | sock, flow, seq, size (IP bytes), phase, train, train_idx, tos_tx, id (OPT_ID, §4.1), tx_intended (mono), tx_user_lag (user send time minus intended, ns) |
| `txts` (OBSV) | every kernel TX timestamp from the error queue | sock, id, kind (0 SCHED, 1 SND), real |
| `rx` (OBSV) | every authenticated probe packet and control datagram received | sock, flow, seq, size, rx (real; kernel stamp, else user time), rx_src (0 kernel, 1 user), tos_rx, ttl_rx, src (index into `peer_addr` events), rxq_drops (§4.2) |
| `bad` (OBSV) | per second with a non-zero count, all flows together | t, bad_tag, unknown (wrong session), truncated |
| `tcpinfo` (OBSV) | 10 ms samples per TCP flow | flow, t (mono), optlen, tcp_info fields (fixed list) |
| `app` (OBSV) | TCP reference-flow application events | flow, t (mono), event, bytes, value |
| `exchange` (CLOK) | clock exchanges (initiator only) | t1, t2, t3, t4, req_nonce, resp_nonce |
| `pairs` (CLOK) | clock pairs | mono, real, width, boot |
| `ifstats` (CTXS) | 10 Hz | t, rx/tx bytes, packets, dropped, errors |
| `netstack` (CTXS) | 10 Hz | t, udp and udp6 in_errors, rcvbuf_errors, sndbuf_errors, in_csum_errors; softnet_dropped, softnet_squeezed (cumulative, nullable) |
| `qdisc` (CTXS) | 10 Hz | t, bytes, packets, qlen, backlog, drops, requeues, overlimits of the egress root qdisc (cumulative except qlen and backlog) |
| `wifi` (CTXS, initiator) | 1 Hz | t, freq (MHz), width, signal, beacon_signal (dBm), tx/rx bitrate (100 kbit/s), tx_retries, tx_failed, bss (hash, pii quasi) |
| EVNT | events | `handshake`, `handshake_resent`, `phase_start`, `phase_failed`, `phase_skipped`, `class_skipped`, `peer_addr`, `nat_rebind`, `addr_new`/`addr_del`/`route_*`/`link_*`, `icmp` (error-queue ICMP: sock, errno, type, code, info, offender, quoted flow and seq), `local_error`, `send_error`, `send_partial`, `send_eagain`, `raw_sent` (a datagram sent without a `tx` row, such as an echo or a handshake reply: sock, id, size), `tx_id_mode`, `tcp_probe`, `udp_reachability`, `saved_syn`, `ref_tcp`, `flow_stopped`, `flow_paused`/`flow_resumed`, `light_paused`/`light_resumed`, `budget_cap`, `channel_overflow`, `interrupted`, `session_end` |

UDP class, NAT and PMTU probes are ordinary flows in `tx`/`rx` (their echoes are logged by the endpoint that sent them). TCP class probes are `tcp_probe` events.

Control datagrams are observations too: the sender logs each sealed control datagram in `tx` as flow 250 (sent by a) or 251 (sent by b) with seq = Noise nonce, and the receiver logs it in `rx`. Every packet the probe puts on the path is therefore observed, which loss-model estimation requires (EXP-0002). Feedback runs at 50 Hz while a controlled flow arrives and at 5 Hz otherwise.

`merge` joins `tx` with `txts` by (sock, OPT_ID), which gives `tx_sched` (real) and `tx_snd_lag` (SND minus SCHED). It then joins the result with the peer's `rx` per direction, keyed by (flow, seq), to form the trace's `pkt` table. Duplicates go to `dup`, unmatched arrivals to `unmatched`, stamps that match no transmission to `txts_unmatched`, and log tables merge does not know are copied unchanged. Nothing is dropped (P1).

Source addresses are never per-row columns. Each new source tuple a receiver sees is logged once as a `peer_addr {idx, addr}` event, with the address marked `pii: id`, and rows carry `src = idx`. Rebinding is visible, and redaction stays trivial.

## 6. Phases and schedule

The profile timelines are fixed by `docs/design/probe.md` §6 tables and implemented as data, not scattered code. The light flow (50 pps, 100 B payload) and light trains (8 × MTU every 500 ms) run from P2 to the end in both directions (ADR 0010). ECN/DSCP coverage costs nothing extra: light-flow packets cycle their TOS byte through a fixed pattern (not-ECT, ECT(0), ECT(1), CE, × DSCP {0, CS1, AF41, EF}), logged per packet as `tos_tx`.

Standard profile (about 90 s of data phases):

| Phase | Duration | Content |
|---|---|---|
| P0 | ≤ 2 s | handshake, 5 clock exchanges, capabilities |
| P1 | ≤ 5 s | reachability of every class × family (UDP: 3 class probes echoed; TCP: connect, plus a TLS handshake on 443), SYN as seen by the responder (`TCP_SAVED_SYN`) |
| P2 | 10 s | quiet: light flow and trains only |
| P3 | 5 s | chirps: 20-packet trains with exponentially shrinking gaps, alternating direction every 250 ms → capacity estimate per direction |
| P4 | ≤ 10 s | saturate a→b: ramp 0.5× → 2× the estimate over 2 s, then hold a standing queue, then stop and watch the drain for 1 s |
| P5 | ≤ 10 s | saturate b→a, same |
| P6 | ≤ 5 s | saturate both directions |
| P7 | ≤ 3 s per class | short saturation on udp/443 opaque and QUIC-shaped (UDP); TCP classes covered by P8 |
| P8 | about 20 s | reference flows: TCP bulk each direction (≤ 5 s or the byte budget), TCP request/response 1 KiB × up to 200, UDP CBR 2 Mbit/s 5 s each direction |
| background | whole session | NAT binding timeouts (15, 30, 60 s; deep adds 120, 300), PMTU ladder in both directions (`PMTUDISC_PROBE` + ICMP), ECN/DSCP via the TOS cycle |

**PMTU ladder** (non-adaptive, so derivation can be re-run): IP sizes 1200 (IPv6: 1280), 1350, 1400, 1420, 1440, 1460, 1472, 1480, 1492 and 1500 (or the local interface MTU if smaller). Each size is sent 3 times per direction with DF set and `IP_PMTUDISC_PROBE`. What arrives, which ICMP errors come back, and what is lost silently together give the path MTU and the black-hole flag.

**NAT binding timeouts**: the initiator opens one spare UDP socket per timeout T and sends one `NatProbe` from each. On receipt, the responder schedules a reply to the observed source tuple after T. A reply that arrives means the binding survived T idle seconds.

**TCP connections** (class probes and reference flows) start with a 48-byte authenticated header: session id, flow id, kind, direction, byte and time limits, and a keyed-BLAKE3 tag under the session key. The responder serves only connections whose header verifies for the active session, so it cannot be used as a traffic source by strangers (REQ-SEC-001).

**Data budget.** Each endpoint's cap applies to what it sends. Before each saturation phase the initiator gives every saturating flow a byte allowance (`max_bytes` in its flow definition):

`allowance = (cap − spent_sender − reserve_sender) × this_phase_s / remaining_saturation_s_sender`

- `spent` is the sender's bytes so far: the initiator's own counter, or the responder's counter as reported in its feedback (`sent`).
- `reserve` is the background traffic still to come (light flow, trains, control) over the planned time still to come, plus P8 until it has run: the CBR flow and the TCP bulk transfer, which is reserved up front at min(cap / 8, 100 MB) per sender. The planned time still to come is the current phase's planned time not yet used plus the planned time of every later phase (at least until the NAT probes end), so a phase that runs long does not shrink the reserve of the phases after it.
- In P8, each direction's TCP bulk transfer sends at most its reserved bytes, and at most what its sender has left after the background and CBR still to come.
- A flow id that is reused (tracking rounds wrap after 150) starts its byte count again.
- `remaining_saturation_s` covers this and all later saturation phases of that sender.

A phase whose allowance is under 1 MB is skipped and records `phase_skipped {reason: "budget"}`. The pacer of either endpoint stops a flow when its bytes reach `max_bytes` (`flow_stopped {reason: "allowance"}`), and the controller starts the overdrive early so that it fits in the allowance (§7). On fast paths, saturations therefore get shorter and every phase still runs. If a hard cap is reached anyway, the pacer stops every probe flow, the light flow included, and records a `budget_cap` event. Only the control traffic needed to finish the session continues, and it is still counted (EXP-0002-r2).

## 7. Saturation controller

The receiver reports feedback every 20 ms while a controlled or chirp flow arrives, otherwise every 200 ms (unreliable): per flow, the delivery rate since the previous report, and the queueing-delay estimate `q = (rx − t_intended) − min(rx − t_intended)` of the latest packet, which is valid for relative changes despite the unknown clock offset. The responder's reports also carry its bytes sent (`sent`). The queue target is q_target = max(10 ms, 3 MTU packet times at the delivery rate). The sender:
1. **slow start**: from 2 Mbit/s, the rate doubles every 50 ms until q exceeds q_target or the rate exceeds twice the delivery rate; it then continues at the delivery rate.
2. **hold**: `rate = delivery_rate × clamp(1 + 0.5 × (q_target − q) / q_target, 0.7, 1.3)`. This keeps a standing queue (a backlog, so arrivals are delivery opportunities) without flooding.
3. **overdrive** (last 1.5 s of saturations longer than 3 s, or earlier once the bytes left in the flow's allowance only cover 1.5 s at 1.5× the delivery rate): send at 1.5× the delivery rate. A tail-drop buffer then fills, and its depth becomes observable at loss onset (draft spec §6.5: "ramp … to 2× the estimate"). Holding a 10 ms queue alone never reveals the buffer.
4. **drain**: stop and keep receiving for 1 s, so the queue drain can be measured.
5. **dead-man** (REQ-PRB-005): if no authenticated feedback has arrived for 500 ms, heavy, chirp, CBR and class-saturation flows stop for good (`flow_stopped {reason: "dead_man"}`). The session-long light trains and the PMTU ladder pause instead (`flow_paused`) and resume when feedback returns (`flow_resumed`): trains skip the packets due while paused, and the ladder waits. A bloated queue in the other direction (P5, P6), a long RTT or a roam can delay feedback past 500 ms without the path being dead, and these observers must cover the whole session. The light flow (40 kbit/s) keeps observing through short outages, which makes outages visible in the trace, and pauses after 5 s without any authenticated control message. The hard rate cap and data cap always apply.

The controller only decides what to send. Whether an arrival counts as a delivery opportunity is decided later by derivation from the logged data (REQ-PRB-013).

## 8. Robustness

- Every phase runs under its own deadline. A failure is recorded as `phase_failed {reason}` and the session moves on (REQ-PRB-020).
- SIGINT and SIGTERM stop the session gracefully. The initiator records `interrupted`, skips the remaining phases, ends the session with the responder, flushes its log, fetches the responder log and merges what it has (exit 3). A second signal terminates at once. The responder ends a running session the same way before it exits: it records `interrupted`, stops its flows, sends a reliable `abort {reason: "signal", signal}`, waits up to 10 s for the initiator's `bye`, flushes its log, and keeps serving fetches for 15 s. The initiator treats `abort` like its own signal (`interrupted {by: "responder"}`, exit 3). An initiator older than wire minor 1 ignores `abort` and finds the responder gone (REQ-PRB-021).
- Right after the handshake, the initiator prints the session id and writes `<trace_id>.session` (0600) next to its log: responder name, session id, fetch token and the responder's TLS certificate. `pathtrace fetch --resume <file>` uses it, so the responder log stays retrievable after a crash or a lost network. The file is deleted once the complete trace is written.
- The responder keeps `b.ptflog` per session under its state directory, with configurable retention (default 14 days), and writes the session's fetch token when the session starts, so a log stays fetchable even if the responder stops mid-session. The initiator fetches it over TLS on the responder's main TCP port, then TLS on 443; plain TCP on the main port is used only when no certificate is known, with a warning that the fetch token is sent unencrypted. A known certificate that cannot be used fails the fetch rather than downgrading it. If that fails, the initiator writes a partial trace with its own log and prints the `pathtrace fetch` command.
- Mobility: the responder re-binds the peer address on any authenticated control message from a new source tuple and logs `nat_rebind`. The initiator logs rtnetlink address changes. Data flows continue (REQ-PRB-022).
- One session at a time per responder. Handshakes from other initiators are not answered while a session runs.
