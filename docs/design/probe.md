# Probe and responder design

- requirements: REQ-PRB-001 … REQ-PRB-025, REQ-SEC-001, REQ-SEC-002
- adr: 0006, 0007, 0010, 0012
- research: R-0010 … R-0014 (Linux APIs)

The probe records everything observable about the path, in both directions, into crash-safe observation logs. It then merges them into one PTF trace. It never computes a path model while capturing: derivation runs afterwards and can be re-run.

## 1. Roles, processes, threads

`pathtrace serve` (responder, public VM) and `pathtrace probe` (initiator, laptop) share all measurement code. Inside each process:

| Thread | Job | Why separate |
|---|---|---|
| control | Noise session, reliable control messages, clock exchanges, phase orchestration (initiator drives, responder follows), feedback | Never blocked by data-path work |
| pacer | The **only** sender on UDP sockets. Executes the send schedule of every active UDP flow (light, trains, chirps, heavy, CBR, class, NAT, PMTU) and drains a queue of control/echo datagrams at least every 200 µs; sleeps until about 200 µs before the deadline, then spins; one `sendmmsg` per due batch | One pacing clock, no cross-thread jitter, and OPT_ID numbering stays consistent (a single sender per socket) |
| receiver | `recvmmsg` on every UDP socket with kernel RX stamps, TOS, TTL; demultiplexes control frames (first byte `0xC1`–`0xC3`) to the control thread; drains the error queue (TX stamps, ICMP) on `POLLERR`; computes live feedback for the saturation controller | Receive timing is independent of sending |
| logger | Turns records into table chunks and appends an OBSV/CLOK/CTXS/EVNT section about once per second (`fsync`) | Disk I/O never stalls the data path |
| context (initiator; responder: interface counters only) | Interface counters at 10 Hz, nl80211 station info at 1 Hz, rtnetlink events | Slow syscalls kept off the data path |
| tcp | Reference flows and TCP class probes; `TCP_INFO` sampling every 10 ms on both ends | Kernel TCP blocks |

Records flow to the logger over bounded `std::sync::mpsc` channels. If a channel is full, a counter of dropped records goes into EVNT. Records are never silently lost, but backpressure must never stall pacing.

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
- Fallback: if no handshake reply arrives within 3 s on UDP, the initiator retries over TCP 443 and then TCP 4433 (Noise over a u16-length-framed stream). UDP classes are then recorded as blocked, and the session continues with TCP-only phases (REQ-PRB-003).

### 3.2 Messages (CBOR maps, deterministic profile)
`hello {wire_major, wire_minor, tool_version, git_commit, capabilities, profile}` → `welcome {wire_major, wire_minor, session_id(u32), responder facts (os, kernel, ts support, cc), tls_cert_sha256}`; `phase {id, kind, params, start_at_offset_ns}`; `phase_done {id, status, reason?, counters}`; `feedback {flow, highest_seq, recv_count, recv_bytes, window_ns, qdelay_min_ns, qdelay_now_ns, delivery_rate_bps}`; `clock_req {t1}` → `clock_resp {t1, t2, t3}`; `nat_probe {...}`; `pmtu_ack {sizes}`; `bye {reason}`; `error {code, text}`.

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

Tag = first 8 bytes of keyed BLAKE3 over everything before the tag. The key is `blake3::derive_key("pathtrace probe tag v1", noise_handshake_hash)`. Padding comes from a ChaCha stream so that packets do not compress (REQ-PRB-006). Packets with bad tags are counted per flow and never logged as observations.

For `udp/443 QUIC-shaped`, the same payload is carried after a QUIC v1 header: the first packet of a flow uses a long header of type Initial, and the rest use short headers with the fixed bit set and an 8-byte DCID derived from the session (ADR 0006, `quic_shape = "header/1"`).

## 4. Clocks and timestamps (ADR 0012)

- Scheduling and intended times use CLOCK_MONOTONIC_RAW.
- Probe sockets enable `SO_TIMESTAMPING = RX_SOFTWARE | TX_SOFTWARE | TX_SCHED | SOFTWARE | OPT_ID | OPT_TSONLY`. Hardware stamps need CAP_NET_ADMIN and are used only when the process has it.
- Kernel software stamps are CLOCK_REALTIME (R-0010). Each side therefore logs a **clock pair** about once per second: the minimum-width sandwich of MONO_RAW, REALTIME, MONO_RAW over 8 tries (~30 ns uncertainty). NTP slews and steps can be undone at derivation time.
- TX stamps: SND (driver, after the local qdisc) where the driver provides it, SCHED (qdisc enqueue) always on supporting kernels. Wi-Fi drivers commonly give SCHED only (R-0010). Both are logged when present, plus the user-space time just before `sendmmsg`.
- Control-channel exchanges (`clock_req`/`clock_resp`) run five times at P0 and once per second afterwards: t1/t4 on the initiator and t2/t3 on the responder, all MONO_RAW.

## 5. What is logged (raw layer)

Per endpoint, in its observation log (`META.kind = "obslog"`, `META.role = "a" | "b"`):

| Table (section) | Rows | Columns |
|---|---|---|
| `tx` (OBSV) | every probe packet sent | flow, seq, size (IP bytes), phase, train, train_idx, tos_tx, id (kernel OPT_ID), tx_intended (mono), tx_user_lag (user send time minus intended, ns) |
| `txts` (OBSV) | every kernel TX timestamp from the error queue | id, kind (0 SCHED, 1 SND), real |
| `rx` (OBSV) | every authenticated probe packet received | flow, seq, size, rx (real; kernel stamp, else user time), rx_src (0 kernel, 1 user), tos_rx, ttl_rx, src (index into `peer_addr` events) |
| `bad` (OBSV) | per flow per second | flow, t, bad_tag count, unknown_flow count |
| `icmp` (OBSV) | every error-queue ICMP | t (real), flow, seq (from the quoted payload), type, code, info (MTU), origin, offender (pii id) |
| `probe` (OBSV) | discrete class, NAT, PMTU and ECN probes | t (mono), test, class, family, attempt, outcome, value, value2 |
| `tcpinfo` (OBSV) | 10 ms samples per TCP flow | flow, t (mono), tcp_info fields (fixed list, `optlen` recorded) |
| `app` (OBSV) | TCP reference-flow application events | flow, t (mono), event, bytes |
| `exchange` (CLOK) | clock exchanges (initiator only) | t1, t2, t3, t4 |
| `pairs` (CLOK) | clock pairs | mono, real, width |
| `ifstats` (CTXS) | 10 Hz | t, rx/tx bytes, packets, errors, drops |
| `wifi` (CTXS, initiator) | 1 Hz | t, freq_mhz, signal_dbm, tx/rx bitrate (100 kbit/s), tx_retries, tx_failed, bssid_hash (pii quasi) |
| EVNT | events | phase start/end/failed, addr_change, iface_change, nat_rebind, control_fallback, budget_cap, dead_man, channel_overflow, ... |

Control datagrams are observations too: the sender logs each sealed control datagram in `tx` as flow 250 (sent by a) or 251 (sent by b) with seq = Noise nonce, and the receiver logs it in `rx`. Every packet the probe puts on the path is therefore observed, which loss-model estimation requires (EXP-0002). Feedback runs at 50 Hz while a controlled flow arrives and at 5 Hz otherwise.

`merge` joins `tx` with `txts` by OPT_ID, which gives `tx_sched` (real) and `tx_snd_lag` (SND minus SCHED). It then joins the result with the peer's `rx` per direction, keyed by (flow, seq), to form the trace's `pkt` table. Duplicates go to `dup` and unmatched arrivals to `unmatched`. Nothing is dropped (P1).

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

The data budget is planned once the P3 estimate is known: saturation phases shrink proportionally (minimum 2 s each) so that the projected total stays under the cap. If a hard limit is reached anyway, the pacer stops every probe flow, the light flow included, and records a `budget_cap` event. Only the control traffic needed to finish the session continues, and it is still counted (EXP-0002-r2).

## 7. Saturation controller

The receiver reports feedback every 10 ms (unreliable): delivery rate over the last 100 ms, and the queueing-delay estimate `q = (rx − t_intended) − min(rx − t_intended)` over the phase, which is valid for relative changes despite the unknown clock offset. The sender:
1. **ramp** (2 s): rate rises linearly from 0.5× to 2× the chirp estimate. The knee, where q starts rising, marks the bottleneck.
2. **hold**: `rate = delivery_rate × clamp(1 + 0.5 × (q_target − q) / q_target, 0.7, 1.3)` with q_target = max(10 ms, half the base RTT). This keeps a standing queue (a backlog, so arrivals are delivery opportunities) without flooding.
3. **overdrive** (last 1.5 s of saturations longer than 3 s): send at 1.5× the delivery rate. A tail-drop buffer then fills, and its depth becomes observable at loss onset (draft spec §6.5: "ramp … to 2× the estimate"). Holding a 10 ms queue alone never reveals the buffer.
4. **drain**: stop and keep receiving for 1 s, so the queue drain can be measured.
5. **dead-man**: heavy, chirp, train, CBR and class flows stop if no authenticated feedback arrives for 500 ms (REQ-PRB-005). The light flow (40 kbit/s) keeps observing through short outages, which makes outages visible in the trace, but it also stops after 5 s without any authenticated control message. The hard rate cap and data cap always apply.

The controller only decides what to send. Whether an arrival counts as a delivery opportunity is decided later by derivation from the logged data (REQ-PRB-013).

## 8. Robustness

- Every phase runs under its own deadline. A failure is recorded as `phase_failed {reason}` and the session moves on (REQ-PRB-020).
- SIGINT and SIGTERM stop the session gracefully. Logs are flushed, and the initiator still merges what it has.
- The responder keeps `b.ptflog` per session under its state directory, with configurable retention (default 14 days). The initiator fetches it over TCP (Noise-framed) on 4433, else 443. If that fails, the initiator writes a partial trace with its own log and prints the `pathtrace fetch` command.
- Mobility: the responder re-binds the peer address on any authenticated control message from a new source tuple and logs `nat_rebind`. The initiator logs rtnetlink address changes. Data flows continue (REQ-PRB-022).
- One session at a time per responder; others get `error {busy}`.
