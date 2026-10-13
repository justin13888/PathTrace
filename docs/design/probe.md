# Probe and responder design

- requirements: REQ-PRB-001 … REQ-PRB-025, REQ-PRB-033, REQ-SCOPE-009, REQ-SEC-001, REQ-SEC-002
- adr: 0006, 0007, 0010, 0012, 0014
- research: R-0010 … R-0015 (Linux APIs), R-0017 (macOS APIs)

The probe records everything observable about the path, in both directions, into crash-safe observation logs. It then merges them into one PTF trace. It never computes a path model while capturing: derivation runs afterwards and can be re-run.

## 1. Roles, processes, threads

`pathtrace serve` (responder, public VM) and `pathtrace probe` (initiator, laptop) share all measurement code. Inside each process:

| Thread | Job | Why separate |
|---|---|---|
| control | Noise session, reliable control messages, clock exchanges, phase orchestration (initiator drives, responder follows), feedback | Never blocked by data-path work |
| pacer | The **only** sender on UDP sockets. Executes the send schedule of every active UDP flow (light, trains, chirps, heavy, CBR, class, NAT, PMTU) and drains a queue of control/echo datagrams at least every 200 µs; sleeps until about 200 µs before the deadline, then spins; one `sendmmsg` per due batch. Records every send that fails or is skipped (§4.1), and skips ahead after a stall instead of bursting (§4.3) | One pacing clock, no cross-thread jitter, and OPT_ID numbering stays consistent (a single sender per socket) |
| receiver | `recvmmsg` on every UDP socket with kernel RX stamps, TOS, TTL and the socket's drop count; demultiplexes control frames (first byte `0xC1`–`0xC3`) to the control thread; drains the error queue (TX stamps, ICMP) on `POLLERR`; computes live feedback for the saturation controller | Receive timing is independent of sending |
| logger | Turns records into table chunks and appends an OBSV/CLOK/CTXS/EVNT section about once per second (`fsync`) | Disk I/O never stalls the data path |
| context (both endpoints; Wi-Fi on the initiator only) | Interface counters, UDP/softnet stack counters and egress qdisc counters at 10 Hz; nl80211 station info and clock pairs at 1 Hz; rtnetlink events; follows the interface that carries the route to the peer (§4.4) | Slow syscalls kept off the data path |
| tcp | Reference flows and TCP class probes; `TCP_INFO` sampling every 10 ms on both ends | Kernel TCP blocks |

The table describes Linux. A macOS initiator (ADR 0014) runs the same threads with the differences in §9: one `sendmsg`/`recvmsg` per datagram, no error queue, no qdisc, nl80211 or `/proc` counters, and `TCP_CONNECTION_INFO` in place of `TCP_INFO`.

Records and events flow to the logger over one bounded `std::sync::mpsc` channel. The pacer and receiver never block on it: if it is full, their record or event is counted (rows per table, events per type), and the logger writes a `channel_overflow {rows: {table: n}, events: n, event_types: {type: n}}` event with the new counts at its next flush and at the end. Events from the session, control and sampler threads (`phase_start`, `session_end`, `interrupted`, …) wait for the logger instead, so they are never lost and derivation can rely on the phase timeline. Records are never silently lost, and backpressure never stalls pacing.

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
- Fallback: if no handshake reply arrives within 3 s on UDP, the initiator retries over TCP 443 and then TCP 4433 (Noise over a u16-length-framed stream). UDP classes are then recorded as blocked, and the session continues with TCP-only phases (REQ-PRB-003): the initiator defines no UDP flow, so the background flows, P2 to P7, the CBR flows of P8 and the tracking saturations are each recorded as `phase_skipped {phase, reason: "udp_blocked"}`, P1 records `udp_reachability` with every UDP class false, and only the TCP class probes (P1) and the TCP reference flows (P8) run. The responder sends no UDP to the initiator in such a session: it learns no UDP peer from the TCP control connection (whose source port is not a UDP port the initiator listens on), only from authenticated probe packets that actually arrive over UDP.
- Address family: the initiator tries the responder's first address of the preferred family (`--ipv6`, else IPv4), then its first address of the other family. A family is skipped when it has no local route or socket (for example `--ipv6` on a host without IPv6 connectivity, or IPv4 on an IPv6-only or NAT64 network), and a UDP handshake is tried on each remaining family before the TCP fallback is tried on each, so a UDP session on the other family is preferred to a TCP-only one on the preferred family. A handshake reply of any kind (a refusal included) ends the search. When the session runs on another family than the preferred one, the initiator records `family_fallback {requested, used, reason}` and says so on stderr; the trace is complete (exit 0), because the path it records is the one the session ran on (`endpoint.addr`, `endpoint.peer_addr`).

  *Alternatives rejected:* trying every resolved address, which bounds the search at 3 s per address and buys nothing for a responder that has one address per family; and TCP on the preferred family before UDP on the other, which would record a TCP-only trace on a path that carries UDP.

### 3.2 Messages (CBOR maps, deterministic profile)
`hello {wire_major, wire_minor, tool_version, git_commit, capabilities, profile}` → `welcome {wire_major, wire_minor, session_id(u32), responder facts (os, kernel, ts support, cc), tls_cert_sha256}`; `phase {id, kind, params, start_at_offset_ns}`; `phase_done {id, status, reason?, counters}`; `feedback {flow, highest_seq, recv_count, recv_bytes, window_ns, qdelay_min_ns, qdelay_now_ns, delivery_rate_bps}`; `clock_req {t1}` → `clock_resp {t1, t2, t3}`; `nat_probe {...}`; `pmtu_ack {sizes}`; `bye {reason}`; `abort {reason, signal}` (wire minor 1, reliable, responder → initiator: the responder was stopped by a signal); `error {code, text}`.

Version rule: a major mismatch fails with a clear error naming both versions. A higher minor is accepted, and unknown keys are ignored (REQ-PRB-021). Each endpoint records the peer's minor in META (`extra.responder.wire_minor` on the initiator, `extra.initiator_wire_minor` on the responder). Mixed minors 1.0 and 1.1 run a session, with these gaps: a 1.0 responder sends no `sent` in its feedback and ignores `max_bytes`, so the initiator's byte allowances for responder-sent saturations see `spent = 0` and are not enforced at the responder (only its hard data cap applies); a 1.0 initiator ignores `abort` and finds a stopped responder gone.

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

For `udp/443 QUIC-shaped`, the same payload is carried after a QUIC v1 header: the first packet of a flow uses a long header of type Initial, and the rest use short headers with the fixed bit set and an 8-byte DCID derived from the session (ADR 0006, `quic_shape = "header/1"`). A receiver strips that header before verifying the tag, and the `icmp` event strips it from the quoted datagram before reading the quoted flow and seq. Both tell a QUIC header from a probe header by its first byte: the fixed bit (0x40) set and a high nibble other than the probe version. A control frame's first byte (`0xC1`–`0xC3`) also passes that test, so a quoted control datagram is recognised first and left undecoded: its `icmp` event records null `flow` and `seq`, since stripping it would read ciphertext as a probe header.

## 4. Clocks and timestamps (ADR 0012)

- Scheduling and intended times use CLOCK_MONOTONIC_RAW.
- Probe sockets enable `SO_TIMESTAMPING = RX_SOFTWARE | TX_SOFTWARE | TX_SCHED | SOFTWARE | OPT_ID | OPT_TSONLY`, falling back to `SO_TIMESTAMPNS` (RX only) where that fails.
- Kernel software stamps are CLOCK_REALTIME (R-0010). Each side therefore logs a **clock pair** about once per second: the minimum-width sandwich of MONO_RAW, REALTIME, MONO_RAW over 8 tries (~30 ns uncertainty). NTP slews and steps can be undone at derivation time.
- TX stamps: SND (driver, after the local qdisc) where the driver provides it, SCHED (qdisc enqueue) always on supporting kernels. Wi-Fi drivers commonly give SCHED only (R-0010). Both are logged when present, plus the user-space time just before `sendmmsg`. Hardware stamps are not used in 1.x.
- Every clock pair also reads CLOCK_BOOTTIME inside the same sandwich, so a suspend shows directly as a jump of BOOTTIME − MONO_RAW.
- On macOS the same roles are played by other clocks and stamps (§9.1 to §9.3).

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

**Re-anchoring predicted ids.** *Problem:* in `predicted` mode a failure whose id consumption was guessed wrong (errno unknown, or classified wrongly) shifts every later id on that socket by one, so each later transmission joins a neighbour's stamp. *Constraints:* raw logs are never altered (P1), so the correction lives in `merge` and re-merging an existing pair of logs applies it; `explicit` ids are exact and are never touched; a correctly predicted trace must come out exactly as before. *Choice:* `merge` walks each socket's `tx` rows in id order and, at each `send_error`, `send_partial` and `send_eagain` event recorded with `tx_ids: predicted`, picks an id offset of −1, 0 or +1 relative to the offset in force, applied from that failure to the next. The failure's position in the id sequence is exact when the event has a `burned_id` (rows above it) or an `unburned_id` (rows from it on); otherwise it lies within the last `sendmmsg` call that started before the event, and every position in that call is a candidate. Each candidate is scored by how many rows up to the next failure join a SCHED stamp inside their call's window: from the call's user-space send time to the next call's on that socket (one second when there is none), both mapped to REALTIME by interpolating the endpoint's clock pairs, with 1 µs slack. A stamp is taken in the kernel during the call that sent it, so only the right alignment keeps every stamp inside its window: one too high gives a call's last row the next call's first stamp, one too low gives its first row the previous call's last stamp. A non-zero offset is taken only when it scores strictly higher than keeping the current one. Failures that can fall at the same position are scored jointly (issue #52): when a failure without a recorded id is followed by one whose position can lie inside the first one's call, the run of such failures picks its offsets together, over the rows up to the next failure after the run, taking the combination that joins the most stamps, then the one that changes the offset at the fewest failures, then the one whose total change is 0, −1, +1, −2, +2, … in that order (for a single failure this is the rule above). Within a run, positions where the offset changes are taken in id order. A failure that would start a run longer than 8 is scored alone as before, so of a longer run only the last 8 are scored jointly: such runs come from outages in which every send fails before taking an id (ENETUNREACH), all placed in the same last call, and the joint search grows with the square of the run's length. Scored one at a time, the first failure's rows would end where the second's candidates start, inside its own call, where every stamp fits every row; in a four-datagram call with burns at ids 3 and 5, a −1 step then scores as high as the true +1 and is taken. A later failure's candidates start no earlier than the last position where the offset changed, so the offsets stay in id order; a failure that changed nothing does not bound them, because once a burn is undone the row reusing its id sorts before the burn's position, yet comes after the undo. Every join, `txts_unmatched`, and the id check use the corrected ids; a failure's `burned_id` is corrected with the offset in force before it. `merge_checks` gains per endpoint `tx_reanchors_<ep>` (failures at which the offset changed) and `tx_reanchored_<ep>` (`tx` rows whose id was corrected). *Alternatives rejected:* the ±1 ms plausibility window of `txts_implausible`, which cannot tell neighbouring stamps apart; matching by stamp gaps alone, which a lost stamp imitates; and logging the failed datagram's would-be id, which existing logs lack. *Validated by:* `merge::tests` (an assumed burn that consumed nothing, an unrecorded burn located inside its call, offsets accumulating over two failures with a `raw_sent` id corrected through both, an undone burn that did consume, a second failure inside the first one's call, two unrecorded burns in one five- and one four-datagram call, three in one call, an outage of a thousand failures before any id was taken, a correct prediction and an `explicit` failure, which keep their ids) and the netns `forced_predicted_ids_join_exactly` session, which forces predicted ids and expects no unexplained stamp and no re-anchoring.

### 4.2 Host drops (R-0015)

A packet the path delivered can still be lost inside a host. Each such place is recorded, so derivation can separate host drops from path loss:

| Where | Recorded as |
|---|---|
| Receiving socket (buffer full) | `SO_RXQ_OVFL`: the socket's cumulative drop count at the time each datagram was queued, per `rx` row (`rxq_drops`) |
| Receive stack | `netstack` table: UDP/UDP6 `InErrors`, `RcvbufErrors`, `SndbufErrors`, `InCsumErrors`; softnet backlog drops and squeezes |
| Egress qdisc | `qdisc` table: root qdisc of the egress interface (bytes, packets, qlen, backlog, drops, requeues, overlimits); its kind and `txqueuelen` in META |
| Recorder channel | `channel_overflow` events |

Receive buffers request 8 MiB with `SO_RCVBUFFORCE`/`SO_SNDBUFFORCE` (effective with CAP_NET_ADMIN), else `SO_RCVBUF`/`SO_SNDBUF`, which the kernel caps at `rmem_max`/`wmem_max`. The effective sizes of every socket are in META.

Two environment variables exist for the ground-truth harness and change what is measured, so field sessions never set them: `PATHTRACE_RECV_BUF=<bytes>` requests that receive buffer size instead of 8 MiB (to provoke socket drops), and `PATHTRACE_TX_IDS=predicted` forces predicted transmit ids on a kernel that supports explicit ones (§4.1). Both `probe` and `serve` honour them, and an endpoint that ran with either records it in META `extra.test_hooks` (null otherwise). A small buffer alone drops only when the receive thread falls behind, which depends on host load (EXP-0002-r13 saw none on a quiet host); the `rcvbuf` scenario therefore also releases a→b packets in 20 ms netem slots, so each burst (about 250 kB at 100 Mbit/s) overflows the responder's buffer whatever the load.
- Control-channel exchanges (`clock_req`/`clock_resp`) run five times at P0 and once per second afterwards: t1/t4 on the initiator and t2/t3 on the responder, all MONO_RAW user-space times. Each row also records the Noise nonces of the request and response datagrams, which identify them as flow 250/251 rows with kernel stamps, so derivation can use the kernel stamps instead.

### 4.3 Stalls and suspends

*Problem:* when the pacer thread is descheduled, its process is stopped, or its VM pauses, every flow's next deadline falls behind. On wakeup it sent the overdue packets back to back, up to 64 per flow per loop, until it caught up. That burst is an artefact of the host, not of the path, yet it builds a queue at the bottleneck that derivation reads as path behaviour; only `tx_user_lag` showed it. A suspend is different: MONO_RAW and the sleeps the pacer uses do not advance while the system is suspended, so the schedule resumes where it stopped, without a burst, but the peer and the path saw a silence. *Constraints:* every packet the probe sends is still observed (no unrecorded skip); a schedule's position in time stays aligned with the phase timeline; the PMTU ladder must probe every size; checking for a stall must cost no more than a clock read per loop. *Choice:* the pacer treats a flow as stalled when its next deadline is more than `STALL_NS` = 2 ms in the past at the moment it collects due packets. A stream (iso, train, chirp, rate) then skips every overdue packet: its sequence numbers are consumed without a `tx` row, exactly like the paused light flow, and the schedule resumes at the first deadline not in the past. A counted pattern (ladder, burst), whose every packet is needed, keeps its packets and shifts the rest of its schedule by the delay. The pacer records one `stall {cause: "late", late_ns, flows: [{flow, late_ns, skipped, shifted_ns}]}` event per loop that found a stall (`late_ns` at the top is the largest of the flows). It also reads CLOCK_BOOTTIME each loop; when BOOTTIME − MONO_RAW grew by more than `STALL_NS` since the previous loop, the host was suspended, and it records `stall {cause: "suspend", suspended_ns}`. Lateness up to 2 ms is caught up as before and stays visible in `tx_user_lag`. *Alternatives rejected:* shifting every schedule by the delay, which moves the rest of a phase past its end and leaves later phases overlapping it; sending the overdue packets spread out at a higher rate, which is still a rate the plan never asked for; a larger threshold such as 10 ms, which at the 500 Mbit/s cap still allows a burst of about 400 packets. *Rationale:* 2 ms is the pacer's own horizon (it blocks on its command channel only when the next deadline is further away than that), well above a normal wakeup error (`sleep_until` is accurate to well under 1 ms) and below one light-flow interval. A skipped packet never left the host, so like any datagram without a `tx` row it is never counted as path loss (§4.1). *Validated by:* `flows::tests` (a stalled stream skips its overdue packets and keeps its phase alignment, a mid-train stall skips the rest of the train, a ladder and a burst shift and lose nothing, a flow less than 2 ms late is untouched) and `io::tests` (the suspend detector).

### 4.4 Interface switches

*Problem:* the context sampler sampled the interface chosen when the session started. After a switch, for example from Wi-Fi to a USB tether, the route to the peer leaves through another interface, and `ifstats`, `qdisc` and `wifi` kept describing the old one, or stopped. *Constraints:* no shelling out (R-0014); no new privileges; the CTXS tables keep their columns (PTF compatibility); the raw `addr_*`/`route_*`/`link_*` events stay as they are. *Choice:* the sampler is given the peer's address. After any batch of rtnetlink events, after an rtnetlink overrun, and once per second when rtnetlink is unavailable, it asks the kernel which local address it would use to reach the peer (a connected UDP socket that sends nothing) and which interface holds that address. When that interface differs from the sampled one, it records `iface_change {from, to, iface, qdisc, txqueuelen, addr}` (`from` and `to` are the old and new interface names, `pii: quasi` like META's `/endpoint/iface/name`; `iface`, `qdisc` and `txqueuelen` as in META for the new interface, except that `iface` omits `name`, which `to` carries, because only top-level detail values can carry a `pii` wrapper; `addr` is the new local address, `pii: id`), and samples the new interface from then on: interface counters, the root qdisc, and Wi-Fi link state when the new interface is Wi-Fi (opening nl80211 then if it was not open). While no route to the peer exists, as in the middle of a switch, it keeps the current interface. A counter series therefore restarts at each `iface_change`: the cumulative counters before and after it belong to different interfaces, and a consumer computes deltas within one segment only (`qdisc.drop-count/2`, derivation.md). META keeps the interface the session started on. *Alternatives rejected:* adding an interface column to every CTXS table, a format change for a rare event that the event already marks; sampling every interface, which multiplies the tables by unrelated interfaces; following only default-route events, which misses a more specific route to the peer and policy routing. *Validated by:* `context::tests` (the follow rule: a change is reported once, an unresolved route keeps the current interface) and `context::tests::resolves_loopback_route` (the resolver finds the interface carrying the route to a peer).

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
| EVNT | events | `handshake`, `handshake_resent`, `phase_start`, `phase_failed`, `phase_skipped`, `class_skipped`, `peer_addr`, `nat_rebind`, `addr_new`/`addr_del`/`route_*`/`link_*`, `iface_change` (§4.4), `stall` (§4.3), `icmp` (error-queue ICMP: sock, errno, type, code, info, offender, quoted flow and seq), `local_error`, `send_error`, `send_partial`, `send_eagain`, `raw_sent` (a datagram sent without a `tx` row, such as an echo or a handshake reply: sock, id, size), `tx_id_mode`, `tcp_probe`, `udp_reachability`, `saved_syn`, `ref_tcp`, `flow_stopped`, `flow_paused`/`flow_resumed`, `light_paused`/`light_resumed`, `budget_cap`, `channel_overflow`, `interrupted`, `session_end` |

UDP class, NAT and PMTU probes are ordinary flows in `tx`/`rx` (their echoes are logged by the endpoint that sent them). TCP class probes are `tcp_probe` events.

Control datagrams are observations too: the sender logs each sealed control datagram in `tx` as flow 250 (sent by a) or 251 (sent by b) with seq = Noise nonce, and the receiver logs it in `rx` with `src` set like a probe's (a control datagram from a source tuple not seen before records its `peer_addr` event). Every packet the probe puts on the path is therefore observed, which loss-model estimation requires (EXP-0002). Feedback runs at 50 Hz while a controlled flow arrives and at 5 Hz otherwise.

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
| P3 | 5 s | chirps: 26-packet trains with exponentially shrinking gaps (below), alternating direction every 250 ms → capacity estimate per direction |
| P4 | ≤ 10 s | saturate a→b: ramp 0.5× → 2× the estimate over 2 s, then hold a standing queue, then stop and watch the drain for 1 s |
| P5 | ≤ 10 s | saturate b→a, same |
| P6 | ≤ 5 s | saturate both directions |
| P7 | ≤ 3 s per class | short saturation on udp/443 opaque and QUIC-shaped (UDP); TCP classes covered by P8 |
| P8 | about 20 s | reference flows: TCP bulk each direction (≤ 5 s or the byte budget), TCP request/response 1 KiB × up to 200, UDP CBR 2 Mbit/s 5 s each direction |
| background | whole session | NAT binding timeouts (15, 30, 60 s; deep adds 120, 300), PMTU ladder in both directions (`PMTUDISC_PROBE` + ICMP), ECN/DSCP via the TOS cycle |

**Chirps** (issue #35). *Problem:* a chirp brackets the capacity between the rates its first and last gaps imply at its packet size. With 20 packets and gaps of 1 ms × 0.85^k it spanned about 12–224 Mbit/s at 1500 bytes, so a path above 224 Mbit/s (well inside the 1 Gbit/s access-network scope) or below 12 Mbit/s queued at every gap or at none, and its `estimated` capacity was only a bound. *Constraints:* chirp packets are the interface MTU capped at 1500 bytes, and the upper end reaches 1 Gbit/s down to the IPv6 minimum MTU, 1280 bytes (a smaller interface MTU scales both ends down in proportion); a chirp stays short against its 500 ms period so the two directions, 200 ms apart, do not overlap; the average rate stays negligible. *Choice:* 26 packets, gaps 2 ms × 0.8^k for k = 0 … 24: 6 Mbit/s – 1.27 Gbit/s at 1500 bytes and 5.1 Mbit/s – 1.08 Gbit/s at 1280 bytes, in steps of 25 %, lasting about 10 ms and averaging 0.6 Mbit/s. Instantaneous rates above the 500 Mbit/s rate cap are within that cap's meaning, which bounds sustained sending: trains already go back to back at line rate. *Alternatives rejected:* keeping factor 0.85 and adding packets, which needs 34 packets for the same span; a larger start gap, which buys rates below 5 Mbit/s that saturation (whose controller goes down to 100 kbit/s) measures anyway, at the cost of a longer chirp. *Validated by:* `flows::tests::chirp_brackets_access_rates` (the generated schedule's first and last gaps at 1280 and 1500 bytes).

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
1. **slow start**: from 2 Mbit/s, the rate doubles once per step until q exceeds q_target, or until, a full step after the last doubling, the rate still exceeds twice the delivery rate; it then continues at the delivery rate. The step is 50 ms, or the flow's feedback lag plus one feedback interval (20 ms) when that is longer. The feedback lag is the time from the flow's start to the first feedback reporting a delivery, about one RTT. The delivery rate reports what was sent one feedback lag earlier, so testing it sooner exits slow start on every long-RTT path after about 100 ms, and hold then grows the rate by at most ×1.3 per RTT. At 600 ms RTT that took about 15 RTTs (9 s) to reach 100 Mbit/s, longer than a 10 s saturation (issue #30). With the lag-gated step it takes log2(capacity / 2 Mbit/s) steps: about 4 s for 100 Mbit/s at 600 ms RTT. Paths with a feedback lag under 30 ms keep the 50 ms step.

   *Alternatives rejected:* seeding the rate from the P3 chirp estimate, which overestimates behind token-bucket policers and frame-aggregating Wi-Fi (bursts pass at line rate) and would then flood the path for a whole RTT before the first feedback; and lengthening saturations when the RTT is large, which changes the phase plan, the budget reserve and the session length on exactly the metered links (in-flight, GEO) where data costs most, and still ramps at ×1.3 per RTT. *Validated by:* `plan::tests::saturation_reaches_capacity_on_geo_paths` (simulated 300 ms one-way path) and the `geo-100m` ground-truth scenario's saturated-time check (≥ 3 s per direction at 300 ms one way, 100 Mbit/s), which fails with the old 50 ms step. Capacity medians, there and in `geo`, came out right with the old step too, so they do not tell the two apart.
2. **hold**: `rate = delivery_rate × clamp(1 + 0.5 × (q_target − q_pred) / q_target, 0.7, 1.3)`. This keeps a standing queue (a backlog, so arrivals are delivery opportunities) without flooding. `q_pred` is the reported q corrected for the bits sent since the packet it describes: `q_pred = max(0, q + ∫(rate − delivery_rate) dt / delivery_rate)` over the report's age, `feedback lag − 10 ms + q` (the base RTT plus that packet's own queueing delay; the lag overstates the base RTT by the wait for the receiver's next report, 0–20 ms). The controller keeps the rates it set over the last feedback lag plus 1 s for this.

   *Problem (issue #40):* q is about one RTT old. Acting on it directly, the sender keeps cutting the rate for a whole RTT after the queue has drained, so the bottleneck idles, then overshoots again: at 300 ms one way and 100 Mbit/s the rate swung 70–130 Mbit/s with a period of about 2 s and the queue was empty about half the hold time; even at 10 ms one way it idled 0.8 s of 5 s in simulation. *Constraints:* the measured feedback lag (item 1) is the only RTT estimate the controller has; short paths must keep their behaviour; the 10 ms target keeps the trace's queue small. *Alternatives rejected:* scaling the gain down by the lag, which damps the swing only by making every correction take several RTTs (at 600 ms RTT, seconds to drain the slow-start overshoot or refill an emptied queue, time a 10 s saturation does not have); a full BBR-style delivery-rate × min-RTT model, which needs an RTT measurement the wire protocol does not carry and a separate probing cycle. *Choice:* predict the queue the new rate meets from the controller's own rate history (a Smith predictor), keeping the gain. *Rationale:* the sender knows exactly what it sent since the reported packet, so the correction is exact up to the error in the age estimate; with that error within about ±20 ms the hold settles to the target on every simulated path, and larger errors (RTT jitter beyond that) leave a bounded swing inside the 0.7–1.3 clamp, no worse than before. *Validated by:* `plan::tests::hold_keeps_a_queue_on_long_rtt_paths` (simulated 10–300 ms one-way paths at 10–100 Mbit/s, in 1 ms steps with the responder's report timing and FIFO queueing delay: no time under 2 ms of queue in the second 5 s, against 0.8–2.6 s before, and the last 2 s within 9.8–10.2 ms of queue) and the `geo-100m` ground-truth scenario's b→a saturated-time check (≥ 6.5 s: 5.8 s with hold on the reported q, 7.7–8.1 s with `q_pred`; a→b, whose saturations the data budget shortens, stays at about 4.1 s either way). The floor was 7 s until EXP-0002-r11, where `q_pred` gave 6.56 s with two other scenarios running beside it on a loaded host; 6.5 s still rejects the reported-q law (5.8–6.1 s) and tolerates that load jitter.
3. **overdrive** (last 1.5 s of saturations longer than 3 s, or earlier once the bytes left in the flow's allowance only cover 1.5 s at 1.5× the delivery rate): send at 1.5× the delivery rate. A tail-drop buffer then fills, and its depth becomes observable at loss onset (draft spec §6.5: "ramp … to 2× the estimate"). Holding a 10 ms queue alone never reveals the buffer.
4. **drain**: stop and keep receiving for 1 s, so the queue drain can be measured.
5. **dead-man** (REQ-PRB-005): if no authenticated feedback has arrived for 500 ms, heavy, chirp, CBR and class-saturation flows stop for good (`flow_stopped {reason: "dead_man"}`). The session-long light trains and the PMTU ladder pause instead (`flow_paused`) and resume when feedback returns (`flow_resumed`): trains skip the packets due while paused, and the ladder waits. A bloated queue in the other direction (P5, P6), a long RTT or a roam can delay feedback past 500 ms without the path being dead, and these observers must cover the whole session. The light flow (40 kbit/s) keeps observing through short outages, which makes outages visible in the trace, and pauses after 5 s without any authenticated control message. The hard rate cap and data cap always apply.

The controller only decides what to send. Whether an arrival counts as a delivery opportunity is decided later by derivation from the logged data (REQ-PRB-013).

## 8. Robustness

- Every phase runs under its own deadline. A failure is recorded as `phase_failed {reason}` and the session moves on (REQ-PRB-020).
- SIGINT and SIGTERM stop the session gracefully. The initiator records `interrupted`, skips the remaining phases, ends the session with the responder, flushes its log, fetches the responder log and merges what it has (exit 3). A second signal terminates at once. The responder ends a running session the same way before it exits: it records `interrupted`, stops its flows, sends a reliable `abort {reason: "signal", signal}`, waits up to 10 s for the initiator's `bye`, flushes its log, and keeps serving fetches for 15 s. The initiator treats `abort` like its own signal (`interrupted {by: "responder"}`, exit 3). An initiator older than wire minor 1 ignores `abort` and finds the responder gone (REQ-PRB-021).
- Right after the handshake, the initiator prints the session id and writes `<trace_id>.session` (0600) next to its log: responder name, session id, fetch token and the responder's TLS certificate. `pathtrace fetch --resume <file>` uses it, so the responder log stays retrievable after a crash or a lost network. The file is deleted once the complete trace is written.
- The responder keeps `b.ptflog` per session under its state directory, with configurable retention (default 14 days), and writes the session's fetch token when the session starts, so a log stays fetchable even if the responder stops mid-session. The initiator fetches it over TLS on the responder's main TCP port, then TLS on 443; plain TCP on the main port is used only when no certificate is known, with a warning that the fetch token is sent unencrypted. A known certificate that cannot be used fails the fetch rather than downgrading it. If that fails, the initiator writes a partial trace with its own log and prints the `pathtrace fetch` command.
- Mobility: the responder re-binds the peer address on any authenticated control message from a new source tuple and logs `nat_rebind`. The initiator logs rtnetlink address changes, and both endpoints follow the interface that carries the route to the peer (§4.4). Data flows continue (REQ-PRB-022).
- One session at a time per responder. While a session runs, an authenticated handshake from another initiator (over UDP on either family's main socket, or over a TCP control connection) is answered with a `welcome` that carries `error: "busy"` and `error_text`, and session id 0; it starts nothing, and the running session records `handshake_refused {reason: "busy", addr}`. The initiator reports "responder busy" and exits 1 without retrying. A handshake that fails authentication is not answered, so the responder stays silent to strangers, and a repeat of the handshake that opened the running session is still answered by resending its reply (§3.1), never by `busy`. The refusal is a sealed Noise reply, so it is no larger than an ordinary handshake reply (REQ-PRB-004) and cannot be forged by an on-path stranger. An initiator older than this change reports it as "responder refused the session: busy".

  *Alternatives rejected:* staying silent, which an initiator cannot tell from a blocked path (it tries the TCP fallback and then reports the responder unreachable); and an unauthenticated plain-text busy datagram, which anyone could send to make a responder look busy, and which would tell a scanner that a responder listens.

## 9. macOS initiator (ADR 0014, R-0017)

ADR 0014 lets the initiator roles run on macOS 15 or newer (aarch64) against a Linux responder (REQ-SCOPE-009, REQ-PRB-033). This section states what a macOS initiator does and records where it differs from Linux; everything it does not name is as in §1 to §8. Platform code lives only in the macOS backend of `pt-sys`, which reports capabilities (kernel TX stamps, error queue, batched I/O, per-socket receive drops, qdisc and stack counters, Wi-Fi link state, TCP state kind). `pt-probe` and `pt-derive` branch on those capabilities and on what the trace records, never on `cfg`, so a Linux socket that lacks a facility (for example one that fell back to `SO_TIMESTAMPNS`) takes the same path. The format additions this needs are PTF 1.2 (ptf-format.md, Versions), all additive. Derivation rules introduced here are listed in §9.10.

### 9.1 Clocks

*Problem:* the Linux design rests on three clocks: MONO_RAW (not slewed, stops during suspend) for scheduling and intended times, REALTIME for kernel stamps, and BOOTTIME (counts suspend) for the suspend detector (§4.3). macOS has clocks with the same names and other meanings: its `CLOCK_MONOTONIC_RAW` counts sleep, and `CLOCK_UPTIME_RAW` (`mach_absolute_time`) is the one that stops (R-0017).

*Constraints:* the `<ep>.mono` domain keeps its meaning on both platforms, because the pacer's schedule must resume after a suspend without a burst and derivation interpolates it against `<ep>.real` with clock pairs (ADR 0012); the suspend detector needs a clock that counts sleep read inside the same sandwich; no privileges.

*Alternatives rejected:* `CLOCK_MONOTONIC_RAW` (equal to `mach_continuous_time`) for `.mono`: it counts sleep, so after a lid close every flow would be late by the whole sleep, the pacer would record `stall {cause: "late"}` and skip, and BOOTTIME − MONO would never jump, so the suspend would not be recorded as one; `CLOCK_MONOTONIC`: also counts sleep.

*Choice:* `a.mono` is `mach_absolute_time` (`CLOCK_UPTIME_RAW`): not slewed, stops while the system sleeps, ticking at 24 MHz on Apple silicon (41.67 ns, converted to ns with `mach_timebase_info`). The `boot` column of `pairs` is `mach_continuous_time` (counts sleep), read inside the same sandwich, so a sleep shows as a jump of boot − mono exactly as on Linux. `a.real` is `CLOCK_REALTIME`, the clock `SO_TIMESTAMP` reads (§9.3). The clock domain keeps the kind `monotonic_raw`, whose meaning PTF 1.2 states without naming a Linux clock, and 1.2 records each domain's `source` (ptf-format.md §6). Clock sync is read with `ntp_adjtime` (`modes = 0`, unprivileged, R-0017) by `doctor` (cli.md), as `adjtimex` is on Linux.

*Rationale:* `CLOCK_UPTIME_RAW` has every property the Linux design uses MONO_RAW for, and `mach_continuous_time` every property it uses BOOTTIME for; matching properties rather than names keeps §4.3, the clock model and the `t_intended_ns` header field unchanged.

*Validated by:* `pt-sys` unit tests on macOS (#61): mono and boot are monotonic, boot − mono stays constant within 1 ms over 1 s awake, and a clock pair's width is under 1 µs; the suspend path by the macOS evidence (#66), which closes the lid during a session and expects `stall {cause: "suspend"}`.

### 9.2 Transmit times

*Problem:* macOS has no kernel TX stamps and no error queue (R-0017), so there is no `txts` table, no OPT_ID and no `tx_sched` or `tx_snd_lag`. The user-space time is the only transmit time.

*Constraints:* every packet the probe sends is still observed; P1 (no correction in the raw layer); derivation must say which transmit times are user-space; a Linux socket without TX stamps already behaves this way.

*Choice:* a macOS probe socket records `kernel_tx: false` and `tx_ids: "none"` in META, like a Linux socket without TX stamps. The pacer reads `a.mono` immediately before each `sendmsg` (one call per datagram, §9.4), so `tx_user_lag` is that read minus `tx_intended`, per datagram. `merge` finds no stamps to join: the trace's `tx_sched` and `tx_snd_lag` are null for every packet a sent, `tx_unstamped_a` counts nothing (it counts only sockets that have stamps), and no re-anchoring applies. Derivation already takes the transmit time as SND, else SCHED, else user (`tx_intended + tx_user_lag`, mapped from `a.mono`), and counts the choice per direction in `PATH.<dir>.timestamps.counts` (`user` for every a→b packet of a macOS trace); `trace info` shows those counts (cli.md). `policy.matrix` uses the same fallback (§9.10).

*Error bound:* the user stamp is taken before the datagram leaves the host, never after, so the error is one-sided: the send-path latency from the clock read to the wire (the system call, UDP/IP output, the interface's output queue, and on Wi-Fi the driver, firmware and channel access). It is expected to be tens of µs on an idle host and wired link and up to milliseconds on Wi-Fi under contention or when the interface queue holds packets, as during an a→b saturation. Its effects: a→b one-way delays are overestimated by it, so `base_delay` (a minimum) carries the minimum send latency and `jitter` carries its variation; a→b inter-departure times include host scheduling; a queue in the Mac's own interface queue appears as path queueing delay, which on Linux `tx_snd_lag` and SND stamps would have separated. Capacity and loss rest on arrivals at the Linux responder and are unaffected. The b→a direction keeps the responder's kernel TX stamps. The bound is not knowable per packet; the macOS evidence (#66) measures it on a wired LAN, where the path is symmetric, as the difference between a→b and b→a base delay.

*Alternatives rejected:* reading the time after `sendmsg` returns, which adds the system call's own duration to an error that is already one-sided in the other direction and mixes the two; `SO_TIMESTAMP` on the sending side, which stamps receives only (R-0017).

*Validated by:* derive unit tests on a macOS-shaped trace (#63): every a→b packet counts as `user`, and delay and loss are derived from it.

### 9.3 Receive times

*Problem:* Linux stamps arrivals in software at the driver in ns (`SOF_TIMESTAMPING_RX_SOFTWARE`); macOS offers `SO_TIMESTAMP` (wall clock, `struct timeval`, µs) and `SO_TIMESTAMP_MONOTONIC` (`mach_absolute_time` ticks), both taken at socket enqueue in `udp_input` (R-0017).

*Constraints:* `rx` is declared in `<receiver>.real` (ptf-format.md, Raw tables) and cannot change domain; a kernel stamp beats a user-space one, which includes the receiver thread's wakeup.

*Choice:* probe sockets enable `SO_TIMESTAMP`; `rx` = `tv_sec × 10⁹ + tv_usec × 10³` in `a.real`, `rx_src = kernel`. The kernel fills the stamp with `microtime` (Kernel.framework `sys/time.h`: `#define getmicrotime(a) microtime(a)`; XNU `kern_time.c`: `microtime` reads `clock_get_calendar_microtime`), the precise calendar clock, not a value cached at a tick. A datagram that arrives without the cmsg gets the user-space time after `recvmsg` and `rx_src = user`, as on Linux. `IP_RECVTOS`, `IP_RECVTTL`, `IPV6_RECVTCLASS` and `IPV6_RECVHOPLIMIT` fill `tos_rx` and `ttl_rx` as on Linux.

*Resolution loss:* stamps are whole µs, truncated, so each b→a arrival time is 0–1 µs early (0.5 µs on average) against ns on Linux. That is below one 1500-byte packet time at 1 Gbit/s (12 µs) and far below Wi-Fi and scheduling noise, so 100 ms capacity bins, delay and loss are unaffected; the gaps of the fastest chirp packets (about 12 µs at 1.27 Gbit/s) carry up to ±1 µs. The stamp is also taken later than Linux's (after IP and UDP input rather than at the driver), which adds a near-constant few µs to b→a delays.

*Alternatives rejected:* `SO_TIMESTAMP_MONOTONIC`, a finer stamp (41.67 ns) in `a.mono`, which `rx` cannot hold: it needs a new column in another domain that every consumer of arrival times would have to handle, for a gain that matters only at the top chirp rates. A later minor can add it if the macOS evidence (#66) shows the µs quantum matters. A user-space time after `recvmsg`, which includes the receiver's wakeup.

*Validated by:* a `pt-sys` loopback test on macOS (#61) that every datagram carries the cmsg and that its time lies between a `CLOCK_REALTIME` read before the send and one after the receive.

### 9.4 Sending and pacing

*Problem:* macOS has no public `sendmmsg`/`recvmmsg` (R-0017), and it coalesces timers: it shifts a timer's expiry within a tolerance that depends on the thread's QoS class (R-0017). A laptop also idle-sleeps.

*Constraints:* the pacer stays the only sender on each UDP socket and records every failed or skipped send (§4.1); STALL_NS (2 ms, §4.3) and the 200 µs control-queue drain stay; no shelling out; no new crate.

*Choice:*
- The pacer sends one `sendmsg` per datagram and the receiver reads one `recvmsg` per datagram; batching through the private `sendmsg_x`/`recvmsg_x` is deferred (#70). A send that fails is recorded as on Linux (`send_eagain` when the send buffer is full, else `send_error {errno}`), with `burned_id` null (`tx_ids: none`); there is no `send_partial`. `ENOBUFS` from a full interface output queue is therefore observed per datagram where the stack reports it; a datagram the interface's own queue management drops after the send returned is not (§9.6).
- The pacer and receiver threads set `QOS_CLASS_USER_INTERACTIVE` (`pthread_set_qos_class_self_np`), the class with the least timer tolerance (R-0017).
- The pacer sleeps with `mach_wait_until` until `SPIN_NS` before the next deadline and then spins on `mach_absolute_time`, still draining the control queue at least every 200 µs. `SPIN_NS` is a `pt-sys` platform constant: 200 µs on Linux (as in §1) and 500 µs on macOS, where a coalesced wakeup can be later. A wakeup late by more than STALL_NS is a stall, skipped and recorded (§4.3), never a burst.
- For the whole session (from before P0 until the trace is written) the probe holds an IOKit power assertion of type `kIOPMAssertPreventUserIdleSystemSleep` named "pathtrace probe session" (`IOPMAssertionCreateWithName`, released with `IOPMAssertionRelease`), linked from `pt-sys` as the IOKit and CoreFoundation frameworks. It records `power_assertion {held, error}` once; a session continues without it. The assertion does not prevent sleep on lid close, the Apple menu or low battery (R-0017); such a sleep is a suspend (§4.3, §9.1).

*Alternatives rejected:* spawning `caffeinate -i` (shelling out, and its lifetime is not the session's); no assertion, which lets an idle laptop sleep in the middle of a `deep` profile or a long `--track-secs`; a 200 µs spin on macOS, which a tolerance-shifted wakeup overshoots; spinning without sleeping, which holds a core for the whole session on battery.

*Rationale:* at the 500 Mbit/s cap with 1500-byte packets the pacer has 24 µs per datagram, which one `sendmsg` per datagram is expected to fit; where it does not, the pacer falls behind visibly (`tx_user_lag`, `stall`) rather than silently. `SPIN_NS` trades CPU for accuracy only on the pacer thread.

*Validated by:* the macOS evidence (#66): the p99 of `tx_user_lag` on an idle host stays below 50 µs and a `standard` session at the rate cap records no `stall {cause: "late"}`; otherwise `SPIN_NS` is raised by a design change.

### 9.5 Path MTU and ICMP without an error queue

*Problem:* on Linux the PMTU ladder sends with `IP_PMTUDISC_PROBE` (DF set, the route's cached PMTU ignored) and reads ICMP errors, including Packet Too Big, from the error queue (`icmp` events). macOS has `IP_DONTFRAG`/`IPV6_DONTFRAG` but no error queue (R-0017), so the initiator sees no ICMP error.

*Constraints:* the ladder stays non-adaptive (§6); an unobservable fact is unknown, never "none happened" (REQ-PRB-033); the responder side keeps its Linux behaviour.

*Choice:* macOS probe sockets set `IP_DONTFRAG` (IPv4) or `IPV6_DONTFRAG` (IPv6) to 1. A ladder size above the egress interface MTU is not scheduled (the ladder caps at that MTU, §6). A send rejected locally fails with `EMSGSIZE` and is a `send_error {errno: EMSGSIZE}` event, with no `tx` row, so it is never path loss; where XNU has lowered the route's MTU after an ICMP Packet Too Big, later sends of larger sizes fail the same way, and the event's size against `endpoint.iface.mtu` tells that case (a size at or below the interface MTU) from the local limit. The path MTU a→b is the largest ladder size the responder received (`mtu.ladder`), as on Linux. The initiator records no `icmp` or `local_error` events, and each of its sockets records `icmp_errors: false` in META (PTF 1.2; `true` on Linux, where `IP_RECVERR` is enabled). Since the absence of an ICMP error is then not evidence, the black-hole verdict for a direction whose sender recorded `icmp_errors: false` is unknown (`blackhole: null`, §9.10), while `path_mtu` stays known. The b→a direction is unchanged: the Linux responder reads its ICMP errors.

*Alternatives rejected:* a raw ICMP socket to watch for Packet Too Big, which needs privileges; inferring black holes from silence alone, which would report every path whose ICMP errors the Mac cannot see as a black hole.

*Validated by:* derive unit tests (#63): a trace whose sender has `icmp_errors: false` and loses the larger ladder sizes reports `path_mtu` and `blackhole: null`; a Linux trace keeps `blackhole: true`.

### 9.6 Counters macOS cannot observe

*Problem:* derivation separates host drops from path loss with per-socket receive drops (`SO_RXQ_OVFL`) and qdisc drops (§4.2). macOS has neither; it has a host-wide UDP counter `udps_fullsock` (datagrams not delivered because the receiving socket was full, read with sysctl `net.inet.udp.stats`) and no output-queue drop counter (`ifi_oqdrops` does not exist, R-0017).

*Constraints:* REQ-PRB-033: a fact the platform cannot observe is recorded and derived as unknown, never as 0, so that derivation does not read it as "no loss"; a host-wide counter may be used only where its value can be attributed to the probe's sockets.

| Fact | Linux | macOS initiator | Recorded as |
|---|---|---|---|
| Per-socket receive drops | `SO_RXQ_OVFL` → `rxq_drops` | none (#72) | `rxq_drops` null, socket `rxq_ovfl: false` |
| Host-wide UDP socket-full drops | `netstack.udp_rcvbuf_errors` | `udps_fullsock` | `netstack.udp_fullsock` (PTF 1.2); the Linux columns null |
| Softnet backlog drops | `/proc/net/softnet_stat` | none | `softnet_dropped`, `softnet_squeezed` null |
| Egress qdisc and interface output-queue drops | `qdisc` table | none (no qdisc; the interface's queue management exposes no drop count) | no `qdisc` rows; META `endpoint.qdisc` and `txqueuelen` null |
| Interface counters | `/proc/net/dev` → `ifstats` | `getifaddrs` `if_data` | `ifstats` (`rx_dropped` from `ifi_iqdrops`; `tx_dropped` null, the column declared nullable as PTF 1.2 allows) |
| Wi-Fi link state | nl80211 → `wifi` | none (#68) | no `wifi` rows |
| TCP state | `TCP_INFO` → `tcpinfo` | `TCP_CONNECTION_INFO` | `tcpinfo_darwin` (§9.7) |

*Choice:* each unobservable value is null or absent, and the derived fields that would read it have status `unknown` with a `reason` and no counts:
- `PATH.b_to_a.host_drops` (receiver a): with no `rxq_drops`, it falls back to the host-wide counter where that is conclusive. If the receiver's `udp_fullsock` did not increase over the session (last minus first over the whole session, with no `iface_change` segmentation: unlike the qdisc counter, which restarts when the sampler follows a new interface, this host-wide counter never resets on an interface change, so a split would drop the rise across each boundary and could report a real socket-full drop as 0; a decrease between consecutive rows, which only a counter wrap or a reboot produces, makes the status `unknown` with `reason: "host-wide counter decreased"`), no UDP socket on the host was dropped into, so the probe's sockets dropped nothing: status `known`, `packets: 0`, method `hostdrop.host-fullsock/1`, `source: ["netstack"]`. If it increased, which socket dropped is unknown: status `unknown`, `reason: "host-wide counter rose"`, and `host_socket_drops` (the increase) as context. Without either counter the field is exactly the `hostdrop.rxq-gap/1` output it is today, reason text included (`unknown`, `reason: "no rxq_drops in this trace (PTF 1.0)"`), so every trace without `udp_fullsock`, Linux and PTF 1.0 traces included, derives unchanged; a macOS trace always records `udp_fullsock` unless sysctl failed, and in that rare case the 1.0 text, though it names the 1.0 format, still states the true cause.
- `PATH.a_to_b.local_qdisc_drops` (sender a): no `qdisc` table, so status `unknown` with `reason: "no qdisc counters recorded"`. `udps_fullsock` is never used here, nor `ifi_oerrors`, which counts output errors, not queue drops.
- Unknown values never enter an estimate as 0: the loss-based methods that exclude host drops (derivation.md, Host drops) exclude none when host drops are unknown, as for a PTF 1.0 trace, and the field says so.

`trace info` shows the unknown status and its reason in place of counts (cli.md).

*Alternatives rejected:* writing 0 for an unobservable counter, which derivation and readers cannot tell from "nothing dropped"; attributing every rise of `udps_fullsock` to the probe, which turns another application's drops into the path's host drops; leaving `udps_fullsock` out, which loses the one case (no rise) where it proves that nothing was dropped.

*Validated by:* derive unit tests (#63) on macOS-shaped tables: no counter → `unknown`; a flat `udp_fullsock` → `known`, 0; one that rises only across an `iface_change` → `unknown`; a rising one → `unknown` with `host_socket_drops`; no `qdisc` table → `unknown`; and the Linux golden traces derive unchanged.

### 9.7 TCP state

*Problem:* `TCP_INFO` does not exist on macOS; `TCP_CONNECTION_INFO` returns `struct tcp_connection_info`, whose fields, units and layout differ (`tcpi_srtt` in ms, `tcpi_snd_cwnd` in bytes, R-0017). The `tcpinfo` columns mean Linux `struct tcp_info` fields.

*Choice:* the tcp thread samples `TCP_CONNECTION_INFO` every 10 ms into a new table `tcpinfo_darwin` (PTF 1.2), never into `tcpinfo`. A trace has `tcpinfo[a]` or `tcpinfo_darwin[a]` depending on the initiator's platform; the responder's `tcpinfo[b]` is unchanged.

*Alternatives rejected:* mapping Darwin fields onto `tcpinfo` columns of similar names, which gives a column a second meaning (forbidden by the compatibility contract) and silently mixes units.

*Validated by:* a `pt-sys` loopback TCP test on macOS (#61) that `optlen` equals the struct size and `srtt` and `txbytes` are filled.

### 9.8 Host identity

META `endpoint` already has `os` (a display name such as "Ubuntu 24.04.1 LTS"), `kernel` (the kernel release) and `arch`. PTF 1.2 adds `os_family` (`linux` or `darwin`) and `os_version` (Linux: `VERSION_ID` from `/etc/os-release`; macOS: sysctl `kern.osproductversion`, e.g. `15.6`), so a consumer can branch on the platform without parsing `os`. On macOS `os` is "macOS " followed by `os_version`, `kernel` is sysctl `kern.osrelease` (the Darwin release, e.g. `24.6.0`), `cpu` is sysctl `machdep.cpu.brand_string`, and `clocksource` is absent.

### 9.9 Overlay paths (both platforms)

*Problem:* when the route to the peer leaves through a tunnel (Tailscale, WireGuard, another VPN), every packet the probe sends, of every class and transport, with every DSCP and ECN codepoint, is encapsulated into one UDP flow between the tunnel endpoints. The network between them then treats all classes alike and sees the tunnel's own header, so what PathTrace measures for per-transport treatment, port- or protocol-keyed policers, DSCP and ECN, and the MTU is the tunnel's behaviour, not the underlying network's. Delay, jitter, loss, capacity and reorder stay end-to-end measurements of the path the traffic takes, overlay included. This applies to Linux endpoints too (`tailscale0`, `wg0`).

*Constraints:* the central rule: a trace records path behaviour, and an overlay is part of the path the user's traffic takes, so the probe does not refuse it; no shelling out (`tailscale status`, `wg`); additive format changes only; the verdicts must not be dropped, only qualified.

*Choice:*
- **Detection** (context sampler, at start and at every `iface_change`, §4.4): the egress interface toward the peer is a tunnel when, on Linux, its rtnetlink link kind (`IFLA_INFO_KIND`) is `wireguard`, `tun`, `ipip`, `sit`, `gre`, `ip6tnl`, `vti` or `xfrm`, and on macOS its name starts with `utun`, `ipsec`, `tun` or `tap` (NetworkExtension VPNs, Tailscale and the WireGuard app included, use `utun`). The provider hint is `tailscale` when the local address on that interface lies in 100.64.0.0/10 or fd7a:115c:a1e0::/48 (Tailscale's address ranges), else null.
- **Record:** META `endpoint.iface.tunnel {kind, provider}` (PTF 1.2; absent when the interface is not a tunnel), with `kind` the link kind on Linux and the name prefix on macOS. `endpoint.iface.mtu` is already the tunnel's MTU. An `iface_change` event carries the same `tunnel` key inside its `iface` detail. The responder records its own egress interface the same way.
- **Derive:** a new top-level field `PATH.overlay` (method `overlay.egress-iface/1`): `overlay` (true when either endpoint's egress toward the peer was a tunnel at any time in the session), `endpoints` (which), `kind`, `provider`, `mtu` (the smallest tunnel MTU) and `overlay_ns` (time under a tunnel). When `overlay` is true, the fields whose verdicts describe the tunnel carry `overlay_limited: true`: every PLCY class entry (per-transport treatment), and per direction `policer`, `mtu`, `ecn` and `dscp`. `capacity`, `base_delay`, `jitter`, `loss`, `reorder` and `queue` are not flagged. `trace info` shows `PATH.overlay` (cli.md), and `doctor` warns before a session (cli.md).

*Alternatives rejected:* refusing to probe through a tunnel, which drops a path users really use; probing the underlay instead, which needs the responder's public address and bypasses the user's routing; guessing an overlay from the traffic (TTL, MTU, delay), which is unreliable where the interface states it directly; dropping the tunnel-limited verdicts, which loses what they do say about the tunnel.

*Rationale:* the tunnel is a fact of the endpoint, observable without privileges, and the qualification is a key added to fields whose values do not change, so traces of non-overlay paths derive exactly as before.

*Validated by:* `context::tests` (#63): classification of Linux link kinds, macOS interface names and Tailscale address ranges; derive unit tests: an overlay trace flags the five verdict groups and no others, and a non-overlay trace has `overlay: false`; the macOS evidence (#66) includes a session over Tailscale.

### 9.10 Derivation changes

These rules take effect with the implementation (#63), which moves them into derivation.md's method tables:

| Method | Change |
|---|---|
| `policy.matrix/2` | An echo's transmit time follows the direction rule (SND, else SCHED, else user, §9.2). A UDP class is reachable when an echo arrived, whether or not its transmit time is known (`/1` read only `tx_sched`, so a trace without TX stamps reported every UDP class unreachable) |
| `mtu.ladder/2` | `blackhole` is null when the direction's sender recorded `icmp_errors: false` (§9.5); otherwise as `/1` |
| `hostdrop.host-fullsock/1` | New: host drops at a receiver without `rxq_drops`, from `netstack.udp_fullsock` (§9.6) |
| `hostdrop.rxq-gap/1`, `qdisc.drop-count/2` | Unchanged results, `unknown` reason text included; both already carry a `reason` on an `unknown` status (§9.6) |
| `overlay.egress-iface/1` | New: `PATH.overlay` and the `overlay_limited` key (§9.9) |
