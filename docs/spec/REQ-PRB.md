# REQ-PRB: probe and responder (capture)

### REQ-PRB-001: One symmetric binary
- status: planned
- spec: §6.1

One `pathtrace` binary acts as initiator (`probe`) or responder (`serve`). The roles differ only in who sends first, and measurement runs in both directions with the same code.

### REQ-PRB-002: Authenticated sessions
- status: planned
- spec: §6.2

Sessions are authenticated with Noise `IKpsk2` (X25519, ChaCha20-Poly1305, BLAKE2s), and the responder accepts only initiator keys listed in its authorized-keys file.

### REQ-PRB-003: Control channel with TCP fallback
- status: planned
- spec: §6.2

Control messages are delivered reliably over UDP. When UDP is blocked the session falls back to TCP port 443, records the UDP classes as blocked, and continues.

### REQ-PRB-004: Anti-amplification
- status: planned
- spec: §6.2

Before an initiator's address is validated, the responder sends at most three times the bytes it has received from that address.

### REQ-PRB-005: Dead-man switch
- status: planned
- spec: §6.2

A sender stops within 500 ms of losing authenticated feedback from its peer.

### REQ-PRB-006: Authenticated probe packets
- status: planned
- spec: §6.2

Probe packets carry an 8-byte keyed BLAKE3 tag derived from the session keys, and random padding so that compression cannot distort sizes. Packets with a bad tag are counted and never treated as observations.

### REQ-PRB-007: Clock observation
- status: planned
- spec: §6.3

Each side timestamps with CLOCK_MONOTONIC_RAW for scheduling and logs paired REALTIME/MONOTONIC_RAW readings throughout the session. Four-timestamp offset exchanges run on the control channel for the whole session.

### REQ-PRB-008: Best available packet timestamps, recorded
- status: planned
- spec: §6.3

Send and receive times use kernel `SO_TIMESTAMPING` (hardware, then software, then userspace fallback). The source actually used is recorded per flow and direction. Logs hold the actual transmit time, and the packet carries the intended send time.

### REQ-PRB-009: Probe header
- status: planned
- spec: §6.4
- design: docs/design/probe.md

Probe packets carry a fixed little-endian header (version and type, flow, phase, session, sequence, intended send time, train id and index, flags) followed by padding and the tag.

### REQ-PRB-010: Light observer flow and light trains
- status: planned
- spec: §6.5
- adr: 0010

For the whole session, in both directions, two workloads run. An isochronous light flow (50 packets/s, 100-byte payload) observes delay, loss and jitter without saturating. Periodic light trains (by default 8 back-to-back path-MTU packets every 500 ms) capture what short bursty load experiences.

### REQ-PRB-011: Measurement phases
- status: planned
- spec: §6.5

The standard profile runs handshake, reachability, quiet baseline, chirps, saturation in each direction, simultaneous saturation and per-class differential phases, plus background NAT-timeout, path-MTU, ECN and DSCP checks.

### REQ-PRB-012: Reference flows
- status: planned
- spec: §6.5, §11.3

The probe runs fixed reference workloads over the real path: TCP bulk transfer, TCP request/response and constant-rate UDP. It records application events, `TCP_INFO` every 10 ms and the congestion-control algorithm, as ground truth for future fidelity scoring.

### REQ-PRB-013: Saturation validity
- status: planned
- spec: §6.5

An arrival counts as a delivery opportunity only while the sender demonstrably had a backlog at the bottleneck. Other periods are recorded as unknown, never zero.

### REQ-PRB-014: Profiles with data caps
- status: planned
- spec: §6.5, §3

Profiles: `smoke` (about 15 s, deployment check), `light` (2 MB or less), `standard` (200 MB or less, about 90 s), `deep` (standard plus a configurable tracking period with periodic short saturations). Phase durations shrink to fit the cap.

### REQ-PRB-015: Transport policy probing
- status: planned
- spec: §6.6

For each class (`udp/high-port`, `udp/443 opaque`, `udp/443 QUIC-shaped`, `tcp/443 TLS`, `tcp/80`, `tcp/high-port`), the probe records per family: reachability, handshake RTT, capacity ratio and loss differential against the reference class, largest passing datagram, whether ICMP Packet Too Big returns, NAT binding idle timeout, port preservation and rebinding, ECN handling, DSCP handling and suspected TCP proxies.

### REQ-PRB-016: Safety limits
- status: planned
- spec: §6.7

Every session has a hard data cap and a hard rate cap. Saturation is feedback-controlled to hold a standing queue, and a metered connection selects `light` automatically.

### REQ-PRB-017: Timing-faithful Linux I/O
- status: planned
- spec: §6.8

Probe sockets use `sendmmsg`/`recvmmsg`, kernel timestamping, `IP_RECVTOS`/`IPV6_RECVTCLASS`, TTL/hop-limit reception and error-queue PMTU signals. UDP GSO/GRO stay disabled, and sending and receiving run on dedicated threads with sleep-then-spin pacing.

### REQ-PRB-018: Observation logs and merge
- status: planned
- spec: §6.9

Each side writes a crash-safe observation log. After the session the logs are merged over the control channel, or offline with `pathtrace merge`, into one trace.

### REQ-PRB-019: Context capture
- status: planned
- spec: new

The initiator records context that cannot be recovered later: interface type, driver and MTU; Wi-Fi link state over time (frequency, signal, bitrates, hashed BSSID); host interface byte counters (local competing traffic); address and route changes; metered state; and user tags (network class, label, mobility).

### REQ-PRB-020: Robust, partial-safe sessions
- status: planned
- spec: new

A failing phase never aborts a session; it is recorded as an event with its reason. A trace is always written, partial if necessary. The responder keeps its log per session so `pathtrace fetch` can recover it later.

### REQ-PRB-021: Versioned wire protocol
- status: planned
- issue: #23
- spec: new

Initiator and responder exchange protocol versions in the handshake and fail with a clear error on a major mismatch.

### REQ-PRB-022: Mobility survival
- status: planned
- spec: §6.6, §7.3

The session survives initiator address changes and NAT rebinding. Each change is recorded as an event.

### REQ-PRB-023: QUIC-shaped class
- status: planned
- spec: §6.6
- adr: 0006

The `udp/443 QUIC-shaped` class sends packets with valid QUIC v1 long- and short-header framing around opaque payload, recorded as shape level `header/1`.

### REQ-PRB-024: Genuine TLS on tcp/443
- status: planned
- spec: §6.6
- adr: 0006

The `tcp/443` class runs a real TLS 1.3 session. The responder certificate is pinned through the Noise-authenticated control channel.

### REQ-PRB-025: Preflight doctor
- status: planned
- spec: new

`pathtrace doctor` checks local prerequisites (timestamping support, clocks, offloads, keys) and reachability of the responder on every class port before a field session.

### REQ-PRB-026: Cryptographically faithful QUIC Initial
- status: deferred
- spec: §6.6
- issue: #14

The QUIC-shaped class sends an Initial packet that deep-packet inspection can decrypt to a valid ClientHello.

### REQ-PRB-027: Cellular modem metadata
- status: deferred
- spec: new
- issue: #15

Record cellular access technology, band and signal (ModemManager) as context.

### REQ-PRB-028: Field corpus
- status: user-acceptance
- spec: §2.3, §12
- issue: #16

At least 50 traces across at least 4 network classes are captured on real access networks and pass `trace check`.

### REQ-PRB-029: Synchronised-clock one-way delay
- status: deferred
- spec: §4, §7.4
- issue: #17

When both endpoints have a verified synchronised clock (for example PTP), the one-way delay split is measured (`synced_clocks`) instead of assumed symmetric.
