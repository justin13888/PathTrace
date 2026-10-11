# REQ-SCOPE: product boundaries

### REQ-SCOPE-001: Linux only
- status: met
- spec: §2.2, §3, §6.8
- adr: 0002
- evidence: EXP-0007-r3

Every role (initiator, responder, tooling) runs on Linux only: x86_64 and aarch64, kernel 6.1 or newer. No code paths, configuration or CI exist for macOS, Windows, Android or iOS.

### REQ-SCOPE-002: Two endpoints, one path
- status: met
- spec: §2.2
- evidence: EXP-0007-r3

A trace describes exactly one path between exactly two endpoints. No topology, multi-hop or multipath modelling.

### REQ-SCOPE-003: Path behaviour, never protocol achievement
- status: met
- spec: §1
- evidence: EXP-0007-r3

A trace records what the path does to packets. Throughput achieved by a protocol is never an input to the path model; reference-flow results are stored only as validation ground truth (VALD), separate from the model.

### REQ-SCOPE-004: Excluded problem areas
- status: met
- spec: §2.2
- evidence: EXP-0007-r3

PathTrace does not model competing flows, does not provide chaos or fault injection, does not replay packet captures, does not decode protocol internals and does not attempt internet-scale measurement.

### REQ-SCOPE-005: Access-network rates
- status: met
- spec: §2.2, §6.7
- evidence: EXP-0002-r4, EXP-0007-r3

Target paths run at up to 1 Gbit/s. The probe enforces a hard sending-rate cap (default 500 Mbit/s).

### REQ-SCOPE-006: IPv4 and IPv6
- status: met
- spec: §6.6, §9.3
- adr: 0013
- evidence: EXP-0002-r4

A session measures over one primary address family, either IPv4 or IPv6. When the responder name resolves to both families, TCP class reachability is also probed over the secondary family.

### REQ-SCOPE-007: Own endpoints only
- status: met
- spec: §3, §6.7
- evidence: EXP-0006-r2

The probe only ever exchanges traffic with a responder operated by the user and authenticated by key.

### REQ-SCOPE-008: UDP class reachability on the secondary family
- status: deferred
- spec: §6.6
- adr: 0013
- issue: #21

UDP classes (`udp/high-port`, `udp/443`, QUIC-shaped) are also probed for reachability over the secondary address family.
