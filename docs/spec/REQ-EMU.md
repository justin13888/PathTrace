# REQ-EMU: emulator, runner, fidelity (deferred)

These requirements come from the original draft spec (§9–§11). They are deferred beyond the capture-ready release, and each one is tracked by a GitHub issue. PTF is designed so that they need no format change: see docs/design/simulator-requirements.md. A simulator that meets an older trace re-derives it, or treats missing fields as `unknown`.

### REQ-EMU-001: Deterministic model core
- status: deferred
- spec: §9.1, §9.2, §9.5, §13.3
- issue: #1

A pure, I/O-free path model (classify, policy, NAT, MTU, queue, link, loss, delay, duplicate) gives bit-identical verdicts for identical trace, seed and input. It is property-tested for conservation, monotonic time and determinism.

### REQ-EMU-002: Real-time driver
- status: deferred
- spec: §9.3, §9.6, §9.8
- issue: #2

Three namespaces joined by veth pairs, configured over netlink, with offloads disabled, AF_PACKET rings and pinned sleep-then-spin threads. Release-time self-monitoring invalidates runs whose p99 error exceeds the threshold, and `emu calibrate` measures the host.

### REQ-EMU-003: Virtual-time driver
- status: deferred
- spec: §9.7
- issue: #3

The model core runs in virtual time for sans-IO protocol implementations, fully deterministically.

### REQ-EMU-004: Replay modes
- status: deferred
- spec: §9.4
- issue: #4

Replay modes are `exact` (recorded series), `model` (synthesised from fitted models with a seed) and `stress` (scaling factors).

### REQ-EMU-005: Runner, scenarios, statistics
- status: deferred
- spec: §10
- issue: #5

Scenario files cover traces × workloads × protocols. The runner implements the protocol contract (environment variables, JSON Lines events, black-box fallback) and reports paired per-trace ratios with bootstrap intervals per network class.

### REQ-EMU-006: Plain HTTP baseline
- status: deferred
- spec: §10.3
- issue: #6

`pathtrace-ref` provides an HTTP/1.1-over-TLS client and server on kernel TCP (one connection and six connections), isolated from measurement code.

### REQ-EMU-007: Fidelity scoring
- status: deferred
- spec: §11.3
- issue: #7

Each trace receives a fidelity score comparing the recorded reference flows (VALD, captured today) with the same flows replayed through the emulator.

### REQ-EMU-008: Round trip through the emulator
- status: deferred
- spec: §11.2
- issue: #8

Probing through the emulator replaying trace T reproduces T within the §11.2 tolerances.

### REQ-EMU-009: Cross-tool agreement
- status: deferred
- spec: §11.4
- issue: #9

The same imported Mahimahi trace replayed on Mahimahi, Rattan and PathTrace gives agreeing reference-flow results.

### REQ-EMU-010: AQM emulation stages
- status: deferred
- spec: §9.2, §14
- issue: #10

The queue stage supports CoDel and FQ-CoDel with ECN marking.
