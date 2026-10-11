# REQ-DRV: derivation (raw observations → path model)

### REQ-DRV-001: Pure and re-runnable
- status: met
- spec: §8
- design: docs/design/derivation.md
- evidence: EXP-0007-r5

Derivation is a deterministic, pure function of the raw layer. `pathtrace derive` regenerates the derived sections (PATH, SERS, PLCY, VALD) of any trace, old or new, and leaves raw sections byte-identical.

### REQ-DRV-002: Clock model
- status: met
- spec: §6.3, §8
- evidence: EXP-0002-r5

Clock offset uses a minimum filter over exchanges and skew a lower-envelope fit. The model is stored with its uncertainty, bounded by half the minimum round-trip time.

### REQ-DRV-003: Base delay
- status: met
- spec: §8, §4
- evidence: EXP-0002-r5

Base delay is a piecewise sliding-window minimum of light-flow delay. The split between directions is stored with its method (`symmetric_assumed` unless clocks are verified synchronised).

### REQ-DRV-004: Capacity
- status: met
- spec: §8, §7.4
- evidence: EXP-0002-r5

Heavy-flow arrivals during valid saturation become delivery opportunities (`saturated`). Chirp estimates fill other periods (`estimated`), and everything else is `unknown`.

### REQ-DRV-005: Light-workload capacity view
- status: met
- spec: §7.4
- adr: 0010
- evidence: EXP-0002-r5

Per-train arrival offsets of the light trains are stored as the light-workload view of the path (`capacity_light`), with train parameters and workload context, for dual-workload replay.

### REQ-DRV-006: Queue depth and discipline
- status: met
- spec: §8
- evidence: EXP-0002-r5

Queue depth (bytes and time) comes from peak queueing delay before loss onset, cross-checked against drain time. The discipline hint is `droptail`, `aqm_suspected`, `policer` or `unknown`.

### REQ-DRV-007: Policer
- status: met
- spec: §8, §7.4
- evidence: EXP-0002-r5

A token-bucket policer (rate, burst) is detected per class: loss without delay growth, with an initial burst followed by a plateau.

### REQ-DRV-008: Loss model
- status: met
- spec: §8
- evidence: EXP-0002-r5

Intrinsic (non-congestive) loss events are kept. A Gilbert-Elliott model is fitted from run lengths, with confidence intervals.

### REQ-DRV-009: Jitter model
- status: met
- spec: §8, §7.4
- evidence: EXP-0002-r5

Jitter is the light-flow delay residual over base delay in quiet periods, stored as the series plus an empirical distribution and autocorrelation.

### REQ-DRV-010: Reordering and duplication
- status: met
- spec: §7.4
- evidence: EXP-0002-r5

Reordering rate with its displacement distribution, and duplication rate, per direction.

### REQ-DRV-011: MTU, ECN, DSCP, policy matrix
- status: met
- spec: §8, §6.6
- evidence: EXP-0002-r5

Path MTU with the black-hole flag, ECN and DSCP handling, and the per-class policy matrix derived from class probes.

### REQ-DRV-012: Named, versioned methods
- status: met
- spec: §7.5
- evidence: EXP-0007-r5

Every derivation method has a stable name and version (`capacity.saturated-arrivals/1`). Changing a method's output semantics bumps its version.

### REQ-DRV-013: Ground-truth recovery
- status: met
- spec: §11.1, §11.2
- design: docs/design/simulator-requirements.md
- evidence: EXP-0002-r5

Captured through namespaces with known kernel-imposed impairments, derivation recovers the truth within these tolerances: capacity series NRMSE ≤ 10%, base delay within 1 ms, queue depth within 15%, loss-model intervals covering the truth, policy matrix identical.

### REQ-DRV-014: Closure under independent replay
- status: met
- spec: §11.2
- design: docs/design/simulator-requirements.md
- evidence: EXP-0002-r5

A trace derived from ground truth, exported to netem, re-imposed and re-probed yields a trace matching the original within the REQ-DRV-013 tolerances (static parameters).

### REQ-DRV-015: Proxy suspicion
- status: planned
- issue: #22
- spec: §6.6, §4

A TCP-terminating proxy is flagged when TCP handshake RTT is far below the UDP minimum RTT, or when the SYN seen by the responder differs from the one sent.
