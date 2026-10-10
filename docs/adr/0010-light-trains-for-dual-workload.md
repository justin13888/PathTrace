# 0010: Add periodic light packet trains to the light observer flow (dual-workload recording)

- status: accepted
- date: 2026-10-10
- requirements: REQ-PRB-010, REQ-DRV-005, REQ-FMT-020
- evidence: R-0002, R-0003

## Context

Draft spec §6.5 claimed CellReplay's dual-workload idea "generalised beyond cellular" through a light isochronous flow (50 packets/s, 100 B). First-hand reading of CellReplay (R-0002) shows its light workload is different: every G ms it sends U back-to-back MTU-sized packets and records per-train arrival offsets ("light PDOs"). Replay splices a light-PDO prefix onto the heavy-PDO suffix. A 100-byte isochronous flow cannot measure light delivery opportunities. NeuralEmu (R-0003) adds that saturation perturbs the scheduler, so what a short burst experiences differs from what a saturating flow experiences.

## Options considered

1. **Keep only the light flow** and drop the CellReplay equivalence claim. This loses the light-workload capacity view that the deferred simulator would need for short-transfer workloads (request/response).
2. **Replace the light flow with trains.** This loses the continuous small-packet delay and loss series (jitter, intrinsic loss, base delay at 20 ms granularity).
3. **Both**: keep the isochronous light flow (delay, loss and jitter observer) and add periodic light trains, U back-to-back MTU packets every G ms in each direction, throughout the session.

## Decision

Option 3. Defaults: U = 8 packets of path-MTU size, G = 500 ms, in both directions, for the whole session. `light` profile: U = 4, G = 2 s. Trains record per-packet arrival times, so derivation produces per-train dispersion (`capacity_light`). Trains that coincide with saturation phases are tagged with their workload context, because they share the bottleneck queue with the heavy flow (CellReplay used two devices to avoid that; PathTrace records the overlap instead of hiding it).

Data cost: 8 × 1500 B × 2 directions / 0.5 s ≈ 48 kB/s, so about 4.3 MB per 90 s standard session. That is well within the 200 MB cap.

## Consequences

- PTF gains `capacity_light` as per-train arrival offsets with train parameters, and capacity segments gain a `workload` provenance field.
- Light-flow (100 B) and train (MTU) packets give a delay-versus-size relation (`size_delay`) at no extra cost.
- The probe's pacing must emit trains back-to-back (one `sendmmsg` batch) while staying out of the way of the light flow's schedule.
