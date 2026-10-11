# EXP-0002-r6: Ground-truth recovery and netem closure (re-run for 1.0.1: doctor warm-up fix)

- verdict: **fail**, 88 of 89 checks (11 per-packet rows `n/a`, as before)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r5](../EXP-0002-r5-ground-truth-recovery/) (passed; went stale when `crates/pathtrace/src` changed for the doctor fix)
- requirements: see `experiment.toml`

## Result

Every check passes except one: in `loss-gemodel`, the 95% Wilson interval for Gilbert-Elliott p is 2.09–4.81%, which just excludes the true 2% (`artifacts/results.md`). All other recovery values match r5 within run-to-run variation. Examples: capacity 19.75 / 9.88 Mbit/s, buffers 149 365 / 74 662 B, delay sum 25.005 ms, rate-step NRMSE 1.29%, standard @ 100 Mbit/s = 2.02 MB, packet tables 5.2–7.5 B/packet.

## Analysis: an acceptance-criterion defect, not an estimator defect

Each run checks four 95% intervals: p and r in `loss-random` and in `loss-gemodel`. Even with a perfect estimator, at least one of four independent 95% intervals misses with probability 1 − 0.95⁴ ≈ 19% per run. Across the five runs with the current loss code (r2–r6), 1 of 20 interval checks missed, which is the nominal 5%. The p-interval midpoints for `loss-gemodel` (2.4, 2.5, 2.7, 1.3, 3.4%) scatter around the truth with no significant bias. The earlier passes were partly luck. The criterion "all four 95% intervals cover the truth" is miscalibrated as a per-run gate.

## Fix

- The trace now records the Gilbert-Elliott transition counts behind p and r (additive PATH keys), so that any reader can compute intervals at any level.
- The ground-truth checker uses a family-wise 95% level (Bonferroni over the 4 interval checks: each at 98.75%, z = 2.498), computed from those counts.
- Re-run as EXP-0002-r7. The estimator is unchanged.
