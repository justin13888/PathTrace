# EXP-0002-r8: Ground-truth recovery and netem closure (1.0.1: GE counts, family-wise intervals, ECT-either ECN check)

- verdict: **pass**, 89 of 89 checks (77 recovery + 12 per-packet size; 11 size rows `n/a` for smoke/light sessions)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r7](../EXP-0002-r7-ground-truth-recovery/) → [r6](../EXP-0002-r6-ground-truth-recovery/), both failed on acceptance criteria that were miscalibrated or over-specified (see their READMEs). Last pass before them: [r5](../EXP-0002-r5-ground-truth-recovery/).
- requirements: see `experiment.toml`

## Method

Same scenarios and harness as r3–r7. Two criteria were corrected, and each correction is recorded with its reason:
- **Gilbert-Elliott (S9):** p and r are judged at a family-wise 95% over the four interval checks of a run (each a 98.75% Wilson interval, z = 2.498), computed from the transition counts the trace now records (r6).
- **ECN (S13):** the truth is that fq_codel with `ecn` marks ECT packets, and a mark on ECT(0) or ECT(1) satisfies it (r7). The thinness of the marking evidence is tracked in #27.

## Result (selected; full table in `artifacts/results.md`)

| Stage | Check | Truth | Recovered |
|---|---|---|---|
| S6 | capacity a→b / b→a; 100 Mbit/s | 19.82 / 9.91; 99.08 Mbit/s | 19.75 / 9.89; 99.05 |
| S6 | rate-step NRMSE | ≤ 10% | 1.57% over 196 bins |
| S7 | light-train dispersion | 49.54 Mbit/s | 49.55 |
| S10 | delay sum; jitter σ | 25 ms; 4 ms | 25.005 ms; 4.18 ms |
| S5 | buffers a→b / b→a | 150 000 / 75 000 B | 149 357 / 74 734 B |
| S9 | GE p, r (98.75% each) | random p 2%, r 98%; gemodel p 2%, r 40% | p 0.65–3.0% / 0.86–3.5%; r 0.62–1.0 / 0.25–0.69 |
| S13 | ECN under fq_codel | ECT marked | ect0 marked, ect1 marked (7 marks in the session) |
| S12 | duplicates | 2% | 1.94% |
| S2 | UDP/443 ratio; policer | ~0.1; 4.95 Mbit/s | 0.107; 4.97 |
| S15 | closure | identical | capacity, buffer, delay within 0.1% |
| safety | dead-man stop | ≤ 600 ms | 505 ms |
| size | standard @ 100 Mbit/s; light file; packet tables | ≤ 10 MB; ≤ 200 kB; ≤ 8 B/packet | 1.94 MB; 58 kB; 5.3–7.5 B/packet |

## Interpretation

- The recovery results are stable across r3–r8. In r6 and r7 every recovered value was also within tolerance; each failed one check because of the criterion, not because of a recovery error.
- The sufficiency verdict stands. S13 is now `recovered-with-limits`, because under a fair-queuing AQM the evidence of marking rests on a few marks per session (#27).
