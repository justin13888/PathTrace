# EXP-0002-r13: Ground-truth recovery and netem closure across 31 scenarios (1.1, one scenario at a time)

- verdict: **fail**, 145 of 148 checks; all three failures are the `rcvbuf` scenario, which saw no socket drops
- pinned commit: see `manifest.toml` (with the `geo-100m` b→a saturated-time floor at 6.5 s, #54)
- supersedes: [EXP-0002-r12](../EXP-0002-r12-ground-truth-recovery/) (135 of 148 under load 38)
- requirements: see `experiment.toml`

## Method

Same as r12 (`--jobs 1`). Host load: the 1-minute load average was 15.12 at the start and 3.15 at the end of the 2512 s run (5- and 15-minute averages 4.81 and 7.12 at the end), on 16 hardware threads; the load fell during the run.

## Result (full table in `artifacts/results.md`)

- `geo-100m` passes: saturated time b→a 7.88 s (≥ 6.5), a→b 4.17 s (≥ 3), capacity within 0.1% both ways.
- REQ-FMT-015 holds in every standard/deep scenario: `bufferbloat` 7.319, `deep` 7.379, `geo` 7.296, `geo-100m` 6.047, `rate-100m` 5.764, `udp443-throttle` 6.460 B/packet (≤ 8).
- The three failures are `rcvbuf`: 0 socket drops (`rxq_drops`), 0 packets attributed to the receiving host, and no `RcvbufErrors` increase in the responder's netstack counters. The session completed and the discipline was not mistaken for a policer.

## Interpretation

- The `rcvbuf` scenario provokes drops only when the responder's receive thread falls behind a 100 Mbit/s paced stream into an 8 KiB buffer. That depends on scheduling: r12 (load 38) saw 80 drops, r11 (quiet start) 9, and this run, whose load fell as it went, none. With nothing dropped there was nothing to attribute, so these checks did not exercise the 1.1 attribution path rather than refute it. The scenario must drop deterministically for the run to measure it; the next run follows that harness change.
- Every other recovery, safety and 1.1 check passed, including the loosened `geo-100m` floor and the budget.
