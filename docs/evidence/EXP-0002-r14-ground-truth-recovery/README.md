# EXP-0002-r14: Ground-truth recovery and netem closure across 31 scenarios (1.1, slotted rcvbuf delivery)

- verdict: **pass**, 148 of 148 checks
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r13](../EXP-0002-r13-ground-truth-recovery/) (145 of 148: `rcvbuf` saw no socket drops on a quiet host)
- requirements: see `experiment.toml`

## Method

Same as r13 (`--jobs 1`), with the `rcvbuf` scenario releasing a→b packets in 20 ms netem slots so that its 8 KiB receive buffer overflows whatever the host load (#54). Host load: the 1-minute load average was 2.07 at the start and 1.74 at the end of the 2510 s run (5- and 15-minute averages 1.77 and 2.05 at the end), on 16 hardware threads.

## Result (full table in `artifacts/results.md`)

- Every check passes.
- `geo-100m`: saturated time b→a 7.73 s (≥ 6.5), a→b 4.13 s (≥ 3), capacity within 0.1% both ways.
- `rcvbuf`: 183 socket drops recorded (`rxq_drops`), all 183 attributed to the receiving host, matching the responder's `RcvbufErrors` increase; not mistaken for a policer.
- REQ-FMT-015 in every standard/deep scenario: `bufferbloat` 6.283, `deep` 6.458, `geo` 6.586, `geo-100m` 5.694, `rate-100m` 5.318, `udp443-throttle` 6.314 B/packet (≤ 8).

## Interpretation

- On a host that stayed quiet for the whole run, 1.1 recovers every ground truth within tolerance, keeps the packet tables well inside the budget, and records and attributes host-side losses on both the send and the receive side.
- The r11–r13 failures were host contention (r11, r12) and a scenario that dropped only under load (r13), not 1.1 regressions.
