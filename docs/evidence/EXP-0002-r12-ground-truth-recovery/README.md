# EXP-0002-r12: Ground-truth recovery and netem closure across 31 scenarios (1.1, one scenario at a time)

- verdict: **fail**, 135 of 148 checks; the host was no longer quiet (load 5 at the start, 38 at the end)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r11](../EXP-0002-r11-ground-truth-recovery/) (147 of 148: only `geo-100m` saturated time b→a, 6.56 s < 7)
- requirements: see `experiment.toml`

## Method

Same as r11 with `--jobs 1`, so the harness never runs two sessions at once. Between r11 and r12, `geo-100m` run alone (`cargo xtask groundtruth geo-100m`, not an evidence run) at load 3.5–8 measured 7.81 s and 7.73 s saturated b→a (≥ 7), so the r11 failure looked like contention between concurrent scenarios.

Host load: the 1-minute load average was 5.10 at the start and 37.78 at the end of the 2527 s run (5- and 15-minute averages 36.12 and 25.98 at the end), on 16 hardware threads; other users' compilations (rustc, cc1plus) took the host over during the run, and the load was 44.75 right after it.

## Result (full table in `artifacts/results.md`)

- 13 failures, all in scenarios that ran while the host was saturated: `geo-100m` (b→a capacity 77.6 Mbit/s, no a→b capacity, saturated time 0.15 s b→a), `loss-gemodel` (GE r interval misses the truth, loss reported b→a), `aqm-ecn` (discipline `droptail` instead of `aqm_suspected`), and the REQ-FMT-015 budget in `geo` 8.857, `geo-100m` 9.442, `bufferbloat` 9.899, `deep` 8.416, `rate-100m` 8.395 and `udp443-throttle` 8.061 B/packet.
- The 1.1 host-loss checks still pass under that load: rcvbuf (80 socket drops attributed to the host), local-qdisc (396 and 469 send failures, 0 implausible TX joins with exact and predicted ids), fast (no hard cap, 3 saturations ended by allowances), data-cap (1 004 406 B ≤ 1 MB + one batch).

## Interpretation

- This run measures the host, not the path: with the CPU oversubscribed more than twice, the pacers and receivers lose their schedule, which shows up as lost capacity, spurious loss and noisier timestamps (higher bytes/packet). It says nothing new about 1.1.
- r11, whose start was quiet, remains the best 1.1 figure: REQ-FMT-015 within budget everywhere (≤ 7.68 B/packet) and 147 of 148 checks. A passing run still needs a host that stays quiet for the whole run.
