# EXP-0002-r15: Ground-truth recovery across 31 scenarios and the netns suite, on Linux after the macOS capture path

- verdict: **fail**, netns suite 12 of 12, ground truth 147 of 148 checks
- pinned commit: see `manifest.toml` (main at 6b1112b, which includes #83 and #92, plus the experiment definition)
- supersedes: [EXP-0002-r14](../EXP-0002-r14-ground-truth-recovery/) (148 of 148)
- requirements: see `experiment.toml`

## Method

The #63 acceptance asks that the Linux netns tests and `cargo xtask groundtruth all` show no regression after the macOS capture path (#83: 200 µs pacer spin before each deadline, user TX fallback in PLCY when `tx_sched` is null, unknown host and local-qdisc drop counters). The command runs the netns integration suite (`mise run test-netns`'s command) and then the same ground-truth suite as r14 (`--jobs 1`) on the same Linux host (Fedora 44, kernel 7.2.4, 16 hardware threads).

Host load: the host was shared with other users' compile jobs for the whole run. The 1-minute load average was 1.63 at the start, 37.30 at 16:04:48 local time, 9.34 at 16:23:54 and 17.33 at the end of the 2588 s run; r14 ran at 1.7 to 2.1.

## Result (full table in `artifacts/results.md`)

- Netns suite: 12 tests run, 12 passed (`artifacts/stdout.log`).
- Ground truth: every check passes except one. `aqm-ecn` derived the a→b discipline as `droptail` instead of `aqm_suspected`. Its other checks pass: ECT(0) and ECT(1) were marked by fq_codel, and capacity was 19.84 against 19.82 Mbit/s. The scenario ran from 16:05:38 to 16:07:10, one minute after the load peak of 37.
- `geo-100m`: saturated time b→a 7.95 s (≥ 6.5), a→b 4.13 s (≥ 3), capacity within 0.1% both ways.
- `rcvbuf`: 287 socket drops recorded (`rxq_drops`), all 287 attributed to the receiving host. This matches the responder's `RcvbufErrors` increase, and the drops were not taken for a policer.
- `local-qdisc` and `local-qdisc-predicted`: 528 and 602 send failures recorded, and TX stamps stayed aligned (0 implausible joins) with both exact and predicted transmit ids.
- REQ-FMT-015 in every standard/deep scenario is ≤ 8 B/packet, between 5.357 (`nat-timeout`) and 7.966 (`rate-step`). This is higher than r14 (5.3 to 6.6); r12 showed the same rise under host load.

## Interpretation

- The netns suite shows no regression.
- The one ground-truth failure matches EXP-0002-r12, where `aqm-ecn` gave the same `droptail` result while the host was saturated, before #63 existed. It did not reproduce: right after the run, `cargo xtask groundtruth aqm-ecn` at the same commit on the same host passed 3 of 3 times (`aqm_suspected` each time) at 1-minute load averages between 14.8 and 29.5. That rerun is outside this manifest. We read this failure as host contention, not a regression, but this run does not show it. A quieter rerun supersedes it (EXP-0002-r16).
