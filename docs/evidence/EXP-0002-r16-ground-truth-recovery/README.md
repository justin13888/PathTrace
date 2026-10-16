# EXP-0002-r16: Ground-truth recovery across 31 scenarios and the netns suite, on Linux after the macOS capture path (re-run of r15)

- verdict: **fail**, netns suite 12 of 12, ground truth 147 of 148 checks
- pinned commit: see `manifest.toml` (main at 6b1112b plus the r15 evidence and this definition)
- supersedes: [EXP-0002-r15](../EXP-0002-r15-ground-truth-recovery/) (147 of 148, the same `aqm-ecn` check)
- requirements: see `experiment.toml`

## Method

Same command and host as r15, started right after it. Host load: the host was again shared with other users' compile jobs. The 1-minute load average was 19.43 at the start, 20.61 at 16:55:07 and 7.83 at 17:03:34 local time, and 27.65 at the end of the 2566 s run. `aqm-ecn` ran from 16:59:01 to 17:00:34.

## Result (full table in `artifacts/results.md`)

- Netns suite: 12 tests run, 12 passed (`artifacts/stderr.log`).
- Ground truth: every check passes except the one that failed in r15. `aqm-ecn` derived the a→b discipline as `droptail` instead of `aqm_suspected`. The trace recorded `ce_marks` 0 on the saturations, so the verdict rests on the loss-onset ratio (`queue.loss-onset/2`). ECT(0) and ECT(1) were marked by fq_codel, and capacity was 19.84 against 19.82 Mbit/s.
- `geo-100m`: saturated time b→a 7.83 s (≥ 6.5), a→b 4.19 s (≥ 3).
- `rcvbuf`: 214 socket drops recorded and attributed to the receiving host. `local-qdisc` and `local-qdisc-predicted`: 555 and 602 send failures, with 0 implausible TX joins.
- REQ-FMT-015 in every standard/deep scenario is ≤ 8 B/packet, between 5.408 and 7.651.

## Diagnosis outside this manifest (scratch runs on the same host, not pinned)

- Derivation is not the cause. Re-deriving this run's `aqm-ecn` trace with the derivation at EXP-0002-r14's pinned commit (5e309dc) also gives `droptail`.
- Capture at the earlier commit passes. `cargo xtask groundtruth all --jobs 1` at 5e309dc, run on this host from 17:33 to 18:15 at 1-minute load averages between 8 and 21, passed every check, and its `aqm-ecn` trace derived `aqm_suspected`.
- `aqm-ecn` alone at this run's code passed 3 of 3 times right after r15 (see r15's README).
- Overall: at this code the check failed in 2 of 2 full runs and passed in 3 of 3 single-scenario runs. At 5e309dc it passed in 3 of 3 full runs (r13, r14 and the scratch run) and failed in r12 (saturated host).

## Interpretation

- The netns suite shows no regression.
- The ground-truth suite does not show "no regression". The `aqm-ecn` discipline verdict moved to `droptail` twice at the current capture code, while the earlier capture code passed under comparable load. The cause is in what was captured, not in derivation. The capture changes since 5e309dc (macOS capture path #83, the macOS pacer #92, and the PTF 1.2 work) have not been bisected. Until a passing rerun supersedes this one, the requirements in `experiment.toml` have no current passing EXP-0002 run.
