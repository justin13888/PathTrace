# EXP-0002-r10: Ground-truth recovery and netem closure across 30 scenarios (1.1, 3 scenarios at a time)

- verdict: **fail**, 138 of 141 checks: only the REQ-FMT-015 bytes/packet budget fails, in `geo` (8.875), `bufferbloat` (8.354) and `deep` (8.040 B/packet; budget ≤ 8)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r9](../EXP-0002-r9-ground-truth-recovery/) (failed on the same check in `geo` alone)
- requirements: see `experiment.toml`

## Method

Same as r9, with `--jobs 3` instead of 6 so that the harness adds less load of its own.

Host load: the 1-minute load average was 12.4 at the start and 17.7 at the end of the 1260 s run (5- and 15-minute averages 18.8 and 16.3 at the end), on 16 hardware threads shared with other users. Between r9 and r10, `geo` run alone (`cargo xtask groundtruth geo`, not an evidence run) at load 12–16 measured 8.002 B/packet.

## Result (full table in `artifacts/results.md`)

Every recovery, safety and host-loss check passes again, with the same outcome as r9 (rcvbuf, local-qdisc, fast, data-cap, geo and bufferbloat behaviour checks all pass). The bytes/packet figures of the standard/deep scenarios are 6.3–7.7 apart from the three failures above; `deep` passed in r9 (7.81) and `bufferbloat` too (7.90).

## Interpretation

- The failures move between scenarios with the load (r9: `geo` only, at load 8–13; r10: `geo`, `bufferbloat`, `deep`, at load 12–19), which is the load dependence #38 describes: timestamp noise from host scheduling jitter raises the entropy of the delta-encoded time columns. The long-delay scenarios (`geo`, `bufferbloat`) are closest to the budget.
- Recovery and the 1.1 behaviour are confirmed twice. What remains open is REQ-FMT-015 on a quiet host: EXP-0002-r11 is defined for that run. If it fails on a quiet host too, the budget is a 1.1 regression for long-delay paths rather than a load effect, and needs its own issue.
