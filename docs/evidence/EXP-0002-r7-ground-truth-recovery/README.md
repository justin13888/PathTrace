# EXP-0002-r7: Ground-truth recovery and netem closure (1.0.1: GE counts, family-wise interval check)

- verdict: **fail**, 88 of 89 checks (11 per-packet rows `n/a`)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r6](../EXP-0002-r6-ground-truth-recovery/) (failed: a per-run gate over four 95% intervals was miscalibrated)
- requirements: see `experiment.toml`

## Result

- The new family-wise Gilbert-Elliott checks pass. They use 98.75% Wilson intervals computed from the transition counts that the trace now records: `loss-random` 14/706 good→bad, 14/14 bad→good; `loss-gemodel` 14/692, 14/27.
- All other values match earlier runs: capacity 19.74 / 9.89 Mbit/s, buffers 149 283 / 74 847 B, delay sum 25.005 ms, rate-step NRMSE 1.12%, standard @ 100 Mbit/s = 1.91 MB, packet tables 5.0–7.0 B/packet.
- One check fails: `aqm-ecn` "ECT(0) marked by fq_codel" got `passed`.

## Analysis: an over-specified check on rare events

fq_codel marked only 6 packets in this session (`artifacts/aqm-ecn/qdisc_stats.txt`, `ecn_mark 6`; 4–13 across all earlier runs). During saturation, the only ECT traffic is the light flow's codepoint cycle, and fair queuing gives that flow its own sub-queue, which rarely exceeds CoDel's target. This run's marks landed on ECT(1) light packets (derived `ect1: marked`) and none on ECT(0) (`ect0: passed`). The derived per-codepoint record is a correct description of what was observed. The check was wrong to require ECT(0) specifically, because fq_codel with `ecn` treats ECT(0) and ECT(1) identically. The truth is "ECT packets are marked".

## Fix

- The checker now accepts a CE mark observed on either ECT codepoint.
- Re-run as EXP-0002-r8.
- The thinness of the marking evidence under fair-queuing AQM is a real limit of `tos.light-cycle/1`. It is filed as #27 (a path-level marking summary with counts) and shown as a limit on S13 in the sufficiency table.
