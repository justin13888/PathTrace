# EXP-0002-r11: Ground-truth recovery and netem closure across 31 scenarios (1.1, quiet host)

- verdict: **fail**, 147 of 148 checks: only `geo-100m` "saturated time b_to_a (s, ≥ 7)" fails, at 6.56 s
- pinned commit: see `manifest.toml` (main through #51 merged into the 1.1 evidence branch)
- supersedes: [EXP-0002-r10](../EXP-0002-r10-ground-truth-recovery/) (failed on the REQ-FMT-015 bytes/packet budget under host load)
- requirements: see `experiment.toml`

## Method

Same as r10 (`--jobs 3`), on the same host, with the scenario `geo-100m` (300 ms one way at 100 Mbit/s, issues #30 and #40) that main added since r10, so 31 scenarios.

Host load: the 1-minute load average was 3.45 at the start (5- and 15-minute 2.86 and 3.52) and 10.39 at the end (6.63 and 4.31) of the 1281 s run, on 16 hardware threads shared with other users. The start is the quiet host #42 asks for; other users' builds raised the load during the second half of the run.

## Result (full table in `artifacts/results.md`)

- REQ-FMT-015 holds in every standard/deep scenario: the highest packet-table cost is `geo` at 7.678 B/packet (r10: 8.875), then `geo-100m` 6.886, `bufferbloat` 6.916 (r10: 8.354), `deep` 6.382 (r10: 8.040). The r9/r10 failures were the host load, not a 1.1 regression on long-delay paths.
- Every recovery, safety and 1.1 host-loss check passes again: rcvbuf (9 socket drops attributed to the host, not a policer), local-qdisc (572 and 623 send failures, 0 implausible TX joins with exact and predicted ids), fast (no hard cap, 7 saturations ended by their allowances), data-cap (1 004 404 B ≤ 1 MB + one batch).
- `geo-100m`: capacity is recovered in both directions (99.05 Mbit/s against 99.08), saturated time a→b 4.17 s (≥ 3), but b→a 6.56 s, under the 7 s floor the scenario was added with in #49.

## Interpretation

- The quiet-host question #42 asked is answered: the bytes/packet budget passes with margin, so no REQ-FMT-015 issue is needed.
- The one failure is the saturated-time floor of `geo-100m` b→a. #49 set it at 7 s from 8.1 s measured with hold on the predicted queue (5.8–6.1 s without it); 6.56 s lies between the two. Whether the floor is too tight for run-to-run variation or the hold regresses under load is examined before the next run; the run stays as evidence.
