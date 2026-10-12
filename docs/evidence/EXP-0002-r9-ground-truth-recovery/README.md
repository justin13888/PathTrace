# EXP-0002-r9: Ground-truth recovery and netem closure across 30 scenarios (1.1)

- verdict: **fail**, 140 of 141 checks: the only failure is the REQ-FMT-015 bytes/packet budget in the new `geo` scenario (8.32 > 8 B/packet)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r8](../EXP-0002-r8-ground-truth-recovery/) (passed; went stale with the 1.1 capture hardening, #37)
- superseded by: EXP-0002-r10 (re-run with fewer parallel scenarios)
- requirements: see `experiment.toml`

## Method

Same harness as r3–r8 (`cargo xtask groundtruth all --jobs 6`), now with 30 scenarios: the 23 of r8 plus `geo` (300 ms each way, 20 Mbit/s), `bufferbloat`, `fast` (300 Mbit/s, standard budget), `rcvbuf` (8 kB responder receive buffer), `local-qdisc` and `local-qdisc-predicted` (a full initiator qdisc, exact and predicted transmit ids), with `closure-replay`. The data-cap scenario caps at 1 MB instead of 3 MB (the 1.1 byte allowances keep a smoke session inside 3 MB, so the hard cap is never reached there; see `xtask/src/groundtruth.rs`).

Host load: the 1-minute load average was 8.3 at the start and 12.5 at the end of the 842 s run, on 16 hardware threads shared with other users (the harness itself runs 6 scenarios at once).

## Result (full table in `artifacts/results.md`)

Every recovery, safety and host-loss check passes. Selected 1.1 checks:

| Scenario | Check | Truth | Recovered |
|---|---|---|---|
| rcvbuf | socket drops recorded; lost packets attributed to the host; netstack RcvbufErrors | > 0 | 179; 179; 179 |
| rcvbuf | host drops not mistaken for a policer | not policer | unknown |
| local-qdisc / -predicted | send failures recorded; implausible TX joins | > 0; 0 | 928 / 929; 0 of 5318 / 0 of 5322 |
| fast | hard cap reached; saturations ended by allowances; phases P4–P8 | no; ≥ 2; all | no; 7; all |
| data-cap | responder bytes ≤ 1 MB + one batch | 1 100 000 | 1 004 641 |
| geo / bufferbloat | train and PMTU flows stopped by the dead-man | 0 | 0 / 0 |

The failing check: `geo` packet tables cost 8.320 B/packet over 55 249 packets (budget ≤ 8). Every other standard/deep scenario is within budget (5.5–7.96), but most measure 0.1–1.5 B/packet more than in r8 on the same host (e.g. loss-random 7.06 vs 5.63, reorder-dup 7.12 vs 5.10).

## Interpretation

- Recovery is unchanged from r8, and the 1.1 behaviour holds: host-side losses are recorded and kept out of path loss and policer estimates (REQ-PRB-030), byte allowances fit every phase into the budget (REQ-PRB-014), and the dead-man no longer stops light flows on long or bufferbloated paths (REQ-PRB-005).
- The bytes/packet cost depends on timestamp noise, which grows with host scheduling jitter: #38 records the same check at 8.5–9.3 B/packet on both `main` and the 1.1 branch under load 40–95, and ≤ 8 on a quiet host. `geo` is new, so it has no quiet-host figure yet. As #38 prescribes, the run is kept and the experiment is re-run (EXP-0002-r10) with fewer parallel scenarios to reduce the harness's own load.
