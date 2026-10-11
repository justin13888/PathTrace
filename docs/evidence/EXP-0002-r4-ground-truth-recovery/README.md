# EXP-0002-r4: Ground-truth recovery and netem closure across 23 namespace scenarios (release re-run)

- verdict: **pass** (all 89 checks; the per-packet size rows are applicable to 13 scenarios and pass, the other 10 are `n/a`)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r3](../EXP-0002-r3-ground-truth-recovery/) (passed, made stale by `da3e911`, a test-only change in `crates/pt-sys/src/udp.rs` that the coverage paths include)
- requirements: see `experiment.toml`

## Method

Same as r3: `cargo xtask groundtruth all --jobs 6`. 23 scenarios, each in three unprivileged namespaces, with known `tc`/`nft` impairments on the middlebox, a real `pathtrace serve`/`probe` session, merge, derive, and comparison with the truth. `rate-delay-asym` is also replayed through its own netem export (closure). Only logs and summaries are copied here (`trace_info.json`, `derived_netem.txt`, `netem_export.txt`, `qdisc_stats.txt`), with no keys and no full traces.

## Result (selected; full table in `artifacts/results.md`)

| Stage | Scenario | Truth | Recovered |
|---|---|---|---|
| S6 capacity | rate-delay-asym a→b / b→a | 19.82 / 9.91 Mbit/s | 19.75 / 9.89 |
| S6 capacity | rate-100m | 99.08 Mbit/s | 99.04 |
| S6 time-varying | rate-step (20 ↔ 8 Mbit/s every 4 s) | NRMSE ≤ 10% | 1.35% over 196 bins |
| S7 light trains | symmetric-delay (netem 50 Mbit/s) | 49.54 Mbit/s | 49.55 (dispersion) |
| S10 delay | rate-delay-asym (10 + 15 ms) | RTT sum 25 ms; split not identifiable | 25.005 ms, `symmetric_assumed` recorded |
| S10 delay | symmetric-delay | 20 / 20 ms, offset 0 | 20.02 / 20.03 ms, offset −0.002 ms |
| S5 queue | rate-delay-asym buffers | 150 000 / 75 000 B | 149 374 / 74 727 B, droptail |
| S5 AQM | aqm-ecn (htb + fq_codel ecn) | aqm, ECT marked | aqm_suspected, ECT(0) `marked` |
| S2/S5 policer | policer (police 5 Mbit/s) | policer, 4.95 Mbit/s | policer, 4.97 |
| S9 loss | loss-random 2% / gemodel p=2% r=40% | p, r | 95% CIs cover truth (p 1.3–3.5% / 1.5–3.8%; r 0.80–1.0 / 0.22–0.47) |
| S10/S11 jitter | 4 ms normal | σ 4 ms | 4.21 ms; reordering detected |
| S11/S12 | reorder 10% / dup 2% | dup 2% | dup 2.17%; reordering detected |
| S4 MTU | route MTU 1400, ICMP / ICMP dropped | 1400, PTB / black hole | 1400 and PTB seen / 1400 and black hole |
| S13 header | pedit dsfield 0 | DSCP rewritten, ECT bleached | rewritten, bleached; reverse preserved |
| S1/S2 policy | UDP/443 throttled to 2 Mbit/s | ratio ~0.1 | 0.108 (QUIC-shaped also) |
| S2 policy | all UDP dropped | TCP fallback | control over TCP, UDP unreachable, TCP reachable, exit 3 |
| S3 NAT | conntrack UDP timeout 20 s | alive 15 s, dead 30/60 s | alive / dead / dead |
| S3/S14 mobility | initiator source address change | rebind | nat_rebind + addr_new; session complete |
| S15 closure | netem export → replay → re-capture | identical | capacity, buffer, delay within 0.1% |
| safety | dead-man (3 s outage during b→a saturation) | stop ≤ 600 ms | 503 ms, `flow_stopped` |
| safety | responder `--data-cap 3 MB` | ≤ 3.1 MB | 3.019 MB, `budget_cap` |
| safety | initiator `--rate-cap 5 Mbit/s` | ≤ 5.5 Mbit/s | 4.94 |
| profiles | light / deep (track 120 s) | ≤ 2 MB, ≤ 200 kB file / tracking + 300 s NAT | 0.61 MB, 62 kB file / 2 saturations, 300 s probe |
| IPv6 | smoke over fd00:2::2 | complete | complete, 19.72 Mbit/s, udp/443 reachable |
| size | standard/deep packet tables | ≤ 8 B/packet | 6.7–7.9 B/packet; standard @ 100 Mbit/s = 2.38 MB file (≤ 10 MB) |

## Interpretation

- Every recovery result matches r3 within run-to-run variation. Every simulator stage has a matching ground-truth recovery, except S16 (direction coupling; netem has no ground truth for it) and S18 (proxy detection, #22). Both are recorded as "recorded, unverified" in docs/design/simulator-requirements.md.
- **Per-packet size depends on the environment.** With the same code as r3 (the only difference is a test), the applicable packet tables cost 6.7–7.9 B/packet here against 4.8–6.6 in r3. A per-column breakdown of the `rate-delay-asym` trace (outside this run, by decoding the scratch trace) puts more than 95% of the bytes in four timestamp columns: `tx_sched`, `rx`, `tx_user_lag` and `tx_snd_lag`, which hold kernel scheduling and arrival-time noise at ns resolution (P4). During this run the shared 16-core host had a load average of 16–18. A later single-scenario re-run at lower load gave 7.18 B/packet. Path jitter itself is cheap: the 4 ms jitter scenario costs 6.1 B/packet. The ≤ 8 B/packet target (REQ-FMT-015) holds, but with a thin margin on a heavily loaded host. The budget that matters for users, the file size per profile, has about 4× headroom (2.38 MB vs 10 MB at 100 Mbit/s). Field sizes are checked as part of user acceptance (#16).
- Limits are unchanged from r3: netem/tc are idealised, all endpoints share one host clock, and real access networks remain user acceptance (#16).
