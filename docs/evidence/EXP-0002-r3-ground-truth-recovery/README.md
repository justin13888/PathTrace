# EXP-0002-r3: Ground-truth recovery and netem closure across 23 namespace scenarios

- verdict: **pass** (89 of 89 checks)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r2](../EXP-0002-r2-ground-truth-recovery/) → [EXP-0002](../EXP-0002-ground-truth-recovery/) (both failed, each with a root cause fixed in code)
- requirements: see `experiment.toml`

## Method

`cargo xtask groundtruth all --jobs 6`. Each of the 23 scenarios builds three unprivileged network namespaces (initiator, middlebox, responder) and applies the impairment exactly with `tc`/`nft` on the middlebox. It then runs a real `pathtrace serve`/`probe` session, merges and derives the trace, and compares the derived values with the truth.

Ground-truth notes:
- Queue truth uses netem for pure delay feeding a byte-limited `tbf`, because netem's own `limit` also counts its delay line.
- Rates count L2 bytes on veth, so the IP-layer truth is R·1500/1514.

`rate-delay-asym` is also replayed through its own netem export and re-captured (closure). Scratch directories hold throwaway keys and full traces and stay out of the evidence; each scenario directory here holds the logs, `trace_info.json` (content digest) and `derived_netem.txt`.

## Result (selected; full table in `artifacts/results.md`)

| Stage | Scenario | Truth | Recovered |
|---|---|---|---|
| S6 capacity | rate-delay-asym a→b / b→a | 19.82 / 9.91 Mbit/s | 19.76 / 9.89 |
| S6 capacity | rate-100m | 99.08 Mbit/s | 99.05 |
| S6 time-varying | rate-step (20 ↔ 8 Mbit/s every 4 s) | NRMSE ≤ 10% | 1.5% over 193 bins |
| S10 delay | rate-delay-asym (10 + 15 ms) | RTT sum 25 ms; split not identifiable | 25.005 ms, `symmetric_assumed` recorded |
| S10 delay | symmetric-delay | 20 / 20 ms, offset 0 | ±0.03 ms, offset −0.003 ms |
| S5 queue | rate-delay-asym buffers | 150 000 / 75 000 B | 149 414 / 74 715 B, droptail |
| S5 AQM | aqm-ecn (htb + fq_codel ecn) | aqm, ECT marked | aqm_suspected, ECT(0) `marked` |
| S2/S5 policer | policer (police 5 Mbit/s, no queue) | policer, 4.95 Mbit/s | policer, 4.97 |
| S9 loss | loss-random 2% / gemodel p=2% r=40% | p, r | 95% CIs cover truth (r CI 0.82–1.0 / 0.23–0.51) |
| S10/S11 jitter | 4 ms normal | σ 4 ms | 4.19 ms; reordering detected |
| S11/S12 | reorder 10%/dup 2% | dup 2% | dup 2.13%; reordering detected |
| S4 MTU | route MTU 1400, ICMP / ICMP dropped | 1400, PTB / black hole | 1400 and PTB seen / 1400 and black hole |
| S13 header | pedit dsfield 0 | DSCP rewritten, ECT bleached | rewritten, bleached; reverse preserved |
| S1/S2 policy | UDP/443 throttled to 2 Mbit/s | ratio ~0.1 | 0.107 (QUIC-shaped also) |
| S2 policy | all UDP dropped | TCP fallback | control over TCP, UDP unreachable, TCP reachable, exit 3 |
| S3 NAT | conntrack UDP timeout 20 s | alive 15 s, dead 30/60 s | alive / dead / dead |
| S3/S14 mobility | initiator source address change | rebind | nat_rebind + addr_new; session complete |
| S15 closure | netem export → replay → re-capture | identical | capacity, buffer, delay within 0.1% |
| safety | dead-man (3 s outage during b→a saturation) | stop ≤ 600 ms | 506 ms, `flow_stopped` |
| safety | responder `--data-cap 3 MB` | ≤ 3.1 MB | 3.018 MB, `budget_cap` |
| safety | initiator `--rate-cap 5 Mbit/s` | ≤ 5.5 Mbit/s | 4.94 |
| profiles | light / deep (track 120 s) | ≤ 2 MB / tracking + 300 s NAT | 0.61 MB, 57 kB trace / 2 saturations, 300 s probe |
| IPv6 | smoke over fd00:2::2 | complete | complete, 19.73 Mbit/s, udp/443 reachable |
| size | standard/deep packet tables | ≤ 8 B/packet | 4.7–6.6 B/packet; standard @ 100 Mbit/s = 1.86 MB file |

## Interpretation

- Every simulator stage in docs/design/simulator-requirements.md has a matching ground-truth recovery, except direction coupling (S16, no netem ground truth) and proxy detection (S18, #22). Their status in the sufficiency matrix is "recorded, unverified".
- Limits: netem/tc are idealised (no cellular schedulers, no Wi-Fi aggregation beyond what the timing noise of veth produces), and all endpoints share one host clock, which makes the clock-offset check exact. Real access networks remain user acceptance (#16).
