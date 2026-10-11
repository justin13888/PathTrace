# EXP-0002-r5: Ground-truth recovery and netem closure across 23 namespace scenarios (release re-run after the musl fix)

- verdict: **pass**, 89 of 89 checks: 77 recovery checks plus 12 per-packet size checks. The size check is `n/a` for the other 11 scenarios, which are smoke or light sessions.
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002-r4](../EXP-0002-r4-ground-truth-recovery/) (passed; went stale when `crates/pt-sys/src/udp.rs` got the musl build fix, which only changes casts)
- requirements: see `experiment.toml`

**Correction to r4's README.** r4 had the same split as this run (12 applicable per-packet rows, 11 `n/a`). Its README said 13 and 10. Its verdict and values are unaffected.

## Method

Same as r4 and r3: `cargo xtask groundtruth all --jobs 6`, 23 scenarios in unprivileged namespaces with known `tc`/`nft` impairments, a real session, merge, derive, and comparison with the truth, plus netem closure for `rate-delay-asym`. As before, sessions use the glibc release build. The shipped static musl binaries are checked by the release evidence (EXP-0008).

## Result (selected; full table in `artifacts/results.md`)

| Stage | Check | Truth | Recovered |
|---|---|---|---|
| S6 | rate-delay-asym capacity a→b / b→a | 19.82 / 9.91 Mbit/s | 19.75 / 9.89 |
| S6 | rate-100m / IPv6 capacity | 99.08 / 19.82 Mbit/s | 99.04 / 19.73 |
| S6 | rate-step NRMSE | ≤ 10% | 1.64% over 191 bins |
| S7 | light-train dispersion | 49.54 Mbit/s | 49.54 |
| S10 | base delay sum / symmetric 20+20 ms / clock offset | 25 / 20, 20 / 0 ms | 25.004 / 20.03, 20.02 / −0.001 ms |
| S5 | buffers a→b / b→a | 150 000 / 75 000 B | 149 415 / 74 733 B |
| S9 | GE 95% CIs (random 2%; gemodel p=2%, r=40%) | cover truth | p 0.97–2.9% / 0.48–2.0%; r 0.76–1.0 / 0.20–0.61 |
| S10/S11 | jitter σ | 4 ms | 3.92 ms |
| S12 | duplicates | 2% | 1.92% |
| S2 | UDP/443 ratio; policer | ~0.1; 4.95 Mbit/s | 0.107; 4.97 Mbit/s |
| S15 | closure (netem export replayed) | identical | capacity, buffer, delay within 0.1% |
| safety | dead-man stop; data cap; rate cap | ≤ 600 ms; ≤ 3.1 MB; ≤ 5.5 Mbit/s | 510 ms; 3.019 MB; 4.94 Mbit/s |
| size | standard @ 100 Mbit/s file; light file; packet tables | ≤ 10 MB; ≤ 200 kB; ≤ 8 B/packet | 1.92 MB; 58 kB; 5.4–7.6 B/packet |

All other checks (discipline, AQM/ECN, MTU and black hole, DSCP/ECN rewriting, UDP blocking with TCP fallback, NAT lifetime and rebinding, profiles) match the truth, as in r4.

## Interpretation

- Results are unchanged from r4 within run-to-run variation, as expected for a cast-only change. The sufficiency verdict in docs/design/simulator-requirements.md stands.
- Per-packet size: 5.4–7.6 B/packet at a host load average of about 7–10, against 6.7–7.9 in r4 (load 16–18) and 4.8–6.6 in r3, all with equivalent code. This confirms r4's finding: the figure tracks host scheduling noise in the timestamp columns, and the ≤ 8 B/packet target holds in every run.
