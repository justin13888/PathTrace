# EXP-0002: Ground-truth recovery and netem closure across 18 namespace scenarios

- verdict: **fail** (82 of 83 checks pass)
- pinned commit: see `manifest.toml` (5e91686)
- requirements: see `experiment.toml`
- superseded by: EXP-0002-r2 (after the fix described below)

## Hypothesis

See `experiment.toml`. Every scenario builds initiator ↔ middlebox ↔ responder namespaces with exact `tc`/`nft` impairments, runs a real `pathtrace` session, derives the model and compares it with the truth.

## Result

`artifacts/results.md` has the full table, and every scenario directory holds `trace_info.json` (content digest), `derived_netem.txt` and the session logs. All checks passed except one:

| Scenario | Check | Truth | Recovered |
|---|---|---|---|
| loss-gemodel | Gilbert-Elliott r, 95% CI covers truth | 0.40 | (0.478, 0.814) |

Highlights among the passes:
- capacity within 1.5% (20, 10 and 100 Mbit/s), with the rate-step series at NRMSE 1.6%;
- buffer depth 149.2 kB against 150 kB, and the netem closure replay reproducing capacity, buffer and delay;
- policer and AQM/ECN detected; MTU 1400 with and without ICMP (black-hole flag); DSCP/ECN rewriting;
- per-class throttling (ratio 0.11); TCP fallback under UDP blocking; NAT binding 15 s alive and 30/60 s expired; rebinding recorded;
- dead-man stop 497 ms after the outage started; data cap held at 3.08 MB against 3 MB.

## Root cause of the failure

netem's Gilbert chain advances on **every** packet crossing it. During quiet phases the a→b direction also carries about 50 control and feedback datagrams per second, which the trace did not record. The observed probe packets therefore see a subsampled chain, so the run-length estimate of r is biased upward. The bias grows with control traffic and CPU load, which explains why an earlier single-scenario run passed (r CI 0.33–0.67) while this run with six parallel scenarios did not. Real networks would bias the estimate the same way.

## Consequence

The raw layer lacked observations of the control datagrams. The fix records every control datagram as an observation (flows 250/251, sequence = Noise nonce), reduces feedback to 5 Hz when nothing saturates, and feeds the complete packet sequence into the loss model. It is verified by EXP-0002-r2.

Note: `artifacts/mtu/` is a leftover directory from an earlier exploratory run (the scenario was replaced by `mtu-icmp` / `mtu-blackhole`). It is not part of this run's results table. The harness now clears its scratch directory before full runs.
