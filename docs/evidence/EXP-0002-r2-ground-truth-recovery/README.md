# EXP-0002-r2: Ground-truth recovery across 23 scenarios (all profiles, IPv6)

- verdict: **fail** (88 of 89 checks pass)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0002](../EXP-0002-ground-truth-recovery/); superseded by EXP-0002-r3

## Result

`artifacts/results.md` has the full table. The fix for EXP-0002's failure holds: with control datagrams observed, both Gilbert-Elliott runs cover the truth (loss-random r CI 0.74–1.0 vs 0.98; loss-gemodel r CI 0.18–0.43 vs 0.40). The new scenarios pass:
- IPv6 end to end, capacity within 0.4%;
- the light profile at 0.61 MB per endpoint and a 57 kB trace;
- the deep profile with 2 tracking saturations and 300 s NAT probes;
- the initiator's `--rate-cap` held at 4.94 Mbit/s against 5.

One check failed:

| Scenario | Check | Truth | Recovered |
|---|---|---|---|
| data-cap | responder UDP bytes sent ≤ cap + 100 kB | 3 000 000 (+100 000) | 3 100 895 |

## Root cause

After the cap was reached, the pacer stopped every flow *except the light flow*. Since this run, sent control datagrams are also counted in `bytes_sent`. Light-flow and control bytes kept accumulating for the rest of the session, so the total exceeded the allowance by 895 bytes. The light-flow exemption contradicts "hard data cap" (REQ-PRB-016).

## Consequence

The cap now stops every probe flow, light included. Only the control traffic needed to finish the session continues, and it is still counted. Verified by EXP-0002-r3.
