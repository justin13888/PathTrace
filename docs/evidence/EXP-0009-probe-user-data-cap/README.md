# EXP-0009: `probe --data-cap` bounds both endpoints of a standard session

- verdict: **pass**, 8 of 8 checks
- pinned commit: see `manifest.toml`
- requirements: REQ-PRB-014, REQ-PRB-016, REQ-SEC-001
- supersedes / superseded by: —

## Hypothesis

A `standard` session with `probe --data-cap 30000000` (cli.md, "`probe --data-cap`") through a 100 Mbit/s path stays within 30 MB per endpoint, plans its saturations within that cap so the hard cap is never reached, still runs the single-direction saturations, and records the request in META.

## Method

`cargo xtask groundtruth probe-data-cap --jobs 1`: unprivileged namespaces (tools/netns/session.sh), `netem delay 10ms rate 100mbit limit 1000` in both directions, `standard` profile, `PROBE_ARGS="--data-cap 30000000"`. Without the flag the profile's cap is 200 MB per endpoint; at 100 Mbit/s its saturations alone would send far more than 30 MB. Run on a 16-thread Linux 7.2 host (`manifest.toml`).

## Result (`artifacts/results.md`)

| Check | Truth | Got |
|---|---|---|
| session complete | true | true |
| a UDP bytes sent | ≤ 30 MB | 29,036,487 |
| b UDP bytes sent | ≤ 30 MB | 25,317,279 |
| `budget_cap` events, a / b | 0 | 0 / 0 |
| phases run | P4 and P5 | P0–P9, none skipped |
| META `extra.a.data_cap_user` | 30000000 | 30000000 |
| pkt table bytes/packet | ≤ 8 | 6.996 |

## Interpretation

- The user's cap reaches both senders: the responder enforces it for b→a through `hello`'s existing `data_cap`, without a wire change.
- The allowances, not the hard stop, kept the session within the cap: the initiator used 97 % of it with no `budget_cap`, and every phase still ran, with shorter saturations.
- Not shown: how much capacity accuracy a small cap costs on faster or long-RTT paths (the saturations get shorter and reach the overdrive sooner), or caps so small that phases are skipped. The `light` and `data-cap` scenarios of EXP-0002-r14 cover the hard-cap stop and small budgets.
