# EXP-0005-r6: Fuzzing PTF, CBOR, JSON twin and wire parsers (re-run after #39 to #51)

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0005-r5](../EXP-0005-r5-fuzz-smoke/) (passed; went stale when main's #39 to #51 changed `crates/pt-wire/src`)
- requirements: REQ-FMT-016, REQ-SEC-004

## Method

Identical to r5: 120 s of cargo-fuzz per target, `ptf_read` seeded with every conformance directory.

## Result

All four targets exited cleanly, with no crashes, leaks, timeouts or assertion failures (`artifacts/stderr.log`). Executions: `ptf_read` 0.33 M, `cbor_decode` 2.95 M, `jsonl_load` 10.86 M, `wire` 2.62 M (16.8 M in total, r5: 16.3 M). The host was shared with heavy compilation load (load average about 30 on 16 threads) during this run.

## Interpretation

The wire changes merged from main (#39 to #51) introduce no parser crash reachable within the budget.
