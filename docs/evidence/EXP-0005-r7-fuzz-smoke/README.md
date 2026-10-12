# EXP-0005-r7: Fuzzing PTF, CBOR, JSON twin and wire parsers (re-run at 1.1.0)

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0005-r6](../EXP-0005-r6-fuzz-smoke/) (passed; went stale when the 1.1.0 version bump, #55, changed `fuzz/Cargo.lock`)
- requirements: REQ-FMT-016, REQ-SEC-004

## Method

Identical to r6: 120 s of cargo-fuzz per target, `ptf_read` seeded with every conformance directory.

## Result

All four targets exited cleanly, with no crashes, leaks, timeouts or assertion failures (`artifacts/stderr.log`). Executions: `ptf_read` 0.33 M, `cbor_decode` 2.60 M, `jsonl_load` 14.75 M, `wire` 6.38 M (24.1 M in total, r6: 16.8 M). The host was shared with heavy load (load average about 50 on 16 threads) during this run. `stderr.log` is 2.05 MB (1.96 MiB), larger than r6's because libFuzzer logs grow with executions.

## Interpretation

The only covered change since r6 is the version of `pt-format` and `pt-wire` recorded in `fuzz/Cargo.lock`; the parsers are unchanged and show no crash reachable within the budget at 1.1.0.
