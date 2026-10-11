# EXP-0005-r3: Fuzzing PTF, CBOR, JSON twin and wire parsers (re-run at version 1.0.1)

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0005-r2](../EXP-0005-r2-fuzz-smoke/) (passed; went stale when the 1.0.1 version bump changed `fuzz/Cargo.lock`; the fuzzed code is unchanged)
- requirements: REQ-FMT-016, REQ-SEC-004

## Method

Identical to EXP-0005: 120 s of cargo-fuzz per target (see the EXP-0005 README for the properties checked).

## Result

All four targets exited cleanly, with no crashes, leaks, timeouts or assertion failures. Executions: `ptf_read` 0.72 M, `cbor_decode` 3.65 M, `jsonl_load` 11.73 M, `wire` 3.08 M (19.2 M in total; about 58 M in total across EXP-0005, r2 and r3, on a corpus that grows from run to run).

## Interpretation

Unchanged from EXP-0005.
