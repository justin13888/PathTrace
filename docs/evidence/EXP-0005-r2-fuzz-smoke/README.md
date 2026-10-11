# EXP-0005-r2: Fuzzing PTF, CBOR, JSON twin and wire parsers (re-run at version 1.0.0)

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0005](../EXP-0005-fuzz-smoke/) (passed; went stale when the 1.0.0 version bump changed `fuzz/Cargo.lock`, a covered path; the fuzzed code is unchanged)
- requirements: REQ-FMT-016, REQ-SEC-004

## Method

Identical to EXP-0005: `FUZZ_SECONDS=120 mise run fuzz` runs cargo-fuzz (libFuzzer with AddressSanitizer, nightly) for 120 s on each of `ptf_read`, `cbor_decode`, `jsonl_load` and `wire`, with the same properties checked (see the EXP-0005 README).

## Result

All four targets exited cleanly, with no crashes, leaks, timeouts or assertion failures (`artifacts/stdout.log`, `stderr.log`). Executions per target: `ptf_read` 0.95 M, `cbor_decode` 4.76 M, `jsonl_load` 13.85 M, `wire` 3.47 M (23.0 M in total). Each run reuses the corpus left by the previous campaign, so it continues from where EXP-0005 stopped.

## Interpretation

Unchanged from EXP-0005: this is a smoke-level campaign (8 CPU-minutes), not an exhaustive one.
