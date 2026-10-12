# EXP-0005-r5: Fuzzing PTF, CBOR, JSON twin and wire parsers (re-run at PTF 1.1, wire minor 1)

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0005-r4](../EXP-0005-r4-fuzz-smoke/) (failed before fuzzing: the v1.1 seed copy collided on a file name); last pass: [EXP-0005-r3](../EXP-0005-r3-fuzz-smoke/)
- requirements: REQ-FMT-016, REQ-SEC-004

## Method

Identical to EXP-0005: 120 s of cargo-fuzz per target (see the EXP-0005 README for the properties checked). The `ptf_read` seeds now include `conformance/v1.1` (under a `v1.1-` prefix), so the PTF 1.1 columns and tables are in the starting corpus.

## Result

All four targets exited cleanly, with no crashes, leaks, timeouts or assertion failures (`artifacts/stderr.log`). Executions: `ptf_read` 0.55 M, `cbor_decode` 3.56 M, `jsonl_load` 9.70 M, `wire` 2.47 M (16.3 M in total). The counts are somewhat lower than r3's (19.2 M) on the same host, which was shared with other load during this run.

## Interpretation

The PTF 1.1 reader changes and the wire minor 1 messages (`abort`, handshake-reply resend) introduce no parser crash reachable within the budget.
