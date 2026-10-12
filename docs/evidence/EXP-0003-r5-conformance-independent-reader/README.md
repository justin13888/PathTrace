# EXP-0003-r5: Independent and Rust readers agree on every conformance directory (re-run after #39 to #51)

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0003-r4](../EXP-0003-r4-conformance-independent-reader/) (passed; went stale when main's #39 to #51 changed `docs/design/ptf-format.md`)
- requirements: REQ-FMT-001, -002, -003, -005, -009, -010, -013, -014, -018

## Method

Same command and corpus as r4: the spec-only Python reader over `conformance/v1.0`, `conformance/v1.0-real` and `conformance/v1.1`, then the Rust conformance tests.

## Result

18/18, 1/1 and 3/3 cases pass (`artifacts/stdout.log`) and both Rust conformance tests pass. Every content digest is identical to r4.

## Interpretation

The format reading is unchanged by the probe and CLI fixes merged from main; the independent reader still agrees with the Rust reader on every golden file.
