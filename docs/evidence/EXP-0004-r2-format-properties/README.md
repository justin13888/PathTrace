# EXP-0004-r2: PTF property and unit tests (re-run at PTF 1.1)

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0004](../EXP-0004-format-properties/) (passed; went stale when PTF 1.1 changed `crates/pt-format/src`)
- requirements: REQ-FMT-004, -006, -007, -011, -012, -017, -019

## Method

Same command and tests as EXP-0004 (see its README for the test-to-requirement table): `cargo test --release --locked -q -p pt-format`.

## Result

`artifacts/stdout.log`: 24 unit and property tests and 2 conformance tests pass, 0 fail. The conformance tests now also cover `conformance/v1.1` (EXP-0003-r4).

## Interpretation

Unchanged from EXP-0004: the deterministic CBOR profile, every column encoding, truncation recovery, canonical encoding, limits, the JSON twin and redaction hold at PTF 1.1.
