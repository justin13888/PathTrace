# EXP-0003-r2: Independent and Rust readers agree on every conformance directory

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0003](../EXP-0003-conformance-independent-reader/) (re-run with the real golden trace added)
- requirements: REQ-FMT-001, -002, -003, -005, -009, -010, -013, -014, -018

## Method

As in EXP-0003, but over every directory in `conformance/`:
- `v1.0`: 18 synthetic valid and invalid cases;
- `v1.0-real`: a real IPv6 smoke capture from the harness, derived and redacted to `anonymous`, so it contains no identifiers.

## Result

The Python reader passes 18/18 and 1/1 cases (`artifacts/stdout.log`). The Rust conformance tests pass. The independent reader reproduces the Rust content digest of the real trace (`07496f6b…`), covering all of its tables: per-packet, TCP_INFO, app events, clock pairs and exchanges, context, derived series.

## Interpretation

A spec-only implementation reads real PathTrace output, not only hand-built cases. Both directories are now goldens: later releases must keep these verdicts and digests (REQ-FMT-010).
