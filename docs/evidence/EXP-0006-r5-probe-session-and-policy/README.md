# EXP-0006-r5: Probe, wire, syscall and derive tests; end-to-end session; unsafe and dependency policy (re-run)

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: see `experiment.toml`
- supersedes: [EXP-0006-r4](../EXP-0006-r4-probe-session-and-policy/) (passed; went stale when pt-derive started recording the Gilbert-Elliott transition counts)

## Method

Same command as r2–r4 (see the r2 README).

## Result

All steps pass: 35 unit tests (one more than r4, the new `wilson_level` test), the end-to-end namespace session, clippy, the `unsafe` confinement and `cargo deny` (`artifacts/stdout.log`).

## Interpretation

Unchanged from r4.
