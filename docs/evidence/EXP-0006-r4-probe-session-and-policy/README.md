# EXP-0006-r4: Probe, wire, syscall and derive tests; end-to-end session; unsafe and dependency policy (re-run)

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: see `experiment.toml`
- supersedes: [EXP-0006-r3](../EXP-0006-r3-probe-session-and-policy/) (passed; went stale when `crates/pathtrace` changed for the doctor warm-up fix and the 1.0.1 version)

## Method

Same command as r2 and r3 (see the r2 README).

## Result

All steps pass: the 34 unit tests, the end-to-end namespace session, clippy, the `unsafe` confinement and `cargo deny` (`artifacts/stdout.log`).

## Interpretation

Unchanged from r3.
