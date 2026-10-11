# EXP-0006-r3: Probe, wire, syscall and derive tests; end-to-end session; unsafe and dependency policy (re-run)

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: see `experiment.toml`
- supersedes: [EXP-0006-r2](../EXP-0006-r2-probe-session-and-policy/) (passed; went stale when `crates/pt-sys/src/udp.rs` got the musl build fix: control-message lengths are `socklen_t` and the `recvmmsg` flags are unsigned on musl)

## Method

Same command as r2 (see its README): the crate tests in release mode, the ignored end-to-end namespace session, clippy with `-D warnings`, the rule that only pt-sys contains `unsafe`, and `cargo deny`.

## Result

All steps pass. The 34 unit tests and the end-to-end session pass, as in r2 (`artifacts/stdout.log`).

## Interpretation

The musl fix only changes casts (`as _`), so nothing changes on glibc, which is what this run uses. The shipped musl binary is exercised separately: a local static musl build passed the pt-sys tests and a smoke session with kernel RX/TX timestamps, and the release evidence (EXP-0008) checks the published binaries.
