# EXP-0008-r3: Release v1.1.0, published static binaries verified end to end

- verdict: pass (15 checks)
- pinned commit: see `manifest.toml` (the tag is `v1.1.0` → `ba30886`, the merge commit of #56)
- supersedes: [EXP-0008-r2](../EXP-0008-r2-release-artefacts/) (v1.0.1)
- requirements: REQ-REPO-009

## Method

The same checks as EXP-0008-r2, run against `v1.1.0`, plus one more: `doctor` from the released binary must run the 1.1 preflight checks added by #46 and #48 (clock sync, power, CPU governor, NIC offloads).

The tag is on the merge commit of #56, not of the version bump (#55). The release dry run at #55's merge failed its `audit` job because the bump changed `fuzz/Cargo.lock`, which made EXP-0005-r6 stale. #56 re-ran it as EXP-0005-r7, and the next dry run passed. `v1.1.0` was never pushed before that, so no tag was reused.

## Result

All 15 checks pass (`artifacts/checks.txt`): annotated tag on a main merge commit; both static musl archives and `SHA256SUMS` (verified); x86-64 and aarch64 static binaries with the expected contents; `pathtrace 1.1.0`; `doctor` ok, with kernel RX and TX stamps and the 1.1 preflight checks; a namespace smoke session with a valid trace whose META records 1.1.0, the tag commit and a clean build; `audit --release` at the tag.

## Interpretation

REQ-REPO-009 holds for the current release. v1.1.0 is the release to install on both machines for field capture (`docs/runbooks/field-session.md`).
