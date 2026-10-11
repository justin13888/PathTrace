# EXP-0008-r2: Release v1.0.1, published static binaries verified end to end

- verdict: pass (14 checks)
- pinned commit: see `manifest.toml` (the tag is `v1.0.1` → `c1b70ee`, the merge commit of #28)
- supersedes: [EXP-0008](../EXP-0008-release-artefacts/) (v1.0.0; its doctor finding is fixed in 1.0.1)
- requirements: REQ-REPO-009

## Method

The same checks as EXP-0008, run against `v1.0.1`, plus one more: `doctor` from the released binary must report kernel RX and TX timestamps. Sessions on this host get kernel RX stamps, and v1.0.0's doctor falsely denied them.

## Result

All 14 checks pass (`artifacts/checks.txt`): annotated tag on a main merge commit; both static musl archives and `SHA256SUMS` (verified); x86-64 and aarch64 static binaries with the expected contents; `pathtrace 1.0.1`; `doctor` ok with kernel RX and TX stamps; a namespace smoke session with a valid trace whose META records 1.0.1, the tag commit and a clean build; `audit --release` at the tag.

## Interpretation

REQ-REPO-009 holds for the current release. v1.0.1 is the release to install for field capture.
