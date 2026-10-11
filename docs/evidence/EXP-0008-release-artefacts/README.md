# EXP-0008: Release v1.0.0, published static binaries verified end to end

- verdict: pass (13 checks)
- pinned commit: see `manifest.toml` (the tag itself is `v1.0.0` → `a5678cf`, the merge commit of #25)
- requirements: REQ-REPO-009

## Method

`check.sh` downloads the published release with `gh` and checks:

1. `v1.0.0` is an annotated tag on a merge commit reachable from `main`.
2. Both musl archives and `SHA256SUMS` are present, and `sha256sum -c` passes.
3. `file` shows a statically linked binary of the right architecture for each archive (x86-64, aarch64), and each archive contains the binary, LICENSE, README.md and the systemd unit.
4. The released x86_64 binary prints `pathtrace 1.0.0` and passes `doctor --json` with a fresh key.
5. The released binary completes a smoke session in the namespace harness (`tools/netns/session.sh`). The trace passes `trace check`, and its META records version 1.0.0, the tag's commit and `git_dirty = false`, so the release build is traceable to clean, tagged source.
6. `cargo xtask audit --release` passes in a worktree at the tag.

## Result

All 13 checks pass (`artifacts/checks.txt`). Archives are about 11 MB (x86_64) and 10 MB (aarch64). The release workflow's own `audit` job (release mode) also passed before publishing.

## Interpretation

- REQ-REPO-009 is met: tagged releases publish static, checksummed binaries for both architectures, and the published x86_64 binary works end to end. The aarch64 binary is checked for format and static linking only; this host cannot execute it. CI builds and tests the same code natively on arm64 runners.
- Finding: `doctor` reported `kernel RX stamps false` (a non-fatal check), while sessions on the same host record kernel RX stamps. The kernel enables RX timestamping lazily, and doctor's self-test sends a single packet with no warm-up. The capture itself is unaffected: packets that arrive before stamping is enabled are recorded with `rx_src = user`. This is fixed in 1.0.1.
- Earlier findings from the dry runs of this release, fixed before tagging (#25): pt-sys did not compile for musl, and CI did not check the release target.
