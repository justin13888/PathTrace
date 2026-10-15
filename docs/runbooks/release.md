# Release

How a `vX.Y.Z` release is cut. Releases are tags on `main` merge commits; the tag push runs `.github/workflows/release.yml`, which publishes only if `cargo xtask audit --release` passes (no stale or pending evidence).

## Prerequisites

- `main` is green in CI, and on `main` `cargo xtask audit --release` exits 0 locally.
- No experiment is defined without a run (that would be `pending` and block the release).
- If the PTF format changed: a new `conformance/<version>/` directory exists (existing ones are never edited).

## Steps

1. **Bump the version.** On a branch `build/release-X.Y.Z`, set `version` in the root `Cargo.toml` (`[workspace.package]`), run `cargo build` to update `Cargo.lock`, commit `build(repo): version X.Y.Z`, open a PR, wait for green CI, and merge it (merge commit).
2. **Dry run.** `gh workflow run release.yml --ref main`. Expect the three `build` jobs to pass (static musl x86_64 and aarch64 Linux, `--version` printed, no dynamic libraries; aarch64-apple-darwin on `macos-15`, an arm64 Mach-O linking only system libraries, `--version` printed) and `publish` to be skipped (not a tag). Download one artifact and check that `pathtrace --version` prints `pathtrace X.Y.Z`.
3. **Tag.** On the merge commit from step 1: `git tag -a vX.Y.Z -m "PathTrace X.Y.Z" <merge-sha> && git push origin vX.Y.Z`. Annotated tags only; tags are never moved or deleted.
4. **Watch.** `gh run watch` on the tag's Release run. `audit`, the three `build` jobs and `publish` must pass. The release then has `pathtrace-vX.Y.Z-{x86_64,aarch64}-unknown-linux-musl.tar.gz`, `pathtrace-vX.Y.Z-aarch64-apple-darwin.tar.gz` and `SHA256SUMS` (one line per archive; Linux lines from `sha256sum`, the macOS line from `shasum -a 256`, same format).
5. **Verify with evidence.** On a branch, define an experiment that downloads the release and checks checksums, static linking and architecture, `--version`, `doctor`, a smoke session in the namespace harness with the released binary (including the trace's META provenance: version, tag commit, clean build), and `audit --release` at the tag (template: EXP-0008). Run it, commit it, and mark REQ-REPO-009 met against it if the evidence is new. For the macOS archive (REQ-REPO-010), the experiment also checks on a Mac that `shasum -a 256 -c SHA256SUMS` passes, the archive holds `pathtrace`, `LICENSE` and `README.md` and no systemd unit, `file` reports an arm64 Mach-O, `pathtrace --version` prints the tag's version and `pathtrace doctor --json` has no fatal finding but the missing key; mark REQ-REPO-010 met only against that passing run.

## When a step fails

- CI fails on the bump PR: fix on the branch with new commits; never tag an unmerged commit.
- `audit` fails in the release run: nothing is published. Re-run the stale experiments on a branch, merge, then tag the new merge commit with the next patch version. A pushed tag is never reused.
- `publish` fails after a successful build: re-run the failed job (`gh run rerun --failed`); the tag stays.
