# EXP-0007-r3: Repository process, scope, CLI surface, derivation purity, provenance (re-run)

- verdict: pass (23 checks)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0007-r2](../EXP-0007-r2-repo-process-scope-cli/) (passed; went stale when AGENTS.md gained the note that release.yml gates publishing on `audit --release`)
- requirements: see `experiment.toml`

## Method

The same `check.sh` as r2 (copied unchanged apart from its header); see the r2 README for the check-to-requirement table.

## Result

All 23 checks pass (`artifacts/checks.txt`). The design-first check now also covers the merged PRs #18, #19 and #20.

## Interpretation

Unchanged from r2.
