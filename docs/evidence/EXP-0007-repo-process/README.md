# EXP-0007: Repository process

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: REQ-REPO-003, -004, -005, -006, -007, -008

## Hypothesis

The repository's process rules hold mechanically, not just on paper.

## Method

`check.sh` (committed before the run) checks:

1. Every non-merge commit reachable from HEAD passes `convco check` against `.convco` (closed types and scopes) and has a scope (REQ-REPO-003).
2. GitHub settings: merge commits only, with squash and rebase disabled. The `Protect main` ruleset is active with `non_fast_forward`, `deletion` and `allowed_merge_methods = ["merge"]` (REQ-REPO-004).
3. `mise.lock` present; `mise ls --current` lists every pinned tool (REQ-REPO-005).
4. The GitHub licence API reports `Apache-2.0` for the verbatim LICENSE (REQ-REPO-006).
5. `CLAUDE.md` is a symlink to `AGENTS.md` (REQ-REPO-007).
6. For each merged PR (first-parent merge commits), the first commit of the PR branch is documentation (`docs(...)`): design precedes code (REQ-REPO-008).

## Result

All checks PASS (`artifacts/checks.txt`). PRs #18, #19 and #20 each start with a `docs(research)` or `docs(design)` commit. Raw API responses are in `artifacts/merge_settings.json`, `ruleset.json` and `license_spdx.txt`.

## Interpretation

The check is a snapshot of GitHub settings at run time. It does not prevent them from being changed later; re-running the experiment re-verifies them. The design-first rule is verified at PR granularity (first commit), not per change.
