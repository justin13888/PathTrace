# 0005: Merge-commit-only history with commit-pinned evidence

- status: accepted
- date: 2026-10-10
- requirements: REQ-REPO-001, REQ-REPO-002, REQ-REPO-004
- evidence: —

## Context

Every product claim must be auditable by a human: what was claimed, why it was decided, and the evidence, reproducible at an exact commit. The repository has one or very few active contributors, and full history is the audit trail, so history is never rewritten.

## Options considered

1. **Squash merges**: tidy main, but the individual commits an experiment pinned are orphaned once the branch is deleted, which breaks the evidence chain.
2. **Rebase merges**: linear history, but commits are rewritten with new SHAs, which also breaks pinned SHAs.
3. **Merge commits (`--no-ff`)**: every feature-branch commit stays reachable from main, and the merge commit marks the PR boundary.

## Decision

`main` accepts PRs only as merge commits. Squash and rebase merging are disabled in repository settings, and force-push and deletion of main are blocked by a ruleset. Experiments run on a clean tree at commit X (`cargo xtask evidence run`), and the next commit adds the manifest pinning X plus the hashed artifacts. `cargo xtask audit` checks in CI that each pinned commit is an ancestor of HEAD, that each artifact hash matches, that each `met` requirement has current passing evidence, and it reports evidence whose covered paths changed since X as stale (an error on release).

## Consequences

- Branch commits must be clean and atomic, because they are permanent. Hooks enforce Conventional Commits.
- `git log --first-parent main` gives the PR-level view; full `git log` gives the detail.
- Evidence becomes stale when its code changes; releases require rerunning stale experiments, which is the intended cost of auditability.
