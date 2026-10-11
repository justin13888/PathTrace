# EXP-0007-r5: Repository process, scope, CLI surface, derivation purity, provenance (re-run)

- verdict: pass (23 checks)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0007-r4](../EXP-0007-r4-repo-process-scope-cli/) (failed: requirement citations still named the just-superseded EXP-0006-r3)
- requirements: see `experiment.toml`

## Method

Same checks as r2–r4, with one change to the audit-chain check. When `cargo xtask audit` reports errors, the check passes only if every error is a requirement whose only evidence is this experiment's lineage (EXP-0007*). Those requirements cannot have current evidence until this run is committed, because the failed r4 superseded r3. Any other error fails the check.

## Result

All 23 checks pass (`artifacts/checks.txt`). The audit reported 17 errors, all of them requirements that cite EXP-0007 and await this run (`artifacts/audit.txt`, `audit_reqs.txt`). With the EXP-0006-r4 citations fixed, nothing else failed.

## Interpretation

The r4 failure was a sequencing error, and this run confirms the fix. Once this run is committed and the requirements cite it, the audit chain is intact again (checked right after).
