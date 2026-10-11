# EXP-0007-r6: Repository process, scope, CLI surface, derivation purity, provenance (re-run)

- verdict: pass (23 checks)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0007-r5](../EXP-0007-r5-repo-process-scope-cli/) (passed; went stale when pt-derive started recording the Gilbert-Elliott transition counts)
- requirements: see `experiment.toml`

## Method

Same `check.sh` as r5, including the self-citation-aware audit check.

## Result

All 23 checks pass (`artifacts/checks.txt`). This time the audit chain was intact without needing the exemption: all requirement citations were current when the run started.

## Interpretation

Derivation stays deterministic, idempotent and raw-preserving with the added keys, and every PATH field still carries a versioned method and status.
