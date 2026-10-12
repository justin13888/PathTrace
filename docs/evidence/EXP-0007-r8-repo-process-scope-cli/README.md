# EXP-0007-r8: Repository process, scope, CLI surface, derivation purity, provenance (1.1)

- verdict: pass (31 checks)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0007-r7](../EXP-0007-r7-repo-process-scope-cli/) (29 of 30: its raw-section comparison counted the file header, whose minor 1.1 re-derivation raises)
- requirements: see `experiment.toml`

## Method

`check.sh` is r7's with one change to the derivation-purity check: the raw-section comparison skips the first JSON-twin line (the file header, not a section), and a separate check asserts that re-deriving the 1.0 golden trace raises the header from minor 0 to minor 1, as `docs/design/ptf-format.md` specifies.

## Result

All 31 checks pass (`artifacts/checks.txt`). The audit check used the self-citation exemption: 17 of the requirements this experiment carries had no other current evidence and still cited EXP-0007-r6, which r7 superseded, when the run started; every other requirement, including the ground-truth ones citing EXP-0002-r14, had a current pass.

## Interpretation

At 1.1 the process rules hold, the code stays in scope, the documented CLI surface and exit codes are intact, derivation is deterministic, idempotent and leaves every raw section byte-identical, and traces carry their provenance.
