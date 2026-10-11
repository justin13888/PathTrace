# EXP-0007-r4: Repository process, scope, CLI surface, derivation purity, provenance (re-run)

- verdict: **fail** (22 of 23 checks pass; the audit-chain check fails)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0007-r3](../EXP-0007-r3-repo-process-scope-cli/) (stale after the doctor fix in `crates/pathtrace/src`)
- requirements: see `experiment.toml`

## Result

Every process, scope, CLI, purity, provenance and doctor check passes (`artifacts/checks.txt`). The new release PR #25 is also seen to start with a design commit. `cargo xtask audit` reports 15 errors (`artifacts/audit.txt`). Each one is a requirement that cites EXP-0006-r3.

## Root cause

EXP-0006-r4 was committed just before this run, and it supersedes EXP-0006-r3. The audit only accepts evidence that is not superseded, so every requirement that still cited r3 lost its current evidence. The requirement citations had not yet been moved to r4. This is a sequencing error in the re-run batch, not a defect in the code. The audit caught it as designed.

## Fix

The citations now name EXP-0006-r4, and the experiment is re-run as EXP-0007-r5. Rule recorded in docs/evidence/README.md: after committing a superseding run, update the requirement citations before running anything that audits.
