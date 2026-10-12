# EXP-0007-r7: Repository process, scope, CLI surface, derivation purity, provenance (re-run at 1.1)

- verdict: **fail**, 29 of 30 checks
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0007-r6](../EXP-0007-r6-repo-process-scope-cli/) (passed; went stale when 1.1 changed its covered paths)
- requirements: see `experiment.toml`

## Method

Same `check.sh` as r6, run after EXP-0002-r14 passed and the ground-truth requirements cited it.

## Result

29 checks pass (`artifacts/checks.txt`), including the audit chain, the merge-only settings and ruleset, scope, CLI surface, exit codes, deterministic and idempotent derivation and in-trace provenance. One fails: "derive changed raw sections".

## Interpretation

- The only difference between the raw layer of `conformance/v1.0-real/smoke-ipv6-netns-anonymous.ptf` and that of its re-derivation is the first JSON-twin line, the file header: `{"ptf":{"major":1,"minor":0}}` becomes `{"ptf":{"major":1,"minor":1}}`. Every raw section line is identical.
- That is the behaviour `docs/design/ptf-format.md` specifies for 1.1 (re-deriving a 1.0 file raises the header minor to the tool's, the raw layer keeps what it had). The check predates 1.1 and counts the header line as raw, so it measures its own assumption rather than a purity defect.
- The next run (EXP-0007-r8) compares raw sections without the header line and checks the header minor separately.
