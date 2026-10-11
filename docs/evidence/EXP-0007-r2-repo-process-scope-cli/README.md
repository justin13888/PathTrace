# EXP-0007-r2: Repository process, scope, CLI surface, derivation purity, provenance

- verdict: pass (23 checks)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0007](../EXP-0007-repo-process/) (stale after AGENTS.md changes; scope, CLI, purity and provenance checks added)
- requirements: see `experiment.toml`

## Method

`check.sh` (committed before the run):

| # | Check | Requirement |
|---|---|---|
| 1–6 | As EXP-0007: conventional history with the closed scope set; merge-commit-only settings and ruleset; Apache-2.0 detected; CLAUDE.md symlink; pinned tools; design-first PRs | REQ-REPO-003…008 |
| 7 | `cargo xtask audit`: chain intact | REQ-REPO-001, -002 |
| 8 | No `target_os` code except Linux; exactly two endpoint roles; PATH derivation never reads protocol results (`tcpinfo`/`app` feed only VALD); no topology, chaos, replay or emulator crates; rate cap defaults to 500 Mbit/s in `probe` and `serve` | REQ-SCOPE-001…005 |
| 9 | Every documented command and trace subcommand exists; `trace info/check --json` parse; exit codes 0 (valid), 1 (invalid file), 2 (usage) | REQ-CLI-001, -003, -004 |
| 10 | `derive` run twice on the golden trace gives byte-identical files (deterministic, idempotent), raw sections stay identical to the input (JSON twin compared), META carries the tool commit and dirty flag, and every PATH field has a versioned method and a status | REQ-DRV-001, -012, REQ-FMT-008 |
| 11 | `doctor --json` runs with a fresh key and reports ok local checks | REQ-PRB-025 |

## Result

All checks PASS (`artifacts/checks.txt`).

## Interpretation

Scope checks are structural proxies (for example, "two roles" stands in for "one path, two endpoints"). They catch accidental scope creep in code, not every conceivable violation. `doctor` was checked locally; its responder-side checks (TCP reachability) are exercised in the field runbook.
