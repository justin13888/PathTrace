# docs/evidence/ — experiments pinned to commits

Each experiment is a directory `EXP-NNNN-kebab-slug/`, numbered sequentially. Copy `TEMPLATE/` to start one.

## Files in an experiment directory

| File | Written | Purpose |
|---|---|---|
| `experiment.toml` | by hand, committed **before** the run | Definition: title, hypothesis, command, covered paths, requirements |
| `manifest.toml` | by `cargo xtask evidence run` | Pinned commit, host, timing, exit status, verdict, BLAKE3 of every artifact |
| `artifacts/` | by the experiment command | Raw outputs (CSV/JSONL/text, kept small: < 2 MB per experiment) |
| `README.md` | by hand, after the run | Hypothesis, method, result, verdict, interpretation, links |

## Lifecycle

1. Write `experiment.toml` (and the code the experiment runs). Commit.
2. On a clean tree: `cargo xtask evidence run EXP-NNNN`. It refuses to run if the tree is dirty, runs `command` with `PT_EVIDENCE_OUT` pointing at `artifacts/`, captures stdout/stderr into `artifacts/`, reads the verdict, and writes `manifest.toml` with `pinned_commit = HEAD`.
3. Write `README.md` interpreting the result. Commit as `docs(evidence): EXP-NNNN <slug>`.
4. Verdict comes from the command: exit code 0 → `pass`, exit code 1 → `fail`, exit code 3 → `partial`, anything else → the run is an error and no manifest is written. An experiment may refine this by writing `artifacts/verdict.txt` containing `pass`, `fail` or `partial`.

## Rules

- Never delete or edit a completed experiment's artifacts or manifest. A rerun is a new experiment (or `EXP-NNNN-r2`) whose `experiment.toml` lists `supersedes = ["EXP-NNNN"]`; `cargo xtask audit` treats the superseded one as historical.
- Failed experiments stay; they are evidence too.
- `covers` lists the source paths whose behaviour the experiment measures. If any of them change after `pinned_commit`, `cargo xtask audit` reports the experiment as **stale** (warning on branches, error with `--release`).
- Pinned commits stay reachable because `main` only takes merge commits (see `AGENTS.md`).

## Index

| ID | Title | Verdict | Requirements |
|---|---|---|---|
| [EXP-0001](EXP-0001-ptf-encoding-bakeoff/) | PTF raw-layer encoding bake-off | pass | REQ-FMT-005, REQ-FMT-015 |
