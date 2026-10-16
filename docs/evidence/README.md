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
- A run supersedes its predecessor as soon as its manifest exists, whatever its verdict. Right after committing a superseding run, move the requirement citations to it, before running anything that audits (EXP-0007-r4 failed this way). An experiment that audits the chain cannot vouch for itself: requirements whose only evidence is that experiment's own lineage are exempt from its audit check (EXP-0007-r5).
- Failed experiments stay; they are evidence too.
- `covers` lists the source paths whose behaviour the experiment measures. If any of them change after `pinned_commit`, `cargo xtask audit` reports the experiment as **stale** (warning on branches, error with `--release`).
- Pinned commits stay reachable because `main` only takes merge commits (see `AGENTS.md`).

## Index

| ID | Title | Verdict | Status | Requirements |
|---|---|---|---|---|
| [EXP-0001](EXP-0001-ptf-encoding-bakeoff/) | PTF raw-layer encoding bake-off | pass | superseded by EXP-0001-r2 | REQ-FMT-005, REQ-FMT-015 |
| [EXP-0001-r2](EXP-0001-r2-ptf-encoding-bakeoff/) | PTF raw-layer encoding bake-off (rerun at the capture-ready format) | pass | superseded by EXP-0001-r3 | REQ-FMT-005, REQ-FMT-015 |
| [EXP-0001-r3](EXP-0001-r3-ptf-encoding-bakeoff/) | PTF raw-layer encoding bake-off (re-run at PTF 1.1) | pass | **current** | REQ-FMT-005, REQ-FMT-015 |
| [EXP-0002](EXP-0002-ground-truth-recovery/) | Ground-truth recovery and netem closure across 18 namespace scenarios | fail | superseded by EXP-0002-r2 | 26 (see `experiment.toml`) |
| [EXP-0002-r2](EXP-0002-r2-ground-truth-recovery/) | Ground-truth recovery and netem closure across 23 namespace scenarios (all profiles, IPv6) | fail | superseded by EXP-0002-r3 | 31 (see `experiment.toml`) |
| [EXP-0002-r3](EXP-0002-r3-ground-truth-recovery/) | Ground-truth recovery and netem closure across 23 namespace scenarios (after the hard data-cap fix) | pass | superseded by EXP-0002-r4 | 31 (see `experiment.toml`) |
| [EXP-0002-r4](EXP-0002-r4-ground-truth-recovery/) | Ground-truth recovery and netem closure across 23 namespace scenarios (release re-run) | pass | superseded by EXP-0002-r5 | 31 (see `experiment.toml`) |
| [EXP-0002-r5](EXP-0002-r5-ground-truth-recovery/) | Ground-truth recovery and netem closure across 23 namespace scenarios (release re-run after the musl fix) | pass | superseded by EXP-0002-r6 | 31 (see `experiment.toml`) |
| [EXP-0002-r6](EXP-0002-r6-ground-truth-recovery/) | Ground-truth recovery and netem closure across 23 namespace scenarios (re-run for 1.0.1: doctor warm-up fix) | fail | superseded by EXP-0002-r7 | 31 (see `experiment.toml`) |
| [EXP-0002-r7](EXP-0002-r7-ground-truth-recovery/) | Ground-truth recovery and netem closure across 23 namespace scenarios (1.0.1: GE counts, family-wise interval check) | fail | superseded by EXP-0002-r8 | 31 (see `experiment.toml`) |
| [EXP-0002-r8](EXP-0002-r8-ground-truth-recovery/) | Ground-truth recovery and netem closure across 23 namespace scenarios (1.0.1: GE counts, family-wise intervals, ECT-either ECN check) | pass | superseded by EXP-0002-r9 | 31 (see `experiment.toml`) |
| [EXP-0002-r9](EXP-0002-r9-ground-truth-recovery/) | Ground-truth recovery and netem closure across 30 namespace scenarios (1.1: host-side losses, byte allowances, dead-man pauses) | fail | superseded by EXP-0002-r10 | 32 (see `experiment.toml`) |
| [EXP-0002-r10](EXP-0002-r10-ground-truth-recovery/) | Ground-truth recovery and netem closure across 30 namespace scenarios (1.1, 3 scenarios at a time) | fail | superseded by EXP-0002-r11 | 32 (see `experiment.toml`) |
| [EXP-0002-r11](EXP-0002-r11-ground-truth-recovery/) | Ground-truth recovery and netem closure across 31 namespace scenarios (1.1, quiet host) | fail | superseded by EXP-0002-r12 | 32 (see `experiment.toml`) |
| [EXP-0002-r12](EXP-0002-r12-ground-truth-recovery/) | Ground-truth recovery and netem closure across 31 namespace scenarios (1.1, quiet host, one scenario at a time) | fail | superseded by EXP-0002-r13 | 32 (see `experiment.toml`) |
| [EXP-0002-r13](EXP-0002-r13-ground-truth-recovery/) | Ground-truth recovery and netem closure across 31 namespace scenarios (1.1, quiet for the whole run, one scenario at a time) | fail | superseded by EXP-0002-r14 | 32 (see `experiment.toml`) |
| [EXP-0002-r14](EXP-0002-r14-ground-truth-recovery/) | Ground-truth recovery and netem closure across 31 namespace scenarios (1.1, one scenario at a time, slotted rcvbuf delivery) | pass | superseded by EXP-0002-r15 | 32 (see `experiment.toml`) |
| [EXP-0002-r15](EXP-0002-r15-ground-truth-recovery/) | Ground-truth recovery and netem closure across 31 namespace scenarios, and the netns suite, on Linux after the macOS capture path (#63, #83) | fail | superseded by EXP-0002-r16 | 32 (see `experiment.toml`) |
| [EXP-0002-r16](EXP-0002-r16-ground-truth-recovery/) | Ground-truth recovery and netem closure across 31 namespace scenarios, and the netns suite, on Linux after the macOS capture path (#63, #83; re-run of r15) | fail | **current** | 32 (see `experiment.toml`) |
| [EXP-0003](EXP-0003-conformance-independent-reader/) | Independent Python reader and Rust reader agree on the v1.0 conformance corpus | pass | superseded by EXP-0003-r2 | 9 (see `experiment.toml`) |
| [EXP-0003-r2](EXP-0003-r2-conformance-independent-reader/) | Independent Python reader and Rust reader agree on every conformance directory (incl. a real golden trace) | pass | superseded by EXP-0003-r3 | 9 (see `experiment.toml`) |
| [EXP-0003-r3](EXP-0003-r3-conformance-independent-reader/) | Independent Python reader and Rust reader agree on every conformance directory (incl. a real golden trace) | pass | superseded by EXP-0003-r4 | 9 (see `experiment.toml`) |
| [EXP-0003-r4](EXP-0003-r4-conformance-independent-reader/) | Independent Python reader and Rust reader agree on every conformance directory (incl. the v1.1 corpus and a real golden trace) | pass | superseded by EXP-0003-r5 | 9 (see `experiment.toml`) |
| [EXP-0003-r5](EXP-0003-r5-conformance-independent-reader/) | Independent Python reader and Rust reader agree on every conformance directory (incl. the v1.1 corpus and a real golden trace) (re-run after #39 to #51) | pass | **current** | 9 (see `experiment.toml`) |
| [EXP-0004](EXP-0004-format-properties/) | PTF property and unit tests: CBOR profile, encodings, recovery, determinism, redaction | pass | superseded by EXP-0004-r2 | 7 (see `experiment.toml`) |
| [EXP-0004-r2](EXP-0004-r2-format-properties/) | PTF property and unit tests (re-run at PTF 1.1) | pass | **current** | 7 (see `experiment.toml`) |
| [EXP-0005](EXP-0005-fuzz-smoke/) | Fuzzing PTF, CBOR, JSON twin and wire parsers (120 s per target) | pass | superseded by EXP-0005-r2 | REQ-FMT-016, REQ-SEC-004 |
| [EXP-0005-r2](EXP-0005-r2-fuzz-smoke/) | Fuzzing PTF, CBOR, JSON twin and wire parsers (120 s per target) (re-run at version 1.0.0) | pass | superseded by EXP-0005-r3 | REQ-FMT-016, REQ-SEC-004 |
| [EXP-0005-r3](EXP-0005-r3-fuzz-smoke/) | Fuzzing PTF, CBOR, JSON twin and wire parsers (120 s per target) (re-run at version 1.0.1) | pass | superseded by EXP-0005-r4 | REQ-FMT-016, REQ-SEC-004 |
| [EXP-0005-r4](EXP-0005-r4-fuzz-smoke/) | Fuzzing PTF, CBOR, JSON twin and wire parsers (re-run at PTF 1.1, wire minor 1) | fail | superseded by EXP-0005-r5 | REQ-FMT-016, REQ-SEC-004 |
| [EXP-0005-r5](EXP-0005-r5-fuzz-smoke/) | Fuzzing PTF, CBOR, JSON twin and wire parsers (re-run at PTF 1.1, wire minor 1) | pass | superseded by EXP-0005-r6 | REQ-FMT-016, REQ-SEC-004 |
| [EXP-0005-r6](EXP-0005-r6-fuzz-smoke/) | Fuzzing PTF, CBOR, JSON twin and wire parsers (120 s per target) (re-run after #39 to #51) | pass | superseded by EXP-0005-r7 | REQ-FMT-016, REQ-SEC-004 |
| [EXP-0005-r7](EXP-0005-r7-fuzz-smoke/) | Fuzzing PTF, CBOR, JSON twin and wire parsers (120 s per target) (re-run at 1.1.0) | pass | **current** | REQ-FMT-016, REQ-SEC-004 |
| [EXP-0006](EXP-0006-probe-session-and-policy/) | Probe, wire and syscall tests, end-to-end namespace session, unsafe and dependency policy | pass | superseded by EXP-0006-r2 | 18 (see `experiment.toml`) |
| [EXP-0006-r2](EXP-0006-r2-probe-session-and-policy/) | Probe, wire, syscall and derive tests, end-to-end namespace session, unsafe and dependency policy | pass | superseded by EXP-0006-r3 | 17 (see `experiment.toml`) |
| [EXP-0006-r3](EXP-0006-r3-probe-session-and-policy/) | Probe, wire, syscall and derive tests, end-to-end namespace session, unsafe and dependency policy | pass | superseded by EXP-0006-r4 | 17 (see `experiment.toml`) |
| [EXP-0006-r4](EXP-0006-r4-probe-session-and-policy/) | Probe, wire, syscall and derive tests, end-to-end namespace session, unsafe and dependency policy | pass | superseded by EXP-0006-r5 | 17 (see `experiment.toml`) |
| [EXP-0006-r5](EXP-0006-r5-probe-session-and-policy/) | Probe, wire, syscall and derive tests, end-to-end namespace session, unsafe and dependency policy | pass | superseded by EXP-0006-r6 | 17 (see `experiment.toml`) |
| [EXP-0006-r6](EXP-0006-r6-probe-session-and-policy/) | Probe, wire, syscall and derive tests, end-to-end and interruption namespace sessions, unsafe and dependency policy | pass | superseded by EXP-0006-r7 | 19 (see `experiment.toml`) |
| [EXP-0006-r7](EXP-0006-r7-probe-session-and-policy/) | Probe, wire, syscall and derive tests, end-to-end and interruption namespace sessions, unsafe and dependency policy (re-run after #39 to #51) | pass | **current** | 19 (see `experiment.toml`) |
| [EXP-0007](EXP-0007-repo-process/) | Repository process: conventional history, merge-commit-only settings, license, agents file, design-first PRs | pass | superseded by EXP-0007-r2 | REQ-REPO-003, REQ-REPO-004, REQ-REPO-005, REQ-REPO-006, REQ-REPO-007, REQ-REPO-008 |
| [EXP-0007-r2](EXP-0007-r2-repo-process-scope-cli/) | Repository process, scope, CLI surface, derivation purity and in-trace provenance | pass | superseded by EXP-0007-r3 | 18 (see `experiment.toml`) |
| [EXP-0007-r3](EXP-0007-r3-repo-process-scope-cli/) | Repository process, scope, CLI surface, derivation purity and in-trace provenance | pass | superseded by EXP-0007-r4 | 18 (see `experiment.toml`) |
| [EXP-0007-r4](EXP-0007-r4-repo-process-scope-cli/) | Repository process, scope, CLI surface, derivation purity and in-trace provenance | fail | superseded by EXP-0007-r5 | 18 (see `experiment.toml`) |
| [EXP-0007-r5](EXP-0007-r5-repo-process-scope-cli/) | Repository process, scope, CLI surface, derivation purity and in-trace provenance | pass | superseded by EXP-0007-r6 | 18 (see `experiment.toml`) |
| [EXP-0007-r6](EXP-0007-r6-repo-process-scope-cli/) | Repository process, scope, CLI surface, derivation purity and in-trace provenance | pass | superseded by EXP-0007-r7 | 18 (see `experiment.toml`) |
| [EXP-0007-r7](EXP-0007-r7-repo-process-scope-cli/) | Repository process, scope, CLI surface, derivation purity and in-trace provenance (re-run at 1.1) | fail | superseded by EXP-0007-r8 | 18 (see `experiment.toml`) |
| [EXP-0007-r8](EXP-0007-r8-repo-process-scope-cli/) | Repository process, scope, CLI surface, derivation purity and in-trace provenance (1.1, header minor apart from raw sections) | pass | **current** | 18 (see `experiment.toml`) |
| [EXP-0008](EXP-0008-release-artefacts/) | Release v1.0.0: published static binaries verified end to end | pass | superseded by EXP-0008-r2 | REQ-REPO-009 |
| [EXP-0008-r2](EXP-0008-r2-release-artefacts/) | Release v1.0.1: published static binaries verified end to end | pass | superseded by EXP-0008-r3 | REQ-REPO-009 |
| [EXP-0008-r3](EXP-0008-r3-release-artefacts/) | Release v1.1.0: published static binaries verified end to end | pass | **current** | REQ-REPO-009 |

## Planned

- **Overlay ground truth, macOS initiator against a Linux responder (#66).** Not yet run. The harness is `tools/overlay-gt/` and the checker `cargo xtask overlay-gt check <dir>` (docs/design/overlay-ground-truth.md, which fixes the schedule and tolerances before the run). The experiment's command runs `tools/overlay-gt/run.sh` from the Mac while the owner holds `sudo tools/overlay-gt/impair.sh` open on the responder, then the checker with `PT_EVIDENCE_OUT` set, so `artifacts/` gets only `results.md`, `results.csv` and `summary.json`, never the traces or the scratch directory with the session file.
