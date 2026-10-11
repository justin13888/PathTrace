# REQ-REPO: repository process

### REQ-REPO-001: Mechanical audit chain
- status: met
- spec: new
- design: docs/README.md
- evidence: EXP-0007-r3

`cargo xtask audit` verifies, in CI on every PR, that every `met` requirement has current passing evidence, every evidence manifest pins a commit reachable from `HEAD`, every artifact hash matches, and reports evidence made stale by later changes to the code it covers.

### REQ-REPO-002: Commit-pinned evidence
- status: met
- spec: new
- design: docs/evidence/README.md
- evidence: EXP-0007-r3

Experiments run only on a clean working tree; the manifest records the commit, command, host and BLAKE3 of each artifact. Completed experiments are never edited or deleted, only superseded.

### REQ-REPO-003: Semantic commits with a closed scope set
- status: met
- spec: new
- evidence: EXP-0007-r3

Every commit message follows Conventional Commits with a type and a scope from the closed set in `AGENTS.md`, enforced by a commit-msg hook (hk + convco) and by CI over the PR range.

### REQ-REPO-004: Merge-commit-only, never rewritten history
- status: met
- spec: new
- evidence: EXP-0007-r3

`main` accepts changes only through pull requests merged as merge commits; squash and rebase merges, force pushes and branch deletion are disabled by repository settings.

### REQ-REPO-005: Pinned tooling
- status: met
- spec: new
- evidence: EXP-0007-r3

Every development tool (Rust toolchain, hk, convco, nextest, cargo-deny, typos, taplo, actionlint, shellcheck, Python) is pinned in `mise.toml` and used through mise locally and in CI.

### REQ-REPO-006: License
- status: met
- spec: new
- adr: 0001
- evidence: EXP-0007-r3

The repository is licensed Apache-2.0 with the verbatim license text, detected as such by GitHub.

### REQ-REPO-007: Agent instructions
- status: met
- spec: new
- evidence: EXP-0007-r3

`AGENTS.md` holds agent-oriented rules (scopes, commits, merging, evidence workflow, policies); `CLAUDE.md` is a symlink to it.

### REQ-REPO-008: Design before code, immutable decisions
- status: met
- spec: new
- design: docs/design/README.md
- evidence: EXP-0007-r3

Each change that adds or alters behaviour lands its design section first; decisions that are hard to reverse or depart from the original draft spec are ADRs, immutable once accepted.

### REQ-REPO-009: Release artefacts
- status: planned
- spec: new

Tagged releases publish static (musl) `pathtrace` binaries for x86_64 and aarch64 Linux with SHA-256 checksums.
