# AGENTS.md

Agent rulebook for PathTrace. Dense by design. CLAUDE.md is a symlink to this file. Directory READMEs are authoritative for their own conventions; this file links them rather than repeating them.

## Product
- PathTrace: Linux tool that records what a network path does to packets (capacity over time, delay, jitter, loss, queue, policers, reorder, dup, MTU, ECN/DSCP, per-transport treatment) between two endpoints the user controls, into PTF (Path Trace Format, `.ptf`), for a future trace-driven emulator.
- Central rule: a trace records path behaviour, never what a protocol achieved over it.
- Capture is irreversible, derivation is not: never lose or alter raw observations; derived model (PATH) is re-derivable from raw (OBSV etc.).
- Requirements: docs/spec/REQ-*.md. Design: docs/design/. Decisions: docs/adr/. Proof: docs/evidence/. External facts: docs/research/.

## Scopes (hard boundaries)
- Platform: Linux only, all roles (initiator, responder, tooling). x86_64 + aarch64. Kernel >= 6.1. IPv4 + IPv6. No macOS/Windows/mobile code paths, no cfg for them.
- Path: exactly two endpoints, one path. No topology, multipath, cross-traffic modelling, chaos/fault injection, pcap replay, protocol (QUIC/HTTP) analysis.
- Rates: access networks up to 1 Gbit/s; probe hard rate cap default 500 Mbit/s.
- Peers: probe only talks to the user's own Noise-authenticated responder.
- In this release: format, probe, responder, derivation, exports, CLI. Emulator/runner/fidelity scoring are deferred (GitHub issues labelled `deferred`, docs/spec/REQ-EMU.md).

## Crate map (details: crates/README.md)
- pt-format: PTF read/write/validate, JSONL twin, import/export. forbid(unsafe).
- pt-wire: probe header + control messages. forbid(unsafe).
- pt-sys: Linux syscalls (sockets, timestamping, mmsg, cmsg, TCP_INFO, clocks, netlink). ONLY crate allowing unsafe; every unsafe block needs `// SAFETY:`.
- pt-probe: session, phases, responder, obslog. No async runtime; threads only.
- pt-derive: raw -> PATH model. Pure.
- pathtrace: CLI.
- xtask: evidence runner, audit, ground-truth netns harness (only place allowed to exec ip/tc/nft/ethtool).
- tools/ptf-py: independent Python PTF reader written only from docs/design/ptf-format.md (conformance proof). Do not port Rust code into it.

## Dependency policy
- Measurement crates forbid: tokio, async-std, smol, quinn, hyper, h2, any packet-batching layer, shelling out to ip/tc/ethtool/nft. Enforced by deny.toml bans where possible.
- New dependency: justify in PR description; check license is in deny.toml allowlist (Apache-2.0 compatible).

## Commands (all tools pinned in mise.toml; run `mise install` first)
- `mise run check`: fmt check, clippy -D warnings, typos, taplo, actionlint, shellcheck.
- `mise run test`: cargo nextest (unit + integration not needing namespaces).
- `mise run test-netns`: integration tests inside unprivileged user+net namespaces (needs `unshare -Urn` to work; on Ubuntu set `kernel.apparmor_restrict_unprivileged_userns=0`). A skip is a failure in CI.
- `mise run fuzz`: short cargo-fuzz smoke on all targets (nightly, pinned).
- `mise run audit` = `cargo xtask audit`: requirement/evidence chain. `--release` also fails on stale/pending evidence.
- `cargo xtask evidence new <slug>` / `cargo xtask evidence run EXP-NNNN`.
- `hk install` once per clone: installs pre-commit + commit-msg hooks.

## Commits
- Conventional Commits, validated by convco at commit-msg (hk) and over the PR range in CI. Config: .convco.
- Types: feat fix docs test refactor perf build ci chore revert.
- Scopes (closed set, required): format wire sys probe derive cli xtask harness docs adr evidence research deploy ci repo deps.
- One logical change per commit; every commit builds and passes tests. Breaking change: `!` + `BREAKING CHANGE:` footer.
- Evidence commits: `docs(evidence): EXP-NNNN <slug>` containing only that experiment's manifest, artifacts, README.
- No `TODO` without an issue: write `TODO(#NN)`. hk rejects bare TODO/FIXME.

## Branches and merging
- Merge rule: PRs into `main` land only as merge commits (`--no-ff`) of conventional-commit branches; no squash, no rebase-merge, no force-push, no history rewrite; every commit on main builds.
- Why: full history is the audit trail, and evidence manifests pin feature-branch commits that must stay reachable from main (squash would orphan them).
- Branch names: `<type>/<kebab-topic>` e.g. `feat/format-container`, `docs/spec-distillation`.
- Flow: branch from main -> design commit first -> code + tests -> evidence run on clean tree -> evidence commit -> PR (link design section, REQ ids) -> CI green -> `gh pr merge --merge`.
- Never `git push --force`, never amend/rebase published commits. Fix mistakes with new commits (or `git revert`).

## Evidence workflow (details: docs/evidence/README.md)
- experiment.toml committed before running. Run only on clean tree (xtask refuses otherwise). Manifest pins HEAD and hashes artifacts. Never edit/delete a run; supersede it.
- A requirement may be `met` only with a current passing experiment. Failed results are kept.

## Docs rules
- Design precedes code. Design decision shape: Problem / Constraints / Alternatives / Choice / Rationale / Validated by.
- ADRs immutable once accepted (docs/adr/README.md). Departures from the original draft spec always get an ADR.
- Research notes cite URL + access date + quote; verdict confirmed/partially-confirmed/refuted/unverifiable (docs/research/README.md).
- Requirement syntax and statuses: docs/spec/README.md.

## PTF compatibility contract
- Every PTF >= 1.0 file stays readable by every later pathtrace. Additive changes only in minor versions (new non-critical sections, new columns, new CBOR keys). Never reuse a key or column name with new meaning. Golden files of every release live in the conformance corpus and are tested forever.
- Changing meaning of a critical section = major bump = needs ADR.
- CLI commands and flags are stable from 1.0; removal requires a deprecation warning for at least one minor release.
