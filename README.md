# PathTrace

PathTrace records what a network path does to packets and writes it to **PTF** (Path Trace Format), an open, versioned trace file built so that a trace-driven emulator can later replay the path for unmodified protocol implementations.

A trace records path behaviour (capacity over time, delay, jitter, loss and its burst structure, queue depth, policers, reordering, duplication, MTU, ECN/DSCP handling, per-transport treatment), never what a protocol achieved over that path.

> Status: under active development toward v1.0 (capture-ready). See [docs/spec/](docs/spec/) for requirement status.

## Scope

- Linux only (x86_64, aarch64, kernel ≥ 6.1), IPv4 and IPv6.
- Two endpoints you control: an initiator (your laptop on any access network) and a responder (a public Linux VM).
- Access networks up to 1 Gbit/s.

## Repository map

| Path | Contents |
|---|---|
| [`crates/`](crates/) | Rust workspace: format, wire, sys, probe, derive, CLI |
| [`xtask/`](xtask/) | Repository automation: evidence runner, audit, test harness |
| [`docs/`](docs/) | Requirements → designs → ADRs → evidence, plus research and runbooks |
| [`references/`](references/) | Third-party fixtures with provenance |
| [`AGENTS.md`](AGENTS.md) | Contributor and agent rules: scopes, commits, merging, evidence workflow |

## Development

```sh
mise install        # pinned toolchain and tools
hk install          # git hooks (pre-commit, commit-msg)
mise run check      # format, lint
mise run test       # tests
mise run audit      # requirement → evidence chain
```

Contribution rules (Conventional Commits with a closed scope set, merge-commit-only history, design before code, commit-pinned evidence) are in [AGENTS.md](AGENTS.md).

## License

[Apache-2.0](LICENSE).
