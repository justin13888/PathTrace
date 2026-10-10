# PathTrace

PathTrace records what a network path does to packets and writes it to **PTF** (Path Trace Format), an open, versioned, self-describing trace file. A trace-driven emulator can later replay the path for unmodified protocol implementations.

A trace records path behaviour, never what a protocol achieved over the path. That behaviour covers:

- capacity over time, including what short bursts experience;
- one-way delay and jitter;
- loss and its burst structure;
- queue depth and discipline, and policers;
- reordering and duplication;
- path MTU and ECN/DSCP handling;
- per-transport treatment (UDP high port, UDP/443, QUIC-shaped, TCP/80, TCP/443 TLS);
- NAT binding lifetime.

Every derived number carries its method, version and confidence. Every raw observation is kept, so traces can be re-derived as methods improve.

## Scope

- Linux only (x86_64, aarch64, kernel ≥ 6.1), IPv4 and IPv6. ([ADR 0002](docs/adr/0002-linux-only.md))
- Two endpoints you control: an initiator (your laptop, on any access network) and a responder (a public Linux VM).
- Access networks up to 1 Gbit/s. One path, two endpoints: no topology or cross-traffic modelling.
- This release captures, derives and exports. The emulator, runner and fidelity scoring are tracked as issues labelled [`deferred`](https://github.com/justin13888/PathTrace/labels/deferred).

## Quickstart

1. Install the static binary from the latest [release](https://github.com/justin13888/PathTrace/releases) on both machines, or build it: `mise install && cargo build --release -p pathtrace`.
2. Deploy the responder on the VM and pair the laptop: [docs/runbooks/responder-deploy.md](docs/runbooks/responder-deploy.md).
3. Verify: `pathtrace doctor vm`, then `pathtrace probe vm --class home --profile smoke`.
4. Capture on real networks: [docs/runbooks/field-session.md](docs/runbooks/field-session.md).

```sh
pathtrace probe vm --class hotel-wifi --label "Hotel X lobby"   # ~100 s, ≤ 200 MB (light: ≤ 2 MB on metered links)
pathtrace trace info <id>.ptf
pathtrace export netem <id>.ptf          # replay a static summary with tc netem today
pathtrace export mahimahi <id>.ptf -o t  # Mahimahi up/down traces
pathtrace trace redact <id>.ptf --level shareable -o shared.ptf
```

## What is proven

Claims are backed by commit-pinned experiments ([docs/evidence/](docs/evidence/)) and checked mechanically by `cargo xtask audit`:

- PTF's encoding costs about 5 bytes per packet, 2–2.6× smaller than Arrow IPC, CBOR rows or JSON Lines with zstd ([EXP-0001](docs/evidence/EXP-0001-ptf-encoding-bakeoff/)).
- The probe recovers known capacity, delay, buffer, loss, jitter, reordering, duplication, MTU, policer, AQM/ECN, DSCP rewriting, per-class throttling, UDP blocking and NAT behaviour, injected in unprivileged network namespaces. A trace exported to netem reproduces itself when re-captured (see [docs/design/simulator-requirements.md](docs/design/simulator-requirements.md) for the sufficiency matrix).

## Repository map

| Path | Contents |
|---|---|
| [`crates/`](crates/) | `pt-format` (PTF), `pt-wire`, `pt-sys` (Linux syscalls), `pt-probe` (capture), `pt-derive` (model, exports), `pathtrace` (CLI) |
| [`xtask/`](xtask/) | Evidence runner, audit, ground-truth experiments |
| [`docs/`](docs/) | Requirements → designs → ADRs → evidence, plus research and runbooks |
| [`deploy/`](deploy/) | systemd unit and firewall ports for the responder |
| [`tools/`](tools/) | Namespace test harness; independent Python PTF reader |
| [`references/`](references/) | Third-party fixtures with provenance |
| [`AGENTS.md`](AGENTS.md) | Contributor and agent rules: scopes, commits, merging, evidence workflow |

The PTF specification is [docs/design/ptf-format.md](docs/design/ptf-format.md).

## Development

```sh
mise install        # pinned toolchain and tools
hk install          # git hooks (pre-commit, commit-msg)
mise run check      # format, lint, spelling, deny
mise run test       # tests
mise run test-netns # end-to-end session in unprivileged network namespaces
mise run audit      # requirement → evidence chain
```

Contribution rules (Conventional Commits with a closed scope set, merge-commit-only history, design before code, commit-pinned evidence) are in [AGENTS.md](AGENTS.md).

## License

[Apache-2.0](LICENSE).
