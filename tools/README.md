# tools/

Helper programs that are not part of the shipped binary. Linux and macOS are the supported targets (ADR 0014): Linux for every role, macOS for the initiator roles. Each tool below says where it runs.

| Path | Purpose |
|---|---|
| `netns/session.sh` | Ground-truth harness (Linux: network namespaces): three unprivileged network namespaces (initiator, middlebox, responder) with known `tc` impairments on the middlebox, running a full `pathtrace serve`/`probe` session. Used by the `netns` integration test and by evidence experiments |
| `overlay-gt/` | Ground truth over a real overlay path (docs/design/overlay-ground-truth.md): `impair.sh` runs once under `sudo` on the Linux responder and applies each step of `schedule` with netem on its tailnet egress, filtered to the probe's ports and the initiator's address; `run.sh` drives the steps from the initiator (macOS or Linux) over ssh and collects each step's trace, ack and snapshots. Check a run with `cargo xtask overlay-gt check <dir>` |
| `ptf-py/` | Independent Python reader of PTF (Linux and macOS, Python 3), written only from `docs/design/ptf-format.md` (conformance proof, REQ-FMT-018) |

Rules: tools may use `ip`, `tc`, `nft` and `ethtool` (the measurement crates may not). Scripts must pass shellcheck (enforced by hk).
