# tools/

Helper programs that are not part of the shipped binary.

| Path | Purpose |
|---|---|
| `netns/session.sh` | Ground-truth harness: three unprivileged network namespaces (initiator, middlebox, responder) with known `tc` impairments on the middlebox, running a full `pathtrace serve`/`probe` session. Used by the `netns` integration test and by evidence experiments |
| `ptf-py/` | Independent Python reader of PTF, written only from `docs/design/ptf-format.md` (conformance proof, REQ-FMT-018) |

Rules: tools may use `ip`, `tc`, `nft` and `ethtool` (the measurement crates may not). Scripts must pass shellcheck (enforced by hk).
