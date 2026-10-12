# REQ-SEC: security and safety

### REQ-SEC-001: No third-party flooding
- status: met
- spec: §6.2, §6.7
- evidence: EXP-0002-r10, EXP-0006-r6

The responder cannot be made to send traffic toward an address that has not completed authentication, beyond the anti-amplification allowance. Every sender is bounded by the dead-man switch and the data and rate caps.

### REQ-SEC-002: Key handling
- status: met
- spec: new
- evidence: EXP-0006-r6

Private keys live in `$XDG_CONFIG_HOME/pathtrace/` with mode 0600. The tool refuses group- or world-readable private keys, and no key material is committed to the repository.

### REQ-SEC-003: Contained unsafe code
- status: met
- spec: §13.3
- evidence: EXP-0006-r6

`unsafe` is forbidden in every crate except `pt-sys`, and each unsafe block there carries a `SAFETY` justification (enforced by lints).

### REQ-SEC-004: Fuzzed parsers
- status: met
- spec: §13.3
- evidence: EXP-0005-r3

PTF parsing, control messages and probe packets have cargo-fuzz targets, smoke-run in CI.

### REQ-SEC-005: Enforced dependency policy
- status: met
- spec: §13.2
- evidence: EXP-0006-r6

`cargo-deny` enforces the license allowlist, rejects known advisories, and bans async runtimes and protocol stacks.
