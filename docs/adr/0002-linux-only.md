# 0002: Linux only, for every role

- status: accepted
- date: 2026-10-10
- requirements: REQ-SCOPE-001
- evidence: —

## Context

The draft spec (§3, §6.8) had a cross-platform probe: Linux tier 1, a macOS initiator tier 1, a Windows initiator tier 2, and mobile later. The emulator was Linux only. The product owner has scoped the tool to Linux and Linux only. The initiator runs on a Linux laptop and the responder on a Linux VM.

## Options considered

1. **Cross-platform probe as drafted**: three timestamping models (SO_TIMESTAMPING, mach_continuous_time plus kernel receive stamps, QPC), three pacing models, and a no-OS-assumption probe core. Roughly triples the I/O and test surface; macOS and Windows cannot be exercised in unprivileged namespaces or the CI used here.
2. **Linux only**: one I/O path, built on the best timestamping available (kernel TX/RX software stamps, hardware where present). Everything can be tested end to end in network namespaces.

## Decision

Linux only for every role: x86_64 and aarch64, kernel 6.1 or newer (oldest current LTS with all needed socket options and TCP_INFO fields). No `cfg` branches or abstractions for other operating systems.

## Consequences

- `pt-format` no longer needs `no_std` (the embedding rationale was the mobile probe; see ADR 0009).
- The probe may use Linux-only facilities freely: `SO_TIMESTAMPING`, error queues, `recvmmsg`, netlink, nl80211.
- Captures from macOS/Windows laptops are impossible; users boot Linux (a live USB works) on the roaming laptop.
- Reversal would mean adding a platform abstraction layer under `pt-sys`; the PTF format already records the timestamp source per flow, so traces from other platforms would remain representable.
