# 0014: Linux and macOS are the only supported targets; macOS runs the initiator

- status: accepted
- date: 2026-10-13
- requirements: REQ-SCOPE-001, REQ-SCOPE-009, REQ-PRB-033, REQ-REPO-010
- evidence: R-0017, R-0010
- supersedes: 0002

## Context

ADR 0002 scoped every role to Linux, so a user whose roaming laptop is a Mac had to boot Linux to capture. The product owner now wants macOS laptops to capture too: only Linux and macOS are supported targets. The responder is a public VM, which is Linux in every deployment described (deploy/, docs/runbooks/responder-deploy.md). R-0017 records what macOS offers an initiator: kernel RX stamps at socket enqueue (`SO_TIMESTAMP` in wall-clock µs, `SO_TIMESTAMP_MONOTONIC` in `mach_absolute_time` ticks), no kernel TX stamps, no error queue, `IP_DONTFRAG`/`IPV6_DONTFRAG`, `TCP_CONNECTION_INFO` instead of `TCP_INFO`, no public `sendmmsg`/`recvmmsg`, only host-wide UDP socket-full drops, no output-queue drop counter, timer coalescing governed by thread QoS, and different `SOL_SOCKET` option numbers.

## Options considered

1. **Keep Linux only** (ADR 0002). Simplest, but Mac users must boot Linux to capture, which is the main obstacle to the field corpus on the networks they roam.
2. **macOS for every role.** A macOS responder adds a second server I/O path, service management (launchd) and deployment for no deployment that needs it.
3. **macOS for the initiator roles only, Linux for every role.** Captures from Mac laptops become possible; the responder, whose stamps carry the half of each path the Mac cannot stamp in the kernel, stays on the best facility (Linux `SO_TIMESTAMPING`).
4. **A platform abstraction across all crates** (`cfg` wherever behaviour differs). Spreads platform knowledge through the probe and makes each crate's tests platform-dependent.

## Decision

Option 3, with platform code confined as below.

- **Linux**: every role, unchanged: x86_64 and aarch64, kernel 6.1 or newer.
- **macOS**: the initiator roles on aarch64-apple-darwin, macOS 15 or newer: `keygen`, `responder add`/`list`, `probe`, `fetch`, `merge`, `derive`, `export`, `import`, `trace`, `doctor`. `serve` and `authorize` (the responder) are not supported on macOS and are deferred (#67), as is x86_64-apple-darwin (#69).
- **Nothing else**: no code paths, configuration or CI for Windows, Android or iOS.
- **Where platform code lives**: only in `pt-sys`, in per-OS backends selected by `cfg(target_os = "linux")` and `cfg(target_os = "macos")`. `pt-sys` exposes capabilities (for example "kernel TX stamps available", "per-socket receive drops available"); `pt-probe`, `pt-derive`, `pt-format`, `pt-wire` and the CLI branch on capabilities, never on `cfg`. Constants come from the target's `libc` definitions, never from Linux numbers (R-0017: Linux `SO_SNDBUFFORCE` 32 is macOS `SO_BROADCAST`).
- **What a macOS capture records**: every packet the probe sends and receives, with the best stamp available, the stamp's source recorded and its clock domain declared, and clock pairs relating the domains (ADR 0012's rule). A fact the platform cannot observe (kernel TX stamps, error-queue PMTU and send-error reports, per-socket receive drops, egress qdisc and output-queue drops) is recorded as unknown, never as zero, so derivation does not read it as "no loss" or "no delay" (REQ-PRB-033).

macOS 15 is the floor because it is the oldest release CI builds and tests on (the `macos-15` runner, #65); R-0017 found nothing that needs a newer release. Raising or lowering it is a new ADR.

## Consequences

- REQ-SCOPE-001 is dropped and replaced by REQ-SCOPE-009. REQ-PRB-017 (Linux I/O) and REQ-REPO-009 (Linux release binaries) keep their meaning; REQ-PRB-033 and REQ-REPO-010 add the macOS counterparts.
- macOS captures carry user-space TX stamps, so one-way delay and inter-departure times on the Mac's send side include host scheduling noise that Linux kernel stamps avoid. PTF already keeps the user-space TX time beside nullable kernel TX stamps, records the RX stamp source per packet and declares each time column's clock domain (R-0017); derivation must use them. Facts PTF cannot yet express (host OS, Darwin TCP state, an overlay egress interface) are added additively in a minor version (#62), under the PTF compatibility contract.
- The macOS backend cannot be tested in network namespaces. Its correctness rests on unit tests of `pt-sys`, CI on a macOS runner and evidence experiments against a Linux responder; the ground-truth harness stays Linux only until a macOS equivalent exists (#71).
- The work is tracked in GitHub issues labelled `macos`: design (#60), the `pt-sys` backend (#61), PTF additions (#62), capture and derivation (#63), `doctor` (#64), CI and the release artefact (#65), evidence (#66); deferred: #67 to #72. This ADR changes no code.
- Reversal: delete the macOS backend of `pt-sys` and drop REQ-SCOPE-009, REQ-PRB-033 and REQ-REPO-010 with a new ADR; Linux behaviour is untouched by this decision.
