# 0013: Refining requirements from evidence before they are first met

- status: accepted
- date: 2026-10-10
- requirements: REQ-FMT-015, REQ-SCOPE-006, REQ-SCOPE-008
- evidence: EXP-0002, EXP-0002-r2

## Context

docs/spec/README.md says that a requirement that changes meaning is dropped and replaced by a new ID. While building the evidence, two requirements written from the draft spec turned out to be imprecise. Neither had been `met` yet.

1. **REQ-FMT-015 (space budget)**. "≤ 8 B/packet" was written for the raw per-packet layer at volume. In EXP-0002 every `standard` session measured 4.8–7.4 B/packet, but `smoke` and `light` sessions measured 7.5–9.2 B/packet. With a few thousand packets, fixed per-chunk and per-column overhead dominates, and those files are 60–150 kB in total.
2. **REQ-SCOPE-006 (IPv4 and IPv6)**. Measurement over either family is verified (the ipv6 scenario), but UDP class reachability on the *secondary* family is not implemented: only TCP classes are probed there.

## Options considered

1. **Drop and re-issue IDs** for every wording change, even before a requirement was ever met. This churns IDs for no audit benefit, since nothing ever claimed the old wording was met.
2. **Refine in place while a requirement has never been `met`**, recording the reason in an ADR. Once it has been `met`, the drop-and-replace rule applies.
3. **Weaken the checks** so the original wording passes. That would hide the measurement, so it is rejected.

## Decision

Option 2.

- REQ-FMT-015 now applies its per-packet figure to `standard` and `deep` sessions. `smoke` and `light` are exempt but still measured and reported.
- REQ-SCOPE-006 now states what is delivered: measurement over the primary family, IPv4 or IPv6, with TCP class reachability on the secondary family.
- New REQ-SCOPE-008 (deferred, #21) covers UDP class reachability on the secondary family.

The process rule is added to docs/spec/README.md.

## Consequences

Requirement IDs stay stable through initial development, and every refinement is traceable to the evidence that forced it. After a requirement's first `met`, wording is frozen.
