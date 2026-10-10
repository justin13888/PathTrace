# 0008: Capture-first release; PTF 1.0 frozen at capture-ready; permanent read compatibility

- status: accepted
- date: 2026-10-10
- requirements: REQ-FMT-009, REQ-FMT-010, REQ-CLI-002
- evidence: —

## Context

The draft's milestone order put the emulator first (M0) and froze the format last (M4, after 50 field traces). The product owner has to capture real traces within two days. A real-network session can never be repeated, while derivation (observations → model) can be re-run at any time.

## Options considered

1. **Draft order (emulator first)**: delays capture past the deadline.
2. **Capture first, format kept at 0.x**: traces captured now would carry no compatibility guarantee, and could become unreadable or need migration.
3. **Capture first, PTF 1.0 frozen at the capture-ready release, with a permanent read-compatibility contract**: the raw layer (META, FLOW, CLOK, OBSV, CTXS, EVNT) is fixed at 1.0. The derived layer (PATH, SERS, PLCY, VALD) evolves through versioned method names and minor versions, and any trace can be re-derived.

## Decision

Option 3. The emulator, runner and fidelity scoring are deferred (REQ-EMU-*, GitHub issues). Every PTF ≥ 1.0 file remains readable by every later release. Minor versions only add sections, columns and keys; a key or column name is never reused with a new meaning. Golden files from each release stay in the conformance corpus forever. A future simulator handles an older trace by re-deriving it with current methods, or by treating missing fields as `unknown`.

## Consequences

- The raw layer must be complete on day one; this is why the probe records everything observable (including context that cannot be recovered later) and why format sufficiency is demonstrated by experiment (REQ-FMT-022) before the freeze.
- Breaking a critical section later requires a major version, an ADR and a reader that still accepts 1.x.
- CLI commands and flags are stable from 1.0.
