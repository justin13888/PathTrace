# 0009: pt-format uses std (no `no_std` requirement)

- status: accepted
- date: 2026-10-10
- requirements: REQ-FMT-001
- evidence: —

## Context

The draft required `pt-format` and `pt-model` to be `no_std + alloc`, so the probe core could be embedded in mobile apps. ADR 0002 removed the non-Linux platforms.

## Decision

`pt-format` uses `std`. That allows `std::io::{Read, Write}` streaming, the `zstd` crate (C libzstd: faster and better compression than pure-Rust alternatives) and simpler error types. The deferred model core (REQ-EMU-001) keeps its own no-I/O, deterministic requirement, which is about purity, not `no_std`.

## Consequences

Embedding in a non-std environment would need a later refactor; there is no such target in scope.
