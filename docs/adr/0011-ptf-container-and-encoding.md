# 0011: PTF container and encoding: chunked sections, own deterministic CBOR codec, columnar tables, zstd

- status: accepted
- date: 2026-10-10
- requirements: REQ-FMT-001, REQ-FMT-004, REQ-FMT-005, REQ-FMT-012, REQ-FMT-015
- evidence: EXP-0001, R-0007

## Context

PTF has to carry kilobytes of metadata alongside hundreds of thousands of per-packet rows per session. It has to survive crashes mid-write, stay readable forever, be implementable from a document, and stay small (docs/design/ptf-format.md, P1–P14).

## Options considered

1. **JSON Lines + zstd**: the simplest, human-readable, universal. Row-oriented with repeated keys, so size per packet depends entirely on zstd. No types (int vs float is ambiguous), no binary.
2. **CBOR rows + zstd**: binary and typed, but still row-oriented.
3. **Apache Arrow IPC (or Parquet) + zstd**: columnar, mature, with many readers. Heavy dependency tree. The stream format can be appended to, but recovery from a torn write is not part of the format. Small typed metadata (provenance, CBOR-like nesting) fits awkwardly in schema metadata strings.
4. **SQLite**: queryable, but its file bytes are not deterministic and it is not append-only. Crash safety needs WAL configuration, and an independent implementation means implementing SQLite.
5. **Custom chunked container** (PNG-style typed sections with CRC) holding deterministic-CBOR heads and self-describing columnar tables with per-column encodings, compressed per section with zstd.

For CBOR within option 5: (a) the `minicbor` crate, or (b) a small in-crate codec over a `Value` tree. Option (b) can enforce the deterministic profile exactly on both encode and decode (key order, shortest forms, depth limit, rejecting non-canonical input), which the content digest depends on, in a few hundred lines with no dependency.

## Decision

Option 5 with codec (b). EXP-0001 confirmed it: the canonical encoding costs 4.5–5.0 B/packet against 9–12 B/packet for Arrow IPC, CBOR rows and JSON Lines with zstd, and it encodes 1.37 M packets in 0.35 s. EXP-0001 also fixed the canonical parameters: zstd level 19 (only 0.4–3% smaller than level 3, but cheap at merge time), 65 536-row chunks (size-neutral, with bounded memory), and delta2 for timestamps (3–13% smaller than delta).

## Consequences

- One small, fully specified format, with an independent Python reader as proof of implementability.
- No ecosystem reader exists. Mitigations: the JSON Lines twin (`trace dump`) and exporters.
- The canonical form depends on the zstd level fixed in the specification; the content digest is independent of compression.
