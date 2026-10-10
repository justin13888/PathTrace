# 0004: Build the format, probe and derivation; defer the emulator datapath decision

- status: accepted
- date: 2026-10-10
- requirements: REQ-FMT-001, REQ-PRB-001, REQ-EMU-002
- evidence: R-0001, R-0002, R-0006

## Context

Draft spec §5.8: the recorder and the format have no open competitor, while the emulator is the most crowded piece (Mahimahi, CellReplay, Rattan). Rattan (R-0006) already offers a Rust, trace-capable datapath with Bw/Delay/Loss replay cells and a TokenBucket cell, but it records nothing, defines no rich format, and has no fidelity scoring.

## Options considered

1. **Build everything as drafted**: format, probe, model core, our own real-time driver.
2. **Build format + probe + derivation now; decide the emulator datapath later from a benchmark** (our own driver vs Rattan cells vs Mahimahi), keeping exporters to the existing tools so traces are usable right away.
3. **Adopt Rattan's datapath now**: commits to its async runtime and cell model before any measurement of it.

## Decision

Option 2. PathTrace builds what nobody else provides: the PTF format, the bidirectional probe, and derivation. It exports to Mahimahi and netem today, so captured traces can be replayed on existing emulators immediately, and Rattan export is filed as #11. The build-vs-reuse decision for the datapath is made in issue #2, backed by the benchmark the draft spec asked for. The format is designed independently of any datapath (docs/design/simulator-requirements.md).

## Consequences

- Traces are useful before PathTrace has its own emulator.
- PTF must not encode any emulator's implementation details. Exporters adapt it, and stating the quantum explicitly (R-0001) keeps the adaptation lossless where possible.
