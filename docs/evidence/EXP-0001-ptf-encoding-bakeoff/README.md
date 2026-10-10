# EXP-0001: PTF raw-layer encoding bake-off

- verdict: pass
- pinned commit: see `manifest.toml` (8d54aea)
- requirements: REQ-FMT-005, REQ-FMT-015 (per-packet budget part)
- supersedes / superseded by: —
- informs: ADR 0011, docs/design/ptf-format.md P2, P3, P4, §7

## Hypothesis

The canonical PTF encoding of the per-packet table (columnar tables, delta2 timestamps at ns resolution, 65 536-row chunks, zstd 19) meets three conditions in every scenario:
- it costs ≤ 8 B/packet;
- it is within 10% of the smallest lossless candidate;
- it encodes the largest scenario in ≤ 10 s.

## Method

`pt-bench bakeoff` generates seeded synthetic 60 s sessions shaped like the `standard` profile in both directions:
- traffic: light flow (50 pps), light trains (8 × 1500 B every 500 ms), and heavy saturation phases ramping 0.5→2× then holding 1.05× the bottleneck;
- bottleneck: a FIFO bottleneck with a 100 ms buffer, an AR(1) jitter process, Gilbert-Elliott loss, and a receiver clock offset and skew of 3.2 ms / 4 ppm;
- timing noise: µs-scale pacing and timestamp noise.

There are four scenarios: wired 10, 100 and 500 Mbit/s, and Wi-Fi-style aggregated delivery at 100 Mbit/s (35 k to 1.37 M packets). Each candidate encodes the same 9-column table (flow, seq, size, tx_intended, tx, rx?, tos?, ttl?, phase) and is decoded back:
- PTF variants: the canonical encoding; zstd 3 and 9; chunk sizes 16 Ki and 256 Ki rows; delta instead of delta2; µs quantisation (lossy, reported only to price ns precision); plain column encoding.
- Other formats: JSON Lines + zstd 3/19, CBOR rows + zstd 3/19, Arrow IPC + zstd.

PTF round trips are checked for equality.

## Result (bytes per packet; `artifacts/results.csv`)

| Candidate | wired-10M | wired-100M | wired-500M | wifi-100M |
|---|---|---|---|---|
| **PTF canonical (delta2/ns/zstd19/64Ki)** | **5.01** | **4.71** | **4.68** | **4.48** |
| PTF zstd 3 | 5.18 | 4.74 | 4.70 | 4.49 |
| PTF delta (not delta2) | 5.76 | 5.34 | 4.82 | 4.95 |
| PTF plain columns + zstd 19 | 10.65 | 9.68 | 8.53 | 9.65 |
| PTF µs quantised (lossy) | 2.13 | 1.93 | 1.90 | 1.57 |
| Arrow IPC + zstd | 10.96 | 10.35 | 9.13 | 10.02 |
| CBOR rows + zstd 19 | 11.60 | 11.92 | 10.45 | 11.56 |
| JSON Lines + zstd 19 | 11.28 | 10.70 | 10.21 | 10.56 |

Canonical encode time for the 1.37 M-packet scenario: 354 ms (zstd 19), against 2.5–100 s for row formats at zstd 19. Chunk size changes size by less than 0.7%.

## Interpretation

- The column encodings, not general-purpose compression, give the win: plain columns with zstd are 2× larger, and row formats and Arrow (whose columns are compressed without delta coding) are 2.0–2.6× larger. delta2 beats delta by 3–13%, because paced send times have near-constant spacing.
- Level 19 is only 0.4–3% smaller than level 3, but costs < 0.4 s at the largest scenario. The canonical level stays 19, since merging happens once per trace. Observation logs use level 3 while streaming.
- Chunk size barely affects size. 65 536 rows bounds writer memory at about 5 MiB per chunk uncompressed (9 columns × 8 B × 64 Ki), so it is kept.
- Keeping ns instead of µs costs about 2.7 B/packet (×2.4). That is the measured price of P4, and it is within budget: the budget leaves about 3 B/packet for the extra TX-stamp columns of the real probe. EXP on real harness captures re-checks this.
- Dependencies (normal edges): pt-format pulls 15 crates and arrow-ipc 43.
- Threats to validity: synthetic entropy may differ from real captures (especially Wi-Fi). The bake-off will be repeated on harness captures once the probe exists. The pilot run (not pinned) used a criterion that included the lossy µs variant. The criterion was corrected to lossless candidates before this pinned run (see commit 8d54aea's message).
