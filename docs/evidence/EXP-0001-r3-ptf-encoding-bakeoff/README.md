# EXP-0001-r3: PTF raw-layer encoding bake-off (re-run at PTF 1.1)

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: REQ-FMT-005, REQ-FMT-015
- supersedes: [EXP-0001-r2](../EXP-0001-r2-ptf-encoding-bakeoff/) (passed; went stale when PTF 1.1 changed `crates/pt-format/src`)

## Hypothesis, method

Same as EXP-0001 and r2: unchanged command and synthetic generator, re-run at the PTF 1.1 code.

## Result

Byte-for-byte identical sizes to r2 (`artifacts/stdout.log`): canonical 5.007 / 4.713 / 4.677 / 4.482 B/packet for wired 10/100/500 Mbit/s and Wi-Fi-aggregated 100 Mbit/s, within 10% of the smallest lossless candidate in each scenario. Encode time for 1.37 M packets: 362 ms.

## Interpretation

PTF 1.1's additions are new columns and tables; the encodings themselves are unchanged, so the synthetic 9-column table costs exactly what it did. Real 1.1 captures carry more columns and timestamp noise from the host, and their per-packet cost is measured by EXP-0002 (r9–r10: 5.5–8.9 B/packet, load-dependent).
