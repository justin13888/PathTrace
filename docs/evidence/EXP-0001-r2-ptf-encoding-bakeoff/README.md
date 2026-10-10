# EXP-0001-r2: PTF raw-layer encoding bake-off (rerun at the capture-ready format)

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: REQ-FMT-005, REQ-FMT-015
- supersedes: [EXP-0001](../EXP-0001-ptf-encoding-bakeoff/) (stale after later pt-format changes)

## Hypothesis, method

Same as EXP-0001, unchanged command and generator, re-run at the commit whose pt-format becomes PTF 1.0.

## Result

Byte-for-byte identical sizes to EXP-0001 (`artifacts/results.csv`): canonical 5.007 / 4.713 / 4.677 / 4.482 B/packet for wired 10/100/500 Mbit/s and Wi-Fi-aggregated 100 Mbit/s, within 10% of the smallest lossless candidate in each scenario. Encode time for 1.37 M packets: 415 ms.

## Interpretation

The changes to pt-format after EXP-0001 (redaction, canonical section order, the `Value` default) did not affect the encoding, as expected. On real probe captures the per-packet table has 19 columns rather than 9 and costs 4.2–7.9 B/packet: see EXP-0002.
