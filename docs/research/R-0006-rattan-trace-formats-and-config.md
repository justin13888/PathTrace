# R-0006: Rattan cells, config format, and netem-trace trace formats
- source: https://github.com/stack-rs/rattan (main @ 3db4c16, 2026-08-18): config.example.toml, rattan-core/src/config/{mod,bandwidth,delay,loss}.rs, assets/dynamic-loss.toml, assets/delay-per-packet.toml ; https://github.com/stack-rs/netem-trace (v0.4.7; Rattan pins 0.4.4): src/lib.rs, src/model/bw.rs, src/mahimahi.rs ; https://arxiv.org/abs/2507.08134
- accessed: 2026-10-10
- claim-under-test: Rattan consumes netem-trace bandwidth, delay and loss traces. To record: its list of cells and its config format (TOML?), with enough detail to write an exporter.
- verdict: confirmed
- applicability: High. SPEC 7.7 requires a Rattan exporter, and SPEC section 5 names Rattan as the closest competitor.
## Evidence
Config is TOML, passed with `rattan -c <file>` (config.example.toml header). Sections: `[general] [env] [http] [cells.<ID>] [links] [resource] [commands]`. `[links]` maps cell egress to ingress, for example `up_1 = "up_2"`. `left`/`right` are reserved IDs.

Cells (`rattan-core/src/config/mod.rs:107-120`):
> Bw, BwReplay, Delay, DelayReplay, Loss, LossReplay, Shadow, Spy, DelayPerPacket, Router, TokenBucket, Custom

- `Bw`: `bandwidth = "1Gbps 200Mbps"`, `bw_type = NetworkLayer|LinkLayer` (+38 B), `queue`, `queue_config = { packet_limit, byte_limit, ... }`. Queue types in code: Infinite, DropTail, DropHead, CoDel (`interval`, `target`, `mtu`), Red, Pie (bandwidth.rs:38-39). The example file lists only the first four.
- `BwReplay`: `trace = <file>`. bandwidth.rs:185-200 picks the parser by extension: `.json`/`.toml` give a netem-trace `BwTraceConfig`; anything else is parsed as Mahimahi.
- `DelayReplay`/`LossReplay`: `trace` (netem-trace `DelayTraceConfig`/`LossTraceConfig`, JSON or TOML). LossReplay also takes an optional `seed`.
- `Loss`: `pattern = [0.1, 0.2]`. These are conditional probabilities: index i is the drop probability given i consecutive previous losses (netem-trace lib.rs:129-146).
- `DelayPerPacket`: for example `NormalizedDelayPerPacketConfig { mean, std_dev, lower_bound, upper_bound, count, seed }`.
- `TokenBucket`: `limit`, `burst`, `rate`, `minburst`, `peakrate`, which is a tbf-like policer/shaper.

netem-trace formats are serde enums keyed by type name. Durations and rates are human-readable strings (`"1s"`, `"12Mbps"`):
> {"RepeatedBwPatternConfig":{"pattern":[{"TraceBwConfig":{"pattern":[["1ms",["2Mbps","4Mbps"]],["2ms",["1Mbps"]]]}}],"count":0}}

- `TraceBwConfig.pattern: Vec<(Duration, Vec<Bandwidth>)>`: each bandwidth in the inner list is held for that duration, in sequence. `count = 0` repeats forever. Other models: Static, Normalized, Sawtooth, RepeatedPattern. Loss uses `StaticLossConfig { loss = [..], duration }` (assets/dynamic-loss.toml). netem-trace also has duplicate and rwnd models.
- Mahimahi import (netem-trace mahimahi.rs:107-119): "Each timestamp will be converted into a 12Mbps bandwidth lasting for 1 millisecond [...] this trace may slightly deviate from the behavior of mahimahi". So Rattan replays Mahimahi files as a 1 ms piecewise-constant rate, not as per-opportunity byte credits.
## Implications for PTF / probe
- Rattan exporter: write one TOML channel (cells + links per direction) plus a JSON netem-trace file per series. PTF capacity goes to `TraceBwConfig` (piecewise-constant rate). Do not export Mahimahi to Rattan, because it is quantised to 1 ms at 12 Mbps per opportunity.
- PTF delay series goes to `DelayReplay`, or to `DelayPerPacket` for distributions. PTF loss goes to `LossReplay` with time-segmented conditional-probability patterns. The PTF Gilbert-Elliott fit is not native, so the exporter must approximate it with the burst-conditional pattern or document the loss.
- PTF policer goes to `TokenBucket` (rate, burst, limit). SPEC section 5 omits that Rattan already has this cell.
- PTF queue hints go to `queue_config` (`packet_limit`/`byte_limit`, CoDel/RED/PIE). PTF should state whether sizes are network-layer or link-layer bytes, because Rattan distinguishes `bw_type`.
- Missing in Rattan cells: reordering, ECN/DSCP treatment, and per-transport policy beyond `Router` by prefix. An exporter must flag these as dropped.
- Pin the netem-trace version in exporter tests. The schema is enum-tagged and has changed across 0.4.x.
