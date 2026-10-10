# Derivation: raw observations → path model

- requirements: REQ-DRV-001 … REQ-DRV-015, REQ-FMT-020, REQ-FMT-021
- adr: 0008, 0012
- research: R-0001, R-0002, R-0004, R-0005

`pathtrace derive` (and `probe`, after merge) turns the raw layer into the derived layer: PATH, SERS, PLCY, VALD. Derivation is a deterministic, pure function of the raw sections and the tool version (REQ-DRV-001). It never changes raw sections, so it can be re-run on any trace whenever a method improves. Every derived field records `method` (`name/N`), `confidence` in [0, 1], `status` (`known`, `estimated`, `unknown`) and the raw source it used.

Methods are versioned independently. Changing a method's output semantics bumps its `/N` (REQ-DRV-012).

## Time base

| Step | Method | Rule |
|---|---|---|
| Endpoint REALTIME → MONO_RAW | `clock.pairs-piecewise/1` | Piecewise-linear interpolation between consecutive clock pairs (≈1 Hz, ~30 ns width), extrapolated with the nearest segment's slope. A jump in (real − mono) > 1 ms between neighbouring pairs is a clock step and is recorded in PATH.clock.steps |
| b.mono → a.mono | `clock.exchange-minfilter/1` | For each exchange, offset θ = ((t2−t1)+(t3−t4))/2 and delay δ = (t4−t1)−(t3−t2). Keep the 25% lowest-δ exchanges and fit θ = θ0 + skew·(t1−t̄) by least squares. Uncertainty = min δ / 2 (draft spec §8). This assumes symmetric paths (`split_method = symmetric_assumed`) |
| Trace time | — | ns since `META.session.a.t0_mono` on a.mono |

Packet transmit time is SND when present (closest to the wire), else SCHED, else user-space (`tx_intended + tx_user_lag`). The choice is counted per direction in `PATH.<dir>.timestamps`.

## Per-direction fields

| Field | Method | Rule (summary) |
|---|---|---|
| `base_delay` | `delay.light-window-min/1` | One-way delay (OWD) of the light flow. Base = minimum over ±5 s windows, emitted as 1 s segments in SERS `base_delay[dir]`. Scalar = median of segments |
| `jitter` | `jitter.light-residual/1` | OWD − base for light-flow packets in **quiet** periods: the initiator's P2 and P10 phases (from EVNT `phase_start`), excluding intervals with any saturating or chirp flow in either direction. The phase timeline matters because TCP reference flows also load the path but are not in `pkt`. Series plus quantiles (p1…p99) plus autocorrelation at lags 1–10 |
| `size_delay` | `delay.size-slope/1` | Median OWD of quiet-period train packets (MTU) minus light packets (128 B) gives a per-byte serialisation delay estimate (R-0002 comp(s)) |
| `capacity` | `capacity.saturated-arrivals/1` | Saturated windows are where the heavy flow's queueing delay exceeds `max(2 ms, 25% of the controller target)`, or where heavy-flow packets are being lost: loss also proves that demand exceeded capacity, and a policer builds no queue (REQ-PRB-013). Every arrival in that direction during those windows becomes a delivery opportunity (t, bytes) in SERS `capacity_opps[dir]` (`quantum_bytes` is the per-row size, R-0001). 100 ms rate bins go to `capacity_rate[dir]`. Segments: `saturated` with workload `heavy`, `estimated` from trains, `unknown` elsewhere |
| `capacity_light` | `capacity.train-dispersion/1` | Per light train: arrival offsets relative to the first packet (SERS `train_offsets[dir]`), dispersion rate (n−1)·size·8/(t_last−t_first), losses, and the workload context (quiet or during saturation) (R-0002, ADR 0010) |
| `queue` | `queue.loss-onset/1` | Per saturation: depth_time = the maximum heavy-flow queueing delay in the 500 ms before each loss (the full-buffer delay for tail drop), median across losses, taken over the flows whose losses revealed the buffer; the overall max if no flow lost packets (a lower bound). depth_bytes = depth_time × saturated rate, cross-checked against drain time after the sender stops. Discipline: `droptail` when losses cluster at the maximum delay (onset delay ≥ 80% of the max), `aqm_suspected` when losses or CE marks occur at lower varying delay, `policer` when losses occur with queueing delay < 2 ms, else `unknown` |
| `policer` | `policer.lossy-flat/1` | When the discipline is `policer`: rate = delivery rate during lossy periods, burst = bytes delivered above that rate before the first loss |
| `loss` | `loss.gilbert-runs/1` | Losses of quiet-period light-flow and light-train packets, taken in transmit order (the path's Gilbert chain advances on every packet) → events (t, burst length) in SERS `loss_events[dir]`. Gilbert model p = P(good→bad), r = P(bad→good), h = 1, k = 0 (netem `gemodel p r 1-h 1-k`, R-0005), with Wilson 95% intervals |
| `reorder` | `reorder.late-arrivals/1` | Per flow, a packet is reordered if it arrives after a packet with a higher sequence number; rate plus displacement histogram |
| `duplicate` | `duplicate.count/1` | Rows in `dup` / received rows |
| `mtu` | `mtu.ladder/1` | Path MTU = largest ladder size received. Black hole = larger sizes lost with no ICMP Packet Too Big; ICMP MTU values are recorded |
| `ecn` | `tos.light-cycle/1` | Per ECN codepoint sent on the light flow: `passed`, `bleached` (arrives as not-ECT), `remarked`, `marked` (CE seen) or `dropped` (loss rate ≥ 5× that of not-ECT) |
| `dscp` | `tos.light-cycle/1` | Per DSCP sent: `preserved` or `rewritten` to the observed value(s) |
| `summary` | `summary.pantheon5/1` | Rate (median saturated 100 ms bin), one-way base delay, intrinsic loss rate, buffer bytes, delivery process (`isochronous` if the inter-delivery CV in saturation is < 1, else `poisson`) (R-0004) |

## Session-wide

| Item | Method | Rule |
|---|---|---|
| `coupling` | `coupling.both-ratio/1` | Saturated rate per direction during P6 divided by the rate in P4 / P5 |
| `timeline` | `timeline.outage/1` | Gaps ≥ 1 s with sends but no arrivals on any flow in a direction |
| PLCY | `policy.matrix/1` | UDP classes: reachability (echoes), echo RTT, capacity ratio and loss differential from P7 against `udp/high-port`. TCP classes: connect and TLS times and errors. NAT: binding survived T if the delayed echo arrived. Proxy suspected when TCP connect time < 0.5 × UDP minimum echo RTT, or when the responder's saved SYN TTL differs from the UDP TTL seen at the responder |
| VALD | `vald.reference/1` | Bulk goodput per direction (bytes / elapsed between first byte and done), request/response completion p50/p95/p99, CBR one-way latency p50/p95/p99 and loss |

## Exports (REQ-FMT-021)

- **netem** (`export.netem/1`): `delay <base>ms <jitter p50 spread>ms distribution` + `loss gemodel p r 1-h 1-k` + `rate <summary rate>` + `limit <buffer packets>` per direction. A static summary only, as netem cannot replay time-varying capacity (R-0005).
- **Mahimahi** (`export.mahimahi/1`): delivery opportunities converted to ms timestamps, one line per 1504-byte quantum (per-byte accounting: an opportunity of n bytes emits n/1504 lines, carrying the remainder) (R-0001). Unknown periods are filled with the median saturated rate, and the file says so in a sidecar.
- **Mahimahi import** (`import.mahimahi/1`): lines become capacity opportunities with `quantum_bytes = 1504`, `quality = saturated`, `workload = "imported"`. Every other field is `unknown`.

## Validation

Ground-truth recovery (REQ-DRV-013) and closure under netem replay (REQ-DRV-014) are evidence experiments that use `tools/netns/session.sh`. The sufficiency matrix in `simulator-requirements.md` records their results.
