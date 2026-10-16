# Derivation: raw observations → path model

- requirements: REQ-DRV-001 … REQ-DRV-015, REQ-FMT-020, REQ-FMT-021
- adr: 0008, 0012, 0014
- research: R-0001, R-0002, R-0004, R-0005

`pathtrace derive` (and `probe`, after merge) turns the raw layer into the derived layer: PATH, SERS, PLCY, VALD. Derivation is a deterministic, pure function of the raw sections and the tool version (REQ-DRV-001). It never changes raw sections, so it can be re-run on any trace whenever a method improves. Every derived field records `method` (`name/N`), `confidence` in [0, 1], `status` (`known`, `estimated`, `unknown`) and the raw source it used.

Methods are versioned independently. Changing a method's output semantics bumps its `/N` (REQ-DRV-012).

## Time base

| Step | Method | Rule |
|---|---|---|
| Endpoint REALTIME → MONO_RAW | `clock.pairs-piecewise/1` | Piecewise-linear interpolation between consecutive clock pairs (≈1 Hz, ~30 ns width), extrapolated with the nearest segment's slope. A jump in (real − mono) > 1 ms between neighbouring pairs is a clock step and is recorded in PATH.clock.steps |
| b.mono → a.mono | `clock.exchange-minfilter/1` | For each exchange, offset θ = ((t2−t1)+(t3−t4))/2 and delay δ = (t4−t1)−(t3−t2). Keep the 25% lowest-δ exchanges and fit θ = θ0 + skew·(t1−t̄) by least squares. Uncertainty = min δ / 2 (draft spec §8). This assumes symmetric paths (`split_method = symmetric_assumed`) |
| Trace time | — | ns since `META.session.a.t0_mono` on a.mono |

Packet transmit time is SND when present (closest to the wire), else SCHED, else user-space (`tx_intended + tx_user_lag`). The choice is counted per direction in `PATH.<dir>.timestamps`. A trace from a macOS initiator, which has no kernel TX stamps, counts every a→b packet as `user` (probe.md §9.2).

## Host drops

| Step | Method | Rule |
|---|---|---|
| Receiver host drops | `hostdrop.rxq-gap/1` | For each receiving socket, take its arrivals (all flows of the direction, by receive time). Where `rxq_drops` increases between two consecutive arrivals, the socket dropped datagrams in that gap. A lost packet to that socket whose transmit time lies between the transmit times of those two arrivals is a host-drop candidate. Each gap marks at most as many candidates as the socket dropped in it (`rxq_drops` increase), earliest transmit time first, as **host drops**, so `host_drops.packets` never exceeds `socket_drops`. When a gap has more candidates than drops, which of them the socket dropped is unknown; the unmarked ones stay losses, and the gap and its excess candidates are counted (`ambiguous_gaps`, `ambiguous_losses`). Host drops are excluded from the loss-based estimates that say so below (`capacity.saturated-arrivals/2`, `queue.loss-onset/2`, `policer.lossy-flat/2`, `loss.gilbert-runs/2`), counted in `PATH.<dir>.host_drops {packets, gaps, socket_drops, ambiguous_gaps, ambiguous_losses}`, and treated there as unknown (neither delivered nor lost). Other methods still count them as not received: the light-train counts of `capacity.train-dispersion/1`, `mtu.ladder/2` and `timeline.outage/1`. The receiving socket of a lost packet is the one most arrivals of its flow used (the main socket if none arrived). Traces without `rxq_drops` (PTF 1.0) have no host drops by this rule, and `host_drops.status` is `unknown` |
| Receiver host drops without `rxq_drops` | `hostdrop.host-fullsock/1` | Applies where the receiver recorded no `rxq_drops` but its `netstack` table has `udp_fullsock` (PTF 1.2, macOS, probe.md §9.6). Over the receiver's non-null `udp_fullsock` rows in time order, with no `iface_change` segmentation (the host-wide counter does not restart when the sampler follows another interface): a decrease between consecutive rows (a counter wrap or a reboot) gives `unknown` with `reason: "host-wide counter decreased"`; otherwise last minus first is the rise. No rise means no UDP socket on the host was dropped into, so the probe's sockets dropped nothing: `known`, `packets: 0`, `source: ["netstack"]`, and no packet is marked. A rise gives `unknown` with `reason: "host-wide counter rose"` and the rise as `host_socket_drops`, because which socket dropped is unknown. Without `udp_fullsock` the field is exactly `hostdrop.rxq-gap/1`'s, its `unknown` reason text (`no rxq_drops in this trace (PTF 1.0)`) included |

Sender-side drops need no rule: a datagram the sender failed to send has no `tx` row (probe.md §4.1). Drops in the sender's own egress qdisc are a property of the access link as the host uses it; the `qdisc` table records them alongside, and `PATH.<dir>.local_qdisc_drops {drops, segments}` (`qdisc.drop-count/2`) reports the sender's root-qdisc drops during the session. The `drops` column is cumulative per interface and restarts at each of the sender's `iface_change` events (probe.md §4.4), and at a qdisc replacement, where it decreases. So the rows are cut into segments at each `iface_change` and at each decrease, and `drops` is the sum over segments of last minus first. `segments` counts them. Drops between a segment's last row and the switch are not observed. (`/1` took last minus first over the whole table, which spans two interfaces after a switch.) A sender with no `qdisc` table (PTF 1.0, or macOS, which has no qdisc, probe.md §9.6) gets `unknown` with `reason: "no qdisc counters recorded"`; a macOS trace never reads `udps_fullsock` or `ifi_oerrors` here. An unknown field carries no counts, and an unknown count never enters an estimate as 0.

## Per-direction fields

| Field | Method | Rule (summary) |
|---|---|---|
| `base_delay` | `delay.light-window-min/1` | One-way delay (OWD) of the light flow. Base = minimum over ±5 s windows, emitted as 1 s segments in SERS `base_delay[dir]`. Scalar = median of segments |
| `jitter` | `jitter.light-residual/1` | OWD − base for light-flow packets in **quiet** periods: the initiator's P2 and P10 phases (from EVNT `phase_start`), excluding intervals with any saturating or chirp flow in either direction. The phase timeline matters because TCP reference flows also load the path but are not in `pkt`. Series plus quantiles (p1…p99) plus autocorrelation at lags 1–10 |
| `size_delay` | `delay.size-slope/1` | Median OWD of quiet-period train packets (MTU) minus light packets (128 B) gives a per-byte serialisation delay estimate (R-0002 comp(s)) |
| `capacity` | `capacity.saturated-arrivals/2` | Saturated windows are where the heavy flow's queueing delay exceeds `max(2 ms, 25% of the controller target)`, or where heavy-flow packets are being lost (host drops excluded; /1 counted them): loss also proves that demand exceeded capacity, and a policer builds no queue (REQ-PRB-013). Every arrival in that direction during those windows becomes a delivery opportunity (t, bytes) in SERS `capacity_opps[dir]` (`quantum_bytes` is the per-row size, R-0001). 100 ms rate bins go to `capacity_rate[dir]`. Segments: `saturated` with workload `heavy`, `estimated` from trains, `unknown` elsewhere |
| `capacity_light` | `capacity.train-dispersion/1` | Per light train: arrival offsets relative to the first packet (SERS `train_offsets[dir]`), dispersion rate (n−1)·size·8/(t_last−t_first), losses, and the workload context (quiet or during saturation) (R-0002, ADR 0010) |
| `queue` | `queue.loss-onset/2` | Per saturation: depth_time = the maximum heavy-flow queueing delay in the 500 ms before each loss (the full-buffer delay for tail drop), median across losses, taken over the flows whose losses revealed the buffer; the overall max if no flow lost packets (a lower bound). depth_bytes = depth_time × saturated rate, cross-checked against drain time after the sender stops. Discipline: `droptail` when losses cluster at the maximum delay (onset delay ≥ 80% of the max), `aqm_suspected` when losses or CE marks occur at lower varying delay, `policer` when losses occur with queueing delay < 2 ms, else `unknown` |
| `policer` | `policer.lossy-flat/2` | When the discipline is `policer`: rate = delivery rate during lossy periods, burst = bytes delivered above that rate before the first loss |
| `loss` | `loss.gilbert-runs/2` | Losses (host drops excluded; /1 counted them) of quiet-period light-flow, light-train and control datagrams, taken in transmit order (the path's Gilbert chain advances on every packet, so every packet the probe puts on the path must be observed: EXP-0002) → events (t, burst length) in SERS `loss_events[dir]`. Gilbert model p = P(good→bad), r = P(bad→good), h = 1, k = 0 (netem `gemodel p r 1-h 1-k`, R-0005), with Wilson 95% intervals (`p_ci95`, `r_ci95`) and the transition counts behind them (`good_n`, `good_to_bad`, `bad_n`, `bad_to_good`; p = good_to_bad / good_n, r = bad_to_good / bad_n). The counts let any reader compute an interval at another level, for example a family-wise level when several intervals are judged together (EXP-0002-r6). Added in 1.0.1; older traces lack them, and `derive` adds them |
| `reorder` | `reorder.late-arrivals/1` | Per flow, a packet is reordered if it arrives after a packet with a higher sequence number; rate plus displacement histogram |
| `duplicate` | `duplicate.count/1` | Rows in `dup` / received rows |
| `mtu` | `mtu.ladder/2` | Path MTU = largest ladder size received. Black hole = larger sizes lost with no ICMP Packet Too Big; ICMP MTU values are recorded. `blackhole` is null when the socket the sender sent the ladder from (FLOW `sock`) recorded `icmp_errors: false` in META (PTF 1.2, macOS, probe.md §9.5), because the absence of an ICMP error is then not evidence; `path_mtu` stays known. Otherwise as `/1` |
| `ecn` | `tos.light-cycle/1` | Per ECN codepoint sent on the light flow: `passed`, `bleached` (arrives as not-ECT), `remarked`, `marked` (CE seen) or `dropped` (loss rate ≥ 5× that of not-ECT) |
| `dscp` | `tos.light-cycle/1` | Per DSCP sent: `preserved` or `rewritten` to the observed value(s) |
| `summary` | `summary.pantheon5/1` | Rate (median saturated 100 ms bin), one-way base delay, intrinsic loss rate, buffer bytes, delivery process (`isochronous` if the inter-delivery CV in saturation is < 1, else `poisson`) (R-0004) |

## Session-wide

| Item | Method | Rule |
|---|---|---|
| `coupling` | `coupling.both-ratio/1` | Saturated rate per direction during P6 divided by the rate in P4 / P5 |
| `timeline` | `timeline.outage/1` | Gaps ≥ 1 s with sends but no arrivals on any flow in a direction |
| PLCY | `policy.matrix/2` | UDP classes: reachability (an echo arrived, whether or not its transmit time is known; `/1` required `tx_sched`, so a trace without TX stamps reported every UDP class unreachable), echo RTT (echo arrival minus the transmit time by the direction rule of Time base: SND, else SCHED, else user), echo RTT, capacity ratio and loss differential from P7 against `udp/high-port`. TCP classes: connect and TLS times and errors. NAT: binding survived T if the delayed echo arrived. Proxy suspected when TCP connect time < 0.5 × UDP minimum echo RTT, or when the responder's saved SYN TTL differs from the UDP TTL seen at the responder |
| `overlay` | `overlay.egress-iface/1` | From META `endpoints.<ep>.iface.tunnel` and the `tunnel` key of each `iface_change` event's `iface` (PTF 1.2, probe.md §9.9). `overlay` is true when either endpoint's egress toward the peer was a tunnel at any time; `endpoints` lists which, `kind` and `provider` are the first tunnel's (a before b), `mtu` the smallest tunnel MTU, `overlay_ns` the trace time under a tunnel at either endpoint, each endpoint's span running from its first to its last clock pair. Without a tunnel it is `known` and false when every endpoint recorded `os_family` (a 1.2 writer, which records `tunnel` whenever there is one), else `unknown` with `reason: "no tunnel fact recorded (PTF < 1.2)"`. When `overlay` is true, every PLCY class entry and, per direction, `policer`, `mtu`, `ecn` and `dscp` carry `overlay_limited: true`; no other field changes |
| VALD | `vald.reference/1` | Bulk goodput per direction (bytes / elapsed between first byte and done), request/response completion p50/p95/p99, CBR one-way latency p50/p95/p99 and loss |

## Exports (REQ-FMT-021)

Version 2 of `capacity.saturated-arrivals`, `queue.loss-onset`, `policer.lossy-flat` and `loss.gilbert-runs` differs from version 1 only by excluding host drops; on a trace without `rxq_drops` the results are identical.

- **netem** (`export.netem/1`): `delay <base>ms <jitter p50 spread>ms distribution` + `loss gemodel p r 1-h 1-k` + `rate <summary rate>` + `limit <buffer packets>` per direction. A static summary only, as netem cannot replay time-varying capacity (R-0005).
- **Mahimahi** (`export.mahimahi/1`): delivery opportunities converted to ms timestamps, one line per 1504-byte quantum (per-byte accounting: an opportunity of n bytes emits n/1504 lines, carrying the remainder) (R-0001). Unknown periods are filled with the median saturated rate, and the file says so in a sidecar.
- **Mahimahi import** (`import.mahimahi/1`): lines become capacity opportunities with `quantum_bytes = 1504`, `quality = saturated`, `workload = "imported"`. Every other field is `unknown`.

## Validation

Ground-truth recovery (REQ-DRV-013) and closure under netem replay (REQ-DRV-014) are evidence experiments that use `tools/netns/session.sh`. The sufficiency matrix in `simulator-requirements.md` records their results. Recovery by a macOS initiator over a real overlay path is checked by `tools/overlay-gt/` and `cargo xtask overlay-gt check` (overlay-ground-truth.md).
