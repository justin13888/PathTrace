# Simulator requirements and PTF sufficiency

- requirements: REQ-FMT-020, REQ-FMT-022, REQ-DRV-013, REQ-DRV-014
- adr: 0008, 0010
- research: R-0001 … R-0007

## Purpose

The emulator is deferred (ADR 0008). PTF 1.0 freezes the raw layer before any simulator exists, so this document fixes, ahead of time, what a simulator will need. Every input is traced to a PTF field, to the raw observations that field is derived from, and to the experiment that shows the probe can recover it from a path with known ground truth.

Sufficiency is argued in three layers:

1. **Requirements**: the inputs each simulator stage consumes. The source is draft spec §9.2, cross-checked first-hand against the representations used by Mahimahi (R-0001), CellReplay (R-0002), Pantheon (R-0004), netem (R-0005) and Rattan (R-0006). Literature is only used where it describes what an emulator consumes. It is never used as evidence that our probe measures correctly.
2. **Recoverability**: ground-truth experiments. A namespace path with kernel-imposed, known impairments is captured by the probe and derived, and the result is compared with the truth. The namespace path has both endpoints on Linux; a macOS initiator is checked the same way over a real overlay path to a Linux responder, with netem on the responder's tailnet egress (overlay-ground-truth.md, first run #66).
3. **Closure**: the derived trace is exported to netem, re-imposed and re-captured, and the second trace must match the first. If the trace holds enough to reproduce what it measured on an independent emulator, the information is there.

## Anticipated simulator pipeline

Per direction, matching draft spec §9.2:
`classify → policy → NAT → MTU → queue → link → loss → delay (+jitter, reorder) → duplicate`.
In addition: light-vs-heavy workload switching (CellReplay-style), timeline events, and a static calibrated summary for parametric emulators.

## Requirements matrix

| # | Stage | Simulator needs | Basis | PTF field(s) | Derived from (raw) | Ground truth (harness) |
|---|---|---|---|---|---|---|
| S1 | Classify | Transport classes and how packets map to them (protocol, port, shape) | spec §9.2 | `PLCY.classes[]`, `FLOW` | class probes in `OBSV.probe` | n/a (definition) |
| S2 | Policy | Per class: blocked or not, policer (rate, burst), capacity ratio and loss differential against the reference class | spec §6.6; Rattan TokenBucket cell (R-0006) | `PLCY.matrix[family][class]`, `PATH.<dir>.policer[class]` | P1 reachability, P7 class differential | nft drop on one class; tbf on one UDP port via u32 filter |
| S3 | NAT | Idle binding timeout, port preservation, rebinding and address-change times | spec §6.6, §9.2 | `PLCY.nat`, `EVNT` (`addr_change`, `nat_rebind`) | NAT timeout search, responder-observed source tuples | nft masquerade + per-netns `nf_conntrack_udp_timeout`; forced conntrack flush |
| S4 | MTU | Path MTU; whether ICMP Packet Too Big comes back (black hole) | spec §6.6 | `PATH.<dir>.mtu {bytes, blackhole}` | PMTU search packets, error-queue ICMP | veth MTU reduced on the middlebox; with and without ICMP dropped |
| S5 | Queue | Buffer depth in bytes and time; discipline (tail drop, AQM, policer); ECN marking | spec §8; Pantheon: buffer size is the dominant calibration parameter (R-0004); netem `limit` is packets only (R-0005) | `PATH.<dir>.queue {bytes, time_ns, discipline}`, `PATH.<dir>.ecn` | heavy-flow queueing delay at loss onset, drain after stop | bfifo `limit` in bytes behind a rate limiter; fq_codel `ecn` |
| S6 | Link (heavy) | Time-varying delivery opportunities under saturation, with an explicit byte quantum and quality per segment | Mahimahi opportunities with a 1504-byte quantum, per-byte accounting (R-0001) | `PATH.<dir>.capacity {representation, quantum_bytes, segments[quality, workload]}` + `SERS` table | heavy-flow arrivals during valid saturation (P4–P6, deep tracking) | static rate; scripted step changes (`tc change`); asymmetric up/down |
| S7 | Link (light) | Behaviour seen by short bursty load: per-train arrival offsets of back-to-back MTU packets, sampled periodically, plus the switching rule | CellReplay light PDOs, splice replay, fallback timer F (R-0002) | `PATH.<dir>.capacity_light {trains SERS table, train_size, gap, packet_size}` | periodic light trains (ADR 0010) | same rate paths; check that train dispersion recovers the bottleneck rate |
| S8 | Workload provenance | Which workload produced each capacity segment (heavy saturation, light train, chirp, estimate) | NeuralEmu: saturation perturbs schedulers, so a trace is a snapshot of one traffic pattern (R-0003) | `segments[].workload` | phase tags on every observation | n/a (bookkeeping, checked by the conformance corpus) |
| S9 | Loss | Non-congestive loss events and burst structure; a Gilbert-Elliott fit convertible to netem `gemodel p r 1-h 1-k` | spec §8; netem GE parameterisation (R-0005) | `PATH.<dir>.loss {events SERS, ge {p, r, h, k, ci}}` | light-flow losses outside saturation | netem `loss random`, `loss gemodel` |
| S10 | Delay | Time-varying base delay; split method; jitter as series plus empirical distribution and autocorrelation; size-dependent delay | CellReplay: a fixed delay underestimates RTT, and comp(s) is size-dependent (R-0002); spec §7.4 | `PATH.<dir>.base_delay {series, split_method}`, `PATH.<dir>.jitter {series, quantiles, acf}`, `PATH.<dir>.size_delay` | light flow (100 B) vs train packets (MTU) delay at the same time | netem `delay D J distribution`; static D in each direction |
| S11 | Reorder | Rate and displacement distribution | spec §7.4 | `PATH.<dir>.reorder` | sequence vs arrival order | netem `reorder` with delay |
| S12 | Duplicate | Rate | spec §7.4 | `PATH.<dir>.duplicate` | duplicate arrivals per sequence number | netem `duplicate` |
| S13 | Header treatment | ECN passed, bleached, marked or dropped; DSCP preserved or rewritten | spec §6.6 | `PATH.<dir>.ecn`, `PATH.<dir>.dscp` | sent vs received TOS byte per packet | tc `pedit` rewriting dsfield; fq_codel marking |
| S14 | Timeline | Outages, address changes, interface changes | spec §7.3 EVNT | `EVNT` (observed), `PATH.timeline` (derived outages) | rtnetlink monitor; loss runs on all flows | netem `loss 100%` for a window; address change on the initiator |
| S15 | Calibrated summary | Pantheon-style static fit: rate, one-way delay, loss rate, buffer size, isochronous vs Poisson delivery | Pantheon calibrated emulators, average error 17% (R-0004) | `PATH.<dir>.summary` | all of the above | closure experiment (netem export → re-capture) |
| S16 | Direction coupling | Capacity of each direction while both are saturated | spec §6.5 P6 | `PATH.coupling {ratio_a_to_b, ratio_b_to_a}` | P6 simultaneous saturation | none: netem directions are independent, so no ground truth exists here; recorded, verified only for consistency (stated limit) |
| S17 | Validation ground truth | Real-path results of fixed reference flows, plus the raw events behind them | spec §11.3 | `VALD.reference[]`; raw `OBSV.tcpinfo`, `OBSV.app` | P8 reference flows | consumed by fidelity scoring (REQ-EMU-007), not by the simulator |
| S18 | Proxy | Whether a TCP-terminating middlebox is present | spec §4, §6.6 | `PLCY.proxy_suspected {evidence}` | TCP handshake RTT vs UDP min RTT; SYN as seen by responder | a TCP relay process in the middlebox namespace |

## Format consequences of the research

These features would not exist if the draft spec were followed literally. Each one is tied to its source.

- **Explicit capacity quantum** (`quantum_bytes`). Mahimahi's code uses 1504 bytes per opportunity while its documentation says 1500, and it accounts per byte with carry-over (R-0001). Importers and exporters must state the quantum, never assume it.
- **Light trains in addition to the light flow.** The draft's light flow (50 packets/s, 100 B) measures small-flow delay and loss but not CellReplay's light delivery opportunities, which need short back-to-back MTU trains (R-0002). ADR 0010 adds periodic trains, and `capacity_light` stores per-train arrival offsets.
- **Workload provenance per capacity segment** (R-0003).
- **Size-dependent delay.** Light-flow packets (100 B) and train packets (MTU) both cross the path, which yields a delay-versus-size relation (R-0002 comp(s)).
- **A derived-layer section flag.** PNG's safe-to-copy bit (R-0007) inspired a PTF section flag marking sections derived from the raw layer. Tools that change raw data must drop or regenerate them (`docs/design/ptf-format.md`).
- **Gilbert-Elliott in netem's parameterisation** (p, r, h, k) so export is lossless (R-0005).
- **Pantheon-style summary.** A static five-parameter fit (R-0004) per direction, used by the netem export and as a future fidelity baseline.

## Known limits (not representable by any recorded trace)

- How the network would react to a different workload (R-0003). Mitigation: dual workload (heavy + light trains + light flow) and recorded provenance. Fidelity scoring (deferred) measures the residual error.
- Reaction of cross traffic. Out of scope (REQ-SCOPE-004).
- Behaviour of a TCP-terminating proxy: detected and flagged, not modelled.
- The absolute one-way delay split without synchronised clocks: stored as `symmetric_assumed` (#17).

## Sufficiency verdict

From the pinned evidence. Verdicts: `recovered` (ground truth recovered within the experiment's tolerance), `recovered-with-limits` (recovered, with the stated limit), `recorded-unverified` (the fields are recorded, but no ground truth is available yet), `not-representable` (none).

| Stage | EXP | Verdict | Basis |
|---|---|---|---|
| S1 Classify | EXP-0002-r14 | `recovered` | class probes on every class; reachability per class and per family (udp443-throttle, udp-blocked, ipv6) |
| S2 Policy | EXP-0002-r14 | `recovered` | UDP/443 ratio 0.109 against truth ~0.1; policer 4.97 vs 4.95 Mbit/s; all-UDP block detected, with TCP fallback |
| S3 NAT | EXP-0002-r14 | `recovered` | binding alive at 15 s, expired at 30/60 s (timeout 20 s); rebind: `nat_rebind` + `addr_new`, session complete |
| S4 MTU | EXP-0002-r14 | `recovered` | 1400 with PTB seen / 1400 with black hole; reverse 1500 |
| S5 Queue | EXP-0002-r14 | `recovered` | buffers 150 184 / 74 788 B vs 150 000 / 75 000; droptail, aqm_suspected, policer; ECT marked (ECT(1) in this run, see S13) |
| S6 Link (heavy) | EXP-0002-r14 | `recovered` | static ±0.5% (20/10/100 Mbit/s, IPv6; 20 and 100 Mbit/s at 300 ms one way within 0.1%); steps NRMSE 1.36% |
| S7 Link (light) | EXP-0002-r14 | `recovered-with-limits` | train dispersion 49.54 vs 49.54 Mbit/s; the switching rule between light and heavy is the simulator's (R-0002); not checked against a workload-reactive scheduler (R-0003) |
| S8 Workload provenance | EXP-0003-r5, EXP-0007-r8 | `recovered` | every capacity segment carries `workload`; bookkeeping, checked by the corpus |
| S9 Loss | EXP-0002-r14 | `recovered` | p and r recovered for Bernoulli and Gilbert-Elliott (intervals at a family-wise 95% from the recorded transition counts); requires that every packet sent is observed (EXP-0002) |
| S10 Delay | EXP-0002-r14 | `recovered-with-limits` | base delay ±0.03 ms, RTT sum ±0.01 ms, jitter σ 3.75 vs 4 ms; the one-way split is not identifiable without synchronised clocks (`symmetric_assumed`, #17); size-dependent delay is recorded but not scored |
| S11 Reorder | EXP-0002-r14 | `recovered` | detected under netem jitter and `reorder` |
| S12 Duplicate | EXP-0002-r14 | `recovered` | 2.10% vs 2% |
| S13 Header treatment | EXP-0002-r14 | `recovered-with-limits` | DSCP rewritten, ECT bleached, reverse preserved; fq_codel marking detected, but under a fair-queuing AQM it rests on a few marks per session (4–13), so per-codepoint verdicts can differ (#27) |
| S14 Timeline | EXP-0002-r14 | `recovered-with-limits` | address change and rebind events recorded; the derived outage (`PATH.timeline`) is not scored separately |
| S15 Calibrated summary | EXP-0002-r14 | `recovered` | closure: the netem export replayed and re-captured reproduces capacity, buffer and delay within 0.1% |
| S16 Direction coupling | — | `recorded-unverified` | no ground truth exists here (netem directions are independent) |
| S17 Validation ground truth | EXP-0006-r7 | `recorded-unverified` | reference flows recorded in `VALD`; their use is fidelity scoring (#7) |
| S18 Proxy | — | `recorded-unverified` | `PLCY.proxy_suspected` recorded; validation is #22 |

**Conclusion (REQ-FMT-022).** No anticipated stage is `not-representable`. Fifteen of eighteen stages are recovered from ground truth, four of them with stated limits. The netem export of a trace reproduces that trace when replayed (closure). S16, S17 and S18 are recorded but cannot be verified with the present harness, and each is tracked. Limits that no recorded trace can remove are listed under *Known limits* above.
