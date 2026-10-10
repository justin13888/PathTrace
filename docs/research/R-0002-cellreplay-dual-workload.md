# R-0002: CellReplay dual-workload recording (light and heavy PDOs)
- source: https://www.usenix.org/conference/nsdi25/presentation/sentosa ; PDF https://www.usenix.org/system/files/nsdi25-sentosa.pdf
- accessed: 2026-10-10
- claim-under-test: CellReplay (NSDI 2025, Sentosa et al.) records under light and heavy workloads at the same time and interpolates at replay. To verify: what it records, and the error reductions it reports against Mahimahi.
- verdict: confirmed (with a correction: the replay "interpolation" is a splice, not numeric blending)
- applicability: High. SPEC 6.5 and 7.4 (`capacity_light`) borrow this idea directly. The details show a mismatch with the SPEC light flow (see implications).
## Evidence
Abstract:
> CellReplay records network behavior under two predefined workloads simultaneously and interpolates upon replay for other workloads.

§4.1–4.2 describe what is recorded:
> (1) Packet train probing to capture link PDOs under short and bursty load (light PDOs), and (2) Saturator to capture PDOs under heavy continuous load (heavy PDOs).
> In every G ms, (a) the client sends U back-to-back MTU-sized packets.

- There are three traces: **base delay** (RTT/2 measured from the train), **light PDOs** (per-train relative arrival times, uplink and downlink), and **heavy PDOs** (saturator, in Mahimahi PDO format).
- Two phones are used side by side, relying on per-user queue separation by operators: "we perform these workloads on separate identical phones placed in close proximity".
- Replay (§4.3): when a packet arrives at time t, the replay takes DELAY and the light-PDO train sampled at or before t (linearly interpolated across G). It builds `TempPDO` = light PDOs + DELAY, then "concatenates these with the suffix of the heavy PDOs". After F ms with no packets queued it returns to the inactive state.
- Calibration parameters (Table 1): U, D (train sizes), Gmin (train gap), F (fallback timer), comp(s) (delay compensation for s-byte packets), B (bottleneck buffer bytes).

Reported results against Mahimahi (§1):
> CellReplay reduces emulation error from 17.1% with Mahimahi to 6.7% [...] For randomized file download [...] from 7.9%-49% with Mahimahi to just 0.2%-22.4%.

- Basement 15.22% to 5.87%. Crowded library 22.51% to 8.47%. Walking 14.48% to 4.13%. Driving 13.15% to 6.97%. Mahimahi underestimates median packet RTT by 16.88% (T-Mobile) and 13.25% (Verizon).
- Limitation (§6): "CellReplay probes UDP traffic [...] cannot capture the effects of network discrimination based on IP protocol types".
## Implications for PTF / probe
- `capacity_light` must be a series of **per-train arrival offsets** (light PDOs) sampled every G, together with train size (U/D) and packet size. A single rate curve is not enough. The replay rule (light prefix, heavy suffix, fallback timer F) and the parameters U, D, Gmin, F, comp(s), B need metadata fields.
- **Mismatch with SPEC 6.5:** the SPEC light flow (isochronous, 50 pps, 100 B) measures delay and loss for a small flow. It does not measure CellReplay light PDOs, which need short back-to-back MTU trains. Either add periodic packet trains or stop claiming CellReplay equivalence.
- A base-delay series (time-varying, measured with non-queue-inflating probes) is needed in addition to the PDOs, because a fixed delay underestimated RTT.
- `comp(s)` shows that size-dependent delay matters. Record the delay of a packet as a function of its size, or at least the probe packet sizes.
- CellReplay used two devices to avoid self-interference. PathTrace runs light and heavy flows on one host. Flag in the trace that light-flow samples taken during saturation share the same queue (expected for wired and Wi-Fi bottlenecks).
- Per-transport treatment is out of CellReplay's scope (UDP only), so PathTrace's transport matrix is not redundant.
