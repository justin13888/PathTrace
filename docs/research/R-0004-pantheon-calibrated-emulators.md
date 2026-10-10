# R-0004: Pantheon calibrated emulators and their replication error
- source: https://www.usenix.org/conference/atc18/presentation/yan-francis ; PDF https://www.usenix.org/system/files/conference/atc18/atc18-yan-francis.pdf
- accessed: 2026-10-10
- claim-under-test: Pantheon (USENIX ATC 2018) shows that calibrated emulators (constant rate + delay + random loss + droptail buffer) reproduce real paths' throughput and delay within some percentage. Get the figure.
- verdict: partially-confirmed. The figure is 17% average error. The model has **five** parameters, not four: the claim omits the isochronous/Poisson delivery bit.
- applicability: Moderate. This is the baseline that a "rich" PTF must beat. If a 5-parameter fit gets within about 17%, PTF fidelity scoring should report improvement over this fit, not only absolute error.
## Evidence
§1:
> a bottleneck link rate, buffer size, stochastic per-packet loss rate, and propagation delay) is sufficient to replicate
> the performance of a diverse library of transport protocols (with each protocol matching its real-world throughput
> and delay to within 17% on average)

§5.2, the five parameters:
> 1. a bottleneck link rate, 2. a constant propagation delay, 3. a DropTail threshold for the sender's queue,
> 4. a stochastic loss rate (per-packet, i.i.d.), and 5. a bit that selects whether the link runs isochronously
> [...] or with packet deliveries governed by a memoryless Poisson point process

- Error metric: the average of the percentage changes in mean throughput and mean 95th-percentile delay, taken across the reference schemes. Fitted with Bayesian optimisation (Spearmint).
- Fig. 4 per-path errors: 19.1, 13.0, 25.1, 17.7, 15.6, 12.7%, and 14.4% with 3 flows of cross traffic. The emulators are built on Mahimahi.
- Fig. 5 ablation, China wired path: rate only 211.8%, plus delay 189.7%, plus buffer 32.3%, plus loss 17.7%. Colombia cellular: constant to Poisson took the error from 23.7% to 13.0%.
- §7 calls 17% a limitation: "replicate throughput and delay metrics only within 17% accuracy on average".
## Implications for PTF / probe
- Buffer size accounts for most of the error reduction (189.7% to 32.3%). A queue/buffer estimate is essential in PTF, not optional.
- The derivation should also emit a **Pantheon-style 5-parameter summary** (rate, delay, droptail bytes or packets, i.i.d. loss, isochronous/Poisson). It is cheap, it gives a baseline for fidelity comparison, and it maps onto Mahimahi and netem exports.
- Delivery-process shape matters (constant vs Poisson). The opportunity-level capacity series keeps it. Exporting to a constant rate loses it.
- These are aggregate metrics (mean throughput, p95 delay) for congestion-control schemes, over 30 s runs. That is weak evidence for time-varying or per-transport fields. Do not use it to argue that those fields are unnecessary.
