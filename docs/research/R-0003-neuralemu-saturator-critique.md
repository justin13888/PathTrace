# R-0003: NeuralEmu's critique that saturating probes perturb the scheduler and traces are frozen snapshots
- source: https://arxiv.org/abs/2604.26080 ; PDF https://arxiv.org/pdf/2604.26080 (v1, 28 Apr 2026; Wan, Xie, Jamieson; Princeton / Univ. at Buffalo)
- accessed: 2026-10-10
- claim-under-test: NeuralEmu (arXiv 2604.26080, 2026) argues that saturating probes alter cellular scheduler behaviour and that recorded traces are frozen snapshots.
- verdict: confirmed
- applicability: Applies as a limitation statement (SPEC section 4, line 87). Its remedy, a learned 5G scheduler driven by RAN telemetry, is outside PTF's scope.
## Evidence
§3.2:
> the act of saturating the network fundamentally alters the network's behavior. [...] the scheduler
> observes the saturator flow's artificially large buffer and reacts by highly prioritizing this flow
> a network trace is merely a snapshot of the RAN scheduler's reaction to one specific application's traffic pattern
> [...] using this frozen trace, they make a fundamentally flawed assumption

- The paper also criticises CellReplay directly (§3.2.1). Running CellReplay's saturator alongside a BBR flow during recording makes the replay overstate the capacity available to a future sender.
- Its approach captures RAN telemetry with NG-Scope and NR-Scope (passive decoding of the 5G control channel: PRBs, MCS, CQI). It trains a "Neural Scheduler" plus a "Traffic Reconstructor" for background users and emulates with an AF_XDP middlebox.
- Reported error reductions against the state of the art: 55% for page load time, 57% for WebRTC bitrate, 51% for cloud-gaming one-way delay.
- Status: arXiv preprint (v1). No peer-reviewed venue is listed on the PDF.
## Implications for PTF / probe
- The SPEC citation and the paraphrase at line 87 are accurate. Cite it as a preprint.
- PTF cannot fix this with more fields. A PDO trace is workload-conditioned by construction. PTF should record **which workload produced each capacity segment** (heavy-flow rate profile and whether cross-probes were running), so consumers know what the trace is conditioned on.
- Adding a "scheduler model" section is not needed for v1. NeuralEmu requires air-interface telemetry (an SDR-based sniffer) that a portable probe on arbitrary access networks cannot get. Mark it as an extension slot (non-critical section), not a requirement.
- This supports SPEC 11.3: measure residual error of replay against live for non-saturating reference flows, and report it per trace.
