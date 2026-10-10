# Coverage of the original draft specification

The draft "PathLab: path profiling, trace format and emulator, Specification v0.1 (8 October 2026)" was the starting input. It is not kept in the repository. Every section is absorbed below into requirements (REQ), ADRs, design documents or research notes. Where this repository and the draft disagree, the repository wins, and the ADR says why.

| Draft § | Topic | Absorbed into | Notes |
|---|---|---|---|
| 1 | Summary; central rule | REQ-SCOPE-003; README | "PathLab" renamed (ADR 0003) |
| 2.1 | Goals G1–G5 | G1 → REQ-PRB-*; G2 → REQ-FMT-*; G3, G4, G5 → REQ-EMU-* | G3 to G5 deferred (ADR 0008) |
| 2.2 | Non-goals | REQ-SCOPE-002, -004, -005; ADR 0002 | macOS/Windows emulator non-goal widened to "Linux only, every role" |
| 2.3 | Definition of done | REQ-FMT-018, REQ-FMT-016, REQ-SEC-003, REQ-EMU-008, REQ-EMU-007, REQ-PRB-028 | Field-corpus criteria are `user-acceptance` (#16) |
| 3 | Assumptions | REQ-PRB-014 (data budget), REQ-PRB-012 (CC recorded), REQ-EMU-006 (baseline), REQ-FMT-017 (sharing), ADR 0002 (platforms) | Roaming endpoint is a Linux laptop only |
| 4 | Identifiable vs not | docs/design/simulator-requirements.md "Known limits"; REQ-DRV-003 (split method), REQ-DRV-015 (proxy) | Verified against R-0003 |
| 5.1–5.7 | Competitive analysis | R-0001 (Mahimahi), R-0002 (CellReplay), R-0003 (NeuralEmu), R-0004 (Pantheon), R-0005 (netem), R-0006 (Rattan), R-0007 (PNG) | Rows the draft marked † were not re-verified and are not relied on |
| 5.8 | Conclusions; build vs reuse | ADR 0004 | Datapath decision moved to #2 |
| 6.1 | Roles | REQ-PRB-001 | |
| 6.2 | Session and security | REQ-PRB-002 … -006, REQ-SEC-001 | |
| 6.3 | Clocks and timestamps | REQ-PRB-007, REQ-PRB-008, REQ-DRV-002 | Kernel stamps are CLOCK_REALTIME; handled by logging clock pairs (design: probe.md) |
| 6.4 | Probe header | REQ-PRB-009 | Layout finalised in docs/design/probe.md |
| 6.5 | Phases, saturation validity, profiles | REQ-PRB-010, -011, -012, -013, -014; ADR 0010 | Light trains added (ADR 0010); `smoke` profile added |
| 6.6 | Transport policy matrix | REQ-PRB-015, -023, -024, -026; ADR 0006 | |
| 6.7 | Safety and etiquette | REQ-PRB-016, REQ-SCOPE-005, REQ-SCOPE-007 | |
| 6.8 | Platform and I/O | REQ-PRB-017; ADR 0002, ADR 0007 | Only the Linux tier remains |
| 6.9 | Output | REQ-PRB-018 | |
| 7.1 | Format principles | REQ-FMT-006, -007, -008, -014; docs/design/ptf-format.md | |
| 7.2 | Container | REQ-FMT-001 … -005 | |
| 7.3 | Sections | REQ-FMT-019, REQ-FMT-013, REQ-FMT-024 | CTXS (context) added; SIGN deferred (#12) |
| 7.4 | Path model | REQ-FMT-020; docs/design/simulator-requirements.md | quantum, workload provenance, size_delay, summary added |
| 7.5 | Versioning | REQ-FMT-009, REQ-FMT-010, REQ-DRV-012; ADR 0008 | |
| 7.6 | Privacy | REQ-FMT-017 | |
| 7.7 | Interoperability | REQ-FMT-021, REQ-FMT-023, REQ-FMT-025 | Rattan export and pcapng import deferred (#11, #13) |
| 7.8 | Conformance | REQ-FMT-018 | |
| 8 | Derivation | REQ-DRV-001 … -012 | |
| 9.1–9.8 | Emulator | REQ-EMU-001 … -004, -010 | Deferred (#1 to #4, #10) |
| 10 | Runner and reporting | REQ-EMU-005, -006 | Deferred (#5, #6) |
| 11.1 | Emulator vs synthetic | REQ-EMU-002 (deferred); its analogue for the probe: REQ-DRV-013 | |
| 11.2 | Round trip | REQ-EMU-008 (deferred); closure via netem: REQ-DRV-014 | |
| 11.3 | Real vs emulated | REQ-EMU-007 (deferred); ground truth captured now: REQ-PRB-012 | |
| 11.4 | Cross-tool | REQ-EMU-009 (deferred) | |
| 12 | Sampling plan | REQ-PRB-028; docs/runbooks/field-session.md; REQ-PRB-019 (tags) | |
| 13.1 | Workspace | crates/README.md; AGENTS.md crate map; ADR 0009 | pt-model, pt-emu, pt-run, pt-ref deferred with the emulator |
| 13.2 | Dependency policy | REQ-SEC-005; deny.toml; ADR 0007 | |
| 13.3 | Quality bar | REQ-SEC-003, REQ-SEC-004, REQ-FMT-010 (golden files) | |
| 14 | Milestones | ADR 0008 (reordered: capture first) | |
| 15 | Risks | docs/design/simulator-requirements.md "Known limits"; ADR 0010 | |
| 16 | Open questions | Resolved: 1 → all three workloads kept as reference flows; 2 → laptop only (ADR 0002); 3 → one responder per session, any number of regions; 4 → recorded, not controlled (REQ-PRB-012); 5 → irrelevant to capture; 6 → ADR 0004; 7 → public repo, Apache-2.0 (ADR 0001), redaction (REQ-FMT-017); 8 → 200 MB cap kept, `light` auto on metered | |
| 17 | References | docs/research/ | |
