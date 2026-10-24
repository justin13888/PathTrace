# 0015: Trace metadata records generic facts; vendor names are labels only

- status: accepted
- date: 2026-10-24
- requirements: REQ-PRB-019, REQ-PRB-034
- evidence: R-0017

## Context

A field run (2026-10-19, Mac over Tailscale to a Linux responder) recorded 314 of 319 traces over a relayed overlay path. Only the operator's free-text tag `derp` said so. The same review found facts a trace cannot recover later: each host's clock-sync state, the pacing check, the power source, and the physical link under a tunnel. The obvious fix is to record what the overlay software knows (relay region, peer endpoint, direct or relayed). That puts one vendor's state into the schema. A trace from someone else's machine (another VPN, another overlay, none) would then need another vendor's fields, and those fields would be empty or meaningless for everyone else. PTF additions are permanent (ADR 0008, REQ-FMT-010), so whatever the schema admits now it keeps forever.

## Options considered

1. **Record vendor state** (query the overlay's local API, store its fields). This is precise for one vendor. Each new vendor needs new keys and new platform code, the keys mean nothing on other machines, and the probe depends on software outside its control.
2. **Record nothing beyond the path itself.** This keeps the schema minimal, but the facts that decide whether a trace can be trusted (clock sync, power, suspend, the link under a tunnel) are lost for good.
3. **Record generic facts and keep vendor names as labels.** The schema holds only facts any implementation could observe on any supported machine without a vendor API. Vendor or product names may appear only as informative label values.

## Decision

Option 3. The rules:

- **Generic facts only.** META, EVNT and CTXS record what the host itself reports through operating-system interfaces: interface type, driver, MTU, whether the egress is a tunnel, the interface the default route uses beneath it, clock sources and kernel clock-sync state, the power source, the pacing check, suspends, interface and route changes. Each fact has a meaning independent of who made the software that produced it.
- **Vendor names are labels.** A product name may appear only as the value of an informative key: the existing `iface.tunnel.provider` hint, user tags, the label and the network class. No key names a vendor, and no field holds a vendor's internal state (relay region, peer endpoint, coordination-server status). A consumer may ignore every label and lose nothing it needs for the path model.
- **No vendor APIs.** pathtrace does not query overlay or VPN software (no local API, no CLI, no config files). `doctor` may advise the operator about such software, but nothing it learns that way goes into a trace.
- **Anomalies are recorded by their effect.** A path that changes mid-session (relay to direct, route or interface switch, suspend) is recorded as what the host observes (`iface_change`, an underlay change, `stall {cause: "suspend"}`) and as what derivation finds in the raw data (a base-delay change-point). It is never recorded as what a vendor reports. Derived findings are re-derivable from raw, so improving them later loses nothing.
- **Operator sidecars sit outside the schema.** Files an operator keeps next to a trace (ping logs, notes) are not part of PTF and are not read by pathtrace.

## Consequences

- PTF 1.3 adds `endpoints.<ep>.clock_sync`, `power`, `pacing` and `underlay`, the EVNT types `host_state` and `underlay_change`, and the CTXS table `ifstats_underlay` (probe.md §4.5, ptf-format.md). Each one means the same on Linux and macOS, and is unknown where the platform cannot observe it.
- Whether an overlay was relayed is not a recorded fact. Where it matters, it shows as a delay step or an underlay change, and the operator's tags remain as labels.
- Reversing this means a new ADR. Vendor keys added under such an ADR would still be permanent.
