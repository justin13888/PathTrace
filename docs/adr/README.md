# docs/adr/ — Architecture Decision Records

One file per decision that is hard to reverse, affects compatibility, or departs from the original specification.

- Naming: `NNNN-kebab-title.md`, numbered sequentially from `0001`. `0000-template.md` is the template.
- Status: `proposed` → `accepted` → optionally `superseded-by: NNNN`. Also `rejected`.
- Accepted ADRs are immutable. To change a decision, write a new ADR that supersedes it and only add the `superseded-by` line to the old one.
- An ADR that asserts one option is better than another must cite `docs/research/R-*` or `docs/evidence/EXP-*`.
- Commit scope: `adr` (e.g. `docs(adr): 0004 columnar observation encoding`).

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-license-apache-2.md) | License under Apache-2.0 | accepted |
| [0002](0002-linux-only.md) | Linux only, for every role | accepted |
| [0003](0003-name-pathtrace.md) | Product name PathTrace; format PTF | accepted |
| [0004](0004-build-format-and-probe-defer-datapath.md) | Build the format, probe and derivation; defer the emulator datapath decision | accepted |
| [0005](0005-merge-commits-and-pinned-evidence.md) | Merge-commit-only history with commit-pinned evidence | accepted |
| [0006](0006-transport-class-shaping.md) | Transport class shaping: QUIC header framing (header/1) and genuine TLS on tcp/443 | accepted |
| [0007](0007-threads-no-async-runtime.md) | Dedicated threads, no async runtime, in measurement code | accepted |
| [0008](0008-capture-first-release-and-compatibility.md) | Capture-first release; PTF 1.0 frozen at capture-ready; permanent read compatibility | accepted |
| [0009](0009-pt-format-uses-std.md) | pt-format uses std (no `no_std` requirement) | accepted |
| [0010](0010-light-trains-for-dual-workload.md) | Add periodic light packet trains to the light observer flow (dual-workload recording) | accepted |
| [0011](0011-ptf-container-and-encoding.md) | PTF container and encoding | accepted |
| [0012](0012-timestamp-clock-domains.md) | Packet timestamps: kernel software stamps in CLOCK_REALTIME, recorded raw with clock pairs | accepted |
