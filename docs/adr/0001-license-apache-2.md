# 0001: License under Apache-2.0

- status: accepted
- date: 2026-10-10
- requirements: REQ-REPO-006
- evidence: —

## Context

The repository is public. PTF is meant to be implemented independently by other tools (the conformance suite exists for exactly that). The software is a command-line tool and a file format, not a hosted network service. The license must be detected by GitHub, so the text has to be verbatim.

## Options considered

1. **MIT**: minimal and permissive, but no explicit patent grant.
2. **Apache-2.0**: permissive, with an explicit patent grant and patent-retaliation clause, and explicit contribution terms (§5).
3. **MIT OR Apache-2.0 (dual)**: the Rust ecosystem convention, mainly for GPLv2 compatibility. It needs two license files and doubles the decision surface for contributors.
4. **MPL-2.0**: file-level copyleft. It would force modified format-reader files open, which deters adoption of the format by closed tools.
5. **AGPL-3.0**: network copyleft. Its trigger (users interacting over a network) does not match a CLI that measures paths, and it would block adoption of the format and probe by most organisations.

## Decision

Apache-2.0, single license. The explicit patent grant matters for a file format that third parties are invited to implement: an implementer of PTF receives patent rights from contributors. Copyleft has no justification here because nothing is offered as a service, and adoption of the format is a goal. GPLv2 compatibility, the main argument for dual licensing, is not a need of this project.

The text is fetched verbatim from `https://www.apache.org/licenses/LICENSE-2.0.txt` (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`, 11358 bytes) so that GitHub's license detection matches.

## Consequences

- Contributions are licensed under Apache-2.0 §5 without a CLA.
- Dependencies must be Apache-2.0-compatible, enforced by the `deny.toml` license allowlist.
- Relicensing later would need consent from contributors; with a single maintainer today that remains feasible.
