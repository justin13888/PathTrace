# docs/spec/ — requirements

The product requirements PathTrace commits to, each with a stable ID and a machine-checked status.

## Files

One file per area: `REQ-<AREA>.md`. Areas:

| Area | File | Scope |
|---|---|---|
| SCOPE | `REQ-SCOPE.md` | Platform, product boundaries, non-goals |
| FMT | `REQ-FMT.md` | PTF trace format |
| PRB | `REQ-PRB.md` | Probe and responder (capture) |
| DRV | `REQ-DRV.md` | Derivation (observations → path model) |
| CLI | `REQ-CLI.md` | Command-line interface and compatibility |
| SEC | `REQ-SEC.md` | Security and safety |
| EMU | `REQ-EMU.md` | Emulator, runner, fidelity (deferred work) |
| REPO | `REQ-REPO.md` | Repository process: audit, git hygiene, tooling |

## Requirement syntax (parsed by `cargo xtask audit`)

```
### REQ-FMT-001: Short title
- status: met
- spec: §7.2
- design: docs/design/ptf-format.md
- adr: 0003
- evidence: EXP-0004, EXP-0005
- issue: #12

One or more sentences stating the testable requirement.
```

- `status` is one of: `planned`, `met`, `deferred`, `user-acceptance`, `dropped`.
  - `met` requires at least one `evidence` entry whose manifest has `verdict = "pass"` and is not superseded.
  - `deferred` and `user-acceptance` require an `issue`.
  - `dropped` requires an `adr` explaining why.
- `spec` cites the section of the original draft specification (v0.1, 8 October 2026) the requirement derives from, or `new`.
- IDs are never reused or renumbered. A requirement that changes meaning is `dropped` and replaced by a new ID.

## Coverage of the original specification

`coverage.md` maps every section of the original draft specification to the requirements or ADRs that absorb it, so that the draft itself is no longer needed.
