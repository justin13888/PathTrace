# docs/design/ — component designs

One document per component or cross-cutting concern. Written before the code it describes; updated in the same PR as any code change that alters behaviour.

- Naming: `kebab-topic.md` (e.g. `ptf-format.md`, `probe.md`, `derivation.md`).
- Each design decision inside a document uses this shape: **Problem**, **Constraints**, **Alternatives**, **Choice**, **Rationale**, **Validated by** (EXP/R ids, or "pending EXP-NNNN").
- Section headings are stable anchors referenced from `docs/spec/` requirements; do not rename a heading without updating references (`cargo xtask audit` checks that referenced files exist).
- Decisions that are hard to reverse are also recorded as ADRs; the design doc links the ADR.

## Index

| Document | Covers |
|---|---|
| [simulator-requirements.md](simulator-requirements.md) | What the deferred simulator needs; PTF field mapping; sufficiency verdict |
| [ptf-format.md](ptf-format.md) | PTF 1.0 normative specification: principles, byte layout, sections |
| [probe.md](probe.md) | Probe and responder: threads, pairing, wire protocol, clocks, raw tables, phases, saturation control, robustness |
