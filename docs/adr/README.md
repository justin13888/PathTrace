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
