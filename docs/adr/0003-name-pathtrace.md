# 0003: Product name PathTrace; format PTF

- status: accepted
- date: 2026-10-10
- requirements: —
- evidence: —

## Context

The draft used "PathLab" and "PTF" as working names. The repository is named PathTrace.

## Decision

The product is **PathTrace**, the binary is `pathtrace`, crates are prefixed `pt-`, the format is **PTF** (Path Trace Format) with extension `.ptf` and magic `89 50 54 46 0D 0A 1A 0A` ("\x89PTF\r\n\x1a\n", PNG-style). The PTF expansion matches the product name, so the format needs no rename.

## Consequences

Every reference to "PathLab" in the draft maps to PathTrace. Since nothing has shipped, there is no compatibility cost.
