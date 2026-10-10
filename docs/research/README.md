# docs/research

First-hand verification notes for claims that PathTrace's design depends on: prior-art tools, papers, formats, and kernel facilities. Each note records what the primary source actually says (paper, source code, man page, or spec), a verdict, and what it means for the PTF format and the probe. The goal is that no design decision rests on remembered or second-hand claims.

"SPEC" in a note means the original draft specification (v0.1, 8 October 2026). It is not kept in the repository; `docs/spec/coverage.md` maps its sections to requirements. Section numbers are stable references; line numbers cited in early notes refer to that draft and are informational only.

Commit scope: `research` (e.g. `docs(research): R-0010 so_timestamping on veth`).

## Naming convention

`R-NNNN-<slug>.md`: a four-digit, zero-padded, monotonically increasing id plus a short kebab-case slug, for example `R-0001-mahimahi-trace-format.md`. Ids are never reused.

## Template

```
# R-NNNN: <title>
- source: <URL(s)>
- accessed: YYYY-MM-DD
- claim-under-test: <claim>
- verdict: confirmed | partially-confirmed | refuted | unverifiable
- applicability: <how/whether it matters for what PTF must represent; be skeptical — say "not applicable" when so>
## Evidence
<short direct quotes (<=3 lines each) or code excerpts with file path/line, then your summary>
## Implications for PTF / probe
<concrete bullets: which fields/data are needed, which aren't>
```

Pin source code to a commit or version. Keep notes under about 80 lines.

## Lifecycle

- Notes are **append-only**. Once written, a note's evidence and verdict are not edited, apart from typo fixes.
- When a note turns out wrong or outdated (refuted by newer evidence, or the source changed), keep it. Write a new note with a new id that cites the old one, and add a line `- superseded-by: R-NNNN` to the old note's header.
- Refuted and unverifiable notes are kept. They record what was checked.
- Update the index below whenever a note is added or superseded.

## Index

| id | title | verdict | superseded-by |
|----|-------|---------|---------------|
| [R-0001](R-0001-mahimahi-trace-format.md) | Mahimahi trace format, mm-link queues, mm-delay and mm-loss arguments | partially-confirmed | |
| [R-0002](R-0002-cellreplay-dual-workload.md) | CellReplay dual-workload recording (light and heavy PDOs) | confirmed | |
| [R-0003](R-0003-neuralemu-saturator-critique.md) | NeuralEmu's critique that saturating probes perturb the scheduler and traces are frozen snapshots | confirmed | |
| [R-0004](R-0004-pantheon-calibrated-emulators.md) | Pantheon calibrated emulators and their replication error | partially-confirmed | |
| [R-0005](R-0005-tc-netem-parameters.md) | tc-netem parameters and limits | confirmed | |
| [R-0006](R-0006-rattan-trace-formats-and-config.md) | Rattan cells, config format, and netem-trace trace formats | confirmed | |
| [R-0007](R-0007-png-chunk-criticality.md) | PNG chunk criticality rule (analogy for PTF section flags) | partially-confirmed | |
| [R-0008](R-0008-hk-convco-commit-validation.md) | Can hk alone enforce semantic commits with a closed scope set? | refuted | |
| [R-0009](R-0009-github-merge-policy-and-license-detection.md) | GitHub merge-commit-only settings, license detection, CI namespaces | confirmed | |
