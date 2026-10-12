# EXP-0005-r4: Fuzzing PTF, CBOR, JSON twin and wire parsers (re-run at PTF 1.1): harness error

- verdict: **fail** (no target ran)
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0005-r3](../EXP-0005-r3-fuzz-smoke/) (passed; went stale with PTF 1.1 and wire minor 1)
- superseded by: EXP-0005-r5
- requirements: REQ-FMT-016, REQ-SEC-004

## Method

Identical to EXP-0005, with the `ptf_read` seed corpus extended to `conformance/v1.1/*.ptf` (commit "seed ptf_read fuzzing with the v1.1 corpus").

## Result

The fuzz task stopped before fuzzing (`artifacts/stderr.log`): `cp: will not overwrite just-created 'corpus/ptf_read/valid-minimal.ptf' with '../conformance/v1.1/valid-minimal.ptf'`. Both corpora have a `valid-minimal.ptf`, and one `cp` into a single directory refuses the second.

## Interpretation

A defect in the seed step, not a finding about the parsers. The task now copies the v1.1 seeds under a `v1.1-` prefix, and EXP-0005-r5 re-runs the experiment.
