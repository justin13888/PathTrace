# EXP-0003-r3: Independent and Rust readers agree on every conformance directory (re-run)

- verdict: pass
- pinned commit: see `manifest.toml`
- supersedes: [EXP-0003-r2](../EXP-0003-r2-conformance-independent-reader/) (passed; went stale when `f530436` untracked `tools/ptf-py/__pycache__/ptf.cpython-314.pyc`, a bytecode file that had been committed by mistake, in a covered path)
- requirements: REQ-FMT-001, -002, -003, -005, -009, -010, -013, -014, -018

## Method

Same as EXP-0003-r2: the Python reader runs over `conformance/v1.0` (18 synthetic cases) and `conformance/v1.0-real` (1 real, anonymised IPv6 capture), together with the Rust conformance tests.

## Result

18/18 and 1/1 cases pass (`artifacts/stdout.log`), and both Rust conformance tests pass. All content digests are identical to r2, including the real trace (`07496f6b…`).

## Interpretation

Unchanged from r2: the reader source is identical; only the stray bytecode is gone.
