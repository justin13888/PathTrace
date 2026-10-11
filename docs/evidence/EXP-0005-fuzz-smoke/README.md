# EXP-0005: Fuzzing PTF, CBOR, JSON twin and wire parsers

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: REQ-FMT-016, REQ-SEC-004

## Method

`FUZZ_SECONDS=120 mise run fuzz`: cargo-fuzz (libFuzzer with AddressSanitizer, nightly toolchain) for 120 s per target. The `ptf_read` corpus is seeded with the conformance files.

| Target | Property checked on every input |
|---|---|
| `ptf_read` | No panic in strict or recovering reads with bounded limits; every accepted file re-encodes canonically to the same content digest |
| `cbor_decode` | No panic; anything accepted re-encodes byte-identically (only canonical CBOR is accepted) |
| `jsonl_load` | No panic on arbitrary text; loaded files encode |
| `wire` | Control frames, envelopes, probe headers and tags, and QUIC framing never panic |

## Result

All four targets exited cleanly (`artifacts/stdout.log`, `stderr.log`): 1.18 M, 4.32 M, 7.37 M and 3.13 M executions respectively, with no crashes, leaks, timeouts or assertion failures.

## Interpretation

This is a smoke-level campaign (8 CPU-minutes). It shows the parsers survive millions of mutated inputs. It is not an exhaustive campaign; longer runs (`FUZZ_SECONDS=3600`) can be added to CI later.
