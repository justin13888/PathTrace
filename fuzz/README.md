# fuzz/

cargo-fuzz targets (nightly toolchain, not a workspace member). Run all for 60 s each: `mise run fuzz`.

| Target | Property |
|---|---|
| `ptf_read` | Reader never panics (strict and recovering, bounded limits); valid files re-encode canonically to the same content digest |
| `cbor_decode` | Deterministic-CBOR decoder never panics; anything accepted re-encodes byte-identically (only canonical input is accepted) |
| `jsonl_load` | JSON Lines twin loader never panics |
| `wire` | Control frames, envelopes, probe headers/tags, QUIC framing never panic |

Seed corpus: `conformance/v1.0/*.ptf` and `conformance/v1.1/*.ptf` are copied in by the fuzz task.
