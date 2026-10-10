# EXP-0004: PTF property and unit tests

- verdict: pass
- pinned commit: see `manifest.toml`
- requirements: REQ-FMT-004, -006, -007, -011, -012, -017, -019

## Hypothesis

pt-format's unit and property tests pass. Together they cover the deterministic CBOR profile, every column encoding, crash recovery, canonical encoding, limits, the JSON twin and redaction.

## Method

`cargo test --release -p pt-format`: 24 unit and property tests plus 2 conformance tests. Relevant ones:

| Test | Property | Requirement |
|---|---|---|
| `cbor::roundtrip_is_identity_and_canonical` (proptest) | decode(encode(v)) = v and re-encoding is byte-identical | REQ-FMT-004, -012 |
| `cbor::rejects_non_canonical`, `depth_limit`, `rfc8949_vectors`, `key_order_is_length_first` | Only the deterministic profile is accepted | REQ-FMT-004 |
| `column::int_encodings_roundtrip`, `nullable_roundtrip`, `f64_and_bool_roundtrip` (proptest) | Every encoding is lossless over the full u64/i64/f64 range; nulls are explicit validity bits | REQ-FMT-006, -007 |
| `column::decode_never_panics`, `cbor::decoder_never_panics` (proptest) | No panics on arbitrary blobs | REQ-FMT-016 (also EXP-0005) |
| `container::truncation_recovery_keeps_complete_sections` | A log cut at **every** byte offset after META recovers every complete section, and a strict read refuses it | REQ-FMT-011 |
| `container::write_read_roundtrip_canonical` | Identical bytes on re-encode; content digest identical with and without compression | REQ-FMT-012 |
| `container::decompression_bomb_guard`, `rejections`, `unknown_sections` | Limits, magic, major, CRC, critical rule | REQ-FMT-002, -003 |
| `jsonl::dump_load_is_byte_identical` | Byte-identical JSON twin, including NaN, -0.0, extreme ints, opaque sections | REQ-FMT-014 |
| `redact::shareable_and_anonymous` | `id` and `quasi` items and columns removed by annotation; realtime shifted; level recorded | REQ-FMT-017 |

The section inventory (REQ-FMT-019) is defined by `is_known_type` and exercised by every container test, and the merged traces in EXP-0002 contain all raw and derived sections.

## Result

`artifacts/stdout.log`: 24 passed, 2 passed, 0 failed.

## Interpretation

These tests check properties over randomised inputs (proptest, 256 cases per property) as well as fixed vectors. Crash recovery is exhaustive over truncation offsets but does not simulate partially written sectors inside a section: CRC32C catches those.
