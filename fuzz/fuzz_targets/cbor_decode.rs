#![no_main]
//! Deterministic-CBOR decoder: never panics; accepted input re-encodes byte-identically.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = pt_format::cbor::decode(data) {
        assert_eq!(
            pt_format::cbor::encode(&v).expect("encodable"),
            data,
            "non-canonical input accepted"
        );
    }
});
