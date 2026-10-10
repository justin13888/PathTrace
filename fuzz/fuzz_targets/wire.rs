#![no_main]
//! Control frames, envelopes, probe headers/tags and QUIC framing never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pt_wire::ctrl::Frame::decode(data);
    let _ = pt_wire::ctrl::Envelope::decode(data);
    let _ = pt_wire::probe::Header::decode(data);
    let _ = pt_wire::probe::quic::unwrap(data);
    let t = pt_wire::probe::Tagger::new(b"fuzz");
    let _ = t.verify(data);
});
