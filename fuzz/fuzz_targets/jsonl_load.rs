#![no_main]
//! JSON Lines twin loader never panics on arbitrary text.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(f) = pt_format::jsonl::load(s) {
            let mut out = Vec::new();
            let _ = pt_format::write(&f, &pt_format::WriteOptions::canonical(), &mut out);
        }
    }
});
