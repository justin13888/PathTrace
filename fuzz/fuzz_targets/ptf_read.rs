#![no_main]
//! Arbitrary bytes must never panic the PTF reader, strict or recovering; valid files must
//! re-encode canonically to the same content digest.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = pt_format::Limits {
        max_section: 1 << 24,
        max_total: 1 << 26,
    };
    let _ = pt_format::read(
        data,
        pt_format::ReadOptions {
            limits,
            recover: true,
        },
    );
    if let Ok((f, rep)) = pt_format::read(
        data,
        pt_format::ReadOptions {
            limits,
            recover: false,
        },
    ) {
        let mut out = Vec::new();
        if let Ok(d) = pt_format::write(&f, &pt_format::WriteOptions::canonical(), &mut out) {
            assert_eq!(
                d, rep.content_digest,
                "canonical re-encoding changed content"
            );
        }
    }
});
