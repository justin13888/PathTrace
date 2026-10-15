//! Conformance corpus and golden files (REQ-FMT-010, REQ-FMT-018): every file under
//! `conformance/` must produce exactly the verdict recorded in its directory's expected.json,
//! forever. New releases add directories; existing ones are never edited.

use std::path::Path;

fn cases(dir: &Path) -> Vec<(String, bool, String)> {
    let text = std::fs::read_to_string(dir.join("expected.json")).expect("expected.json");
    let v: serde_json::Value = serde_json::from_str(&text).expect("json");
    v.as_object()
        .expect("object")
        .iter()
        .map(|(k, e)| {
            let valid = e["valid"].as_bool().expect("valid");
            let detail = if valid {
                e["content_digest"].as_str()
            } else {
                e["kind"].as_str()
            };
            (k.clone(), valid, detail.expect("detail").to_string())
        })
        .collect()
}

#[test]
fn corpus_verdicts_are_stable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
    let mut n = 0;
    for entry in std::fs::read_dir(&root).expect("conformance dir") {
        let dir = entry.expect("entry").path();
        if !dir.is_dir() {
            continue;
        }
        for (name, valid, detail) in cases(&dir) {
            let bytes = std::fs::read(dir.join(&name)).expect("case file");
            match pt_format::read(&bytes, pt_format::ReadOptions::default()) {
                Ok((_, rep)) => {
                    assert!(valid, "{name}: expected rejection ({detail}), was accepted");
                    assert_eq!(rep.content_digest, detail, "{name}: content digest changed");
                }
                Err(e) => {
                    assert!(!valid, "{name}: expected valid, got {e}");
                    assert_eq!(e.kind(), detail, "{name}: wrong rejection reason: {e}");
                }
            }
            n += 1;
        }
    }
    assert!(n >= 18, "corpus too small: {n}");
}

#[test]
fn jsonl_twin_roundtrips_valid_corpus() {
    // The synthetic corpora (conformance/v1.0-real holds captured traces, checked above).
    for version in ["v1.0", "v1.1", "v1.2"] {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance")
            .join(version);
        for (name, valid, _) in cases(&root) {
            if !valid {
                continue;
            }
            let bytes = std::fs::read(root.join(&name)).unwrap();
            let (f, rep) = pt_format::read(&bytes, pt_format::ReadOptions::default()).unwrap();
            let back = pt_format::jsonl::load(&pt_format::jsonl::dump(&f)).unwrap();
            let mut out = Vec::new();
            let d =
                pt_format::write(&back, &pt_format::WriteOptions::canonical(), &mut out).unwrap();
            assert_eq!(
                d, rep.content_digest,
                "{version}/{name}: JSON twin changed content"
            );
        }
    }
}
