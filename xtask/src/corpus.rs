//! Conformance corpus generator (REQ-FMT-018): `conformance/v1.0/*.ptf` + `expected.json`.
//!
//! Each case is a file plus its expected verdict: valid (with content digest) or invalid with an
//! error kind (`pt_format::Error::kind`). Invalid files keep correct CRCs wherever the intended
//! failure is not the CRC itself, so readers must detect the intended problem.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::Result;
use pt_format::{
    Body, Column, Enc, Key, Map, PtfFile, Section, Table, Value, Values, WriteOptions, flags,
};

fn meta(extra: Value) -> Section {
    let mut m = Value::map()
        .with("kind", "trace")
        .with("redaction", "full")
        .with("note", "PTF conformance corpus");
    if let Value::Map(e) = extra {
        for (k, v) in e {
            m = m.with(&k.0, v);
        }
    }
    Section::new(
        b"META",
        flags::CRITICAL,
        m.as_map().cloned().unwrap_or_default(),
    )
}

fn write(f: &PtfFile, opts: &WriteOptions) -> Vec<u8> {
    let mut b = Vec::new();
    pt_format::write(f, opts, &mut b).expect("corpus encodes");
    b
}

fn file(sections: Vec<Section>) -> PtfFile {
    PtfFile {
        major: 1,
        minor: 0,
        sections,
    }
}

/// Raw section record with arbitrary type/flags/payload and a correct CRC.
fn record(kind: &[u8; 4], sflags: u16, reserved: u16, payload: &[u8]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(kind);
    r.extend_from_slice(&sflags.to_le_bytes());
    r.extend_from_slice(&reserved.to_le_bytes());
    r.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    r.extend_from_slice(payload);
    let crc = crc32c(&r);
    r.extend_from_slice(&crc.to_le_bytes());
    r
}

fn crc32c(b: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &x in b {
        c ^= u32::from(x);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0x82f6_3b78
            } else {
                c >> 1
            };
        }
    }
    !c
}

fn header(major: u16, minor: u16, fflags: u32) -> Vec<u8> {
    let mut h = vec![0x89, b'P', b'T', b'F', 0x0d, 0x0a, 0x1a, 0x0a];
    h.extend_from_slice(&major.to_le_bytes());
    h.extend_from_slice(&minor.to_le_bytes());
    h.extend_from_slice(&fflags.to_le_bytes());
    h
}

fn meta_payload() -> Vec<u8> {
    meta(Value::map()).encode_payload().expect("meta")
}

fn all_encodings() -> Table {
    let n = 20usize;
    let u: Vec<u64> = (0..n as u64)
        .map(|i| 1_000_000_000_000 + i * 20_000_000 + (i * 7919) % 1000)
        .collect();
    let i: Vec<i64> = (0..n as i64).map(|x| (x - 10) * 37).collect();
    let opt: Vec<Option<u64>> = (0..n as u64)
        .map(|x| (x % 3 != 0).then_some(x * 11))
        .collect();
    Table::new("cases", n)
        .with(Column::new("u_plain", Enc::Plain, Values::U64(u.clone())).unit("ns"))
        .with(Column::new("u_varint", Enc::Varint, Values::U64(u.clone())))
        .with(Column::new("u_delta", Enc::Delta, Values::U64(u.clone())))
        .with(Column::new("u_delta2", Enc::Delta2, Values::U64(u.clone())).clock("a.real"))
        .with(Column::new(
            "u_rle",
            Enc::Rle,
            Values::U64((0..n as u64).map(|x| x / 4).collect()),
        ))
        .with(Column::new("i_plain", Enc::Plain, Values::I64(i.clone())))
        .with(Column::new("i_varint", Enc::Varint, Values::I64(i.clone())))
        .with(Column::new("i_delta", Enc::Delta, Values::I64(i.clone())))
        .with(Column::new("i_delta2", Enc::Delta2, Values::I64(i.clone())))
        .with(Column::new(
            "i_rle",
            Enc::Rle,
            Values::I64((0..n as i64).map(|x| -(x / 5)).collect()),
        ))
        .with(Column::new(
            "f_plain",
            Enc::Plain,
            Values::F64((0..n).map(|x| x as f64 / 3.0).collect()),
        ))
        .with(Column::new(
            "b_bitmap",
            Enc::Bitmap,
            Values::Bool((0..n).map(|x| x % 2 == 0).collect()),
        ))
        .with(Column::nullable_u64("n_delta2", Enc::Delta2, &opt).with_meta("pii", "quasi"))
        .with(Column::new(
            "u_extremes",
            Enc::Delta,
            Values::U64(vec![
                0,
                u64::MAX,
                1,
                u64::MAX - 1,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
                5,
            ]),
        ))
        .with_attrs(Value::map().with("note", "every type/encoding combination"))
}

pub fn generate(root: &Path) -> Result<()> {
    let dir = root.join("conformance/v1.0");
    std::fs::create_dir_all(&dir)?;
    let mut cases: BTreeMap<String, (Vec<u8>, Option<&str>)> = BTreeMap::new();
    let canon = WriteOptions::canonical();

    // ---- valid ----
    cases.insert(
        "valid-minimal.ptf".into(),
        (write(&file(vec![meta(Value::map())]), &canon), None),
    );
    cases.insert(
        "valid-all-encodings.ptf".into(),
        (
            write(
                &file(vec![
                    meta(Value::map()),
                    Section::new(b"OBSV", 0, Map::new()).with_table(all_encodings()),
                ]),
                &canon,
            ),
            None,
        ),
    );
    cases.insert(
        "valid-uncompressed-no-index.ptf".into(),
        (
            write(
                &file(vec![
                    meta(Value::map()),
                    Section::new(b"OBSV", 0, Map::new()).with_table(all_encodings()),
                ]),
                &WriteOptions {
                    zstd_level: None,
                    compress_threshold: 0,
                    index: false,
                },
            ),
            None,
        ),
    );
    let big = Table::new("big", 100_000).with(Column::new(
        "t",
        Enc::Delta2,
        Values::U64(
            (0..100_000u64)
                .map(|i| i * 120_000 + (i * 7919) % 997)
                .collect(),
        ),
    ));
    cases.insert(
        "valid-compressed.ptf".into(),
        (
            write(
                &file(vec![
                    meta(Value::map()),
                    Section::new(b"OBSV", 0, Map::new()).with_table(big),
                ]),
                &canon,
            ),
            None,
        ),
    );
    let unknown = Section::new(
        b"ZZZZ",
        0,
        Value::map()
            .with("future", "non-critical section a 1.0 reader skips")
            .as_map()
            .cloned()
            .unwrap_or_default(),
    );
    cases.insert(
        "valid-unknown-noncritical.ptf".into(),
        (
            write(&file(vec![meta(Value::map()), unknown]), &canon),
            None,
        ),
    );
    // Future minor version: unknown column type/encoding, unknown table and column keys, unknown
    // head keys, an unknown non-critical section with unknown flag bits, minor = 7.
    let mut t = all_encodings();
    t.meta
        .insert(Key::from("future_table_key"), Value::from(1u64));
    t.columns[0] = t.columns[0].clone().with_meta("future_column_key", "x");
    t.columns.push(Column {
        name: "future".into(),
        data: pt_format::Data::Opaque {
            type_name: "u128".into(),
            enc_name: "zstd-dict".into(),
            nullable: false,
            blob: vec![1, 2, 3, 4],
        },
        validity: None,
        meta: Map::new(),
    });
    let mut f = file(vec![
        meta(Value::map().with("future_meta_key", Value::map().with("x", 1u64))),
        Section::new(b"OBSV", 0, Map::new()).with_table(t),
    ]);
    f.minor = 7;
    f.sections.push(Section {
        kind: *b"FUTR",
        flags: 1 << 9,
        body: Body::Opaque(b"bytes a 1.0 reader must skip".to_vec()),
    });
    cases.insert("valid-future-minor.ptf".into(), (write(&f, &canon), None));

    // ---- invalid ----
    let good = write(
        &file(vec![
            meta(Value::map()),
            Section::new(b"OBSV", 0, Map::new()).with_table(all_encodings()),
        ]),
        &WriteOptions {
            zstd_level: None,
            compress_threshold: 0,
            index: false,
        },
    );
    let mut b = good.clone();
    b[1] = b'X';
    cases.insert("invalid-bad-magic.ptf".into(), (b, Some("bad_magic")));
    let mut b = good.clone();
    b[8] = 2;
    cases.insert(
        "invalid-unsupported-major.ptf".into(),
        (b, Some("unsupported_major")),
    );
    let mut b = good.clone();
    b[12] = 1;
    cases.insert("invalid-file-flags.ptf".into(), (b, Some("reserved")));
    cases.insert(
        "invalid-truncated.ptf".into(),
        (good[..good.len() - 10].to_vec(), Some("truncated")),
    );
    let mut b = good.clone();
    let n = b.len();
    b[n - 30] ^= 0x40;
    cases.insert("invalid-crc.ptf".into(), (b, Some("crc")));
    let mut b = header(1, 0, 0);
    b.extend(record(b"META", flags::CRITICAL, 0, &meta_payload()));
    b.extend(record(b"ZZZZ", flags::CRITICAL, 0, &meta_payload()));
    cases.insert(
        "invalid-unknown-critical.ptf".into(),
        (b, Some("unknown_critical")),
    );
    let mut b = header(1, 0, 0);
    b.extend(record(
        b"META",
        flags::CRITICAL | (1 << 9),
        0,
        &meta_payload(),
    ));
    cases.insert(
        "invalid-unknown-flag-on-critical.ptf".into(),
        (b, Some("reserved")),
    );
    let mut b = header(1, 0, 0);
    b.extend(record(b"FLOW", 0, 0, &meta_payload()));
    b.extend(record(b"META", flags::CRITICAL, 0, &meta_payload()));
    cases.insert("invalid-meta-not-first.ptf".into(), (b, Some("order")));
    // Non-canonical CBOR head: keys out of order {"z":1,"a":2}.
    let mut payload = vec![7, 0, 0, 0, 0xa2, 0x61, b'z', 1, 0x61, b'a', 2];
    payload.truncate(11);
    let mut b = header(1, 0, 0);
    b.extend(record(b"META", flags::CRITICAL, 0, &payload));
    cases.insert("invalid-cbor-key-order.ptf".into(), (b, Some("cbor")));
    // Column blob with a trailing byte (len one larger than the encoding consumes).
    let t = Table::new("t", 2).with(Column::new("x", Enc::Varint, Values::U64(vec![1, 2])));
    let mut s = Section::new(b"OBSV", 0, Map::new())
        .with_table(t)
        .encode_payload()?;
    // Patch the head's "len": 2 → 3 and append a byte. Re-encode properly through CBOR.
    let hl = u32::from_le_bytes(s[..4].try_into()?) as usize;
    let mut head = pt_format::cbor::decode(&s[4..4 + hl])?;
    if let Some(Value::Array(ts)) = head
        .as_map_mut()
        .and_then(|m| m.get_mut(&Key::from("tables")))
        && let Some(Value::Array(cols)) = ts[0]
            .as_map_mut()
            .and_then(|m| m.get_mut(&Key::from("columns")))
        && let Some(m) = cols[0].as_map_mut()
    {
        m.insert(Key::from("len"), Value::from(3u64));
    }
    let hb = pt_format::cbor::encode(&head)?;
    let mut p = (hb.len() as u32).to_le_bytes().to_vec();
    p.extend(hb);
    p.extend_from_slice(&s[4 + hl..]);
    p.push(0);
    s = p;
    let mut b = header(1, 0, 0);
    b.extend(record(b"META", flags::CRITICAL, 0, &meta_payload()));
    b.extend(record(b"OBSV", 0, 0, &s));
    cases.insert(
        "invalid-column-trailing-byte.ptf".into(),
        (b, Some("column")),
    );
    // Decompression bomb: declares 2^40 bytes.
    let mut bomb = (1u64 << 40).to_le_bytes().to_vec();
    bomb.extend(zstd::bulk::compress(&[0u8; 64], 3)?);
    let mut b = header(1, 0, 0);
    b.extend(record(b"META", flags::CRITICAL, 0, &meta_payload()));
    b.extend(record(b"OBSV", flags::ZSTD, 0, &bomb));
    cases.insert("invalid-decompression-bomb.ptf".into(), (b, Some("limit")));
    // INDX whose file hash does not match.
    let mut f2 = write(&file(vec![meta(Value::map())]), &canon);
    let idx = Section::new(
        b"INDX",
        0,
        Value::map()
            .with("file_blake3", "00".repeat(32))
            .with("content_digest", "00".repeat(32))
            .with("sections", Value::Array(vec![]))
            .as_map()
            .cloned()
            .unwrap_or_default(),
    );
    // Replace the real INDX (last record) with the bad one.
    let (meta_rec, _) = pt_format::container::encode_record(&meta(Value::map()), &canon)?;
    f2.truncate(16 + meta_rec.len());
    f2.extend(record(b"INDX", 0, 0, &idx.encode_payload()?));
    cases.insert("invalid-index-hash.ptf".into(), (f2, Some("schema")));

    // Write files and expected verdicts (computed with the Rust reader for valid digests;
    // invalid kinds are asserted, not computed).
    let mut expected = serde_like::Obj::default();
    for (name, (bytes, kind)) in &cases {
        std::fs::write(dir.join(name), bytes)?;
        let r = pt_format::read(bytes, pt_format::ReadOptions::default());
        match (kind, r) {
            (None, Ok((_, rep))) => expected.push(
                name,
                format!(
                    "{{\"valid\": true, \"content_digest\": \"{}\"}}",
                    rep.content_digest
                ),
            ),
            (Some(k), Err(e)) if e.kind() == *k => {
                expected.push(name, format!("{{\"valid\": false, \"kind\": \"{k}\"}}"))
            }
            (k, r) => anyhow::bail!(
                "corpus case {name}: expected {k:?}, Rust reader gave {:?}",
                r.map(|_| ()).map_err(|e| e.kind())
            ),
        }
    }
    std::fs::write(dir.join("expected.json"), expected.finish())?;
    println!("wrote {} cases to {}", cases.len(), dir.display());
    Ok(())
}

/// Tiny ordered JSON object writer (avoids a serde_json dependency in xtask).
mod serde_like {
    #[derive(Default)]
    pub struct Obj(Vec<(String, String)>);
    impl Obj {
        pub fn push(&mut self, k: &str, raw: String) {
            self.0.push((k.to_string(), raw));
        }
        pub fn finish(self) -> String {
            let body: Vec<String> = self
                .0
                .into_iter()
                .map(|(k, v)| format!("  \"{k}\": {v}"))
                .collect();
            format!("{{\n{}\n}}\n", body.join(",\n"))
        }
    }
}
