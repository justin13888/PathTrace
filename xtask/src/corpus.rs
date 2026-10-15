//! Conformance corpus generator (REQ-FMT-018): `conformance/<version>/*.ptf` + `expected.json`
//! for v1.0, v1.1 and v1.2.
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

/// Corpus cases: file name → (bytes, expected error kind; `None` = valid).
type Cases = BTreeMap<String, (Vec<u8>, Option<&'static str>)>;

/// Writes every release's corpus. Existing directories must come out byte-identical
/// (REQ-FMT-010): a release adds a directory and never changes an earlier one.
pub fn generate(root: &Path) -> Result<()> {
    emit(&root.join("conformance/v1.0"), v1_0()?)?;
    emit(&root.join("conformance/v1.1"), v1_1())?;
    emit(&root.join("conformance/v1.2"), v1_2())?;
    Ok(())
}

/// The PTF 1.0 corpus: every encoding, compression, recovery-relevant and invalid case.
fn v1_0() -> Result<Cases> {
    let mut cases = Cases::new();
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
    Ok(cases)
}

/// Writes a corpus directory: the files and their expected verdicts (computed with the Rust
/// reader for valid digests; invalid kinds are asserted, not computed).
fn emit(dir: &Path, cases: Cases) -> Result<()> {
    std::fs::create_dir_all(dir)?;
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

/// The PTF 1.1 corpus (header minor 1): every 1.1 addition of ptf-format.md's Versions table,
/// with the types, canonical encodings, units and clocks of its Part III.
fn v1_1() -> Cases {
    let canon = WriteOptions::canonical();
    let v11 = |sections| PtfFile {
        major: 1,
        minor: 1,
        sections,
    };
    let mut cases = Cases::new();
    cases.insert(
        "valid-minimal.ptf".into(),
        (write(&v11(vec![meta(Value::map())]), &canon), None),
    );
    cases.insert(
        "valid-1-1-additions.ptf".into(),
        (write(&v11(additions_1_1()), &canon), None),
    );
    cases.insert(
        "valid-1-1-additions-uncompressed-no-index.ptf".into(),
        (
            write(
                &v11(additions_1_1()),
                &WriteOptions {
                    zstd_level: None,
                    compress_threshold: 0,
                    index: false,
                },
            ),
            None,
        ),
    );
    cases
}

/// Nullable u64 column with a unit.
fn nu(name: &str, enc: Enc, unit: &str, rows: &[Option<u64>]) -> Column {
    Column::nullable_u64(name, enc, rows).unit(unit)
}

/// Nullable i64 column with a unit.
fn ni(name: &str, enc: Enc, unit: &str, rows: &[Option<i64>]) -> Column {
    Column {
        name: name.into(),
        data: pt_format::Data::Known {
            enc,
            values: Values::I64(rows.iter().flatten().copied().collect()),
        },
        validity: Some(rows.iter().map(Option::is_some).collect()),
        meta: Map::new(),
    }
    .unit(unit)
}

fn all(n: usize, v: u64) -> Vec<Option<u64>> {
    vec![Some(v); n]
}

/// A small merged trace carrying the PTF 1.1 additions: META `endpoints.<ep>.sockets`, `qdisc`,
/// `txqueuelen`, `session.<ep>.t0_boot` and `merge_checks`; FLOW `max_bytes`; CLOK `pairs.boot`
/// and `exchange.req_nonce`/`resp_nonce`; OBSV `pkt.rxq_drops`, `dup` with `rx_src`, `size` and
/// `rxq_drops`, and `txts_unmatched`; CTXS `netstack` and `qdisc`. Twelve packets a → b, two of
/// them dropped by the receiving socket (its `rxq_drops` rises by 2 across the gap).
fn additions_1_1() -> Vec<Section> {
    let socket = |name: &str, rxq_ovfl: bool, tx_ids: &str| {
        Value::map()
            .with("name", name)
            .with("kernel_rx", true)
            .with("kernel_tx", true)
            .with("recv_buf", 212_992u64)
            .with("send_buf", 212_992u64)
            .with("rxq_ovfl", rxq_ovfl)
            .with("tx_ids", tx_ids)
    };
    let session = |t0: u64| {
        Value::map()
            .with("id", "00112233445566778899aabbccddeeff")
            .with("profile", "smoke")
            .with("t0_mono", t0)
            .with("t0_real", 1_000_000_000_000_000_000u64 + t0)
            .with("t0_boot", t0 + 5_000_000_000)
    };
    let clocks = ["a", "b"].iter().fold(Value::map(), |m, ep| {
        m.with(
            &format!("{ep}.mono"),
            Value::map()
                .with("kind", "monotonic_raw")
                .with("endpoint", *ep),
        )
        .with(
            &format!("{ep}.real"),
            Value::map()
                .with("kind", "realtime")
                .with("endpoint", *ep)
                .with("pii", "quasi"),
        )
    });
    let m = meta(
        Value::map()
            .with(
                "session",
                Value::map()
                    .with("a", session(1_000_000_000))
                    .with("b", session(2_000_000_000)),
            )
            .with(
                "endpoints",
                Value::map()
                    .with(
                        "a",
                        Value::map()
                            .with(
                                "sockets",
                                Value::Array(vec![
                                    socket("main", true, "explicit"),
                                    socket("ctrl", true, "explicit"),
                                ]),
                            )
                            .with(
                                "qdisc",
                                Value::map().with("kind", "fq_codel").with("handle", 0u64),
                            )
                            .with("txqueuelen", 1000u64),
                    )
                    .with(
                        "b",
                        Value::map()
                            .with(
                                "sockets",
                                Value::Array(vec![
                                    socket("main", true, "predicted"),
                                    socket("ctrl", false, "none"),
                                ]),
                            )
                            .with("qdisc", Value::Null)
                            .with("txqueuelen", Value::Null),
                    ),
            )
            .with("clocks", clocks)
            .with(
                "merge_checks",
                Value::map()
                    .with(
                        "a_to_b",
                        Value::map()
                            .with("txts_joined", 12u64)
                            .with("txts_implausible", 0u64),
                    )
                    .with(
                        "b_to_a",
                        Value::map()
                            .with("txts_joined", 0u64)
                            .with("txts_implausible", 0u64),
                    )
                    .with("txts_unmatched_a", 2u64)
                    .with("txts_unmatched_b", 0u64)
                    .with("tx_unstamped_a", 0u64)
                    .with("tx_unstamped_b", 0u64)
                    .with("txts_unexplained_a", 0u64)
                    .with("txts_unexplained_b", 0u64),
            ),
    );

    let flow = Value::map()
        .with("id", 3u64)
        .with("kind", "train")
        .with("sender", "a")
        .with("sock", "main")
        .with("dst_port", 4433u64)
        .with("class", "udp/high-port")
        .with("quic_shape", Value::Null)
        .with("phase", 4u64)
        .with("size", 1200u64)
        .with(
            "pattern",
            Value::map().with("type", "rate").with("bps", 10_000_000u64),
        )
        .with("tos", 0u64)
        .with("duration_ns", 10_000_000u64)
        .with("echo", false)
        .with("echo_delay_ns", 0u64)
        .with("max_bytes", 14_400u64);
    let flows = Section::new(
        b"FLOW",
        0,
        Value::map()
            .with("flows", Value::Array(vec![flow]))
            .as_map()
            .cloned()
            .unwrap_or_default(),
    );

    let ep = |e: &str| Value::map().with("endpoint", e);
    let dir = Value::map().with("dir", "a_to_b");
    let pairs = Table::new("pairs", 3)
        .with(
            Column::new(
                "mono",
                Enc::Delta2,
                Values::U64(vec![1_000_000_000, 1_500_000_000, 2_000_000_000]),
            )
            .unit("ns")
            .clock("a.mono"),
        )
        .with(
            Column::new(
                "real",
                Enc::Delta2,
                Values::U64(vec![
                    1_000_000_001_000_000_000,
                    1_000_000_001_500_000_150,
                    1_000_000_002_000_000_310,
                ]),
            )
            .unit("ns")
            .clock("a.real"),
        )
        .with(Column::new("width", Enc::Varint, Values::U64(vec![41, 38, 44])).unit("ns"))
        .with(nu(
            "boot",
            Enc::Delta2,
            "ns",
            &[Some(6_000_000_020), None, Some(7_000_000_021)],
        ))
        .with_attrs(ep("a"));
    let exchange = Table::new("exchange", 2)
        .with(
            Column::new(
                "t1",
                Enc::Delta2,
                Values::U64(vec![1_100_000_000, 1_600_000_000]),
            )
            .unit("ns")
            .clock("a.mono"),
        )
        .with(
            Column::new(
                "t2",
                Enc::Delta2,
                Values::U64(vec![2_105_000_300, 2_605_000_310]),
            )
            .unit("ns")
            .clock("b.mono"),
        )
        .with(
            Column::new(
                "t3",
                Enc::Delta2,
                Values::U64(vec![2_105_020_300, 2_605_020_290]),
            )
            .unit("ns")
            .clock("b.mono"),
        )
        .with(
            Column::new(
                "t4",
                Enc::Delta2,
                Values::U64(vec![1_110_020_000, 1_610_020_050]),
            )
            .unit("ns")
            .clock("a.mono"),
        )
        .with(nu("req_nonce", Enc::Delta, "id", &[Some(7), Some(8)]))
        .with(nu("resp_nonce", Enc::Delta, "id", &[Some(5), None]))
        .with_attrs(ep("a"));

    // Twelve packets, seq 5 and 6 dropped by the receiving socket (rxq_drops 0 → 2).
    let n = 12usize;
    let lost = |i: usize| i == 5 || i == 6;
    let rx = |i: usize, v: u64| (!lost(i)).then_some(v);
    let tx: Vec<u64> = (0..n as u64).map(|i| 1_200_000_000 + i * 960_000).collect();
    let pkt = Table::new("pkt", n)
        .with(nu("flow", Enc::Rle, "id", &all(n, 3)))
        .with(nu(
            "seq",
            Enc::Delta,
            "count",
            &(0..n as u64).map(Some).collect::<Vec<_>>(),
        ))
        .with(nu("size", Enc::Rle, "B", &all(n, 1228)))
        .with(nu("phase", Enc::Rle, "id", &all(n, 4)))
        .with(nu("train", Enc::Rle, "id", &all(n, 0)))
        .with(nu("train_idx", Enc::Rle, "count", &all(n, 0)))
        .with(nu("tos_tx", Enc::Rle, "tos", &all(n, 0)))
        .with(nu("tx_sock", Enc::Rle, "id", &all(n, 0)))
        .with(
            nu(
                "tx_intended",
                Enc::Delta2,
                "ns",
                &tx.iter().map(|&t| Some(t)).collect::<Vec<_>>(),
            )
            .clock("a.mono"),
        )
        .with(ni(
            "tx_user_lag",
            Enc::Varint,
            "ns",
            &(0..n as i64)
                .map(|i| Some(2_000 + (i * 37) % 500))
                .collect::<Vec<_>>(),
        ))
        .with(
            nu(
                "tx_sched",
                Enc::Delta2,
                "ns",
                &tx.iter()
                    .map(|&t| Some(1_000_000_000_000_000_000 + t + 4_000))
                    .collect::<Vec<_>>(),
            )
            .clock("a.real"),
        )
        .with(ni(
            "tx_snd_lag",
            Enc::Varint,
            "ns",
            &(0..n as i64)
                .map(|i| (i != 9).then_some(11_000 + (i * 53) % 900))
                .collect::<Vec<_>>(),
        ))
        .with(
            nu(
                "rx",
                Enc::Delta2,
                "ns",
                &(0..n)
                    .map(|i| {
                        rx(
                            i,
                            1_000_000_000_000_000_000
                                + tx[i]
                                + 10_000_000
                                + (i as u64 * 7919) % 50_000,
                        )
                    })
                    .collect::<Vec<_>>(),
            )
            .clock("b.real"),
        )
        .with(
            nu(
                "rx_src",
                Enc::Rle,
                "enum",
                &(0..n).map(|i| rx(i, 0)).collect::<Vec<_>>(),
            )
            .with_meta(
                "enum",
                Value::Array(vec![Value::from("kernel"), Value::from("user")]),
            ),
        )
        .with(nu(
            "tos_rx",
            Enc::Rle,
            "tos",
            &(0..n).map(|i| rx(i, 0)).collect::<Vec<_>>(),
        ))
        .with(nu(
            "ttl_rx",
            Enc::Rle,
            "hops",
            &(0..n).map(|i| rx(i, 63)).collect::<Vec<_>>(),
        ))
        .with(nu(
            "src",
            Enc::Rle,
            "id",
            &(0..n).map(|i| rx(i, 0)).collect::<Vec<_>>(),
        ))
        .with(nu(
            "rx_sock",
            Enc::Rle,
            "id",
            &(0..n).map(|i| rx(i, 0)).collect::<Vec<_>>(),
        ))
        .with(nu(
            "rx_size",
            Enc::Rle,
            "B",
            &(0..n).map(|i| rx(i, 1228)).collect::<Vec<_>>(),
        ))
        .with(nu(
            "rxq_drops",
            Enc::Rle,
            "count",
            &(0..n)
                .map(|i| rx(i, if i < 5 { 0 } else { 2 }))
                .collect::<Vec<_>>(),
        ))
        .with_attrs(dir.clone());
    let dup = Table::new("dup", 1)
        .with(nu("flow", Enc::Rle, "id", &[Some(3)]))
        .with(nu("seq", Enc::Delta, "count", &[Some(8)]))
        .with(nu("rx", Enc::Delta2, "ns", &[Some(1_000_000_001_217_690_000)]).clock("b.real"))
        .with(nu("tos_rx", Enc::Rle, "id", &[Some(0)]))
        .with(nu("ttl_rx", Enc::Rle, "id", &[Some(63)]))
        .with(nu("src", Enc::Rle, "id", &[Some(0)]))
        .with(nu("rx_sock", Enc::Rle, "id", &[Some(0)]))
        .with(nu("rx_src", Enc::Rle, "enum", &[Some(1)]).with_meta(
            "enum",
            Value::Array(vec![Value::from("kernel"), Value::from("user")]),
        ))
        .with(nu("size", Enc::Rle, "B", &[Some(1228)]))
        .with(nu("rxq_drops", Enc::Rle, "count", &[None]))
        .with_attrs(dir);
    let txts_unmatched = Table::new("txts_unmatched", 2)
        .with(Column::new("sock", Enc::Rle, Values::U64(vec![1, 1])).unit("id"))
        .with(Column::new("id", Enc::Delta, Values::U64(vec![40, 40])).unit("id"))
        .with(
            Column::new("kind", Enc::Rle, Values::U64(vec![0, 1]))
                .unit("enum")
                .with_meta(
                    "enum",
                    Value::Array(vec![Value::from("sched"), Value::from("snd")]),
                ),
        )
        .with(
            Column::new(
                "real",
                Enc::Delta2,
                Values::U64(vec![1_000_000_001_400_000_000, 1_000_000_001_400_012_000]),
            )
            .unit("ns")
            .clock("a.real"),
        )
        .with_attrs(ep("a"));

    let t = |i: u64| 1_000_000_000 + i * 1_000_000_000;
    let netstack = [
        "udp_in_errors",
        "udp_rcvbuf_errors",
        "udp_sndbuf_errors",
        "udp_in_csum_errors",
        "udp6_in_errors",
        "udp6_rcvbuf_errors",
        "udp6_sndbuf_errors",
        "udp6_in_csum_errors",
        "softnet_dropped",
        "softnet_squeezed",
    ]
    .iter()
    .fold(
        Table::new("netstack", 2).with(
            Column::new("t", Enc::Delta2, Values::U64(vec![t(0), t(1)]))
                .unit("ns")
                .clock("b.mono"),
        ),
        |tb, name| {
            let rows = match *name {
                "udp_in_errors" | "udp_rcvbuf_errors" => [Some(10), Some(12)],
                n if n.starts_with("udp6") => [None, None],
                _ => [Some(0), Some(0)],
            };
            tb.with(nu(name, Enc::Delta, "count", &rows))
        },
    )
    .with_attrs(ep("b"));
    let qdisc = Table::new("qdisc", 2)
        .with(
            Column::new("t", Enc::Delta2, Values::U64(vec![t(0), t(1)]))
                .unit("ns")
                .clock("a.mono"),
        )
        .with(nu(
            "bytes",
            Enc::Delta,
            "B",
            &[Some(1_000_000), Some(1_014_736)],
        ))
        .with(nu("packets", Enc::Delta, "count", &[Some(900), Some(912)]))
        .with(nu("drops", Enc::Delta, "count", &[Some(0), Some(0)]))
        .with(nu("requeues", Enc::Delta, "count", &[Some(0), Some(0)]))
        .with(nu("overlimits", Enc::Delta, "count", &[Some(0), Some(0)]))
        .with(nu("qlen", Enc::Rle, "count", &[Some(0), Some(0)]))
        .with(nu("backlog", Enc::Rle, "B", &[Some(0), None]))
        .with_attrs(ep("a"));

    let s = |kind: &[u8; 4], t: Table| Section::new(kind, 0, Map::new()).with_table(t);
    vec![
        m,
        flows,
        s(b"CLOK", pairs),
        s(b"CLOK", exchange),
        s(b"OBSV", pkt),
        s(b"OBSV", dup),
        s(b"OBSV", txts_unmatched),
        s(b"CTXS", netstack),
        s(b"CTXS", qdisc),
    ]
}

/// The PTF 1.2 corpus (header minor 2): every 1.2 addition of ptf-format.md's Versions table,
/// with the types, canonical encodings, units and clocks of its Part III.
fn v1_2() -> Cases {
    let canon = WriteOptions::canonical();
    let v12 = |sections| PtfFile {
        major: 1,
        minor: 2,
        sections,
    };
    let mut cases = Cases::new();
    cases.insert(
        "valid-minimal.ptf".into(),
        (write(&v12(vec![meta(Value::map())]), &canon), None),
    );
    cases.insert(
        "valid-1-2-additions.ptf".into(),
        (write(&v12(additions_1_2()), &canon), None),
    );
    cases.insert(
        "valid-1-2-additions-uncompressed-no-index.ptf".into(),
        (
            write(
                &v12(additions_1_2()),
                &WriteOptions {
                    zstd_level: None,
                    compress_threshold: 0,
                    index: false,
                },
            ),
            None,
        ),
    );
    cases
}

/// A small merged trace from a macOS initiator (a) reaching a Linux responder (b) through a
/// Tailscale tunnel, carrying the PTF 1.2 additions: META `endpoints.<ep>.os_family`,
/// `os_version`, `iface.tunnel` and `sockets[].icmp_errors`, and `source` on every clock domain;
/// OBSV `tcpinfo_darwin`; CTXS `netstack.udp_fullsock` (macOS rising, Linux null) and `ifstats`
/// with a nullable `tx_dropped`; EVNT `power_assertion` and an `iface_change` whose `iface`
/// carries `tunnel`; PLCY and PATH with `PATH.overlay` and `overlay_limited` on the verdicts
/// it qualifies.
fn additions_1_2() -> Vec<Section> {
    let socket = |linux: bool| {
        Value::map()
            .with("name", "main")
            .with("kernel_rx", true)
            .with("kernel_tx", linux)
            .with("recv_buf", 786_896u64)
            .with("send_buf", 9_216u64)
            .with("rxq_ovfl", linux)
            .with("tx_ids", if linux { "explicit" } else { "none" })
            .with("icmp_errors", linux)
    };
    let tunnel = || {
        Value::map()
            .with("kind", "utun")
            .with("provider", "tailscale")
    };
    let a = Value::map()
        .with("os", "macOS 15.6")
        .with("os_family", "darwin")
        .with("os_version", "15.6")
        .with("kernel", "24.6.0")
        .with("arch", "aarch64")
        .with("cpu", "Apple M2")
        .with(
            "iface",
            Value::map()
                .with("name", "utun4")
                .with("mtu", 1280u64)
                .with("tunnel", tunnel()),
        )
        .with("sockets", Value::Array(vec![socket(false)]));
    let b = Value::map()
        .with("os", "Ubuntu 24.04.1 LTS")
        .with("os_family", "linux")
        .with("os_version", "24.04")
        .with("kernel", "6.8.0-45-generic")
        .with("arch", "x86_64")
        .with("clocksource", "tsc")
        .with(
            "iface",
            Value::map().with("name", "eth0").with("mtu", 1500u64),
        )
        .with("sockets", Value::Array(vec![socket(true)]));
    let clocks = [("a", "mach_absolute_time"), ("b", "CLOCK_MONOTONIC_RAW")]
        .iter()
        .fold(Value::map(), |m, (ep, mono)| {
            m.with(
                &format!("{ep}.mono"),
                Value::map()
                    .with("kind", "monotonic_raw")
                    .with("endpoint", *ep)
                    .with("source", *mono),
            )
            .with(
                &format!("{ep}.real"),
                Value::map()
                    .with("kind", "realtime")
                    .with("endpoint", *ep)
                    .with("pii", "quasi")
                    .with("source", "CLOCK_REALTIME"),
            )
        });
    let m = meta(
        Value::map()
            .with("endpoints", Value::map().with("a", a).with("b", b))
            .with("clocks", clocks),
    );

    let ep = |e: &str| Value::map().with("endpoint", e);
    let t = |i: u64| 1_000_000_000 + i * 10_000_000;

    // tcpinfo_darwin: three samples of a reference TCP flow, every struct field filled.
    let n = 3usize;
    let fields: [(&str, &str, [u64; 3]); 23] = [
        ("state", "enum", [4, 4, 4]),
        ("snd_wscale", "raw", [6, 6, 6]),
        ("rcv_wscale", "raw", [7, 7, 7]),
        ("options", "bitmask", [0x7, 0x7, 0x7]),
        ("flags", "bitmask", [0x0, 0x0, 0x0]),
        ("rto", "ms", [230, 228, 226]),
        ("maxseg", "B", [1228, 1228, 1228]),
        ("snd_ssthresh", "B", [1_073_725_440, 1_073_725_440, 98_240]),
        ("snd_cwnd", "B", [14_736, 29_472, 49_120]),
        ("snd_wnd", "B", [131_712, 262_144, 262_144]),
        ("snd_sbbytes", "B", [0, 24_560, 49_120]),
        ("rcv_wnd", "B", [131_072, 131_072, 131_072]),
        ("rttcur", "ms", [31, 30, 33]),
        ("srtt", "ms", [31, 31, 32]),
        ("rttvar", "raw", [15, 12, 11]),
        ("tfo", "raw", [0, 0, 0]),
        ("txpackets", "count", [3, 25, 61]),
        ("txbytes", "B", [517, 27_533, 71_741]),
        ("txretransmitbytes", "B", [0, 0, 1_228]),
        ("rxpackets", "count", [3, 14, 30]),
        ("rxbytes", "B", [4_310, 4_310, 4_310]),
        ("rxoutoforderbytes", "B", [0, 0, 0]),
        ("txretransmitpackets", "count", [0, 0, 1]),
    ];
    let tcpinfo_darwin = fields
        .iter()
        .fold(
            Table::new("tcpinfo_darwin", n)
                .with(nu("flow", Enc::Rle, "id", &all(n, 20)))
                .with(
                    nu(
                        "t",
                        Enc::Delta2,
                        "ns",
                        &[Some(t(0)), Some(t(1)), Some(t(2))],
                    )
                    .clock("a.mono"),
                )
                .with(nu("optlen", Enc::Rle, "B", &all(n, 112))),
            |tb, (name, unit, v)| tb.with(nu(name, Enc::Delta, unit, &v.map(Some))),
        )
        .with_attrs(ep("a"));

    // netstack: the Linux counters null and udp_fullsock rising on macOS (a); the reverse on
    // Linux (b).
    let linux_cols = [
        "udp_in_errors",
        "udp_rcvbuf_errors",
        "udp_sndbuf_errors",
        "udp_in_csum_errors",
        "udp6_in_errors",
        "udp6_rcvbuf_errors",
        "udp6_sndbuf_errors",
        "udp6_in_csum_errors",
        "softnet_dropped",
        "softnet_squeezed",
    ];
    let netstack = |e: &str, linux: bool| {
        let s = |i: u64| 1_000_000_000 + i * 1_000_000_000;
        linux_cols
            .iter()
            .fold(
                Table::new("netstack", 2).with(
                    Column::new("t", Enc::Delta2, Values::U64(vec![s(0), s(1)]))
                        .unit("ns")
                        .clock(&format!("{e}.mono")),
                ),
                |tb, name| {
                    let rows = if linux {
                        [Some(4), Some(4)]
                    } else {
                        [None, None]
                    };
                    tb.with(nu(name, Enc::Delta, "count", &rows))
                },
            )
            .with(nu(
                "udp_fullsock",
                Enc::Delta,
                "count",
                &if linux {
                    [None, None]
                } else {
                    [Some(17), Some(19)]
                },
            ))
            .with_attrs(ep(e))
    };
    let ifstats = Table::new("ifstats", 2)
        .with(
            Column::new("t", Enc::Delta2, Values::U64(vec![t(0), t(100)]))
                .unit("ns")
                .clock("a.mono"),
        )
        .with(
            Column::new(
                "rx_bytes",
                Enc::Delta,
                Values::U64(vec![9_000_000, 9_412_000]),
            )
            .unit("B"),
        )
        .with(
            Column::new(
                "tx_bytes",
                Enc::Delta,
                Values::U64(vec![3_000_000, 4_228_000]),
            )
            .unit("B"),
        )
        .with(Column::new("rx_packets", Enc::Delta, Values::U64(vec![9_100, 9_480])).unit("count"))
        .with(Column::new("tx_packets", Enc::Delta, Values::U64(vec![4_200, 5_200])).unit("count"))
        .with(Column::new("rx_dropped", Enc::Delta, Values::U64(vec![0, 0])).unit("count"))
        .with(nu("tx_dropped", Enc::Delta, "count", &[None, None]))
        .with(Column::new("rx_errors", Enc::Delta, Values::U64(vec![0, 0])).unit("count"))
        .with(Column::new("tx_errors", Enc::Delta, Values::U64(vec![0, 0])).unit("count"))
        .with_attrs(ep("a"));

    let event = |t: u64, kind: &str, detail: Value| {
        Value::map()
            .with("t", t)
            .with("clock", "a.mono")
            .with("endpoint", "a")
            .with("type", kind)
            .with("detail", detail)
    };
    let events = Section::new(
        b"EVNT",
        0,
        Value::map()
            .with(
                "events",
                Value::Array(vec![
                    event(
                        t(0),
                        "power_assertion",
                        Value::map().with("held", true).with("error", Value::Null),
                    ),
                    event(
                        t(50),
                        "iface_change",
                        Value::map().with(
                            "iface",
                            Value::map().with("mtu", 1280u64).with("tunnel", tunnel()),
                        ),
                    ),
                ]),
            )
            .as_map()
            .cloned()
            .unwrap_or_default(),
    );

    // Derived: PLCY and PATH qualified by the overlay (probe.md §9.9).
    let plcy = Section::new(
        b"PLCY",
        flags::DERIVED,
        Value::map()
            .with("method", "policy.matrix/2")
            .with(
                "classes",
                Value::map().with(
                    "udp/high-port",
                    Value::map()
                        .with("transport", "udp")
                        .with("reachable", true)
                        .with("overlay_limited", true),
                ),
            )
            .as_map()
            .cloned()
            .unwrap_or_default(),
    );
    let qualified = |status: &str, method: &str| {
        Value::map()
            .with("status", status)
            .with("method", method)
            .with("overlay_limited", true)
    };
    let direction = || {
        Value::map()
            .with(
                "policer",
                qualified("unknown", "policer.lossy-flat/2").with("reason", "no saturation"),
            )
            .with(
                "mtu",
                qualified("known", "mtu.ladder/2")
                    .with("path_mtu", 1280u64)
                    .with("blackhole", Value::Null),
            )
            .with("ecn", qualified("known", "tos.light-cycle/1"))
            .with("dscp", qualified("known", "tos.light-cycle/1"))
    };
    let path = Section::new(
        b"PATH",
        flags::CRITICAL | flags::DERIVED,
        Value::map()
            .with(
                "derivation",
                Value::map().with(
                    "methods",
                    Value::Array(vec![
                        Value::from("mtu.ladder/2"),
                        Value::from("overlay.egress-iface/1"),
                        Value::from("policer.lossy-flat/2"),
                        Value::from("policy.matrix/2"),
                        Value::from("tos.light-cycle/1"),
                    ]),
                ),
            )
            .with(
                "directions",
                Value::map()
                    .with("a_to_b", direction())
                    .with("b_to_a", direction()),
            )
            .with(
                "overlay",
                Value::map()
                    .with("status", "known")
                    .with("method", "overlay.egress-iface/1")
                    .with(
                        "source",
                        Value::Array(vec![Value::from("META"), Value::from("EVNT")]),
                    )
                    .with("overlay", true)
                    .with("endpoints", Value::Array(vec![Value::from("a")]))
                    .with("kind", "utun")
                    .with("provider", "tailscale")
                    .with("mtu", 1280u64)
                    .with("overlay_ns", 1_000_000_000u64),
            )
            .as_map()
            .cloned()
            .unwrap_or_default(),
    );

    let s = |kind: &[u8; 4], t: Table| Section::new(kind, 0, Map::new()).with_table(t);
    vec![
        m,
        s(b"OBSV", tcpinfo_darwin),
        s(b"CTXS", ifstats),
        s(b"CTXS", netstack("a", false)),
        s(b"CTXS", netstack("b", true)),
        events,
        plcy,
        path,
    ]
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
