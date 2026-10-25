//! What `merge` keeps of a .ptflog pair (ptf-format.md, "What `merge` keeps"): every logged
//! row, columns and tables it does not know, column metadata, and sections it cannot interpret.

use std::path::{Path, PathBuf};

use pt_format::{
    Column, Enc, Map, PtfFile, Section, Table, Value, Values, WriteOptions, container, flags,
};
use pt_probe::merge::merge_file;
use pt_probe::session::ToolInfo;

fn tool() -> ToolInfo {
    ToolInfo {
        version: "test".into(),
        git_commit: "0".into(),
        git_dirty: false,
    }
}

fn u64s(name: &str, enc: Enc, v: &[u64]) -> Column {
    Column::new(name, enc, Values::U64(v.to_vec()))
}

fn table(name: &str, role: &str, cols: Vec<Column>) -> Table {
    let rows = cols.first().and_then(Column::values).map_or(0, Values::len);
    let mut t = Table::new(name, rows).with_attrs(Value::map().with("endpoint", role));
    t.columns = cols;
    t
}

fn obsv(t: Table) -> Section {
    Section::new(b"OBSV", 0, Map::new()).with_table(t)
}

fn meta(role: &str) -> Section {
    let head = Value::map()
        .with("kind", "obslog")
        .with("role", role)
        .with("trace_id", "t");
    Section::new(b"META", flags::CRITICAL, head.as_map().cloned().unwrap())
}

fn flows(role: &str, ids: &[u64]) -> Section {
    let fl: Vec<Value> = ids
        .iter()
        .map(|&id| Value::map().with("id", id).with("sender", role))
        .collect();
    Section::new(
        b"FLOW",
        0,
        Value::map()
            .with("flows", Value::Array(fl))
            .as_map()
            .cloned()
            .unwrap(),
    )
}

fn write(dir: &Path, name: &str, sections: Vec<Section>) -> PathBuf {
    let p = dir.join(name);
    let f = PtfFile {
        major: container::MAJOR,
        minor: container::MINOR,
        sections,
    };
    let mut out = std::fs::File::create(&p).unwrap();
    pt_format::write(&f, &WriteOptions::canonical(), &mut out).unwrap();
    p
}

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Tables named `name` with attrs `key` = `val`, in file order.
fn tables<'a>(f: &'a PtfFile, name: &str, key: &str, val: &str) -> Vec<&'a Table> {
    f.sections
        .iter()
        .flat_map(Section::tables)
        .filter(|t| {
            t.name == name
                && t.attrs().and_then(|a| a.get(key)).and_then(Value::as_str) == Some(val)
        })
        .collect()
}

fn rows(t: &Table, col: &str) -> Vec<Option<u64>> {
    t.columns
        .iter()
        .find(|c| c.name == col)
        .unwrap_or_else(|| panic!("{}: no column {col}", t.name))
        .u64_rows()
        .unwrap()
}

/// The initiator sends flow 1, seq 0..3 on socket 0 with OPT_IDs 10..13. Its `tx` carries a
/// column merge does not know (`future_tx`) and a `desc` on `size`; the responder's `rx`
/// carries `future_rx` and receives seq 1 twice.
fn pair(dir: &Path) -> (PathBuf, PathBuf) {
    let tx = table(
        "tx",
        "a",
        vec![
            u64s("sock", Enc::Rle, &[0; 4]),
            u64s("flow", Enc::Rle, &[1; 4]),
            u64s("seq", Enc::Delta, &[0, 1, 2, 3]),
            u64s("size", Enc::Rle, &[100; 4])
                .unit("B")
                .with_meta("desc", "IP bytes"),
            u64s("id", Enc::Delta, &[10, 11, 12, 13]),
            u64s("future_tx", Enc::Rle, &[7, 8, 9, 6]).unit("count"),
        ],
    );
    // SCHED for 10, 11, 12; SND for 10 (joined), 13 (no SCHED); a kind merge does not know
    // (2) for 11.
    let txts = table(
        "txts",
        "a",
        vec![
            u64s("sock", Enc::Rle, &[0; 6]),
            u64s("id", Enc::Delta, &[10, 10, 11, 12, 13, 11]),
            u64s("kind", Enc::Rle, &[0, 1, 0, 0, 1, 2]),
            u64s("real", Enc::Delta2, &[1000, 1005, 2000, 3000, 4005, 2010]).clock("a.real"),
        ],
    );
    // A table merge does not know, logged in CTXS; one with a float column; a section with a
    // head merge does not interpret.
    let ctx = Section::new(b"CTXS", 0, Map::new()).with_table(table(
        "future_ctx",
        "a",
        vec![u64s("t", Enc::Delta2, &[1, 2])],
    ));
    let float = obsv(table(
        "future_float",
        "a",
        vec![Column::new("x", Enc::Plain, Values::F64(vec![0.5, 1.5]))],
    ));
    let headed = Section::new(
        b"OBSV",
        0,
        Value::map().with("note", "kept").as_map().cloned().unwrap(),
    )
    .with_table(table("headed", "a", vec![u64s("v", Enc::Rle, &[3])]));
    let a = write(
        dir,
        "a.ptflog",
        vec![
            meta("a"),
            flows("a", &[1]),
            obsv(tx),
            obsv(txts),
            ctx,
            float,
            headed,
        ],
    );
    let rx = table(
        "rx",
        "b",
        vec![
            u64s("sock", Enc::Rle, &[0; 4]),
            u64s("flow", Enc::Rle, &[1, 1, 1, 9]),
            u64s("seq", Enc::Delta, &[0, 1, 1, 0]),
            u64s("size", Enc::Rle, &[100; 4]),
            u64s("rx", Enc::Delta2, &[5000, 6000, 6100, 7000]).clock("b.real"),
            u64s("future_rx", Enc::Rle, &[1, 2, 3, 4]),
        ],
    );
    let b = write(dir, "b.ptflog", vec![meta("b"), obsv(rx)]);
    (a, b)
}

#[test]
fn merge_keeps_every_stamp_column_and_section() {
    let dir = scratch("merge_keeps_every_stamp_column_and_section");
    let (a, b) = pair(&dir);
    let (f, report) = merge_file(&a, Some(&b), &tool()).unwrap();

    let pkt = tables(&f, "pkt", "dir", "a_to_b");
    assert_eq!(pkt.len(), 1);
    let pkt = pkt[0];
    assert_eq!(
        rows(pkt, "tx_sched"),
        vec![Some(1000), Some(2000), Some(3000), None]
    );
    // Columns merge does not know are carried, from the first arrival for `rx`.
    assert_eq!(
        rows(pkt, "tx.future_tx"),
        vec![Some(7), Some(8), Some(9), Some(6)]
    );
    assert_eq!(
        rows(pkt, "rx.future_rx"),
        vec![Some(1), Some(2), None, None]
    );
    let size = pkt.columns.iter().find(|c| c.name == "size").unwrap();
    assert_eq!(
        size.meta.get(&"desc".into()).and_then(Value::as_str),
        Some("IP bytes")
    );
    let fut = pkt
        .columns
        .iter()
        .find(|c| c.name == "tx.future_tx")
        .unwrap();
    assert_eq!(
        fut.meta.get(&"unit".into()).and_then(Value::as_str),
        Some("count")
    );
    let dup = tables(&f, "dup", "dir", "a_to_b");
    assert_eq!(rows(dup[0], "rx"), vec![Some(6100)]);
    assert_eq!(rows(dup[0], "rx.future_rx"), vec![Some(3)]);
    // Flow 9 has no transmission; `unmatched` keeps every `rx` column.
    let un = tables(&f, "unmatched", "dir", "a_to_b");
    assert_eq!(rows(un[0], "future_rx"), vec![Some(4)]);

    // `pkt` holds SCHED 10, 11, 12 and SND 10; the SND of 13 (no SCHED) and kind 2 stay.
    let orphans = tables(&f, "txts_unmatched", "endpoint", "a");
    assert_eq!(rows(orphans[0], "id"), vec![Some(13), Some(11)]);
    assert_eq!(rows(orphans[0], "kind"), vec![Some(1), Some(2)]);
    assert_eq!(report.txts_unmatched["a"], 2);

    // A table merge does not know stays in the section kind it was logged in.
    let ctx = f
        .sections
        .iter()
        .find(|s| s.tables().iter().any(|t| t.name == "future_ctx"))
        .unwrap();
    assert_eq!(&ctx.kind, b"CTXS");
    // A float column survives, and so does a section head merge does not interpret.
    let float = tables(&f, "future_float", "endpoint", "a");
    assert_eq!(float.len(), 1);
    assert!(matches!(
        float[0].columns[0].values(),
        Some(Values::F64(v)) if v == &vec![0.5, 1.5]
    ));
    let headed = f
        .sections
        .iter()
        .find(|s| s.tables().iter().any(|t| t.name == "headed"))
        .unwrap();
    assert_eq!(
        headed.get("note").and_then(Value::as_str),
        Some("kept"),
        "the head of a section merge does not interpret is kept"
    );
}

fn meta_redacted(role: &str, redaction: &str) -> Section {
    let mut s = meta(role);
    s.head_mut()
        .unwrap()
        .insert("redaction".into(), Value::from(redaction));
    s
}

fn col_meta<'a>(t: &'a Table, col: &str, key: &str) -> Option<&'a str> {
    t.columns
        .iter()
        .find(|c| c.name == col)
        .unwrap_or_else(|| panic!("{}: no column {col}", t.name))
        .meta_str(key)
}

/// Stamps with a null key field or a value in a `txts` column merge does not know stay in
/// `txts_unmatched`; `dup` columns keep their `rx` column's metadata; the trace's
/// `redaction` follows the logs'.
#[test]
fn merge_keeps_null_and_unknown_stamps_and_dup_metadata() {
    let dir = scratch("merge_keeps_null_and_unknown_stamps_and_dup_metadata");
    let tx = table(
        "tx",
        "a",
        vec![
            u64s("sock", Enc::Rle, &[0; 2]),
            u64s("flow", Enc::Rle, &[1; 2]),
            u64s("seq", Enc::Delta, &[0, 1]),
            u64s("size", Enc::Rle, &[100; 2]),
            u64s("id", Enc::Delta, &[10, 11]),
        ],
    );
    // 0: SCHED 10, joined. 1: SCHED 11, joined, but with a value in `future_ts`.
    // 2: null kind. 3: SND 10 with a null real.
    let txts = table(
        "txts",
        "a",
        vec![
            u64s("sock", Enc::Rle, &[0; 4]),
            u64s("id", Enc::Delta, &[10, 11, 10, 10]),
            Column::nullable_u64("kind", Enc::Rle, &[Some(0), Some(0), None, Some(1)]),
            Column::nullable_u64(
                "real",
                Enc::Delta2,
                &[Some(1000), Some(2000), Some(1100), None],
            )
            .clock("a.real"),
            Column::nullable_u64("future_ts", Enc::Rle, &[None, Some(5), None, None]),
        ],
    );
    let a = write(
        &dir,
        "a.ptflog",
        vec![
            meta_redacted("a", "shareable"),
            flows("a", &[1]),
            obsv(tx),
            obsv(txts),
        ],
    );
    // Seq 0 arrives twice; `sock`, `rx` and `size` carry metadata of their own.
    let rx = table(
        "rx",
        "b",
        vec![
            u64s("sock", Enc::Rle, &[0; 3]).with_meta("desc", "receiving socket"),
            u64s("flow", Enc::Rle, &[1; 3]),
            u64s("seq", Enc::Delta, &[0, 0, 1]),
            u64s("size", Enc::Rle, &[100; 3]).with_meta("desc", "IP bytes"),
            u64s("rx", Enc::Delta2, &[5000, 5100, 6000])
                .clock("b.real")
                .with_meta("desc", "arrival"),
        ],
    );
    let b = write(
        &dir,
        "b.ptflog",
        vec![meta_redacted("b", "shareable"), obsv(rx)],
    );
    let (f, report) = merge_file(&a, Some(&b), &tool()).unwrap();

    let pkt = tables(&f, "pkt", "dir", "a_to_b")[0];
    assert_eq!(rows(pkt, "tx_sched"), vec![Some(1000), Some(2000)]);
    let orphans = tables(&f, "txts_unmatched", "endpoint", "a")[0];
    assert_eq!(rows(orphans, "id"), vec![Some(11), Some(10), Some(10)]);
    assert_eq!(rows(orphans, "kind"), vec![Some(0), None, Some(1)]);
    assert_eq!(rows(orphans, "real"), vec![Some(2000), Some(1100), None]);
    assert_eq!(rows(orphans, "future_ts"), vec![Some(5), None, None]);
    assert_eq!(report.txts_unmatched["a"], 3);

    // `dup` columns inherit from `rx`, `rx_sock` from `sock`; merge's own `clock` wins.
    let dup = tables(&f, "dup", "dir", "a_to_b")[0];
    assert_eq!(rows(dup, "rx"), vec![Some(5100)]);
    assert_eq!(col_meta(dup, "rx_sock", "desc"), Some("receiving socket"));
    assert_eq!(col_meta(dup, "size", "desc"), Some("IP bytes"));
    assert_eq!(col_meta(dup, "rx", "desc"), Some("arrival"));
    assert_eq!(col_meta(dup, "rx", "unit"), Some("ns"));

    let level = |f: &PtfFile| {
        f.sections
            .iter()
            .find(|s| &s.kind == b"META")
            .and_then(|s| s.get("redaction"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    assert_eq!(level(&f).as_deref(), Some("shareable"));
    // Logs that record different levels give `full`.
    let b_full = write(&dir, "b_full.ptflog", vec![meta_redacted("b", "full")]);
    let (f, _) = merge_file(&a, Some(&b_full), &tool()).unwrap();
    assert_eq!(level(&f).as_deref(), Some("full"));
}

#[test]
fn an_initiator_log_alone_keeps_the_responder_s_arrivals() {
    let dir = scratch("an_initiator_log_alone_keeps_the_responder_s_arrivals");
    // The initiator received flow 2 (the responder's) and has no responder log to join it to.
    let rx = table(
        "rx",
        "a",
        vec![
            u64s("sock", Enc::Rle, &[0; 2]),
            u64s("flow", Enc::Rle, &[2, 2]),
            u64s("seq", Enc::Delta, &[0, 1]),
            u64s("size", Enc::Rle, &[100; 2]),
            u64s("rx", Enc::Delta2, &[5000, 6000]).clock("a.real"),
        ],
    );
    let a = write(
        &dir,
        "a.ptflog",
        vec![meta("a"), flows("a", &[1]), obsv(rx)],
    );
    let (f, report) = merge_file(&a, None, &tool()).unwrap();
    let un = tables(&f, "unmatched", "dir", "b_to_a");
    assert_eq!(un.len(), 1);
    assert_eq!(rows(un[0], "seq"), vec![Some(0), Some(1)]);
    // No direction is reported for a sender whose log is absent.
    assert!(!report.pkt_rows.contains_key("b_to_a"));
    assert!(!report.stamps.contains_key("b_to_a"));
}
