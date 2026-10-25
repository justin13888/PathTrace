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
/// `redaction` follows the logs' (common level, `full` when they differ or one records none,
/// the initiator's own level when merged alone).
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
    // A responder log that records no level gives `full`.
    let b_none = write(&dir, "b_none.ptflog", vec![meta("b")]);
    let (f, _) = merge_file(&a, Some(&b_none), &tool()).unwrap();
    assert_eq!(level(&f).as_deref(), Some("full"));
    // The initiator's log alone gives its own level.
    let (f, _) = merge_file(&a, None, &tool()).unwrap();
    assert_eq!(level(&f).as_deref(), Some("shareable"));
}

const MS: u64 = 1_000_000;
const US: u64 = 1_000;
/// REALTIME = MONO_RAW + R on the initiator.
const R: u64 = 1_000_000_000;

/// A full log META head, as pathtrace writes one, with a key merge does not know.
fn full_meta(role: &str, trace_id: &str, utc: &str, label: &str, clocks: Value) -> Section {
    let head = Value::map()
        .with("kind", "obslog")
        .with("role", role)
        .with("trace_id", trace_id)
        .with("created_utc", utc)
        .with(
            "tool",
            Value::map().with("name", "pathtrace").with("version", role),
        )
        .with(
            "session",
            Value::map().with("id", 7u64).with("profile", "quick"),
        )
        .with(
            "endpoint",
            Value::map().with("peer_addr", format!("peer-of-{role}")),
        )
        .with("extra", Value::map().with("note", role))
        .with(
            "network",
            Value::map().with("class", "home").with("label", label),
        )
        .with("clocks", clocks)
        .with("redaction", "full")
        .with("future_key", Value::map().with("from", role))
        .with(
            "pii",
            Value::map()
                .with("/network/label", "id")
                .with("/endpoint/peer_addr", "id"),
        );
    Section::new(b"META", flags::CRITICAL, head.as_map().cloned().unwrap())
}

fn clock(kind: &str, ep: &str) -> Value {
    Value::map().with("kind", kind).with("endpoint", ep)
}

fn head_section(kind: &[u8; 4], head: Value) -> Section {
    Section::new(kind, 0, head.as_map().cloned().unwrap())
}

/// The values of every row of `t`'s columns `cols` (null where `t` lacks one).
fn row_values(t: &Table, cols: &[&str]) -> Vec<Vec<Option<i64>>> {
    let rows = |name: &str| -> Vec<Option<i64>> {
        match t.columns.iter().find(|c| c.name == name) {
            Some(c) => c
                .u64_rows()
                .map(|v| v.into_iter().map(|x| x.map(|x| x as i64)).collect())
                .or_else(|| c.i64_rows())
                .unwrap(),
            None => vec![None; t.rows],
        }
    };
    let by_col: Vec<Vec<Option<i64>>> = cols.iter().map(|c| rows(c)).collect();
    (0..t.rows)
        .map(|i| by_col.iter().map(|c| c[i]).collect())
        .collect()
}

/// The logged rows of table `name` in a log file, over its own columns, sorted.
fn logged(f: &PtfFile, name: &str) -> (Vec<String>, Vec<Vec<Option<i64>>>) {
    let t = f
        .sections
        .iter()
        .flat_map(Section::tables)
        .find(|t| t.name == name)
        .unwrap();
    let cols: Vec<String> = t.columns.iter().map(|c| c.name.clone()).collect();
    let names: Vec<&str> = cols.iter().map(String::as_str).collect();
    let mut rows = row_values(t, &names);
    rows.sort();
    (cols, rows)
}

/// `t`'s rows over the logged columns `cols`, each read from the trace column `rename(col)`.
fn rebuilt(t: &Table, cols: &[String], rename: impl Fn(&str) -> String) -> Vec<Vec<Option<i64>>> {
    let names: Vec<String> = cols.iter().map(|c| rename(c)).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    row_values(t, &names)
}

/// The initiator sends flow 1, seq 0..6, one datagram per call 1 ms apart on a `predicted`
/// socket; the call of seq 3 fails and is recorded as burning id 3, which the kernel did not
/// consume, so `merge` re-anchors the last three ids by −1 (probe.md §4.1). The responder
/// receives seq 1 twice and an arrival of a flow nobody sent, sends flow 2 to the initiator,
/// and receives one of its own probes back (an echo). Both logs define flow 1, declare a clock
/// domain `x`, and carry FLOW and EVNT head keys and META keys merge does not know.
fn lossless_pair(dir: &Path) -> (PathBuf, PathBuf) {
    let user = |c: u64| 10 * MS + c * MS;
    let calls = [0u64, 1, 2, 4, 5, 6];
    let tx = table(
        "tx",
        "a",
        vec![
            u64s("sock", Enc::Rle, &[0; 6]),
            u64s("flow", Enc::Rle, &[1; 6]),
            u64s("seq", Enc::Delta, &[0, 1, 2, 3, 4, 5]),
            u64s("size", Enc::Rle, &[100; 6]),
            u64s("id", Enc::Delta, &[0, 1, 2, 4, 5, 6]),
            u64s("tx_intended", Enc::Delta2, &calls.map(user)).clock("a.mono"),
            Column::new("tx_user_lag", Enc::Varint, Values::I64(vec![0; 6])),
            u64s("future_tx", Enc::Rle, &[1, 2, 3, 4, 5, 6]),
        ],
    );
    // SCHED for kernel ids 0..6, 5 µs into each call; SND for id 1; a repeat of id 0's SCHED;
    // an SND of id 2 carrying a value in a column merge does not know.
    let stamp = |c: u64| user(c) + R + 5 * US;
    let mut ids: Vec<u64> = (0..6).collect();
    let mut kinds = vec![0u64; 6];
    let mut real: Vec<u64> = calls.map(stamp).to_vec();
    ids.extend([1, 0, 2]);
    kinds.extend([1, 0, 1]);
    real.extend([stamp(1) + 2 * US, stamp(0) + US, stamp(2) + 3 * US]);
    let mut future = vec![None; 8];
    future.push(Some(9));
    let txts = table(
        "txts",
        "a",
        vec![
            u64s("sock", Enc::Rle, &[0; 9]),
            u64s("id", Enc::Delta, &ids),
            u64s("kind", Enc::Rle, &kinds),
            u64s("real", Enc::Delta2, &real).clock("a.real"),
            Column::nullable_u64("future_ts", Enc::Rle, &future),
        ],
    );
    let pairs = Section::new(b"CLOK", 0, Map::new()).with_table(table(
        "pairs",
        "a",
        vec![
            u64s("mono", Enc::Delta2, &[0, 10_000 * MS]).clock("a.mono"),
            u64s("real", Enc::Delta2, &[R, 10_000 * MS + R]).clock("a.real"),
        ],
    ));
    let a_rx = table(
        "rx",
        "a",
        vec![
            u64s("sock", Enc::Rle, &[0; 2]),
            u64s("flow", Enc::Rle, &[2, 2]),
            u64s("seq", Enc::Delta, &[0, 1]),
            u64s("size", Enc::Rle, &[200; 2]),
            u64s("rx", Enc::Delta2, &[9000, 9100]).clock("a.real"),
        ],
    );
    let failure = Value::map()
        .with("t", user(3) + 10 * US)
        .with("clock", "a.mono")
        .with("endpoint", "a")
        .with("type", "send_partial")
        .with(
            "detail",
            Value::map()
                .with("sock", 0u64)
                .with("burned_id", 3u64)
                .with("tx_ids", "predicted"),
        );
    let a_flows = head_section(
        b"FLOW",
        Value::map()
            .with(
                "flows",
                Value::Array(vec![
                    Value::map()
                        .with("id", 1u64)
                        .with("sender", "a")
                        .with("by", "a"),
                ]),
            )
            .with("future_flow_key", "a"),
    );
    let a = write(
        dir,
        "a.ptflog",
        vec![
            full_meta(
                "a",
                "trace-a",
                "2026-01-01T00:00:00Z",
                "home-a",
                Value::map()
                    .with("a.mono", clock("monotonic_raw", "a"))
                    .with("a.real", clock("realtime", "a"))
                    .with("x", clock("tai", "a")),
            ),
            a_flows,
            obsv(tx),
            obsv(txts),
            obsv(a_rx),
            pairs,
            head_section(
                b"EVNT",
                Value::map().with("events", Value::Array(vec![failure])),
            ),
        ],
    );

    let b_tx = table(
        "tx",
        "b",
        vec![
            u64s("sock", Enc::Rle, &[0; 2]),
            u64s("flow", Enc::Rle, &[2, 2]),
            u64s("seq", Enc::Delta, &[0, 1]),
            u64s("size", Enc::Rle, &[200; 2]),
            u64s("id", Enc::Delta, &[0, 1]),
        ],
    );
    // Seq 1 twice, flow 9 (sent by nobody), flow 3 (b's own probe, echoed back).
    let b_rx = table(
        "rx",
        "b",
        vec![
            u64s("sock", Enc::Rle, &[0; 9]),
            u64s("flow", Enc::Rle, &[1, 1, 1, 1, 1, 1, 1, 9, 3]),
            u64s("seq", Enc::Delta, &[0, 1, 1, 2, 3, 4, 5, 0, 0]),
            u64s("size", Enc::Rle, &[100; 9]),
            u64s(
                "rx",
                Enc::Delta2,
                &[100, 200, 210, 300, 400, 500, 600, 700, 800],
            )
            .clock("b.real"),
            Column::nullable_u64("rx_src", Enc::Rle, &[Some(0); 9]),
            u64s("future_rx", Enc::Rle, &[1, 2, 3, 4, 5, 6, 7, 8, 9]),
        ],
    );
    let wrapped = Value::map().with("value", "10.0.0.1").with("pii", "id");
    let b_events = head_section(
        b"EVNT",
        Value::map()
            .with(
                "events",
                Value::Array(vec![
                    Value::map()
                        .with("t", 1u64)
                        .with("clock", "b.mono")
                        .with("endpoint", "b")
                        .with("type", "peer_addr")
                        .with("detail", Value::map().with("addr", wrapped)),
                ]),
            )
            .with("future_event_key", Value::map().with("who", "secret-b"))
            .with(
                "pii",
                Value::map()
                    .with("/events/0/detail/addr/value", "id")
                    .with("/future_event_key/who", "id"),
            ),
    );
    let b_flows = head_section(
        b"FLOW",
        Value::map()
            .with(
                "flows",
                Value::Array(vec![
                    Value::map()
                        .with("id", 1u64)
                        .with("sender", "a")
                        .with("by", "b"),
                    Value::map().with("id", 2u64).with("sender", "b"),
                    Value::map().with("id", 3u64).with("sender", "b"),
                ]),
            )
            .with(
                "pii",
                Value::map()
                    .with("/flows/0/by", "quasi")
                    .with("/flows/2/sender", "quasi")
                    .with("/flows/7/sender", "quasi"),
            ),
    );
    let b = write(
        dir,
        "b.ptflog",
        vec![
            full_meta(
                "b",
                "trace-b",
                "2026-01-01T00:00:01Z",
                "office-b",
                Value::map()
                    .with("b.mono", clock("monotonic_raw", "b"))
                    .with("b.real", clock("realtime", "b"))
                    .with("x", clock("tai", "b")),
            ),
            b_flows,
            obsv(b_tx),
            obsv(b_rx),
            b_events,
        ],
    );
    (a, b)
}

fn read_ptf(p: &Path) -> PtfFile {
    pt_format::read(
        &std::fs::read(p).unwrap(),
        pt_format::ReadOptions::default(),
    )
    .unwrap()
    .0
}

fn one<'a>(f: &'a PtfFile, name: &str, key: &str, val: &str) -> &'a Table {
    let t = tables(f, name, key, val);
    assert_eq!(t.len(), 1, "{name} {key}={val}");
    t[0]
}

/// The `tx` rows of the log of `role`, rebuilt from its sending direction's `pkt` (ptf-format.md,
/// 1.4 additions).
fn rebuild_tx(f: &PtfFile, dir: &str, cols: &[String]) -> Vec<Vec<Option<i64>>> {
    let pkt = one(f, "pkt", "dir", dir);
    let mut rows = rebuilt(pkt, cols, |c| match c {
        "sock" => "tx_sock".into(),
        "id" => "tx_id".into(),
        "flow" | "seq" | "size" | "phase" | "train" | "train_idx" | "tos_tx" | "tx_intended"
        | "tx_user_lag" => c.into(),
        other => format!("tx.{other}"),
    });
    rows.sort();
    rows
}

fn rebuild_txts(f: &PtfFile, dir: &str, ep: &str, cols: &[String]) -> Vec<Vec<Option<i64>>> {
    let pkt = one(f, "pkt", "dir", dir);
    let names = ["tx_sock", "tx_id", "tx_id_offset", "tx_sched", "tx_snd_lag"];
    let mut seen = std::collections::HashSet::new();
    let mut rows = Vec::new();
    for r in row_values(pkt, &names) {
        let (Some(sock), Some(id), Some(off), Some(sched)) = (r[0], r[1], r[2], r[3]) else {
            continue;
        };
        if !seen.insert((sock, id + off)) {
            continue;
        }
        let mut stamps = vec![(0, sched)];
        if let Some(lag) = r[4] {
            stamps.push((1, sched + lag));
        }
        for (kind, real) in stamps {
            rows.push(
                cols.iter()
                    .map(|c| match c.as_str() {
                        "sock" => Some(sock),
                        "id" => Some(id + off),
                        "kind" => Some(kind),
                        "real" => Some(real),
                        _ => None,
                    })
                    .collect(),
            );
        }
    }
    // A stamp `pkt` also holds is there only for its other values (`joined`, 1.4).
    for t in tables(f, "txts_unmatched", "endpoint", ep) {
        let joined = row_values(t, &["joined"]);
        for (r, j) in rebuilt(t, cols, str::to_owned).into_iter().zip(joined) {
            if j[0] == Some(1) {
                let k = (r[0], r[1], r[2]);
                let pos = rows
                    .iter()
                    .position(|x: &Vec<Option<i64>>| (x[0], x[1], x[2]) == k)
                    .expect("a joined stamp is in pkt");
                rows.remove(pos);
            }
            rows.push(r);
        }
    }
    rows.sort();
    rows
}

fn rebuild_rx(f: &PtfFile, dir: &str, ep: &str, cols: &[String]) -> Vec<Vec<Option<i64>>> {
    let pkt = one(f, "pkt", "dir", dir);
    let receive = [
        "rx",
        "rx_src",
        "tos_rx",
        "ttl_rx",
        "src",
        "rx_sock",
        "rx_size",
        "rxq_drops",
    ];
    let mut names: Vec<String> = receive.iter().map(|s| (*s).to_owned()).collect();
    names.extend(
        pkt.columns
            .iter()
            .filter(|c| c.name.starts_with("rx."))
            .map(|c| c.name.clone()),
    );
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let arrived: Vec<bool> = row_values(pkt, &names)
        .iter()
        .map(|r| r.iter().any(Option::is_some))
        .collect();
    let in_pkt = |c: &str| match c {
        "sock" => "rx_sock".to_owned(),
        "size" => "rx_size".to_owned(),
        "flow" | "seq" | "rx" | "rx_src" | "tos_rx" | "ttl_rx" | "src" | "rxq_drops" => c.into(),
        other => format!("rx.{other}"),
    };
    let mut rows: Vec<Vec<Option<i64>>> = rebuilt(pkt, cols, in_pkt)
        .into_iter()
        .zip(arrived)
        .filter_map(|(r, a)| a.then_some(r))
        .collect();
    let in_dup = |c: &str| match c {
        "sock" => "rx_sock".to_owned(),
        "flow" | "seq" | "rx" | "rx_src" | "tos_rx" | "ttl_rx" | "src" | "size" | "rxq_drops" => {
            c.into()
        }
        other => format!("rx.{other}"),
    };
    for t in tables(f, "dup", "dir", dir) {
        rows.extend(rebuilt(t, cols, in_dup));
    }
    for t in tables(f, "unmatched", "dir", dir) {
        rows.extend(rebuilt(t, cols, str::to_owned));
    }
    for t in tables(f, "echo", "endpoint", ep) {
        rows.extend(rebuilt(t, cols, str::to_owned));
    }
    rows.sort();
    rows
}

/// The META head of log `i`, rebuilt from the trace META alone (ptf-format.md, 1.4 additions).
fn rebuild_meta(trace: &Value, i: usize) -> Map {
    let from = &trace.get("merged_from").unwrap().as_array().unwrap()[i];
    let role = from.get("role").and_then(Value::as_str).unwrap();
    let mut m = from
        .get("meta")
        .and_then(Value::as_map)
        .cloned()
        .unwrap_or_default();
    let mut put = |k: &str, v: &Value| {
        m.insert(k.into(), v.clone());
    };
    put("role", &Value::from(role));
    for (k, at) in [
        ("endpoint", "endpoints"),
        ("extra", "extra"),
        ("tool", "captured_by"),
        ("session", "session"),
    ] {
        put(k, trace.get(at).and_then(|x| x.get(role)).unwrap());
    }
    if i == 0 {
        for k in ["trace_id", "created_utc", "network"] {
            put(k, trace.get(k).unwrap());
        }
    }
    m
}

/// Merging a log pair and then reading the trace alone gives back every logged value of `tx`,
/// `txts`, `rx` and both META heads (issue #120, PTF 1.4).
#[test]
fn the_trace_alone_gives_back_every_logged_value() {
    let dir = scratch("the_trace_alone_gives_back_every_logged_value");
    let (a, b) = lossless_pair(&dir);
    let (f, report) = merge_file(&a, Some(&b), &tool()).unwrap();
    assert_eq!(f.minor, 4);
    // The re-anchoring happened, and `pkt` records it.
    assert_eq!(report.reanchor["a"].rows, 3);
    let pkt = one(&f, "pkt", "dir", "a_to_b");
    assert_eq!(rows(pkt, "tx_id"), [0, 1, 2, 4, 5, 6].map(Some).to_vec());
    let off = pkt
        .columns
        .iter()
        .find(|c| c.name == "tx_id_offset")
        .unwrap()
        .i64_rows()
        .unwrap();
    assert_eq!(
        off,
        vec![Some(0), Some(0), Some(0), Some(-1), Some(-1), Some(-1)]
    );

    for (path, role, sends, receives) in
        [(&a, "a", "a_to_b", "b_to_a"), (&b, "b", "b_to_a", "a_to_b")]
    {
        let log = read_ptf(path);
        let (cols, want) = logged(&log, "tx");
        assert_eq!(rebuild_tx(&f, sends, &cols), want, "{role} tx");
        if role == "a" {
            let (cols, want) = logged(&log, "txts");
            assert_eq!(rebuild_txts(&f, sends, role, &cols), want, "{role} txts");
        }
        let (cols, want) = logged(&log, "rx");
        assert_eq!(rebuild_rx(&f, receives, role, &cols), want, "{role} rx");
    }

    let meta = Value::Map(f.sections[0].head().unwrap().clone());
    for (i, path) in [&a, &b].into_iter().enumerate() {
        let log = read_ptf(path);
        assert_eq!(
            &rebuild_meta(&meta, i),
            log.sections[0].head().unwrap(),
            "META {i}"
        );
    }

    // FLOW keeps the responder's definition of flow 1 and the initiator's other head key.
    let flow = f.sections.iter().find(|s| &s.kind == b"FLOW").unwrap();
    let fx = flow.get("merged_from").and_then(Value::as_array).unwrap();
    assert_eq!(
        fx[0]
            .pointer("/heads/0/future_flow_key")
            .and_then(Value::as_str),
        Some("a")
    );
    assert_eq!(
        fx[1].pointer("/flows/0/by").and_then(Value::as_str),
        Some("b")
    );
    assert_eq!(
        flow.get("flows").and_then(Value::as_array).unwrap().len(),
        3
    );
    // Its pointers follow each definition: into `merged_from` for the one the union does not
    // hold, to the trace's index for flow 3; one past its list points at nothing.
    let fpii: Vec<&str> = flow
        .get("pii")
        .and_then(Value::as_map)
        .unwrap()
        .keys()
        .map(|k| k.0.as_str())
        .collect();
    assert_eq!(fpii, vec!["/flows/2/sender", "/merged_from/1/flows/0/by"]);
    // EVNT keeps the responder's other head key, its pointers moved to the trace's places.
    let evnt = f.sections.iter().find(|s| &s.kind == b"EVNT").unwrap();
    let ex = evnt.get("merged_from").and_then(Value::as_array).unwrap();
    assert_eq!(ex[0], Value::map());
    assert_eq!(
        ex[1]
            .pointer("/heads/0/future_event_key/who")
            .and_then(Value::as_str),
        Some("secret-b")
    );
    let epii = evnt.get("pii").and_then(Value::as_map).unwrap();
    assert!(epii.contains_key(&"/events/1/detail/addr/value".into()));
    assert!(epii.contains_key(&"/merged_from/1/heads/0/future_event_key/who".into()));
}

/// The copies `merge` keeps of each log's identifying values are redacted with the rest.
#[test]
fn redaction_removes_the_kept_copies_of_identifying_values() {
    let dir = scratch("redaction_removes_the_kept_copies_of_identifying_values");
    let (a, b) = lossless_pair(&dir);
    let (f, _) = merge_file(&a, Some(&b), &tool()).unwrap();
    let meta = f.sections[0].head().unwrap();
    let from = Value::Map(meta.clone());
    assert_eq!(
        from.pointer("/merged_from/1/meta/network/label")
            .and_then(Value::as_str),
        Some("office-b")
    );
    let (r, _) = pt_format::redact::redact(&f, pt_format::redact::Level::Shareable).unwrap();
    let meta = Value::Map(r.sections[0].head().unwrap().clone());
    assert_eq!(meta.pointer("/merged_from/1/meta/network/label"), None);
    assert_eq!(meta.pointer("/network/label"), None);
    assert_eq!(
        meta.pointer("/merged_from/1/meta/network/class")
            .and_then(Value::as_str),
        Some("home")
    );
    let evnt = r.sections.iter().find(|s| &s.kind == b"EVNT").unwrap();
    assert_eq!(
        evnt.head()
            .map(|h| Value::Map(h.clone()))
            .unwrap()
            .pointer("/merged_from/1/heads/0/future_event_key/who"),
        None
    );
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
