//! Observation-log recorder (docs/design/probe.md §5, ptf-format.md P7).
//!
//! A dedicated thread receives batches of rows over a bounded channel and appends one chunk
//! section per table about once per second (or every 65 536 rows) to a crash-safe PTF log.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use pt_format::{AppendWriter, Column, Enc, Key, Map, Section, Table, Value, Values, flags};

use crate::flows::Role;

/// Column definition.
#[derive(Debug, Clone)]
pub struct ColDef {
    pub name: &'static str,
    pub signed: bool,
    pub enc: Enc,
    pub nullable: bool,
    pub unit: &'static str,
    /// Clock domain suffix (`mono`/`real`) resolved against the table's endpoint, or a full id.
    pub clock: Option<String>,
    pub enum_values: Option<&'static [&'static str]>,
    pub pii: Option<&'static str>,
}

fn c(name: &'static str, enc: Enc, unit: &'static str) -> ColDef {
    ColDef {
        name,
        signed: false,
        enc,
        nullable: false,
        unit,
        clock: None,
        enum_values: None,
        pii: None,
    }
}

impl ColDef {
    fn signed(mut self) -> Self {
        self.signed = true;
        self
    }
    fn null(mut self) -> Self {
        self.nullable = true;
        self
    }
    fn clock(mut self, id: String) -> Self {
        self.clock = Some(id);
        self
    }
    fn enums(mut self, e: &'static [&'static str]) -> Self {
        self.enum_values = Some(e);
        self
    }
    fn pii(mut self, p: &'static str) -> Self {
        self.pii = Some(p);
        self
    }
}

pub const TXTS_KINDS: &[&str] = &["sched", "snd"];
pub const RX_SRC: &[&str] = &["kernel", "user"];
pub const APP_EVENTS: &[&str] = &[
    "connect_start",
    "connected",
    "tls_done",
    "first_byte",
    "progress",
    "done",
    "req_start",
    "resp_done",
    "error",
];

/// Schema of every raw table (docs/design/probe.md §5). `r` is the logging endpoint.
pub fn table_def(name: &str, r: Role) -> Option<(&'static [u8; 4], Vec<ColDef>)> {
    let mono = format!("{}.mono", r.name());
    let real = format!("{}.real", r.name());
    Some(match name {
        "tx" => (
            b"OBSV",
            vec![
                c("sock", Enc::Rle, "id"),
                c("flow", Enc::Rle, "id"),
                c("seq", Enc::Delta, "count"),
                c("size", Enc::Rle, "B"),
                c("phase", Enc::Rle, "id"),
                c("train", Enc::Rle, "id"),
                c("train_idx", Enc::Rle, "count"),
                c("tos_tx", Enc::Rle, "tos"),
                c("id", Enc::Delta, "id"),
                c("tx_intended", Enc::Delta2, "ns").clock(mono),
                c("tx_user_lag", Enc::Varint, "ns").signed(),
            ],
        ),
        "txts" => (
            b"OBSV",
            vec![
                c("sock", Enc::Rle, "id"),
                c("id", Enc::Delta, "id"),
                c("kind", Enc::Rle, "enum").enums(TXTS_KINDS),
                c("real", Enc::Delta2, "ns").clock(real),
            ],
        ),
        "rx" => (
            b"OBSV",
            vec![
                c("sock", Enc::Rle, "id"),
                c("flow", Enc::Rle, "id"),
                c("seq", Enc::Delta, "count"),
                c("size", Enc::Rle, "B"),
                c("rx", Enc::Delta2, "ns").clock(real),
                c("rx_src", Enc::Rle, "enum").enums(RX_SRC),
                c("tos_rx", Enc::Rle, "tos").null(),
                c("ttl_rx", Enc::Rle, "hops").null(),
                c("src", Enc::Rle, "id"),
                c("rxq_drops", Enc::Rle, "count").null(),
            ],
        ),
        "tcpinfo" => {
            let mut v = vec![
                c("flow", Enc::Rle, "id"),
                c("t", Enc::Delta2, "ns").clock(mono),
                c("optlen", Enc::Rle, "B"),
            ];
            for (f, _, _) in pt_sys::tcp::TCP_INFO_FIELDS {
                v.push(c(f, Enc::Delta, "raw").null());
            }
            (b"OBSV", v)
        }
        "app" => (
            b"OBSV",
            vec![
                c("flow", Enc::Rle, "id"),
                c("t", Enc::Delta2, "ns").clock(mono),
                c("event", Enc::Rle, "enum").enums(APP_EVENTS),
                c("bytes", Enc::Delta, "B"),
                c("value", Enc::Varint, "raw").signed(),
            ],
        ),
        "bad" => (
            b"OBSV",
            vec![
                c("t", Enc::Delta2, "ns").clock(mono),
                c("bad_tag", Enc::Varint, "count"),
                c("unknown", Enc::Varint, "count"),
                c("truncated", Enc::Varint, "count"),
            ],
        ),
        "pairs" => (
            b"CLOK",
            vec![
                c("mono", Enc::Delta2, "ns").clock(mono),
                c("real", Enc::Delta2, "ns").clock(real),
                c("width", Enc::Varint, "ns"),
                c("boot", Enc::Delta2, "ns").null(),
            ],
        ),
        "exchange" => (
            b"CLOK",
            vec![
                c("t1", Enc::Delta2, "ns").clock("a.mono".into()),
                c("t2", Enc::Delta2, "ns").clock("b.mono".into()),
                c("t3", Enc::Delta2, "ns").clock("b.mono".into()),
                c("t4", Enc::Delta2, "ns").clock("a.mono".into()),
                c("req_nonce", Enc::Delta, "id").null(),
                c("resp_nonce", Enc::Delta, "id").null(),
            ],
        ),
        "ifstats" => (
            b"CTXS",
            vec![
                c("t", Enc::Delta2, "ns").clock(mono),
                c("rx_bytes", Enc::Delta, "B"),
                c("tx_bytes", Enc::Delta, "B"),
                c("rx_packets", Enc::Delta, "count"),
                c("tx_packets", Enc::Delta, "count"),
                c("rx_dropped", Enc::Delta, "count"),
                c("tx_dropped", Enc::Delta, "count"),
                c("rx_errors", Enc::Delta, "count"),
                c("tx_errors", Enc::Delta, "count"),
            ],
        ),
        "netstack" => (
            b"CTXS",
            vec![
                c("t", Enc::Delta2, "ns").clock(mono),
                c("udp_in_errors", Enc::Delta, "count").null(),
                c("udp_rcvbuf_errors", Enc::Delta, "count").null(),
                c("udp_sndbuf_errors", Enc::Delta, "count").null(),
                c("udp_in_csum_errors", Enc::Delta, "count").null(),
                c("udp6_in_errors", Enc::Delta, "count").null(),
                c("udp6_rcvbuf_errors", Enc::Delta, "count").null(),
                c("udp6_sndbuf_errors", Enc::Delta, "count").null(),
                c("udp6_in_csum_errors", Enc::Delta, "count").null(),
                c("softnet_dropped", Enc::Delta, "count").null(),
                c("softnet_squeezed", Enc::Delta, "count").null(),
            ],
        ),
        "qdisc" => (
            b"CTXS",
            vec![
                c("t", Enc::Delta2, "ns").clock(mono),
                c("bytes", Enc::Delta, "B").null(),
                c("packets", Enc::Delta, "count").null(),
                c("drops", Enc::Delta, "count").null(),
                c("requeues", Enc::Delta, "count").null(),
                c("overlimits", Enc::Delta, "count").null(),
                c("qlen", Enc::Rle, "count").null(),
                c("backlog", Enc::Rle, "B").null(),
            ],
        ),
        "wifi" => (
            b"CTXS",
            vec![
                c("t", Enc::Delta2, "ns").clock(mono),
                c("freq", Enc::Rle, "MHz").null(),
                c("width", Enc::Rle, "enum").null(),
                c("signal", Enc::Rle, "dBm").signed().null(),
                c("beacon_signal", Enc::Rle, "dBm").signed().null(),
                c("tx_bitrate", Enc::Rle, "100kbit/s").null(),
                c("rx_bitrate", Enc::Rle, "100kbit/s").null(),
                c("tx_retries", Enc::Delta, "count").null(),
                c("tx_failed", Enc::Delta, "count").null(),
                c("bss", Enc::Rle, "hash").null().pii("quasi"),
            ],
        ),
        _ => return None,
    })
}

/// Messages to the recorder.
#[derive(Debug)]
pub enum Rec {
    Rows {
        table: &'static str,
        rows: Vec<Vec<Option<i64>>>,
    },
    Event(Value),
    Flow(Value),
    Flush,
}

/// Cloneable handle for producers. Never blocks: a full channel increments `dropped`.
#[derive(Debug, Clone)]
pub struct Recorder {
    tx: SyncSender<Rec>,
    pub dropped: Arc<AtomicU64>,
    t0: u64,
    role: Role,
}

impl Recorder {
    pub fn rows(&self, table: &'static str, rows: Vec<Vec<Option<i64>>>) {
        if rows.is_empty() {
            return;
        }
        let n = rows.len() as u64;
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.tx.try_send(Rec::Rows { table, rows })
        {
            self.dropped.fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn row(&self, table: &'static str, row: Vec<Option<i64>>) {
        self.rows(table, vec![row]);
    }

    /// Record an event at local MONO_RAW time `t` (ns). `pii` maps keys of `detail` to a class.
    pub fn event(&self, kind: &str, detail: Value) {
        self.event_at(pt_sys::clock::mono_raw(), kind, detail);
    }

    pub fn event_at(&self, t: u64, kind: &str, detail: Value) {
        let v = Value::map()
            .with("t", t)
            .with("clock", format!("{}.mono", self.role.name()))
            .with("endpoint", self.role.name())
            .with("type", kind)
            .with("detail", detail);
        // Events are rare and precious: block briefly rather than drop.
        let _ = self.tx.send(Rec::Event(v));
    }

    pub fn flow(&self, spec: Value) {
        let _ = self.tx.send(Rec::Flow(spec));
    }

    pub fn flush(&self) {
        let _ = self.tx.send(Rec::Flush);
    }

    pub fn t0(&self) -> u64 {
        self.t0
    }
}

struct Buf {
    kind: &'static [u8; 4],
    defs: Vec<ColDef>,
    cols: Vec<Vec<Option<i64>>>,
    rows: usize,
}

impl Buf {
    fn push(&mut self, row: &[Option<i64>]) {
        for (i, col) in self.cols.iter_mut().enumerate() {
            col.push(row.get(i).copied().flatten());
        }
        self.rows += 1;
    }

    fn take_table(&mut self, name: &str, endpoint: Role) -> Table {
        let mut t =
            Table::new(name, self.rows).with_attrs(Value::map().with("endpoint", endpoint.name()));
        for (def, col) in self.defs.iter().zip(self.cols.iter_mut()) {
            let data = std::mem::take(col);
            let mut column = if def.nullable {
                if def.signed {
                    let validity: Vec<bool> = data.iter().map(Option::is_some).collect();
                    Column {
                        name: def.name.to_string(),
                        data: pt_format::Data::Known {
                            enc: def.enc,
                            values: Values::I64(data.iter().flatten().copied().collect()),
                        },
                        validity: Some(validity),
                        meta: Map::new(),
                    }
                } else {
                    let rows: Vec<Option<u64>> = data.iter().map(|v| v.map(|x| x as u64)).collect();
                    Column::nullable_u64(def.name, def.enc, &rows)
                }
            } else if def.signed {
                Column::new(
                    def.name,
                    def.enc,
                    Values::I64(data.iter().map(|v| v.unwrap_or(0)).collect()),
                )
            } else {
                Column::new(
                    def.name,
                    def.enc,
                    Values::U64(data.iter().map(|v| v.unwrap_or(0) as u64).collect()),
                )
            };
            column = column.unit(def.unit);
            if let Some(clk) = &def.clock {
                column = column.clock(clk);
            }
            if let Some(e) = def.enum_values {
                column = column.with_meta(
                    "enum",
                    Value::Array(e.iter().map(|s| Value::from(*s)).collect()),
                );
            }
            if let Some(p) = def.pii {
                column = column.with_meta("pii", p);
            }
            t.columns.push(column);
        }
        self.rows = 0;
        t
    }
}

/// Summary returned when the recorder stops.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub path: PathBuf,
    pub rows: BTreeMap<String, u64>,
    pub events: u64,
    pub dropped: u64,
}

const CHUNK_ROWS: usize = 65_536;

/// Start the recorder thread writing to `path` with the given META head.
pub fn start(
    path: &Path,
    meta_head: Map,
    role: Role,
) -> std::io::Result<(Recorder, JoinHandle<std::io::Result<Summary>>)> {
    let meta = Section::new(b"META", flags::CRITICAL, meta_head);
    let mut w = AppendWriter::create(path, &meta, true)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let (tx, rx): (SyncSender<Rec>, Receiver<Rec>) = sync_channel(1 << 16);
    let dropped = Arc::new(AtomicU64::new(0));
    let rec = Recorder {
        tx,
        dropped: dropped.clone(),
        t0: pt_sys::clock::mono_raw(),
        role,
    };
    let path = path.to_path_buf();
    let h = std::thread::Builder::new()
        .name("recorder".into())
        .spawn(move || {
            let mut bufs: BTreeMap<&'static str, Buf> = BTreeMap::new();
            let mut events: Vec<Value> = Vec::new();
            let mut flows: Vec<Value> = Vec::new();
            let mut summary = Summary {
                path,
                ..Default::default()
            };
            let mut last = Instant::now();
            let io = |e: pt_format::Error| std::io::Error::other(e.to_string());
            let flush = |bufs: &mut BTreeMap<&'static str, Buf>,
                         events: &mut Vec<Value>,
                         flows: &mut Vec<Value>,
                         w: &mut AppendWriter|
             -> std::io::Result<()> {
                for (name, b) in bufs.iter_mut() {
                    if b.rows > 0 {
                        let t = b.take_table(name, role);
                        w.append(&Section::new(b.kind, 0, Map::new()).with_table(t))
                            .map_err(io)?;
                    }
                }
                if !flows.is_empty() {
                    let mut h = Map::new();
                    h.insert(Key::from("flows"), Value::Array(std::mem::take(flows)));
                    w.append(&Section::new(b"FLOW", 0, h)).map_err(io)?;
                }
                if !events.is_empty() {
                    let evs = std::mem::take(events);
                    let mut pii = Map::new();
                    for (i, e) in evs.iter().enumerate() {
                        if let Some(Value::Map(d)) = e.get("detail") {
                            for (k, v) in d {
                                if let Some(class) = v.get("pii").and_then(Value::as_str) {
                                    pii.insert(
                                        Key(format!("/events/{i}/detail/{}/value", k.0)),
                                        Value::from(class),
                                    );
                                }
                            }
                        }
                    }
                    let mut h = Map::new();
                    h.insert(Key::from("events"), Value::Array(evs));
                    if !pii.is_empty() {
                        h.insert(Key::from("pii"), Value::Map(pii));
                    }
                    w.append(&Section::new(b"EVNT", 0, h)).map_err(io)?;
                }
                Ok(())
            };
            loop {
                let msg = rx.recv_timeout(Duration::from_millis(200));
                let mut force = false;
                match msg {
                    Ok(Rec::Rows { table, rows }) => {
                        let b = bufs.entry(table).or_insert_with(|| {
                            let (kind, defs) = table_def(table, role).expect("known table");
                            let n = defs.len();
                            Buf {
                                kind,
                                defs,
                                cols: vec![Vec::new(); n],
                                rows: 0,
                            }
                        });
                        *summary.rows.entry(table.to_string()).or_default() += rows.len() as u64;
                        for r in &rows {
                            b.push(r);
                        }
                        if b.rows >= CHUNK_ROWS {
                            force = true;
                        }
                    }
                    Ok(Rec::Event(v)) => {
                        summary.events += 1;
                        events.push(v);
                    }
                    Ok(Rec::Flow(v)) => flows.push(v),
                    Ok(Rec::Flush) => force = true,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        flush(&mut bufs, &mut events, &mut flows, &mut w)?;
                        summary.dropped = dropped.load(Ordering::Relaxed);
                        w.finish().map_err(io)?;
                        return Ok(summary);
                    }
                }
                if force || last.elapsed() >= Duration::from_secs(1) {
                    flush(&mut bufs, &mut events, &mut flows, &mut w)?;
                    last = Instant::now();
                }
            }
        })?;
    Ok((rec, h))
}

/// A value carrying a privacy class inside an event detail: `{"value": v, "pii": class}`.
pub fn pii(v: impl Into<Value>, class: &str) -> Value {
    Value::map().with("value", v.into()).with("pii", class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_recovers() {
        let path = std::env::temp_dir().join(format!("pt-rec-{}.ptflog", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut head = Map::new();
        head.insert(Key::from("kind"), Value::from("obslog"));
        let (rec, h) = start(&path, head, Role::A).unwrap();
        rec.rows(
            "tx",
            (0..1000)
                .map(|i| {
                    vec![
                        Some(0),
                        Some(1),
                        Some(i),
                        Some(128),
                        Some(2),
                        Some(0),
                        Some(0),
                        Some(0),
                        Some(i),
                        Some(1_000_000 + i * 20_000_000),
                        Some(-5),
                    ]
                })
                .collect(),
        );
        rec.event(
            "phase_start",
            Value::map()
                .with("phase", 2u64)
                .with("addr", pii("192.0.2.1:4433", "id")),
        );
        rec.flow(Value::map().with("id", 1u64));
        drop(rec);
        let s = h.join().unwrap().unwrap();
        assert_eq!(s.rows["tx"], 1000);
        let bytes = std::fs::read(&path).unwrap();
        let (f, rep) = pt_format::read(
            &bytes,
            pt_format::ReadOptions {
                recover: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(rep.stopped.is_none());
        let tx = f.sections.iter().find_map(|s| s.table("tx")).unwrap();
        assert_eq!(tx.rows, 1000);
        assert_eq!(
            tx.column("tx_user_lag").unwrap().i64_rows().unwrap()[0],
            Some(-5)
        );
        let ev = f.sections.iter().find(|s| &s.kind == b"EVNT").unwrap();
        assert!(ev.get("pii").is_some());
        let _ = std::fs::remove_file(&path);
    }
}
