//! Merge two observation logs into one canonical PTF trace (REQ-PRB-018,
//! docs/design/probe.md §5). Lossless: every logged row ends up in the trace.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use pt_format::{
    Body, Column, Data, Enc, Key, Map, PtfFile, ReadOptions, Section, Table, Value, Values,
    WriteOptions, flags,
};

use crate::session::ToolInfo;

pub const CHUNK_ROWS: usize = 65_536;

/// A decoded column as optional i64 rows plus its directory metadata.
#[derive(Debug, Clone)]
struct Col {
    name: String,
    signed: bool,
    enc: Enc,
    nullable: bool,
    meta: Map,
    rows: Vec<Option<i64>>,
}

#[derive(Debug, Clone, Default)]
struct Tab {
    cols: Vec<Col>,
    rows: usize,
}

impl Tab {
    fn col(&self, name: &str) -> Option<&Col> {
        self.cols.iter().find(|c| c.name == name)
    }

    fn append(&mut self, t: &Table) {
        for c in &t.columns {
            let (signed, rows): (bool, Vec<Option<i64>>) = match c.values() {
                Some(Values::U64(_)) => (
                    false,
                    c.u64_rows()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|v| v.map(|x| x as i64))
                        .collect(),
                ),
                Some(Values::I64(_)) => (true, c.i64_rows().unwrap_or_default()),
                _ => continue,
            };
            let enc = match &c.data {
                Data::Known { enc, .. } => *enc,
                Data::Opaque { .. } => continue,
            };
            let idx = match self.cols.iter().position(|x| x.name == c.name) {
                Some(i) => i,
                None => {
                    self.cols.push(Col {
                        name: c.name.clone(),
                        signed,
                        enc,
                        nullable: c.validity.is_some(),
                        meta: c.meta.clone(),
                        rows: vec![None; self.rows],
                    });
                    self.cols.len() - 1
                }
            };
            self.cols[idx].rows.extend(rows);
        }
        self.rows += t.rows;
        for c in &mut self.cols {
            c.rows.resize(self.rows, None);
        }
    }
}

fn mk_column(c: &Col, rows: &[Option<i64>]) -> Column {
    let nullable = c.nullable || rows.iter().any(Option::is_none);
    let mut col = if nullable {
        let validity: Vec<bool> = rows.iter().map(Option::is_some).collect();
        let present: Vec<i64> = rows.iter().flatten().copied().collect();
        Column {
            name: c.name.clone(),
            data: Data::Known {
                enc: c.enc,
                values: if c.signed {
                    Values::I64(present)
                } else {
                    Values::U64(present.into_iter().map(|v| v as u64).collect())
                },
            },
            validity: Some(validity),
            meta: Map::new(),
        }
    } else {
        let v: Vec<i64> = rows.iter().map(|v| v.unwrap_or(0)).collect();
        Column::new(
            &c.name,
            c.enc,
            if c.signed {
                Values::I64(v)
            } else {
                Values::U64(v.into_iter().map(|x| x as u64).collect())
            },
        )
    };
    col.meta = c.meta.clone();
    col
}

/// Emit `cols` (all of equal length) as tables of at most CHUNK_ROWS rows.
fn chunks(name: &str, cols: &[Col], attrs: &Value) -> Vec<Table> {
    let n = cols.first().map_or(0, |c| c.rows.len());
    let mut out = Vec::new();
    let mut start = 0;
    while start < n {
        let end = (start + CHUNK_ROWS).min(n);
        let mut t = Table::new(name, end - start).with_attrs(attrs.clone());
        for c in cols {
            t.columns.push(mk_column(c, &c.rows[start..end]));
        }
        out.push(t);
        start = end;
    }
    out
}

fn col(
    name: &str,
    signed: bool,
    enc: Enc,
    unit: &str,
    clock: Option<String>,
    rows: Vec<Option<i64>>,
) -> Col {
    let mut meta = Map::new();
    meta.insert(Key::from("unit"), Value::from(unit));
    if let Some(c) = clock {
        meta.insert(Key::from("clock"), Value::from(c));
    }
    Col {
        name: name.into(),
        signed,
        enc,
        nullable: false,
        meta,
        rows,
    }
}

fn copy_col(src: &Col, rows: Vec<Option<i64>>) -> Col {
    Col {
        rows,
        ..src.clone()
    }
}

/// What a log contributed.
#[derive(Debug, Clone)]
pub struct LogInfo {
    pub role: String,
    pub content_digest: String,
    pub stopped: Option<String>,
}

/// How well kernel TX stamps joined transmissions in one direction (probe.md §4.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StampCheck {
    /// `tx` rows that got a SCHED stamp.
    pub joined: usize,
    /// Joined rows whose SCHED stamp is implausible in time (more than 1 ms before the
    /// user-space send time, or more than 1 s after it): a sign of misaligned ids.
    pub implausible: usize,
}

#[derive(Debug, Clone)]
pub struct MergeReport {
    pub content_digest: String,
    pub logs: Vec<LogInfo>,
    pub pkt_rows: BTreeMap<String, usize>,
    pub unmatched: BTreeMap<String, usize>,
    pub stamps: BTreeMap<String, StampCheck>,
    /// Kernel TX stamps that matched no transmission, or repeated one, per endpoint.
    pub txts_unmatched: BTreeMap<String, usize>,
    /// Id-level join check per endpoint.
    pub ids: BTreeMap<String, IdCheck>,
    /// Re-anchoring of predicted transmit ids per endpoint.
    pub reanchor: BTreeMap<String, Reanchor>,
}

struct Log {
    role: String,
    meta: Value,
    tables: BTreeMap<String, Tab>,
    flows: Vec<Value>,
    events: Vec<Value>,
    info: LogInfo,
}

fn read_log(path: &Path) -> pt_format::Result<Log> {
    let bytes = std::fs::read(path)?;
    let (f, rep) = pt_format::read(
        &bytes,
        ReadOptions {
            recover: true,
            ..Default::default()
        },
    )?;
    let meta = Value::Map(f.sections[0].head().cloned().unwrap_or_default());
    let role = meta
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("a")
        .to_string();
    let mut tables: BTreeMap<String, Tab> = BTreeMap::new();
    let mut flows = Vec::new();
    let mut events = Vec::new();
    for s in &f.sections[1..] {
        match &s.kind {
            b"FLOW" => flows.extend(
                s.get("flows")
                    .and_then(Value::as_array)
                    .unwrap_or(&[])
                    .iter()
                    .cloned(),
            ),
            b"EVNT" => events.extend(
                s.get("events")
                    .and_then(Value::as_array)
                    .unwrap_or(&[])
                    .iter()
                    .cloned(),
            ),
            _ => {
                for t in s.tables() {
                    tables.entry(t.name.clone()).or_default().append(t);
                }
            }
        }
    }
    Ok(Log {
        role: role.clone(),
        meta,
        tables,
        flows,
        events,
        info: LogInfo {
            role,
            content_digest: rep.content_digest,
            stopped: rep.stopped.map(|(o, r)| format!("at byte {o}: {r}")),
        },
    })
}

/// Maps an endpoint's MONO_RAW to REALTIME with its nearest clock pair (coarse: only used to
/// sanity-check stamp joins).
struct MonoToReal(Vec<(i64, i64)>);

impl MonoToReal {
    fn new(log: &Log) -> MonoToReal {
        let empty = Tab::default();
        let t = log.tables.get("pairs").unwrap_or(&empty);
        let (m, r) = (rows_of(t, "mono"), rows_of(t, "real"));
        let mut v: Vec<(i64, i64)> = m
            .iter()
            .zip(&r)
            .filter_map(|(m, r)| Some(((*m)?, (*r)? - (*m)?)))
            .collect();
        v.sort_unstable();
        MonoToReal(v)
    }

    fn real(&self, mono: i64) -> Option<i64> {
        let i = self.0.partition_point(|(m, _)| *m < mono);
        let near = [i.checked_sub(1), Some(i)]
            .into_iter()
            .flatten()
            .filter_map(|k| self.0.get(k))
            .min_by_key(|(m, _)| (m - mono).abs())?;
        Some(mono + near.1)
    }

    /// REALTIME of `mono`, interpolating the offset between the clock pairs around it (the
    /// nearest pair's offset outside them): accurate to well under a microsecond, which
    /// re-anchoring needs (probe.md §4.1).
    fn interp(&self, mono: i64) -> Option<i64> {
        let i = self.0.partition_point(|(m, _)| *m < mono);
        match (i.checked_sub(1).and_then(|k| self.0.get(k)), self.0.get(i)) {
            (Some(&(m0, o0)), Some(&(m1, o1))) if m1 > m0 => {
                let f = (mono - m0) as i128 * (o1 - o0) as i128 / (m1 - m0) as i128;
                Some(mono + o0 + f as i64)
            }
            (Some(&(_, o)), _) | (None, Some(&(_, o))) => Some(mono + o),
            (None, None) => None,
        }
    }
}

/// Slack of the re-anchoring window (probe.md §4.1).
const REANCHOR_SLACK_NS: i64 = 1_000;

/// How `merge` re-anchored one endpoint's predicted transmit ids (probe.md §4.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reanchor {
    /// Recorded send failures at which the id offset changed.
    pub anchors: usize,
    /// `tx` rows whose id was corrected.
    pub rows: usize,
}

/// One endpoint's transmit ids as `merge` joins them: the logged ids, re-anchored after send
/// failures on `predicted` sockets (probe.md §4.1).
#[derive(Debug, Clone, Default)]
struct TxIds {
    /// Per socket: (first logged id the offset applies to, offset), ascending.
    steps: HashMap<i64, Vec<(i64, i64)>>,
    /// Ids consumed by sends without a `tx` row (burns, `raw_sent`), corrected.
    burned: HashSet<(i64, i64)>,
    check: Reanchor,
}

impl TxIds {
    /// The corrected id of a logged (sock, id).
    fn id(&self, sock: i64, id: i64) -> i64 {
        let Some(st) = self.steps.get(&sock) else {
            return id;
        };
        match st.partition_point(|s| s.0 <= id) {
            0 => id,
            k => id + st[k - 1].1,
        }
    }
}

/// A recorded send failure (`send_error`, `send_partial`, `send_eagain`).
struct Failure {
    t: i64,
    sock: i64,
    burned: Option<i64>,
    unburned: Option<i64>,
    predicted: bool,
}

/// Re-anchor `log`'s transmit ids (probe.md §4.1): per `predicted` socket, at each recorded
/// send failure, the id offset (−1, 0 or +1 relative to the current one) whose rows up to the
/// next failure join the most SCHED stamps inside their call's window. A non-zero offset must
/// score strictly higher than the current one.
fn tx_ids(log: &Log) -> TxIds {
    let empty = Tab::default();
    let tx = log.tables.get("tx").unwrap_or(&empty);
    let txts = log.tables.get("txts").unwrap_or(&empty);
    let to_real = MonoToReal::new(log);
    let (ts_sock, ts_id, ts_kind, ts_real) = (
        rows_of(txts, "sock"),
        rows_of(txts, "id"),
        rows_of(txts, "kind"),
        rows_of(txts, "real"),
    );
    let mut sched: HashMap<(i64, i64), i64> = HashMap::new();
    for j in 0..txts.rows {
        if let (Some(s), Some(i), Some(0), Some(r)) = (ts_sock[j], ts_id[j], ts_kind[j], ts_real[j])
        {
            sched.entry((s, i)).or_insert(r);
        }
    }
    // Per socket: (logged id, user-space send time in MONO_RAW).
    let (t_sock, t_id, t_int, t_lag) = (
        rows_of(tx, "sock"),
        rows_of(tx, "id"),
        rows_of(tx, "tx_intended"),
        rows_of(tx, "tx_user_lag"),
    );
    let mut rows: HashMap<i64, Vec<(i64, Option<i64>)>> = HashMap::new();
    for i in 0..tx.rows {
        if let (Some(s), Some(p)) = (t_sock[i], t_id[i]) {
            rows.entry(s)
                .or_default()
                .push((p, t_int[i].zip(t_lag[i]).map(|(a, b)| a + b)));
        }
    }
    let mut failures: Vec<Failure> = Vec::new();
    let mut raw_sent: Vec<(i64, i64)> = Vec::new();
    for e in &log.events {
        let ty = e.get("type").and_then(Value::as_str);
        let d = e.get("detail");
        let get = |k: &str| {
            d.and_then(|d| d.get(k))
                .and_then(Value::as_u64)
                .map(|v| v as i64)
        };
        let Some(sock) = get("sock") else { continue };
        match ty {
            Some("raw_sent") => {
                if let Some(i) = get("id") {
                    raw_sent.push((sock, i));
                }
            }
            Some("send_error" | "send_partial" | "send_eagain") => failures.push(Failure {
                t: e.get("t").and_then(Value::as_u64).map_or(0, |t| t as i64),
                sock,
                burned: get("burned_id"),
                unburned: get("unburned_id"),
                predicted: d.and_then(|d| d.get("tx_ids")).and_then(Value::as_str)
                    == Some("predicted"),
            }),
            _ => {}
        }
    }
    failures.sort_by_key(|f| f.t);

    let mut out = TxIds::default();
    for f in failures.iter().filter(|f| !f.predicted) {
        // Ids not predicted are taken as logged.
        if let Some(b) = f.burned {
            out.burned.insert((f.sock, b));
        }
        if let Some(u) = f.unburned {
            out.burned.remove(&(f.sock, u));
        }
    }
    let mut socks: Vec<i64> = failures
        .iter()
        .filter(|f| f.predicted)
        .map(|f| f.sock)
        .collect();
    socks.sort_unstable();
    socks.dedup();
    for s in socks {
        let mut r = rows.remove(&s).unwrap_or_default();
        r.sort_unstable_by_key(|x| x.0);
        let n = r.len();
        // Each row's window: its call's send time to the next call's (calls share a send time).
        let lo: Vec<Option<i64>> = r
            .iter()
            .map(|x| x.1.and_then(|u| to_real.interp(u)))
            .collect();
        let mut hi: Vec<Option<i64>> = vec![None; n];
        let mut next: Option<i64> = None;
        for i in (0..n).rev() {
            hi[i] = next.or_else(|| lo[i].map(|l| l + 1_000_000_000));
            if i == 0 || r[i - 1].1 != r[i].1 {
                next = lo[i];
            }
        }
        let fits = |i: usize, id: i64| {
            sched.get(&(s, id)).is_some_and(|&t| {
                lo[i].is_some_and(|l| t >= l - REANCHOR_SLACK_NS)
                    && hi[i].is_some_and(|h| t <= h + REANCHOR_SLACK_NS)
            })
        };
        // Where each failure falls among the rows (rows are in send order): exact with a burned
        // or unburned id, else anywhere in the last call that started before the event.
        let fs: Vec<&Failure> = failures
            .iter()
            .filter(|f| f.predicted && f.sock == s)
            .collect();
        let region = |f: &Failure| -> (usize, usize) {
            if let Some(b) = f.burned {
                let k = r.partition_point(|x| x.0 <= b);
                (k, k)
            } else if let Some(u) = f.unburned {
                let k = r.partition_point(|x| x.0 < u);
                (k, k)
            } else {
                let end = r.partition_point(|x| x.1.is_none_or(|u| u <= f.t));
                let start = end
                    .checked_sub(1)
                    .map_or(0, |l| r.partition_point(|x| x.1 < r[l].1));
                (start, end)
            }
        };
        let regions: Vec<(usize, usize)> = fs.iter().map(|f| region(f)).collect();
        let mut off = 0i64;
        let mut floor = 0usize;
        let mut steps = Vec::new();
        for (k, f) in fs.iter().enumerate() {
            if let Some(b) = f.burned {
                out.burned.insert((s, b + off));
            }
            if let Some(u) = f.unburned {
                out.burned.remove(&(s, u + off));
            }
            let a = regions[k].0.max(floor);
            let b = regions[k].1.max(a);
            let e = regions.get(k + 1).map_or(n, |x| x.0).max(b);
            // prefix[d][i]: rows a..a+i that fit with offset off+d.
            let prefix = |d: i64| -> Vec<usize> {
                let mut p = vec![0; e - a + 1];
                for i in a..e {
                    p[i - a + 1] = p[i - a] + usize::from(fits(i, r[i].0 + off + d));
                }
                p
            };
            let keep = prefix(0);
            let mut best = (keep[e - a], 0i64, a);
            for d in [-1, 1] {
                let p = prefix(d);
                for sp in a..=b {
                    let score = keep[sp - a] + p[e - a] - p[sp - a];
                    if score > best.0 {
                        best = (score, d, sp);
                    }
                }
            }
            // Only an anchor bounds later candidates (steps stay in id order). A failure that
            // moved nothing does not: a burn's region lies after the row that reuses its id once
            // the burn is undone, and that row belongs to the undo.
            if best.1 != 0 {
                off += best.1;
                floor = best.2;
                steps.push((r.get(best.2).map_or(i64::MAX, |x| x.0), off));
                out.check.anchors += 1;
            }
        }
        if !steps.is_empty() {
            out.steps.insert(s, steps);
        }
    }
    out.check.rows = t_sock
        .iter()
        .zip(&t_id)
        .filter_map(|(s, i)| s.zip(*i))
        .filter(|&(s, i)| out.id(s, i) != i)
        .count();
    for (s, i) in raw_sent {
        let c = out.id(s, i);
        out.burned.insert((s, c));
    }
    out
}

fn rows_of(t: &Tab, name: &str) -> Vec<Option<i64>> {
    t.col(name)
        .map(|c| c.rows.clone())
        .unwrap_or_else(|| vec![None; t.rows])
}

/// The joined direction: `pkt`, `dup`, `unmatched` columns and the stamp check.
type Joined = (Vec<Col>, Vec<Col>, Vec<Col>, StampCheck);

/// Join sender `tx`/`txts` with receiver `rx` for one direction, by the sender's corrected
/// transmit ids `ids`.
fn join_direction(sender: &Log, receiver: Option<&Log>, ids: &TxIds) -> Joined {
    let s = sender.role.as_str();
    let r = if s == "a" { "b" } else { "a" };
    let empty = Tab::default();
    let tx = sender.tables.get("tx").unwrap_or(&empty);
    let txts = sender.tables.get("txts").unwrap_or(&empty);
    let rx = receiver.and_then(|l| l.tables.get("rx")).unwrap_or(&empty);

    // (sock, id) -> (sched, snd)
    let mut stamps: HashMap<(i64, i64), (Option<i64>, Option<i64>)> = HashMap::new();
    let (ts_sock, ts_id, ts_kind, ts_real) = (
        rows_of(txts, "sock"),
        rows_of(txts, "id"),
        rows_of(txts, "kind"),
        rows_of(txts, "real"),
    );
    for i in 0..txts.rows {
        let (Some(sock), Some(id), Some(kind), Some(real)) =
            (ts_sock[i], ts_id[i], ts_kind[i], ts_real[i])
        else {
            continue;
        };
        let e = stamps.entry((sock, id)).or_default();
        if kind == 0 {
            e.0.get_or_insert(real);
        } else {
            e.1.get_or_insert(real);
        }
    }
    // (flow, seq) -> rx row indices
    let (rx_flow, rx_seq) = (rows_of(rx, "flow"), rows_of(rx, "seq"));
    let mut arrivals: HashMap<(i64, i64), Vec<usize>> = HashMap::new();
    for i in 0..rx.rows {
        if let (Some(f), Some(q)) = (rx_flow[i], rx_seq[i]) {
            arrivals.entry((f, q)).or_default().push(i);
        }
    }
    // Only flows this sender sent belong to this direction.
    let mut order: Vec<usize> = (0..tx.rows).collect();
    let (tx_flow, tx_seq) = (rows_of(tx, "flow"), rows_of(tx, "seq"));
    order.sort_by_key(|&i| (tx_flow[i], tx_seq[i]));
    let g = |name: &str| rows_of(tx, name);
    let (t_sock, t_size, t_phase, t_train, t_idx, t_tos, t_id, t_int, t_lag) = (
        g("sock"),
        g("size"),
        g("phase"),
        g("train"),
        g("train_idx"),
        g("tos_tx"),
        g("id"),
        g("tx_intended"),
        g("tx_user_lag"),
    );
    let rg = |name: &str| rows_of(rx, name);
    let (r_sock, r_rx, r_src_kind, r_tos, r_ttl, r_src, r_size, r_drops) = (
        rg("sock"),
        rg("rx"),
        rg("rx_src"),
        rg("tos_rx"),
        rg("ttl_rx"),
        rg("src"),
        rg("size"),
        rg("rxq_drops"),
    );

    let to_real = MonoToReal::new(sender);
    let mut check = StampCheck::default();
    let mut out: Vec<Vec<Option<i64>>> = (0..20).map(|_| Vec::with_capacity(order.len())).collect();
    let mut used: HashMap<(i64, i64), usize> = HashMap::new();
    let mut dup: Vec<Vec<Option<i64>>> = vec![Vec::new(); 10];
    for &i in &order {
        let key = (tx_flow[i].unwrap_or(-1), tx_seq[i].unwrap_or(-1));
        let st = t_sock[i]
            .zip(t_id[i])
            .and_then(|(s, id)| stamps.get(&(s, ids.id(s, id))))
            .copied()
            .unwrap_or((None, None));
        let arr = arrivals.get(&key);
        let first = arr.and_then(|v| v.first()).copied();
        if let Some(v) = arr {
            used.insert(key, v.len());
            for &j in v.iter().skip(1) {
                for (k, val) in [
                    rx_flow[j],
                    rx_seq[j],
                    r_rx[j],
                    r_tos[j],
                    r_ttl[j],
                    r_src[j],
                    r_sock[j],
                    r_src_kind[j],
                    r_size[j],
                    r_drops[j],
                ]
                .into_iter()
                .enumerate()
                {
                    dup[k].push(val);
                }
            }
        }
        if let Some(sched) = st.0 {
            check.joined += 1;
            let user = t_int[i]
                .zip(t_lag[i])
                .and_then(|(a, b)| to_real.real(a + b));
            if user.is_some_and(|u| sched < u - 1_000_000 || sched > u + 1_000_000_000) {
                check.implausible += 1;
            }
        }
        let at = |v: &Vec<Option<i64>>| first.and_then(|j| v[j]);
        let vals = [
            tx_flow[i],
            tx_seq[i],
            t_size[i],
            t_phase[i],
            t_train[i],
            t_idx[i],
            t_tos[i],
            t_sock[i],
            t_int[i],
            t_lag[i],
            st.0,
            st.0.zip(st.1).map(|(a, b)| b - a),
            at(&r_rx),
            at(&r_src_kind),
            at(&r_tos),
            at(&r_ttl),
            at(&r_src),
            at(&r_sock),
            at(&r_size),
            at(&r_drops),
        ];
        for (k, v) in vals.into_iter().enumerate() {
            out[k].push(v);
        }
    }
    let sm = Some(format!("{s}.mono"));
    let sr = Some(format!("{s}.real"));
    let rr = Some(format!("{r}.real"));
    let names: [(&str, bool, Enc, &str, Option<String>); 20] = [
        ("flow", false, Enc::Rle, "id", None),
        ("seq", false, Enc::Delta, "count", None),
        ("size", false, Enc::Rle, "B", None),
        ("phase", false, Enc::Rle, "id", None),
        ("train", false, Enc::Rle, "id", None),
        ("train_idx", false, Enc::Rle, "count", None),
        ("tos_tx", false, Enc::Rle, "tos", None),
        ("tx_sock", false, Enc::Rle, "id", None),
        ("tx_intended", false, Enc::Delta2, "ns", sm.clone()),
        ("tx_user_lag", true, Enc::Varint, "ns", None),
        ("tx_sched", false, Enc::Delta2, "ns", sr),
        ("tx_snd_lag", true, Enc::Varint, "ns", None),
        ("rx", false, Enc::Delta2, "ns", rr.clone()),
        ("rx_src", false, Enc::Rle, "enum", None),
        ("tos_rx", false, Enc::Rle, "tos", None),
        ("ttl_rx", false, Enc::Rle, "hops", None),
        ("src", false, Enc::Rle, "id", None),
        ("rx_sock", false, Enc::Rle, "id", None),
        ("rx_size", false, Enc::Rle, "B", None),
        ("rxq_drops", false, Enc::Rle, "count", None),
    ];
    let mut pkt: Vec<Col> = names
        .iter()
        .zip(out)
        .map(|((n, signed, enc, unit, clock), rows)| {
            col(n, *signed, *enc, unit, clock.clone(), rows)
        })
        .collect();
    let dupn = [
        "flow",
        "seq",
        "rx",
        "tos_rx",
        "ttl_rx",
        "src",
        "rx_sock",
        "rx_src",
        "size",
        "rxq_drops",
    ];
    let mut dup_cols: Vec<Col> = dupn
        .iter()
        .zip(dup)
        .map(|(n, rows)| {
            let (enc, unit, clock) = match *n {
                "rx" => (Enc::Delta2, "ns", rr.clone()),
                "seq" => (Enc::Delta, "count", None),
                "size" => (Enc::Rle, "B", None),
                "rxq_drops" => (Enc::Rle, "count", None),
                "rx_src" => (Enc::Rle, "enum", None),
                _ => (Enc::Rle, "id", None),
            };
            col(n, false, enc, unit, clock, rows)
        })
        .collect();
    for c in pkt.iter_mut().chain(dup_cols.iter_mut()) {
        if c.name == "rx_src" {
            c.meta.insert(
                Key::from("enum"),
                Value::Array(vec![Value::from("kernel"), Value::from("user")]),
            );
        }
    }
    // Arrivals with no matching transmission (sender log lost or truncated).
    let mut un: Vec<usize> = (0..rx.rows)
        .filter(|&j| {
            let key = (rx_flow[j].unwrap_or(-1), rx_seq[j].unwrap_or(-1));
            !used.contains_key(&key) && !receiver.is_some_and(|r| sender_owns(r, key.0))
        })
        .collect();
    un.sort_by_key(|&j| (rx_flow[j], rx_seq[j], r_rx[j]));
    let unmatched: Vec<Col> = rx
        .cols
        .iter()
        .map(|c| copy_col(c, un.iter().map(|&j| c.rows[j]).collect()))
        .collect();
    (pkt, dup_cols, unmatched, check)
}

/// Kernel TX stamps of `log` that the join does not use: stamps whose (sock, id) matches no
/// `tx` row (echoes, failed sends, mispredicted ids), and every stamp after the first of its
/// (sock, id, kind), which the join skips (probe.md §4.1). Kept as `txts_unmatched` so
/// nothing is dropped (P1).
fn unmatched_stamps(log: &Log, ids: &TxIds) -> Vec<Col> {
    let empty = Tab::default();
    let tx = log.tables.get("tx").unwrap_or(&empty);
    let txts = log.tables.get("txts").unwrap_or(&empty);
    let sent: HashSet<(i64, i64)> = rows_of(tx, "sock")
        .into_iter()
        .zip(rows_of(tx, "id"))
        .filter_map(|(s, i)| s.zip(i))
        .map(|(s, i)| (s, ids.id(s, i)))
        .collect();
    let (sock, id, kind) = (
        rows_of(txts, "sock"),
        rows_of(txts, "id"),
        rows_of(txts, "kind"),
    );
    let mut seen: HashSet<(i64, i64, Option<i64>)> = HashSet::new();
    let keep: Vec<usize> = (0..txts.rows)
        .filter(|&j| match sock[j].zip(id[j]) {
            None => true,
            Some(k) => !sent.contains(&k) || !seen.insert((k.0, k.1, kind[j])),
        })
        .collect();
    txts.cols
        .iter()
        .map(|c| copy_col(c, keep.iter().map(|&j| c.rows[j]).collect()))
        .collect()
}

/// Id-level check of the `tx`–`txts` join for one endpoint (probe.md §4.1). The time window
/// of [`StampCheck`] cannot see ids that are off by one (each row would get a neighbour's
/// stamp, microseconds away); a shifted id shows here instead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IdCheck {
    /// `tx` rows with no SCHED stamp, on sockets that have stamps at all.
    pub unstamped: usize,
    /// Distinct SCHED stamp ids that match no `tx` row, no burned id (`burned_id` in
    /// `send_error`, `send_partial`, `send_eagain`, less any `unburned_id`) and no unobserved
    /// send (`raw_sent`), counting ids from the socket's first `tx` id on (earlier ones are
    /// the handshake's). Ids are compared after re-anchoring.
    pub unexplained: usize,
}

fn id_check(log: &Log, ids: &TxIds) -> IdCheck {
    let empty = Tab::default();
    let tx = log.tables.get("tx").unwrap_or(&empty);
    let txts = log.tables.get("txts").unwrap_or(&empty);
    let sent: Vec<(i64, i64)> = rows_of(tx, "sock")
        .into_iter()
        .zip(rows_of(tx, "id"))
        .filter_map(|(s, i)| s.zip(i))
        .map(|(s, i)| (s, ids.id(s, i)))
        .collect();
    let mut first: HashMap<i64, i64> = HashMap::new();
    for &(s, i) in &sent {
        let f = first.entry(s).or_insert(i);
        *f = (*f).min(i);
    }
    let sent_set: HashSet<(i64, i64)> = sent.iter().copied().collect();
    let burned = &ids.burned;
    let (sock, id, kind) = (
        rows_of(txts, "sock"),
        rows_of(txts, "id"),
        rows_of(txts, "kind"),
    );
    let sched: HashSet<(i64, i64)> = (0..txts.rows)
        .filter(|&j| kind[j] == Some(0))
        .filter_map(|j| sock[j].zip(id[j]))
        .collect();
    let stamped_socks: HashSet<i64> = sched.iter().map(|k| k.0).collect();
    IdCheck {
        unstamped: sent
            .iter()
            .filter(|k| stamped_socks.contains(&k.0) && !sched.contains(k))
            .count(),
        unexplained: sched
            .iter()
            .filter(|k| {
                !sent_set.contains(k)
                    && !burned.contains(k)
                    && first.get(&k.0).is_some_and(|f| k.1 >= *f)
            })
            .count(),
    }
}

fn sender_owns(sender: &Log, flow: i64) -> bool {
    sender.flows.iter().any(|f| {
        f.get("id").and_then(Value::as_u64) == Some(flow as u64)
            && f.get("sender").and_then(Value::as_str) == Some(sender.role.as_str())
    })
}

fn remap_pii(meta: &Value, role: &str, into: &mut Map) {
    if let Some(Value::Map(p)) = meta.get("pii") {
        for (k, v) in p {
            let path = &k.0;
            let new = if let Some(rest) = path.strip_prefix("/endpoint") {
                format!("/endpoints/{role}{rest}")
            } else if let Some(rest) = path.strip_prefix("/extra") {
                format!("/extra/{role}{rest}")
            } else {
                path.clone()
            };
            into.insert(Key(new), v.clone());
        }
    }
}

/// Merge `log_a` (initiator) and optionally `log_b` (responder) into a canonical trace.
pub fn merge_file(
    log_a: &Path,
    log_b: Option<&Path>,
    tool: &ToolInfo,
) -> pt_format::Result<(PtfFile, MergeReport)> {
    let a = read_log(log_a)?;
    let b = match log_b {
        Some(p) => Some(read_log(p)?),
        None => None,
    };
    let mut pii = Map::new();
    remap_pii(&a.meta, "a", &mut pii);
    let mut endpoints =
        Value::map().with("a", a.meta.get("endpoint").cloned().unwrap_or(Value::Null));
    let mut clocks = a
        .meta
        .get("clocks")
        .and_then(Value::as_map)
        .cloned()
        .unwrap_or_default();
    let mut extra = Value::map().with("a", a.meta.get("extra").cloned().unwrap_or(Value::Null));
    let mut captured = Value::map().with("a", a.meta.get("tool").cloned().unwrap_or(Value::Null));
    let mut sessions =
        Value::map().with("a", a.meta.get("session").cloned().unwrap_or(Value::Null));
    if let Some(b) = &b {
        remap_pii(&b.meta, "b", &mut pii);
        endpoints = endpoints.with("b", b.meta.get("endpoint").cloned().unwrap_or(Value::Null));
        if let Some(c) = b.meta.get("clocks").and_then(Value::as_map) {
            clocks.extend(c.clone());
        }
        extra = extra.with("b", b.meta.get("extra").cloned().unwrap_or(Value::Null));
        captured = captured.with("b", b.meta.get("tool").cloned().unwrap_or(Value::Null));
        sessions = sessions.with("b", b.meta.get("session").cloned().unwrap_or(Value::Null));
    }
    let logs: Vec<LogInfo> = std::iter::once(a.info.clone())
        .chain(b.as_ref().map(|b| b.info.clone()))
        .collect();
    let mut meta = Value::map()
        .with("kind", "trace")
        .with(
            "trace_id",
            a.meta.get("trace_id").cloned().unwrap_or(Value::Null),
        )
        .with(
            "created_utc",
            a.meta.get("created_utc").cloned().unwrap_or(Value::Null),
        )
        .with("tool", tool.to_value())
        .with("captured_by", captured)
        .with("session", sessions)
        .with(
            "profile",
            a.meta
                .get("session")
                .and_then(|s| s.get("profile"))
                .cloned()
                .unwrap_or(Value::Null),
        )
        .with("endpoints", endpoints)
        .with(
            "network",
            a.meta.get("network").cloned().unwrap_or(Value::Null),
        )
        .with("clocks", Value::Map(clocks))
        .with("redaction", "full")
        .with("extra", extra)
        .with(
            "merged_from",
            Value::Array(
                logs.iter()
                    .map(|l| {
                        Value::map()
                            .with("role", l.role.as_str())
                            .with("content_digest", l.content_digest.as_str())
                            .with("stopped", l.stopped.clone())
                    })
                    .collect(),
            ),
        )
        .with(
            "complete",
            b.is_some() && logs.iter().all(|l| l.stopped.is_none()),
        );
    if !pii.is_empty() {
        meta = meta.with("pii", Value::Map(pii));
    }

    let mut sections = vec![Section::new(
        b"META",
        flags::CRITICAL,
        meta.as_map().cloned().unwrap_or_default(),
    )];
    // FLOW: union by id, initiator's definition first.
    let mut flows: BTreeMap<u64, Value> = BTreeMap::new();
    for f in a.flows.iter().chain(b.iter().flat_map(|b| b.flows.iter())) {
        if let Some(id) = f.get("id").and_then(Value::as_u64) {
            flows.entry(id).or_insert_with(|| f.clone());
        }
    }
    let mut fh = Map::new();
    fh.insert(
        Key::from("flows"),
        Value::Array(flows.into_values().collect()),
    );
    sections.push(Section::new(b"FLOW", 0, fh));

    let mut report = MergeReport {
        content_digest: String::new(),
        logs: logs.clone(),
        pkt_rows: BTreeMap::new(),
        unmatched: BTreeMap::new(),
        stamps: BTreeMap::new(),
        txts_unmatched: BTreeMap::new(),
        ids: BTreeMap::new(),
        reanchor: BTreeMap::new(),
    };
    let ids_a = tx_ids(&a);
    let ids_b = b.as_ref().map(tx_ids).unwrap_or_default();
    let ids_of = |l: &Log| if l.role == "a" { &ids_a } else { &ids_b };
    let mut obsv_tables = Vec::new();
    for (sender, receiver) in [(Some(&a), b.as_ref()), (b.as_ref(), Some(&a))] {
        let Some(sender) = sender else { continue };
        let dir = if sender.role == "a" {
            "a_to_b"
        } else {
            "b_to_a"
        };
        let (pkt, dup, unmatched, check) = join_direction(sender, receiver, ids_of(sender));
        report.stamps.insert(dir.into(), check);
        let attrs = Value::map()
            .with("dir", dir)
            .with("sender", sender.role.as_str())
            .with("receiver", if sender.role == "a" { "b" } else { "a" });
        report
            .pkt_rows
            .insert(dir.into(), pkt.first().map_or(0, |c| c.rows.len()));
        report
            .unmatched
            .insert(dir.into(), unmatched.first().map_or(0, |c| c.rows.len()));
        obsv_tables.extend(chunks("pkt", &pkt, &attrs));
        obsv_tables.extend(chunks("dup", &dup, &attrs));
        obsv_tables.extend(chunks("unmatched", &unmatched, &attrs));
    }
    // Echoes: arrivals at an endpoint of probes it sent itself (class and NAT probes).
    for l in std::iter::once(&a).chain(b.iter()) {
        let Some(rx) = l.tables.get("rx") else {
            continue;
        };
        let flows = rows_of(rx, "flow");
        let keep: Vec<usize> = (0..rx.rows)
            .filter(|&j| flows[j].is_some_and(|f| sender_owns(l, f)))
            .collect();
        if keep.is_empty() {
            continue;
        }
        let cols: Vec<Col> = rx
            .cols
            .iter()
            .map(|c| copy_col(c, keep.iter().map(|&j| c.rows[j]).collect()))
            .collect();
        obsv_tables.extend(chunks(
            "echo",
            &cols,
            &Value::map().with("endpoint", l.role.as_str()),
        ));
    }
    // Per-endpoint raw tables copied as-is; tables merge does not know go to OBSV unchanged.
    let mut clok = Vec::new();
    let mut ctxs = Vec::new();
    for l in std::iter::once(&a).chain(b.iter()) {
        let attrs = Value::map().with("endpoint", l.role.as_str());
        for (name, t) in &l.tables {
            let target = match name.as_str() {
                "tx" | "txts" | "rx" => continue,
                "pairs" | "exchange" => &mut clok,
                "ifstats" | "wifi" | "netstack" | "qdisc" => &mut ctxs,
                _ => &mut obsv_tables,
            };
            target.extend(chunks(name, &t.cols, &attrs));
        }
        let ids = ids_of(l);
        let orphans = unmatched_stamps(l, ids);
        let n = orphans.first().map_or(0, |c| c.rows.len());
        report.txts_unmatched.insert(l.role.clone(), n);
        report.ids.insert(l.role.clone(), id_check(l, ids));
        report.reanchor.insert(l.role.clone(), ids.check);
        obsv_tables.extend(chunks("txts_unmatched", &orphans, &attrs));
    }
    // One OBSV section per table chunk keeps sections bounded in memory.
    for t in obsv_tables {
        sections.push(Section::new(b"OBSV", 0, Map::new()).with_table(t));
    }
    for t in clok {
        sections.push(Section::new(b"CLOK", 0, Map::new()).with_table(t));
    }
    for t in ctxs {
        sections.push(Section::new(b"CTXS", 0, Map::new()).with_table(t));
    }
    // EVNT: all events, pii pointers regenerated from wrapped values.
    let events: Vec<Value> = a
        .events
        .iter()
        .chain(b.iter().flat_map(|b| b.events.iter()))
        .cloned()
        .collect();
    let mut epii = Map::new();
    for (i, e) in events.iter().enumerate() {
        if let Some(Value::Map(d)) = e.get("detail") {
            for (k, v) in d {
                if let Some(class) = v.get("pii").and_then(Value::as_str) {
                    epii.insert(
                        Key(format!("/events/{i}/detail/{}/value", k.0)),
                        Value::from(class),
                    );
                }
            }
        }
    }
    let mut eh = Map::new();
    eh.insert(Key::from("events"), Value::Array(events));
    if !epii.is_empty() {
        eh.insert(Key::from("pii"), Value::Map(epii));
    }
    sections.push(Section::new(b"EVNT", 0, eh));
    // How well TX stamps joined (probe.md §4.1): misaligned ids show as implausible joins.
    let mut checks = Value::map();
    for (dir, c) in &report.stamps {
        checks = checks.with(
            dir,
            Value::map()
                .with("txts_joined", c.joined)
                .with("txts_implausible", c.implausible),
        );
    }
    for (ep, n) in &report.txts_unmatched {
        checks = checks.with(&format!("txts_unmatched_{ep}"), *n);
    }
    for (ep, c) in &report.ids {
        checks = checks
            .with(&format!("tx_unstamped_{ep}"), c.unstamped)
            .with(&format!("txts_unexplained_{ep}"), c.unexplained);
    }
    for (ep, c) in &report.reanchor {
        checks = checks
            .with(&format!("tx_reanchors_{ep}"), c.anchors)
            .with(&format!("tx_reanchored_{ep}"), c.rows);
    }
    if let Some(h) = sections[0].head_mut() {
        h.insert(Key::from("merge_checks"), checks);
    }
    let mut file = PtfFile {
        major: pt_format::container::MAJOR,
        minor: pt_format::container::MINOR,
        sections,
    };
    pt_format::canonicalize(&mut file);
    Ok((file, report))
}

/// Write a trace canonically and atomically (temp file + rename). Returns the content digest.
pub fn write_trace(file: &PtfFile, out: &Path) -> pt_format::Result<String> {
    let tmp = out.with_extension("ptf.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    let d = pt_format::write(file, &WriteOptions::canonical(), &mut f)?;
    f.sync_all()?;
    std::fs::rename(&tmp, out)?;
    Ok(d)
}

/// Merge and write (no derivation).
pub fn merge(
    log_a: &Path,
    log_b: Option<&Path>,
    out: &Path,
    tool: &ToolInfo,
) -> pt_format::Result<MergeReport> {
    let (file, mut report) = merge_file(log_a, log_b, tool)?;
    report.content_digest = write_trace(&file, out)?;
    Ok(report)
}

/// Read a PTF file strictly.
pub fn read_trace(path: &Path) -> pt_format::Result<PtfFile> {
    let bytes = std::fs::read(path)?;
    Ok(pt_format::read(&bytes, ReadOptions::default())?.0)
}

/// Whether a section is one of the derived ones.
pub fn is_derived(s: &Section) -> bool {
    s.is_derived()
        || matches!(&s.body, Body::Parsed { .. } if matches!(&s.kind, b"PATH" | b"SERS" | b"PLCY" | b"VALD"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(cols: &[(&str, Vec<Option<i64>>)]) -> Tab {
        Tab {
            rows: cols.first().map_or(0, |c| c.1.len()),
            cols: cols
                .iter()
                .map(|(n, rows)| col(n, false, Enc::Rle, "id", None, rows.clone()))
                .collect(),
        }
    }

    fn sender(tx_ids: &[i64], stamps: &[(i64, i64, i64, i64)], events: Vec<Value>) -> Log {
        let n = tx_ids.len();
        let tx = tab(&[
            ("sock", vec![Some(0); n]),
            ("flow", vec![Some(1); n]),
            ("seq", (0..n as i64).map(Some).collect()),
            ("id", tx_ids.iter().copied().map(Some).collect()),
        ]);
        let pick = |k: usize| {
            stamps
                .iter()
                .map(|s| Some([s.0, s.1, s.2, s.3][k]))
                .collect()
        };
        let txts = tab(&[
            ("sock", pick(0)),
            ("id", pick(1)),
            ("kind", pick(2)),
            ("real", pick(3)),
        ]);
        Log {
            role: "a".into(),
            meta: Value::map(),
            tables: BTreeMap::from([("tx".to_string(), tx), ("txts".to_string(), txts)]),
            flows: Vec::new(),
            events,
            info: LogInfo {
                role: "a".into(),
                content_digest: String::new(),
                stopped: None,
            },
        }
    }

    fn send_error(detail: Value) -> Value {
        Value::map()
            .with("type", "send_error")
            .with("detail", detail)
    }

    #[test]
    fn join_keeps_every_stamp_and_checks_ids() {
        // tx ids 0, 1, 2 on socket 0. Stamps: id 0 twice (a duplicate), id 1 SCHED and SND,
        // id 3 (no tx row, not burned), id 5 (burned), id 7 (burned, then unburned), id 9 (an
        // unobserved send such as an echo).
        let log = sender(
            &[0, 1, 2],
            &[
                (0, 0, 0, 100),
                (0, 0, 0, 105),
                (0, 1, 0, 110),
                (0, 1, 1, 111),
                (0, 3, 0, 120),
                (0, 5, 0, 130),
                (0, 7, 0, 140),
                (0, 9, 0, 150),
            ],
            vec![
                send_error(Value::map().with("sock", 0u64).with("burned_id", 5u64)),
                send_error(Value::map().with("sock", 0u64).with("burned_id", 7u64)),
                send_error(Value::map().with("sock", 0u64).with("unburned_id", 7u64)),
                Value::map()
                    .with("type", "raw_sent")
                    .with("detail", Value::map().with("sock", 0u64).with("id", 9u64)),
            ],
        );
        let (pkt, _, _, check) = join_direction(&log, None, &tx_ids(&log));
        let sched = &pkt.iter().find(|c| c.name == "tx_sched").unwrap().rows;
        assert_eq!(sched, &vec![Some(100), Some(110), None]);
        assert_eq!(check.joined, 2);
        // The duplicate and the three stamps of ids without a tx row are kept.
        let orphans = unmatched_stamps(&log, &tx_ids(&log));
        let ids = &orphans.iter().find(|c| c.name == "id").unwrap().rows;
        let real = &orphans.iter().find(|c| c.name == "real").unwrap().rows;
        assert_eq!(ids, &vec![Some(0), Some(3), Some(5), Some(7), Some(9)]);
        assert_eq!(
            real,
            &vec![Some(105), Some(120), Some(130), Some(140), Some(150)]
        );
        // tx id 2 has no stamp; ids 3 and 7 are unexplained (5 was burned, 9 an echo).
        assert_eq!(
            id_check(&log, &tx_ids(&log)),
            IdCheck {
                unstamped: 1,
                unexplained: 2
            }
        );
    }

    #[test]
    fn ids_off_by_one_are_caught_although_every_join_looks_plausible() {
        // Predicted ids one too low: every tx row joins its successor's stamp (microseconds
        // later, so the time window passes), the first row has none, and the last stamp's id
        // is unexplained.
        let log = sender(
            &[0, 1, 2],
            &[(0, 1, 0, 100), (0, 2, 0, 101), (0, 3, 0, 102)],
            Vec::new(),
        );
        assert_eq!(
            id_check(&log, &tx_ids(&log)),
            IdCheck {
                unstamped: 1,
                unexplained: 1
            }
        );
        let aligned = sender(
            &[0, 1, 2],
            &[(0, 0, 0, 100), (0, 1, 0, 101), (0, 2, 0, 102)],
            Vec::new(),
        );
        assert_eq!(id_check(&aligned, &tx_ids(&aligned)), IdCheck::default());
    }

    const MS: i64 = 1_000_000;
    const US: i64 = 1_000;
    /// REALTIME minus MONO_RAW in [`timed`] logs.
    const R: i64 = 1_000_000_000;

    /// A log with `tx` rows (logged id, user send time in MONO_RAW) on socket 0, SCHED stamps
    /// (kernel id, REALTIME), and clock pairs mapping MONO_RAW + R to REALTIME.
    fn timed(rows: &[(i64, i64)], stamps: &[(i64, i64)], events: Vec<Value>) -> Log {
        let mut log = sender(
            &rows.iter().map(|r| r.0).collect::<Vec<_>>(),
            &stamps.iter().map(|s| (0, s.0, 0, s.1)).collect::<Vec<_>>(),
            events,
        );
        let n = rows.len();
        let tx = log.tables.get_mut("tx").unwrap();
        let extra = tab(&[
            ("tx_intended", rows.iter().map(|r| Some(r.1)).collect()),
            ("tx_user_lag", vec![Some(0); n]),
        ]);
        tx.cols.extend(extra.cols);
        log.tables.insert(
            "pairs".into(),
            tab(&[
                ("mono", vec![Some(0), Some(10_000 * MS)]),
                ("real", vec![Some(R), Some(10_000 * MS + R)]),
            ]),
        );
        log
    }

    fn failure(ty: &str, t: i64, burned: Option<u64>, unburned: Option<u64>, mode: &str) -> Value {
        Value::map().with("t", t as u64).with("type", ty).with(
            "detail",
            Value::map()
                .with("sock", 0u64)
                .with("burned_id", burned)
                .with("unburned_id", unburned)
                .with("tx_ids", mode),
        )
    }

    /// The corrected ids of `log`'s `tx` rows, and how they were re-anchored.
    fn corrected(log: &Log) -> (Vec<i64>, Reanchor) {
        let ids = tx_ids(log);
        let t = &log.tables["tx"];
        let rows = rows_of(t, "id")
            .into_iter()
            .map(|i| ids.id(0, i.unwrap()))
            .collect();
        (rows, ids.check)
    }

    /// One datagram per call, 1 ms apart, stamped 5 µs after its call; the call at index 3
    /// fails and is recorded with `burned_id` 3, but the kernel consumed no id.
    fn assumed_burn(mode: &str) -> Log {
        let user = |c: i64| 10 * MS + c * MS;
        let rows = [
            (0, user(0)),
            (1, user(1)),
            (2, user(2)),
            (4, user(4)),
            (5, user(5)),
            (6, user(6)),
        ];
        let stamps: Vec<(i64, i64)> = [0, 1, 2, 4, 5, 6]
            .iter()
            .enumerate()
            .map(|(k, &c)| (k as i64, user(c) + R + 5 * US))
            .collect();
        timed(
            &rows,
            &stamps,
            vec![failure(
                "send_partial",
                user(3) + 10 * US,
                Some(3),
                None,
                mode,
            )],
        )
    }

    #[test]
    fn an_assumed_burn_that_consumed_nothing_is_undone() {
        let log = assumed_burn("predicted");
        assert_eq!(
            corrected(&log),
            (
                vec![0, 1, 2, 3, 4, 5],
                Reanchor {
                    anchors: 1,
                    rows: 3
                }
            )
        );
        // Every row now joins its own stamp, and every stamp is explained.
        let ids = tx_ids(&log);
        let (pkt, _, _, _) = join_direction(&log, None, &ids);
        let sched = &pkt.iter().find(|c| c.name == "tx_sched").unwrap().rows;
        let want: Vec<Option<i64>> = [0, 1, 2, 4, 5, 6]
            .iter()
            .map(|c| Some(10 * MS + c * MS + R + 5 * US))
            .collect();
        assert_eq!(sched, &want);
        assert_eq!(id_check(&log, &ids), IdCheck::default());
        let orphans = unmatched_stamps(&log, &ids);
        assert_eq!(orphans.first().map_or(0, |c| c.rows.len()), 0);
        // Without re-anchoring the same log shows the shift.
        assert_eq!(
            id_check(&log, &TxIds::default()),
            IdCheck {
                unstamped: 1,
                unexplained: 1
            }
        );
    }

    #[test]
    fn explicit_ids_are_never_re_anchored() {
        let log = assumed_burn("explicit");
        assert_eq!(
            corrected(&log),
            (vec![0, 1, 2, 4, 5, 6], Reanchor::default())
        );
    }

    #[test]
    fn an_unrecorded_burn_is_located_inside_its_call() {
        // Two datagrams per call, 1 ms apart, stamped 5 and 6 µs after their call. In call 1 the
        // middle one of three fails with no burn recorded, but the kernel consumed id 3: the
        // last one of the call and everything after are one id higher than logged.
        let user = |c: i64| 10 * MS + c * MS;
        let rows = [
            (0, user(0)),
            (1, user(0)),
            (2, user(1)),
            (3, user(1)),
            (4, user(2)),
            (5, user(2)),
        ];
        let stamps = [
            (0, user(0) + R + 5 * US),
            (1, user(0) + R + 6 * US),
            (2, user(1) + R + 5 * US),
            (4, user(1) + R + 7 * US),
            (5, user(2) + R + 5 * US),
            (6, user(2) + R + 6 * US),
        ];
        let log = timed(
            &rows,
            &stamps,
            vec![failure(
                "send_error",
                user(1) + 20 * US,
                None,
                None,
                "predicted",
            )],
        );
        assert_eq!(
            corrected(&log),
            (
                vec![0, 1, 2, 4, 5, 6],
                Reanchor {
                    anchors: 1,
                    rows: 3
                }
            )
        );
        assert_eq!(id_check(&log, &tx_ids(&log)).unexplained, 0);
    }

    #[test]
    fn a_correct_prediction_keeps_its_ids() {
        // As `assumed_burn`, but the failure did consume id 3 (no stamp for it).
        let user = |c: i64| 10 * MS + c * MS;
        let rows: Vec<(i64, i64)> = [0, 1, 2, 4, 5, 6].iter().map(|&c| (c, user(c))).collect();
        let stamps: Vec<(i64, i64)> = rows.iter().map(|r| (r.0, r.1 + R + 5 * US)).collect();
        let log = timed(
            &rows,
            &stamps,
            vec![failure(
                "send_partial",
                user(3) + 10 * US,
                Some(3),
                None,
                "predicted",
            )],
        );
        assert_eq!(
            corrected(&log),
            (vec![0, 1, 2, 4, 5, 6], Reanchor::default())
        );
        assert_eq!(id_check(&log, &tx_ids(&log)), IdCheck::default());
    }

    #[test]
    fn offsets_accumulate_over_failures_and_correct_raw_sends() {
        // One datagram per call, 1 ms apart, stamped 5 µs after its call. Calls 3 and 6 fail
        // and are recorded with `burned_id` 3 and 6, but neither consumed an id: the rows after
        // call 3 are one id too high, those after call 6 two. A `raw_sent` (no `tx` row) at
        // call 10 was logged as id 10 and took id 8; its stamp falls in the last row's one-second
        // window.
        let user = |c: i64| 10 * MS + c * MS;
        let calls = [0, 1, 2, 4, 5, 7, 8, 9];
        let logged = [0, 1, 2, 4, 5, 7, 8, 9];
        let rows: Vec<(i64, i64)> = logged
            .iter()
            .zip(calls)
            .map(|(&i, c)| (i, user(c)))
            .collect();
        let mut stamps: Vec<(i64, i64)> = calls
            .iter()
            .enumerate()
            .map(|(k, &c)| (k as i64, user(c) + R + 5 * US))
            .collect();
        stamps.push((8, user(10) + R + 5 * US));
        let raw = Value::map()
            .with("t", (user(10) + 10 * US) as u64)
            .with("type", "raw_sent")
            .with("detail", Value::map().with("sock", 0u64).with("id", 10u64));
        let log = timed(
            &rows,
            &stamps,
            vec![
                failure(
                    "send_partial",
                    user(3) + 10 * US,
                    Some(3),
                    None,
                    "predicted",
                ),
                failure(
                    "send_partial",
                    user(6) + 10 * US,
                    Some(6),
                    None,
                    "predicted",
                ),
                raw,
            ],
        );
        assert_eq!(
            corrected(&log),
            (
                vec![0, 1, 2, 3, 4, 5, 6, 7],
                Reanchor {
                    anchors: 2,
                    rows: 5
                }
            )
        );
        let ids = tx_ids(&log);
        assert_eq!(ids.steps[&0], vec![(4, -1), (7, -2)]);
        // Each burn is corrected with the offset before its failure; the raw send with both.
        assert_eq!(ids.burned, HashSet::from([(0, 3), (0, 5), (0, 8)]));
        assert_eq!(id_check(&log, &ids), IdCheck::default());
    }

    #[test]
    fn an_undone_burn_that_did_consume_is_restored() {
        // One datagram per call, 1 ms apart. Call 2's assumed burn (id 2) consumed nothing, so
        // later rows are one too high. Call 5 sends partially (`burned_id` 5) and its retry
        // fails at once (`unburned_id` 5), so call 6 reuses logged id 5; but the partial send did
        // consume an id, which restores the logged ids from call 6 on.
        let user = |c: i64| 10 * MS + c * MS;
        let calls = [0, 1, 3, 4, 6, 7, 8];
        let logged = [0, 1, 3, 4, 5, 6, 7];
        let truth = [0, 1, 2, 3, 5, 6, 7];
        let rows: Vec<(i64, i64)> = logged
            .iter()
            .zip(calls)
            .map(|(&i, c)| (i, user(c)))
            .collect();
        let stamps: Vec<(i64, i64)> = truth
            .iter()
            .zip(calls)
            .map(|(&i, c)| (i, user(c) + R + 5 * US))
            .collect();
        let log = timed(
            &rows,
            &stamps,
            vec![
                failure(
                    "send_partial",
                    user(2) + 10 * US,
                    Some(2),
                    None,
                    "predicted",
                ),
                failure(
                    "send_partial",
                    user(5) + 10 * US,
                    Some(5),
                    None,
                    "predicted",
                ),
                failure("send_error", user(5) + 20 * US, None, Some(5), "predicted"),
            ],
        );
        assert_eq!(
            corrected(&log),
            (
                truth.to_vec(),
                Reanchor {
                    anchors: 2,
                    rows: 2
                }
            )
        );
        let ids = tx_ids(&log);
        // The undo removes the burn it undoes (logged 5, corrected to 4), not logged id 5's.
        assert_eq!(ids.burned, HashSet::from([(0, 2)]));
        assert_eq!(id_check(&log, &ids), IdCheck::default());
    }

    #[test]
    fn a_second_failure_in_the_same_call_starts_at_the_first_anchor() {
        // Two datagrams in call 0, three in call 1, two in call 2. In call 1 a datagram after
        // the first fails with no burn recorded and consumes id 3; its retry, still before call
        // 2, fails again with nothing recorded and consumes none. Both events fall in call 1,
        // so the second's candidates start at the first's anchor.
        let user = |c: i64| 10 * MS + c * MS;
        let rows = [
            (0, user(0)),
            (1, user(0)),
            (2, user(1)),
            (3, user(1)),
            (4, user(1)),
            (5, user(2)),
            (6, user(2)),
        ];
        let stamps = [
            (0, user(0) + R + 5 * US),
            (1, user(0) + R + 6 * US),
            (2, user(1) + R + 5 * US),
            (4, user(1) + R + 7 * US),
            (5, user(1) + R + 8 * US),
            (6, user(2) + R + 5 * US),
            (7, user(2) + R + 6 * US),
        ];
        let log = timed(
            &rows,
            &stamps,
            vec![
                failure("send_error", user(1) + 20 * US, None, None, "predicted"),
                failure("send_error", user(1) + 30 * US, None, None, "predicted"),
            ],
        );
        assert_eq!(
            corrected(&log),
            (
                vec![0, 1, 2, 4, 5, 6, 7],
                Reanchor {
                    anchors: 1,
                    rows: 4
                }
            )
        );
        assert_eq!(tx_ids(&log).steps[&0], vec![(3, 1)]);
        assert_eq!(id_check(&log, &tx_ids(&log)).unexplained, 0);
    }

    #[test]
    fn clock_pairs_are_interpolated() {
        let m = MonoToReal(vec![(0, 100), (1_000, 200)]);
        assert_eq!(m.interp(500), Some(650));
        assert_eq!(m.interp(-10), Some(90));
        assert_eq!(m.interp(2_000), Some(2_200));
        assert_eq!(MonoToReal(Vec::new()).interp(5), None);
    }
}
