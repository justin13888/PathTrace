//! Per-direction path model fields (docs/design/derivation.md "Per-direction fields").

use std::collections::{BTreeMap, HashMap};

use pt_format::{Column, Enc, Table, Value, Values};

use crate::clock::TimeBase;
use crate::raw::Raw;

pub const SAT_THRESHOLD_NS: i64 = 2_500_000;

/// One transmitted probe packet on the trace time axis.
#[derive(Debug, Clone)]
pub struct Pkt {
    pub flow: i64,
    pub seq: i64,
    pub size: i64,
    pub phase: i64,
    pub train: i64,
    pub train_idx: i64,
    pub tos_tx: i64,
    pub tos_rx: Option<i64>,
    pub tx: Option<i64>,
    pub rx: Option<i64>,
    pub kind: String,
    /// Receiving socket and its cumulative drop count at arrival (PTF 1.1 `rxq_drops`).
    pub rx_sock: Option<i64>,
    pub rxq_drops: Option<i64>,
    /// Lost inside the receiving host, not on the path (`hostdrop.rxq-gap/1`): excluded from
    /// every loss statistic.
    pub host_drop: bool,
}

impl Pkt {
    pub fn owd(&self) -> Option<i64> {
        Some(self.rx? - self.tx?)
    }
}

fn quantile(v: &mut [f64], q: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let i = ((v.len() - 1) as f64 * q).round() as usize;
    Some(v[i])
}

fn median(v: &mut [f64]) -> Option<f64> {
    quantile(v, 0.5)
}

/// Wilson 95% interval for k successes in n trials.
pub fn wilson(k: f64, n: f64) -> (f64, f64) {
    wilson_z(k, n, 1.96)
}

/// Wilson interval for k successes in n trials at the two-sided level given by its z quantile.
pub fn wilson_z(k: f64, n: f64, z: f64) -> (f64, f64) {
    if n <= 0.0 {
        return (0.0, 1.0);
    }
    let p = k / n;
    let d = 1.0 + z * z / n;
    let c = (p + z * z / (2.0 * n)) / d;
    let h = z * ((p * (1.0 - p) + z * z / (4.0 * n)) / n).sqrt() / d;
    ((c - h).max(0.0), (c + h).min(1.0))
}

fn field(status: &str, method: &str, confidence: f64) -> Value {
    Value::map()
        .with("status", status)
        .with("method", method)
        .with("confidence", (confidence * 1000.0).round() / 1000.0)
}

/// Build the packet list of one direction.
pub fn packets(raw: &Raw, tb: &TimeBase, dir: &str) -> (Vec<Pkt>, BTreeMap<String, u64>) {
    let (pkts, ts_src, _) = packets_marked(raw, tb, dir);
    (pkts, ts_src)
}

/// [`packets`], with how ambiguous the host-drop marking was.
fn packets_marked(
    raw: &Raw,
    tb: &TimeBase,
    dir: &str,
) -> (Vec<Pkt>, BTreeMap<String, u64>, HostDropMarks) {
    let (snd, rcv) = if dir == "a_to_b" {
        ("a", "b")
    } else {
        ("b", "a")
    };
    let mut out = Vec::new();
    let mut ts_src: BTreeMap<String, u64> = BTreeMap::new();
    let Some(t) = raw.table(&format!("pkt[{dir}]")) else {
        return (out, ts_src, HostDropMarks::default());
    };
    for i in 0..t.n {
        let flow = t.get("flow", i).unwrap_or(-1);
        let sched = t.get("tx_sched", i);
        let snd_lag = t.get("tx_snd_lag", i);
        let tx = match (sched, snd_lag) {
            (Some(s), Some(l)) => {
                *ts_src.entry("snd".into()).or_default() += 1;
                tb.real(snd, s + l)
            }
            (Some(s), None) => {
                *ts_src.entry("sched".into()).or_default() += 1;
                tb.real(snd, s)
            }
            _ => {
                *ts_src.entry("user".into()).or_default() += 1;
                t.get("tx_intended", i)
                    .and_then(|m| tb.mono(snd, m + t.get("tx_user_lag", i).unwrap_or(0)))
            }
        };
        let rx = t.get("rx", i).and_then(|r| tb.real(rcv, r));
        out.push(Pkt {
            flow,
            seq: t.get("seq", i).unwrap_or(0),
            size: t.get("size", i).unwrap_or(0),
            phase: t.get("phase", i).unwrap_or(0),
            train: t.get("train", i).unwrap_or(0),
            train_idx: t.get("train_idx", i).unwrap_or(0),
            tos_tx: t.get("tos_tx", i).unwrap_or(0),
            tos_rx: t.get("tos_rx", i),
            tx,
            rx,
            kind: raw.flow_kind(flow).to_string(),
            rx_sock: t.get("rx_sock", i),
            rxq_drops: t.get("rxq_drops", i),
            host_drop: false,
        });
    }
    let marks = mark_host_drops(&mut out);
    (out, ts_src, marks)
}

/// Gaps whose host-drop candidates outnumber the socket's drops in them, and those excess
/// candidates, which stay losses (`hostdrop.rxq-gap/1`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostDropMarks {
    pub ambiguous_gaps: usize,
    pub ambiguous_losses: usize,
}

/// A gap between two consecutive arrivals on one receiving socket across which the socket
/// dropped datagrams (`rxq_drops` increased; docs/design/derivation.md, Host drops).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostDropGap {
    pub sock: i64,
    /// Transmit times (trace ns) of the two arrivals bounding the gap.
    pub tx_lo: i64,
    pub tx_hi: i64,
    /// Datagrams the socket dropped in the gap.
    pub drops: i64,
}

/// Gaps with socket drops, per receiving socket, in arrival order (`hostdrop.rxq-gap/1`).
pub fn host_drop_gaps(pkts: &[Pkt]) -> Vec<HostDropGap> {
    let mut by_sock: BTreeMap<i64, Vec<(i64, i64, i64)>> = BTreeMap::new();
    for p in pkts {
        if let (Some(s), Some(rx), Some(tx), Some(d)) = (p.rx_sock, p.rx, p.tx, p.rxq_drops) {
            by_sock.entry(s).or_default().push((rx, tx, d));
        }
    }
    let mut gaps = Vec::new();
    for (sock, mut v) in by_sock {
        v.sort_unstable();
        for w in v.windows(2) {
            let ((_, t0, d0), (_, t1, d1)) = (w[0], w[1]);
            if d1 > d0 {
                gaps.push(HostDropGap {
                    sock,
                    tx_lo: t0.min(t1),
                    tx_hi: t0.max(t1),
                    drops: d1 - d0,
                });
            }
        }
    }
    gaps
}

/// Mark lost packets that fall in a host-drop gap of the socket their flow arrives on, at
/// most as many per gap as the socket dropped in it (earliest transmit time first).
fn mark_host_drops(pkts: &mut [Pkt]) -> HostDropMarks {
    let mut marks = HostDropMarks::default();
    let gaps = host_drop_gaps(pkts);
    if gaps.is_empty() {
        return marks;
    }
    // Receiving socket of each flow: the one most of its arrivals used.
    let mut votes: BTreeMap<(i64, i64), usize> = BTreeMap::new();
    for p in pkts.iter() {
        if let Some(s) = p.rx_sock {
            *votes.entry((p.flow, s)).or_default() += 1;
        }
    }
    let mut flow_sock: BTreeMap<i64, (i64, usize)> = BTreeMap::new();
    for ((f, s), n) in votes {
        let e = flow_sock.entry(f).or_insert((s, n));
        if n > e.1 {
            *e = (s, n);
        }
    }
    // Lost packets with their transmit time and receiving socket, in transmit order. A flow
    // with no arrival at all is assumed to use the main socket (index 0).
    let mut lost: Vec<(i64, i64, usize)> = pkts
        .iter()
        .enumerate()
        .filter(|(_, p)| p.rx.is_none())
        .filter_map(|(i, p)| Some((p.tx?, flow_sock.get(&p.flow).map_or(0, |x| x.0), i)))
        .collect();
    lost.sort_unstable();
    for g in &gaps {
        let lo = lost.partition_point(|x| x.0 < g.tx_lo);
        let hi = lost.partition_point(|x| x.0 <= g.tx_hi);
        let cands: Vec<usize> = lost[lo..hi.max(lo)]
            .iter()
            .filter(|(_, s, i)| *s == g.sock && !pkts[*i].host_drop)
            .map(|x| x.2)
            .collect();
        let n = usize::try_from(g.drops).unwrap_or(0).min(cands.len());
        for &i in &cands[..n] {
            pkts[i].host_drop = true;
        }
        if cands.len() > n {
            marks.ambiguous_gaps += 1;
            marks.ambiguous_losses += cands.len() - n;
        }
    }
    marks
}

/// Saturating flow kinds.
pub fn saturating(kind: &str) -> bool {
    matches!(kind, "heavy" | "class-sat")
}

/// Loss onset of one saturating flow that lost packets (`queue.loss-onset/3`).
struct Onset {
    /// A `heavy` flow: it overdrives and so probes the buffer (probe.md §7). A class
    /// saturation (3 s) only holds the controller's queue target, so its losses come at its
    /// maximum delay whatever the discipline.
    heavy: bool,
    /// Its onset depth (median over its losses of the maximum queueing delay in the 500 ms
    /// before each) over its maximum queueing delay.
    ratio: f64,
    /// Losses with queueing delay below 2 ms.
    low_queue: bool,
}

/// Queue discipline from the lossy saturating flows (`queue.loss-onset/3`, derivation.md).
/// Every lossy flow votes on `policer`; only the heavy flows tell `droptail` from
/// `aqm_suspected`, and without a lossy heavy flow that is `unknown`.
fn queue_discipline(saturated: bool, onsets: &[Onset], ce_marks: usize) -> &'static str {
    let low = onsets.iter().filter(|o| o.low_queue).count();
    let mut heavy: Vec<f64> = onsets.iter().filter(|o| o.heavy).map(|o| o.ratio).collect();
    if !saturated {
        "unknown"
    } else if low > 0 && low * 2 >= onsets.len() {
        "policer"
    } else if ce_marks > 0 {
        "aqm_suspected"
    } else {
        match median(&mut heavy) {
            None => "unknown",
            Some(r) if r >= 0.8 => "droptail",
            Some(_) => "aqm_suspected",
        }
    }
}

/// Intervals (trace ns) during which any saturating or chirp flow was active, per direction.
pub fn loaded_intervals(pkts: &[Pkt]) -> Vec<(i64, i64)> {
    let mut by_flow: HashMap<i64, (i64, i64)> = HashMap::new();
    for p in pkts
        .iter()
        .filter(|p| saturating(&p.kind) || p.kind == "chirp")
    {
        if let Some(t) = p.tx {
            let e = by_flow.entry(p.flow).or_insert((t, t));
            e.0 = e.0.min(t);
            e.1 = e.1.max(t);
        }
    }
    let mut v: Vec<(i64, i64)> = by_flow
        .values()
        .map(|(a, b)| (*a, b + 1_500_000_000))
        .collect();
    v.sort();
    v
}

fn in_any(t: i64, iv: &[(i64, i64)]) -> bool {
    iv.iter().any(|(a, b)| t >= *a && t <= *b)
}

/// Steps of the unloaded base delay (`pathchange.base-delay-step/1`, derivation.md): `segs` are
/// the `base_delay` segments (t, delay ns) whose ±5 s window overlaps no loaded interval.
/// Returns (t, median before, median after) per change, in time order.
pub fn path_changes(segs: &[(i64, i64)]) -> Option<Vec<(i64, i64, i64)>> {
    const W: usize = 10;
    if segs.len() < 2 * W {
        return None;
    }
    let med = |s: &[(i64, i64)]| {
        let mut v: Vec<i64> = s.iter().map(|x| x.1).collect();
        v.sort_unstable();
        v[v.len() / 2]
    };
    let mean = |s: &[(i64, i64)]| s.iter().map(|x| x.1 as f64).sum::<f64>() / s.len() as f64;
    // One-way delay carries the unknown clock offset, so the threshold is absolute: 10 ms, or
    // five times the median absolute segment-to-segment difference on a noisier path.
    let mut diffs: Vec<i64> = segs.windows(2).map(|w| (w[1].1 - w[0].1).abs()).collect();
    diffs.sort_unstable();
    let limit = (10_000_000f64).max(5.0 * diffs[diffs.len() / 2] as f64);
    // (score, index, before, after) of every boundary whose median step exceeds the
    // threshold. The medians gate (robust to outliers); the mean step ranks, because it peaks
    // at the step itself where the medians plateau over several boundaries.
    let mut cands: Vec<(f64, usize, i64, i64)> = (W..=segs.len() - W)
        .filter_map(|k| {
            let (b, a) = (med(&segs[k - W..k]), med(&segs[k..k + W]));
            let d = (a - b).abs() as f64;
            let dm = (mean(&segs[k..k + W]) - mean(&segs[k - W..k])).abs();
            (d > limit).then_some((dm / limit, k, b, a))
        })
        .collect();
    cands.sort_by(|x, y| y.0.total_cmp(&x.0).then(x.1.cmp(&y.1)));
    let mut taken: Vec<(usize, i64, i64)> = Vec::new();
    for (_, k, b, a) in cands {
        if taken.iter().all(|(j, _, _)| k.abs_diff(*j) >= W) {
            taken.push((k, b, a));
        }
    }
    taken.sort_unstable();
    Some(
        taken
            .into_iter()
            .map(|(k, b, a)| (segs[k].0, b, a))
            .collect(),
    )
}

/// Derived output of one direction.
#[derive(Debug, Default)]
pub struct DirOut {
    pub fields: Value,
    pub tables: Vec<Table>,
    pub summary_rate_bps: Option<f64>,
    pub base_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub loss: Option<(f64, f64)>,
    pub buffer_bytes: Option<f64>,
    /// Saturated rate per phase (for coupling).
    pub phase_rate: BTreeMap<i64, f64>,
    pub opps: Vec<(i64, i64)>,
}

fn table(name: &str, dir: &str, cols: Vec<Column>, rows: usize) -> Table {
    let mut t = Table::new(name, rows).with_attrs(Value::map().with("dir", dir));
    t.columns = cols;
    t
}

fn ucol(name: &str, enc: Enc, unit: &str, v: Vec<u64>) -> Column {
    Column::new(name, enc, Values::U64(v)).unit(unit)
}

fn icol(name: &str, enc: Enc, unit: &str, v: Vec<i64>) -> Column {
    Column::new(name, enc, Values::I64(v)).unit(unit)
}

/// Quiet phases from the initiator's phase timeline (trace ns): P2 (quiet) and P10 (deep
/// tracking), each until the next phase start. Load inside them is excluded separately.
pub fn quiet_intervals(raw: &Raw, tb: &TimeBase) -> Vec<(i64, i64)> {
    let mut starts: Vec<(i64, u64)> = raw
        .events_of("phase_start")
        .filter(|e| e.get("endpoint").and_then(Value::as_str) == Some("a"))
        .filter_map(|e| {
            Some((
                tb.mono("a", e.get("t")?.as_u64()? as i64)?,
                e.get("detail")?.get("phase")?.as_u64()?,
            ))
        })
        .collect();
    starts.sort();
    let mut out = Vec::new();
    for (i, (t, ph)) in starts.iter().enumerate() {
        if matches!(ph, 2 | 10) {
            let end = starts.get(i + 1).map_or(i64::MAX, |n| n.0);
            out.push((*t, end));
        }
    }
    out
}

/// `qdisc.drop-count/2`: the cumulative `drops` counter restarts at each `iface_change` (the
/// sampler follows a new interface) and decreases at a qdisc replacement. Rows `(t, drops)`, in
/// the sender's mono clock like the switch times, are cut into segments at each switch and each
/// decrease; the result is the sum of last minus first per segment and the segment count.
fn segmented_drops(rows: &[(i64, i64)], switches: &[i64]) -> Option<(i64, usize)> {
    let mut rows = rows.to_vec();
    rows.sort_by_key(|r| r.0);
    let (mut total, mut segments) = (0i64, 0usize);
    let mut start: Option<(i64, i64)> = None; // (first drops, last drops) of the open segment
    let mut prev_t = i64::MIN;
    for &(t, d) in &rows {
        let switched = switches.iter().any(|&s| s > prev_t && s <= t);
        match start {
            Some((a, b)) if !switched && d >= b => start = Some((a, d)),
            _ => {
                if let Some((a, b)) = start {
                    total += b - a;
                }
                segments += 1;
                start = Some((d, d));
            }
        }
        prev_t = t;
    }
    let (a, b) = start?;
    Some((total + b - a, segments))
}

/// Whether a socket the sender sent the ladder `flows` from recorded `icmp_errors: false` in
/// META (PTF 1.2): it cannot observe ICMP errors, so their absence proves nothing
/// (`mtu.ladder/2`). A trace without the key (PTF < 1.2) keeps the `/1` verdict.
fn icmp_unobservable(raw: &Raw, sender: &str, flows: &[i64]) -> bool {
    let socks: Vec<&str> = flows
        .iter()
        .map(|f| {
            raw.flows
                .get(&(*f as u64))
                .and_then(|v| v.get("sock"))
                .and_then(Value::as_str)
                .unwrap_or("main")
        })
        .collect();
    raw.meta
        .get("endpoints")
        .and_then(|e| e.get(sender))
        .and_then(|e| e.get("sockets"))
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .filter(|s| {
            s.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| socks.contains(&n))
        })
        .any(|s| s.get("icmp_errors").and_then(Value::as_bool) == Some(false))
}

/// The rise of a host-wide cumulative counter over `(t, value)` rows, taken whole (no
/// `iface_change` segmentation: the counter does not restart when the sampler follows another
/// interface): `Err` when it decreases between consecutive rows (a wrap or a reboot), `None`
/// without rows.
fn counter_rise(rows: &[(i64, i64)]) -> Option<Result<i64, ()>> {
    let mut rows = rows.to_vec();
    rows.sort_by_key(|r| r.0);
    if rows.windows(2).any(|w| w[1].1 < w[0].1) {
        return Some(Err(()));
    }
    Some(Ok(rows.last()?.1 - rows.first()?.1))
}

/// `hostdrop.host-fullsock/1`: host drops at a receiver without `rxq_drops`, from the
/// host-wide `netstack.udp_fullsock` (PTF 1.2, macOS; docs/design/derivation.md, Host drops).
/// `None` when the receiver recorded no such counter.
fn host_fullsock(raw: &Raw, receiver: &str) -> Option<Value> {
    const M: &str = "hostdrop.host-fullsock/1";
    let ns = raw.table(&format!("netstack[{receiver}]"))?;
    let rows: Vec<(i64, i64)> = ns
        .col("t")
        .iter()
        .zip(ns.col("udp_fullsock"))
        .filter_map(|(t, v)| Some(((*t)?, (*v)?)))
        .collect();
    let source = Value::Array(vec![Value::from("netstack")]);
    Some(match counter_rise(&rows)? {
        Err(()) => field("unknown", M, 0.0).with("reason", "host-wide counter decreased"),
        // No UDP socket on the host was dropped into, so the probe's sockets dropped nothing.
        Ok(0) => field("known", M, 0.9)
            .with("packets", 0u64)
            .with("source", source),
        // Which socket dropped is unknown: the rise is context, not a count of host drops.
        Ok(rise) => field("unknown", M, 0.0)
            .with("reason", "host-wide counter rose")
            .with("host_socket_drops", rise)
            .with("source", source),
    })
}

pub fn derive_dir(raw: &Raw, tb: &TimeBase, dir: &str, others_loaded: &[(i64, i64)]) -> DirOut {
    let (pkts, ts_src, marks) = packets_marked(raw, tb, dir);
    let mut out = DirOut::default();
    // Which transmit timestamp source each packet's send time came from (SND > SCHED > user).
    let mut f = Value::map().with(
        "timestamps",
        field("known", "timestamps.source-count/1", 1.0).with(
            "counts",
            Value::Map(
                ts_src
                    .iter()
                    .map(|(k, v)| (pt_format::Key(k.clone()), Value::from(*v)))
                    .collect(),
            ),
        ),
    );
    // Host drops at the receiver (excluded from every loss statistic) and drops in the
    // sender's own egress qdisc (docs/design/derivation.md, Host drops).
    let rxq_known = pkts.iter().any(|p| p.rxq_drops.is_some());
    let gaps = host_drop_gaps(&pkts);
    f = f.with(
        "host_drops",
        if rxq_known {
            field("known", "hostdrop.rxq-gap/1", 0.9)
                .with("packets", pkts.iter().filter(|p| p.host_drop).count())
                .with("gaps", gaps.len())
                .with("socket_drops", gaps.iter().map(|g| g.drops).sum::<i64>())
                .with("ambiguous_gaps", marks.ambiguous_gaps)
                .with("ambiguous_losses", marks.ambiguous_losses)
                .with("source", Value::Array(vec![Value::from("pkt")]))
        } else {
            let receiver = if dir == "a_to_b" { "b" } else { "a" };
            host_fullsock(raw, receiver).unwrap_or_else(|| {
                field("unknown", "hostdrop.rxq-gap/1", 0.0)
                    .with("reason", "no rxq_drops in this trace (PTF 1.0)")
            })
        },
    );
    let sender = if dir == "a_to_b" { "a" } else { "b" };
    f = f.with(
        "local_qdisc_drops",
        match raw.table(&format!("qdisc[{sender}]")) {
            Some(q) => {
                let rows: Vec<(i64, i64)> = q
                    .col("t")
                    .iter()
                    .zip(q.col("drops"))
                    .filter_map(|(t, d)| Some(((*t)?, (*d)?)))
                    .collect();
                let switches: Vec<i64> = raw
                    .events_of("iface_change")
                    .filter(|e| e.get("endpoint").and_then(Value::as_str) == Some(sender))
                    .filter_map(|e| Some(e.get("t")?.as_u64()? as i64))
                    .collect();
                match segmented_drops(&rows, &switches) {
                    Some((drops, segments)) => field("known", "qdisc.drop-count/2", 1.0)
                        .with("drops", drops)
                        .with("segments", segments)
                        .with("source", Value::Array(vec![Value::from("qdisc")])),
                    None => field("unknown", "qdisc.drop-count/2", 0.0),
                }
            }
            // PTF 1.0, or a macOS sender, which has no qdisc (probe.md §9.6).
            None => field("unknown", "qdisc.drop-count/2", 0.0)
                .with("reason", "no qdisc counters recorded"),
        },
    );
    let loaded = loaded_intervals(&pkts);
    let quiet_phases = quiet_intervals(raw, tb);
    let quiet =
        |t: i64| in_any(t, &quiet_phases) && !in_any(t, &loaded) && !in_any(t, others_loaded);
    let src = |tables: &[&str]| {
        Value::Array(
            tables
                .iter()
                .map(|t| Value::from(format!("{t}[{dir}]")))
                .collect(),
        )
    };

    // --- base delay (light flow) ---
    let light: Vec<&Pkt> = pkts.iter().filter(|p| p.kind == "light").collect();
    let mut segs: Vec<(i64, i64)> = Vec::new();
    if let (Some(t0), Some(t1)) = (
        light.iter().filter_map(|p| p.tx).min(),
        light.iter().filter_map(|p| p.tx).max(),
    ) {
        let s = 1_000_000_000i64;
        let mut k = t0.div_euclid(s);
        while k * s <= t1 {
            let (lo, hi) = (k * s - 5 * s, k * s + 6 * s);
            if let Some(m) = light
                .iter()
                .filter(|p| p.tx.is_some_and(|t| t >= lo && t < hi))
                .filter_map(|p| p.owd())
                .min()
            {
                segs.push((k * s, m));
            }
            k += 1;
        }
    }
    let base_at = |t: i64| -> Option<i64> {
        if segs.is_empty() {
            return None;
        }
        let i = segs.partition_point(|s| s.0 <= t).saturating_sub(1);
        Some(segs[i].1)
    };
    let mut bvals: Vec<f64> = segs.iter().map(|s| s.1 as f64).collect();
    let base_med = median(&mut bvals);
    out.base_ms = base_med.map(|b| b / 1e6);
    f = f.with(
        "base_delay",
        match base_med {
            Some(b) => field("known", "delay.light-window-min/1", 0.9)
                .with("delay_ns", b)
                .with("series", format!("base_delay[{dir}]"))
                .with("split_method", "symmetric_assumed")
                .with("source", src(&["pkt"])),
            None => field("unknown", "delay.light-window-min/1", 0.0)
                .with("reason", "no received light-flow packets"),
        },
    );
    // --- path change (steps of the unloaded base delay) ---
    let s5 = 5_000_000_000i64;
    let unloaded: Vec<(i64, i64)> = segs
        .iter()
        .copied()
        .filter(|(t, _)| {
            ![&loaded[..], others_loaded].iter().any(|iv| {
                iv.iter()
                    .any(|(a, b)| *a <= t + s5 + 1_000_000_000 && *b >= t - s5)
            })
        })
        .collect();
    f = f.with(
        "path_change",
        match path_changes(&unloaded) {
            Some(ch) => field("known", "pathchange.base-delay-step/1", 0.7)
                .with("count", ch.len())
                .with(
                    "changes",
                    Value::Array(
                        ch.iter()
                            .map(|(t, b, a)| {
                                Value::map()
                                    .with("t", *t)
                                    .with("before_ns", *b)
                                    .with("after_ns", *a)
                            })
                            .collect(),
                    ),
                )
                .with("source", src(&["base_delay"])),
            None => field("unknown", "pathchange.base-delay-step/1", 0.0)
                .with("reason", "fewer than 20 s of unloaded base delay"),
        },
    );
    if !segs.is_empty() {
        out.tables.push(table(
            "base_delay",
            dir,
            vec![
                icol("t", Enc::Delta, "ns", segs.iter().map(|s| s.0).collect()).clock("trace"),
                icol(
                    "delay",
                    Enc::Delta,
                    "ns",
                    segs.iter().map(|s| s.1).collect(),
                ),
            ],
            segs.len(),
        ));
    }

    // --- jitter (quiet light residuals) ---
    let resid: Vec<(i64, i64)> = light
        .iter()
        .filter(|p| p.tx.is_some_and(quiet))
        .filter_map(|p| Some((p.tx?, p.owd()? - base_at(p.tx?)?)))
        .collect();
    if resid.len() >= 20 {
        let mut v: Vec<f64> = resid.iter().map(|r| r.1 as f64).collect();
        let qs: Vec<Value> = [0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99]
            .iter()
            .map(|q| Value::from(quantile(&mut v, *q).unwrap_or(0.0)))
            .collect();
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / v.len() as f64;
        let series: Vec<f64> = resid.iter().map(|r| r.1 as f64).collect();
        let acf: Vec<Value> = (1..=10)
            .map(|lag| {
                if var <= 0.0 || series.len() <= lag {
                    return Value::from(0.0);
                }
                let c = (0..series.len() - lag)
                    .map(|i| (series[i] - mean) * (series[i + lag] - mean))
                    .sum::<f64>()
                    / (series.len() - lag) as f64;
                Value::from(c / var)
            })
            .collect();
        out.jitter_ms = quantile(&mut v, 0.5).map(|m| m / 1e6);
        f = f.with(
            "jitter",
            field(
                "known",
                "jitter.light-residual/1",
                (resid.len() as f64 / 500.0).min(0.9),
            )
            .with("quantiles_ns", Value::Array(qs))
            .with(
                "quantile_levels",
                Value::Array(
                    [0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99]
                        .iter()
                        .map(|q| Value::from(*q))
                        .collect(),
                ),
            )
            .with("stddev_ns", var.sqrt())
            .with("acf", Value::Array(acf))
            .with("samples", resid.len())
            .with("series", format!("jitter[{dir}]"))
            .with("source", src(&["pkt"])),
        );
        out.tables.push(table(
            "jitter",
            dir,
            vec![
                icol("t", Enc::Delta2, "ns", resid.iter().map(|r| r.0).collect()).clock("trace"),
                icol(
                    "residual",
                    Enc::Varint,
                    "ns",
                    resid.iter().map(|r| r.1).collect(),
                ),
            ],
            resid.len(),
        ));
    } else {
        f = f.with(
            "jitter",
            field("unknown", "jitter.light-residual/1", 0.0)
                .with("reason", "too few quiet light-flow samples"),
        );
    }

    // --- size-dependent delay ---
    let mut ldel: Vec<f64> = light
        .iter()
        .filter(|p| p.tx.is_some_and(quiet))
        .filter_map(|p| Some((p.owd()? - base_at(p.tx?)?) as f64))
        .collect();
    let trains: Vec<&Pkt> = pkts.iter().filter(|p| p.kind == "train").collect();
    let mut tdel: Vec<f64> = trains
        .iter()
        .filter(|p| p.train_idx == 0 && p.tx.is_some_and(quiet))
        .filter_map(|p| Some((p.owd()? - base_at(p.tx?)?) as f64))
        .collect();
    let tsize = trains.first().map_or(1500, |p| p.size);
    if let (Some(l), Some(t)) = (median(&mut ldel), median(&mut tdel)) {
        let per_byte = (t - l) / (tsize - 128).max(1) as f64;
        f = f.with(
            "size_delay",
            field("estimated", "delay.size-slope/1", 0.5)
                .with("ns_per_byte", per_byte)
                .with("small_bytes", 128u64)
                .with("large_bytes", tsize as u64),
        );
    } else {
        f = f.with("size_delay", field("unknown", "delay.size-slope/1", 0.0));
    }

    // --- queueing delay of saturating flows, saturated windows ---
    let q_of = |p: &Pkt| -> Option<i64> { Some(p.owd()? - base_at(p.tx?)?) };
    let mut sat: Vec<(i64, i64)> = Vec::new(); // windows on rx time
    let mut heavy: Vec<&Pkt> = pkts
        .iter()
        .filter(|p| saturating(&p.kind) && p.rx.is_some())
        .collect();
    heavy.sort_by_key(|p| p.rx);
    // A heavy-flow loss also proves demand exceeded capacity (policers queue nothing): the next
    // arrival after a loss counts as saturated, like a queueing-delay excess.
    let mut lost_anchor: std::collections::HashSet<(i64, i64)> = std::collections::HashSet::new();
    {
        let mut by_flow: BTreeMap<i64, Vec<&Pkt>> = BTreeMap::new();
        for p in pkts.iter().filter(|p| saturating(&p.kind)) {
            by_flow.entry(p.flow).or_default().push(p);
        }
        for ps in by_flow.values_mut() {
            ps.sort_by_key(|p| p.seq);
            let mut pending = false;
            for p in ps.iter().filter(|p| !p.host_drop) {
                if p.rx.is_none() {
                    pending = true;
                } else if pending {
                    lost_anchor.insert((p.flow, p.seq));
                    pending = false;
                }
            }
        }
    }
    for p in &heavy {
        if q_of(p).is_some_and(|q| q > SAT_THRESHOLD_NS) || lost_anchor.contains(&(p.flow, p.seq)) {
            let r = p.rx.unwrap_or(0);
            match sat.last_mut() {
                Some(w) if r - w.1 < 50_000_000 => w.1 = r,
                _ => sat.push((r, r)),
            }
        }
    }
    sat.retain(|w| w.1 - w.0 >= 100_000_000);
    let mut rx_all: Vec<(i64, i64, i64)> = pkts
        .iter()
        .filter_map(|p| Some((p.rx?, p.size, p.phase)))
        .collect();
    rx_all.sort();
    let opps: Vec<(i64, i64)> = rx_all
        .iter()
        .filter(|(r, _, _)| in_any(*r, &sat))
        .map(|(r, s, _)| (*r, *s))
        .collect();
    // 100 ms rate bins fully inside saturated windows.
    let mut bins: Vec<(i64, f64, i64)> = Vec::new();
    for w in &sat {
        let mut b0 = w.0;
        while b0 + 100_000_000 <= w.1 {
            let b1 = b0 + 100_000_000;
            let lo = rx_all.partition_point(|x| x.0 < b0);
            let hi = rx_all.partition_point(|x| x.0 < b1);
            let bytes: i64 = rx_all[lo..hi].iter().map(|x| x.1).sum();
            let phase = rx_all.get(lo).map_or(0, |x| x.2);
            bins.push((b0, bytes as f64 * 8.0 / 0.1, phase));
            b0 = b1;
        }
    }
    let mut rates: Vec<f64> = bins.iter().map(|b| b.1).collect();
    let rate_med = median(&mut rates);
    out.summary_rate_bps = rate_med;
    for (ph, _) in bins.iter().map(|b| (b.2, ())).collect::<BTreeMap<_, _>>() {
        let mut r: Vec<f64> = bins.iter().filter(|b| b.2 == ph).map(|b| b.1).collect();
        if let Some(m) = median(&mut r) {
            out.phase_rate.insert(ph, m);
        }
    }
    // Inter-delivery CV within windows (delivery process).
    let gaps: Vec<f64> = opps
        .windows(2)
        .filter(|w| w[1].0 - w[0].0 < 50_000_000)
        .map(|w| (w[1].0 - w[0].0) as f64)
        .collect();
    let cv = if gaps.len() > 10 {
        let m = gaps.iter().sum::<f64>() / gaps.len() as f64;
        (gaps.iter().map(|g| (g - m).powi(2)).sum::<f64>() / gaps.len() as f64).sqrt() / m.max(1.0)
    } else {
        f64::NAN
    };
    let mut segs_v = Vec::new();
    for w in &sat {
        segs_v.push(
            Value::map()
                .with("t0", w.0)
                .with("t1", w.1)
                .with("quality", "saturated")
                .with("workload", "heavy"),
        );
    }
    f = f.with(
        "capacity",
        if opps.is_empty() {
            field("unknown", "capacity.saturated-arrivals/2", 0.0).with(
                "reason",
                "no saturated windows (no saturation phase, or queue never built)",
            )
        } else {
            field("known", "capacity.saturated-arrivals/2", 0.85)
                .with("representation", "opportunities")
                .with("quantum_bytes", "per-row")
                .with("opportunities", format!("capacity_opps[{dir}]"))
                .with("rate_series", format!("capacity_rate[{dir}]"))
                .with("median_rate_bps", rate_med.unwrap_or(0.0))
                .with("segments", Value::Array(segs_v))
                .with("outside_segments", "unknown")
                .with(
                    "delivery_cv",
                    if cv.is_nan() {
                        Value::Null
                    } else {
                        Value::from(cv)
                    },
                )
                .with("source", src(&["pkt"]))
        },
    );
    if !opps.is_empty() {
        out.tables.push(table(
            "capacity_opps",
            dir,
            vec![
                icol("t", Enc::Delta2, "ns", opps.iter().map(|o| o.0).collect()).clock("trace"),
                ucol(
                    "bytes",
                    Enc::Rle,
                    "B",
                    opps.iter().map(|o| o.1 as u64).collect(),
                ),
            ],
            opps.len(),
        ));
        out.tables.push(table(
            "capacity_rate",
            dir,
            vec![
                icol("t", Enc::Delta, "ns", bins.iter().map(|b| b.0).collect()).clock("trace"),
                ucol(
                    "rate",
                    Enc::Varint,
                    "bit/s",
                    bins.iter().map(|b| b.1 as u64).collect(),
                ),
            ],
            bins.len(),
        ));
    }
    out.opps = opps;

    // --- light trains (capacity_light) ---
    let mut by_train: BTreeMap<i64, Vec<&Pkt>> = BTreeMap::new();
    for p in &trains {
        by_train.entry(p.train).or_default().push(p);
    }
    let (mut tt, mut tid, mut tsent, mut trecv, mut tdisp, mut tctx) =
        (vec![], vec![], vec![], vec![], vec![], vec![]);
    let (mut oid, mut oidx, mut ooff): (Vec<u64>, Vec<u64>, Vec<Option<u64>>) =
        (vec![], vec![], vec![]);
    let mut disp_quiet = Vec::new();
    for (id, ps) in &by_train {
        let first_rx = ps.iter().filter_map(|p| p.rx).min();
        let last_rx = ps.iter().filter_map(|p| p.rx).max();
        let recv: Vec<&&Pkt> = ps.iter().filter(|p| p.rx.is_some()).collect();
        let t = ps.iter().filter_map(|p| p.tx).min().unwrap_or(0);
        let d = match (first_rx, last_rx) {
            (Some(a), Some(b)) if b > a && recv.len() >= 2 => {
                ((recv.len() - 1) as f64 * ps[0].size as f64 * 8.0 * 1e9 / (b - a) as f64) as u64
            }
            _ => 0,
        };
        let ctx = if quiet(t) { 0 } else { 1 };
        if ctx == 0 && d > 0 {
            disp_quiet.push(d as f64);
        }
        tt.push(t);
        tid.push(*id as u64);
        tsent.push(ps.len() as u64);
        trecv.push(recv.len() as u64);
        tdisp.push(d);
        tctx.push(ctx);
        for p in ps {
            oid.push(*id as u64);
            oidx.push(p.train_idx as u64);
            ooff.push(p.rx.zip(first_rx).map(|(r, f0)| (r - f0) as u64));
        }
    }
    if !tt.is_empty() {
        let mut dq = disp_quiet.clone();
        f = f.with(
            "capacity_light",
            field("known", "capacity.train-dispersion/1", 0.7)
                .with("trains", format!("trains[{dir}]"))
                .with("offsets", format!("train_offsets[{dir}]"))
                .with(
                    "train_size",
                    by_train.values().next().map_or(0, |v| v.len()),
                )
                .with("packet_bytes", tsize as u64)
                .with("median_quiet_dispersion_bps", median(&mut dq))
                .with("shares_queue_with_heavy", true)
                .with("source", src(&["pkt"])),
        );
        let n = tt.len();
        let mut ctxc = ucol("context", Enc::Rle, "enum", tctx);
        ctxc = ctxc.with_meta(
            "enum",
            Value::Array(vec![Value::from("quiet"), Value::from("loaded")]),
        );
        out.tables.push(table(
            "trains",
            dir,
            vec![
                icol("t", Enc::Delta, "ns", tt).clock("trace"),
                ucol("train", Enc::Delta, "id", tid),
                ucol("sent", Enc::Rle, "count", tsent),
                ucol("received", Enc::Rle, "count", trecv),
                ucol("dispersion_rate", Enc::Varint, "bit/s", tdisp),
                ctxc,
            ],
            n,
        ));
        let m = oid.len();
        out.tables.push(table(
            "train_offsets",
            dir,
            vec![
                ucol("train", Enc::Rle, "id", oid),
                ucol("idx", Enc::Rle, "count", oidx),
                Column::nullable_u64("offset", Enc::Varint, &ooff).unit("ns"),
            ],
            m,
        ));
    } else {
        f = f.with(
            "capacity_light",
            field("unknown", "capacity.train-dispersion/1", 0.0),
        );
    }

    // --- queue (per saturating flow) ---
    let mut depths = Vec::new();
    let mut lossy_depths: Vec<f64> = Vec::new();
    let mut onsets = Vec::new();
    let mut losses_total = 0usize;
    let mut ce_marks = 0usize;
    let mut sat_flows: BTreeMap<i64, Vec<&Pkt>> = BTreeMap::new();
    for p in pkts.iter().filter(|p| saturating(&p.kind)) {
        sat_flows.entry(p.flow).or_default().push(p);
    }
    for ps in sat_flows.values() {
        let qs: Vec<(i64, i64)> = ps.iter().filter_map(|p| Some((p.tx?, q_of(p)?))).collect();
        let qmax = qs.iter().map(|x| x.1).max().unwrap_or(0) as f64;
        ce_marks += ps
            .iter()
            .filter(|p| p.tos_rx.is_some_and(|t| t & 3 == 3) && p.tos_tx & 3 != 3)
            .count();
        let lost: Vec<i64> = ps
            .iter()
            .filter(|p| p.rx.is_none() && !p.host_drop)
            .filter_map(|p| p.tx)
            .collect();
        losses_total += lost.len();
        let mut at_loss = Vec::new();
        for t in &lost {
            let mut w: Vec<f64> = qs
                .iter()
                .filter(|x| x.0 >= t - 500_000_000 && x.0 <= *t)
                .map(|x| x.1 as f64)
                .collect();
            if let Some(q) = quantile(&mut w, 1.0) {
                at_loss.push(q);
            }
        }
        let depth = if at_loss.is_empty() {
            qmax
        } else {
            median(&mut at_loss.clone()).unwrap_or(qmax)
        };
        if !at_loss.is_empty() {
            lossy_depths.push(depth);
        }
        if !at_loss.is_empty() && qmax > 0.0 {
            onsets.push(Onset {
                heavy: ps[0].kind == "heavy",
                ratio: depth / qmax,
                low_queue: depth < 2_000_000.0,
            });
        }
        depths.push(depth);
    }
    // Flows whose losses revealed the buffer (tail drop at full queue) define the depth; flows
    // without loss only bound it from below.
    let mut dmed = if lossy_depths.is_empty() {
        depths.clone()
    } else {
        lossy_depths.clone()
    };
    let depth_ns = if lossy_depths.is_empty() {
        dmed.iter()
            .copied()
            .fold(None, |m: Option<f64>, x| Some(m.map_or(x, |m| m.max(x))))
    } else {
        median(&mut dmed)
    };
    let discipline = queue_discipline(!sat_flows.is_empty(), &onsets, ce_marks);
    let buffer_bytes = depth_ns.zip(rate_med).map(|(d, r)| d / 1e9 * r / 8.0);
    out.buffer_bytes = buffer_bytes;
    f = f.with(
        "queue",
        match depth_ns {
            Some(d) if !sat_flows.is_empty() => field(
                if losses_total > 0 {
                    "known"
                } else {
                    "estimated"
                },
                "queue.loss-onset/3",
                if losses_total > 0 { 0.8 } else { 0.4 },
            )
            .with("depth_time_ns", d)
            .with("depth_bytes", buffer_bytes)
            .with("discipline", discipline)
            .with("losses", losses_total)
            .with("ce_marks", ce_marks)
            .with(
                "note",
                if losses_total == 0 {
                    "no loss in saturation: depth is a lower bound (max observed queueing delay)"
                } else {
                    ""
                },
            )
            .with("source", src(&["pkt"])),
            _ => field("unknown", "queue.loss-onset/3", 0.0).with("discipline", "unknown"),
        },
    );
    // --- policer ---
    f = f.with(
        "policer",
        if discipline == "policer" {
            field("estimated", "policer.lossy-flat/2", 0.6)
                .with("rate_bps", rate_med)
                .with("burst_bytes", Value::Null)
        } else {
            field("unknown", "policer.lossy-flat/2", 0.0).with("detected", false)
        },
    );

    // --- intrinsic loss (quiet light flow) ---
    // Per-packet process as the path sees it: all quiet-period light and train packets in
    // transmit order (a Gilbert chain advances on every packet, not just light-flow ones).
    let mut seqd: Vec<(&Pkt, bool)> = pkts
        .iter()
        .filter(|p| {
            matches!(p.kind.as_str(), "light" | "train" | "control")
                && p.tx.is_some_and(quiet)
                && !p.host_drop
        })
        .map(|p| (p, p.rx.is_some()))
        .collect();
    seqd.sort_by_key(|x| x.0.tx);
    let (mut ng, mut nb, mut gb, mut bg) = (0f64, 0f64, 0f64, 0f64);
    let mut events: Vec<(i64, u64)> = Vec::new();
    let mut run = 0u64;
    let mut run_t = 0i64;
    for w in seqd.windows(2) {
        let (a, b) = (w[0].1, w[1].1);
        if a {
            ng += 1.0;
            if !b {
                gb += 1.0;
            }
        } else {
            nb += 1.0;
            if b {
                bg += 1.0;
            }
        }
    }
    for (p, ok) in &seqd {
        if !ok {
            if run == 0 {
                run_t = p.tx.unwrap_or(0);
            }
            run += 1;
        } else if run > 0 {
            events.push((run_t, run));
            run = 0;
        }
    }
    if run > 0 {
        events.push((run_t, run));
    }
    let lost_n = seqd.iter().filter(|x| !x.1).count() as f64;
    if seqd.len() >= 50 {
        let rate = lost_n / seqd.len() as f64;
        let p = if ng > 0.0 { gb / ng } else { 0.0 };
        let r = if nb > 0.0 { bg / nb } else { 1.0 };
        let (plo, phi) = wilson(gb, ng);
        let (rlo, rhi) = wilson(bg, nb);
        out.loss = Some((rate, p));
        f = f.with(
            "loss",
            field(
                "known",
                "loss.gilbert-runs/2",
                (seqd.len() as f64 / 1000.0).min(0.9),
            )
            .with("rate", rate)
            .with(
                "ge",
                Value::map()
                    .with("p", p)
                    .with("r", r)
                    .with("h", 1.0)
                    .with("k", 0.0)
                    .with("p_ci95", Value::Array(vec![plo.into(), phi.into()]))
                    .with("r_ci95", Value::Array(vec![rlo.into(), rhi.into()]))
                    // Counts behind p and r, so readers can compute intervals at any level.
                    .with("good_n", ng as u64)
                    .with("good_to_bad", gb as u64)
                    .with("bad_n", nb as u64)
                    .with("bad_to_good", bg as u64),
            )
            .with("samples", seqd.len())
            .with("events", format!("loss_events[{dir}]"))
            .with("source", src(&["pkt"])),
        );
        out.tables.push(table(
            "loss_events",
            dir,
            vec![
                icol("t", Enc::Delta, "ns", events.iter().map(|e| e.0).collect()).clock("trace"),
                ucol(
                    "burst",
                    Enc::Rle,
                    "count",
                    events.iter().map(|e| e.1).collect(),
                ),
            ],
            events.len(),
        ));
    } else {
        f = f.with(
            "loss",
            field("unknown", "loss.gilbert-runs/2", 0.0)
                .with("reason", "too few quiet light-flow packets"),
        );
    }

    // --- reorder ---
    let mut flows: BTreeMap<i64, Vec<&Pkt>> = BTreeMap::new();
    // Control datagrams are sealed by two threads, so their sequence order is not their send
    // order: they are excluded from reordering (and duplication) statistics.
    for p in pkts
        .iter()
        .filter(|p| p.rx.is_some() && p.kind != "control")
    {
        flows.entry(p.flow).or_default().push(p);
    }
    let (mut reord, mut total) = (0u64, 0u64);
    let mut disp: BTreeMap<u64, u64> = BTreeMap::new();
    for ps in flows.values_mut() {
        ps.sort_by_key(|p| p.seq);
        let mut by_rx: Vec<(i64, i64)> = ps.iter().map(|p| (p.rx.unwrap_or(0), p.seq)).collect();
        by_rx.sort();
        let mut max_seq = i64::MIN;
        for (rank, (_, seq)) in by_rx.iter().enumerate() {
            total += 1;
            if *seq < max_seq {
                reord += 1;
                let expected = ps.iter().position(|p| p.seq == *seq).unwrap_or(rank);
                *disp.entry(rank.abs_diff(expected) as u64).or_default() += 1;
            }
            max_seq = max_seq.max(*seq);
        }
    }
    f = f.with(
        "reorder",
        field(
            "known",
            "reorder.late-arrivals/1",
            if total > 1000 { 0.9 } else { 0.5 },
        )
        .with(
            "rate",
            if total > 0 {
                reord as f64 / total as f64
            } else {
                0.0
            },
        )
        .with("reordered", reord)
        .with("received", total)
        .with(
            "displacement_hist",
            Value::Map(
                disp.iter()
                    .take(64)
                    .map(|(k, v)| (pt_format::Key(k.to_string()), Value::from(*v)))
                    .collect(),
            ),
        ),
    );
    let dups = raw.table(&format!("dup[{dir}]")).map_or(0, |t| t.n);
    f = f.with(
        "duplicate",
        field(
            "known",
            "duplicate.count/1",
            if total > 1000 { 0.9 } else { 0.5 },
        )
        .with(
            "rate",
            if total > 0 {
                dups as f64 / total as f64
            } else {
                0.0
            },
        )
        .with("duplicates", dups),
    );

    // --- MTU (ladder) ---
    let pm: Vec<&Pkt> = pkts.iter().filter(|p| p.kind == "pmtu").collect();
    if pm.is_empty() {
        f = f.with("mtu", field("unknown", "mtu.ladder/2", 0.0));
    } else {
        let mut sizes: BTreeMap<i64, (u64, u64)> = BTreeMap::new();
        for p in &pm {
            let e = sizes.entry(p.size).or_default();
            e.0 += 1;
            if p.rx.is_some() {
                e.1 += 1;
            }
        }
        let max_ok = sizes.iter().filter(|(_, v)| v.1 > 0).map(|(k, _)| *k).max();
        let sender = if dir == "a_to_b" { "a" } else { "b" };
        let icmp_mtu: Vec<u64> = raw
            .events_of("icmp")
            .filter(|e| e.get("endpoint").and_then(Value::as_str) == Some(sender))
            .filter_map(|e| {
                e.get("detail")
                    .and_then(|d| d.get("info"))
                    .and_then(Value::as_u64)
            })
            .filter(|m| *m > 0)
            .collect();
        let larger_lost = sizes.iter().any(|(k, v)| Some(*k) > max_ok && v.1 == 0);
        let flows: Vec<i64> = pm.iter().map(|p| p.flow).collect();
        f = f.with(
            "mtu",
            field(
                if max_ok.is_some() { "known" } else { "unknown" },
                "mtu.ladder/2",
                0.9,
            )
            .with("path_mtu", max_ok)
            .with(
                "blackhole",
                // Without ICMP errors at the sender, silence is not evidence (probe.md §9.5).
                if icmp_unobservable(raw, sender, &flows) {
                    Value::Null
                } else {
                    Value::from(larger_lost && icmp_mtu.is_empty())
                },
            )
            .with(
                "icmp_mtu",
                Value::Array(icmp_mtu.iter().map(|m| Value::from(*m)).collect()),
            )
            .with(
                "ladder",
                Value::Array(
                    sizes
                        .iter()
                        .map(|(k, v)| {
                            Value::map()
                                .with("size", *k as u64)
                                .with("sent", v.0)
                                .with("received", v.1)
                        })
                        .collect(),
                ),
            ),
        );
    }

    // --- ECN / DSCP (light cycle) ---
    let mut by_tos: BTreeMap<i64, (u64, u64, BTreeMap<i64, u64>)> = BTreeMap::new();
    for p in &light {
        let e = by_tos.entry(p.tos_tx).or_default();
        e.0 += 1;
        if let Some(r) = p.tos_rx {
            e.1 += 1;
            *e.2.entry(r).or_default() += 1;
        }
    }
    let ecn_names = ["not-ect", "ect1", "ect0", "ce"];
    let mut ecn = Value::map();
    let base_loss = {
        let (s, r) = by_tos
            .iter()
            .filter(|(k, _)| *k & 3 == 0)
            .fold((0, 0), |a, (_, v)| (a.0 + v.0, a.1 + v.1));
        if s > 0 {
            1.0 - r as f64 / s as f64
        } else {
            0.0
        }
    };
    for e in 0..4i64 {
        let (s, r, seen) = by_tos.iter().filter(|(k, _)| *k & 3 == e).fold(
            (0u64, 0u64, BTreeMap::new()),
            |mut a, (_, v)| {
                a.0 += v.0;
                a.1 += v.1;
                for (k, n) in &v.2 {
                    *a.2.entry(k & 3).or_insert(0u64) += n;
                }
                a
            },
        );
        if s == 0 {
            continue;
        }
        let loss = 1.0 - r as f64 / s as f64;
        let dominant = seen.iter().max_by_key(|x| x.1).map(|x| *x.0);
        let verdict = if r == 0 || (loss > 0.05 && loss >= 5.0 * base_loss.max(0.01)) {
            "dropped"
        } else if dominant == Some(e) {
            if e != 0 && seen.get(&3).copied().unwrap_or(0) > 0 && e != 3 {
                "marked"
            } else {
                "passed"
            }
        } else if dominant == Some(0) {
            "bleached"
        } else {
            "remarked"
        };
        ecn = ecn.with(
            ecn_names[e as usize],
            Value::map()
                .with("sent", s)
                .with("received", r)
                .with("verdict", verdict),
        );
    }
    f = f.with(
        "ecn",
        field(
            if by_tos.is_empty() {
                "unknown"
            } else {
                "known"
            },
            "tos.light-cycle/1",
            0.9,
        )
        .with("codepoints", ecn),
    );
    let mut dscp = Value::map();
    for d in [0i64, 8, 34, 46] {
        let (s, seen) = by_tos.iter().filter(|(k, _)| *k >> 2 == d).fold(
            (0u64, BTreeMap::new()),
            |mut a, (_, v)| {
                a.0 += v.0;
                for (k, n) in &v.2 {
                    *a.1.entry(k >> 2).or_insert(0u64) += n;
                }
                a
            },
        );
        if s == 0 {
            continue;
        }
        let dominant = seen.iter().max_by_key(|x| x.1).map(|x| *x.0);
        dscp = dscp.with(
            &d.to_string(),
            Value::map()
                .with("sent", s)
                .with(
                    "verdict",
                    if dominant == Some(d) {
                        "preserved"
                    } else if dominant.is_none() {
                        "unknown"
                    } else {
                        "rewritten"
                    },
                )
                .with("observed", dominant),
        );
    }
    f = f.with(
        "dscp",
        field(
            if by_tos.is_empty() {
                "unknown"
            } else {
                "known"
            },
            "tos.light-cycle/1",
            0.9,
        )
        .with("values", dscp),
    );

    // --- summary ---
    f = f.with(
        "summary",
        field(
            if rate_med.is_some() {
                "known"
            } else {
                "estimated"
            },
            "summary.pantheon5/1",
            0.7,
        )
        .with("rate_bps", rate_med)
        .with("delay_ns", base_med)
        .with("loss_rate", out.loss.map(|l| l.0))
        .with("buffer_bytes", buffer_bytes)
        .with(
            "delivery",
            if cv.is_nan() {
                Value::Null
            } else if cv < 1.0 {
                Value::from("isochronous")
            } else {
                Value::from("poisson")
            },
        ),
    );

    // --- outages ---
    let mut outages = Vec::new();
    if let (Some(t0), Some(t1)) = (
        light.iter().filter_map(|p| p.tx).min(),
        light.iter().filter_map(|p| p.tx).max(),
    ) {
        let s = 1_000_000_000i64;
        let mut k = t0;
        let mut cur: Option<i64> = None;
        while k < t1 {
            let sent = light
                .iter()
                .filter(|p| p.tx.is_some_and(|t| t >= k && t < k + s))
                .count();
            let recv = light
                .iter()
                .filter(|p| p.tx.is_some_and(|t| t >= k && t < k + s) && p.rx.is_some())
                .count();
            if sent >= 20 && recv == 0 {
                cur.get_or_insert(k);
            } else if let Some(st) = cur.take() {
                outages.push(
                    Value::map()
                        .with("t0", st)
                        .with("t1", k)
                        .with("dir", dir)
                        .with("type", "outage")
                        .with("method", "timeline.outage/1"),
                );
            }
            k += s;
        }
        if let Some(st) = cur {
            outages.push(
                Value::map()
                    .with("t0", st)
                    .with("t1", t1)
                    .with("dir", dir)
                    .with("type", "outage")
                    .with("method", "timeline.outage/1"),
            );
        }
    }
    f = f.with("outages", Value::Array(outages));
    out.fields = f;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segs(levels: &[(usize, i64)]) -> Vec<(i64, i64)> {
        let mut v = Vec::new();
        for (n, ms) in levels {
            for _ in 0..*n {
                let t = v.len() as i64 * 1_000_000_000;
                // ±1 ms of noise around the level.
                v.push((t, ms * 1_000_000 + (t / 1_000_000_000 % 3 - 1) * 1_000_000));
            }
        }
        v
    }

    /// `pathchange.base-delay-step/1`: a step beyond max(5 ms, 20%) is a change, noise and
    /// small drifts are not, and too short a series is unknown (derivation.md).
    #[test]
    fn path_change_finds_base_delay_steps() {
        assert!(path_changes(&segs(&[(19, 200)])).is_none());
        assert_eq!(path_changes(&segs(&[(60, 200)])).unwrap(), vec![]);
        // A relay (230 ms) giving way to a direct path (40 ms) at 30 s.
        let ch = path_changes(&segs(&[(30, 230), (40, 40)])).unwrap();
        assert_eq!(ch.len(), 1, "{ch:?}");
        assert!((ch[0].0 - 30_000_000_000).abs() <= 1_000_000_000, "{ch:?}");
        assert!(ch[0].1 > 220_000_000 && ch[0].2 < 50_000_000);
        // A 7 ms shift is below the 10 ms floor; the level itself (here negative, as a clock
        // offset makes it) does not matter.
        assert_eq!(
            path_changes(&segs(&[(30, 200), (30, 207)])).unwrap(),
            vec![]
        );
        assert_eq!(
            path_changes(&segs(&[(30, -300), (30, -280)]))
                .unwrap()
                .len(),
            1
        );
        // Two changes, each found once.
        let ch = path_changes(&segs(&[(30, 40), (30, 230), (30, 40)])).unwrap();
        assert_eq!(ch.len(), 2, "{ch:?}");
    }

    fn onsets(flows: &[(bool, f64, bool)]) -> Vec<Onset> {
        flows
            .iter()
            .map(|&(heavy, ratio, low_queue)| Onset {
                heavy,
                ratio,
                low_queue,
            })
            .collect()
    }

    /// `queue.loss-onset/3`: class saturations hold the queue target, so their losses sit at
    /// their maximum delay under any discipline and must not outvote the heavy flows. Ratios
    /// are those of the EXP-0002-r16 `aqm-ecn` trace (fq_codel), which `/2` called droptail
    /// (issue #103), and of the `rate-delay-asym` and `policer` traces of the same run.
    #[test]
    fn class_saturations_do_not_vote_on_the_discipline() {
        let aqm = onsets(&[
            (true, 0.696, false),
            (false, 1.0, false),
            (false, 1.0, false),
            (false, 1.0, false),
            (true, 0.528, false),
        ]);
        assert_eq!(queue_discipline(true, &aqm, 0), "aqm_suspected");
        let droptail = onsets(&[(true, 1.0, false), (true, 1.0, false)]);
        assert_eq!(queue_discipline(true, &droptail, 0), "droptail");
        // Class flows that lost at low delay still count towards a policer.
        let policer = onsets(&[
            (true, 0.712, true),
            (false, 0.791, true),
            (false, 0.795, true),
            (false, 0.469, true),
            (true, 0.379, true),
        ]);
        assert_eq!(queue_discipline(true, &policer, 0), "policer");
        // Only class flows lost: nothing probed the buffer.
        let class_only = onsets(&[(false, 1.0, false), (false, 0.5, false)]);
        assert_eq!(queue_discipline(true, &class_only, 0), "unknown");
        // CE marks still mean AQM; no saturation means unknown.
        assert_eq!(queue_discipline(true, &droptail, 3), "aqm_suspected");
        assert_eq!(queue_discipline(false, &[], 0), "unknown");
        assert_eq!(queue_discipline(true, &[], 0), "unknown");
    }

    #[test]
    fn qdisc_drops_segment_at_iface_change_and_reset() {
        // No rows with a drops value: unknown.
        assert_eq!(segmented_drops(&[], &[]), None);
        // One interface: last minus first.
        assert_eq!(
            segmented_drops(&[(0, 5), (10, 7), (20, 9)], &[]),
            Some((4, 1))
        );
        // Switch at t = 15 to an interface whose counter stands at 100: 2 + 3, never 103 - 5.
        assert_eq!(
            segmented_drops(&[(0, 5), (10, 7), (20, 100), (30, 103)], &[15]),
            Some((5, 2))
        );
        // Switch to an interface with a lower counter: no negative count.
        assert_eq!(
            segmented_drops(&[(0, 50), (10, 60), (20, 1), (30, 4)], &[15]),
            Some((13, 2))
        );
        // A decrease without a switch (qdisc replaced) also starts a segment.
        assert_eq!(
            segmented_drops(&[(0, 50), (10, 60), (20, 0), (30, 2)], &[]),
            Some((12, 2))
        );
        // A switch before the first row or after the last changes nothing.
        assert_eq!(segmented_drops(&[(10, 1), (20, 3)], &[5, 25]), Some((2, 1)));
    }

    fn pk(flow: i64, seq: i64, tx: i64, rx: Option<i64>, drops: Option<i64>) -> Pkt {
        Pkt {
            flow,
            seq,
            size: 1500,
            phase: 4,
            train: 0,
            train_idx: 0,
            tos_tx: 0,
            tos_rx: None,
            tx: Some(tx),
            rx,
            kind: "heavy".into(),
            rx_sock: rx.map(|_| 0),
            rxq_drops: rx.and(drops),
            host_drop: false,
        }
    }

    #[test]
    fn losses_inside_a_socket_drop_gap_are_host_drops() {
        // Arrivals at tx 0, 10, 40, 50 with drop counts 0, 0, 2, 2: the socket dropped two
        // datagrams between tx 10 and 40. Packets lost at tx 20 and 30 are host drops; the
        // one lost at 60 (no later count increase) is path loss.
        let mut v = vec![
            pk(7, 0, 0, Some(100), Some(0)),
            pk(7, 1, 10, Some(110), Some(0)),
            pk(7, 2, 20, None, None),
            pk(7, 3, 30, None, None),
            pk(7, 4, 40, Some(140), Some(2)),
            pk(7, 5, 50, Some(150), Some(2)),
            pk(7, 6, 60, None, None),
        ];
        let gaps = host_drop_gaps(&v);
        assert_eq!(
            gaps,
            vec![HostDropGap {
                sock: 0,
                tx_lo: 10,
                tx_hi: 40,
                drops: 2
            }]
        );
        assert_eq!(mark_host_drops(&mut v), HostDropMarks::default());
        let marked: Vec<i64> = v.iter().filter(|p| p.host_drop).map(|p| p.seq).collect();
        assert_eq!(marked, vec![2, 3]);
        // A gap with more losses than socket drops marks only as many as were dropped; the
        // rest stay losses and the gap is ambiguous.
        let mut tail = vec![
            pk(7, 0, 0, Some(100), Some(0)),
            pk(7, 1, 10, None, None),
            pk(7, 2, 20, None, None),
            pk(7, 3, 30, None, None),
            pk(7, 4, 40, Some(140), Some(1)),
        ];
        assert_eq!(
            mark_host_drops(&mut tail),
            HostDropMarks {
                ambiguous_gaps: 1,
                ambiguous_losses: 2
            }
        );
        let marked: Vec<i64> = tail.iter().filter(|p| p.host_drop).map(|p| p.seq).collect();
        assert_eq!(marked, vec![1]);
        // Without rxq_drops (PTF 1.0) nothing is a host drop.
        let mut old: Vec<Pkt> = v
            .iter()
            .map(|p| Pkt {
                rxq_drops: None,
                host_drop: false,
                ..p.clone()
            })
            .collect();
        mark_host_drops(&mut old);
        assert!(old.iter().all(|p| !p.host_drop));
    }

    #[test]
    fn wilson_bounds() {
        let (lo, hi) = wilson(5.0, 100.0);
        assert!(lo < 0.05 && hi > 0.05 && lo > 0.0 && hi < 0.2);
    }

    #[test]
    fn wilson_level() {
        // A higher level widens the interval around the same point and matches the 95% default.
        assert_eq!(wilson(5.0, 100.0), wilson_z(5.0, 100.0, 1.96));
        let (lo95, hi95) = wilson(5.0, 100.0);
        let (lo, hi) = wilson_z(5.0, 100.0, 2.498);
        assert!(lo < lo95 && hi > hi95 && lo > 0.0);
    }

    #[test]
    fn quantiles() {
        let mut v = vec![3.0, 1.0, 2.0];
        assert_eq!(median(&mut v), Some(2.0));
    }
}
