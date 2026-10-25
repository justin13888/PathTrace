//! Interoperability: netem and Mahimahi export, Mahimahi import (REQ-FMT-021,
//! docs/design/derivation.md "Exports", R-0001, R-0005).

use pt_format::{Column, Enc, Key, Map, PtfFile, Section, Table, Value, Values, flags};

/// Mahimahi's per-opportunity byte quantum in code (R-0001: 1504, not the documented 1500).
pub const MAHIMAHI_QUANTUM: u64 = 1504;

fn dir_fields<'a>(f: &'a PtfFile, dir: &str) -> Option<&'a Value> {
    let p = f.sections.iter().find(|s| &s.kind == b"PATH")?;
    p.get("directions")?.get(dir)
}

fn num(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Float(x) => Some(*x),
        Value::Uint(u) => Some(*u as f64),
        _ => None,
    }
}

/// netem arguments reproducing a direction's static summary (`export.netem/1`).
pub fn netem_args(f: &PtfFile, dir: &str) -> Option<String> {
    let d = dir_fields(f, dir)?;
    let s = d.get("summary")?;
    let mut parts = Vec::new();
    let delay_ms = num(s.get("delay_ns")).map(|v| v / 1e6);
    let jit_ms = d
        .get("jitter")
        .and_then(|j| j.get("stddev_ns"))
        .and_then(|v| num(Some(v)))
        .map(|v| v / 1e6);
    if let Some(dm) = delay_ms {
        match jit_ms {
            Some(j) if j > 0.01 => {
                parts.push(format!("delay {dm:.3}ms {j:.3}ms distribution normal"))
            }
            _ => parts.push(format!("delay {dm:.3}ms")),
        }
    }
    if let Some(ge) = d.get("loss").and_then(|l| l.get("ge")) {
        let p = num(ge.get("p")).unwrap_or(0.0);
        let r = num(ge.get("r")).unwrap_or(1.0);
        let h = num(ge.get("h")).unwrap_or(1.0);
        let k = num(ge.get("k")).unwrap_or(0.0);
        if p > 0.0 {
            // netem gemodel p r 1-h 1-k (R-0005); h/k here are loss probabilities in bad/good.
            parts.push(format!(
                "loss gemodel {:.4}% {:.4}% {:.4}% {:.4}%",
                p * 100.0,
                r * 100.0,
                h * 100.0,
                k * 100.0
            ));
        }
    }
    let rate = num(s.get("rate_bps"));
    if let Some(r) = rate {
        parts.push(format!("rate {}kbit", (r / 1000.0).round() as u64));
        if let Some(b) = num(s.get("buffer_bytes")) {
            // netem's `limit` counts every packet it holds, including those waiting in the delay
            // line (R-0005), so add the delay-line occupancy to the queue depth.
            let in_delay = delay_ms.map_or(0.0, |d| d / 1e3 * r / (1514.0 * 8.0));
            let pkts = (b / 1500.0 + in_delay).ceil().max(1.0) as u64;
            parts.push(format!("limit {pkts}"));
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("netem {}", parts.join(" ")))
}

/// Method id of the Mahimahi export.
pub const MAHIMAHI_EXPORT_METHOD: &str = "export.mahimahi/2";

/// One direction's Mahimahi export (`export.mahimahi/2`).
#[derive(Debug, Clone, PartialEq)]
pub struct MahimahiExport {
    /// Trace lines: ms since the first opportunity, one 1504-byte opportunity per line.
    pub lines: Vec<u64>,
    /// Sidecar describing the gaps filled at the median saturated rate (derivation.md "Exports").
    /// `None` when there is nothing to export.
    pub sidecar: Option<Value>,
    /// Human-readable notes for stderr.
    pub notes: Vec<String>,
}

/// The `saturated` capacity segments (t0, t1) of a direction, sorted, and its median rate.
fn saturated_segments(f: &PtfFile, dir: &str) -> (Vec<(i64, i64)>, Option<f64>) {
    let cap = dir_fields(f, dir).and_then(|d| d.get("capacity"));
    let mut segs: Vec<(i64, i64)> = cap
        .and_then(|c| c.get("segments"))
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter(|s| s.get("quality").and_then(Value::as_str) == Some("saturated"))
        .filter_map(|s| Some((s.get("t0")?.as_i64()?, s.get("t1")?.as_i64()?)))
        .filter(|(a, b)| b >= a)
        .collect();
    segs.sort();
    let rate =
        num(cap.and_then(|c| c.get("median_rate_bps"))).filter(|r| r.is_finite() && *r > 0.0);
    (segs, rate)
}

/// Mahimahi trace lines (ms timestamps, one 1504-byte opportunity per line) from a direction's
/// delivery opportunities, with the gaps between saturated segments filled at the median
/// saturated rate (`export.mahimahi/2`).
pub fn mahimahi_lines(f: &PtfFile, dir: &str) -> MahimahiExport {
    let mut notes = Vec::new();
    let mut opps: Vec<(i64, i64)> = Vec::new();
    for s in f.sections.iter().filter(|s| &s.kind == b"SERS") {
        for t in s.tables() {
            let attr = t.attrs().and_then(|a| a.get("dir")).and_then(Value::as_str);
            if t.name == "capacity_opps" && attr == Some(dir) {
                let ts = t.column("t").and_then(|c| c.i64_rows()).unwrap_or_default();
                let bs = t
                    .column("bytes")
                    .and_then(|c| c.u64_rows())
                    .unwrap_or_default();
                for (a, b) in ts.iter().zip(bs) {
                    if let (Some(a), Some(b)) = (a, b) {
                        opps.push((*a, b as i64));
                    }
                }
            }
        }
    }
    if opps.is_empty() {
        notes.push(format!(
            "{dir}: no saturated delivery opportunities; nothing to export"
        ));
        return MahimahiExport {
            lines: Vec::new(),
            sidecar: None,
            notes,
        };
    }
    opps.sort();
    let t0 = opps[0].0;
    let t_end = opps[opps.len() - 1].0;
    let to_ms = |t: i64| ((t - t0).max(0) / 1_000_000) as u64;
    let (segs, rate) = saturated_segments(f, dir);
    let reason = match rate {
        None => Some("no positive median_rate_bps in PATH capacity"),
        Some(_) if segs.is_empty() => Some("no saturated segments in PATH capacity"),
        Some(_) => None,
    };
    // Synthetic opportunities in each gap between consecutive saturated segments, inside the
    // exported timeline (first to last measured opportunity), both gap ends excluded.
    let mut fill: Vec<i64> = Vec::new();
    let mut filled = Vec::new();
    if let (Some(r), None) = (rate, reason) {
        let period = MAHIMAHI_QUANTUM as f64 * 8.0 * 1e9 / r;
        for w in segs.windows(2) {
            let (g0, g1) = (w[0].1.max(t0), w[1].0.min(t_end));
            if g1 <= g0 {
                continue;
            }
            let n0 = fill.len();
            let mut k = 1u64;
            loop {
                let t = g0 + (k as f64 * period) as i64;
                if t >= g1 {
                    break;
                }
                fill.push(t);
                k += 1;
            }
            if fill.len() > n0 {
                filled.push(
                    Value::map()
                        .with("start_ms", to_ms(g0))
                        .with("end_ms", to_ms(g1)),
                );
            }
        }
    }
    let mut lines = Vec::new();
    let mut carry: u64 = 0;
    for (t, b) in &opps {
        carry += *b as u64;
        while carry >= MAHIMAHI_QUANTUM {
            lines.push(to_ms(*t));
            carry -= MAHIMAHI_QUANTUM;
        }
    }
    let measured = lines.len();
    lines.extend(fill.iter().map(|t| to_ms(*t)));
    lines.sort_unstable();
    let mut sidecar = Value::map()
        .with("method", MAHIMAHI_EXPORT_METHOD)
        .with("dir", dir)
        .with("quantum_bytes", MAHIMAHI_QUANTUM)
        .with("t0_ns", t0)
        .with("lines", lines.len())
        .with("measured_lines", measured)
        .with("filled_lines", fill.len())
        .with(
            "fill_rate_bps",
            match (rate, reason) {
                (Some(r), None) => Value::from(r),
                _ => Value::Null,
            },
        )
        .with("filled", Value::Array(filled.clone()));
    if let Some(why) = reason {
        sidecar = sidecar.with("reason", why);
    }
    notes.push(match reason {
        None => format!(
            "{dir}: {} opportunities: {measured} measured in saturated windows, {} filled at the median saturated rate ({:.1} Mbit/s) in {} gaps where capacity is unknown, not measured",
            lines.len(),
            fill.len(),
            rate.unwrap_or(0.0) / 1e6,
            filled.len()
        ),
        Some(why) => format!("{dir}: {measured} opportunities, nothing filled ({why})"),
    });
    MahimahiExport {
        lines,
        sidecar: Some(sidecar),
        notes,
    }
}

/// Import a Mahimahi trace (ms timestamps, one 1504-byte opportunity per line) as a minimal PTF
/// trace whose PATH carries capacity only; every other field is `unknown` (`import.mahimahi/1`).
pub fn import_mahimahi(up: &str, down: Option<&str>, label: &str) -> Result<PtfFile, String> {
    let parse = |s: &str| -> Result<Vec<i64>, String> {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| {
                l.parse::<i64>()
                    .map(|v| v * 1_000_000)
                    .map_err(|e| format!("bad Mahimahi line {l:?}: {e}"))
            })
            .collect()
    };
    let mut meta = Map::new();
    meta.insert(Key::from("kind"), Value::from("trace"));
    meta.insert(Key::from("redaction"), Value::from("full"));
    meta.insert(
        Key::from("imported"),
        Value::map()
            .with("format", "mahimahi")
            .with("method", "import.mahimahi/1")
            .with("label", label)
            .with("quantum_bytes", MAHIMAHI_QUANTUM),
    );
    let mut sections = vec![Section::new(b"META", flags::CRITICAL, meta)];
    let mut dirs = Value::map();
    for (dir, text) in [("a_to_b", Some(up)), ("b_to_a", down)] {
        let Some(text) = text else {
            dirs = dirs.with(
                dir,
                Value::map().with(
                    "capacity",
                    Value::map()
                        .with("status", "unknown")
                        .with("method", "import.mahimahi/1"),
                ),
            );
            continue;
        };
        let ts = parse(text)?;
        let n = ts.len();
        let span = ts.last().copied().unwrap_or(0).max(1);
        let rate = n as f64 * MAHIMAHI_QUANTUM as f64 * 8.0 * 1e9 / span as f64;
        let mut t = Table::new("capacity_opps", n).with_attrs(Value::map().with("dir", dir));
        t.columns.push(
            Column::new("t", Enc::Delta2, Values::I64(ts))
                .unit("ns")
                .clock("trace"),
        );
        t.columns
            .push(Column::new("bytes", Enc::Rle, Values::U64(vec![MAHIMAHI_QUANTUM; n])).unit("B"));
        sections.push(
            Section::new(b"SERS", flags::CRITICAL | flags::DERIVED, Map::new()).with_table(t),
        );
        let unknown = |m: &str| Value::map().with("status", "unknown").with("method", m);
        dirs = dirs.with(
            dir,
            Value::map()
                .with(
                    "capacity",
                    Value::map()
                        .with("status", "known")
                        .with("method", "import.mahimahi/1")
                        .with("confidence", 0.5)
                        .with("representation", "opportunities")
                        .with("quantum_bytes", MAHIMAHI_QUANTUM)
                        .with("opportunities", format!("capacity_opps[{dir}]"))
                        .with("median_rate_bps", rate)
                        .with(
                            "segments",
                            Value::Array(vec![
                                Value::map()
                                    .with("t0", 0u64)
                                    .with("t1", span)
                                    .with("quality", "saturated")
                                    .with("workload", "imported"),
                            ]),
                        ),
                )
                .with("base_delay", unknown("import.mahimahi/1"))
                .with("loss", unknown("import.mahimahi/1"))
                .with("queue", unknown("import.mahimahi/1"))
                .with("jitter", unknown("import.mahimahi/1"))
                .with(
                    "summary",
                    Value::map()
                        .with("status", "estimated")
                        .with("method", "import.mahimahi/1")
                        .with("rate_bps", rate),
                ),
        );
    }
    let path = Value::map()
        .with(
            "derivation",
            Value::map().with(
                "methods",
                Value::Array(vec![Value::from("import.mahimahi/1")]),
            ),
        )
        .with("directions", dirs);
    sections.insert(
        1,
        Section::new(
            b"PATH",
            flags::CRITICAL | flags::DERIVED,
            path.as_map().cloned().unwrap_or_default(),
        ),
    );
    let mut f = PtfFile {
        major: pt_format::container::MAJOR,
        minor: pt_format::container::MINOR,
        sections,
    };
    pt_format::canonicalize(&mut f);
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mahimahi_roundtrip() {
        let up = "0\n0\n1\n2\n2\n2\n5\n";
        let f = import_mahimahi(up, None, "test").unwrap();
        let e = mahimahi_lines(&f, "a_to_b");
        // One saturated segment over the whole import: nothing to fill.
        assert_eq!(e.lines, vec![0, 0, 1, 2, 2, 2, 5]);
        let sc = e.sidecar.unwrap();
        assert_eq!(sc.get("filled_lines").and_then(Value::as_u64), Some(0));
        assert_eq!(
            sc.get("filled").and_then(Value::as_array).map(<[_]>::len),
            Some(0)
        );
        assert!(sc.get("reason").is_none());
        let mut buf = Vec::new();
        pt_format::write(&f, &pt_format::WriteOptions::canonical(), &mut buf).unwrap();
        assert!(pt_format::read(&buf, pt_format::ReadOptions::default()).is_ok());
    }

    /// A trace with two saturated windows (0-100 ms and 1000-1100 ms, one 1504-byte
    /// opportunity per ms) and the given PATH capacity for a_to_b.
    fn two_windows(capacity: Value) -> PtfFile {
        let ts: Vec<i64> = (0..100)
            .chain(1000..1100)
            .map(|ms| ms * 1_000_000)
            .collect();
        let n = ts.len();
        let mut t = Table::new("capacity_opps", n).with_attrs(Value::map().with("dir", "a_to_b"));
        t.columns.push(
            Column::new("t", Enc::Delta2, Values::I64(ts))
                .unit("ns")
                .clock("trace"),
        );
        t.columns
            .push(Column::new("bytes", Enc::Rle, Values::U64(vec![MAHIMAHI_QUANTUM; n])).unit("B"));
        let path = Value::map().with(
            "directions",
            Value::map().with("a_to_b", Value::map().with("capacity", capacity)),
        );
        PtfFile {
            major: pt_format::container::MAJOR,
            minor: pt_format::container::MINOR,
            sections: vec![
                Section::new(
                    b"PATH",
                    flags::CRITICAL | flags::DERIVED,
                    path.as_map().cloned().unwrap(),
                ),
                Section::new(b"SERS", flags::CRITICAL | flags::DERIVED, Map::new()).with_table(t),
            ],
        }
    }

    fn seg(t0_ms: i64, t1_ms: i64) -> Value {
        Value::map()
            .with("t0", t0_ms * 1_000_000)
            .with("t1", t1_ms * 1_000_000)
            .with("quality", "saturated")
            .with("workload", "heavy")
    }

    #[test]
    fn mahimahi_fills_gap_at_median_rate() {
        // 1504 B per ms = 12.032 Mbit/s; the fill emits one opportunity per ms in the gap.
        let rate = MAHIMAHI_QUANTUM as f64 * 8.0 * 1e3;
        let f = two_windows(
            Value::map()
                .with("median_rate_bps", rate)
                .with("segments", Value::Array(vec![seg(0, 99), seg(1000, 1099)])),
        );
        let e = mahimahi_lines(&f, "a_to_b");
        // Gap 99 ms .. 1000 ms, both ends excluded: 100..=999 are filled.
        assert_eq!(e.lines, (0..1100).collect::<Vec<u64>>());
        let sc = e.sidecar.unwrap();
        assert_eq!(
            sc.get("method").and_then(Value::as_str),
            Some("export.mahimahi/2")
        );
        assert_eq!(sc.get("measured_lines").and_then(Value::as_u64), Some(200));
        assert_eq!(sc.get("filled_lines").and_then(Value::as_u64), Some(900));
        assert_eq!(sc.get("lines").and_then(Value::as_u64), Some(1100));
        assert_eq!(sc.get("fill_rate_bps").and_then(Value::as_f64), Some(rate));
        let filled = sc.get("filled").and_then(Value::as_array).unwrap();
        assert_eq!(filled.len(), 1);
        assert_eq!(filled[0].get("start_ms").and_then(Value::as_u64), Some(99));
        assert_eq!(filled[0].get("end_ms").and_then(Value::as_u64), Some(1000));
    }

    #[test]
    fn mahimahi_without_rate_does_not_fill() {
        let f = two_windows(
            Value::map().with("segments", Value::Array(vec![seg(0, 99), seg(1000, 1099)])),
        );
        let e = mahimahi_lines(&f, "a_to_b");
        assert_eq!(e.lines.len(), 200);
        let sc = e.sidecar.unwrap();
        assert_eq!(sc.get("filled_lines").and_then(Value::as_u64), Some(0));
        assert_eq!(sc.get("fill_rate_bps"), Some(&Value::Null));
        assert!(sc.get("reason").and_then(Value::as_str).is_some());
    }

    #[test]
    fn mahimahi_nothing_to_export() {
        let f = PtfFile {
            major: pt_format::container::MAJOR,
            minor: pt_format::container::MINOR,
            sections: Vec::new(),
        };
        let e = mahimahi_lines(&f, "a_to_b");
        assert!(e.lines.is_empty());
        assert!(e.sidecar.is_none());
    }
}
