//! Interoperability: netem and Mahimahi export, Mahimahi import (REQ-FMT-021,
//! docs/design/derivation.md "Exports", R-0001, R-0005).

use pt_format::{Column, Enc, Key, Map, PtfFile, Section, Table, Value, Values, flags};

use crate::raw::Raw;

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

/// Mahimahi trace lines (ms timestamps, one 1504-byte opportunity per line) from a direction's
/// delivery opportunities (`export.mahimahi/1`). Returns (lines, notes).
pub fn mahimahi_lines(f: &PtfFile, dir: &str) -> (Vec<u64>, Vec<String>) {
    let raw = Raw::load(f);
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
    let _ = raw;
    if opps.is_empty() {
        notes.push(format!(
            "{dir}: no saturated delivery opportunities; nothing to export"
        ));
        return (Vec::new(), notes);
    }
    opps.sort();
    let t0 = opps[0].0;
    let mut lines = Vec::new();
    let mut carry: u64 = 0;
    for (t, b) in &opps {
        carry += *b as u64;
        let ms = ((t - t0).max(0) / 1_000_000) as u64;
        while carry >= MAHIMAHI_QUANTUM {
            lines.push(ms);
            carry -= MAHIMAHI_QUANTUM;
        }
    }
    notes.push(format!(
        "{dir}: {} opportunities, from saturated windows only. Gaps between windows stay in the timeline as periods without opportunities (Mahimahi treats them as zero capacity); capacity there is unknown, not zero",
        lines.len()
    ));
    (lines, notes)
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
        let (lines, _) = mahimahi_lines(&f, "a_to_b");
        assert_eq!(lines, vec![0, 0, 1, 2, 2, 2, 5]);
        let mut buf = Vec::new();
        pt_format::write(&f, &pt_format::WriteOptions::canonical(), &mut buf).unwrap();
        assert!(pt_format::read(&buf, pt_format::ReadOptions::default()).is_ok());
    }
}
