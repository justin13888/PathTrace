//! Derivation: raw observations → path model (docs/design/derivation.md).
//!
//! [`derive`] is a pure function of a trace's raw layer (REQ-DRV-001): it returns the derived
//! sections (PATH, SERS, PLCY, VALD), which [`apply`] substitutes into the file, leaving raw
//! sections untouched.

pub mod clock;
pub mod dir;
pub mod export;
pub mod policy;
pub mod raw;

use pt_format::{Key, Map, PtfFile, Section, Value, flags};

use crate::clock::TimeBase;
use crate::raw::Raw;

/// Tool identity for derivation provenance.
#[derive(Debug, Clone)]
pub struct Tool {
    pub version: String,
    pub git_commit: String,
    pub git_dirty: bool,
}

pub const DERIVED: [&[u8; 4]; 4] = [b"PATH", b"SERS", b"PLCY", b"VALD"];

/// Compute the derived sections of `f`.
pub fn derive(f: &PtfFile, tool: &Tool) -> Vec<Section> {
    let raw = Raw::load(f);
    let tb = TimeBase::from_raw(&raw);
    // Loaded intervals of each direction, so quiet periods exclude load in either direction.
    let (pa, _) = dir::packets(&raw, &tb, "a_to_b");
    let (pb, _) = dir::packets(&raw, &tb, "b_to_a");
    let la = dir::loaded_intervals(&pa);
    let lb = dir::loaded_intervals(&pb);
    drop((pa, pb));
    let ab = dir::derive_dir(&raw, &tb, "a_to_b", &lb);
    let ba = dir::derive_dir(&raw, &tb, "b_to_a", &la);

    let coupling = |d: &dir::DirOut, single: i64| -> Value {
        match (d.phase_rate.get(&6), d.phase_rate.get(&single)) {
            (Some(both), Some(one)) if *one > 0.0 => Value::from(both / one),
            _ => Value::Null,
        }
    };
    let timeline: Vec<Value> = ab
        .fields
        .get("outages")
        .and_then(Value::as_array)
        .into_iter()
        .chain(ba.fields.get("outages").and_then(Value::as_array))
        .flatten()
        .cloned()
        .collect();
    let methods = [
        "clock.pairs-piecewise/1",
        "clock.exchange-minfilter/1",
        "delay.light-window-min/1",
        "jitter.light-residual/1",
        "delay.size-slope/1",
        "capacity.saturated-arrivals/1",
        "capacity.train-dispersion/1",
        "queue.loss-onset/2",
        "policer.lossy-flat/2",
        "hostdrop.rxq-gap/1",
        "qdisc.drop-count/1",
        "loss.gilbert-runs/2",
        "reorder.late-arrivals/1",
        "duplicate.count/1",
        "mtu.ladder/1",
        "tos.light-cycle/1",
        "summary.pantheon5/1",
        "coupling.both-ratio/1",
        "timeline.outage/1",
        "timestamps.source-count/1",
        "policy.matrix/1",
        "vald.reference/1",
    ];
    let path = Value::map()
        .with(
            "derivation",
            Value::map()
                .with(
                    "tool",
                    Value::map()
                        .with("name", "pathtrace")
                        .with("version", tool.version.as_str())
                        .with("git_commit", tool.git_commit.as_str())
                        .with("git_dirty", tool.git_dirty),
                )
                .with(
                    "methods",
                    Value::Array(methods.iter().map(|m| Value::from(*m)).collect()),
                ),
        )
        .with(
            "time_base",
            Value::map()
                .with("origin", "a.mono at META.session.a.t0_mono")
                .with("t0_a_mono", tb.t0)
                .with("unit", "ns"),
        )
        .with(
            "clock",
            Value::map()
                .with("a", tb.a.to_value("clock.pairs-piecewise/1"))
                .with("b", tb.b.to_value("clock.pairs-piecewise/1"))
                .with(
                    "offset",
                    tb.off.as_ref().map_or(
                        Value::map()
                            .with("status", "unknown")
                            .with("method", "clock.exchange-minfilter/1"),
                        clock::Offset::to_value,
                    ),
                ),
        )
        .with(
            "directions",
            Value::map()
                .with("a_to_b", ab.fields.clone())
                .with("b_to_a", ba.fields.clone()),
        )
        .with(
            "coupling",
            Value::map()
                .with("method", "coupling.both-ratio/1")
                .with("a_to_b", coupling(&ab, 4))
                .with("b_to_a", coupling(&ba, 5)),
        )
        .with("timeline", Value::Array(timeline));
    let mut out = vec![Section::new(
        b"PATH",
        flags::CRITICAL | flags::DERIVED,
        path.as_map().cloned().unwrap_or_default(),
    )];
    for t in ab.tables.into_iter().chain(ba.tables) {
        // One table per section keeps each section bounded; large series are already chunked
        // by the canonical writer limits.
        for chunk in chunk_table(t) {
            out.push(
                Section::new(b"SERS", flags::CRITICAL | flags::DERIVED, Map::new())
                    .with_table(chunk),
            );
        }
    }
    out.push(Section::new(
        b"PLCY",
        flags::DERIVED,
        policy::plcy(&raw, &tb)
            .as_map()
            .cloned()
            .unwrap_or_default(),
    ));
    out.push(Section::new(
        b"VALD",
        flags::DERIVED,
        policy::vald(&raw, &tb)
            .as_map()
            .cloned()
            .unwrap_or_default(),
    ));
    out
}

fn chunk_table(t: pt_format::Table) -> Vec<pt_format::Table> {
    const N: usize = 65_536;
    if t.rows <= N {
        return vec![t];
    }
    let mut out = Vec::new();
    let mut start = 0;
    while start < t.rows {
        let end = (start + N).min(t.rows);
        let mut c = pt_format::Table::new(&t.name, end - start);
        c.meta = t.meta.clone();
        for col in &t.columns {
            let mut nc = col.clone();
            if let pt_format::Data::Known { values, .. } = &mut nc.data {
                // Derived series are never nullable except train offsets, which stay small.
                *values = match values {
                    pt_format::Values::U64(v) => pt_format::Values::U64(v[start..end].to_vec()),
                    pt_format::Values::I64(v) => pt_format::Values::I64(v[start..end].to_vec()),
                    pt_format::Values::F64(v) => pt_format::Values::F64(v[start..end].to_vec()),
                    pt_format::Values::Bool(v) => pt_format::Values::Bool(v[start..end].to_vec()),
                };
            }
            if let Some(vv) = &nc.validity {
                nc.validity = Some(vv[start..end].to_vec());
                // Re-slice present values for nullable columns.
                if let pt_format::Data::Known {
                    values: pt_format::Values::U64(v),
                    ..
                } = &mut nc.data
                {
                    let rows = col.u64_rows().unwrap_or_default();
                    *v = rows[start..end].iter().flatten().copied().collect();
                }
            }
            c.columns.push(nc);
        }
        out.push(c);
        start = end;
    }
    out
}

/// Replace the derived sections of `f` with freshly derived ones (raw sections unchanged).
pub fn apply(f: &PtfFile, tool: &Tool) -> PtfFile {
    let derived = derive(f, tool);
    let mut sections: Vec<Section> = f
        .sections
        .iter()
        .filter(|s| !DERIVED.contains(&&s.kind))
        .cloned()
        .collect();
    let rest = derived;
    sections.extend(rest);
    let mut out = PtfFile {
        major: f.major,
        // Derived sections written by this tool may use this minor's additions.
        minor: f.minor.max(pt_format::container::MINOR),
        sections,
    };
    pt_format::canonicalize(&mut out);
    out
}

/// Convenience: a head value lookup on the first section of a kind.
pub fn head_of<'a>(f: &'a PtfFile, kind: &[u8; 4]) -> Option<&'a Map> {
    f.sections
        .iter()
        .find(|s| &s.kind == kind)
        .and_then(Section::head)
}

pub fn key(s: &str) -> Key {
    Key(s.to_string())
}
