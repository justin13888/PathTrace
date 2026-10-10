//! Generic redaction driven by privacy annotations (spec Part II §9, REQ-FMT-017).
//!
//! No per-field code: every identifying item is tagged where it lives (`pii` pointers in section
//! heads, `pii` on columns), so redaction also covers sections and columns added by future
//! versions.

use crate::cbor::{Key, Map, Value};
use crate::container::PtfFile;
use crate::error::{Error, Result};
use crate::section::Body;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Keep everything (no-op).
    Full,
    /// Remove `id` items.
    Shareable,
    /// Remove `id` and `quasi` items and shift realtime clock domains to start at 0.
    Anonymous,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "full" => Level::Full,
            "shareable" => Level::Shareable,
            "anonymous" => Level::Anonymous,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Level::Full => "full",
            Level::Shareable => "shareable",
            Level::Anonymous => "anonymous",
        }
    }
    fn removes(self, class: &str) -> bool {
        match self {
            Level::Full => false,
            Level::Shareable => class == "id",
            Level::Anonymous => class == "id" || class == "quasi",
        }
    }
}

/// Counts of what was removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub pointers: usize,
    pub columns: usize,
    pub shifted_columns: usize,
}

fn origin_of(meta: &Value, domain: &str) -> Option<u64> {
    // Domains are "<endpoint>.real"; the origin is that endpoint's session start time.
    let ep = domain.strip_suffix(".real")?;
    let s = meta.get("session")?;
    s.get(ep)
        .and_then(|e| e.get("t0_real"))
        .or_else(|| s.get("t0_real"))
        .and_then(Value::as_u64)
}

/// Redact `file` to `level`. Derived sections are left in place; callers must regenerate them
/// (they contain no identifying data, but the spec requires regeneration after raw changes).
pub fn redact(file: &PtfFile, level: Level) -> Result<(PtfFile, Report)> {
    let mut out = file.clone();
    let mut rep = Report::default();
    if level == Level::Full {
        return Ok((out, rep));
    }
    let meta = Value::Map(
        out.sections
            .first()
            .and_then(|s| s.head())
            .cloned()
            .ok_or_else(|| Error::Schema("no META".into()))?,
    );
    if let Some(prev) = meta.get("redaction").and_then(Value::as_str)
        && (prev == "anonymous" || (prev == "shareable" && level == Level::Shareable))
    {
        // Already at least this level: idempotent.
        return Ok((out, rep));
    }
    for s in &mut out.sections {
        let Body::Parsed { head, tables } = &mut s.body else {
            continue;
        };
        if let Some(Value::Map(pii)) = head.get(&Key::from("pii")).cloned() {
            let mut keep = Map::new();
            let mut v = Value::Map(head.clone());
            for (ptr, class) in &pii {
                let class = class.as_str().unwrap_or("id");
                if level.removes(class) {
                    if v.redact_pointer(&ptr.0) {
                        rep.pointers += 1;
                    }
                } else {
                    keep.insert(ptr.clone(), Value::from(class));
                }
            }
            let Value::Map(mut h) = v else {
                unreachable!("map stays a map")
            };
            if keep.is_empty() {
                h.remove(&Key::from("pii"));
            } else {
                h.insert(Key::from("pii"), Value::Map(keep));
            }
            *head = h;
        }
        for t in tables.iter_mut() {
            let before = t.columns.len();
            t.columns
                .retain(|c| !c.meta_str("pii").is_some_and(|p| level.removes(p)));
            rep.columns += before - t.columns.len();
            if level == Level::Anonymous {
                for c in &mut t.columns {
                    let Some(clock) = c.meta_str("clock").map(str::to_string) else {
                        continue;
                    };
                    if !clock.ends_with(".real") {
                        continue;
                    }
                    let Some(origin) = origin_of(&meta, &clock) else {
                        continue;
                    };
                    if let crate::column::Data::Known {
                        values: crate::column::Values::U64(v),
                        ..
                    } = &mut c.data
                    {
                        for x in v.iter_mut() {
                            *x = x.wrapping_sub(origin);
                        }
                        rep.shifted_columns += 1;
                    }
                }
            }
        }
    }
    // META: record the level; shift notes for realtime domains; drop session wall-clock origins.
    if let Some(Body::Parsed { head, .. }) = out.sections.first_mut().map(|s| &mut s.body) {
        head.insert(Key::from("redaction"), Value::from(level.name()));
        if level == Level::Anonymous {
            if let Some(Value::Map(clocks)) = head.get_mut(&Key::from("clocks")) {
                for (k, v) in clocks.iter_mut() {
                    if k.0.ends_with(".real")
                        && let Value::Map(m) = v
                    {
                        m.insert(Key::from("shifted"), Value::Bool(true));
                    }
                }
            }
            let mut h = Value::Map(head.clone());
            for ep in ["a", "b", ""] {
                let ptr = if ep.is_empty() {
                    "/session/t0_real".to_string()
                } else {
                    format!("/session/{ep}/t0_real")
                };
                h.redact_pointer(&ptr);
            }
            if let Value::Map(m) = h {
                *head = m;
            }
        }
    }
    Ok((out, rep))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::column::{Column, Enc, Values};
    use crate::section::{Section, Table, flags};

    fn sample() -> PtfFile {
        let meta = Value::map()
            .with("kind", "trace")
            .with("redaction", "full")
            .with(
                "network",
                Value::map()
                    .with("label", "Hotel X")
                    .with("class", "hotel-wifi")
                    .with("asn", 64500u64),
            )
            .with(
                "session",
                Value::map().with("a", Value::map().with("t0_real", 1_000u64)),
            )
            .with(
                "clocks",
                Value::map().with("a.real", Value::map().with("kind", "realtime")),
            )
            .with(
                "pii",
                Value::map()
                    .with("/network/label", "id")
                    .with("/network/asn", "quasi"),
            );
        let t = Table::new("pkt", 2)
            .with(Column::new("rx", Enc::Delta, Values::U64(vec![1_500, 2_000])).clock("a.real"))
            .with(Column::new("addr", Enc::Plain, Values::U64(vec![7, 7])).with_meta("pii", "id"))
            .with(
                Column::new("bss", Enc::Plain, Values::U64(vec![9, 9])).with_meta("pii", "quasi"),
            );
        PtfFile {
            major: 1,
            minor: 0,
            sections: vec![
                Section::new(
                    b"META",
                    flags::CRITICAL,
                    meta.as_map().cloned().unwrap_or_default(),
                ),
                Section::new(b"OBSV", 0, Map::new()).with_table(t),
            ],
        }
    }

    #[test]
    fn shareable_and_anonymous() {
        let f = sample();
        let (s, r) = redact(&f, Level::Shareable).unwrap();
        assert_eq!(r.pointers, 1);
        assert_eq!(r.columns, 1);
        let m = Value::Map(s.sections[0].head().unwrap().clone());
        assert!(m.pointer("/network/label").is_none());
        assert!(m.pointer("/network/asn").is_some());
        assert_eq!(
            m.get("redaction").and_then(Value::as_str),
            Some("shareable")
        );
        let (a, r) = redact(&f, Level::Anonymous).unwrap();
        assert_eq!(r.columns, 2);
        assert_eq!(r.shifted_columns, 1);
        let t = a.sections[1].table("pkt").unwrap();
        assert_eq!(
            t.column("rx").unwrap().u64_rows().unwrap(),
            vec![Some(500), Some(1_000)]
        );
        let m = Value::Map(a.sections[0].head().unwrap().clone());
        assert!(m.pointer("/network/asn").is_none());
        assert!(m.pointer("/session/a/t0_real").is_none());
        assert_eq!(
            m.pointer("/clocks/a.real/shifted"),
            Some(&Value::Bool(true))
        );
    }
}
