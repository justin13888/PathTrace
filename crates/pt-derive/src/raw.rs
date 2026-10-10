//! Load the raw layer of a trace into convenient row-major structures.

use std::collections::BTreeMap;

use pt_format::{PtfFile, Table, Value};

/// All rows of a table name (and attribute filter), concatenated across chunks, as
/// column name → optional i64 rows.
#[derive(Debug, Clone, Default)]
pub struct Rows {
    pub n: usize,
    pub cols: BTreeMap<String, Vec<Option<i64>>>,
}

impl Rows {
    pub fn col(&self, name: &str) -> &[Option<i64>] {
        self.cols.get(name).map_or(&[], Vec::as_slice)
    }

    pub fn get(&self, name: &str, i: usize) -> Option<i64> {
        self.cols
            .get(name)
            .and_then(|c| c.get(i).copied().flatten())
    }

    fn append(&mut self, t: &Table) {
        for c in &t.columns {
            let rows: Vec<Option<i64>> = if let Some(r) = c.u64_rows() {
                r.into_iter().map(|v| v.map(|x| x as i64)).collect()
            } else if let Some(r) = c.i64_rows() {
                r
            } else {
                continue;
            };
            let col = self
                .cols
                .entry(c.name.clone())
                .or_insert_with(|| vec![None; self.n]);
            col.extend(rows);
        }
        self.n += t.rows;
        for c in self.cols.values_mut() {
            c.resize(self.n, None);
        }
    }
}

/// The raw layer of a merged trace.
#[derive(Debug, Clone, Default)]
pub struct Raw {
    pub meta: Value,
    pub flows: BTreeMap<u64, Value>,
    pub events: Vec<Value>,
    /// Keyed by `name[attr]` (e.g. `pkt[a_to_b]`, `pairs[a]`).
    pub tables: BTreeMap<String, Rows>,
}

impl Raw {
    pub fn load(f: &PtfFile) -> Raw {
        let mut r = Raw {
            meta: Value::Map(
                f.sections
                    .first()
                    .and_then(|s| s.head())
                    .cloned()
                    .unwrap_or_default(),
            ),
            ..Default::default()
        };
        for s in &f.sections {
            if s.is_derived() {
                continue;
            }
            match &s.kind {
                b"FLOW" => {
                    for fl in s.get("flows").and_then(Value::as_array).unwrap_or(&[]) {
                        if let Some(id) = fl.get("id").and_then(Value::as_u64) {
                            r.flows.insert(id, fl.clone());
                        }
                    }
                }
                b"EVNT" => r.events.extend(
                    s.get("events")
                        .and_then(Value::as_array)
                        .unwrap_or(&[])
                        .iter()
                        .cloned(),
                ),
                _ => {}
            }
            for t in s.tables() {
                let attr = t
                    .attrs()
                    .and_then(|a| a.get("dir").or_else(|| a.get("endpoint")))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                r.tables
                    .entry(format!("{}[{attr}]", t.name))
                    .or_default()
                    .append(t);
            }
        }
        r
    }

    pub fn table(&self, key: &str) -> Option<&Rows> {
        self.tables.get(key)
    }

    pub fn flow_kind(&self, id: i64) -> &str {
        self.flows
            .get(&(id as u64))
            .and_then(|f| f.get("kind"))
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    pub fn flow_phase(&self, id: i64) -> u64 {
        self.flows
            .get(&(id as u64))
            .and_then(|f| f.get("phase"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }

    pub fn flow_class(&self, id: i64) -> &str {
        self.flows
            .get(&(id as u64))
            .and_then(|f| f.get("class"))
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    pub fn events_of(&self, kind: &str) -> impl Iterator<Item = &Value> {
        let kind = kind.to_string();
        self.events
            .iter()
            .filter(move |e| e.get("type").and_then(Value::as_str) == Some(kind.as_str()))
    }

    /// `META.session.a.t0_mono` (trace time origin).
    pub fn t0_a(&self) -> i64 {
        self.meta
            .get("session")
            .and_then(|s| s.get("a"))
            .and_then(|a| a.get("t0_mono"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as i64
    }
}
