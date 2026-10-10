//! Tables and the generic section payload (spec Part II §3, §5).

use crate::cbor::{self, Key, Map, Value};
use crate::column::Column;
use crate::error::{Error, Result};

/// A table: named rows of typed columns.
#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    pub name: String,
    pub rows: usize,
    pub columns: Vec<Column>,
    /// Other table-directory keys (`attrs` and unknown future keys), preserved verbatim.
    pub meta: Map,
}

const RESERVED_TABLE_KEYS: &[&str] = &["name", "rows", "columns"];

impl Table {
    pub fn new(name: &str, rows: usize) -> Self {
        Table {
            name: name.to_string(),
            rows,
            columns: Vec::new(),
            meta: Map::new(),
        }
    }

    pub fn with(mut self, c: Column) -> Self {
        self.columns.push(c);
        self
    }

    pub fn with_attrs(mut self, attrs: Value) -> Self {
        self.meta.insert("attrs".into(), attrs);
        self
    }

    pub fn attrs(&self) -> Option<&Value> {
        self.meta.get(&Key::from("attrs"))
    }

    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }

    fn encode(&self, blobs: &mut Vec<Vec<u8>>) -> Result<Value> {
        let mut cols = Vec::with_capacity(self.columns.len());
        for (i, c) in self.columns.iter().enumerate() {
            if self.columns[..i].iter().any(|p| p.name == c.name) {
                return Err(Error::Column(format!(
                    "duplicate column {} in table {}",
                    c.name, self.name
                )));
            }
            let (dir, blob) = c.encode(self.rows)?;
            cols.push(dir);
            blobs.push(blob);
        }
        let mut m = self.meta.clone();
        m.insert("name".into(), Value::from(self.name.as_str()));
        m.insert("rows".into(), Value::from(self.rows));
        m.insert("columns".into(), Value::Array(cols));
        Ok(Value::Map(m))
    }
}

/// The decoded content of a section payload.
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    /// Generic structure: CBOR head (without the `tables` key) plus tables.
    Parsed { head: Map, tables: Vec<Table> },
    /// Payload of an unknown non-critical section that does not follow the generic
    /// structure. Kept verbatim (uncompressed) for copy-through.
    Opaque(Vec<u8>),
}

/// Section flag bits (spec Part II §2).
pub mod flags {
    pub const CRITICAL: u16 = 1 << 0;
    pub const ZSTD: u16 = 1 << 1;
    pub const DERIVED: u16 = 1 << 2;
    pub const KNOWN: u16 = CRITICAL | ZSTD | DERIVED;
}

/// One section. `flags` here never includes the ZSTD bit: compression is a property of the
/// encoding, decided at write time.
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    pub kind: [u8; 4],
    pub flags: u16,
    pub body: Body,
}

impl Section {
    pub fn new(kind: &[u8; 4], flags: u16, head: Map) -> Self {
        Section {
            kind: *kind,
            flags: flags & !self::flags::ZSTD,
            body: Body::Parsed {
                head,
                tables: Vec::new(),
            },
        }
    }

    pub fn with_table(mut self, t: Table) -> Self {
        if let Body::Parsed { tables, .. } = &mut self.body {
            tables.push(t);
        }
        self
    }

    pub fn kind_str(&self) -> String {
        String::from_utf8_lossy(&self.kind).into_owned()
    }

    pub fn is_critical(&self) -> bool {
        self.flags & flags::CRITICAL != 0
    }

    pub fn is_derived(&self) -> bool {
        self.flags & flags::DERIVED != 0
    }

    pub fn head(&self) -> Option<&Map> {
        match &self.body {
            Body::Parsed { head, .. } => Some(head),
            Body::Opaque(_) => None,
        }
    }

    pub fn head_mut(&mut self) -> Option<&mut Map> {
        match &mut self.body {
            Body::Parsed { head, .. } => Some(head),
            Body::Opaque(_) => None,
        }
    }

    pub fn tables(&self) -> &[Table] {
        match &self.body {
            Body::Parsed { tables, .. } => tables,
            Body::Opaque(_) => &[],
        }
    }

    pub fn tables_mut(&mut self) -> Option<&mut Vec<Table>> {
        match &mut self.body {
            Body::Parsed { tables, .. } => Some(tables),
            Body::Opaque(_) => None,
        }
    }

    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables().iter().find(|t| t.name == name)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.head()?.get(&Key(key.to_string()))
    }

    /// Encode the uncompressed payload.
    pub fn encode_payload(&self) -> Result<Vec<u8>> {
        match &self.body {
            Body::Opaque(p) => Ok(p.clone()),
            Body::Parsed { head, tables } => {
                if head.contains_key(&Key::from("tables")) {
                    return Err(Error::Schema(
                        "head must not contain `tables` directly".into(),
                    ));
                }
                let mut blobs = Vec::new();
                let mut m = head.clone();
                if cbor::has_reserved_key(&Value::Map(m.clone())) {
                    return Err(Error::Schema(
                        "head map keys must not begin with `$`".into(),
                    ));
                }
                if !tables.is_empty() {
                    let mut tvals = Vec::with_capacity(tables.len());
                    for t in tables {
                        tvals.push(t.encode(&mut blobs)?);
                    }
                    m.insert("tables".into(), Value::Array(tvals));
                }
                let head_bytes = cbor::encode(&Value::Map(m))?;
                let total = 4 + head_bytes.len() + blobs.iter().map(Vec::len).sum::<usize>();
                let mut out = Vec::with_capacity(total);
                out.extend_from_slice(
                    &u32::try_from(head_bytes.len())
                        .map_err(|_| Error::Limit("head larger than 4 GiB".into()))?
                        .to_le_bytes(),
                );
                out.extend_from_slice(&head_bytes);
                for b in blobs {
                    out.extend_from_slice(&b);
                }
                Ok(out)
            }
        }
    }

    /// Decode an uncompressed payload with the generic structure.
    pub fn decode_payload(kind: [u8; 4], flags: u16, payload: &[u8]) -> Result<Section> {
        let (head, tables) = decode_generic(payload)?;
        Ok(Section {
            kind,
            flags: flags & !self::flags::ZSTD,
            body: Body::Parsed { head, tables },
        })
    }
}

fn decode_generic(payload: &[u8]) -> Result<(Map, Vec<Table>)> {
    if payload.len() < 4 {
        return Err(Error::Schema("payload shorter than head length".into()));
    }
    let hlen = u32::from_le_bytes(payload[..4].try_into().expect("4")) as usize;
    if hlen > payload.len() - 4 {
        return Err(Error::Schema("head length exceeds payload".into()));
    }
    let head = cbor::decode(&payload[4..4 + hlen])?;
    let Value::Map(mut head) = head else {
        return Err(Error::Schema("section head is not a map".into()));
    };
    let mut pos = 4 + hlen;
    let mut tables = Vec::new();
    if let Some(tv) = head.remove(&Key::from("tables")) {
        let Value::Array(tv) = tv else {
            return Err(Error::Schema("`tables` is not an array".into()));
        };
        for t in &tv {
            let tm = t
                .as_map()
                .ok_or_else(|| Error::Schema("table entry is not a map".into()))?;
            let name = t
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Schema("table missing `name`".into()))?
                .to_string();
            let rows = t
                .get("rows")
                .and_then(Value::as_u64)
                .and_then(|r| usize::try_from(r).ok())
                .ok_or_else(|| Error::Schema(format!("table {name} missing `rows`")))?;
            let cols = t
                .get("columns")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::Schema(format!("table {name} missing `columns`")))?;
            let mut columns = Vec::with_capacity(cols.len());
            for c in cols {
                let len = c
                    .get("len")
                    .and_then(Value::as_u64)
                    .and_then(|l| usize::try_from(l).ok())
                    .ok_or_else(|| Error::Column(format!("column in {name} missing `len`")))?;
                if len > payload.len() - pos {
                    return Err(Error::Column(format!(
                        "column blob in {name} exceeds payload"
                    )));
                }
                let col = Column::decode(c, &payload[pos..pos + len], rows)?;
                if columns.iter().any(|p: &Column| p.name == col.name) {
                    return Err(Error::Column(format!(
                        "duplicate column {} in table {name}",
                        col.name
                    )));
                }
                columns.push(col);
                pos += len;
            }
            let mut meta = Map::new();
            for (k, v) in tm {
                if !RESERVED_TABLE_KEYS.contains(&k.0.as_str()) {
                    meta.insert(k.clone(), v.clone());
                }
            }
            tables.push(Table {
                name,
                rows,
                columns,
                meta,
            });
        }
    }
    if pos != payload.len() {
        return Err(Error::Schema(format!(
            "{} trailing bytes after last column blob",
            payload.len() - pos
        )));
    }
    Ok((head, tables))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::column::{Enc, Values};

    #[test]
    fn payload_roundtrip() {
        let t = Table::new("pkt", 3)
            .with(Column::new("seq", Enc::Delta, Values::U64(vec![1, 2, 3])).unit("count"))
            .with(
                Column::nullable_u64("rx", Enc::Delta2, &[Some(10), None, Some(30)])
                    .clock("b.real"),
            )
            .with_attrs(Value::map().with("flow", 1u64));
        let s = Section::new(b"OBSV", 0, Map::new()).with_table(t);
        let p = s.encode_payload().unwrap();
        let back = Section::decode_payload(*b"OBSV", 0, &p).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.encode_payload().unwrap(), p);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let s = Section::new(b"META", 1, Map::new());
        let mut p = s.encode_payload().unwrap();
        p.push(0);
        assert!(Section::decode_payload(*b"META", 1, &p).is_err());
    }
}
