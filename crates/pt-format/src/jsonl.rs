//! Lossless JSON Lines twin (spec P11, REQ-FMT-014).
//!
//! Line 1: `{"ptf":{"major":M,"minor":m}}`. Then one object per section:
//! `{"type":"OBSV","flags":0,"head":{...},"tables":[{"name":..,"rows":..,"meta":{..},
//!   "columns":[{"name":..,"type":..,"enc":..,"nullable":..,"meta":{..},"values":[..]}]}]}`.
//! Opaque sections: `{"type":..,"flags":..,"opaque_hex":".."}`. Opaque columns carry
//! `"blob_hex"` instead of `"values"`.
//!
//! CBOR → JSON: unsigned/negative integers → JSON integers (negative beyond i64 →
//! `{"$nint":"<n>"}` meaning -1-n), floats → JSON numbers with a fraction or exponent
//! (non-finite → `{"$f64":"NaN"|"inf"|"-inf"}`), byte strings → `{"$bytes":"<hex>"}`.
//! PTF heads never use map keys beginning with `$` (spec Part II §4), so these tags are
//! unambiguous.

use serde_json::{Map as JMap, Number, Value as J, json};

use crate::cbor::{Key, Map, Value};
use crate::column::{ColType, Column, Data, Enc, Values};
use crate::container::PtfFile;
use crate::error::{Error, Result};
use crate::section::{Body, Section, Table};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Json("odd-length hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::Json("bad hex".into())))
        .collect()
}

fn f64_json(f: f64) -> J {
    if f.is_nan() {
        json!({"$f64": "NaN"})
    } else if f.is_infinite() {
        json!({"$f64": if f > 0.0 { "inf" } else { "-inf" }})
    } else {
        J::Number(Number::from_f64(f).expect("finite"))
    }
}

pub fn cbor_to_json(v: &Value) -> J {
    match v {
        Value::Uint(u) => J::from(*u),
        Value::Nint(n) => match i64::try_from(*n) {
            Ok(n) => J::from(-1 - n),
            Err(_) => json!({"$nint": n.to_string()}),
        },
        Value::Bytes(b) => json!({"$bytes": hex(b)}),
        Value::Text(s) => J::String(s.clone()),
        Value::Array(a) => J::Array(a.iter().map(cbor_to_json).collect()),
        Value::Map(m) => J::Object(map_to_json(m)),
        Value::Bool(b) => J::Bool(*b),
        Value::Null => J::Null,
        Value::Float(f) => f64_json(*f),
    }
}

fn map_to_json(m: &Map) -> JMap<String, J> {
    m.iter()
        .map(|(k, v)| (k.0.clone(), cbor_to_json(v)))
        .collect()
}

fn json_f64(j: &J) -> Option<f64> {
    match j {
        J::Number(n) if n.is_f64() => n.as_f64(),
        J::Object(o) if o.len() == 1 => match o.get("$f64")?.as_str()? {
            "NaN" => Some(f64::NAN),
            "inf" => Some(f64::INFINITY),
            "-inf" => Some(f64::NEG_INFINITY),
            _ => None,
        },
        _ => None,
    }
}

pub fn json_to_cbor(j: &J) -> Result<Value> {
    Ok(match j {
        J::Null => Value::Null,
        J::Bool(b) => Value::Bool(*b),
        J::Number(n) => {
            if let Some(u) = n.as_u64() {
                Value::Uint(u)
            } else if let Some(i) = n.as_i64() {
                Value::int(i)
            } else {
                Value::Float(n.as_f64().ok_or_else(|| Error::Json("bad number".into()))?)
            }
        }
        J::String(s) => Value::Text(s.clone()),
        J::Array(a) => Value::Array(a.iter().map(json_to_cbor).collect::<Result<_>>()?),
        J::Object(o) => {
            if o.len() == 1 {
                let (k, v) = o.iter().next().expect("len 1");
                match k.as_str() {
                    "$bytes" => return Ok(Value::Bytes(unhex(v.as_str().unwrap_or("?"))?)),
                    "$nint" => {
                        let n = v
                            .as_str()
                            .and_then(|s| s.parse::<u64>().ok())
                            .ok_or_else(|| Error::Json("bad $nint".into()))?;
                        return Ok(Value::Nint(n));
                    }
                    "$f64" => {
                        return json_f64(j)
                            .map(Value::Float)
                            .ok_or_else(|| Error::Json("bad $f64".into()));
                    }
                    _ => {}
                }
            }
            Value::Map(json_to_map(o)?)
        }
    })
}

fn json_to_map(o: &JMap<String, J>) -> Result<Map> {
    let mut m = Map::new();
    for (k, v) in o {
        m.insert(Key(k.clone()), json_to_cbor(v)?);
    }
    Ok(m)
}

fn column_json(c: &Column) -> J {
    let mut o = JMap::new();
    o.insert("name".into(), J::from(c.name.clone()));
    o.insert("meta".into(), J::Object(map_to_json(&c.meta)));
    match &c.data {
        Data::Known { enc, values } => {
            o.insert("type".into(), J::from(values.col_type().name()));
            o.insert("enc".into(), J::from(enc.name()));
            o.insert("nullable".into(), J::Bool(c.validity.is_some()));
            let present: Vec<J> = match values {
                Values::U64(v) => v.iter().map(|x| J::from(*x)).collect(),
                Values::I64(v) => v.iter().map(|x| J::from(*x)).collect(),
                Values::F64(v) => v.iter().map(|x| f64_json(*x)).collect(),
                Values::Bool(v) => v.iter().map(|x| J::Bool(*x)).collect(),
            };
            let all = match &c.validity {
                None => present,
                Some(valid) => {
                    let mut it = present.into_iter();
                    valid
                        .iter()
                        .map(|p| {
                            if *p {
                                it.next().unwrap_or(J::Null)
                            } else {
                                J::Null
                            }
                        })
                        .collect()
                }
            };
            o.insert("values".into(), J::Array(all));
        }
        Data::Opaque {
            type_name,
            enc_name,
            nullable,
            blob,
        } => {
            o.insert("type".into(), J::from(type_name.clone()));
            o.insert("enc".into(), J::from(enc_name.clone()));
            o.insert("nullable".into(), J::Bool(*nullable));
            o.insert("blob_hex".into(), J::from(hex(blob)));
        }
    }
    J::Object(o)
}

fn section_json(s: &Section) -> J {
    let mut o = JMap::new();
    o.insert("type".into(), J::from(s.kind_str()));
    o.insert("flags".into(), J::from(s.flags));
    match &s.body {
        Body::Opaque(p) => {
            o.insert("opaque_hex".into(), J::from(hex(p)));
        }
        Body::Parsed { head, tables } => {
            o.insert("head".into(), J::Object(map_to_json(head)));
            let ts: Vec<J> = tables
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "rows": t.rows,
                        "meta": J::Object(map_to_json(&t.meta)),
                        "columns": t.columns.iter().map(column_json).collect::<Vec<_>>(),
                    })
                })
                .collect();
            o.insert("tables".into(), J::Array(ts));
        }
    }
    J::Object(o)
}

/// Dump a file as JSON Lines.
pub fn dump(f: &PtfFile) -> String {
    let mut out = json!({"ptf": {"major": f.major, "minor": f.minor}}).to_string();
    out.push('\n');
    for s in &f.sections {
        out.push_str(&section_json(s).to_string());
        out.push('\n');
    }
    out
}

fn field<'a>(o: &'a JMap<String, J>, k: &str) -> Result<&'a J> {
    o.get(k)
        .ok_or_else(|| Error::Json(format!("missing `{k}`")))
}

fn obj(j: &J) -> Result<&JMap<String, J>> {
    j.as_object()
        .ok_or_else(|| Error::Json("expected object".into()))
}

fn str_of<'a>(o: &'a JMap<String, J>, k: &str) -> Result<&'a str> {
    field(o, k)?
        .as_str()
        .ok_or_else(|| Error::Json(format!("`{k}` must be a string")))
}

fn load_column(cj: &J, rows: usize) -> Result<Column> {
    let o = obj(cj)?;
    let name = str_of(o, "name")?.to_string();
    let meta = json_to_map(obj(field(o, "meta")?)?)?;
    let type_name = str_of(o, "type")?;
    let enc_name = str_of(o, "enc")?;
    let nullable = field(o, "nullable")?.as_bool().unwrap_or(false);
    if let Some(h) = o.get("blob_hex") {
        return Ok(Column {
            name,
            data: Data::Opaque {
                type_name: type_name.to_string(),
                enc_name: enc_name.to_string(),
                nullable,
                blob: unhex(h.as_str().unwrap_or("?"))?,
            },
            validity: None,
            meta,
        });
    }
    let (Some(t), Some(enc)) = (ColType::parse(type_name), Enc::parse(enc_name)) else {
        return Err(Error::Json(format!(
            "{name}: unknown type/enc without blob_hex"
        )));
    };
    let vals = field(o, "values")?
        .as_array()
        .ok_or_else(|| Error::Json(format!("{name}: values must be an array")))?;
    if vals.len() != rows {
        return Err(Error::Json(format!(
            "{name}: {} values for {rows} rows",
            vals.len()
        )));
    }
    let validity = nullable.then(|| vals.iter().map(|v| !v.is_null()).collect::<Vec<_>>());
    let present = vals.iter().filter(|v| !(nullable && v.is_null()));
    let bad = || Error::Json(format!("{name}: value does not match type {type_name}"));
    let values = match t {
        ColType::U64 => Values::U64(
            present
                .map(|v| v.as_u64().ok_or_else(bad))
                .collect::<Result<_>>()?,
        ),
        ColType::I64 => Values::I64(
            present
                .map(|v| v.as_i64().ok_or_else(bad))
                .collect::<Result<_>>()?,
        ),
        ColType::F64 => Values::F64(
            present
                .map(|v| json_f64(v).ok_or_else(bad))
                .collect::<Result<_>>()?,
        ),
        ColType::Bool => Values::Bool(
            present
                .map(|v| v.as_bool().ok_or_else(bad))
                .collect::<Result<_>>()?,
        ),
    };
    Ok(Column {
        name,
        data: Data::Known { enc, values },
        validity,
        meta,
    })
}

/// Load JSON Lines produced by [`dump`].
pub fn load(text: &str) -> Result<PtfFile> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let first: J = serde_json::from_str(
        lines
            .next()
            .ok_or_else(|| Error::Json("empty input".into()))?,
    )
    .map_err(|e| Error::Json(e.to_string()))?;
    let ver = obj(field(obj(&first)?, "ptf")?)?;
    let num = |k: &str| -> Result<u16> {
        field(ver, k)?
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| Error::Json(format!("bad `{k}`")))
    };
    let (major, minor) = (num("major")?, num("minor")?);
    let mut sections = Vec::new();
    for line in lines {
        let j: J = serde_json::from_str(line).map_err(|e| Error::Json(e.to_string()))?;
        let o = obj(&j)?;
        let t = str_of(o, "type")?.as_bytes();
        let kind: [u8; 4] = t
            .try_into()
            .map_err(|_| Error::Json("section type must be 4 bytes".into()))?;
        let flags = field(o, "flags")?
            .as_u64()
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| Error::Json("bad flags".into()))?;
        let body = if let Some(h) = o.get("opaque_hex") {
            Body::Opaque(unhex(h.as_str().unwrap_or("?"))?)
        } else {
            let head = json_to_map(obj(field(o, "head")?)?)?;
            let mut tables = Vec::new();
            for tj in field(o, "tables")?
                .as_array()
                .ok_or_else(|| Error::Json("tables".into()))?
            {
                let to = obj(tj)?;
                let rows = field(to, "rows")?
                    .as_u64()
                    .and_then(|r| usize::try_from(r).ok())
                    .ok_or_else(|| Error::Json("bad rows".into()))?;
                let columns = field(to, "columns")?
                    .as_array()
                    .ok_or_else(|| Error::Json("columns".into()))?
                    .iter()
                    .map(|c| load_column(c, rows))
                    .collect::<Result<_>>()?;
                tables.push(Table {
                    name: str_of(to, "name")?.to_string(),
                    rows,
                    columns,
                    meta: json_to_map(obj(field(to, "meta")?)?)?,
                });
            }
            Body::Parsed { head, tables }
        };
        sections.push(Section { kind, flags, body });
    }
    Ok(PtfFile {
        major,
        minor,
        sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{ReadOptions, WriteOptions, read, write};
    use crate::section::flags;

    #[test]
    fn dump_load_is_byte_identical() {
        let meta = Section::new(
            b"META",
            flags::CRITICAL,
            Value::map()
                .with("kind", "trace")
                .with("neg", Value::int(-5))
                .with("bin", Value::Bytes(vec![0, 255]))
                .with("f", Value::Float(1.0))
                .with("nan", Value::Float(f64::NAN))
                .with("big", Value::Nint(u64::MAX))
                .as_map()
                .cloned()
                .unwrap_or_default(),
        );
        let t = Table::new("pkt", 4)
            .with(Column::new(
                "a",
                Enc::Delta2,
                Values::U64(vec![1, 5, 9, u64::MAX]),
            ))
            .with(Column::nullable_u64(
                "b",
                Enc::Rle,
                &[None, Some(2), Some(2), None],
            ))
            .with(Column::new(
                "c",
                Enc::Plain,
                Values::F64(vec![0.5, -0.0, f64::INFINITY, 3.0]),
            ))
            .with(Column::new(
                "d",
                Enc::Bitmap,
                Values::Bool(vec![true, false, true, true]),
            ))
            .with(
                Column::new(
                    "e",
                    Enc::Varint,
                    Values::I64(vec![-1, i64::MIN, 0, i64::MAX]),
                )
                .unit("ns"),
            );
        let obsv = Section::new(b"OBSV", 0, Map::new()).with_table(t);
        let unknown = Section {
            kind: *b"ZZZZ",
            flags: 0,
            body: Body::Opaque(vec![1, 2, 3]),
        };
        let f = PtfFile {
            major: 1,
            minor: 0,
            sections: vec![meta, obsv, unknown],
        };
        let mut a = Vec::new();
        write(&f, &WriteOptions::canonical(), &mut a).unwrap();
        let (parsed, _) = read(&a, ReadOptions::default()).unwrap();
        let text = dump(&parsed);
        let loaded = load(&text).unwrap();
        let mut b = Vec::new();
        write(&loaded, &WriteOptions::canonical(), &mut b).unwrap();
        assert_eq!(a, b);
    }
}
