//! Columns and their encodings (spec Part II §5).

use crate::cbor::{Key, Map, Value};
use crate::error::{Error, Result};

/// Logical column type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColType {
    U64,
    I64,
    F64,
    Bool,
}

impl ColType {
    pub fn name(self) -> &'static str {
        match self {
            ColType::U64 => "u64",
            ColType::I64 => "i64",
            ColType::F64 => "f64",
            ColType::Bool => "bool",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "u64" => ColType::U64,
            "i64" => ColType::I64,
            "f64" => ColType::F64,
            "bool" => ColType::Bool,
            _ => return None,
        })
    }
}

/// Column value encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enc {
    Plain,
    Varint,
    Delta,
    Delta2,
    Rle,
    Bitmap,
}

impl Enc {
    pub fn name(self) -> &'static str {
        match self {
            Enc::Plain => "plain",
            Enc::Varint => "varint",
            Enc::Delta => "delta",
            Enc::Delta2 => "delta2",
            Enc::Rle => "rle",
            Enc::Bitmap => "bitmap",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "plain" => Enc::Plain,
            "varint" => Enc::Varint,
            "delta" => Enc::Delta,
            "delta2" => Enc::Delta2,
            "rle" => Enc::Rle,
            "bitmap" => Enc::Bitmap,
            _ => return None,
        })
    }

    /// Whether the encoding is defined for the type.
    pub fn valid_for(self, t: ColType) -> bool {
        matches!(
            (t, self),
            (
                ColType::U64 | ColType::I64,
                Enc::Plain | Enc::Varint | Enc::Delta | Enc::Delta2 | Enc::Rle
            ) | (ColType::F64, Enc::Plain)
                | (ColType::Bool, Enc::Bitmap)
        )
    }
}

/// Values of the *present* rows of a column, in row order.
#[derive(Debug, Clone, PartialEq)]
pub enum Values {
    U64(Vec<u64>),
    I64(Vec<i64>),
    F64(Vec<f64>),
    Bool(Vec<bool>),
}

impl Values {
    pub fn col_type(&self) -> ColType {
        match self {
            Values::U64(_) => ColType::U64,
            Values::I64(_) => ColType::I64,
            Values::F64(_) => ColType::F64,
            Values::Bool(_) => ColType::Bool,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Values::U64(v) => v.len(),
            Values::I64(v) => v.len(),
            Values::F64(v) => v.len(),
            Values::Bool(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Column payload: decoded values, or an opaque blob when the type or encoding is unknown
/// to this reader (preserved byte-for-byte on rewrite, spec P6).
#[derive(Debug, Clone, PartialEq)]
pub enum Data {
    Known {
        enc: Enc,
        values: Values,
    },
    Opaque {
        type_name: String,
        enc_name: String,
        nullable: bool,
        /// The whole blob as stored, including any validity bitmap.
        blob: Vec<u8>,
    },
}

/// One column of a table.
#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub name: String,
    pub data: Data,
    /// Row validity, `Some` iff the column is nullable. Length equals the table's row count.
    pub validity: Option<Vec<bool>>,
    /// All other column-directory keys (`unit`, `clock`, `enum`, `pii`, `desc`, and unknown
    /// future keys), preserved verbatim.
    pub meta: Map,
}

const RESERVED_COLUMN_KEYS: &[&str] = &["name", "type", "enc", "len", "nullable"];

impl Column {
    /// A non-nullable column.
    pub fn new(name: &str, enc: Enc, values: Values) -> Self {
        Column {
            name: name.to_string(),
            data: Data::Known { enc, values },
            validity: None,
            meta: Map::new(),
        }
    }

    /// A nullable column from optional values.
    pub fn nullable_u64(name: &str, enc: Enc, rows: &[Option<u64>]) -> Self {
        let validity: Vec<bool> = rows.iter().map(Option::is_some).collect();
        let values = rows.iter().flatten().copied().collect();
        Column {
            name: name.to_string(),
            data: Data::Known {
                enc,
                values: Values::U64(values),
            },
            validity: Some(validity),
            meta: Map::new(),
        }
    }

    pub fn with_meta(mut self, key: &str, v: impl Into<Value>) -> Self {
        assert!(
            !RESERVED_COLUMN_KEYS.contains(&key),
            "reserved column key {key}"
        );
        self.meta.insert(Key(key.to_string()), v.into());
        self
    }

    pub fn unit(self, unit: &str) -> Self {
        self.with_meta("unit", unit)
    }

    pub fn clock(self, clock: &str) -> Self {
        self.with_meta("clock", clock)
    }

    pub fn meta_str(&self, key: &str) -> Option<&str> {
        self.meta.get(&Key(key.to_string()))?.as_str()
    }

    pub fn values(&self) -> Option<&Values> {
        match &self.data {
            Data::Known { values, .. } => Some(values),
            Data::Opaque { .. } => None,
        }
    }

    pub fn present_count(&self, rows: usize) -> usize {
        self.validity
            .as_ref()
            .map_or(rows, |v| v.iter().filter(|b| **b).count())
    }

    /// u64 values expanded to all rows (`None` for null rows). `None` if not a known u64 column.
    pub fn u64_rows(&self) -> Option<Vec<Option<u64>>> {
        let Some(Values::U64(vals)) = self.values() else {
            return None;
        };
        Some(expand(vals, self.validity.as_deref()))
    }

    pub fn i64_rows(&self) -> Option<Vec<Option<i64>>> {
        let Some(Values::I64(vals)) = self.values() else {
            return None;
        };
        Some(expand(vals, self.validity.as_deref()))
    }

    pub fn f64_rows(&self) -> Option<Vec<Option<f64>>> {
        let Some(Values::F64(vals)) = self.values() else {
            return None;
        };
        Some(expand(vals, self.validity.as_deref()))
    }

    pub fn bool_rows(&self) -> Option<Vec<Option<bool>>> {
        let Some(Values::Bool(vals)) = self.values() else {
            return None;
        };
        Some(expand(vals, self.validity.as_deref()))
    }

    /// Encode to (directory entry, blob).
    pub fn encode(&self, rows: usize) -> Result<(Value, Vec<u8>)> {
        let mut blob = Vec::new();
        if let Some(v) = &self.validity {
            if v.len() != rows {
                return Err(Error::Column(format!(
                    "{}: validity has {} rows, table has {rows}",
                    self.name,
                    v.len()
                )));
            }
            blob.extend(pack_bits(v));
        }
        let (type_name, enc_name) = match &self.data {
            Data::Known { enc, values } => {
                let t = values.col_type();
                if !enc.valid_for(t) {
                    return Err(Error::Column(format!(
                        "{}: encoding {} invalid for type {}",
                        self.name,
                        enc.name(),
                        t.name()
                    )));
                }
                let present = self.present_count(rows);
                if values.len() != present {
                    return Err(Error::Column(format!(
                        "{}: {} values for {present} present rows",
                        self.name,
                        values.len()
                    )));
                }
                encode_values(*enc, values, &mut blob);
                (t.name().to_string(), enc.name().to_string())
            }
            Data::Opaque {
                type_name,
                enc_name,
                blob: raw,
                ..
            } => {
                blob.clear();
                blob.extend_from_slice(raw);
                (type_name.clone(), enc_name.clone())
            }
        };
        let nullable = match &self.data {
            Data::Opaque { nullable, .. } => *nullable,
            Data::Known { .. } => self.validity.is_some(),
        };
        let mut dir = self.meta.clone();
        dir.insert("name".into(), Value::from(self.name.as_str()));
        dir.insert("type".into(), Value::Text(type_name));
        dir.insert("enc".into(), Value::Text(enc_name));
        dir.insert("len".into(), Value::from(blob.len()));
        if nullable {
            dir.insert("nullable".into(), Value::Bool(true));
        }
        Ok((Value::Map(dir), blob))
    }

    /// Decode from a directory entry and its blob.
    pub fn decode(dir: &Value, blob: &[u8], rows: usize) -> Result<Column> {
        let m = dir
            .as_map()
            .ok_or_else(|| Error::Column("column entry is not a map".into()))?;
        let get_str = |k: &str| {
            m.get(&Key(k.to_string()))
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Column(format!("column entry missing text `{k}`")))
        };
        let name = get_str("name")?.to_string();
        let type_name = get_str("type")?;
        let enc_name = get_str("enc")?;
        let nullable = match m.get(&Key::from("nullable")) {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(Error::Column(format!("{name}: `nullable` must be bool"))),
        };
        let mut meta = Map::new();
        for (k, v) in m {
            if !RESERVED_COLUMN_KEYS.contains(&k.0.as_str()) {
                meta.insert(k.clone(), v.clone());
            }
        }
        let (Some(t), Some(enc)) = (ColType::parse(type_name), Enc::parse(enc_name)) else {
            // Unknown type or encoding: keep opaque (spec: skip, never fail the file).
            return Ok(Column {
                name,
                data: Data::Opaque {
                    type_name: type_name.to_string(),
                    enc_name: enc_name.to_string(),
                    nullable,
                    blob: blob.to_vec(),
                },
                validity: None,
                meta,
            });
        };
        if !enc.valid_for(t) {
            return Err(Error::Column(format!(
                "{name}: encoding {enc_name} invalid for type {type_name}"
            )));
        }
        let mut pos = 0;
        let validity = if nullable {
            let nbytes = rows.div_ceil(8);
            if blob.len() < nbytes {
                return Err(Error::Column(format!("{name}: validity bitmap truncated")));
            }
            let v = unpack_bits(&blob[..nbytes], rows);
            if !rows.is_multiple_of(8) && blob[nbytes - 1] >> (rows % 8) != 0 {
                return Err(Error::Column(format!(
                    "{name}: padding bits set in validity"
                )));
            }
            pos = nbytes;
            Some(v)
        } else {
            None
        };
        let n = validity
            .as_ref()
            .map_or(rows, |v| v.iter().filter(|b| **b).count());
        let values = decode_values(t, enc, &blob[pos..], n)
            .map_err(|e| Error::Column(format!("{name}: {e}")))?;
        Ok(Column {
            name,
            data: Data::Known { enc, values },
            validity,
            meta,
        })
    }
}

fn expand<T: Copy>(vals: &[T], validity: Option<&[bool]>) -> Vec<Option<T>> {
    match validity {
        None => vals.iter().map(|v| Some(*v)).collect(),
        Some(valid) => {
            let mut it = vals.iter();
            valid
                .iter()
                .map(|p| if *p { it.next().copied() } else { None })
                .collect()
        }
    }
}

pub fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, b) in bits.iter().enumerate() {
        if *b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

pub fn unpack_bits(bytes: &[u8], n: usize) -> Vec<bool> {
    (0..n).map(|i| bytes[i / 8] >> (i % 8) & 1 == 1).collect()
}

pub fn write_leb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Read an unsigned LEB128. Rejects overlong (non-minimal) encodings and overflow, so that
/// every value has exactly one encoding.
pub fn read_leb128(b: &[u8], pos: &mut usize) -> std::result::Result<u64, String> {
    let mut v: u64 = 0;
    let mut shift = 0u32;
    loop {
        let Some(&byte) = b.get(*pos) else {
            return Err("truncated LEB128".into());
        };
        *pos += 1;
        let low = u64::from(byte & 0x7f);
        if shift == 63 && low > 1 {
            return Err("LEB128 overflow".into());
        }
        v |= low << shift;
        if byte & 0x80 == 0 {
            if byte == 0 && shift > 0 {
                return Err("overlong LEB128".into());
            }
            return Ok(v);
        }
        shift += 7;
        if shift > 63 {
            return Err("LEB128 overflow".into());
        }
    }
}

#[inline]
pub fn zigzag(x: i64) -> u64 {
    ((x << 1) ^ (x >> 63)) as u64
}

#[inline]
pub fn unzigzag(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

fn ints_as_i64(values: &Values) -> Vec<i64> {
    match values {
        Values::U64(v) => v.iter().map(|x| *x as i64).collect(),
        Values::I64(v) => v.clone(),
        _ => unreachable!("integer encoding on non-integer column"),
    }
}

fn encode_values(enc: Enc, values: &Values, out: &mut Vec<u8>) {
    match (enc, values) {
        (Enc::Plain, Values::U64(v)) => v.iter().for_each(|x| out.extend(x.to_le_bytes())),
        (Enc::Plain, Values::I64(v)) => v.iter().for_each(|x| out.extend(x.to_le_bytes())),
        (Enc::Plain, Values::F64(v)) => {
            v.iter().for_each(|x| out.extend(x.to_bits().to_le_bytes()))
        }
        (Enc::Bitmap, Values::Bool(v)) => out.extend(pack_bits(v)),
        (Enc::Varint, Values::U64(v)) => v.iter().for_each(|x| write_leb128(out, *x)),
        (Enc::Varint, Values::I64(v)) => v.iter().for_each(|x| write_leb128(out, zigzag(*x))),
        (Enc::Delta, _) => {
            let mut prev = 0i64;
            for x in ints_as_i64(values) {
                write_leb128(out, zigzag(x.wrapping_sub(prev)));
                prev = x;
            }
        }
        (Enc::Delta2, _) => {
            let (mut prev, mut prev_d) = (0i64, 0i64);
            for (i, x) in ints_as_i64(values).into_iter().enumerate() {
                if i == 0 {
                    write_leb128(out, zigzag(x));
                } else {
                    let d = x.wrapping_sub(prev);
                    write_leb128(out, zigzag(d.wrapping_sub(prev_d)));
                    prev_d = d;
                }
                prev = x;
            }
        }
        (Enc::Rle, _) => {
            let v = ints_as_i64(values);
            let mut i = 0;
            while i < v.len() {
                let mut j = i + 1;
                while j < v.len() && v[j] == v[i] {
                    j += 1;
                }
                write_leb128(out, zigzag(v[i]));
                write_leb128(out, (j - i) as u64);
                i = j;
            }
        }
        _ => unreachable!("validated by Enc::valid_for"),
    }
}

fn decode_values(t: ColType, enc: Enc, b: &[u8], n: usize) -> std::result::Result<Values, String> {
    let mut pos = 0usize;
    let ints = |v: Vec<i64>| match t {
        ColType::U64 => Values::U64(v.into_iter().map(|x| x as u64).collect()),
        _ => Values::I64(v),
    };
    // Every encoding needs at least one byte per value except bitmap and rle; bound
    // allocations by the input size (hostile `rows`).
    let cap = n.min(b.len().saturating_mul(8));
    let values = match enc {
        Enc::Plain => {
            if b.len() != n.checked_mul(8).ok_or("row count overflow")? {
                return Err(format!("plain: expected {} bytes, got {}", n * 8, b.len()));
            }
            pos = b.len();
            let words = b.as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c));
            match t {
                ColType::U64 => Values::U64(words.collect()),
                ColType::I64 => Values::I64(words.map(|w| w as i64).collect()),
                ColType::F64 => Values::F64(words.map(f64::from_bits).collect()),
                ColType::Bool => unreachable!(),
            }
        }
        Enc::Bitmap => {
            let nbytes = n.div_ceil(8);
            if b.len() != nbytes {
                return Err(format!("bitmap: expected {nbytes} bytes, got {}", b.len()));
            }
            if !n.is_multiple_of(8) && b[nbytes - 1] >> (n % 8) != 0 {
                return Err("bitmap: padding bits set".into());
            }
            pos = nbytes;
            Values::Bool(unpack_bits(b, n))
        }
        Enc::Varint => {
            let mut v = Vec::with_capacity(cap);
            for _ in 0..n {
                let u = read_leb128(b, &mut pos)?;
                v.push(if t == ColType::I64 {
                    unzigzag(u)
                } else {
                    u as i64
                });
            }
            ints(v)
        }
        Enc::Delta => {
            let mut v = Vec::with_capacity(cap);
            let mut prev = 0i64;
            for _ in 0..n {
                prev = prev.wrapping_add(unzigzag(read_leb128(b, &mut pos)?));
                v.push(prev);
            }
            ints(v)
        }
        Enc::Delta2 => {
            let mut v = Vec::with_capacity(cap);
            let (mut prev, mut prev_d) = (0i64, 0i64);
            for i in 0..n {
                let e = unzigzag(read_leb128(b, &mut pos)?);
                let x = if i == 0 {
                    e
                } else {
                    let d = prev_d.wrapping_add(e);
                    prev_d = d;
                    prev.wrapping_add(d)
                };
                prev = x;
                v.push(x);
            }
            ints(v)
        }
        Enc::Rle => {
            let mut v = Vec::with_capacity(cap);
            while v.len() < n {
                let val = unzigzag(read_leb128(b, &mut pos)?);
                let run = read_leb128(b, &mut pos)?;
                if run == 0 {
                    return Err("rle: zero-length run".into());
                }
                let run = usize::try_from(run).map_err(|_| "rle: run overflow")?;
                if run > n - v.len() {
                    return Err("rle: runs exceed row count".into());
                }
                if let Some(last) = v.last()
                    && *last == val
                {
                    return Err("rle: adjacent runs with equal value (non-canonical)".into());
                }
                v.extend(std::iter::repeat_n(val, run));
            }
            ints(v)
        }
    };
    if pos != b.len() {
        return Err(format!("{} trailing bytes in column blob", b.len() - pos));
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn roundtrip(c: &Column, rows: usize) -> Column {
        let (dir, blob) = c.encode(rows).unwrap();
        Column::decode(&dir, &blob, rows).unwrap()
    }

    proptest! {
        #[test]
        fn int_encodings_roundtrip(v in proptest::collection::vec(any::<u64>(), 0..200),
                                   enc in prop_oneof![Just(Enc::Plain), Just(Enc::Varint), Just(Enc::Delta), Just(Enc::Delta2), Just(Enc::Rle)]) {
            let c = Column::new("x", enc, Values::U64(v.clone()));
            prop_assert_eq!(roundtrip(&c, v.len()), c);
            let iv: Vec<i64> = v.iter().map(|x| *x as i64).collect();
            let c = Column::new("y", enc, Values::I64(iv.clone()));
            prop_assert_eq!(roundtrip(&c, iv.len()), c);
        }

        #[test]
        fn nullable_roundtrip(rows in proptest::collection::vec(proptest::option::of(any::<u64>()), 0..100)) {
            let c = Column::nullable_u64("n", Enc::Delta2, &rows);
            let back = roundtrip(&c, rows.len());
            prop_assert_eq!(back.u64_rows().unwrap(), rows);
        }

        #[test]
        fn f64_and_bool_roundtrip(f in proptest::collection::vec(any::<f64>(), 0..50), b in proptest::collection::vec(any::<bool>(), 0..70)) {
            let c = Column::new("f", Enc::Plain, Values::F64(f.clone()));
            let back = roundtrip(&c, f.len());
            let Some(Values::F64(g)) = back.values() else { panic!() };
            prop_assert!(f.iter().zip(g).all(|(a, b)| a.to_bits() == b.to_bits()));
            let c = Column::new("b", Enc::Bitmap, Values::Bool(b.clone()));
            prop_assert_eq!(roundtrip(&c, b.len()), c);
        }

        #[test]
        fn decode_never_panics(blob in proptest::collection::vec(any::<u8>(), 0..64), rows in 0usize..1000,
                               t in prop_oneof![Just("u64"), Just("i64"), Just("f64"), Just("bool")],
                               e in prop_oneof![Just("plain"), Just("varint"), Just("delta"), Just("delta2"), Just("rle"), Just("bitmap")],
                               nullable in any::<bool>()) {
            let dir = Value::map().with("name", "z").with("type", t).with("enc", e).with("len", blob.len()).with("nullable", nullable);
            let _ = Column::decode(&dir, &blob, rows);
        }
    }

    #[test]
    fn delta2_of_paced_times_is_small() {
        let times: Vec<u64> = (0..1000).map(|i| 1_000_000_000 + i * 20_000_000).collect();
        let c = Column::new("t", Enc::Delta2, Values::U64(times));
        let (_, blob) = c.encode(1000).unwrap();
        // First value ~5 bytes, second delta ~4 bytes, then 998 zero bytes.
        assert!(blob.len() < 1010, "{}", blob.len());
    }

    #[test]
    fn leb128_rejects_overlong() {
        let mut pos = 0;
        assert!(read_leb128(&[0x80, 0x00], &mut pos).is_err());
        let mut pos = 0;
        assert_eq!(read_leb128(&[0x00], &mut pos), Ok(0));
        let mut out = Vec::new();
        write_leb128(&mut out, u64::MAX);
        let mut pos = 0;
        assert_eq!(read_leb128(&out, &mut pos), Ok(u64::MAX));
        // 2^64 overflow
        let mut pos = 0;
        assert!(
            read_leb128(
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02],
                &mut pos
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_type_is_opaque() {
        let dir = Value::map()
            .with("name", "future")
            .with("type", "u128")
            .with("enc", "magic")
            .with("len", 3u64)
            .with("unit", "ns");
        let c = Column::decode(&dir, &[1, 2, 3], 10).unwrap();
        assert!(matches!(c.data, Data::Opaque { .. }));
        let (dir2, blob2) = c.encode(10).unwrap();
        assert_eq!(dir2, dir);
        assert_eq!(blob2, vec![1, 2, 3]);
    }

    #[test]
    fn rle_rejects_non_canonical_runs() {
        let mut blob = Vec::new();
        for _ in 0..2 {
            write_leb128(&mut blob, zigzag(5));
            write_leb128(&mut blob, 1);
        }
        assert!(decode_values(ColType::U64, Enc::Rle, &blob, 2).is_err());
    }
}
