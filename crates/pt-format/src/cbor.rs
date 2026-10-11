//! Deterministic CBOR profile used for PTF section heads (spec Part II §4).
//!
//! A small in-crate codec (ADR 0011) so that the profile is enforced exactly in both
//! directions: the encoder can only produce canonical bytes, and the decoder rejects anything
//! non-canonical (key order, non-shortest lengths, indefinite lengths, tags, non-f64 floats,
//! non-canonical NaN, excessive depth).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// Maximum nesting depth of arrays/maps (spec Part II §4).
pub const MAX_DEPTH: usize = 32;

const CANONICAL_NAN: u64 = 0x7ff8_0000_0000_0000;

/// A map key. Ordered as the profile requires: by encoded bytes, which for text keys
/// is shorter-first, then bytewise.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key(pub String);

impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.as_bytes().cmp(other.0.as_bytes()))
    }
}

impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        Key(s.to_string())
    }
}

pub type Map = BTreeMap<Key, Value>;

/// A CBOR data item within the PTF profile.
#[derive(Debug, Clone, Default)]
pub enum Value {
    /// Major type 0.
    Uint(u64),
    /// Major type 1: the value is `-1 - n`.
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Map),
    Bool(bool),
    #[default]
    Null,
    Float(f64),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        use Value::*;
        match (self, other) {
            (Uint(a), Uint(b)) | (Nint(a), Nint(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Text(a), Text(b)) => a == b,
            (Array(a), Array(b)) => a == b,
            (Map(a), Map(b)) => a == b,
            (Bool(a), Bool(b)) => a == b,
            (Null, Null) => true,
            // Bitwise: NaN == NaN and 0.0 != -0.0, matching encoded identity.
            (Float(a), Float(b)) => canonical_f64_bits(*a) == canonical_f64_bits(*b),
            _ => false,
        }
    }
}

fn canonical_f64_bits(f: f64) -> u64 {
    if f.is_nan() {
        CANONICAL_NAN
    } else {
        f.to_bits()
    }
}

impl Value {
    pub fn map() -> Value {
        Value::Map(Map::new())
    }

    /// Builder: insert `key` into a map value. Panics if `self` is not a map (programming error).
    pub fn with(mut self, key: &str, v: impl Into<Value>) -> Value {
        match &mut self {
            Value::Map(m) => {
                m.insert(Key(key.to_string()), v.into());
            }
            _ => panic!("Value::with on non-map"),
        }
        self
    }

    pub fn int(i: i64) -> Value {
        if i >= 0 {
            Value::Uint(i as u64)
        } else {
            Value::Nint((-(i + 1)) as u64)
        }
    }

    pub fn as_map(&self) -> Option<&Map> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_map_mut(&mut self) -> Option<&mut Map> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(u) => Some(*u),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Uint(u) => i64::try_from(*u).ok(),
            Value::Nint(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Map lookup convenience: `None` if not a map or key absent.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_map()?.get(&Key(key.to_string()))
    }

    /// Resolve an RFC 6901 JSON Pointer.
    pub fn pointer(&self, ptr: &str) -> Option<&Value> {
        if ptr.is_empty() {
            return Some(self);
        }
        let mut cur = self;
        for tok in ptr.strip_prefix('/')?.split('/') {
            let tok = tok.replace("~1", "/").replace("~0", "~");
            cur = match cur {
                Value::Map(m) => m.get(&Key(tok))?,
                Value::Array(a) => a.get(tok.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(cur)
    }

    /// Remove the item at an RFC 6901 pointer: map entries are deleted, array elements
    /// become `null` (so sibling indices stay stable). Returns whether something was removed.
    pub fn redact_pointer(&mut self, ptr: &str) -> bool {
        let Some(rest) = ptr.strip_prefix('/') else {
            return false;
        };
        let toks: Vec<String> = rest
            .split('/')
            .map(|t| t.replace("~1", "/").replace("~0", "~"))
            .collect();
        let (last, parents) = toks.split_last().expect("split of non-empty");
        let mut cur = self;
        for tok in parents {
            cur = match cur {
                Value::Map(m) => match m.get_mut(&Key(tok.clone())) {
                    Some(v) => v,
                    None => return false,
                },
                Value::Array(a) => match tok.parse::<usize>().ok().and_then(|i| a.get_mut(i)) {
                    Some(v) => v,
                    None => return false,
                },
                _ => return false,
            };
        }
        match cur {
            Value::Map(m) => m.remove(&Key(last.clone())).is_some(),
            Value::Array(a) => match last.parse::<usize>().ok().and_then(|i| a.get_mut(i)) {
                Some(v) => {
                    *v = Value::Null;
                    true
                }
                None => false,
            },
            _ => false,
        }
    }
}

macro_rules! from_uint {
    ($($t:ty),*) => {$(impl From<$t> for Value { fn from(v: $t) -> Self { Value::Uint(v as u64) } })*};
}
from_uint!(u8, u16, u32, u64, usize);

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::int(v)
    }
}
impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::int(i64::from(v))
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Self {
        Value::Float(v)
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Text(v.to_string())
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Text(v)
    }
}
impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::Array(v)
    }
}
impl From<Map> for Value {
    fn from(v: Map) -> Self {
        Value::Map(v)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Value::Null, Into::into)
    }
}

fn write_head(out: &mut Vec<u8>, major: u8, n: u64) {
    let mt = major << 5;
    if n < 24 {
        out.push(mt | n as u8);
    } else if n <= 0xff {
        out.push(mt | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(mt | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(mt | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Whether any map key anywhere in `v` begins with `$` (reserved for the JSON twin's tags,
/// spec Part II §4).
pub fn has_reserved_key(v: &Value) -> bool {
    match v {
        Value::Map(m) => m
            .iter()
            .any(|(k, x)| k.0.starts_with('$') || has_reserved_key(x)),
        Value::Array(a) => a.iter().any(has_reserved_key),
        _ => false,
    }
}

/// Encode a value in the deterministic profile. Fails only on excessive depth.
pub fn encode(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(&mut out, v, 0)?;
    Ok(out)
}

fn encode_into(out: &mut Vec<u8>, v: &Value, depth: usize) -> Result<()> {
    match v {
        Value::Uint(n) => write_head(out, 0, *n),
        Value::Nint(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(a) => {
            if depth >= MAX_DEPTH {
                return Err(Error::Cbor(format!("nesting deeper than {MAX_DEPTH}")));
            }
            write_head(out, 4, a.len() as u64);
            for x in a {
                encode_into(out, x, depth + 1)?;
            }
        }
        Value::Map(m) => {
            if depth >= MAX_DEPTH {
                return Err(Error::Cbor(format!("nesting deeper than {MAX_DEPTH}")));
            }
            write_head(out, 5, m.len() as u64);
            // BTreeMap<Key> iterates in profile order.
            for (k, x) in m {
                write_head(out, 3, k.0.len() as u64);
                out.extend_from_slice(k.0.as_bytes());
                encode_into(out, x, depth + 1)?;
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Float(f) => {
            out.push(0xfb);
            out.extend_from_slice(&canonical_f64_bits(*f).to_be_bytes());
        }
    }
    Ok(())
}

/// Decode exactly one value occupying all of `bytes`, enforcing the profile.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut d = Decoder { b: bytes, pos: 0 };
    let v = d.value(0)?;
    if d.pos != bytes.len() {
        return Err(Error::Cbor(format!(
            "{} trailing bytes after item",
            bytes.len() - d.pos
        )));
    }
    Ok(v)
}

struct Decoder<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.b.len() - self.pos < n {
            return Err(Error::Cbor(format!("truncated at byte {}", self.pos)));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a head; returns (major, additional-info, argument).
    fn head(&mut self) -> Result<(u8, u8, u64)> {
        let ib = self.take(1)?[0];
        let (major, ai) = (ib >> 5, ib & 0x1f);
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().expect("2"))),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().expect("4"))),
            27 => u64::from_be_bytes(self.take(8)?.try_into().expect("8")),
            _ => {
                return Err(Error::Cbor(format!(
                    "additional info {ai} (indefinite or reserved) not allowed"
                )));
            }
        };
        // Shortest-form check (floats are checked separately: they are always 27).
        if major != 7 {
            let shortest = match arg {
                0..=23 => ai < 24,
                24..=0xff => ai == 24,
                0x100..=0xffff => ai == 25,
                0x1_0000..=0xffff_ffff => ai == 26,
                _ => ai == 27,
            };
            if !shortest {
                return Err(Error::Cbor(format!(
                    "non-shortest encoding of {arg} at byte {}",
                    self.pos
                )));
            }
        }
        Ok((major, ai, arg))
    }

    fn len(&self, arg: u64) -> Result<usize> {
        let n = usize::try_from(arg).map_err(|_| Error::Cbor("length overflow".into()))?;
        if n > self.b.len() - self.pos {
            // Every element needs at least one byte; reject impossible lengths before allocating.
            return Err(Error::Cbor(format!("length {n} exceeds remaining input")));
        }
        Ok(n)
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        let (major, ai, arg) = self.head()?;
        Ok(match major {
            0 => Value::Uint(arg),
            1 => Value::Nint(arg),
            2 => {
                let n = self.len(arg)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.len(arg)?;
                let s = std::str::from_utf8(self.take(n)?)
                    .map_err(|_| Error::Cbor("invalid UTF-8 in text string".into()))?;
                Value::Text(s.to_string())
            }
            4 => {
                if depth >= MAX_DEPTH {
                    return Err(Error::Cbor(format!("nesting deeper than {MAX_DEPTH}")));
                }
                let n = self.len(arg)?;
                let mut a = Vec::with_capacity(n);
                for _ in 0..n {
                    a.push(self.value(depth + 1)?);
                }
                Value::Array(a)
            }
            5 => {
                if depth >= MAX_DEPTH {
                    return Err(Error::Cbor(format!("nesting deeper than {MAX_DEPTH}")));
                }
                let n = self.len(arg)?;
                let mut m = Map::new();
                let mut prev: Option<Key> = None;
                for _ in 0..n {
                    let (kmaj, _, klen) = self.head()?;
                    if kmaj != 3 {
                        return Err(Error::Cbor("map keys must be text strings".into()));
                    }
                    let kn = self.len(klen)?;
                    let k = std::str::from_utf8(self.take(kn)?)
                        .map_err(|_| Error::Cbor("invalid UTF-8 in map key".into()))?;
                    let key = Key(k.to_string());
                    if let Some(p) = &prev
                        && key <= *p
                    {
                        return Err(Error::Cbor(format!(
                            "map keys not in canonical order or duplicated at {:?}",
                            key.0
                        )));
                    }
                    let v = self.value(depth + 1)?;
                    prev = Some(key.clone());
                    m.insert(key, v);
                }
                Value::Map(m)
            }
            6 => return Err(Error::Cbor("tags are not allowed".into())),
            7 => match (ai, arg) {
                (20, _) => Value::Bool(false),
                (21, _) => Value::Bool(true),
                (22, _) => Value::Null,
                (27, bits) => {
                    let f = f64::from_bits(bits);
                    if f.is_nan() && bits != CANONICAL_NAN {
                        return Err(Error::Cbor("non-canonical NaN".into()));
                    }
                    Value::Float(f)
                }
                _ => {
                    return Err(Error::Cbor(format!(
                        "simple value / float form {ai} not allowed (only false, true, null, f64)"
                    )));
                }
            },
            _ => unreachable!("major type is 3 bits"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            any::<u64>().prop_map(Value::Uint),
            any::<u64>().prop_map(Value::Nint),
            proptest::collection::vec(any::<u8>(), 0..16).prop_map(Value::Bytes),
            ".{0,12}".prop_map(Value::Text),
            any::<bool>().prop_map(Value::Bool),
            Just(Value::Null),
            any::<f64>().prop_map(Value::Float),
        ];
        leaf.prop_recursive(4, 64, 8, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
                proptest::collection::btree_map(".{0,8}".prop_map(Key), inner, 0..8)
                    .prop_map(Value::Map),
            ]
        })
    }

    proptest! {
        #[test]
        fn roundtrip_is_identity_and_canonical(v in arb_value()) {
            let bytes = encode(&v).unwrap();
            let back = decode(&bytes).unwrap();
            prop_assert_eq!(&back, &v);
            prop_assert_eq!(encode(&back).unwrap(), bytes);
        }

        #[test]
        fn decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode(&bytes);
        }
    }

    #[test]
    fn rfc8949_vectors() {
        assert_eq!(encode(&Value::Uint(0)).unwrap(), [0x00]);
        assert_eq!(encode(&Value::Uint(23)).unwrap(), [0x17]);
        assert_eq!(encode(&Value::Uint(24)).unwrap(), [0x18, 0x18]);
        assert_eq!(encode(&Value::Uint(1000)).unwrap(), [0x19, 0x03, 0xe8]);
        assert_eq!(encode(&Value::int(-1)).unwrap(), [0x20]);
        assert_eq!(encode(&Value::int(-1000)).unwrap(), [0x39, 0x03, 0xe7]);
        assert_eq!(encode(&Value::from("a")).unwrap(), [0x61, 0x61]);
        assert_eq!(
            encode(&Value::Float(1.1)).unwrap(),
            [0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a]
        );
    }

    #[test]
    fn key_order_is_length_first() {
        let v = Value::map()
            .with("bb", 1u64)
            .with("a", 2u64)
            .with("ab", 3u64);
        let bytes = encode(&v).unwrap();
        // a3 61 'a' 02 62 'ab' 03 62 'bb' 01
        assert_eq!(
            bytes,
            [
                0xa3, 0x61, b'a', 2, 0x62, b'a', b'b', 3, 0x62, b'b', b'b', 1
            ]
        );
    }

    #[test]
    fn rejects_non_canonical() {
        // non-shortest uint
        assert!(decode(&[0x18, 0x05]).is_err());
        // indefinite array
        assert!(decode(&[0x9f, 0xff]).is_err());
        // keys out of order: {"b":1,"a":2}
        assert!(decode(&[0xa2, 0x61, b'b', 1, 0x61, b'a', 2]).is_err());
        // duplicate keys
        assert!(decode(&[0xa2, 0x61, b'a', 1, 0x61, b'a', 2]).is_err());
        // half float
        assert!(decode(&[0xf9, 0x3c, 0x00]).is_err());
        // tag
        assert!(decode(&[0xc0, 0x00]).is_err());
        // non-canonical NaN
        assert!(decode(&[0xfb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 1]).is_err());
        // integer key
        assert!(decode(&[0xa1, 0x01, 0x02]).is_err());
        // trailing bytes
        assert!(decode(&[0x00, 0x00]).is_err());
        // impossible length
        assert!(decode(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).is_err());
    }

    #[test]
    fn depth_limit() {
        let mut v = Value::Null;
        for _ in 0..MAX_DEPTH {
            v = Value::Array(vec![v]);
        }
        assert!(encode(&v).is_ok());
        let deeper = Value::Array(vec![v]);
        assert!(encode(&deeper).is_err());
        let mut bytes = vec![0x81; MAX_DEPTH + 1];
        bytes.push(0xf6);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn pointers() {
        let mut v = Value::map()
            .with(
                "network",
                Value::map().with("label", "home").with("class", "wifi"),
            )
            .with(
                "list",
                Value::Array(vec![Value::from(1u64), Value::from(2u64)]),
            );
        assert_eq!(v.pointer("/network/label"), Some(&Value::from("home")));
        assert!(v.redact_pointer("/network/label"));
        assert!(v.pointer("/network/label").is_none());
        assert!(v.redact_pointer("/list/0"));
        assert_eq!(v.pointer("/list/0"), Some(&Value::Null));
        assert!(!v.redact_pointer("/missing/x"));
    }
}
