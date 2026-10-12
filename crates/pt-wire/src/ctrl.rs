//! Control-channel framing and messages (docs/design/probe.md §3.1–3.2, REQ-PRB-021).
//!
//! Datagram framing on the control port (outside Noise):
//! - `0xC1 len:u16 noise_msg1 padding…` (padded to ≥ 1200 bytes, anti-amplification)
//! - `0xC2 session:u32 len:u16 noise_msg2`
//! - `0xC3 session:u32 nonce:u64 ciphertext` (Noise stateless transport)
//!
//! Plaintext of a transport message is one CBOR [`Envelope`]. Message bodies are CBOR maps whose
//! keys are documented per `kind` in docs/design/probe.md; unknown kinds and keys are ignored
//! (minor-version compatibility).

use pt_format::{Value, cbor};

pub const WIRE_MAJOR: u64 = 1;
pub const WIRE_MINOR: u64 = 1;

pub const T_INIT: u8 = 0xC1;
pub const T_RESP: u8 = 0xC2;
pub const T_DATA: u8 = 0xC3;
pub const INIT_MIN_LEN: usize = 1200;

/// Framed control datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Init {
        noise: Vec<u8>,
    },
    Resp {
        session: u32,
        noise: Vec<u8>,
    },
    Data {
        session: u32,
        nonce: u64,
        ciphertext: Vec<u8>,
    },
}

impl Frame {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Init { noise } => {
                let mut v = vec![T_INIT];
                v.extend_from_slice(&(noise.len() as u16).to_le_bytes());
                v.extend_from_slice(noise);
                if v.len() < INIT_MIN_LEN {
                    v.resize(INIT_MIN_LEN, 0);
                }
                v
            }
            Frame::Resp { session, noise } => {
                let mut v = vec![T_RESP];
                v.extend_from_slice(&session.to_le_bytes());
                v.extend_from_slice(&(noise.len() as u16).to_le_bytes());
                v.extend_from_slice(noise);
                v
            }
            Frame::Data {
                session,
                nonce,
                ciphertext,
            } => {
                let mut v = Vec::with_capacity(13 + ciphertext.len());
                v.push(T_DATA);
                v.extend_from_slice(&session.to_le_bytes());
                v.extend_from_slice(&nonce.to_le_bytes());
                v.extend_from_slice(ciphertext);
                v
            }
        }
    }

    pub fn decode(b: &[u8]) -> Option<Frame> {
        match *b.first()? {
            T_INIT => {
                let len = u16::from_le_bytes([*b.get(1)?, *b.get(2)?]) as usize;
                Some(Frame::Init {
                    noise: b.get(3..3 + len)?.to_vec(),
                })
            }
            T_RESP => {
                let session = u32::from_le_bytes(b.get(1..5)?.try_into().ok()?);
                let len = u16::from_le_bytes([*b.get(5)?, *b.get(6)?]) as usize;
                Some(Frame::Resp {
                    session,
                    noise: b.get(7..7 + len)?.to_vec(),
                })
            }
            T_DATA => Some(Frame::Data {
                session: u32::from_le_bytes(b.get(1..5)?.try_into().ok()?),
                nonce: u64::from_le_bytes(b.get(5..13)?.try_into().ok()?),
                ciphertext: b.get(13..)?.to_vec(),
            }),
            _ => None,
        }
    }

    /// Whether a datagram looks like a control frame (first byte), for demultiplexing.
    pub fn is_control(b: &[u8]) -> bool {
        matches!(b.first(), Some(&(T_INIT | T_RESP | T_DATA)))
    }
}

/// A control message with reliability metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// Reliable sequence number (≥ 1), or 0 for unreliable messages.
    pub seq: u64,
    /// Cumulative acknowledgement of the peer's reliable messages.
    pub ack: u64,
    pub kind: String,
    pub body: Value,
}

impl Envelope {
    pub fn new(kind: &str, body: Value) -> Envelope {
        Envelope {
            seq: 0,
            ack: 0,
            kind: kind.to_string(),
            body,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let v = Value::map()
            .with("seq", self.seq)
            .with("ack", self.ack)
            .with("k", self.kind.as_str())
            .with("b", self.body.clone());
        cbor::encode(&v).expect("control message depth is bounded")
    }

    pub fn decode(b: &[u8]) -> Option<Envelope> {
        let v = cbor::decode(b).ok()?;
        Some(Envelope {
            seq: v.get("seq")?.as_u64()?,
            ack: v.get("ack")?.as_u64()?,
            kind: v.get("k")?.as_str()?.to_string(),
            body: v.get("b")?.clone(),
        })
    }
}

/// Body accessors with defaults, for terse message handling.
pub trait BodyExt {
    fn u64_or(&self, key: &str, d: u64) -> u64;
    fn str_or<'a>(&'a self, key: &str, d: &'a str) -> &'a str;
    fn f64_or(&self, key: &str, d: f64) -> f64;
}

impl BodyExt for Value {
    fn u64_or(&self, key: &str, d: u64) -> u64 {
        self.get(key).and_then(Value::as_u64).unwrap_or(d)
    }
    fn str_or<'a>(&'a self, key: &str, d: &'a str) -> &'a str {
        self.get(key).and_then(Value::as_str).unwrap_or(d)
    }
    fn f64_or(&self, key: &str, d: f64) -> f64 {
        self.get(key).and_then(Value::as_f64).unwrap_or(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn frames_roundtrip() {
        for f in [
            Frame::Init {
                noise: vec![1, 2, 3],
            },
            Frame::Resp {
                session: 9,
                noise: vec![4; 48],
            },
            Frame::Data {
                session: 9,
                nonce: 77,
                ciphertext: vec![5; 30],
            },
        ] {
            let b = f.encode();
            assert!(Frame::is_control(&b));
            assert_eq!(Frame::decode(&b), Some(f.clone()));
        }
        assert!(Frame::Init { noise: vec![0; 10] }.encode().len() >= INIT_MIN_LEN);
    }

    #[test]
    fn envelope_roundtrip() {
        let e = Envelope {
            seq: 3,
            ack: 2,
            kind: "phase".into(),
            body: Value::map().with("id", 4u64),
        };
        assert_eq!(Envelope::decode(&e.encode()), Some(e));
    }

    proptest! {
        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = Frame::decode(&b);
            let _ = Envelope::decode(&b);
        }
    }
}
