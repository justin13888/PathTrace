//! Probe packet header and authentication tag (docs/design/probe.md §3.3, REQ-PRB-006/009).

/// Header length in bytes.
pub const HEADER_LEN: usize = 32;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 8;
/// Smallest valid probe payload.
pub const MIN_PAYLOAD: usize = HEADER_LEN + TAG_LEN;
/// Wire format version carried in the high nibble of byte 0.
pub const VERSION: u8 = 1;

/// Probe packet types (low nibble of byte 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PktType {
    Data = 0,
    NatProbe = 1,
    PmtuProbe = 2,
    ClassProbe = 3,
    Echo = 4,
}

impl PktType {
    pub fn from_u8(v: u8) -> Option<PktType> {
        Some(match v {
            0 => PktType::Data,
            1 => PktType::NatProbe,
            2 => PktType::PmtuProbe,
            3 => PktType::ClassProbe,
            4 => PktType::Echo,
            _ => return None,
        })
    }
}

/// Header flags.
pub mod flags {
    pub const LAST_OF_TRAIN: u16 = 1 << 0;
    pub const FEEDBACK_REQUEST: u16 = 1 << 1;
}

/// Decoded probe header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub ptype: PktType,
    pub flow: u8,
    pub phase: u16,
    pub session: u32,
    pub seq: u64,
    pub t_intended: u64,
    pub train: u32,
    pub train_idx: u16,
    pub flags: u16,
}

impl Header {
    pub fn encode(&self, out: &mut [u8]) {
        out[0] = (VERSION << 4) | self.ptype as u8;
        out[1] = self.flow;
        out[2..4].copy_from_slice(&self.phase.to_le_bytes());
        out[4..8].copy_from_slice(&self.session.to_le_bytes());
        out[8..16].copy_from_slice(&self.seq.to_le_bytes());
        out[16..24].copy_from_slice(&self.t_intended.to_le_bytes());
        out[24..28].copy_from_slice(&self.train.to_le_bytes());
        out[28..30].copy_from_slice(&self.train_idx.to_le_bytes());
        out[30..32].copy_from_slice(&self.flags.to_le_bytes());
    }

    pub fn decode(b: &[u8]) -> Option<Header> {
        if b.len() < HEADER_LEN || b[0] >> 4 != VERSION {
            return None;
        }
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().expect("4"));
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8"));
        Some(Header {
            ptype: PktType::from_u8(b[0] & 0x0f)?,
            flow: b[1],
            phase: u16_at(2),
            session: u32_at(4),
            seq: u64_at(8),
            t_intended: u64_at(16),
            train: u32_at(24),
            train_idx: u16_at(28),
            flags: u16_at(30),
        })
    }
}

/// Keyed-BLAKE3 tagger for probe packets. The key is derived from the Noise handshake hash.
#[derive(Clone)]
pub struct Tagger {
    key: [u8; 32],
    pad: blake3::OutputReader,
}

impl std::fmt::Debug for Tagger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Tagger(..)")
    }
}

impl Tagger {
    pub fn new(handshake_hash: &[u8]) -> Tagger {
        let key = blake3::derive_key("pathtrace probe tag v1", handshake_hash);
        let pad_key = blake3::derive_key("pathtrace probe padding v1", handshake_hash);
        let pad = blake3::Hasher::new_keyed(&pad_key).finalize_xof();
        Tagger { key, pad }
    }

    /// Fill a whole probe payload: header, incompressible padding, tag. `buf.len()` is the
    /// payload size and must be at least [`MIN_PAYLOAD`].
    pub fn build(&mut self, h: &Header, buf: &mut [u8]) {
        debug_assert!(buf.len() >= MIN_PAYLOAD);
        h.encode(&mut buf[..HEADER_LEN]);
        let end = buf.len() - TAG_LEN;
        self.pad.fill(&mut buf[HEADER_LEN..end]);
        let tag = blake3::keyed_hash(&self.key, &buf[..end]);
        buf[end..].copy_from_slice(&tag.as_bytes()[..TAG_LEN]);
    }

    /// Verify and decode. Returns `None` for malformed or unauthenticated packets.
    pub fn verify(&self, buf: &[u8]) -> Option<Header> {
        if buf.len() < MIN_PAYLOAD {
            return None;
        }
        let end = buf.len() - TAG_LEN;
        let tag = blake3::keyed_hash(&self.key, &buf[..end]);
        // Constant-time comparison is unnecessary for an 8-byte integrity tag on measurement
        // traffic (no secret is protected by it), but cheap enough.
        let ok = tag.as_bytes()[..TAG_LEN]
            .iter()
            .zip(&buf[end..])
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            == 0;
        if !ok {
            return None;
        }
        Header::decode(buf)
    }
}

/// QUIC v1 framing for the `udp/443 QUIC-shaped` class (ADR 0006, `quic_shape = "header/1"`).
pub mod quic {
    /// Bytes prepended for a long-header (Initial-typed) packet.
    /// flags, version, DCID len+DCID, SCID len+SCID, token length, length, packet number.
    pub const LONG_OVERHEAD: usize = 1 + 4 + 1 + 8 + 1 + 8 + 1 + 2 + 1;
    /// Bytes prepended for a short-header packet.
    pub const SHORT_OVERHEAD: usize = 1 + 8;

    /// Prepend a QUIC v1 header to `inner`. `first` selects a long header of type Initial.
    pub fn wrap(first: bool, dcid: [u8; 8], scid: [u8; 8], inner: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(inner.len() + LONG_OVERHEAD);
        if first {
            // Long header: form=1, fixed=1, type=Initial(00), reserved=00, packet-number length 1 byte.
            out.push(0xc0);
            out.extend_from_slice(&1u32.to_be_bytes());
            out.push(8);
            out.extend_from_slice(&dcid);
            out.push(8);
            out.extend_from_slice(&scid);
            out.push(0); // token length (varint 0)
            // Length varint (2-byte form) covering packet number + payload.
            let len = (inner.len() + 1) as u16 | 0x4000;
            out.extend_from_slice(&len.to_be_bytes());
            out.push(0); // packet number
        } else {
            // Short header: form=0, fixed=1, spin=0, reserved=00, key phase=0, packet-number length 1 byte.
            out.push(0x40);
            out.extend_from_slice(&dcid);
        }
        out.extend_from_slice(inner);
        out
    }

    /// Strip a QUIC framing produced by [`wrap`]; returns the inner payload.
    pub fn unwrap(b: &[u8]) -> Option<&[u8]> {
        let first = *b.first()?;
        if first & 0x80 != 0 {
            b.get(LONG_OVERHEAD..)
        } else if first & 0x40 != 0 {
            b.get(SHORT_OVERHEAD..)
        } else {
            None
        }
    }

    /// The probe payload of a received or ICMP-quoted datagram: `b` itself, or what follows
    /// its QUIC header when its first byte has the fixed bit (0x40) set and a high nibble
    /// other than the probe version. A QUIC header cut short is returned unchanged, so it
    /// fails to verify or decode like any other foreign datagram.
    pub fn strip(b: &[u8]) -> &[u8] {
        if b.first()
            .is_some_and(|f| f & 0x40 != 0 && f >> 4 != super::VERSION)
        {
            unwrap(b).unwrap_or(b)
        } else {
            b
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hdr() -> Header {
        Header {
            ptype: PktType::Data,
            flow: 3,
            phase: 4,
            session: 0xdead_beef,
            seq: 1 << 40,
            t_intended: 123_456_789,
            train: 7,
            train_idx: 2,
            flags: flags::LAST_OF_TRAIN,
        }
    }

    #[test]
    fn build_verify() {
        let mut t = Tagger::new(b"handshake-hash");
        let mut buf = vec![0u8; 100];
        t.build(&hdr(), &mut buf);
        assert_eq!(t.verify(&buf), Some(hdr()));
        let mut bad = buf.clone();
        bad[50] ^= 1;
        assert_eq!(t.verify(&bad), None);
        let other = Tagger::new(b"other");
        assert_eq!(other.verify(&buf), None);
        // Padding differs between packets (incompressible stream).
        let mut buf2 = vec![0u8; 100];
        t.build(&hdr(), &mut buf2);
        assert_ne!(buf[HEADER_LEN..92], buf2[HEADER_LEN..92]);
    }

    #[test]
    fn quic_wrap_unwrap() {
        let inner = [9u8; 60];
        let l = quic::wrap(true, [1; 8], [2; 8], &inner);
        assert_eq!(l.len(), inner.len() + quic::LONG_OVERHEAD);
        assert_eq!(quic::unwrap(&l), Some(&inner[..]));
        let s = quic::wrap(false, [1; 8], [2; 8], &inner);
        assert_eq!(quic::unwrap(&s), Some(&inner[..]));
    }

    #[test]
    fn strip_finds_the_probe_header_under_quic_framing() {
        let mut t = Tagger::new(b"handshake-hash");
        let mut inner = vec![0u8; 100];
        t.build(&hdr(), &mut inner);
        // A bare probe packet is left alone.
        assert_eq!(quic::strip(&inner), &inner[..]);
        for first in [true, false] {
            let q = quic::wrap(first, [1; 8], [2; 8], &inner);
            assert_eq!(Header::decode(&q), None);
            assert_eq!(Header::decode(quic::strip(&q)), Some(hdr()));
            assert_eq!(t.verify(quic::strip(&q)), Some(hdr()));
        }
        // A truncated ICMP quote still yields the header when it covers it.
        let q = quic::wrap(true, [1; 8], [2; 8], &inner);
        let cut = &q[..quic::LONG_OVERHEAD + HEADER_LEN];
        assert_eq!(Header::decode(quic::strip(cut)), Some(hdr()));
        // A QUIC header cut short is returned unchanged.
        assert_eq!(quic::strip(&q[..4]), &q[..4]);
    }

    proptest! {
        #[test]
        fn verify_never_panics(b in proptest::collection::vec(any::<u8>(), 0..200)) {
            let t = Tagger::new(b"k");
            let _ = t.verify(&b);
            let _ = Header::decode(&b);
            let _ = quic::unwrap(&b);
            let _ = Header::decode(quic::strip(&b));
        }
    }
}
