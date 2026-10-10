//! Noise IKpsk2 session setup and stateless transport (REQ-PRB-002, docs/design/probe.md §2–3).
//!
//! `psk2` places the PSK after the responder's message pattern, so the responder can read
//! message 1, learn the initiator's static key, look up that initiator's PSK, and only then
//! write message 2.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use pt_wire::ctrl::{Envelope, Frame};

use crate::config::{Authorized, Keypair, NOISE_PATTERN};

fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("noise: {e}"))
}

/// Initiator side of a handshake in progress.
#[derive(Debug)]
pub struct InitiatorHandshake {
    hs: snow::HandshakeState,
}

/// Start a handshake; returns the state and the framed message 1 carrying `hello`.
pub fn initiator_start(
    kp: &Keypair,
    responder_pub: &[u8; 32],
    psk: &[u8; 32],
    hello: &Envelope,
) -> io::Result<(InitiatorHandshake, Vec<u8>)> {
    let mut hs = snow::Builder::new(NOISE_PATTERN.parse().map_err(err)?)
        .local_private_key(&kp.private)
        .map_err(err)?
        .remote_public_key(responder_pub)
        .map_err(err)?
        .psk(2, psk)
        .map_err(err)?
        .build_initiator()
        .map_err(err)?;
    let mut buf = vec![0u8; 65535];
    let n = hs.write_message(&hello.encode(), &mut buf).map_err(err)?;
    buf.truncate(n);
    Ok((
        InitiatorHandshake { hs },
        Frame::Init { noise: buf }.encode(),
    ))
}

impl InitiatorHandshake {
    /// Process message 2; returns the transport and the responder's `welcome`.
    pub fn finish(mut self, noise_msg2: &[u8], session: u32) -> io::Result<(Transport, Envelope)> {
        let mut buf = vec![0u8; 65535];
        let n = self.hs.read_message(noise_msg2, &mut buf).map_err(err)?;
        let welcome = Envelope::decode(&buf[..n]).ok_or_else(|| err("malformed welcome"))?;
        Ok((Transport::new(self.hs, session)?, welcome))
    }
}

/// Result of a responder accepting message 1.
#[derive(Debug)]
pub struct Accepted {
    pub hello: Envelope,
    pub initiator: Authorized,
    hs: snow::HandshakeState,
}

/// Read message 1 and authenticate the initiator against `authorized`.
pub fn responder_accept(
    kp: &Keypair,
    authorized: &[Authorized],
    noise_msg1: &[u8],
) -> io::Result<Accepted> {
    let mut hs = snow::Builder::new(NOISE_PATTERN.parse().map_err(err)?)
        .local_private_key(&kp.private)
        .map_err(err)?
        // PSK is set after reading message 1 (psk2); a placeholder is required by the builder.
        .psk(2, &[0u8; 32])
        .map_err(err)?
        .build_responder()
        .map_err(err)?;
    let mut buf = vec![0u8; 65535];
    let n = hs.read_message(noise_msg1, &mut buf).map_err(err)?;
    let rs: [u8; 32] = hs
        .get_remote_static()
        .ok_or_else(|| err("no initiator static key"))?
        .try_into()
        .map_err(|_| err("bad static key length"))?;
    let initiator = authorized
        .iter()
        .find(|a| a.public == rs)
        .cloned()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "initiator key not authorized",
            )
        })?;
    hs.set_psk(2, &initiator.psk).map_err(err)?;
    let hello = Envelope::decode(&buf[..n]).ok_or_else(|| err("malformed hello"))?;
    Ok(Accepted {
        hello,
        initiator,
        hs,
    })
}

impl Accepted {
    /// Write message 2 carrying `welcome`; returns the transport and the framed message.
    pub fn respond(mut self, session: u32, welcome: &Envelope) -> io::Result<(Transport, Vec<u8>)> {
        let mut buf = vec![0u8; 65535];
        let n = self
            .hs
            .write_message(&welcome.encode(), &mut buf)
            .map_err(err)?;
        buf.truncate(n);
        Ok((
            Transport::new(self.hs, session)?,
            Frame::Resp {
                session,
                noise: buf,
            }
            .encode(),
        ))
    }
}

/// Sliding replay window over explicit nonces.
#[derive(Debug, Default)]
struct Replay {
    highest: u64,
    seen: u128,
}

impl Replay {
    fn check_and_set(&mut self, n: u64) -> bool {
        if n > self.highest {
            let shift = n - self.highest;
            self.seen = if shift >= 128 { 0 } else { self.seen << shift };
            self.seen |= 1;
            self.highest = n;
            true
        } else {
            let back = self.highest - n;
            if back >= 128 || self.seen & (1 << back) != 0 {
                return false;
            }
            self.seen |= 1 << back;
            true
        }
    }
}

/// Encrypted control transport with explicit nonces (robust to loss and reordering).
#[derive(Debug)]
pub struct Transport {
    st: snow::StatelessTransportState,
    pub session: u32,
    pub handshake_hash: Vec<u8>,
    send_nonce: AtomicU64,
    replay: Mutex<Replay>,
}

impl Transport {
    fn new(hs: snow::HandshakeState, session: u32) -> io::Result<Transport> {
        let handshake_hash = hs.get_handshake_hash().to_vec();
        Ok(Transport {
            st: hs.into_stateless_transport_mode().map_err(err)?,
            session,
            handshake_hash,
            send_nonce: AtomicU64::new(1),
            replay: Mutex::new(Replay::default()),
        })
    }

    /// Encrypt an envelope into a framed datagram.
    pub fn seal(&self, env: &Envelope) -> io::Result<Vec<u8>> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::Relaxed);
        let pt = env.encode();
        let mut ct = vec![0u8; pt.len() + 16];
        let n = self.st.write_message(nonce, &pt, &mut ct).map_err(err)?;
        ct.truncate(n);
        Ok(Frame::Data {
            session: self.session,
            nonce,
            ciphertext: ct,
        }
        .encode())
    }

    /// Decrypt a data frame; rejects replays, wrong sessions and forgeries.
    pub fn open(&self, frame: &Frame) -> Option<Envelope> {
        let Frame::Data {
            session,
            nonce,
            ciphertext,
        } = frame
        else {
            return None;
        };
        if *session != self.session {
            return None;
        }
        let mut pt = vec![0u8; ciphertext.len()];
        let n = self.st.read_message(*nonce, ciphertext, &mut pt).ok()?;
        if !self.replay.lock().ok()?.check_and_set(*nonce) {
            return None;
        }
        Envelope::decode(&pt[..n])
    }

    /// Key for authenticating TCP connection headers and similar session-bound data.
    pub fn session_key(&self, context: &str) -> [u8; 32] {
        blake3::derive_key(context, &self.handshake_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::generate_keypair;
    use pt_format::Value;

    #[test]
    fn handshake_transport_replay() {
        let (rk, ik) = (generate_keypair(), generate_keypair());
        let psk = [7u8; 32];
        let auth = vec![Authorized {
            public: ik.public,
            psk,
            label: "x".into(),
        }];
        let hello = Envelope::new("hello", Value::map().with("wire_major", 1u64));
        let (ih, m1) = initiator_start(&ik, &rk.public, &psk, &hello).unwrap();
        assert!(m1.len() >= 1200);
        let Some(Frame::Init { noise }) = Frame::decode(&m1) else {
            panic!()
        };
        let acc = responder_accept(&rk, &auth, &noise).unwrap();
        assert_eq!(acc.hello, hello);
        let (rt, m2) = acc
            .respond(42, &Envelope::new("welcome", Value::map()))
            .unwrap();
        let Some(Frame::Resp { session, noise }) = Frame::decode(&m2) else {
            panic!()
        };
        let (it, welcome) = ih.finish(&noise, session).unwrap();
        assert_eq!(welcome.kind, "welcome");
        assert_eq!(it.handshake_hash, rt.handshake_hash);
        let d = it.seal(&Envelope::new("ping", Value::map())).unwrap();
        let f = Frame::decode(&d).unwrap();
        assert_eq!(rt.open(&f).unwrap().kind, "ping");
        assert!(rt.open(&f).is_none(), "replay must be rejected");
    }

    #[test]
    fn unauthorized_and_wrong_psk_rejected() {
        let (rk, ik) = (generate_keypair(), generate_keypair());
        let hello = Envelope::new("hello", Value::map());
        let (_, m1) = initiator_start(&ik, &rk.public, &[1; 32], &hello).unwrap();
        let Some(Frame::Init { noise }) = Frame::decode(&m1) else {
            panic!()
        };
        assert!(responder_accept(&rk, &[], &noise).is_err());
        // Wrong PSK: responder accepts msg1 (PSK not yet used) but initiator rejects msg2.
        let auth = vec![Authorized {
            public: ik.public,
            psk: [2; 32],
            label: "x".into(),
        }];
        let (ih, m1) = initiator_start(&ik, &rk.public, &[1; 32], &hello).unwrap();
        let Some(Frame::Init { noise }) = Frame::decode(&m1) else {
            panic!()
        };
        let acc = responder_accept(&rk, &auth, &noise).unwrap();
        let (_, m2) = acc
            .respond(1, &Envelope::new("welcome", Value::map()))
            .unwrap();
        let Some(Frame::Resp { noise, .. }) = Frame::decode(&m2) else {
            panic!()
        };
        assert!(ih.finish(&noise, 1).is_err());
    }

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        assert!(r.check_and_set(5));
        assert!(r.check_and_set(3));
        assert!(!r.check_and_set(3));
        assert!(r.check_and_set(200));
        assert!(!r.check_and_set(5));
    }
}
