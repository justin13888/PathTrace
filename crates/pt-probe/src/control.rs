//! Reliable control channel over the Noise transport (docs/design/probe.md §3.1).
//!
//! Stop-and-wait reliability per direction (sessions are sequential, so one outstanding
//! reliable message suffices), cumulative acks, RTO = max(50 ms, 3 × SRTT) ≤ 1 s. Feedback and
//! clock messages are unreliable and handled here; everything else is delivered to the session.

use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use pt_format::Value;
use pt_sys::clock::mono_raw;
use pt_wire::ctrl::{BodyExt, Envelope, Frame};

use crate::flows::Role;
use crate::io::{CtrlIn, PacerCmd, Shared};
use crate::noise::Transport;
use crate::record::Recorder;

/// How sealed control datagrams leave this endpoint.
pub enum Wire {
    /// Through the pacer on UDP socket `sock` to the current control destination.
    Udp { cmd: Sender<PacerCmd>, sock: usize },
    /// Over a TCP stream (fallback), length-prefixed.
    Tcp(Arc<Mutex<std::net::TcpStream>>),
}

impl std::fmt::Debug for Wire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Wire::Udp { sock, .. } => write!(f, "Wire::Udp({sock})"),
            Wire::Tcp(_) => f.write_str("Wire::Tcp"),
        }
    }
}

/// Largest control body (encoded CBOR) the session layer may send in one message, so that a
/// sealed control datagram stays below 1280-byte IPv6 minimum MTU minus headers.
pub const MAX_BODY: usize = 1100;
/// Largest sealed control datagram accepted for UDP.
pub const MAX_DATAGRAM: usize = 1232;

/// Handler for `fb` messages (sender side of the saturation controller).
pub type FbHandler = Box<dyn Fn(&Value) + Send + Sync>;

#[derive(Debug, Default)]
struct Rel {
    next_seq: u64,
    peer_acked: u64,
    delivered: u64,
    srtt_ns: u64,
}

/// Responder: the handshake message that opened the session, our reply, and resends left.
type Replay = (Vec<u8>, Vec<u8>, u32);

pub struct Control {
    pub transport: Arc<Transport>,
    wire: Wire,
    shared: Arc<Shared>,
    rel: Mutex<Rel>,
    acked: Condvar,
    incoming: Mutex<Receiver<Envelope>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    replay: Mutex<Option<Replay>>,
}

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control").field("wire", &self.wire).finish()
    }
}

impl Control {
    /// Start the control thread consuming frames from `frames` (fed by the receiver thread or a
    /// TCP reader). `fb` handles feedback; `rec` logs clock exchanges (initiator) and events.
    pub fn start(
        transport: Arc<Transport>,
        wire: Wire,
        shared: Arc<Shared>,
        frames: Receiver<CtrlIn>,
        fb: FbHandler,
        rec: Recorder,
    ) -> Arc<Control> {
        let (in_tx, in_rx) = channel();
        let ctl = Arc::new(Control {
            transport,
            wire,
            shared: shared.clone(),
            rel: Mutex::new(Rel {
                next_seq: 1,
                srtt_ns: 200_000_000,
                ..Default::default()
            }),
            acked: Condvar::new(),
            incoming: Mutex::new(in_rx),
            thread: Mutex::new(None),
            replay: Mutex::new(None),
        });
        let c2 = ctl.clone();
        let h = std::thread::Builder::new()
            .name("control".into())
            .spawn(move || c2.run(frames, in_tx, fb, rec))
            .expect("spawn control thread");
        *ctl.thread.lock().expect("lock") = Some(h);
        let c3 = ctl.clone();
        let _ = shared
            .send_ctrl
            .set(crate::io::CtrlSender(Box::new(move |e| {
                c3.send(&e);
            })));
        ctl
    }

    /// Seal and send one envelope; returns the Noise nonce of the sealed datagram.
    fn emit(&self, env: &Envelope) -> Option<u64> {
        let Ok(bytes) = self.transport.seal(env) else {
            return None;
        };
        let nonce = match Frame::decode(&bytes) {
            Some(Frame::Data { nonce, .. }) => Some(nonce),
            _ => None,
        };
        match &self.wire {
            Wire::Udp { cmd, sock } => {
                debug_assert!(
                    bytes.len() <= MAX_DATAGRAM,
                    "control datagram of {} bytes ({})",
                    bytes.len(),
                    env.kind
                );
                if bytes.len() > MAX_DATAGRAM {
                    eprintln!(
                        "[pathtrace] dropping oversized control message {} ({} bytes)",
                        env.kind,
                        bytes.len()
                    );
                    return None;
                }
                if let Some(dst) = *self.shared.ctrl_dst.read().expect("lock") {
                    let flow = if self.shared.role == Role::A {
                        crate::io::CONTROL_FLOW_A
                    } else {
                        crate::io::CONTROL_FLOW_B
                    };
                    let _ = cmd.send(PacerCmd::Raw {
                        sock: *sock,
                        dst,
                        bytes,
                        at: 0,
                        log: nonce.map(|n| (flow, n)),
                    });
                }
            }
            Wire::Tcp(s) => {
                use std::io::Write;
                let mut s = s.lock().expect("lock");
                let mut buf = (bytes.len() as u32).to_le_bytes().to_vec();
                buf.extend_from_slice(&bytes);
                let _ = s.write_all(&buf);
            }
        }
        nonce
    }

    /// Send an unreliable message; returns its datagram's Noise nonce.
    pub fn send(&self, env: &Envelope) -> Option<u64> {
        let mut e = env.clone();
        e.seq = 0;
        e.ack = self.rel.lock().expect("lock").delivered;
        self.emit(&e)
    }

    /// Send a reliable message and wait for its acknowledgement.
    pub fn request(&self, kind: &str, body: Value, timeout: Duration) -> std::io::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut rel = self.rel.lock().expect("lock");
        let seq = rel.next_seq;
        rel.next_seq += 1;
        let env = Envelope {
            seq,
            ack: rel.delivered,
            kind: kind.to_string(),
            body,
        };
        let start = Instant::now();
        loop {
            self.emit(&env);
            let rto = Duration::from_nanos((3 * rel.srtt_ns).clamp(50_000_000, 1_000_000_000));
            let (r, _) = self
                .acked
                .wait_timeout_while(rel, rto, |r| r.peer_acked < seq)
                .expect("lock");
            rel = r;
            if rel.peer_acked >= seq {
                let sample = start.elapsed().as_nanos() as u64;
                rel.srtt_ns = (rel.srtt_ns * 7 + sample) / 8;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("control request {kind} not acknowledged"),
                ));
            }
        }
    }

    /// Receive the next session-level message.
    pub fn recv(&self, timeout: Duration) -> Option<Envelope> {
        self.incoming
            .lock()
            .expect("lock")
            .recv_timeout(timeout)
            .ok()
    }

    /// Wait for a message of a given kind, discarding others (logged by caller if needed).
    pub fn wait_for(&self, kind: &str, timeout: Duration) -> Option<Envelope> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(e) = self.recv(deadline - Instant::now())
                && e.kind == kind
            {
                return Some(e);
            }
        }
        None
    }

    /// Responder: resend `reply` (at most 3 times) when the initiator repeats the handshake
    /// message `init_noise`, because our reply to it was lost (docs/design/probe.md §3.1).
    pub fn set_handshake_replay(&self, init_noise: Vec<u8>, reply: Vec<u8>) {
        *self.replay.lock().expect("lock") = Some((init_noise, reply, 3));
    }

    fn replay_handshake(&self, noise: &[u8], src: std::net::SocketAddr) -> bool {
        let mut r = self.replay.lock().expect("lock");
        let Some((init, reply, left)) = r.as_mut() else {
            return false;
        };
        if init.as_slice() != noise || *left == 0 {
            return false;
        }
        // Only a UDP session resends; on a TCP wire (after the TCP fallback) a late UDP Init
        // is ignored and is not a resend.
        let Wire::Udp { cmd, sock } = &self.wire else {
            return false;
        };
        let queued = cmd
            .send(PacerCmd::Raw {
                sock: *sock,
                dst: src,
                bytes: reply.clone(),
                at: 0,
                log: None,
            })
            .is_ok();
        if queued {
            *left -= 1;
        }
        queued
    }

    pub fn srtt(&self) -> Duration {
        Duration::from_nanos(self.rel.lock().expect("lock").srtt_ns)
    }

    fn run(
        self: Arc<Self>,
        frames: Receiver<CtrlIn>,
        in_tx: Sender<Envelope>,
        fb: FbHandler,
        rec: Recorder,
    ) {
        let mut last_clock = 0u64;
        let mut clock_burst = 5u32;
        // Recent clock requests: t1 → Noise nonce of the request datagram.
        let mut req_nonces: std::collections::VecDeque<(u64, Option<u64>)> =
            std::collections::VecDeque::new();
        while !self.shared.stop.load(Ordering::Relaxed) {
            // Initiator drives clock exchanges: 5 at start, then 1 per second.
            if self.shared.role == Role::A {
                let now = mono_raw();
                let interval = if clock_burst > 0 {
                    100_000_000
                } else {
                    1_000_000_000
                };
                if now - last_clock >= interval {
                    last_clock = now;
                    clock_burst = clock_burst.saturating_sub(1);
                    let t1 = mono_raw();
                    let n = self.send(&Envelope::new("clock_req", Value::map().with("t1", t1)));
                    req_nonces.push_back((t1, n));
                    if req_nonces.len() > 32 {
                        req_nonces.pop_front();
                    }
                }
            }
            let msg = match frames.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => m,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return,
            };
            if let Frame::Init { noise } = &msg.frame {
                if self.replay_handshake(noise, msg.src) {
                    rec.event("handshake_resent", Value::map());
                }
                continue;
            }
            let Some(env) = self.transport.open(&msg.frame) else {
                continue;
            };
            self.shared.last_ctrl.store(msg.mono, Ordering::Relaxed);
            // Mobility: the responder follows the initiator's authenticated source tuple.
            if self.shared.role == Role::B && matches!(self.wire, Wire::Udp { .. }) {
                let mut dst = self.shared.ctrl_dst.write().expect("lock");
                if *dst != Some(msg.src) {
                    if dst.is_some() {
                        rec.event(
                            "nat_rebind",
                            Value::map()
                                .with("addr", crate::record::pii(msg.src.to_string(), "id")),
                        );
                    }
                    *dst = Some(msg.src);
                    self.shared
                        .peer_by_sock
                        .lock()
                        .expect("lock")
                        .insert(0, msg.src);
                }
            }
            {
                let mut rel = self.rel.lock().expect("lock");
                if env.ack > rel.peer_acked {
                    rel.peer_acked = env.ack;
                    self.acked.notify_all();
                }
            }
            match env.kind.as_str() {
                "ack" => {}
                "fb" => {
                    self.shared.last_feedback.store(msg.mono, Ordering::Relaxed);
                    if let Some(sent) = env.body.get("sent").and_then(Value::as_u64) {
                        self.shared.peer_bytes_sent.store(sent, Ordering::Relaxed);
                    }
                    fb(&env.body);
                }
                "clock_req" => {
                    let t2 = msg.mono;
                    let t1 = env.body.u64_or("t1", 0);
                    self.send(&Envelope::new(
                        "clock_resp",
                        Value::map()
                            .with("t1", t1)
                            .with("t2", t2)
                            .with("t3", mono_raw()),
                    ));
                }
                "clock_resp" => {
                    let b = &env.body;
                    let t1 = b.u64_or("t1", 0);
                    let req = req_nonces
                        .iter()
                        .find(|(t, _)| *t == t1)
                        .and_then(|(_, n)| *n);
                    let resp = match &msg.frame {
                        Frame::Data { nonce, .. } => Some(*nonce),
                        _ => None,
                    };
                    rec.row(
                        "exchange",
                        vec![
                            Some(t1 as i64),
                            Some(b.u64_or("t2", 0) as i64),
                            Some(b.u64_or("t3", 0) as i64),
                            Some(msg.mono as i64),
                            req.map(|n| n as i64),
                            resp.map(|n| n as i64),
                        ],
                    );
                }
                _ => {
                    if env.seq > 0 {
                        let deliver = {
                            let mut rel = self.rel.lock().expect("lock");
                            if env.seq == rel.delivered + 1 {
                                rel.delivered = env.seq;
                                true
                            } else {
                                false
                            }
                        };
                        let ack = self.rel.lock().expect("lock").delivered;
                        let mut a = Envelope::new("ack", Value::map());
                        a.ack = ack;
                        self.emit(&a);
                        if deliver {
                            let _ = in_tx.send(env);
                        }
                    } else {
                        let _ = in_tx.send(env);
                    }
                }
            }
        }
    }

    pub fn join(&self) {
        if let Some(h) = self.thread.lock().expect("lock").take() {
            let _ = h.join();
        }
    }
}

/// Read length-prefixed control frames from a TCP stream into `tx` (fallback transport).
pub fn tcp_reader(mut s: std::net::TcpStream, tx: Sender<CtrlIn>, shared: Arc<Shared>) {
    use std::io::Read;
    let src = s
        .peer_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("addr"));
    let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
    let mut len = [0u8; 4];
    while !shared.stop.load(Ordering::Relaxed) {
        match s.read_exact(&mut len) {
            Ok(()) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => return,
        }
        let n = u32::from_le_bytes(len) as usize;
        if n > 1 << 20 {
            return;
        }
        let mut buf = vec![0u8; n];
        if s.read_exact(&mut buf).is_err() {
            return;
        }
        if let Some(frame) = Frame::decode(&buf) {
            let _ = tx.send(CtrlIn {
                frame,
                src,
                mono: mono_raw(),
            });
        }
    }
}
