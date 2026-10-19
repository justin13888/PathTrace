//! Endpoint I/O core: the pacer (sole sender) and the receiver (docs/design/probe.md §1, §7).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::JoinHandle;
use std::time::Duration;

use pt_format::Value;
use pt_sys::clock::{SPIN_NS, boottime, mono_raw, set_pacing_qos, sleep_until};
use pt_sys::udp::{
    ErrEvent, InMsg, MAX_DATAGRAM, OutMsg, SendOutcome, TxIdMode, TxKind, UdpSock, poll_many,
};
use pt_wire::ctrl::{Envelope, Frame};
use pt_wire::probe::{self, Header, PktType, Tagger};

use crate::flows::{Catchup, Due, FlowSpec, Gen, Pattern, Role, Sock};
use crate::record::{Recorder, pii};

/// Feedback interval and dead-man limits (REQ-PRB-005).
pub const FEEDBACK_INTERVAL_NS: u64 = 20_000_000;
pub const DEAD_MAN_NS: u64 = 500_000_000;
pub const LIGHT_DEAD_MAN_NS: u64 = 5_000_000_000;
/// A flow whose next deadline is further behind than this skips ahead instead of catching
/// up, and a suspend longer than this is recorded (docs/design/probe.md §4.3).
pub const STALL_NS: u64 = 2_000_000;
/// Flow ids under which control datagrams are observed (sender a / sender b).
pub const CONTROL_FLOW_A: u8 = 250;
pub const CONTROL_FLOW_B: u8 = 251;

/// The verdict on a [`pt_sys::clock::pacing_check`], worded once for `doctor` and `probe`
/// (probe.md §9.4): `(ok, detail)`. Not ok when the pacer would wake [`PACING_LATE_NS`] or more
/// late at best, naming the likely cause and what to do about it.
///
/// [`PACING_LATE_NS`]: pt_sys::clock::PACING_LATE_NS
pub fn pacing_verdict(c: &pt_sys::clock::PacingCheck) -> (bool, String) {
    let policy = match &c.policy {
        Some(e) => format!("; pacing policy not set: {e}"),
        None => String::new(),
    };
    if !c.late() {
        return (
            true,
            format!(
                "pacer wakes {} µs late at best{policy}",
                c.best_late_ns / 1_000
            ),
        );
    }
    let cause = if c.background {
        "this process runs in the background policy (taskpolicy -b, a background launchd service)"
    } else {
        "this process likely runs under a QoS clamp (taskpolicy -c, a launchd ProcessType, a CI runner's service) or the host is loaded"
    };
    (
        false,
        format!(
            "pacer wakes {:.1} ms late at best{policy}: {cause}; start pathtrace from a terminal session (lateness is recorded as tx_user_lag and stall events)",
            c.best_late_ns as f64 / 1e6
        ),
    )
}

/// A control datagram handed from the receiver to the control layer.
#[derive(Debug)]
pub struct CtrlIn {
    pub frame: Frame,
    pub src: SocketAddr,
    /// Local MONO_RAW at receipt.
    pub mono: u64,
    /// Index of the UDP socket it arrived on; `None` over the TCP fallback stream.
    pub sock: Option<usize>,
}

/// Per-flow receive statistics used for feedback.
#[derive(Debug, Clone, Default)]
pub struct FbStats {
    pub highest_seq: u64,
    pub count: u64,
    pub bytes: u64,
    /// min over the flow of (rx_real - t_intended): offset-free queueing delay baseline.
    pub min_owd: Option<i64>,
    /// Latest (rx_real - t_intended).
    pub last_owd: i64,
    /// Bytes received in the current feedback window.
    pub win_bytes: u64,
    pub win_start: u64,
    pub updated: u64,
}

/// IP bytes sent per flow id, written by the pacer (byte allowances, docs/design/probe.md §6).
#[derive(Debug)]
pub struct FlowBytes(Box<[AtomicU64]>);

impl Default for FlowBytes {
    fn default() -> Self {
        FlowBytes((0..256).map(|_| AtomicU64::new(0)).collect())
    }
}

impl FlowBytes {
    pub fn get(&self, flow: u8) -> u64 {
        self.0[usize::from(flow)].load(Ordering::Relaxed)
    }
    pub fn add(&self, flow: u8, bytes: u64) {
        self.0[usize::from(flow)].fetch_add(bytes, Ordering::Relaxed);
    }
    /// Start counting a new flow on `flow`: ids are reused (tracking rounds wrap), and an
    /// allowance applies to one flow, not to every flow that ever had the id.
    pub fn reset(&self, flow: u8) {
        self.0[usize::from(flow)].store(0, Ordering::Relaxed);
    }
}

/// State shared between the pacer, receiver, control layer and session logic.
#[derive(Debug)]
pub struct Shared {
    pub role: Role,
    pub session: AtomicU32,
    pub tagger: RwLock<Option<Tagger>>,
    /// Peer IP for flows this endpoint sends (initiator: responder; responder: learned).
    pub peer_ip: RwLock<Option<IpAddr>>,
    /// Peer source tuple observed per local socket (responder replies to these).
    pub peer_by_sock: Mutex<HashMap<usize, SocketAddr>>,
    /// Where control datagrams go.
    pub ctrl_dst: RwLock<Option<SocketAddr>>,
    pub flows: RwLock<HashMap<u8, FlowSpec>>,
    pub last_feedback: AtomicU64,
    pub last_ctrl: AtomicU64,
    pub bytes_sent: AtomicU64,
    /// Per-flow bytes sent by this endpoint.
    pub flow_bytes: Arc<FlowBytes>,
    /// The peer's bytes sent, as last reported in its feedback (`sent`).
    pub peer_bytes_sent: AtomicU64,
    pub data_cap: AtomicU64,
    pub rate_cap_bps: AtomicU64,
    pub stop: AtomicBool,
    pub fb: Mutex<HashMap<u8, FbStats>>,
    pub ctrl_in: Mutex<Option<Sender<CtrlIn>>>,
    /// Installed once the control channel exists: sends an unreliable control envelope.
    pub send_ctrl: OnceLock<CtrlSender>,
    pub cap_hit: AtomicBool,
}

/// Callback sending an unreliable control envelope.
pub struct CtrlSender(pub Box<dyn Fn(Envelope) + Send + Sync>);

impl std::fmt::Debug for CtrlSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CtrlSender")
    }
}

impl Shared {
    pub fn new(role: Role, data_cap: u64, rate_cap_bps: u64) -> Arc<Shared> {
        let now = mono_raw();
        Arc::new(Shared {
            role,
            session: AtomicU32::new(0),
            tagger: RwLock::new(None),
            peer_ip: RwLock::new(None),
            peer_by_sock: Mutex::new(HashMap::new()),
            ctrl_dst: RwLock::new(None),
            flows: RwLock::new(HashMap::new()),
            last_feedback: AtomicU64::new(now),
            last_ctrl: AtomicU64::new(now),
            bytes_sent: AtomicU64::new(0),
            flow_bytes: Arc::new(FlowBytes::default()),
            peer_bytes_sent: AtomicU64::new(0),
            data_cap: AtomicU64::new(data_cap),
            rate_cap_bps: AtomicU64::new(rate_cap_bps),
            stop: AtomicBool::new(false),
            fb: Mutex::new(HashMap::new()),
            ctrl_in: Mutex::new(None),
            send_ctrl: OnceLock::new(),
            cap_hit: AtomicBool::new(false),
        })
    }
}

/// Commands to the pacer.
#[derive(Debug)]
pub enum PacerCmd {
    Start(FlowSpec, u64),
    Stop(u8),
    StopAll,
    SetRate(u8, u64),
    SetTagger(Box<Tagger>),
    /// Send raw bytes at MONO_RAW time `at` (0 = now). `log` = (flow, seq) records the datagram
    /// as an observation (control datagrams: flow 250/251, seq = Noise nonce).
    Raw {
        sock: usize,
        dst: SocketAddr,
        bytes: Vec<u8>,
        at: u64,
        log: Option<(u8, u64)>,
    },
    Shutdown,
}

/// The endpoint: sockets plus pacer and receiver threads.
#[derive(Debug)]
pub struct Endpoint {
    pub shared: Arc<Shared>,
    pub socks: Vec<Arc<UdpSock>>,
    pub sock_ids: HashMap<String, usize>,
    pub cmd: Sender<PacerCmd>,
    pacer: Option<JoinHandle<()>>,
    receiver: Option<JoinHandle<()>>,
}

impl Endpoint {
    /// Start threads over already-bound sockets. `names[i]` is the [`Sock`] name of `socks[i]`.
    pub fn start(
        shared: Arc<Shared>,
        socks: Vec<(Sock, Arc<UdpSock>)>,
        rec: Recorder,
    ) -> std::io::Result<Endpoint> {
        let mut sock_ids = HashMap::new();
        let mut list = Vec::new();
        for (i, (name, s)) in socks.into_iter().enumerate() {
            sock_ids.insert(name.name(), i);
            list.push(s);
        }
        let (cmd_tx, cmd_rx) = channel();
        let pacer = {
            let shared = shared.clone();
            let socks = list.clone();
            let ids = sock_ids.clone();
            let rec = rec.clone();
            std::thread::Builder::new()
                .name("pacer".into())
                .spawn(move || {
                    // On macOS the least timer coalescing and the time-constraint policy;
                    // nothing on Linux (probe.md §9.4).
                    let _ = set_pacing_qos();
                    pacer_loop(shared, socks, ids, cmd_rx, rec);
                })?
        };
        let receiver = {
            let shared = shared.clone();
            let socks = list.clone();
            let cmd = cmd_tx.clone();
            std::thread::Builder::new()
                .name("receiver".into())
                .spawn(move || {
                    let _ = set_pacing_qos();
                    receiver_loop(shared, socks, cmd, rec);
                })?
        };
        Ok(Endpoint {
            shared,
            socks: list,
            sock_ids,
            cmd: cmd_tx,
            pacer: Some(pacer),
            receiver: Some(receiver),
        })
    }

    pub fn sock_index(&self, s: Sock) -> Option<usize> {
        self.sock_ids.get(&s.name()).copied()
    }

    pub fn send_raw(&self, sock: usize, dst: SocketAddr, bytes: Vec<u8>) {
        let _ = self.cmd.send(PacerCmd::Raw {
            sock,
            dst,
            bytes,
            at: 0,
            log: None,
        });
    }

    pub fn start_flow(&self, spec: FlowSpec, at: u64) {
        self.shared
            .flows
            .write()
            .expect("lock")
            .insert(spec.id, spec.clone());
        let _ = self.cmd.send(PacerCmd::Start(spec, at));
    }

    pub fn shutdown(mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        let _ = self.cmd.send(PacerCmd::Shutdown);
        if let Some(h) = self.pacer.take() {
            let _ = h.join();
        }
        if let Some(h) = self.receiver.take() {
            let _ = h.join();
        }
    }
}

fn udp_overhead(v6: bool) -> u32 {
    if v6 { 48 } else { 28 }
}

/// What the 500 ms dead-man switch does to a flow (docs/design/probe.md §7, REQ-PRB-005).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadMan {
    /// Keep sending.
    Run,
    /// Stop for good (heavy, chirp, CBR and class-saturation flows).
    Stop,
    /// Stop sending until feedback returns (session-long observers: trains, PMTU ladder).
    Pause,
    /// Feedback returned: send again.
    Resume,
}

/// Dead-man decision for a flow of `kind`, given whether feedback is lost and whether the flow
/// is currently paused. The light flow has its own, longer rule (5 s without any control).
fn dead_man(kind: &str, feedback_lost: bool, paused: bool) -> DeadMan {
    match kind {
        "heavy" | "chirp" | "cbr" | "class-sat" if feedback_lost => DeadMan::Stop,
        "train" | "pmtu" if feedback_lost && !paused => DeadMan::Pause,
        "train" | "pmtu" if !feedback_lost && paused => DeadMan::Resume,
        _ => DeadMan::Run,
    }
}

/// One packet scheduled for sending: flow, schedule entry, destination, QUIC framing, type, phase.
type DueItem = (u8, Due, SocketAddr, bool, PktType, u16);

/// A scheduled raw datagram: due time, socket, destination, bytes, optional observation.
type Delayed = (u64, usize, SocketAddr, Vec<u8>, Option<(u8, u64)>);

/// A due raw datagram: socket, destination, bytes, optional observation (flow, seq).
type RawItem = (usize, SocketAddr, Vec<u8>, Option<(u8, u64)>);

/// Record a datagram the kernel did not accept (docs/design/probe.md §4.1). `item` is the
/// (flow, seq, size) of the failed datagram when it is an observation.
fn record_send_failure(
    rec: &Recorder,
    sock: usize,
    s: &UdpSock,
    o: &SendOutcome,
    item: Option<(u8, u64, u32)>,
) {
    let mut d = Value::map()
        .with("sock", sock)
        .with("flow", item.map(|i| u64::from(i.0)))
        .with("seq", item.map(|i| i.1))
        .with("size", item.map(|i| u64::from(i.2)))
        .with("burned_id", o.burned_id.map(u64::from))
        .with("unburned_id", o.unburned_id.map(u64::from))
        .with("tx_ids", s.tx_id_mode().name());
    let kind = match &o.error {
        None => "send_partial",
        Some(e) => {
            d = d
                .with("errno", e.raw_os_error().unwrap_or(0) as i64)
                .with("error", e.to_string());
            "send_error"
        }
    };
    rec.event_nb(kind, d);
}

/// Detects a suspend of the host: MONO_RAW stops while the system is suspended and BOOTTIME
/// does not, so BOOTTIME − MONO_RAW grows by the time spent suspended (probe.md §4.3).
#[derive(Debug, Default)]
struct SuspendWatch {
    offset: Option<i64>,
}

impl SuspendWatch {
    /// Feed one (BOOTTIME, MONO_RAW) reading; returns the suspended time (ns) when the offset
    /// grew by more than [`STALL_NS`] since the previous reading.
    fn observe(&mut self, boot: u64, mono: u64) -> Option<u64> {
        let off = boot as i64 - mono as i64;
        let grew = off - self.offset.replace(off)?;
        (grew > STALL_NS as i64).then_some(grew as u64)
    }
}

fn pacer_loop(
    shared: Arc<Shared>,
    socks: Vec<Arc<UdpSock>>,
    ids: HashMap<String, usize>,
    cmd: Receiver<PacerCmd>,
    rec: Recorder,
) {
    let mut gens: Vec<Gen> = Vec::new();
    let mut tagger: Option<Tagger> = None;
    let mut delayed: Vec<Delayed> = Vec::new();
    let mut light_paused = false;
    let mut cap_logged = false;
    let mut id_modes: Vec<TxIdMode> = socks.iter().map(|s| s.tx_id_mode()).collect();
    let mut suspend = SuspendWatch::default();
    let handle = |c: PacerCmd,
                  gens: &mut Vec<Gen>,
                  tagger: &mut Option<Tagger>,
                  delayed: &mut Vec<Delayed>|
     -> bool {
        match c {
            PacerCmd::Start(spec, at) => {
                gens.retain(|g| g.spec.id != spec.id);
                shared.flow_bytes.reset(spec.id);
                gens.push(Gen::new(spec, at.max(mono_raw())));
            }
            PacerCmd::Stop(id) => gens.retain(|g| g.spec.id != id),
            PacerCmd::StopAll => gens.clear(),
            PacerCmd::SetRate(id, bps) => {
                let cap = shared.rate_cap_bps.load(Ordering::Relaxed);
                for g in gens.iter_mut().filter(|g| g.spec.id == id) {
                    g.bps = bps.min(cap);
                }
            }
            PacerCmd::SetTagger(t) => *tagger = Some(*t),
            PacerCmd::Raw {
                sock,
                dst,
                bytes,
                at,
                log,
            } => delayed.push((at, sock, dst, bytes, log)),
            PacerCmd::Shutdown => return false,
        }
        true
    };
    loop {
        // Commands: block briefly when idle, otherwise poll.
        // BOOTTIME is read between two MONO_RAW reads, and a reading the scheduler interrupted
        // is not used, so a preemption is never taken for a suspend.
        let m0 = mono_raw();
        let boot = boottime();
        let now = mono_raw();
        if now - m0 < 100_000
            && let Some(ns) = suspend.observe(boot, m0 + (now - m0) / 2)
        {
            rec.event_nb(
                "stall",
                Value::map()
                    .with("cause", "suspend")
                    .with("suspended_ns", ns),
            );
        }
        let next_flow = gens.iter().map(|g| g.next_due).min();
        let next_raw = delayed.iter().map(|d| d.0).min();
        let next = next_flow
            .into_iter()
            .chain(next_raw)
            .min()
            .unwrap_or(now + 50_000_000);
        if next > now + 2_000_000 {
            match cmd.recv_timeout(Duration::from_nanos(next - now - 1_000_000)) {
                Ok(c) => {
                    if !handle(c, &mut gens, &mut tagger, &mut delayed) {
                        return;
                    }
                    continue;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
        while let Ok(c) = cmd.try_recv() {
            if !handle(c, &mut gens, &mut tagger, &mut delayed) {
                return;
            }
        }
        if shared.stop.load(Ordering::Relaxed) {
            return;
        }
        let next = gens
            .iter()
            .map(|g| g.next_due)
            .chain(delayed.iter().map(|d| d.0))
            .min();
        if let Some(n) = next {
            if n > mono_raw() + 2_000_000 {
                continue;
            }
            // Sleep until SPIN_NS before the deadline, then spin (probe.md §1, §9.4).
            sleep_until(n, Duration::from_nanos(SPIN_NS));
        } else {
            continue;
        }
        let now = mono_raw();

        // Raw datagrams (control, echoes) that are due.
        let mut raw_due: Vec<RawItem> = Vec::new();
        delayed.retain_mut(|d| {
            if d.0 <= now {
                raw_due.push((d.1, d.2, std::mem::take(&mut d.3), d.4));
                false
            } else {
                true
            }
        });
        let mut raw_rows = Vec::new();
        for (sock, dst, bytes, log) in &raw_due {
            if let Some(s) = socks.get(*sock) {
                let t = mono_raw();
                let o = s.send_batch(&[OutMsg {
                    dst: *dst,
                    payload: bytes,
                    tos: 0,
                }]);
                let id = o.first_id;
                let ip = bytes.len() as i64 + i64::from(udp_overhead(s.is_v6()));
                if o.failed {
                    if o.would_block() {
                        rec.event_nb(
                            "send_eagain",
                            Value::map()
                                .with("sock", *sock)
                                .with("burned_id", o.burned_id.map(u64::from))
                                .with("unburned_id", o.unburned_id.map(u64::from))
                                .with("tx_ids", s.tx_id_mode().name())
                                .with(
                                    "skipped",
                                    Value::Array(
                                        log.iter()
                                            .map(|(f, q)| {
                                                Value::Array(vec![Value::from(*f), Value::from(*q)])
                                            })
                                            .collect(),
                                    ),
                                ),
                        );
                    } else {
                        record_send_failure(
                            &rec,
                            *sock,
                            s,
                            &o,
                            log.map(|(f, q)| (f, q, ip as u32)),
                        );
                    }
                } else if let Some((flow, seq)) = log {
                    raw_rows.push(vec![
                        Some(*sock as i64),
                        Some(i64::from(*flow)),
                        Some(*seq as i64),
                        Some(ip),
                        Some(0),
                        Some(0),
                        Some(0),
                        Some(0),
                        Some(i64::from(id)),
                        Some(t as i64),
                        Some(0),
                    ]);
                    shared.bytes_sent.fetch_add(ip as u64, Ordering::Relaxed);
                } else {
                    // An echo or handshake reply: no `tx` row, but its id is recorded so the
                    // merge's id check can account for its stamp (probe.md §4.1).
                    rec.event_nb(
                        "raw_sent",
                        Value::map()
                            .with("sock", *sock)
                            .with("id", u64::from(id))
                            .with("size", ip),
                    );
                }
            }
        }
        rec.rows("tx", raw_rows);

        let Some(tg) = tagger.as_mut() else { continue };
        let session = shared.session.load(Ordering::Relaxed);
        let last_fb = shared.last_feedback.load(Ordering::Relaxed);
        let last_ctrl = shared.last_ctrl.load(Ordering::Relaxed);
        let over_cap =
            shared.bytes_sent.load(Ordering::Relaxed) >= shared.data_cap.load(Ordering::Relaxed);
        if over_cap && !cap_logged {
            cap_logged = true;
            shared.cap_hit.store(true, Ordering::Relaxed);
            rec.event_nb(
                "budget_cap",
                Value::map().with("bytes_sent", shared.bytes_sent.load(Ordering::Relaxed)),
            );
        }
        let light_dead = now.saturating_sub(last_ctrl) > LIGHT_DEAD_MAN_NS;
        if light_dead != light_paused {
            light_paused = light_dead;
            rec.event_nb(
                if light_dead {
                    "light_paused"
                } else {
                    "light_resumed"
                },
                Value::map(),
            );
        }

        // Collect due packets per socket.
        let mut per_sock: HashMap<usize, Vec<DueItem>> = HashMap::new();
        let mut stopped = Vec::new();
        let mut stalls: Vec<(u8, Catchup)> = Vec::new();
        for g in gens.iter_mut() {
            let sock = ids.get(&g.spec.sock.name()).copied().unwrap_or(0);
            let fb_lost = now.saturating_sub(last_fb) > DEAD_MAN_NS
                && now.saturating_sub(g.start) > DEAD_MAN_NS;
            // The data cap is hard: every probe flow stops, the light flow included. Only the
            // control traffic needed to end the session continues (and is still counted).
            if over_cap {
                stopped.push((g.spec.id, "budget_cap"));
                g.done = true;
                continue;
            }
            if g.spec.max_bytes > 0 && shared.flow_bytes.get(g.spec.id) >= g.spec.max_bytes {
                stopped.push((g.spec.id, "allowance"));
                g.done = true;
                continue;
            }
            match dead_man(&g.spec.kind, fb_lost, g.paused) {
                DeadMan::Run => {}
                DeadMan::Stop => {
                    stopped.push((g.spec.id, "dead_man"));
                    g.done = true;
                    continue;
                }
                DeadMan::Pause | DeadMan::Resume => {
                    g.paused = !g.paused;
                    rec.event_nb(
                        if g.paused {
                            "flow_paused"
                        } else {
                            "flow_resumed"
                        },
                        Value::map()
                            .with("flow", g.spec.id)
                            .with("reason", "dead_man"),
                    );
                }
            }
            // A paused ladder waits (every size must be probed); paused trains skip their
            // schedule like the paused light flow.
            if g.paused && g.spec.kind == "pmtu" {
                g.next_due = g.next_due.max(now + 20_000_000);
                continue;
            }
            let dst = match shared.role {
                Role::A => shared
                    .peer_ip
                    .read()
                    .expect("lock")
                    .map(|ip| SocketAddr::new(ip, g.spec.dst_port)),
                Role::B => shared
                    .peer_by_sock
                    .lock()
                    .expect("lock")
                    .get(&sock)
                    .copied(),
            };
            let Some(dst) = dst else { continue };
            let mut n = 0;
            let ptype = match g.spec.kind.as_str() {
                "class" => PktType::ClassProbe,
                "nat" => PktType::NatProbe,
                "pmtu" => PktType::PmtuProbe,
                _ => PktType::Data,
            };
            // After a stall the overdue packets are skipped (or the schedule shifted), never
            // sent back to back (probe.md §4.3).
            if let Some(c) = g.skip_overdue(now, STALL_NS) {
                stalls.push((g.spec.id, c));
            }
            while g.next_due <= now + 20_000 && n < 64 {
                let Some(due) = g.take() else { break };
                let skip = g.paused || (g.spec.kind == "light" && light_paused);
                if !skip {
                    per_sock.entry(sock).or_default().push((
                        g.spec.id,
                        due,
                        dst,
                        g.spec.quic,
                        ptype,
                        g.spec.phase,
                    ));
                }
                n += 1;
            }
        }
        if let Some(late) = stalls.iter().map(|(_, c)| c.late_ns).max() {
            rec.event_nb(
                "stall",
                Value::map()
                    .with("cause", "late")
                    .with("late_ns", late)
                    .with(
                        "flows",
                        Value::Array(
                            stalls
                                .iter()
                                .map(|(id, c)| {
                                    Value::map()
                                        .with("flow", *id)
                                        .with("late_ns", c.late_ns)
                                        .with("skipped", c.skipped)
                                        .with("shifted_ns", c.shifted_ns)
                                })
                                .collect(),
                        ),
                    ),
            );
        }
        for (id, why) in stopped {
            rec.event_nb(
                "flow_stopped",
                Value::map().with("flow", id).with("reason", why),
            );
        }
        gens.retain(|g| !g.done);

        for (sock, items) in per_sock {
            let s = &socks[sock];
            let oh = udp_overhead(s.is_v6());
            let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(items.len());
            for (flow, due, _, quic, ptype, phase) in &items {
                let h = Header {
                    ptype: *ptype,
                    flow: *flow,
                    phase: *phase,
                    session,
                    seq: due.seq,
                    t_intended: due.t_intended,
                    train: due.train,
                    train_idx: due.train_idx,
                    flags: if due.last_of_train {
                        probe::flags::LAST_OF_TRAIN
                    } else {
                        0
                    },
                };
                let payload_len = (due.size.saturating_sub(oh) as usize)
                    .max(probe::MIN_PAYLOAD + if *quic { probe::quic::LONG_OVERHEAD } else { 0 });
                if *quic {
                    let inner_len = payload_len
                        - if due.seq == 0 {
                            probe::quic::LONG_OVERHEAD
                        } else {
                            probe::quic::SHORT_OVERHEAD
                        };
                    let mut inner = vec![0u8; inner_len];
                    tg.build(&h, &mut inner);
                    let cid = (session as u64).to_le_bytes();
                    bufs.push(probe::quic::wrap(due.seq == 0, cid, cid, &inner));
                } else {
                    let mut b = vec![0u8; payload_len];
                    tg.build(&h, &mut b);
                    bufs.push(b);
                }
            }
            let msgs: Vec<OutMsg<'_>> = items
                .iter()
                .zip(&bufs)
                .map(|((_, due, dst, ..), b)| OutMsg {
                    dst: *dst,
                    payload: b,
                    tos: due.tos,
                })
                .collect();
            // Linux sends the batch in one `sendmmsg`, so this read stands for every datagram;
            // macOS returns its own read before each datagram's `sendmsg` (probe.md §9.2).
            let t_batch = mono_raw();
            // Send everything. A datagram the kernel rejects (e.g. EMSGSIZE above a cached PMTU)
            // is recorded and skipped, never the rest of the batch; a full send buffer skips the
            // rest of the batch, recorded too. Each sent datagram's OPT_ID comes from the send
            // outcome (probe.md §4.1).
            let mut ok: Vec<Option<(u32, u64)>> = vec![None; msgs.len()];
            let mut i = 0;
            while i < msgs.len() {
                let o = s.send_batch(&msgs[i..]);
                for (k, slot) in ok.iter_mut().skip(i).take(o.sent).enumerate() {
                    let t_user = o.t_user.get(k).copied().unwrap_or(t_batch);
                    *slot = Some((o.first_id.wrapping_add(k as u32), t_user));
                }
                i += o.sent;
                if !o.failed {
                    break;
                }
                let (flow, due, ..) = &items[i];
                if o.would_block() {
                    rec.event_nb(
                        "send_eagain",
                        Value::map()
                            .with("sock", sock)
                            .with("burned_id", o.burned_id.map(u64::from))
                            .with("unburned_id", o.unburned_id.map(u64::from))
                            .with("tx_ids", s.tx_id_mode().name())
                            .with(
                                "skipped",
                                Value::Array(
                                    items[i..]
                                        .iter()
                                        .map(|(f, d, ..)| {
                                            Value::Array(vec![Value::from(*f), Value::from(d.seq)])
                                        })
                                        .collect(),
                                ),
                            ),
                    );
                    break;
                }
                record_send_failure(&rec, sock, s, &o, Some((*flow, due.seq, due.size)));
                // After a partial send the failed datagram is retried alone, so its errno shows
                // if it fails again; a reported error skips it.
                if o.error.is_some() {
                    i += 1;
                }
            }
            if s.tx_id_mode() != id_modes[sock] {
                id_modes[sock] = s.tx_id_mode();
                rec.event_nb(
                    "tx_id_mode",
                    Value::map()
                        .with("sock", sock)
                        .with("mode", id_modes[sock].name()),
                );
            }
            let mut rows = Vec::with_capacity(items.len());
            let mut bytes = 0u64;
            for ((flow, due, _, _, _, phase), sent_id) in items.iter().zip(&ok) {
                let Some((sent_id, t_user)) = *sent_id else {
                    continue;
                };
                bytes += u64::from(due.size);
                shared.flow_bytes.add(*flow, u64::from(due.size));
                rows.push(vec![
                    Some(sock as i64),
                    Some(i64::from(*flow)),
                    Some(due.seq as i64),
                    Some(i64::from(due.size)),
                    Some(i64::from(*phase)),
                    Some(i64::from(due.train)),
                    Some(i64::from(due.train_idx)),
                    Some(i64::from(due.tos)),
                    Some(i64::from(sent_id)),
                    Some(due.t_intended as i64),
                    Some(t_user as i64 - due.t_intended as i64),
                ]);
            }
            shared.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            rec.rows("tx", rows);
        }
    }
}

/// The `src` index of a received datagram's source tuple; the first datagram from a tuple
/// records its `peer_addr` event (docs/design/probe.md §5).
fn peer_idx(
    src_idx: &mut HashMap<SocketAddr, u64>,
    rec: &Recorder,
    sock: usize,
    src: SocketAddr,
) -> u64 {
    let next = src_idx.len() as u64;
    *src_idx.entry(src).or_insert_with(|| {
        rec.event_nb(
            "peer_addr",
            Value::map()
                .with("idx", next)
                .with("sock", sock)
                .with("addr", pii(src.to_string(), "id")),
        );
        next
    })
}

/// The probe header an ICMP error quotes, under QUIC framing or not (docs/design/probe.md
/// §3.3). A quoted control datagram yields none: its first byte (`0xC1`–`0xC3`) would pass
/// for a QUIC long header, and stripping it would read ciphertext as a flow and seq.
fn quoted_header(payload: &[u8]) -> Option<Header> {
    if Frame::is_control(payload) {
        None
    } else {
        Header::decode(probe::quic::strip(payload))
    }
}

fn receiver_loop(
    shared: Arc<Shared>,
    socks: Vec<Arc<UdpSock>>,
    cmd: Sender<PacerCmd>,
    rec: Recorder,
) {
    let mut bufs = vec![[0u8; MAX_DATAGRAM]; 32];
    let mut src_idx: HashMap<SocketAddr, u64> = HashMap::new();
    let (mut bad_tag, mut unknown, mut truncated) = (0u64, 0u64, 0u64);
    let mut last_bad = mono_raw();
    let mut last_fb_sent = 0u64;
    let refs: Vec<&UdpSock> = socks.iter().map(|s| s.as_ref()).collect();
    while !shared.stop.load(Ordering::Relaxed) {
        let ready = match poll_many(&refs, 5) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for (si, (readable, err)) in ready.iter().enumerate() {
            let s = &socks[si];
            if *err {
                let mut evs = Vec::new();
                let _ = s.drain_errqueue(&mut evs);
                let mut rows = Vec::new();
                for e in evs {
                    match e {
                        ErrEvent::TxStamp { id, kind, real } => rows.push(vec![
                            Some(si as i64),
                            Some(i64::from(id)),
                            Some(match kind {
                                TxKind::Sched => 0,
                                TxKind::Snd => 1,
                            }),
                            Some(real as i64),
                        ]),
                        ErrEvent::Icmp {
                            errno,
                            icmp_type,
                            code,
                            info,
                            offender,
                            payload,
                        } => {
                            let quoted = quoted_header(&payload);
                            rec.event_nb(
                                "icmp",
                                Value::map()
                                    .with("sock", si)
                                    .with("real", pii(pt_sys::clock::realtime(), "quasi"))
                                    .with("errno", errno)
                                    .with("icmp_type", icmp_type)
                                    .with("code", code)
                                    .with("info", info)
                                    .with("offender", pii(offender.map(|o| o.to_string()), "id"))
                                    .with("flow", quoted.map(|h| u64::from(h.flow)))
                                    .with("seq", quoted.map(|h| h.seq)),
                            );
                        }
                        ErrEvent::Local { errno, info } => {
                            rec.event_nb(
                                "local_error",
                                Value::map()
                                    .with("sock", si)
                                    .with("errno", errno)
                                    .with("info", info),
                            );
                        }
                    }
                }
                rec.rows("txts", rows);
            }
            if !*readable {
                continue;
            }
            let mut msgs: Vec<InMsg> = Vec::new();
            let n = match s.recv_batch(&mut bufs, &mut msgs) {
                Ok(n) => n,
                Err(_) => continue,
            };
            let mono = mono_raw();
            let mut rows = Vec::with_capacity(n);
            let tagger = shared.tagger.read().expect("lock").clone();
            let session = shared.session.load(Ordering::Relaxed);
            for (i, m) in msgs.iter().enumerate() {
                let data = &bufs[i][..m.len];
                if m.truncated {
                    truncated += 1;
                    continue;
                }
                if Frame::is_control(data) {
                    // Control datagrams are observations too (they share the path with probes).
                    if let Some(Frame::Data { nonce, .. }) = Frame::decode(data) {
                        let flow = if shared.role == Role::A {
                            CONTROL_FLOW_B
                        } else {
                            CONTROL_FLOW_A
                        };
                        let (rx, rx_src) = match m.rx_kernel {
                            Some(k) => (k, 0),
                            None => (m.rx_user, 1),
                        };
                        rows.push(vec![
                            Some(si as i64),
                            Some(i64::from(flow)),
                            Some(nonce as i64),
                            Some(m.len as i64),
                            Some(rx as i64),
                            Some(rx_src),
                            m.tos.map(i64::from),
                            m.ttl.map(i64::from),
                            Some(peer_idx(&mut src_idx, &rec, si, m.src) as i64),
                            m.rxq_drops.map(i64::from),
                        ]);
                    }
                    if let Some(frame) = Frame::decode(data)
                        && let Some(tx) = shared.ctrl_in.lock().expect("lock").as_ref()
                    {
                        let _ = tx.send(CtrlIn {
                            frame,
                            src: m.src,
                            mono,
                            sock: Some(si),
                        });
                    }
                    continue;
                }
                let Some(tg) = tagger.as_ref() else { continue };
                let Some(h) = tg.verify(probe::quic::strip(data)) else {
                    bad_tag += 1;
                    continue;
                };
                if h.session != session {
                    unknown += 1;
                    continue;
                }
                let idx = peer_idx(&mut src_idx, &rec, si, m.src);
                // The responder replies on each socket to where the initiator's flows come from,
                // except NAT probes, which deliberately come from spare source ports.
                let from_spare = shared
                    .flows
                    .read()
                    .expect("lock")
                    .get(&h.flow)
                    .is_some_and(|f| matches!(f.sock, Sock::Spare(_)));
                if shared.role == Role::B && !from_spare {
                    let mut map = shared.peer_by_sock.lock().expect("lock");
                    if map.get(&si) != Some(&m.src) {
                        map.insert(si, m.src);
                    }
                }
                let (rx, rx_src) = match m.rx_kernel {
                    Some(k) => (k, 0),
                    None => (m.rx_user, 1),
                };
                rows.push(vec![
                    Some(si as i64),
                    Some(i64::from(h.flow)),
                    Some(h.seq as i64),
                    Some(m.len as i64),
                    Some(rx as i64),
                    Some(rx_src),
                    m.tos.map(i64::from),
                    m.ttl.map(i64::from),
                    Some(idx as i64),
                    m.rxq_drops.map(i64::from),
                ]);
                // Echo class/NAT probes back to their source (optionally delayed).
                if matches!(h.ptype, PktType::ClassProbe | PktType::NatProbe) {
                    let spec = shared.flows.read().expect("lock").get(&h.flow).cloned();
                    if let Some(spec) = spec
                        && spec.echo
                        && spec.sender != shared.role
                    {
                        let at = if spec.echo_delay_ns > 0 {
                            mono + spec.echo_delay_ns
                        } else {
                            0
                        };
                        let _ = cmd.send(PacerCmd::Raw {
                            sock: si,
                            dst: m.src,
                            bytes: data.to_vec(),
                            at,
                            log: None,
                        });
                    }
                }
                let mut fb = shared.fb.lock().expect("lock");
                let st = fb.entry(h.flow).or_default();
                st.highest_seq = st.highest_seq.max(h.seq);
                st.count += 1;
                st.bytes += m.len as u64;
                st.win_bytes += m.len as u64;
                let owd = rx as i64 - h.t_intended as i64;
                st.last_owd = owd;
                st.min_owd = Some(st.min_owd.map_or(owd, |v| v.min(owd)));
                st.updated = mono;
            }
            rec.rows("rx", rows);
        }
        let now = mono_raw();
        if now - last_bad > 1_000_000_000 {
            if bad_tag + unknown + truncated > 0 {
                rec.row(
                    "bad",
                    vec![
                        Some(now as i64),
                        Some(bad_tag as i64),
                        Some(unknown as i64),
                        Some(truncated as i64),
                    ],
                );
                (bad_tag, unknown, truncated) = (0, 0, 0);
            }
            last_bad = now;
        }
        // Feedback at 50 Hz while a controlled flow arrives, else 5 Hz (fewer control datagrams
        // on the path; still far inside the 500 ms dead-man window).
        let busy = shared.fb.lock().expect("lock").iter().any(|(id, st)| {
            now.saturating_sub(st.updated) < 1_000_000_000
                && shared
                    .flows
                    .read()
                    .expect("lock")
                    .get(id)
                    .is_some_and(|f| is_controlled(&f.pattern) || f.kind == "chirp")
        });
        let interval = if busy {
            FEEDBACK_INTERVAL_NS
        } else {
            10 * FEEDBACK_INTERVAL_NS
        };
        if now - last_fb_sent >= interval {
            last_fb_sent = now;
            send_feedback(&shared, now);
        }
    }
}

/// Send per-flow feedback for flows with recent arrivals (receiver → sender).
fn send_feedback(shared: &Shared, now: u64) {
    let Some(send) = shared.send_ctrl.get() else {
        return;
    };
    let mut flows = Vec::new();
    {
        let mut fb = shared.fb.lock().expect("lock");
        for (id, st) in fb.iter_mut() {
            if now.saturating_sub(st.updated) > 1_000_000_000 {
                continue;
            }
            let win = now.saturating_sub(st.win_start).max(1);
            let rate = st.win_bytes as f64 * 8.0 * 1e9 / win as f64;
            flows.push(
                Value::map()
                    .with("flow", *id)
                    .with("highest_seq", st.highest_seq)
                    .with("count", st.count)
                    .with("bytes", st.bytes)
                    .with("rate_bps", rate as u64)
                    .with(
                        "qdelay_ns",
                        (st.last_owd - st.min_owd.unwrap_or(st.last_owd)).max(0) as u64,
                    ),
            );
            st.win_bytes = 0;
            st.win_start = now;
        }
    }
    // Bounded message size: at most 8 flows per feedback message.
    for chunk in flows.chunks(8) {
        (send.0)(Envelope::new(
            "fb",
            Value::map()
                .with("flows", Value::Array(chunk.to_vec()))
                .with("t", now)
                .with("sent", shared.bytes_sent.load(Ordering::Relaxed)),
        ));
    }
}

/// Default destination port for a flow's socket at the responder.
pub fn responder_port(sock: Sock, main_port: u16) -> u16 {
    match sock {
        Sock::Udp443 => 443,
        _ => main_port,
    }
}

/// Whether a pattern is rate-controlled by the saturation controller.
pub fn is_controlled(p: &Pattern) -> bool {
    matches!(
        p,
        Pattern::Rate {
            controlled: true,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacing_verdicts() {
        use pt_sys::clock::PacingCheck;
        let c = |late: u64, background: bool, policy: Option<std::io::Error>| PacingCheck {
            policy,
            best_late_ns: late,
            background,
        };
        assert_eq!(
            pacing_verdict(&c(42_000, false, None)),
            (true, "pacer wakes 42 µs late at best".to_string())
        );
        let (ok, d) = pacing_verdict(&c(2_310_792, false, None));
        assert!(!ok);
        assert!(d.starts_with("pacer wakes 2.3 ms late at best: "), "{d}");
        assert!(
            d.contains("QoS clamp") && d.contains("terminal session"),
            "{d}"
        );
        let (ok, d) = pacing_verdict(&c(4_384_334, true, None));
        assert!(!ok);
        assert!(d.contains("background policy (taskpolicy -b"), "{d}");
        let (ok, d) = pacing_verdict(&c(10_000, false, Some(std::io::Error::other("refused"))));
        assert!(ok);
        assert!(d.ends_with("; pacing policy not set: refused"), "{d}");
    }

    #[test]
    fn dead_man_stops_saturating_flows_and_pauses_observers() {
        for k in ["heavy", "chirp", "cbr", "class-sat"] {
            assert_eq!(dead_man(k, true, false), DeadMan::Stop, "{k}");
            assert_eq!(dead_man(k, false, false), DeadMan::Run, "{k}");
        }
        for k in ["train", "pmtu"] {
            assert_eq!(dead_man(k, true, false), DeadMan::Pause, "{k}");
            assert_eq!(dead_man(k, true, true), DeadMan::Run, "{k}");
            assert_eq!(dead_man(k, false, true), DeadMan::Resume, "{k}");
            assert_eq!(dead_man(k, false, false), DeadMan::Run, "{k}");
        }
        // The light flow, NAT and class probes follow other rules.
        for k in ["light", "nat", "class", "control"] {
            assert_eq!(dead_man(k, true, false), DeadMan::Run, "{k}");
        }
    }

    #[test]
    fn peer_idx_numbers_source_tuples_once() {
        let path = std::env::temp_dir().join(format!("pt-peer-{}.ptflog", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut head = pt_format::Map::new();
        head.insert(pt_format::Key::from("kind"), Value::from("obslog"));
        let (rec, h) = crate::record::start(&path, head, Role::B).unwrap();
        let a: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let b: SocketAddr = "192.0.2.1:4434".parse().unwrap();
        let mut idx = HashMap::new();
        // A control datagram and a probe from one tuple share its index.
        assert_eq!(peer_idx(&mut idx, &rec, 0, a), 0);
        assert_eq!(peer_idx(&mut idx, &rec, 0, a), 0);
        assert_eq!(peer_idx(&mut idx, &rec, 1, b), 1);
        assert_eq!(peer_idx(&mut idx, &rec, 0, a), 0);
        drop(rec);
        // One `peer_addr` event per new tuple.
        assert_eq!(h.join().unwrap().unwrap().events, 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn quoted_control_datagrams_decode_no_header() {
        let h = Header {
            ptype: PktType::Data,
            flow: 3,
            phase: 4,
            session: 9,
            seq: 77,
            t_intended: 1,
            train: 0,
            train_idx: 0,
            flags: 0,
        };
        let mut hb = [0u8; probe::HEADER_LEN];
        h.encode(&mut hb);
        // Ciphertext whose bytes land a valid probe header right after a QUIC long header.
        let mut ciphertext = vec![0u8; probe::quic::LONG_OVERHEAD - 13];
        ciphertext.extend_from_slice(&hb);
        let ctrl = Frame::Data {
            session: 9,
            nonce: 5,
            ciphertext,
        }
        .encode();
        // Stripped as QUIC, the quote would yield a made-up flow and seq.
        assert_eq!(Header::decode(probe::quic::strip(&ctrl)), Some(h));
        assert_eq!(quoted_header(&ctrl), None);
        // Probe datagrams, bare or QUIC-framed, still yield theirs.
        assert_eq!(quoted_header(&hb), Some(h));
        let q = probe::quic::wrap(false, [1; 8], [2; 8], &hb);
        assert_eq!(quoted_header(&q), Some(h));
    }

    #[test]
    fn suspend_watch_reports_growth_of_boottime_over_mono() {
        let mut w = SuspendWatch::default();
        let ms = 1_000_000;
        // BOOTTIME 1 s ahead of MONO_RAW at boot already.
        assert_eq!(w.observe(1_000 * ms, 0), None);
        // Both advance together; a slow drift of the offset is no suspend.
        assert_eq!(w.observe(1_100 * ms, 100 * ms), None);
        assert_eq!(w.observe(1_201 * ms, 200 * ms), None);
        // 30 s suspended: MONO_RAW advanced 1 ms, BOOTTIME 30.001 s.
        assert_eq!(w.observe(31_202 * ms, 201 * ms), Some(30_000 * ms));
        // The new offset is the baseline from then on.
        assert_eq!(w.observe(31_302 * ms, 301 * ms), None);
    }
}
