//! Session orchestration: initiator (`probe`) and responder (`serve`)
//! (docs/design/probe.md §3, §6, §8).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pt_format::{Key, Map, Value};
use pt_sys::clock::{mono_raw, pair, realtime};
use pt_sys::udp::{InMsg, MAX_DATAGRAM, OutMsg, SockOpts, UdpSock};
use pt_wire::ctrl::{BodyExt, Envelope, Frame, WIRE_MAJOR, WIRE_MINOR};
use pt_wire::probe::Tagger;

use crate::config::{self, Keypair, Responder};
use crate::context::{self, Sampler};
use crate::control::{Control, Wire, tcp_reader};
use crate::flows::{self, FlowSpec, Pattern, Role, Sock, Tos};
use crate::io::{CtrlIn, Endpoint, PacerCmd, Shared, is_controlled};
use crate::noise;
use crate::plan::{Controller, Profile, ids, pmtu_ladder, spec};
use crate::record::{self, Recorder, pii};
use crate::tcp::{self, ConnHeader, Kind, ServerCtx};

/// Identity of the running tool, recorded in META (REQ-FMT-008).
#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub version: String,
    pub git_commit: String,
    pub git_dirty: bool,
}

impl ToolInfo {
    pub fn to_value(&self) -> Value {
        Value::map()
            .with("name", "pathtrace")
            .with("version", self.version.as_str())
            .with("git_commit", self.git_commit.as_str())
            .with("git_dirty", self.git_dirty)
    }
}

/// User-supplied network description (REQ-PRB-019).
#[derive(Debug, Clone, Default)]
pub struct NetTags {
    pub class: String,
    pub label: String,
    pub mobility: String,
    pub tags: Vec<String>,
}

pub const TCP_KEY_CONTEXT: &str = "pathtrace tcp header v1";
pub const FETCH_KEY_CONTEXT: &str = "pathtrace fetch v1";
pub const TCP_CONTROL_MAGIC: &[u8; 4] = b"PTC1";
/// `welcome.error` of a responder that is running another session (docs/design/probe.md §8).
pub const BUSY: &str = "busy";

fn utc_now() -> String {
    let secs = realtime() / 1_000_000_000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// The clock domains of an endpoint, each with the OS clock it is read from (PTF 1.2
/// `source`, ptf-format.md §6; probe.md §9.1).
fn clocks_value(role: Role) -> Value {
    clocks_value_for(role, pt_sys::PLATFORM.os_family)
}

/// [`clocks_value`] for the platform `os_family` names.
fn clocks_value_for(role: Role, os_family: &str) -> Value {
    let r = role.name();
    let mono_source = if os_family == "darwin" {
        "mach_absolute_time"
    } else {
        "CLOCK_MONOTONIC_RAW"
    };
    Value::map()
        .with(
            &format!("{r}.mono"),
            Value::map()
                .with("kind", "monotonic_raw")
                .with("endpoint", r)
                .with("source", mono_source),
        )
        .with(
            &format!("{r}.real"),
            Value::map()
                .with("kind", "realtime")
                .with("endpoint", r)
                .with("source", "CLOCK_REALTIME"),
        )
}

/// META head for an observation log.
#[allow(clippy::too_many_arguments)]
fn obslog_meta(
    role: Role,
    trace_id: &str,
    session: u32,
    profile: &str,
    tool: &ToolInfo,
    facts: Value,
    net: Option<&NetTags>,
    extra: Value,
) -> Map {
    let p = pair(8);
    let mut pii = Map::new();
    pii.insert(Key::from("/created_utc"), Value::from("quasi"));
    pii.insert(Key::from("/endpoint/hostname"), Value::from("id"));
    pii.insert(Key::from("/endpoint/addr"), Value::from("id"));
    pii.insert(Key::from("/endpoint/peer_addr"), Value::from("id"));
    pii.insert(Key::from("/endpoint/iface/name"), Value::from("quasi"));
    if facts
        .get("underlay")
        .is_some_and(|u| u.get("name").is_some())
    {
        pii.insert(Key::from("/endpoint/underlay/name"), Value::from("quasi"));
    }
    let mut head = Value::map()
        .with("kind", "obslog")
        .with("role", role.name())
        .with("trace_id", trace_id)
        .with("created_utc", utc_now())
        .with("tool", tool.to_value())
        .with(
            "session",
            Value::map()
                .with("id", session)
                .with("profile", profile)
                .with("t0_mono", p.mono)
                .with("t0_real", p.real)
                .with("t0_boot", p.boot),
        )
        .with("endpoint", facts)
        .with("clocks", clocks_value(role))
        .with("redaction", "full")
        .with("extra", extra);
    if let Some(n) = net {
        pii.insert(Key::from("/network/label"), Value::from("id"));
        head = head.with(
            "network",
            Value::map()
                .with("class", n.class.as_str())
                .with("label", n.label.as_str())
                .with("mobility", n.mobility.as_str())
                .with(
                    "tags",
                    Value::Array(n.tags.iter().map(|t| Value::from(t.as_str())).collect()),
                ),
        );
    }
    let mut m = head.as_map().cloned().unwrap_or_default();
    m.insert(Key::from("pii"), Value::Map(pii));
    m
}

/// The detail of the `power_assertion` event (PTF 1.2, probe.md §9.4).
fn power_assertion_detail<T>(held: &io::Result<T>) -> Value {
    Value::map().with("held", held.is_ok()).with(
        "error",
        held.as_ref().err().map(std::string::ToString::to_string),
    )
}

/// Per-socket capabilities for META `endpoint.sockets` (ptf-format.md, PTF 1.1).
fn sockets_value(socks: &[(Sock, Arc<UdpSock>)]) -> Value {
    Value::Array(
        socks
            .iter()
            .map(|(name, s)| {
                let c = s.caps();
                Value::map()
                    .with("name", name.name())
                    .with("kernel_rx", c.kernel_rx)
                    .with("kernel_tx", c.kernel_tx)
                    .with("recv_buf", c.recv_buf)
                    .with("send_buf", c.send_buf)
                    .with("rxq_ovfl", c.rxq_ovfl)
                    .with("tx_ids", s.tx_id_mode().name())
                    .with("icmp_errors", c.icmp_errors)
            })
            .collect(),
    )
}

/// Socket options, with the ground-truth harness's test hooks (docs/design/probe.md §4.2):
/// `PATHTRACE_RECV_BUF` (bytes) shrinks receive buffers to provoke socket drops, and
/// `PATHTRACE_TX_IDS=predicted` forces predicted transmit ids. Field use never sets them.
fn sock_opts() -> SockOpts {
    let mut o = SockOpts::default();
    if let Some(b) = std::env::var("PATHTRACE_RECV_BUF")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        o.recv_buf = b;
    }
    o.force_predicted_ids = std::env::var("PATHTRACE_TX_IDS").is_ok_and(|v| v == "predicted");
    o
}

/// The test hooks in effect, for META `extra.test_hooks` (null when none is set): they
/// change what is measured, so a trace says when it was captured with them.
fn test_hooks_value(o: &SockOpts) -> Value {
    let d = SockOpts::default();
    if o.recv_buf == d.recv_buf && !o.force_predicted_ids {
        return Value::Null;
    }
    Value::map()
        .with(
            "PATHTRACE_RECV_BUF",
            (o.recv_buf != d.recv_buf).then_some(o.recv_buf as u64),
        )
        .with(
            "PATHTRACE_TX_IDS",
            o.force_predicted_ids.then_some("predicted"),
        )
}

fn bind_any(v6: bool, port: u16, opts: SockOpts) -> io::Result<UdpSock> {
    let addr: SocketAddr = if v6 {
        SocketAddr::new(IpAddr::from([0u16; 8]), port)
    } else {
        SocketAddr::new(IpAddr::from([0u8; 4]), port)
    };
    UdpSock::bind(addr, opts)
}

fn recv_one(sock: &UdpSock, timeout: Duration) -> Option<(Vec<u8>, InMsg)> {
    let deadline = Instant::now() + timeout;
    let mut bufs = vec![[0u8; MAX_DATAGRAM]; 1];
    while Instant::now() < deadline {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .max(1) as i32;
        if let Ok((true, _)) = sock.poll(left.min(100)) {
            let mut out = Vec::new();
            if sock.recv_batch(&mut bufs, &mut out).unwrap_or(0) == 1 {
                let m = out[0];
                return Some((bufs[0][..m.len].to_vec(), m));
            }
        }
    }
    None
}

// =====================================================================================
// Initiator
// =====================================================================================

#[derive(Debug, Clone)]
pub struct ProbeOpts {
    pub config_dir: PathBuf,
    pub out_dir: PathBuf,
    pub responder: Responder,
    pub profile: Profile,
    pub net: NetTags,
    pub tool: ToolInfo,
    /// Prefer IPv6 when the responder name resolves to both families.
    pub prefer_v6: bool,
    pub rate_cap_bps: u64,
    /// `--data-cap` as requested, recorded in META; `profile.data_cap` already applies it.
    pub data_cap_user: Option<u64>,
    /// Override the deep profile's tracking time.
    pub track_s: Option<u64>,
    /// Print progress lines to stderr.
    pub verbose: bool,
}

/// Tracking rounds a session may run: round i uses flow id `ids::TRACK0 + i`, and 100–249 is
/// all the one-byte id space has below the control flows (250, 251). A reused id would restart
/// at seq 0 and `merge`, which joins by (flow, seq), would join its sends to the earlier use's
/// arrivals (issue #106).
pub const MAX_TRACK_ROUNDS: u64 = 150;

/// Whether profile `p` (its data cap already lowered by `--data-cap`) can run `track_s`
/// seconds of tracking: at most [`MAX_TRACK_ROUNDS`] rounds, and background traffic over the
/// planned session (at a 1500-byte MTU, the most a session uses) within the cap
/// (docs/design/probe.md §6, Tracking). The error names the largest tracking time that fits.
pub fn check_track(p: &Profile, track_s: u64) -> Result<(), String> {
    if track_s == 0 {
        return Ok(());
    }
    let fits_cap =
        |t: u64| crate::plan::background_bps(p, 1500) * p.planned_s(t) <= p.data_cap as f64;
    let fits = |t: u64| Profile::track_rounds(t) <= MAX_TRACK_ROUNDS && fits_cap(t);
    if fits(track_s) {
        return Ok(());
    }
    let max = (0..track_s.min((MAX_TRACK_ROUNDS + 1) * 60))
        .rev()
        .find(|&t| fits(t))
        .unwrap_or(0);
    let why = if Profile::track_rounds(track_s) > MAX_TRACK_ROUNDS {
        format!("more than {MAX_TRACK_ROUNDS} tracking rounds (one per 60 s)")
    } else {
        format!(
            "background traffic past the {} profile's {} B data cap",
            p.name, p.data_cap
        )
    };
    Err(format!(
        "--track-secs {track_s} needs {why}; at most {max} s fits"
    ))
}

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub trace_id: String,
    pub session: u32,
    pub log_a: PathBuf,
    pub log_b: Option<PathBuf>,
    /// `<trace_id>.session`, needed by `fetch --resume` (delete once the trace is complete).
    pub session_file: PathBuf,
    pub notes: Vec<String>,
}

/// Byte allowances for saturating flows (docs/design/probe.md §6). Index 0 = a, 1 = b.
struct Budget {
    cap: [u64; 2],
    /// Saturation seconds still to come per sender.
    left_s: [f64; 2],
    /// Background bytes per second per sender (light flow, trains, control).
    bg_bps: f64,
    /// Reserve per sender for P8 (TCP bulk transfer and constant-rate flow); 0 once P8 ran.
    ref_bytes: [u64; 2],
    /// Planned seconds per phase (`Profile::phase_plan`).
    plan: Vec<(u16, f64)>,
    /// Planned seconds of the current phase, of the phases after it (plus margin), and when
    /// the current phase started.
    cur_s: f64,
    rest_s: f64,
    phase_start: Instant,
    /// The session lasts at least until here (NAT binding probes).
    nat_end: Instant,
}

impl Budget {
    /// Phase `id` starts: the reserve covers its planned time and every later phase's, so a
    /// phase that ran long does not shrink the reserve for the ones still to come.
    fn enter(&mut self, id: u16) {
        self.cur_s = self.plan.iter().find(|p| p.0 == id).map_or(0.0, |p| p.1);
        self.rest_s = self
            .plan
            .iter()
            .filter(|p| p.0 > id)
            .map(|p| p.1)
            .sum::<f64>()
            + 5.0;
        self.phase_start = Instant::now();
    }

    /// Planned seconds still to come.
    fn time_left_s(&self) -> f64 {
        let planned =
            (self.cur_s - self.phase_start.elapsed().as_secs_f64()).max(0.0) + self.rest_s;
        planned.max(
            self.nat_end
                .saturating_duration_since(Instant::now())
                .as_secs_f64(),
        )
    }

    /// Bytes sender `k` must keep for background traffic and P8 from now on.
    fn reserve(&self, k: usize) -> u64 {
        (self.bg_bps * self.time_left_s()) as u64 + self.ref_bytes[k]
    }
}

struct Ctx {
    ep: Endpoint,
    ctl: Arc<Control>,
    ctrlr: Arc<Controller>,
    rec: Recorder,
    main_port: u16,
    mtu: u32,
    verbose: bool,
    notes: Vec<String>,
    budget: Budget,
    /// A stop signal was received and recorded (docs/design/probe.md §8).
    interrupted: bool,
    /// UDP reaches the responder; false in a TCP-fallback session, which defines no UDP flow
    /// (docs/design/probe.md §3.1).
    udp: bool,
}

impl Ctx {
    fn say(&self, s: &str) {
        if self.verbose {
            eprintln!("[pathtrace] {s}");
        }
    }

    /// Whether a stop signal arrived here, or the responder announced (`abort`) that one
    /// arrived there; records `interrupted` the first time (docs/design/probe.md §8).
    fn interrupted(&mut self) -> bool {
        if self.interrupted {
            return true;
        }
        if let Some(sig) = pt_sys::signal::stop_requested() {
            self.interrupted = true;
            let name = pt_sys::signal::name(sig);
            self.rec
                .event("interrupted", Value::map().with("signal", name));
            self.notes.push(format!(
                "interrupted by {name}: remaining phases skipped, session ended early"
            ));
            self.say(&format!(
                "{name}: ending the session (send it again to quit at once)"
            ));
            return true;
        }
        // The initiator reads no other session-level message, so draining here loses nothing.
        while let Some(env) = self.ctl.recv(Duration::ZERO) {
            if env.kind != "abort" {
                continue;
            }
            self.interrupted = true;
            let name = env.body.str_or("signal", "other").to_string();
            self.rec.event(
                "interrupted",
                Value::map()
                    .with("signal", name.as_str())
                    .with("by", "responder"),
            );
            self.notes.push(format!(
                "responder stopped by {name}: remaining phases skipped, session ended early"
            ));
            self.say(&format!("responder stopped by {name}: ending the session"));
            return true;
        }
        false
    }

    /// Start phase `id`; returns false (and starts nothing) once the session is interrupted.
    fn phase(&mut self, id: u16, name: &str) -> bool {
        if self.interrupted() {
            return false;
        }
        self.budget.enter(id);
        self.log_phase(id, name);
        true
    }

    /// In a TCP-fallback session, record that phase `id` sends none of its UDP flows (`what`)
    /// and return true (docs/design/probe.md §3.1); false when UDP reaches the responder.
    fn udp_blocked(&self, id: u16, what: &str) -> bool {
        if self.udp {
            return false;
        }
        self.rec.event(
            "phase_skipped",
            Value::map()
                .with("phase", id)
                .with("what", what)
                .with("reason", "udp_blocked"),
        );
        self.say(&format!("skipping {what} (P{id}): UDP is blocked"));
        true
    }

    fn log_phase(&self, id: u16, name: &str) {
        self.say(&format!("phase P{id} {name}"));
        let body = Value::map().with("phase", id).with("name", name);
        self.rec.event("phase_start", body.clone());
        self.ctl.send(&Envelope::new("phase", body));
    }

    fn start(&mut self, specs: Vec<FlowSpec>, delay_ms: u64) -> bool {
        if self.interrupted() {
            return false;
        }
        // Control datagrams carry DF (PMTU probing on the main socket), so each message must
        // fit in one packet: send flow definitions in batches of bounded encoded size.
        let mut batches: Vec<Vec<Value>> = vec![Vec::new()];
        let mut size = 0;
        for s in &specs {
            let v = s.to_value();
            let n = pt_format::cbor::encode(&v).map_or(0, |b| b.len());
            if size + n > crate::control::MAX_BODY && !batches.last().is_some_and(Vec::is_empty) {
                batches.push(Vec::new());
                size = 0;
            }
            size += n;
            batches.last_mut().expect("non-empty").push(v);
        }
        let at = mono_raw() + delay_ms * 1_000_000;
        for b in batches {
            let left = at.saturating_sub(mono_raw());
            let body = Value::map()
                .with("flows", Value::Array(b))
                .with("start_in_ns", left);
            if let Err(e) = self.ctl.request("flows", body, Duration::from_secs(5)) {
                self.rec
                    .event("phase_failed", Value::map().with("reason", e.to_string()));
                self.notes.push(format!(
                    "could not start flows {:?}: {e}",
                    specs.iter().map(|s| s.id).collect::<Vec<_>>()
                ));
                return false;
            }
        }
        for s in specs {
            self.rec.flow(s.to_value());
            self.ep.shared.define_flow(s.clone());
            if s.sender == Role::A {
                if is_controlled(&s.pattern) {
                    self.ctrlr.add(s.id, at, s.duration_ns, s.max_bytes);
                }
                self.ep.start_flow(s, at);
            }
        }
        true
    }

    fn stop(&mut self, ids: &[u8]) {
        for id in ids {
            let _ = self.ep.cmd.send(PacerCmd::Stop(*id));
            self.ctrlr.remove(*id);
        }
        let body = Value::map().with(
            "ids",
            Value::Array(ids.iter().map(|i| Value::from(*i)).collect()),
        );
        if self
            .ctl
            .request("stop", body, Duration::from_secs(5))
            .is_err()
        {
            self.notes
                .push(format!("stop of flows {ids:?} not acknowledged"));
        }
    }

    /// Sleep `s` seconds, returning early when a stop signal arrives.
    fn sleep(&mut self, s: f64) {
        let end = Instant::now() + Duration::from_secs_f64(s);
        while !self.interrupted() {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            std::thread::sleep(left.min(Duration::from_millis(100)));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn mk(
        &self,
        id: u8,
        kind: &str,
        sender: Role,
        sock: Sock,
        size: u32,
        pattern: Pattern,
        phase: u16,
        dur_s: f64,
    ) -> FlowSpec {
        spec(
            id,
            kind,
            sender,
            sock,
            size,
            pattern,
            phase,
            (dur_s * 1e9) as u64,
            self.main_port,
        )
    }

    /// Byte allowance for a saturating flow of `sender` lasting `dur_s`, or `None` (recorded
    /// as `phase_skipped`) when too little budget is left (docs/design/probe.md §6).
    fn allow(&mut self, id: u8, sender: Role, phase: u16, dur_s: f64) -> Option<u64> {
        let k = usize::from(sender == Role::B);
        let sh = &self.ep.shared;
        let spent = match sender {
            Role::A => sh.bytes_sent.load(Ordering::Relaxed),
            Role::B => sh.peer_bytes_sent.load(Ordering::Relaxed),
        };
        let b = &mut self.budget;
        let reserve = b.reserve(k);
        let a = crate::plan::allowance(b.cap[k], spent, reserve, dur_s, b.left_s[k]);
        b.left_s[k] = (b.left_s[k] - dur_s).max(0.0);
        if a < crate::plan::MIN_ALLOWANCE {
            self.rec.event(
                "phase_skipped",
                Value::map()
                    .with("phase", phase)
                    .with("flow", id)
                    .with("sender", sender.name())
                    .with("allowance", a)
                    .with("spent", spent)
                    .with("reason", "budget"),
            );
            self.say(&format!(
                "skipping flow {id} (P{phase}): data budget left for {} is {a} B",
                sender.name()
            ));
            return None;
        }
        Some(a)
    }

    /// A saturating heavy flow with its byte allowance, or `None` if the budget is spent.
    fn heavy(&mut self, id: u8, sender: Role, phase: u16, dur_s: f64) -> Option<FlowSpec> {
        let max_bytes = self.allow(id, sender, phase, dur_s)?;
        let mut s = self.mk(
            id,
            "heavy",
            sender,
            Sock::Main,
            self.mtu,
            Pattern::Rate {
                bps: crate::plan::START_BPS as u64,
                controlled: true,
            },
            phase,
            dur_s,
        );
        s.max_bytes = max_bytes;
        Some(s)
    }
}

/// What `pathtrace fetch --resume` needs to retrieve a responder log later: written as
/// `<trace_id>.session` (0600) right after the handshake (docs/design/probe.md §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFile {
    pub responder: String,
    pub session: u32,
    pub token: [u8; 32],
    /// The responder's TLS certificate (DER), pinned through the Noise handshake.
    pub cert: Vec<u8>,
    /// Where the responder log goes.
    pub log_b: PathBuf,
}

impl SessionFile {
    pub fn path(out_dir: &Path, trace_id: &str) -> PathBuf {
        out_dir.join(format!("{trace_id}.session"))
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        let text = format!(
            "# pathtrace session file: pathtrace fetch --resume {}\nresponder {}\nsession {:08x}\ntoken {}\ncert {}\nlog_b {}\n",
            path.display(),
            self.responder,
            self.session,
            config::hex(&self.token),
            config::hex(&self.cert),
            self.log_b.display()
        );
        config::write_secret(path, &text)
    }

    pub fn read(path: &Path) -> io::Result<SessionFile> {
        let text = config::read_private(path)?;
        let field = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k)?.strip_prefix(' '))
                .map(str::trim)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: missing {k}", path.display()),
                    )
                })
        };
        let bad = |e: String| io::Error::new(io::ErrorKind::InvalidData, e);
        let cert = config::unhex(field("cert")?)
            .map_err(|e| bad(format!("{}: cert: {e}", path.display())))?;
        Ok(SessionFile {
            responder: field("responder")?.to_string(),
            session: u32::from_str_radix(field("session")?, 16).map_err(|e| bad(e.to_string()))?,
            token: config::unhex32(field("token")?)?,
            cert,
            log_b: PathBuf::from(field("log_b")?),
        })
    }
}

/// Resolve the responder address, preferring the requested family.
pub fn resolve(addr: &str, prefer_v6: bool) -> io::Result<(SocketAddr, Vec<SocketAddr>)> {
    let all: Vec<SocketAddr> = if let Ok(sa) = addr.parse::<SocketAddr>() {
        vec![sa]
    } else if let Ok(ip) = addr.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, 4433)]
    } else if addr
        .rsplit_once(':')
        .is_some_and(|(h, p)| !h.contains(':') && p.parse::<u16>().is_ok())
    {
        addr.to_socket_addrs()?.collect()
    } else {
        (addr, 4433u16).to_socket_addrs()?.collect()
    };
    let primary = all
        .iter()
        .find(|a| a.is_ipv6() == prefer_v6)
        .or_else(|| all.first())
        .copied()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{addr} did not resolve"))
        })?;
    Ok((primary, all))
}

/// The responder addresses the initiator tries, in order (docs/design/probe.md §3.1): the
/// first of the preferred family, then the first of the other.
fn family_order(all: &[SocketAddr], prefer_v6: bool) -> Vec<SocketAddr> {
    [prefer_v6, !prefer_v6]
        .iter()
        .filter_map(|v6| all.iter().find(|a| a.is_ipv6() == *v6).copied())
        .collect()
}

fn family_name(a: &SocketAddr) -> &'static str {
    if a.is_ipv6() { "ipv6" } else { "ipv4" }
}

/// The responder address to use and the local address that reaches it: the first address in
/// [`family_order`] this host has a route to (docs/design/probe.md §3.1).
pub fn route(addr: &str, prefer_v6: bool) -> io::Result<(SocketAddr, IpAddr)> {
    let (_, all) = resolve(addr, prefer_v6)?;
    let mut errs = Vec::new();
    for c in family_order(&all, prefer_v6) {
        match pt_sys::netif::local_addr_for(c) {
            Ok(ip) => return Ok((c, ip)),
            Err(e) => errs.push(format!("{c}: {e}")),
        }
    }
    Err(no_route(addr, &errs))
}

fn no_route(addr: &str, errs: &[String]) -> io::Error {
    io::Error::new(
        io::ErrorKind::NetworkUnreachable,
        format!("no route to responder {addr} ({})", errs.join("; ")),
    )
}

/// A responder address this host can reach: its local address and the main socket bound for it.
struct Candidate {
    dst: SocketAddr,
    local_ip: IpAddr,
    sock: Arc<UdpSock>,
}

/// How the handshake went: the candidate it succeeded on, the reply, the TCP control stream
/// (fallback), and why every family before it was not used.
struct Handshake {
    cand: Candidate,
    session: u32,
    noise: Vec<u8>,
    tcp: Option<TcpStream>,
    /// The preferred family and why it was not used, when the session runs on the other family.
    fallback: Option<(&'static str, String)>,
}

/// The `family_fallback` a session on `used` records (docs/design/probe.md §3.1): the
/// preferred family and why it was not used, or `None` when `used` is of the preferred family.
/// `why` holds the reason each tried address was given up; a responder without an address of
/// the preferred family was never tried, and that is the reason.
fn family_fallback(
    used: &SocketAddr,
    prefer_v6: bool,
    why: &[(SocketAddr, String)],
) -> Option<(&'static str, String)> {
    if used.is_ipv6() == prefer_v6 {
        return None;
    }
    let requested = if prefer_v6 { "ipv6" } else { "ipv4" };
    let reason = why
        .iter()
        .find(|(a, _)| a.is_ipv6() == prefer_v6)
        .map_or_else(
            || format!("responder has no {requested} address"),
            |(_, w)| w.clone(),
        );
    Some((requested, reason))
}

/// Try the UDP handshake on every reachable family, then the TCP fallback on each
/// (docs/design/probe.md §3.1).
fn handshake(
    addr: &str,
    all: &[SocketAddr],
    prefer_v6: bool,
    sopts: SockOpts,
    init: &[u8],
    verbose: bool,
) -> io::Result<Handshake> {
    let order = family_order(all, prefer_v6);
    let mut why: Vec<(SocketAddr, String)> = Vec::new();
    let mut cands = Vec::new();
    for dst in &order {
        let c = pt_sys::netif::local_addr_for(*dst).and_then(|local_ip| {
            Ok(Candidate {
                dst: *dst,
                local_ip,
                sock: Arc::new(bind_any(dst.is_ipv6(), 0, sopts)?),
            })
        });
        match c {
            Ok(c) => cands.push(c),
            Err(e) => {
                if verbose {
                    eprintln!(
                        "[pathtrace] {} unusable: no route to {dst} ({e})",
                        family_name(dst)
                    );
                }
                why.push((*dst, format!("no route: {e}")));
            }
        }
    }
    if cands.is_empty() {
        let errs: Vec<String> = why.iter().map(|(a, w)| format!("{a}: {w}")).collect();
        return Err(no_route(addr, &errs));
    }
    let done = |cand: Candidate,
                session: u32,
                noise: Vec<u8>,
                tcp: Option<TcpStream>,
                why: &[(SocketAddr, String)]| {
        let fallback = family_fallback(&cand.dst, prefer_v6, why);
        Handshake {
            cand,
            session,
            noise,
            tcp,
            fallback,
        }
    };
    let mut udp_failed = Vec::new();
    for c in cands {
        match handshake_udp(&c.sock, c.dst, init, verbose) {
            Some((session, noise)) => return Ok(done(c, session, noise, None, &why)),
            None => {
                why.push((c.dst, "no handshake reply over UDP".into()));
                udp_failed.push(c);
            }
        }
    }
    if verbose {
        eprintln!("[pathtrace] no UDP handshake reply; trying TCP fallback");
    }
    for c in udp_failed {
        if let Some((s, session, noise)) = handshake_tcp(c.dst.ip(), init) {
            return Ok(done(c, session, noise, Some(s), &why));
        }
        if let Some(w) = why.iter_mut().find(|(a, _)| *a == c.dst) {
            w.1 = "no handshake reply over UDP or TCP".into();
        }
    }
    let tried: Vec<String> = order.iter().map(SocketAddr::to_string).collect();
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "responder {} unreachable over UDP {} and TCP 443/4433",
            tried.join(" and "),
            order.first().map_or(4433, SocketAddr::port)
        ),
    ))
}

fn handshake_udp(
    sock: &UdpSock,
    dst: SocketAddr,
    init: &[u8],
    verbose: bool,
) -> Option<(u32, Vec<u8>)> {
    for attempt in 0..3 {
        if verbose {
            eprintln!(
                "[pathtrace] handshake attempt {} over UDP to {dst}",
                attempt + 1
            );
        }
        let _ = sock.send_batch(&[OutMsg {
            dst,
            payload: init,
            tos: 0,
        }]);
        let deadline = Instant::now() + Duration::from_secs(1);
        while let Some((data, m)) =
            recv_one(sock, deadline.saturating_duration_since(Instant::now()))
        {
            if m.src == dst
                && let Some(Frame::Resp { session, noise }) = Frame::decode(&data)
            {
                return Some((session, noise));
            }
        }
    }
    None
}

fn read_framed(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    if n > 1 << 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut b = vec![0u8; n];
    s.read_exact(&mut b)?;
    Ok(b)
}

fn write_framed(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut v = (b.len() as u32).to_le_bytes().to_vec();
    v.extend_from_slice(b);
    s.write_all(&v)
}

fn handshake_tcp(ip: IpAddr, init: &[u8]) -> Option<(TcpStream, u32, Vec<u8>)> {
    use std::io::Write;
    for port in [443u16, 4433] {
        let Ok(mut s) =
            TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(3))
        else {
            continue;
        };
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        if s.write_all(TCP_CONTROL_MAGIC).is_err() || write_framed(&mut s, init).is_err() {
            continue;
        }
        if let Ok(b) = read_framed(&mut s)
            && let Some(Frame::Resp { session, noise }) = Frame::decode(&b)
        {
            let _ = s.set_read_timeout(None);
            return Some((s, session, noise));
        }
    }
    None
}

/// Run one measurement session as the initiator. Always returns the initiator log path when a
/// session was established, even if phases failed (REQ-PRB-020).
pub fn run_probe(opts: &ProbeOpts) -> io::Result<ProbeOutcome> {
    check_track(&opts.profile, opts.track_s.unwrap_or(opts.profile.track_s))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let kp: Keypair = config::load_keypair(&opts.config_dir)?;
    let (_, all) = resolve(&opts.responder.addr, opts.prefer_v6)?;
    let sopts = sock_opts();
    let trace_id = uuid::Uuid::now_v7().to_string();

    let hello = Envelope::new(
        "hello",
        Value::map()
            .with("wire_major", WIRE_MAJOR)
            .with("wire_minor", WIRE_MINOR)
            .with("tool", opts.tool.to_value())
            .with("trace_id", trace_id.as_str())
            .with("profile", opts.profile.name)
            .with("data_cap", opts.profile.data_cap)
            .with("rate_cap_bps", opts.rate_cap_bps),
    );
    let (ih, init) =
        noise::initiator_start(&kp, &opts.responder.public, &opts.responder.psk, &hello)?;
    let mut notes = Vec::new();
    let hs = handshake(
        &opts.responder.addr,
        &all,
        opts.prefer_v6,
        sopts,
        &init,
        opts.verbose,
    )?;
    let Handshake {
        cand,
        session,
        noise: noise2,
        tcp: mut tcp_ctrl,
        fallback,
    } = hs;
    let (dst, local_ip, main) = (cand.dst, cand.local_ip, cand.sock);
    let v6 = dst.is_ipv6();
    let udp = tcp_ctrl.is_none();
    if !udp {
        notes.push(
            "UDP control blocked; session ran over TCP fallback (UDP classes recorded as blocked)"
                .into(),
        );
    }
    let (transport, welcome) = ih.finish(&noise2, session)?;
    let wb = &welcome.body;
    let peer_major = wb.u64_or("wire_major", 0);
    if peer_major != WIRE_MAJOR {
        return Err(io::Error::other(format!(
            "wire protocol mismatch: initiator v{WIRE_MAJOR}, responder v{peer_major}; upgrade the older side"
        )));
    }
    if let Some(err) = wb.get("error").and_then(Value::as_str) {
        if err == BUSY {
            return Err(io::Error::other(format!(
                "responder busy: {}; try again when it has finished",
                wb.str_or("error_text", "it is running another session")
            )));
        }
        return Err(io::Error::other(format!(
            "responder refused the session: {err}"
        )));
    }
    if let Some((from, why)) = &fallback {
        eprintln!(
            "[pathtrace] {from} unusable ({why}); session runs over {} to {dst}",
            family_name(&dst)
        );
    }
    let iface = pt_sys::netif::iface_with_addr(local_ip)?.unwrap_or_default();
    let iface_info = pt_sys::netif::iface_info(&iface);
    let mtu = iface_info.mtu.unwrap_or(1500).min(1500);
    let metered = context::metered(&iface);
    let transport = Arc::new(transport);
    let cert = match wb.get("tls_cert") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };

    let mut socks: Vec<(Sock, Arc<UdpSock>)> = vec![(Sock::Main, main.clone())];
    socks.push((Sock::Udp443, Arc::new(bind_any(v6, 0, sopts)?)));
    for k in 0..opts.profile.nat_timeouts_s.len() {
        socks.push((
            Sock::Spare(k as u8),
            Arc::new(bind_any(
                v6,
                0,
                SockOpts {
                    pmtu_probe: false,
                    ..sopts
                },
            )?),
        ));
    }

    // Observation log.
    std::fs::create_dir_all(&opts.out_dir)?;
    let log_a = opts.out_dir.join(format!("{trace_id}.a.ptflog"));
    let pacing = pt_sys::clock::pacing_check();
    let facts = context::host_facts()
        .with("addr", local_ip.to_string())
        .with("peer_addr", dst.to_string())
        .with("iface", context::iface_facts(&iface, Some(local_ip)))
        .with("qdisc", context::egress_facts(&iface).0)
        .with("txqueuelen", context::egress_facts(&iface).1)
        .with("metered", metered.as_str())
        .with(
            "timestamping",
            Value::map()
                .with("kernel_rx", main.caps().kernel_rx)
                .with("kernel_tx", main.caps().kernel_tx)
                .with("recv_buf", main.caps().recv_buf)
                .with("send_buf", main.caps().send_buf),
        )
        .with("sockets", sockets_value(&socks));
    let facts = context::host_state_facts(facts, &iface, local_ip, &pacing);
    let mut extra = Value::map()
        .with(
            "responder",
            Value::map()
                .with("name", opts.responder.name.as_str())
                .with("facts", wb.get("facts").cloned().unwrap_or(Value::Null))
                // A responder below wire minor 1 sends no `sent` feedback and enforces no
                // `max_bytes` (probe.md §3.2).
                .with("wire_minor", wb.u64_or("wire_minor", 0)),
        )
        .with(
            "all_addrs",
            Value::Array(all.iter().map(|a| Value::from(a.to_string())).collect()),
        )
        .with("control", if tcp_ctrl.is_some() { "tcp" } else { "udp" })
        .with("test_hooks", test_hooks_value(&sopts));
    if let Some(c) = opts.data_cap_user {
        extra = extra.with("data_cap_user", c);
    }
    let mut meta = obslog_meta(
        Role::A,
        &trace_id,
        session,
        opts.profile.name,
        &opts.tool,
        facts,
        Some(&opts.net),
        extra,
    );
    if let Some(Value::Map(p)) = meta.get_mut(&Key::from("pii")) {
        p.insert(Key::from("/extra/all_addrs"), Value::from("id"));
        p.insert(Key::from("/extra/responder/name"), Value::from("quasi"));
    }
    let (rec, rec_join) = record::start(&log_a, meta, Role::A)?;
    // Before measuring: everything needed to fetch the responder's half later, even if this
    // process is interrupted or the network goes away (docs/design/probe.md §8).
    let log_b = opts.out_dir.join(format!("{trace_id}.b.ptflog"));
    let token = transport.session_key(FETCH_KEY_CONTEXT);
    let session_file = SessionFile::path(&opts.out_dir, &trace_id);
    SessionFile {
        responder: opts.responder.name.clone(),
        session,
        token,
        cert: cert.clone(),
        log_b: log_b.clone(),
    }
    .write(&session_file)?;
    // Printed even with -q: it is what retrieves the responder's half if this process dies
    // (docs/design/cli.md, "probe prints the session before measuring").
    eprintln!(
        "session: {session:08x} (trace {trace_id}; session file {})",
        session_file.display()
    );
    rec.event(
        "handshake",
        Value::map()
            .with("session", session)
            .with("control", if tcp_ctrl.is_some() { "tcp" } else { "udp" }),
    );
    if let Some((from, why)) = &fallback {
        rec.event(
            "family_fallback",
            Value::map()
                .with("requested", *from)
                .with("used", family_name(&dst))
                .with("reason", why.as_str()),
        );
    }
    // Keep an idle host awake from before P0 until this function returns, after the trace is
    // written (probe.md §9.4). A session continues without it.
    let _power = pt_sys::PLATFORM.power_assertion.then(|| {
        let held = pt_sys::power::prevent_idle_sleep(pt_sys::power::SESSION_ASSERTION_NAME);
        rec.event("power_assertion", power_assertion_detail(&held));
        held.ok()
    });
    // On macOS a QoS clamp or background policy on this process caps the pacer whatever it
    // requests; say so on stderr now, before measuring, even with -q (probe.md §9.4). It is
    // not a note: a note marks the trace partial, and the session is complete, with the
    // lateness recorded in the trace anyway.
    if pt_sys::PLATFORM.os_family == "darwin"
        && let Ok(p) = &pacing
        && let (false, d) = crate::io::pacing_verdict(p)
    {
        eprintln!("warning: {d}");
    }

    // Endpoint.
    let shared = Shared::new(Role::A, opts.profile.data_cap, opts.rate_cap_bps);
    shared.session.store(session, Ordering::Relaxed);
    *shared.tagger.write().expect("lock") = Some(Tagger::new(&transport.handshake_hash));
    *shared.peer_ip.write().expect("lock") = Some(dst.ip());
    *shared.ctrl_dst.write().expect("lock") = Some(dst);
    let (frames_tx, frames_rx) = channel::<CtrlIn>();
    *shared.ctrl_in.lock().expect("lock") = Some(frames_tx.clone());
    let ep = Endpoint::start(shared.clone(), socks, rec.clone())?;
    let _ = ep.cmd.send(PacerCmd::SetTagger(Box::new(Tagger::new(
        &transport.handshake_hash,
    ))));
    let ctrlr = Arc::new(Controller::new(
        Role::A,
        ep.cmd.clone(),
        opts.rate_cap_bps,
        shared.flow_bytes.clone(),
    ));
    let wire = match tcp_ctrl.take() {
        Some(s) => {
            let reader = s.try_clone()?;
            let sh = shared.clone();
            std::thread::spawn(move || tcp_reader(reader, frames_tx, sh));
            Wire::Tcp(Arc::new(Mutex::new(s)))
        }
        None => Wire::Udp {
            cmd: ep.cmd.clone(),
            sock: 0,
        },
    };
    let c2 = ctrlr.clone();
    let ctl = Control::start(
        transport.clone(),
        wire,
        shared.clone(),
        frames_rx,
        Box::new(move |b| c2.on_feedback(b)),
        rec.clone(),
    );
    let sampler = Sampler::start(Some(iface.clone()), Some(dst.ip()), rec.clone(), true);
    for c in crate::plan::control_specs(dst.port()) {
        rec.flow(c.to_value());
        shared.flows.write().expect("lock").insert(c.id, c);
    }

    let track_s = opts.track_s.unwrap_or(opts.profile.track_s);
    let p = &opts.profile;
    let started = Instant::now();
    let cap = [
        p.data_cap,
        p.data_cap.min(wb.u64_or("data_cap", p.data_cap)),
    ];
    let ref_bytes = |c: u64| {
        if p.refs {
            crate::plan::ref_tcp_bytes(c) + crate::plan::REF_CBR_BYTES
        } else {
            0
        }
    };
    let mut budget = Budget {
        cap,
        left_s: [
            p.saturation_s(Role::A, track_s),
            p.saturation_s(Role::B, track_s),
        ],
        // A TCP-fallback session sends no UDP background and runs no NAT probes.
        bg_bps: if udp {
            crate::plan::background_bps(p, mtu)
        } else {
            0.0
        },
        ref_bytes: [ref_bytes(cap[0]), ref_bytes(cap[1])],
        plan: p.phase_plan(track_s),
        cur_s: 0.0,
        rest_s: 0.0,
        phase_start: started,
        nat_end: started + Duration::from_secs_f64(if udp { p.nat_s() } else { 0.0 }),
    };
    budget.enter(0);
    let mut ctx = Ctx {
        ep,
        ctl,
        ctrlr,
        rec: rec.clone(),
        main_port: dst.port(),
        mtu,
        verbose: opts.verbose,
        notes,
        budget,
        interrupted: false,
        udp,
    };
    let tcp_key = transport.session_key(TCP_KEY_CONTEXT);
    run_phases(&mut ctx, opts, dst, &all, &cert, &tcp_key, session);

    // NAT probes need the session to outlast the longest timeout.
    let max_nat = opts
        .profile
        .nat_timeouts_s
        .iter()
        .max()
        .copied()
        .unwrap_or(0) as f64
        + 2.0;
    let el = started.elapsed().as_secs_f64();
    if udp && el < max_nat {
        ctx.say(&format!(
            "waiting {:.0} s for NAT binding probes",
            max_nat - el
        ));
        ctx.sleep(max_nat - el);
    }
    ctx.log_phase(9, "end");
    if ctx.udp {
        ctx.stop(&[ids::LIGHT_A, ids::LIGHT_B, ids::TRAIN_A, ids::TRAIN_B]);
    }
    let _ = ctx.ep.cmd.send(PacerCmd::StopAll);
    std::thread::sleep(Duration::from_secs(1));
    let bye_ok = ctx
        .ctl
        .request("bye", Value::map(), Duration::from_secs(5))
        .is_ok();
    if !bye_ok {
        ctx.notes.push("responder did not acknowledge bye".into());
    }
    rec.event(
        "session_end",
        Value::map()
            .with("bytes_sent", shared.bytes_sent.load(Ordering::Relaxed))
            .with("cap_hit", shared.cap_hit.load(Ordering::Relaxed)),
    );
    // Drop every recorder clone explicitly so the recorder thread can finish the log.
    let Ctx {
        ep,
        ctl,
        ctrlr,
        rec: ctx_rec,
        notes,
        ..
    } = ctx;
    drop(ctx_rec);
    drop(ctrlr);
    let mut notes = notes;
    sampler.stop();
    shared.stop.store(true, Ordering::Relaxed);
    ep.shutdown();
    ctl.join();
    drop(ctl);
    drop(rec);
    let summary = rec_join
        .join()
        .map_err(|_| io::Error::other("recorder panicked"))??;
    if summary.dropped > 0 {
        notes.push(format!(
            "{} observation rows dropped by recorder backpressure",
            summary.dropped
        ));
    }

    // Fetch the responder log.
    let fetched = fetch_with_retry(dst, &cert, session, &token, &log_b, opts.verbose);
    if let Err(e) = &fetched {
        notes.push(format!(
            "could not fetch responder log yet ({e}); later run: pathtrace fetch --resume {}",
            session_file.display()
        ));
    }
    Ok(ProbeOutcome {
        trace_id,
        session,
        log_a,
        log_b: fetched.ok().map(|_| log_b),
        session_file,
        notes,
    })
}

/// Fetch routes in order (docs/design/probe.md §8): with the pinned certificate, TLS on the
/// responder's port, then TLS on 443. Plain TCP on the responder's port only when no
/// certificate is known (`cert` empty), with a warning, since the fetch token then crosses
/// the network in clear. A known certificate that cannot be used is an error, never a
/// downgrade to plain TCP.
fn fetch_routes(
    dst: SocketAddr,
    cert: &[u8],
) -> io::Result<Vec<(u16, Option<Arc<rustls::ClientConfig>>)>> {
    if cert.is_empty() {
        eprintln!(
            "[pathtrace] warning: no responder TLS certificate known; fetching over plain TCP on tcp/{} (the fetch token is sent unencrypted; `fetch --resume <id.session>` uses TLS)",
            dst.port()
        );
        return Ok(vec![(dst.port(), None)]);
    }
    let c = tcp::client_config(cert)
        .map_err(|e| io::Error::other(format!("pinned TLS certificate unusable: {e}")))?;
    Ok(vec![(dst.port(), Some(c.clone())), (443, Some(c))])
}

/// Fetch a finished session's responder log from `dst` (the responder's control address)
/// over the routes [`fetch_routes`] gives.
pub fn fetch_with_retry(
    dst: SocketAddr,
    cert: &[u8],
    session: u32,
    token: &[u8; 32],
    out: &Path,
    verbose: bool,
) -> io::Result<u64> {
    let mut last = io::Error::other("no attempt");
    let routes = fetch_routes(dst, cert)?;
    for attempt in 0..10 {
        for (port, cfg) in routes.iter().cloned() {
            let over = if cfg.is_some() { "TLS" } else { "plain TCP" };
            match tcp::fetch(
                SocketAddr::new(dst.ip(), port),
                cfg,
                session,
                token,
                out,
                Duration::from_secs(5),
            ) {
                Ok(n) => {
                    if verbose {
                        eprintln!(
                            "[pathtrace] fetched the responder log over {over} on tcp/{port}"
                        );
                    }
                    return Ok(n);
                }
                Err(e) => {
                    if verbose {
                        eprintln!(
                            "[pathtrace] fetch attempt {} via tcp/{port}: {e}",
                            attempt + 1
                        );
                    }
                    last = e;
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(last)
}

fn run_phases(
    ctx: &mut Ctx,
    opts: &ProbeOpts,
    dst: SocketAddr,
    all: &[SocketAddr],
    cert: &[u8],
    tcp_key: &[u8; 32],
    session: u32,
) {
    let p = &opts.profile;
    let mtu = ctx.mtu;
    let tls = if cert.is_empty() {
        None
    } else {
        tcp::client_config(cert).ok()
    };

    // Background: light flow + light trains (whole session), PMTU ladders, NAT probes.
    if !ctx.phase(0, "background") {
        return;
    }
    if !ctx.udp_blocked(0, "background") {
        let mut bg = Vec::new();
        for (id, sender) in [(ids::LIGHT_A, Role::A), (ids::LIGHT_B, Role::B)] {
            let mut s = ctx.mk(
                id,
                "light",
                sender,
                Sock::Main,
                128,
                Pattern::Iso {
                    interval_ns: 20_000_000,
                },
                0,
                0.0,
            );
            s.tos = Tos::Cycle;
            bg.push(s);
        }
        for (id, sender) in [(ids::TRAIN_A, Role::A), (ids::TRAIN_B, Role::B)] {
            bg.push(ctx.mk(
                id,
                "train",
                sender,
                Sock::Main,
                mtu,
                Pattern::Train {
                    count: p.train_count,
                    period_ns: p.train_period_ms * 1_000_000,
                },
                0,
                0.0,
            ));
        }
        for (k, t) in p.nat_timeouts_s.iter().enumerate() {
            let mut s = ctx.mk(
                ids::NAT0 + k as u8,
                "nat",
                Role::A,
                Sock::Spare(k as u8),
                128,
                Pattern::Burst {
                    count: 1,
                    gap_ns: 1,
                },
                0,
                0.0,
            );
            s.echo = true;
            s.echo_delay_ns = t * 1_000_000_000;
            bg.push(s);
        }
        let ladder = pmtu_ladder(dst.is_ipv6(), mtu.max(1280));
        let ladder_ns = ladder.len() as u64 * 3 * 20_000_000;
        bg.push(ctx.mk(
            ids::PMTU_A,
            "pmtu",
            Role::A,
            Sock::Main,
            0,
            Pattern::Ladder {
                sizes: ladder.clone(),
                reps: 3,
                gap_ns: 20_000_000,
            },
            1,
            0.0,
        ));
        ctx.start(bg, 50);
        // B's ladder after A's, so ICMP and losses are attributable.
        ctx.sleep(ladder_ns as f64 / 1e9 + 0.2);
        let lb = ctx.mk(
            ids::PMTU_B,
            "pmtu",
            Role::B,
            Sock::Main,
            0,
            Pattern::Ladder {
                sizes: ladder,
                reps: 3,
                gap_ns: 20_000_000,
            },
            1,
            0.0,
        );
        ctx.start(vec![lb], 50);
    }

    // P1 reachability: UDP classes (echoed) and TCP classes.
    if !ctx.phase(1, "reachability") {
        return;
    }
    if !ctx.udp_blocked(1, "udp classes") {
        let mut cls = Vec::new();
        for (id, sock, quic, class) in [
            (ids::CLASS_MAIN, Sock::Main, false, "udp/high-port"),
            (ids::CLASS_443, Sock::Udp443, false, "udp/443"),
            (ids::CLASS_QUIC, Sock::Udp443, true, "udp/443-quic"),
        ] {
            let mut s = ctx.mk(
                id,
                "class",
                Role::A,
                sock,
                200,
                Pattern::Burst {
                    count: 5,
                    gap_ns: 100_000_000,
                },
                1,
                0.0,
            );
            s.echo = true;
            s.quic = quic;
            s.class = class.to_string();
            cls.push(s);
        }
        ctx.start(cls, 50);
    }
    for addr in std::iter::once(dst).chain(all.iter().copied().filter(|a| a.ip() != dst.ip())) {
        for (id, port, use_tls) in [
            (ids::TCP_PROBE80, 80u16, false),
            (ids::TCP_PROBE443, 443, true),
            (ids::TCP_PROBE4433, 4433, false),
        ] {
            let hdr = ConnHeader {
                session,
                flow: id,
                kind: Kind::Probe,
                bytes: 0,
                duration_ns: 0,
                param: 0,
            };
            let r = tcp::client(
                SocketAddr::new(addr.ip(), port),
                if use_tls { tls.clone() } else { None },
                hdr,
                tcp_key,
                &ctx.rec,
                0,
                Duration::from_secs(3),
            );
            ctx.rec.event(
                "tcp_probe",
                Value::map()
                    .with("flow", id)
                    .with("port", port)
                    .with("family", if addr.is_ipv6() { "ipv6" } else { "ipv4" })
                    .with("primary", addr.ip() == dst.ip())
                    .with("tls", use_tls)
                    .with("connect_ns", r.connect_ns)
                    .with("tls_ns", r.tls_ns)
                    .with("cc", r.cc.as_str())
                    .with("error", r.error.clone()),
            );
        }
    }
    ctx.sleep(1.0);
    let reached = |id: u8| ctx.ep.shared.fb.lock().expect("lock").contains_key(&id);
    let (high_ok, udp443_ok, quic_ok) = (
        reached(ids::CLASS_MAIN),
        reached(ids::CLASS_443),
        reached(ids::CLASS_QUIC),
    );
    let mut reach = Value::map()
        .with("udp443", udp443_ok)
        .with("quic", quic_ok)
        .with("high_port", high_ok);
    if !ctx.udp {
        reach = reach.with("reason", "udp_blocked");
    }
    ctx.rec.event("udp_reachability", reach);

    if !ctx.phase(2, "quiet") {
        return;
    }
    if !ctx.udp_blocked(2, "quiet") {
        ctx.sleep(p.quiet_s);
    }

    if p.chirp_s > 0.0 {
        if !ctx.phase(3, "chirps") {
            return;
        }
        if !ctx.udp_blocked(3, "chirps") {
            let a = ctx.mk(
                ids::CHIRP_A,
                "chirp",
                Role::A,
                Sock::Main,
                mtu,
                flows::CHIRP,
                3,
                p.chirp_s,
            );
            ctx.start(vec![a], 50);
            let b = ctx.mk(
                ids::CHIRP_B,
                "chirp",
                Role::B,
                Sock::Main,
                mtu,
                flows::CHIRP,
                3,
                p.chirp_s,
            );
            ctx.start(vec![b], 250);
            ctx.sleep(p.chirp_s + 0.5);
        }
    }

    if p.sat_s > 0.0 {
        if !ctx.phase(4, "saturate a_to_b") {
            return;
        }
        if !ctx.udp_blocked(4, "saturation")
            && let Some(s) = ctx.heavy(ids::HEAVY_A, Role::A, 4, p.sat_s)
        {
            ctx.start(vec![s], 50);
            ctx.sleep(p.sat_s + 1.0);
        }
        if !ctx.phase(5, "saturate b_to_a") {
            return;
        }
        if !ctx.udp_blocked(5, "saturation")
            && let Some(s) = ctx.heavy(ids::HEAVY_B, Role::B, 5, p.sat_s)
        {
            ctx.start(vec![s], 50);
            ctx.sleep(p.sat_s + 1.0);
        }
    }
    if p.both_s > 0.0 {
        if !ctx.phase(6, "saturate both") {
            return;
        }
        if !ctx.udp_blocked(6, "saturation") {
            let both: Vec<FlowSpec> = [
                ctx.heavy(ids::BOTH_A, Role::A, 6, p.both_s),
                ctx.heavy(ids::BOTH_B, Role::B, 6, p.both_s),
            ]
            .into_iter()
            .flatten()
            .collect();
            if !both.is_empty() {
                ctx.start(both, 50);
                ctx.sleep(p.both_s + 1.0);
            }
        }
    }
    if p.class_sat_s > 0.0 {
        if !ctx.phase(7, "class differential") {
            return;
        }
        let classes = if ctx.udp_blocked(7, "class saturations") {
            Vec::new()
        } else {
            vec![
                (ids::CSAT_MAIN, Sock::Main, false, "udp/high-port", true),
                (ids::CSAT_443, Sock::Udp443, false, "udp/443", udp443_ok),
                (ids::CSAT_QUIC, Sock::Udp443, true, "udp/443-quic", quic_ok),
            ]
        };
        for (id, sock, quic, class, ok) in classes {
            if !ok {
                ctx.rec.event(
                    "class_skipped",
                    Value::map()
                        .with("class", class)
                        .with("reason", "unreachable in P1"),
                );
                ctx.budget.left_s[0] = (ctx.budget.left_s[0] - p.class_sat_s).max(0.0);
                continue;
            }
            let Some(max_bytes) = ctx.allow(id, Role::A, 7, p.class_sat_s) else {
                continue;
            };
            let mut s = ctx.mk(
                id,
                "class-sat",
                Role::A,
                sock,
                mtu,
                Pattern::Rate {
                    bps: crate::plan::START_BPS as u64,
                    controlled: true,
                },
                7,
                p.class_sat_s,
            );
            s.quic = quic;
            s.class = class.to_string();
            s.max_bytes = max_bytes;
            ctx.start(vec![s], 50);
            ctx.sleep(p.class_sat_s + 0.5);
        }
    }
    if p.refs {
        if !ctx.phase(8, "reference flows") {
            return;
        }
        // Each direction's bulk transfer gets its reserved bytes, or what its sender has left
        // after the background and CBR still to come, whichever is less (probe.md §6).
        let bulk = |ctx: &Ctx, k: usize| {
            let sh = &ctx.ep.shared;
            let spent = if k == 0 {
                sh.bytes_sent.load(Ordering::Relaxed)
            } else {
                sh.peer_bytes_sent.load(Ordering::Relaxed)
            };
            let b = &ctx.budget;
            let after = (b.bg_bps * b.time_left_s()) as u64 + crate::plan::REF_CBR_BYTES;
            crate::plan::ref_tcp_bytes(b.cap[k])
                .min(b.cap[k].saturating_sub(spent).saturating_sub(after))
        };
        let dur = if p.name == "smoke" { 2.0 } else { 5.0 };
        let addr443 = SocketAddr::new(dst.ip(), 443);
        for (id, kind, k) in [
            (ids::TCP_BULK_UP, Kind::Upload, 0),
            (ids::TCP_BULK_DOWN, Kind::Download, 1),
        ] {
            let bulk = bulk(ctx, k);
            let hdr = ConnHeader {
                session,
                flow: id,
                kind,
                bytes: bulk,
                duration_ns: (dur * 1e9) as u64,
                param: 0,
            };
            let r = tcp::client(
                addr443,
                tls.clone(),
                hdr,
                tcp_key,
                &ctx.rec,
                0,
                Duration::from_secs(10),
            );
            ctx.ep.shared.bytes_sent.fetch_add(
                if kind == Kind::Upload { r.bytes } else { 0 },
                Ordering::Relaxed,
            );
            ctx.rec.event(
                "ref_tcp",
                Value::map()
                    .with("flow", id)
                    .with("kind", format!("{kind:?}"))
                    .with("bytes", r.bytes)
                    .with("elapsed_ns", r.elapsed_ns)
                    .with("cc", r.cc.as_str())
                    .with("error", r.error.clone()),
            );
        }
        let n = if p.name == "smoke" { 50u64 } else { 200 };
        let hdr = ConnHeader {
            session,
            flow: ids::TCP_RR,
            kind: Kind::ReqResp,
            bytes: n,
            duration_ns: (dur * 1e9) as u64,
            param: (1024 << 32) | 1024,
        };
        let r = tcp::client(
            addr443,
            tls.clone(),
            hdr,
            tcp_key,
            &ctx.rec,
            0,
            Duration::from_secs(10),
        );
        ctx.rec.event(
            "ref_tcp",
            Value::map()
                .with("flow", ids::TCP_RR)
                .with("kind", "ReqResp")
                .with("bytes", r.bytes)
                .with("elapsed_ns", r.elapsed_ns)
                .with("error", r.error.clone()),
        );
        let cbr = if ctx.udp_blocked(8, "cbr") {
            Vec::new()
        } else {
            vec![(ids::CBR_A, Role::A), (ids::CBR_B, Role::B)]
        };
        for (id, sender) in cbr {
            let s = ctx.mk(
                id,
                "cbr",
                sender,
                Sock::Main,
                1200,
                Pattern::Rate {
                    bps: 2_000_000,
                    controlled: false,
                },
                8,
                dur,
            );
            ctx.start(vec![s], 50);
            ctx.sleep(dur + 0.5);
        }
        // P8 is done: its reserve is free for the tracking saturations.
        ctx.budget.ref_bytes = [0, 0];
    }
    let track = opts.track_s.unwrap_or(p.track_s);
    if track > 0 {
        if !ctx.phase(10, "tracking") || ctx.udp_blocked(10, "tracking saturations") {
            return;
        }
        // `run_probe` refused a longer tracking time; the bound keeps every id unique anyway.
        let rounds = Profile::track_rounds(track).min(MAX_TRACK_ROUNDS);
        for i in 0..rounds {
            ctx.sleep(57.0);
            if ctx.interrupted() {
                return;
            }
            let sender = if i % 2 == 0 { Role::A } else { Role::B };
            // Every round has a flow id of its own (i < MAX_TRACK_ROUNDS = 150).
            let id = ids::TRACK0 + i as u8;
            if let Some(s) = ctx.heavy(id, sender, 10, 3.0) {
                ctx.start(vec![s], 50);
            }
            ctx.sleep(3.0);
        }
    }
}

// =====================================================================================
// Responder
// =====================================================================================

#[derive(Debug, Clone)]
pub struct ServeOpts {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub main_port: u16,
    /// Also listen on UDP/TCP 443 and TCP 80 (needs CAP_NET_BIND_SERVICE below 1024).
    pub class_ports: bool,
    pub data_cap: u64,
    pub rate_cap_bps: u64,
    pub tool: ToolInfo,
    pub retention_days: u64,
    /// Stop after this many sessions (tests); 0 = forever.
    pub max_sessions: u64,
    pub verbose: bool,
}

struct Active {
    session: u32,
    tcp_key: [u8; 32],
    rec: Recorder,
    /// The Noise handshake message that opened the session.
    init: Vec<u8>,
}

/// What the responder needs to refuse a handshake while a session runs.
struct Refuser {
    kp: Keypair,
    config_dir: PathBuf,
    tool: ToolInfo,
}

#[derive(Default)]
struct RespState {
    active: Mutex<Option<Active>>,
    /// Finished sessions: id → (log path, fetch token).
    finished: Mutex<HashMap<u32, (PathBuf, [u8; 32])>>,
    control_tcp: Mutex<Option<Sender<TcpStream>>>,
    refuser: std::sync::OnceLock<Refuser>,
}

impl RespState {
    /// The sealed `welcome {error: "busy"}` reply (session 0) to handshake message `noise`, or
    /// `None` when it does not authenticate: strangers get no answer (docs/design/probe.md §8).
    fn refuse(&self, noise: &[u8]) -> Option<Vec<u8>> {
        let r = self.refuser.get()?;
        let authorized = config::load_authorized(&r.config_dir).ok()?;
        let acc = noise::responder_accept(&r.kp, &authorized, noise).ok()?;
        let body = Value::map()
            .with("wire_major", WIRE_MAJOR)
            .with("wire_minor", WIRE_MINOR)
            .with("session", 0u32)
            .with("tool", r.tool.to_value())
            .with("error", BUSY)
            .with("error_text", "the responder is running another session");
        acc.respond(0, &Envelope::new("welcome", body))
            .ok()
            .map(|(_, m)| m)
    }

    /// The running session's recorder, unless `noise` is the handshake that opened it (which
    /// is answered by the session itself, never refused).
    fn other_than_active(&self, noise: &[u8]) -> Option<Recorder> {
        let a = self.active.lock().expect("lock");
        a.as_ref()
            .filter(|a| a.init.as_slice() != noise)
            .map(|a| a.rec.clone())
    }
}

fn refused_event(src: SocketAddr, via: &str) -> Value {
    Value::map()
        .with("reason", "busy")
        .with("via", via)
        .with("addr", pii(src.to_string(), "id"))
}

/// Refuse the handshakes waiting on main sockets the running session does not use (the other
/// family's). Nothing else sends on them while the session runs.
fn refuse_idle(state: &RespState, idle: &[Arc<UdpSock>]) {
    for s in idle {
        if !matches!(s.poll(0), Ok((true, _))) {
            continue;
        }
        let mut bufs = vec![[0u8; MAX_DATAGRAM]; 8];
        let mut out = Vec::new();
        let _ = s.recv_batch(&mut bufs, &mut out);
        for (k, m) in out.iter().enumerate() {
            let Some(Frame::Init { noise }) = Frame::decode(&bufs[k][..m.len]) else {
                continue;
            };
            let Some(rec) = state.other_than_active(&noise) else {
                continue;
            };
            if let Some(reply) = state.refuse(&noise) {
                let _ = s.send_batch(&[OutMsg {
                    dst: m.src,
                    payload: &reply,
                    tos: 0,
                }]);
                rec.event("handshake_refused", refused_event(m.src, "udp"));
            }
        }
    }
}

/// Refuse a TCP control connection's handshake while a session runs.
fn refuse_tcp(state: &RespState, mut s: TcpStream) {
    let Ok(b) = read_framed(&mut s) else { return };
    let Some(Frame::Init { noise }) = Frame::decode(&b) else {
        return;
    };
    let Some(rec) = state.other_than_active(&noise) else {
        return;
    };
    if let Some(reply) = state.refuse(&noise)
        && write_framed(&mut s, &reply).is_ok()
    {
        let src = s
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("addr"));
        rec.event("handshake_refused", refused_event(src, "tcp"));
    }
}

impl ServerCtx for RespState {
    fn key(&self, session: u32, kind: Kind) -> Option<[u8; 32]> {
        if kind == Kind::Fetch {
            return self.finished.lock().ok()?.get(&session).map(|f| f.1);
        }
        let a = self.active.lock().ok()?;
        a.as_ref()
            .filter(|a| a.session == session)
            .map(|a| a.tcp_key)
    }
    fn recorder(&self, session: u32) -> Option<Recorder> {
        let a = self.active.lock().ok()?;
        a.as_ref()
            .filter(|a| a.session == session)
            .map(|a| a.rec.clone())
    }
    fn log_path(&self, session: u32) -> Option<PathBuf> {
        self.finished
            .lock()
            .ok()?
            .get(&session)
            .map(|f| f.0.clone())
    }
    fn saved_syn(&self, session: u32, flow: u8, port: u16, syn: Vec<u8>) {
        if let Some(rec) = self.recorder(session) {
            rec.event(
                "saved_syn",
                Value::map()
                    .with("flow", flow)
                    .with("port", port)
                    .with("syn", pii(Value::Bytes(syn), "id")),
            );
        }
    }
}

fn load_finished(state_dir: &Path, retention_days: u64) -> HashMap<u32, (PathBuf, [u8; 32])> {
    let mut out = HashMap::new();
    let Ok(rd) = std::fs::read_dir(state_dir.join("sessions")) else {
        return out;
    };
    for e in rd.flatten() {
        let dir = e.path();
        let Some(id) = dir
            .file_name()
            .and_then(|n| u32::from_str_radix(&n.to_string_lossy(), 16).ok())
        else {
            continue;
        };
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > Duration::from_secs(retention_days * 86_400));
        if old {
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        if let Ok(tok) = config::read_private(&dir.join("fetch_token"))
            && let Ok(t) = config::unhex32(tok.trim())
        {
            out.insert(id, (dir.join("b.ptflog"), t));
        }
    }
    out
}

fn spawn_tcp_listener(
    port: u16,
    v6: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
    state: Arc<RespState>,
    verbose: bool,
) {
    let addr = if v6 {
        SocketAddr::new(IpAddr::from([0u16; 8]), port)
    } else {
        SocketAddr::new(IpAddr::from([0u8; 4]), port)
    };
    let l = match bind_tcp(addr) {
        Ok(l) => l,
        Err(e) => {
            if verbose {
                eprintln!(
                    "[pathtrace] not listening on tcp/{port} ({}): {e}",
                    if v6 { "v6" } else { "v4" }
                );
            }
            return;
        }
    };
    let _ = pt_sys::tcp::set_save_syn(std::os::fd::AsRawFd::as_raw_fd(&l));
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let tls = tls.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                let syn = pt_sys::tcp::saved_syn(std::os::fd::AsRawFd::as_raw_fd(&s)).ok();
                let mut peek = [0u8; 4];
                let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                let n = s.peek(&mut peek).unwrap_or(0);
                if n == 4 && &peek == TCP_CONTROL_MAGIC {
                    use std::io::Read;
                    let mut s = s;
                    let mut m = [0u8; 4];
                    if s.read_exact(&mut m).is_err() {
                        return;
                    }
                    // The responder runs one session at a time: answer `busy` now rather
                    // than leave the initiator waiting (docs/design/probe.md §8).
                    if state.active.lock().expect("lock").is_some() {
                        refuse_tcp(&state, s);
                        return;
                    }
                    if let Some(tx) = state.control_tcp.lock().expect("lock").as_ref() {
                        let _ = tx.send(s);
                    }
                    return;
                }
                let use_tls = if n >= 1 && peek[0] == 0x16 { tls } else { None };
                if let Err(e) = tcp::serve_conn(s, use_tls, state.as_ref(), port, syn)
                    && verbose
                {
                    eprintln!("[pathtrace] tcp/{port} connection: {e}");
                }
            });
        }
    });
}

fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    if addr.is_ipv6() {
        // std binds v6 sockets dual-stack by default on Linux; bind v6-only via a v4 check.
        let l = TcpListener::bind(addr)?;
        Ok(l)
    } else {
        TcpListener::bind(addr)
    }
}

/// Run the responder until `max_sessions` sessions have completed (forever if 0).
pub fn serve(opts: &ServeOpts) -> io::Result<()> {
    let kp = config::load_keypair(&opts.config_dir)?;
    std::fs::create_dir_all(&opts.state_dir)?;
    let (cert, key) = tcp::load_or_create_cert(&opts.state_dir)?;
    let tls = tcp::server_config(&cert, &key)?;
    let state = Arc::new(RespState {
        finished: Mutex::new(load_finished(&opts.state_dir, opts.retention_days)),
        ..Default::default()
    });
    let (ctl_tx, ctl_rx) = channel::<TcpStream>();
    *state.control_tcp.lock().expect("lock") = Some(ctl_tx);
    let _ = state.refuser.set(Refuser {
        kp: kp.clone(),
        config_dir: opts.config_dir.clone(),
        tool: opts.tool.clone(),
    });

    let sopts = sock_opts();
    let main4 = Arc::new(bind_any(false, opts.main_port, sopts)?);
    let main6 = bind_any(true, opts.main_port, sopts).ok().map(Arc::new);
    let (u443_4, u443_6) = if opts.class_ports {
        (
            bind_any(false, 443, sopts).ok().map(Arc::new),
            bind_any(true, 443, sopts).ok().map(Arc::new),
        )
    } else {
        (None, None)
    };
    // TCP: main port (control fallback + fetch + class), and 443/80 when allowed. The v6
    // listener is dual-stack, so bind v6 first and fall back to v4.
    let mut ports = vec![opts.main_port];
    if opts.class_ports {
        ports.extend([443, 80]);
    }
    for port in ports {
        // Every TCP port accepts TLS (detected by the first byte) as well as plain headers.
        let t = Some(tls.clone());
        if bind_tcp(SocketAddr::new(IpAddr::from([0u16; 8]), port)).is_ok() {
            spawn_tcp_listener(port, true, t, state.clone(), opts.verbose);
        } else {
            spawn_tcp_listener(port, false, t, state.clone(), opts.verbose);
        }
    }
    if opts.verbose {
        eprintln!(
            "[pathtrace] responder ready: udp/{} (v4{}), udp/443 {}, tcp/{}{}",
            opts.main_port,
            if main6.is_some() { "+v6" } else { "" },
            if u443_4.is_some() { "yes" } else { "no" },
            opts.main_port,
            if opts.class_ports {
                ", tcp/443, tcp/80"
            } else {
                ""
            }
        );
    }
    let mut done = 0u64;
    loop {
        // Wait for a handshake on any main socket, or a TCP control connection.
        let mains: Vec<&UdpSock> = std::iter::once(main4.as_ref())
            .chain(main6.as_deref())
            .collect();
        let mut got: Option<(usize, Vec<u8>, SocketAddr, Option<TcpStream>)> = None;
        while got.is_none() {
            if let Some(sig) = pt_sys::signal::stop_requested() {
                if opts.verbose {
                    eprintln!(
                        "[pathtrace] {}: responder stopping",
                        pt_sys::signal::name(sig)
                    );
                }
                return Ok(());
            }
            if let Ok(s) = ctl_rx.try_recv() {
                let mut s = s;
                if let Ok(b) = read_framed(&mut s) {
                    let src = s
                        .peer_addr()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("addr"));
                    got = Some((0, b, src, Some(s)));
                    break;
                }
            }
            let ready = pt_sys::udp::poll_many(&mains, 200).unwrap_or_default();
            for (i, (r, _)) in ready.iter().enumerate() {
                if *r {
                    let mut bufs = vec![[0u8; MAX_DATAGRAM]; 8];
                    let mut out = Vec::new();
                    let _ = mains[i].recv_batch(&mut bufs, &mut out);
                    for (k, m) in out.iter().enumerate() {
                        if bufs[k].first() == Some(&pt_wire::ctrl::T_INIT) {
                            got = Some((i, bufs[k][..m.len].to_vec(), m.src, None));
                        }
                    }
                }
            }
        }
        let Some((mi, data, src, tcp)) = got else {
            continue;
        };
        let main = if mi == 0 {
            main4.clone()
        } else {
            main6.clone().expect("v6 main")
        };
        let u443 = if mi == 0 {
            u443_4.clone()
        } else {
            u443_6.clone()
        };
        // The other family's main socket, where other initiators are refused meanwhile.
        let idle: Vec<Arc<UdpSock>> = if mi == 0 {
            main6.iter().cloned().collect()
        } else {
            vec![main4.clone()]
        };
        let ran =
            match responder_session(opts, &kp, &state, &cert, main, u443, &idle, &data, src, tcp) {
                Ok(Some(id)) => {
                    done += 1;
                    if opts.verbose {
                        eprintln!("[pathtrace] session {id:08x} complete");
                    }
                    true
                }
                Ok(None) => false,
                Err(e) => {
                    eprintln!("[pathtrace] session error: {e}");
                    false
                }
            };
        if pt_sys::signal::stop_requested().is_some() {
            if ran {
                // The session was ended by the signal: give the initiator time to fetch the
                // log, as after the last of `--max-sessions` (a second signal quits at once).
                std::thread::sleep(Duration::from_secs(15));
            }
            return Ok(());
        }
        if opts.max_sessions > 0 && done >= opts.max_sessions {
            // Give the initiator time to fetch the log.
            std::thread::sleep(Duration::from_secs(15));
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn responder_session(
    opts: &ServeOpts,
    kp: &Keypair,
    state: &Arc<RespState>,
    cert: &[u8],
    main: Arc<UdpSock>,
    u443: Option<Arc<UdpSock>>,
    idle: &[Arc<UdpSock>],
    data: &[u8],
    src: SocketAddr,
    tcp: Option<TcpStream>,
) -> io::Result<Option<u32>> {
    let Some(Frame::Init { noise }) = Frame::decode(data) else {
        return Ok(None);
    };
    let authorized = config::load_authorized(&opts.config_dir)?;
    let acc = match noise::responder_accept(kp, &authorized, &noise) {
        Ok(a) => a,
        Err(e) => {
            if opts.verbose {
                eprintln!("[pathtrace] rejected handshake from {src}: {e}");
            }
            return Ok(None);
        }
    };
    let hello = acc.hello.clone();
    let label = acc.initiator.label.clone();
    let session = u32::from_le_bytes(config::random32()[..4].try_into().expect("4"));
    let peer_major = hello.body.u64_or("wire_major", 0);
    let mut welcome = Value::map()
        .with("wire_major", WIRE_MAJOR)
        .with("wire_minor", WIRE_MINOR)
        .with("session", session)
        .with("tool", opts.tool.to_value())
        .with("tls_cert", Value::Bytes(cert.to_vec()))
        .with("udp443", u443.is_some())
        .with("facts", context::host_facts().with("hostname", Value::Null))
        .with("data_cap", opts.data_cap);
    if peer_major != WIRE_MAJOR {
        welcome = welcome.with(
            "error",
            format!("wire protocol mismatch: responder v{WIRE_MAJOR}, initiator v{peer_major}"),
        );
    }
    let (transport, msg2) = acc.respond(session, &Envelope::new("welcome", welcome))?;
    match &tcp {
        Some(s) => {
            let mut s = s.try_clone()?;
            write_framed(&mut s, &msg2)?;
        }
        None => {
            let _ = main.send_batch(&[OutMsg {
                dst: src,
                payload: &msg2,
                tos: 0,
            }]);
        }
    }
    if peer_major != WIRE_MAJOR {
        return Ok(None);
    }
    let transport = Arc::new(transport);
    if opts.verbose {
        eprintln!("[pathtrace] session {session:08x} with {label} from {src}");
    }
    let trace_id = hello.body.str_or("trace_id", "").to_string();
    let profile = hello.body.str_or("profile", "unknown").to_string();
    let data_cap = hello
        .body
        .u64_or("data_cap", opts.data_cap)
        .min(opts.data_cap);
    let rate_cap = hello
        .body
        .u64_or("rate_cap_bps", opts.rate_cap_bps)
        .min(opts.rate_cap_bps);

    let dir = opts
        .state_dir
        .join("sessions")
        .join(format!("{session:08x}"));
    std::fs::create_dir_all(&dir)?;
    let log = dir.join("b.ptflog");
    // The fetch token is persisted before measuring, so the log stays fetchable after a
    // responder restart mid-session (docs/design/probe.md §8). Fetch is refused while the
    // session runs: only `finished` sessions are served.
    let token = transport.session_key(FETCH_KEY_CONTEXT);
    config::write_secret(&dir.join("fetch_token"), &config::hex(&token))?;
    let mut socks: Vec<(Sock, Arc<UdpSock>)> = vec![(Sock::Main, main.clone())];
    if let Some(u) = &u443 {
        socks.push((Sock::Udp443, u.clone()));
    }
    let local_ip = pt_sys::netif::local_addr_for(src).unwrap_or(src.ip());
    let iface = pt_sys::netif::iface_with_addr(local_ip)
        .ok()
        .flatten()
        .unwrap_or_default();
    let facts = context::host_facts()
        .with("addr", local_ip.to_string())
        .with("peer_addr", src.to_string())
        .with("iface", context::iface_facts(&iface, Some(local_ip)))
        .with("qdisc", context::egress_facts(&iface).0)
        .with("txqueuelen", context::egress_facts(&iface).1)
        .with("initiator_label", label.as_str())
        .with(
            "timestamping",
            Value::map()
                .with("kernel_rx", main.caps().kernel_rx)
                .with("kernel_tx", main.caps().kernel_tx)
                .with("recv_buf", main.caps().recv_buf)
                .with("send_buf", main.caps().send_buf),
        )
        .with("sockets", sockets_value(&socks));
    let facts = context::host_state_facts(facts, &iface, local_ip, &pt_sys::clock::pacing_check());
    let mut meta = obslog_meta(
        Role::B,
        &trace_id,
        session,
        &profile,
        &opts.tool,
        facts,
        None,
        Value::map()
            .with("udp443", u443.is_some())
            .with("control", if tcp.is_some() { "tcp" } else { "udp" })
            .with("initiator_wire_minor", hello.body.u64_or("wire_minor", 0))
            .with("test_hooks", test_hooks_value(&sock_opts())),
    );
    if let Some(Value::Map(p)) = meta.get_mut(&Key::from("pii")) {
        p.insert(Key::from("/endpoint/initiator_label"), Value::from("id"));
    }
    let (rec, rec_join) = record::start(&log, meta, Role::B)?;
    rec.event("handshake", Value::map().with("session", session));

    let shared = Shared::new(Role::B, data_cap, rate_cap);
    shared.session.store(session, Ordering::Relaxed);
    *shared.tagger.write().expect("lock") = Some(Tagger::new(&transport.handshake_hash));
    *shared.peer_ip.write().expect("lock") = Some(src.ip());
    // Over the TCP fallback `src` is the initiator's TCP source port, where it receives no
    // UDP: the UDP peer is then only learnt from authenticated probe packets that arrive
    // (docs/design/probe.md §3.1).
    if tcp.is_none() {
        *shared.ctrl_dst.write().expect("lock") = Some(src);
        shared.peer_by_sock.lock().expect("lock").insert(0, src);
    }
    let (frames_tx, frames_rx) = channel::<CtrlIn>();
    *shared.ctrl_in.lock().expect("lock") = Some(frames_tx.clone());
    let ep = Endpoint::start(shared.clone(), socks, rec.clone())?;
    let _ = ep.cmd.send(PacerCmd::SetTagger(Box::new(Tagger::new(
        &transport.handshake_hash,
    ))));
    let ctrlr = Arc::new(Controller::new(
        Role::B,
        ep.cmd.clone(),
        rate_cap,
        shared.flow_bytes.clone(),
    ));
    let wire = match tcp {
        Some(s) => {
            let reader = s.try_clone()?;
            let sh = shared.clone();
            std::thread::spawn(move || tcp_reader(reader, frames_tx, sh));
            Wire::Tcp(Arc::new(Mutex::new(s)))
        }
        None => Wire::Udp {
            cmd: ep.cmd.clone(),
            sock: 0,
        },
    };
    let c2 = ctrlr.clone();
    let ctl = Control::start(
        transport.clone(),
        wire,
        shared.clone(),
        frames_rx,
        Box::new(move |b| c2.on_feedback(b)),
        rec.clone(),
    );
    // A repeat of the handshake that opened this session means our reply was lost: resend it
    // (docs/design/probe.md §3.1).
    ctl.set_handshake_replay(noise.clone(), msg2.clone());
    // Other initiators' handshakes reaching this session's sockets are refused (§8).
    let st = state.clone();
    ctl.set_busy(Box::new(move |n| st.refuse(n)), ep.cmd.clone());
    *state.active.lock().expect("lock") = Some(Active {
        session,
        tcp_key: transport.session_key(TCP_KEY_CONTEXT),
        rec: rec.clone(),
        init: noise,
    });
    let sampler = Sampler::start(Some(iface), Some(src.ip()), rec.clone(), false);
    for c in crate::plan::control_specs(opts.main_port) {
        rec.flow(c.to_value());
        shared.flows.write().expect("lock").insert(c.id, c);
    }

    let mut reason = "bye";
    loop {
        if let Some(sig) = pt_sys::signal::stop_requested() {
            // End the session the way the initiator does on a signal (docs/design/probe.md
            // §8): record it, stop sending, tell the initiator reliably, and give it time to
            // stop its flows and say bye.
            reason = "signal";
            let name = pt_sys::signal::name(sig);
            rec.event("interrupted", Value::map().with("signal", name));
            if opts.verbose {
                eprintln!("[pathtrace] {name}: ending session {session:08x}");
            }
            let _ = ep.cmd.send(PacerCmd::StopAll);
            let abort = Value::map().with("reason", "signal").with("signal", name);
            if ctl.request("abort", abort, Duration::from_secs(5)).is_ok() {
                let _ = ctl.wait_for("bye", Duration::from_secs(10));
            }
            break;
        }
        refuse_idle(state, idle);
        let Some(env) = ctl.recv(Duration::from_millis(500)) else {
            if mono_raw().saturating_sub(shared.last_ctrl.load(Ordering::Relaxed)) > 30_000_000_000
            {
                reason = "peer_lost";
                break;
            }
            continue;
        };
        match env.kind.as_str() {
            "flows" => {
                let start_in = env.body.u64_or("start_in_ns", 50_000_000);
                let at = mono_raw() + start_in.saturating_sub(ctl.srtt().as_nanos() as u64 / 2);
                for v in env
                    .body
                    .get("flows")
                    .and_then(Value::as_array)
                    .unwrap_or(&[])
                {
                    let Some(s) = FlowSpec::from_value(v) else {
                        continue;
                    };
                    rec.flow(s.to_value());
                    shared.define_flow(s.clone());
                    if s.sender == Role::B {
                        if is_controlled(&s.pattern) {
                            ctrlr.add(s.id, at, s.duration_ns, s.max_bytes);
                        }
                        ep.start_flow(s, at);
                    }
                }
            }
            "stop" => {
                for v in env.body.get("ids").and_then(Value::as_array).unwrap_or(&[]) {
                    if let Some(id) = v.as_u64() {
                        let _ = ep.cmd.send(PacerCmd::Stop(id as u8));
                        ctrlr.remove(id as u8);
                    }
                }
            }
            "phase" => rec.event("phase_start", env.body.clone()),
            "bye" => break,
            _ => {}
        }
    }
    rec.event(
        "session_end",
        Value::map()
            .with("reason", reason)
            .with("bytes_sent", shared.bytes_sent.load(Ordering::Relaxed)),
    );
    // Let the bye acknowledgement leave before stopping the pacer.
    std::thread::sleep(Duration::from_millis(300));
    *state.active.lock().expect("lock") = None;
    sampler.stop();
    shared.stop.store(true, Ordering::Relaxed);
    ep.shutdown();
    ctl.join();
    drop(ctl);
    drop(rec);
    let _ = rec_join.join();
    state
        .finished
        .lock()
        .expect("lock")
        .insert(session, (log, token));
    Ok(Some(session))
}

/// Drain helper for tests: wait until `rx` yields or times out.
pub fn recv_timeout<T>(rx: &Receiver<T>, d: Duration) -> Option<T> {
    rx.recv_timeout(d).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn track_bounds_refuse_wrapping_ids_and_overfull_caps() {
        let p = |n: &str| Profile::by_name(n).unwrap();
        // No tracking always fits, whatever the cap.
        assert_eq!(check_track(&p("light"), 0), Ok(()));
        // deep: 150 rounds (ids 100..=249) is the bound; round 151 would reuse id 100.
        assert_eq!(check_track(&p("deep"), 600), Ok(()));
        assert_eq!(check_track(&p("deep"), 9059), Ok(()));
        assert_eq!(
            check_track(&p("deep"), 9060),
            Err("--track-secs 9060 needs more than 150 tracking rounds (one per 60 s); at most 9059 s fits".into())
        );
        assert!(
            check_track(&p("deep"), 100_000)
                .unwrap_err()
                .ends_with("at most 9059 s fits")
        );
        // light: 15.4 kB/s of background over (35 s + tracking) within 2 MB.
        assert_eq!(check_track(&p("light"), 60), Ok(()));
        assert_eq!(
            check_track(&p("light"), 600),
            Err("--track-secs 600 needs background traffic past the light profile's 2000000 B data cap; at most 94 s fits".into())
        );
        // standard: 36.4 kB/s over (106 s + tracking) within 200 MB.
        assert_eq!(check_track(&p("standard"), 5388), Ok(()));
        assert!(
            check_track(&p("standard"), 5389)
                .unwrap_err()
                .ends_with("at most 5388 s fits")
        );
        // A lowered cap lowers the bound: deep's default 600 s does not fit in 10 MB.
        let small = p("deep").with_data_cap(Some(10_000_000));
        assert!(check_track(&small, 600).is_err());
        // Every round of the longest tracking time has an id of its own, below the control flows.
        let last = ids::TRACK0 + (Profile::track_rounds(9059) - 1) as u8;
        assert_eq!(last, 249);
    }

    #[test]
    fn clock_domains_record_their_os_source() {
        let source = |v: &Value, domain: &str| {
            v.get(domain)
                .and_then(|d| d.get("source"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let linux = clocks_value_for(Role::A, "linux");
        assert_eq!(
            source(&linux, "a.mono").as_deref(),
            Some("CLOCK_MONOTONIC_RAW")
        );
        assert_eq!(source(&linux, "a.real").as_deref(), Some("CLOCK_REALTIME"));
        let darwin = clocks_value_for(Role::B, "darwin");
        assert_eq!(
            source(&darwin, "b.mono").as_deref(),
            Some("mach_absolute_time")
        );
        assert_eq!(source(&darwin, "b.real").as_deref(), Some("CLOCK_REALTIME"));
        assert_eq!(
            clocks_value(Role::A),
            clocks_value_for(Role::A, pt_sys::PLATFORM.os_family)
        );
    }

    #[test]
    fn sockets_record_whether_icmp_errors_are_observable() {
        let s =
            Arc::new(UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap());
        let caps = s.caps();
        let v = sockets_value(&[(Sock::Main, s)]);
        let row = &v.as_array().unwrap()[0];
        assert_eq!(row.get("name").and_then(Value::as_str), Some("main"));
        assert_eq!(
            row.get("icmp_errors").and_then(Value::as_bool),
            Some(caps.icmp_errors)
        );
        // IP_RECVERR on Linux; macOS has no ICMP error queue (probe.md §9.5).
        assert_eq!(caps.icmp_errors, pt_sys::PLATFORM.os_family != "darwin");
    }

    #[test]
    fn budget_reserve_covers_the_planned_time_still_to_come() {
        let p = Profile::by_name("standard").unwrap();
        let now = Instant::now();
        let mut b = Budget {
            cap: [p.data_cap; 2],
            left_s: [0.0; 2],
            bg_bps: 1000.0,
            ref_bytes: [
                crate::plan::ref_tcp_bytes(p.data_cap) + crate::plan::REF_CBR_BYTES,
                0,
            ],
            plan: p.phase_plan(0),
            cur_s: 0.0,
            rest_s: 0.0,
            phase_start: now,
            nat_end: now,
        };
        b.enter(0);
        let total = b.time_left_s();
        assert!((total - (p.planned_s(0))).abs() < 0.5, "{total}");
        b.enter(4);
        // P4, P5, P6, P7, P8 and the margin are still to come.
        let from4 = 2.0 * 11.0 + 6.0 + 3.0 * 3.5 + 35.0 + 5.0;
        assert!((b.time_left_s() - from4).abs() < 0.5);
        // P4 overran by a minute: the later phases still need their planned time.
        b.phase_start = now.checked_sub(Duration::from_secs(60)).unwrap();
        assert!((b.time_left_s() - (from4 - 11.0)).abs() < 0.5);
        // The reserve includes P8 (TCP bulk and CBR) for the sender that still has it.
        let bg = (1000.0 * b.time_left_s()) as u64;
        assert!(b.reserve(0) >= bg + 25_000_000 + crate::plan::REF_CBR_BYTES);
        assert!(b.reserve(1) <= bg + 1000);
    }

    #[test]
    fn test_hooks_are_recorded_only_when_set() {
        assert_eq!(test_hooks_value(&SockOpts::default()), Value::Null);
        let v = test_hooks_value(&SockOpts {
            recv_buf: 8192,
            ..SockOpts::default()
        });
        assert_eq!(
            v.get("PATHTRACE_RECV_BUF").and_then(Value::as_u64),
            Some(8192)
        );
        assert_eq!(v.get("PATHTRACE_TX_IDS"), Some(&Value::Null));
        let v = test_hooks_value(&SockOpts {
            force_predicted_ids: true,
            ..SockOpts::default()
        });
        assert_eq!(
            v.get("PATHTRACE_TX_IDS").and_then(Value::as_str),
            Some("predicted")
        );
    }

    #[test]
    fn fetch_routes_use_tls_when_a_cert_is_known() {
        let dst: SocketAddr = "192.0.2.1:4433".parse().unwrap();
        let r = fetch_routes(dst, &[0x30, 0x82, 0x01, 0xff]).unwrap();
        let r: Vec<(u16, bool)> = r.into_iter().map(|(p, c)| (p, c.is_some())).collect();
        assert_eq!(r, vec![(4433, true), (443, true)]);
        let r = fetch_routes(dst, &[]).unwrap();
        let r: Vec<(u16, bool)> = r.into_iter().map(|(p, c)| (p, c.is_some())).collect();
        assert_eq!(r, vec![(4433, false)]);
    }

    #[test]
    fn family_order_tries_one_address_per_family_preferred_first() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let all = [
            a("192.0.2.1:4433"),
            a("[2001:db8::1]:4433"),
            a("192.0.2.2:4433"),
            a("[2001:db8::2]:4433"),
        ];
        assert_eq!(
            family_order(&all, true),
            vec![a("[2001:db8::1]:4433"), a("192.0.2.1:4433")]
        );
        assert_eq!(
            family_order(&all, false),
            vec![a("192.0.2.1:4433"), a("[2001:db8::1]:4433")]
        );
        // One family only: that family, whatever is preferred.
        assert_eq!(family_order(&all[..1], true), vec![a("192.0.2.1:4433")]);
        assert!(family_order(&[], false).is_empty());
    }

    #[test]
    fn family_fallback_names_the_preferred_family_and_why() {
        let a = |s: &str| s.parse::<SocketAddr>().unwrap();
        let (v4, v6) = (a("192.0.2.1:4433"), a("[2001:db8::1]:4433"));
        // On the preferred family: no fallback.
        assert_eq!(family_fallback(&v6, true, &[]), None);
        assert_eq!(family_fallback(&v4, false, &[(v6, "x".into())]), None);
        // The preferred family was tried and given up: its reason.
        let why = [(v6, "no handshake reply over UDP".to_string())];
        assert_eq!(
            family_fallback(&v4, true, &why),
            Some(("ipv6", "no handshake reply over UDP".into()))
        );
        // The responder has no address of the preferred family (an IPv4 literal with
        // `--ipv6`): still a fallback, never a silent switch.
        assert_eq!(
            family_fallback(&v4, true, &[]),
            Some(("ipv6", "responder has no ipv6 address".into()))
        );
        assert_eq!(
            family_fallback(&v6, false, &[]),
            Some(("ipv4", "responder has no ipv4 address".into()))
        );
    }

    #[test]
    fn busy_refusal_is_sealed_for_authorized_initiators_only() {
        let dir = std::env::temp_dir().join(format!("pt-busy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (rk, _) = config::keygen(&dir, false).unwrap();
        let ik = config::generate_keypair();
        let pairing = config::authorize(&dir, &ik.public, "other").unwrap();
        let (_, psk) = config::parse_pairing(&pairing).unwrap();
        let state = RespState::default();
        let hello = Envelope::new("hello", Value::map());
        let (ih, m1) = noise::initiator_start(&ik, &rk.public, &psk, &hello).unwrap();
        let Some(Frame::Init { noise: n1 }) = Frame::decode(&m1) else {
            panic!()
        };
        // Without a refuser (no `serve`), nothing is answered.
        assert!(state.refuse(&n1).is_none());
        let tool = ToolInfo {
            version: "t".into(),
            git_commit: "c".into(),
            git_dirty: false,
        };
        let _ = state.refuser.set(Refuser {
            kp: rk.clone(),
            config_dir: dir.clone(),
            tool,
        });
        let reply = state.refuse(&n1).expect("authorized initiator is answered");
        let Some(Frame::Resp { session, noise: n2 }) = Frame::decode(&reply) else {
            panic!()
        };
        assert_eq!(session, 0);
        let (_, welcome) = ih.finish(&n2, session).unwrap();
        assert_eq!(welcome.body.str_or("error", ""), BUSY);
        assert_eq!(welcome.body.u64_or("wire_major", 0), WIRE_MAJOR);
        // Anti-amplification (REQ-PRB-004): no larger than three times what was received.
        assert!(
            reply.len() <= 3 * m1.len(),
            "{} vs {}",
            reply.len(),
            m1.len()
        );
        // A stranger gets no answer.
        let stranger = config::generate_keypair();
        let (_, m) = noise::initiator_start(&stranger, &rk.public, &[9; 32], &hello).unwrap();
        let Some(Frame::Init { noise: ns }) = Frame::decode(&m) else {
            panic!()
        };
        assert!(state.refuse(&ns).is_none());
        // The handshake that opened the running session is never refused.
        let (rec, _join) = record::start(&dir.join("b.ptflog"), Map::new(), Role::B).unwrap();
        *state.active.lock().unwrap() = Some(Active {
            session: 1,
            tcp_key: [0; 32],
            rec,
            init: n1.clone(),
        });
        assert!(state.other_than_active(&n1).is_none());
        assert!(state.other_than_active(&ns).is_some());
        *state.active.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_file_roundtrips_and_is_private() {
        let dir = std::env::temp_dir().join(format!("pt-sessfile-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = SessionFile::path(&dir, "trace-1");
        let f = SessionFile {
            responder: "vm".into(),
            session: 0x0abc_def1,
            token: [7u8; 32],
            cert: vec![0x30, 0x82, 0x01, 0xff],
            log_b: dir.join("trace-1.b.ptflog"),
        };
        f.write(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(SessionFile::read(&path).unwrap(), f);
        // A damaged cert line is an error, never a panic or a silently shortened cert.
        let text = std::fs::read_to_string(&path).unwrap();
        for bad in ["30820\n", "3082é1ff\n", "30zz\n"] {
            let damaged = text.replace("308201ff\n", bad);
            config::write_secret(&path, &damaged).unwrap();
            assert!(SessionFile::read(&path).is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
