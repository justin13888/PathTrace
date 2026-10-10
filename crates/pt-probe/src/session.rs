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
use crate::flows::{FlowSpec, Pattern, Role, Sock, Tos};
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

fn clocks_value(role: Role) -> Value {
    let r = role.name();
    Value::map()
        .with(
            &format!("{r}.mono"),
            Value::map()
                .with("kind", "monotonic_raw")
                .with("endpoint", r),
        )
        .with(
            &format!("{r}.real"),
            Value::map().with("kind", "realtime").with("endpoint", r),
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
                .with("t0_real", p.real),
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
    /// Override the deep profile's tracking time.
    pub track_s: Option<u64>,
    /// Print progress lines to stderr.
    pub verbose: bool,
}

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub trace_id: String,
    pub session: u32,
    pub log_a: PathBuf,
    pub log_b: Option<PathBuf>,
    pub notes: Vec<String>,
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
}

impl Ctx {
    fn say(&self, s: &str) {
        if self.verbose {
            eprintln!("[pathtrace] {s}");
        }
    }

    fn phase(&self, id: u16, name: &str) {
        self.say(&format!("phase P{id} {name}"));
        let body = Value::map().with("phase", id).with("name", name);
        self.rec.event("phase_start", body.clone());
        self.ctl.send(&Envelope::new("phase", body));
    }

    fn start(&mut self, specs: Vec<FlowSpec>, delay_ms: u64) -> bool {
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
            self.ep
                .shared
                .flows
                .write()
                .expect("lock")
                .insert(s.id, s.clone());
            if s.sender == Role::A {
                if is_controlled(&s.pattern) {
                    self.ctrlr.add(s.id);
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

    fn sleep(&self, s: f64) {
        std::thread::sleep(Duration::from_secs_f64(s));
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

    fn heavy(&mut self, id: u8, sender: Role, phase: u16, dur_s: f64) -> FlowSpec {
        self.mk(
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
        )
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
    let kp: Keypair = config::load_keypair(&opts.config_dir)?;
    let (dst, all) = resolve(&opts.responder.addr, opts.prefer_v6)?;
    let v6 = dst.is_ipv6();
    let sopts = SockOpts::default();
    let main = Arc::new(bind_any(v6, 0, sopts)?);
    let local_ip = pt_sys::netif::local_addr_for(dst)?;
    let iface = pt_sys::netif::iface_with_addr(local_ip)?.unwrap_or_default();
    let iface_info = pt_sys::netif::iface_info(&iface);
    let mtu = iface_info.mtu.unwrap_or(1500).min(1500);
    let metered = context::metered(&iface);
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
    let mut tcp_ctrl: Option<TcpStream> = None;
    let mut notes = Vec::new();
    let (session, noise2) = match handshake_udp(&main, dst, &init, opts.verbose) {
        Some(r) => r,
        None => {
            if opts.verbose {
                eprintln!("[pathtrace] no UDP handshake reply; trying TCP fallback");
            }
            let (s, sess, n) = handshake_tcp(dst.ip(), &init).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("responder {dst} unreachable over UDP 4433 and TCP 443/4433"),
                )
            })?;
            notes.push("UDP control blocked; session ran over TCP fallback (UDP classes recorded as blocked)".into());
            tcp_ctrl = Some(s);
            (sess, n)
        }
    };
    let (transport, welcome) = ih.finish(&noise2, session)?;
    let wb = &welcome.body;
    let peer_major = wb.u64_or("wire_major", 0);
    if peer_major != WIRE_MAJOR {
        return Err(io::Error::other(format!(
            "wire protocol mismatch: initiator v{WIRE_MAJOR}, responder v{peer_major}; upgrade the older side"
        )));
    }
    if let Some(err) = wb.get("error").and_then(Value::as_str) {
        return Err(io::Error::other(format!(
            "responder refused the session: {err}"
        )));
    }
    let transport = Arc::new(transport);
    let cert = match wb.get("tls_cert") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Vec::new(),
    };

    // Observation log.
    std::fs::create_dir_all(&opts.out_dir)?;
    let log_a = opts.out_dir.join(format!("{trace_id}.a.ptflog"));
    let facts = context::host_facts()
        .with("addr", local_ip.to_string())
        .with("peer_addr", dst.to_string())
        .with("iface", context::iface_facts(&iface))
        .with("metered", metered.as_str())
        .with(
            "timestamping",
            Value::map()
                .with("kernel_rx", main.caps().kernel_rx)
                .with("kernel_tx", main.caps().kernel_tx)
                .with("recv_buf", main.caps().recv_buf)
                .with("send_buf", main.caps().send_buf),
        );
    let extra = Value::map()
        .with(
            "responder",
            Value::map()
                .with("name", opts.responder.name.as_str())
                .with("facts", wb.get("facts").cloned().unwrap_or(Value::Null)),
        )
        .with(
            "all_addrs",
            Value::Array(all.iter().map(|a| Value::from(a.to_string())).collect()),
        )
        .with("control", if tcp_ctrl.is_some() { "tcp" } else { "udp" });
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
    rec.event(
        "handshake",
        Value::map()
            .with("session", session)
            .with("control", if tcp_ctrl.is_some() { "tcp" } else { "udp" }),
    );

    // Endpoint.
    let shared = Shared::new(Role::A, opts.profile.data_cap, opts.rate_cap_bps);
    shared.session.store(session, Ordering::Relaxed);
    *shared.tagger.write().expect("lock") = Some(Tagger::new(&transport.handshake_hash));
    *shared.peer_ip.write().expect("lock") = Some(dst.ip());
    *shared.ctrl_dst.write().expect("lock") = Some(dst);
    let (frames_tx, frames_rx) = channel::<CtrlIn>();
    *shared.ctrl_in.lock().expect("lock") = Some(frames_tx.clone());
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
    let ep = Endpoint::start(shared.clone(), socks, rec.clone())?;
    let _ = ep.cmd.send(PacerCmd::SetTagger(Box::new(Tagger::new(
        &transport.handshake_hash,
    ))));
    let ctrlr = Arc::new(Controller::new(Role::A, ep.cmd.clone(), opts.rate_cap_bps));
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
    let sampler = Sampler::start(Some(iface.clone()), rec.clone(), true);

    let mut ctx = Ctx {
        ep,
        ctl,
        ctrlr,
        rec: rec.clone(),
        main_port: dst.port(),
        mtu,
        verbose: opts.verbose,
        notes,
    };
    let started = Instant::now();
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
    if el < max_nat {
        ctx.say(&format!(
            "waiting {:.0} s for NAT binding probes",
            max_nat - el
        ));
        ctx.sleep(max_nat - el);
    }
    ctx.phase(9, "end");
    ctx.stop(&[ids::LIGHT_A, ids::LIGHT_B, ids::TRAIN_A, ids::TRAIN_B]);
    let _ = ctx.ep.cmd.send(PacerCmd::StopAll);
    ctx.sleep(1.0);
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
    let log_b = opts.out_dir.join(format!("{trace_id}.b.ptflog"));
    let token = transport.session_key(FETCH_KEY_CONTEXT);
    let fetched = fetch_with_retry(dst.ip(), &cert, session, &token, &log_b, opts.verbose);
    if let Err(e) = &fetched {
        notes.push(format!(
            "could not fetch responder log yet ({e}); later run: pathtrace fetch --responder {} --session {session:08x} --token {} --out {}",
            opts.responder.name,
            config::hex(&token),
            log_b.display()
        ));
    }
    Ok(ProbeOutcome {
        trace_id,
        session,
        log_a,
        log_b: fetched.ok().map(|_| log_b),
        notes,
    })
}

pub fn fetch_with_retry(
    ip: IpAddr,
    cert: &[u8],
    session: u32,
    token: &[u8; 32],
    out: &Path,
    verbose: bool,
) -> io::Result<u64> {
    let mut last = io::Error::other("no attempt");
    for attempt in 0..10 {
        for (port, tls) in [(4433u16, false), (443, true)] {
            let cfg = if tls && !cert.is_empty() {
                tcp::client_config(cert).ok()
            } else {
                None
            };
            if tls && cfg.is_none() {
                continue;
            }
            match tcp::fetch(
                SocketAddr::new(ip, port),
                cfg,
                session,
                token,
                out,
                Duration::from_secs(5),
            ) {
                Ok(n) => return Ok(n),
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
    ctx.phase(0, "background");
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

    // P1 reachability: UDP classes (echoed) and TCP classes.
    ctx.phase(1, "reachability");
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
    let udp443_ok = ctx
        .ep
        .shared
        .fb
        .lock()
        .expect("lock")
        .contains_key(&ids::CLASS_443);
    let quic_ok = ctx
        .ep
        .shared
        .fb
        .lock()
        .expect("lock")
        .contains_key(&ids::CLASS_QUIC);
    ctx.rec.event(
        "udp_reachability",
        Value::map().with("udp443", udp443_ok).with("quic", quic_ok),
    );

    ctx.phase(2, "quiet");
    ctx.sleep(p.quiet_s);

    if p.chirp_s > 0.0 {
        ctx.phase(3, "chirps");
        let a = ctx.mk(
            ids::CHIRP_A,
            "chirp",
            Role::A,
            Sock::Main,
            mtu,
            Pattern::Chirp {
                count: 20,
                gap0_ns: 1_000_000,
                factor: 0.85,
                period_ns: 500_000_000,
            },
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
            Pattern::Chirp {
                count: 20,
                gap0_ns: 1_000_000,
                factor: 0.85,
                period_ns: 500_000_000,
            },
            3,
            p.chirp_s,
        );
        ctx.start(vec![b], 250);
        ctx.sleep(p.chirp_s + 0.5);
    }

    if p.sat_s > 0.0 {
        ctx.phase(4, "saturate a_to_b");
        let s = ctx.heavy(ids::HEAVY_A, Role::A, 4, p.sat_s);
        ctx.start(vec![s], 50);
        ctx.sleep(p.sat_s + 1.0);
        ctx.phase(5, "saturate b_to_a");
        let s = ctx.heavy(ids::HEAVY_B, Role::B, 5, p.sat_s);
        ctx.start(vec![s], 50);
        ctx.sleep(p.sat_s + 1.0);
    }
    if p.both_s > 0.0 {
        ctx.phase(6, "saturate both");
        let a = ctx.heavy(ids::BOTH_A, Role::A, 6, p.both_s);
        let b = ctx.heavy(ids::BOTH_B, Role::B, 6, p.both_s);
        ctx.start(vec![a, b], 50);
        ctx.sleep(p.both_s + 1.0);
    }
    if p.class_sat_s > 0.0 {
        ctx.phase(7, "class differential");
        for (id, sock, quic, class, ok) in [
            (ids::CSAT_MAIN, Sock::Main, false, "udp/high-port", true),
            (ids::CSAT_443, Sock::Udp443, false, "udp/443", udp443_ok),
            (ids::CSAT_QUIC, Sock::Udp443, true, "udp/443-quic", quic_ok),
        ] {
            if !ok {
                ctx.rec.event(
                    "class_skipped",
                    Value::map()
                        .with("class", class)
                        .with("reason", "unreachable in P1"),
                );
                continue;
            }
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
            ctx.start(vec![s], 50);
            ctx.sleep(p.class_sat_s + 0.5);
        }
    }
    if p.refs {
        ctx.phase(8, "reference flows");
        let budget = p
            .data_cap
            .saturating_sub(ctx.ep.shared.bytes_sent.load(Ordering::Relaxed));
        let bulk = (budget / 4).min(100_000_000);
        let dur = if p.name == "smoke" { 2.0 } else { 5.0 };
        let addr443 = SocketAddr::new(dst.ip(), 443);
        for (id, kind) in [
            (ids::TCP_BULK_UP, Kind::Upload),
            (ids::TCP_BULK_DOWN, Kind::Download),
        ] {
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
        for (id, sender) in [(ids::CBR_A, Role::A), (ids::CBR_B, Role::B)] {
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
    }
    let track = opts.track_s.unwrap_or(p.track_s);
    if track > 0 {
        ctx.phase(10, "tracking");
        let rounds = track / 60;
        for i in 0..rounds {
            ctx.sleep(57.0);
            let sender = if i % 2 == 0 { Role::A } else { Role::B };
            let id = ids::TRACK0.saturating_add((i % 150) as u8);
            let s = ctx.heavy(id, sender, 10, 3.0);
            ctx.start(vec![s], 50);
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
}

#[derive(Default)]
struct RespState {
    active: Mutex<Option<Active>>,
    /// Finished sessions: id → (log path, fetch token).
    finished: Mutex<HashMap<u32, (PathBuf, [u8; 32])>>,
    control_tcp: Mutex<Option<Sender<TcpStream>>>,
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
                    if s.read_exact(&mut m).is_ok()
                        && let Some(tx) = state.control_tcp.lock().expect("lock").as_ref()
                    {
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

    let sopts = SockOpts::default();
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
        match responder_session(opts, &kp, &state, &cert, main, u443, &data, src, tcp) {
            Ok(Some(id)) => {
                done += 1;
                if opts.verbose {
                    eprintln!("[pathtrace] session {id:08x} complete");
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("[pathtrace] session error: {e}"),
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
    let local_ip = pt_sys::netif::local_addr_for(src).unwrap_or(src.ip());
    let iface = pt_sys::netif::iface_with_addr(local_ip)
        .ok()
        .flatten()
        .unwrap_or_default();
    let facts = context::host_facts()
        .with("addr", local_ip.to_string())
        .with("peer_addr", src.to_string())
        .with("iface", context::iface_facts(&iface))
        .with("initiator_label", label.as_str())
        .with(
            "timestamping",
            Value::map()
                .with("kernel_rx", main.caps().kernel_rx)
                .with("kernel_tx", main.caps().kernel_tx)
                .with("recv_buf", main.caps().recv_buf)
                .with("send_buf", main.caps().send_buf),
        );
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
            .with("control", if tcp.is_some() { "tcp" } else { "udp" }),
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
    *shared.ctrl_dst.write().expect("lock") = Some(src);
    shared.peer_by_sock.lock().expect("lock").insert(0, src);
    let (frames_tx, frames_rx) = channel::<CtrlIn>();
    *shared.ctrl_in.lock().expect("lock") = Some(frames_tx.clone());
    let mut socks: Vec<(Sock, Arc<UdpSock>)> = vec![(Sock::Main, main.clone())];
    if let Some(u) = &u443 {
        socks.push((Sock::Udp443, u.clone()));
    }
    let ep = Endpoint::start(shared.clone(), socks, rec.clone())?;
    let _ = ep.cmd.send(PacerCmd::SetTagger(Box::new(Tagger::new(
        &transport.handshake_hash,
    ))));
    let ctrlr = Arc::new(Controller::new(Role::B, ep.cmd.clone(), rate_cap));
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
    *state.active.lock().expect("lock") = Some(Active {
        session,
        tcp_key: transport.session_key(TCP_KEY_CONTEXT),
        rec: rec.clone(),
    });
    let sampler = Sampler::start(Some(iface), rec.clone(), false);

    let mut reason = "bye";
    loop {
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
                    shared.flows.write().expect("lock").insert(s.id, s.clone());
                    if s.sender == Role::B {
                        if is_controlled(&s.pattern) {
                            ctrlr.add(s.id);
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
    let token = transport.session_key(FETCH_KEY_CONTEXT);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join("fetch_token"))?;
        f.write_all(config::hex(&token).as_bytes())?;
    }
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
