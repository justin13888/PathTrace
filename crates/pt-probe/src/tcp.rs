//! TCP class probes and reference flows (REQ-PRB-012, REQ-PRB-015, REQ-PRB-024).
//!
//! Every connection starts with a 64-byte authenticated header (docs/design/probe.md §6) so
//! the responder only serves its active session. Port 443 is wrapped in real TLS 1.3 with the
//! responder's self-signed certificate pinned through the Noise-authenticated control channel.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use pt_sys::clock::mono_raw;
use pt_sys::tcp::TCP_INFO_FIELDS;

use crate::record::{APP_EVENTS, Recorder};

pub const MAGIC: &[u8; 4] = b"PTT1";
pub const HEADER_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Handshake only: server answers one byte.
    Probe = 0,
    /// Client sends `bytes` (or for `duration`), server counts.
    Upload = 1,
    /// Server sends for `duration` (≤ `bytes`).
    Download = 2,
    /// `bytes` = request count; `param` = request size << 32 | response size.
    ReqResp = 3,
    /// Fetch the responder's observation log for `session`.
    Fetch = 4,
}

impl Kind {
    fn from_u8(v: u8) -> Option<Kind> {
        Some(match v {
            0 => Kind::Probe,
            1 => Kind::Upload,
            2 => Kind::Download,
            3 => Kind::ReqResp,
            4 => Kind::Fetch,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnHeader {
    pub session: u32,
    pub flow: u8,
    pub kind: Kind,
    pub bytes: u64,
    pub duration_ns: u64,
    pub param: u64,
}

impl ConnHeader {
    pub fn encode(&self, key: &[u8; 32]) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[..4].copy_from_slice(MAGIC);
        b[4..8].copy_from_slice(&self.session.to_le_bytes());
        b[8] = self.flow;
        b[9] = self.kind as u8;
        b[12..20].copy_from_slice(&self.bytes.to_le_bytes());
        b[20..28].copy_from_slice(&self.duration_ns.to_le_bytes());
        b[28..36].copy_from_slice(&self.param.to_le_bytes());
        let tag = blake3::keyed_hash(key, &b[..36]);
        b[36..].copy_from_slice(&tag.as_bytes()[..28]);
        b
    }

    /// Parse without verifying (to find the session), then verify with [`ConnHeader::verify`].
    pub fn peek(b: &[u8; HEADER_LEN]) -> Option<ConnHeader> {
        if &b[..4] != MAGIC {
            return None;
        }
        let u64_at = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().expect("8"));
        Some(ConnHeader {
            session: u32::from_le_bytes(b[4..8].try_into().expect("4")),
            flow: b[8],
            kind: Kind::from_u8(b[9])?,
            bytes: u64_at(12),
            duration_ns: u64_at(20),
            param: u64_at(28),
        })
    }

    pub fn verify(b: &[u8; HEADER_LEN], key: &[u8; 32]) -> bool {
        let tag = blake3::keyed_hash(key, &b[..36]);
        tag.as_bytes()[..28] == b[36..]
    }
}

pub fn app_event(name: &str) -> i64 {
    APP_EVENTS
        .iter()
        .position(|e| *e == name)
        .map_or(-1, |i| i as i64)
}

/// Log an application event row.
pub fn log_app(rec: &Recorder, flow: u8, event: &str, bytes: u64, value: i64) {
    rec.row(
        "app",
        vec![
            Some(i64::from(flow)),
            Some(mono_raw() as i64),
            Some(app_event(event)),
            Some(bytes as i64),
            Some(value),
        ],
    );
}

/// Sample TCP_INFO every 10 ms until `done` (REQ-PRB-012).
pub fn spawn_sampler(
    fd: i32,
    flow: u8,
    rec: Recorder,
    done: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut rows = Vec::new();
        while !done.load(Ordering::Relaxed) {
            if let Ok(info) = pt_sys::tcp::tcp_info(fd) {
                let mut row = vec![
                    Some(i64::from(flow)),
                    Some(mono_raw() as i64),
                    Some(info.len as i64),
                ];
                for (_, off, size) in TCP_INFO_FIELDS {
                    row.push(info.field(*off, *size).map(|v| v as i64));
                }
                rows.push(row);
            }
            if rows.len() >= 100 {
                rec.rows("tcpinfo", std::mem::take(&mut rows));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        rec.rows("tcpinfo", rows);
    })
}

// ------------------------------------------------------------------- TLS

/// Load or create the responder's self-signed certificate (DER cert, DER PKCS#8 key).
pub fn load_or_create_cert(state_dir: &Path) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let (cp, kp) = (
        state_dir.join("tls-cert.der"),
        state_dir.join("tls-key.der"),
    );
    if cp.exists() && kp.exists() {
        return Ok((
            std::fs::read(cp)?,
            crate::config::read_private(&kp)
                .map(|_| ())
                .and_then(|()| std::fs::read(&kp))?,
        ));
    }
    std::fs::create_dir_all(state_dir)?;
    let ck = rcgen::generate_simple_self_signed(vec!["pathtrace-responder".into()])
        .map_err(io::Error::other)?;
    let cert = ck.cert.der().to_vec();
    let key = ck.signing_key.serialize_der();
    std::fs::write(&cp, &cert)?;
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&kp)?;
        f.write_all(&key)?;
    }
    Ok((cert, key))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn server_config(cert: &[u8], key: &[u8]) -> io::Result<Arc<rustls::ServerConfig>> {
    let cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert.to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key.to_vec(),
            )),
        )
        .map_err(io::Error::other)?;
    Ok(Arc::new(cfg))
}

/// Accepts exactly one certificate (pinned DER), regardless of name or CA.
#[derive(Debug)]
struct Pinned {
    der: Vec<u8>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.der.as_slice() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "certificate does not match the pinned responder certificate".into(),
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

pub fn client_config(pinned_der: &[u8]) -> io::Result<Arc<rustls::ClientConfig>> {
    let p = provider();
    let algs = p.signature_verification_algorithms;
    let cfg = rustls::ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            der: pinned_der.to_vec(),
            algs,
        }))
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// A client or server stream, TLS or plain.
pub enum Stream {
    Plain(TcpStream),
    TlsClient(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    TlsServer(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl std::fmt::Debug for Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Stream::Plain(_) => "Stream::Plain",
            Stream::TlsClient(_) => "Stream::TlsClient",
            Stream::TlsServer(_) => "Stream::TlsServer",
        })
    }
}

impl Stream {
    pub fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            Stream::TlsClient(s) => &s.sock,
            Stream::TlsServer(s) => &s.sock,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::TlsClient(s) => s.read(buf),
            Stream::TlsServer(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::TlsClient(s) => s.write(buf),
            Stream::TlsServer(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::TlsClient(s) => s.flush(),
            Stream::TlsServer(s) => s.flush(),
        }
    }
}

// ----------------------------------------------------------------- client

/// Result of a client-side TCP action.
#[derive(Debug, Clone, Default)]
pub struct ClientResult {
    pub connect_ns: u64,
    pub tls_ns: Option<u64>,
    pub bytes: u64,
    pub elapsed_ns: u64,
    pub cc: String,
    pub error: Option<String>,
}

/// Run one client connection: connect (optionally TLS), send the header, perform `kind`.
pub fn client(
    addr: SocketAddr,
    tls: Option<Arc<rustls::ClientConfig>>,
    hdr: ConnHeader,
    key: &[u8; 32],
    rec: &Recorder,
    tos: u8,
    timeout: Duration,
) -> ClientResult {
    let mut res = ClientResult::default();
    match client_inner(addr, tls, hdr, key, rec, tos, timeout, &mut res) {
        Ok(()) => {}
        Err(e) => {
            log_app(rec, hdr.flow, "error", res.bytes, 0);
            res.error = Some(e.to_string());
        }
    }
    res
}

#[allow(clippy::too_many_arguments)]
fn client_inner(
    addr: SocketAddr,
    tls: Option<Arc<rustls::ClientConfig>>,
    hdr: ConnHeader,
    key: &[u8; 32],
    rec: &Recorder,
    tos: u8,
    timeout: Duration,
    res: &mut ClientResult,
) -> io::Result<()> {
    log_app(rec, hdr.flow, "connect_start", 0, 0);
    let t0 = mono_raw();
    let s = TcpStream::connect_timeout(&addr, timeout)?;
    res.connect_ns = mono_raw() - t0;
    log_app(rec, hdr.flow, "connected", 0, res.connect_ns as i64);
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let _ = pt_sys::tcp::set_nodelay(s.as_raw_fd());
    let _ = pt_sys::tcp::set_tos(s.as_raw_fd(), addr.is_ipv6(), tos);
    res.cc = pt_sys::tcp::congestion(s.as_raw_fd()).unwrap_or_default();
    let mut stream = match tls {
        Some(cfg) => {
            let name =
                rustls::pki_types::ServerName::try_from("pathtrace-responder").expect("valid name");
            let conn = rustls::ClientConnection::new(cfg, name).map_err(io::Error::other)?;
            let mut st = rustls::StreamOwned::new(conn, s);
            let t1 = mono_raw();
            while st.conn.is_handshaking() {
                st.conn.complete_io(&mut st.sock)?;
            }
            let tls_ns = mono_raw() - t1;
            res.tls_ns = Some(tls_ns);
            log_app(rec, hdr.flow, "tls_done", 0, tls_ns as i64);
            Stream::TlsClient(Box::new(st))
        }
        None => Stream::Plain(s),
    };
    stream.write_all(&hdr.encode(key))?;
    stream.flush()?;
    let done = Arc::new(AtomicBool::new(false));
    let sampler = (hdr.kind != Kind::Probe && hdr.kind != Kind::Fetch).then(|| {
        spawn_sampler(
            stream.tcp().as_raw_fd(),
            hdr.flow,
            rec.clone(),
            done.clone(),
        )
    });
    let start = Instant::now();
    let deadline = Duration::from_nanos(hdr.duration_ns.max(1));
    let r: io::Result<()> = (|| {
        match hdr.kind {
            Kind::Probe => {
                let mut b = [0u8; 1];
                stream.read_exact(&mut b)?;
                log_app(rec, hdr.flow, "done", 0, 0);
            }
            Kind::Upload => {
                let buf = vec![0x5au8; 64 * 1024];
                let mut last = Instant::now();
                while res.bytes < hdr.bytes && start.elapsed() < deadline {
                    let n = ((hdr.bytes - res.bytes) as usize).min(buf.len());
                    stream.write_all(&buf[..n])?;
                    res.bytes += n as u64;
                    if last.elapsed() >= Duration::from_millis(100) {
                        log_app(rec, hdr.flow, "progress", res.bytes, 0);
                        last = Instant::now();
                    }
                }
                stream.flush()?;
                let _ = stream.tcp().shutdown(std::net::Shutdown::Write);
                let mut ack = [0u8; 8];
                stream.read_exact(&mut ack)?;
                log_app(rec, hdr.flow, "done", u64::from_le_bytes(ack), 0);
            }
            Kind::Download => {
                let mut buf = vec![0u8; 64 * 1024];
                let mut last = Instant::now();
                let mut first = true;
                loop {
                    let n = stream.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    if first {
                        log_app(rec, hdr.flow, "first_byte", 0, 0);
                        first = false;
                    }
                    res.bytes += n as u64;
                    if last.elapsed() >= Duration::from_millis(100) {
                        log_app(rec, hdr.flow, "progress", res.bytes, 0);
                        last = Instant::now();
                    }
                }
                log_app(rec, hdr.flow, "done", res.bytes, 0);
            }
            Kind::ReqResp => {
                let (req, resp) = (
                    (hdr.param >> 32) as usize,
                    (hdr.param & 0xffff_ffff) as usize,
                );
                let reqbuf = vec![0x42u8; req];
                let mut respbuf = vec![0u8; resp];
                for i in 0..hdr.bytes {
                    if start.elapsed() >= deadline {
                        break;
                    }
                    log_app(rec, hdr.flow, "req_start", res.bytes, i as i64);
                    stream.write_all(&reqbuf)?;
                    stream.flush()?;
                    stream.read_exact(&mut respbuf)?;
                    res.bytes += (req + resp) as u64;
                    log_app(rec, hdr.flow, "resp_done", res.bytes, i as i64);
                }
                log_app(rec, hdr.flow, "done", res.bytes, 0);
            }
            Kind::Fetch => unreachable!("use fetch()"),
        }
        Ok(())
    })();
    done.store(true, Ordering::Relaxed);
    if let Some(h) = sampler {
        let _ = h.join();
    }
    res.elapsed_ns = start.elapsed().as_nanos() as u64;
    r
}

/// Download the responder's observation log for a finished session.
pub fn fetch(
    addr: SocketAddr,
    tls: Option<Arc<rustls::ClientConfig>>,
    session: u32,
    token: &[u8; 32],
    out: &Path,
    timeout: Duration,
) -> io::Result<u64> {
    let s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut stream = match tls {
        Some(cfg) => {
            let name =
                rustls::pki_types::ServerName::try_from("pathtrace-responder").expect("valid name");
            let conn = rustls::ClientConnection::new(cfg, name).map_err(io::Error::other)?;
            Stream::TlsClient(Box::new(rustls::StreamOwned::new(conn, s)))
        }
        None => Stream::Plain(s),
    };
    let hdr = ConnHeader {
        session,
        flow: 0,
        kind: Kind::Fetch,
        bytes: 0,
        duration_ns: 0,
        param: 0,
    };
    stream.write_all(&hdr.encode(token))?;
    stream.flush()?;
    let mut len = [0u8; 8];
    stream.read_exact(&mut len)?;
    let len = u64::from_le_bytes(len);
    if len == u64::MAX {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "responder has no log for this session",
        ));
    }
    let tmp = out.with_extension("part");
    let mut f = std::fs::File::create(&tmp)?;
    let copied = io::copy(&mut (&mut stream).take(len), &mut f)?;
    if copied != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("received {copied} of {len} bytes"),
        ));
    }
    f.sync_all()?;
    std::fs::rename(&tmp, out)?;
    Ok(len)
}

// ----------------------------------------------------------------- server

/// What the server needs from the responder's session state.
pub trait ServerCtx: Send + Sync {
    /// Key for headers of `session` (active session key, or a stored fetch token for Kind::Fetch).
    fn key(&self, session: u32, kind: Kind) -> Option<[u8; 32]>;
    /// Recorder of the active session, if `session` is active.
    fn recorder(&self, session: u32) -> Option<Recorder>;
    /// Path of a finished session's log (fetch).
    fn log_path(&self, session: u32) -> Option<std::path::PathBuf>;
    /// Record the SYN as seen by the responder.
    fn saved_syn(&self, session: u32, flow: u8, port: u16, syn: Vec<u8>);
}

/// Serve one accepted connection.
pub fn serve_conn(
    s: TcpStream,
    tls: Option<Arc<rustls::ServerConfig>>,
    ctx: &dyn ServerCtx,
    port: u16,
    syn: Option<Vec<u8>>,
) -> io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(15)))?;
    s.set_write_timeout(Some(Duration::from_secs(15)))?;
    let _ = pt_sys::tcp::set_nodelay(s.as_raw_fd());
    let mut stream = match tls {
        Some(cfg) => {
            let conn = rustls::ServerConnection::new(cfg).map_err(io::Error::other)?;
            Stream::TlsServer(Box::new(rustls::StreamOwned::new(conn, s)))
        }
        None => Stream::Plain(s),
    };
    let mut hb = [0u8; HEADER_LEN];
    stream.read_exact(&mut hb)?;
    let hdr = ConnHeader::peek(&hb)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad header"))?;
    let key = ctx
        .key(hdr.session, hdr.kind)
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "unknown session"))?;
    if !ConnHeader::verify(&hb, &key) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bad header tag",
        ));
    }
    if hdr.kind == Kind::Fetch {
        let Some(path) = ctx.log_path(hdr.session) else {
            stream.write_all(&u64::MAX.to_le_bytes())?;
            return Ok(());
        };
        let mut f = std::fs::File::open(path)?;
        let len = f.metadata()?.len();
        stream.write_all(&len.to_le_bytes())?;
        io::copy(&mut f, &mut stream)?;
        stream.flush()?;
        return Ok(());
    }
    let rec = ctx
        .recorder(hdr.session)
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "session not active"))?;
    if let Some(syn) = syn {
        ctx.saved_syn(hdr.session, hdr.flow, port, syn);
    }
    let done = Arc::new(AtomicBool::new(false));
    let sampler = (hdr.kind != Kind::Probe).then(|| {
        spawn_sampler(
            stream.tcp().as_raw_fd(),
            hdr.flow,
            rec.clone(),
            done.clone(),
        )
    });
    let start = Instant::now();
    let limit = Duration::from_nanos(hdr.duration_ns.clamp(1, 60_000_000_000));
    let r: io::Result<()> = (|| {
        match hdr.kind {
            Kind::Probe => {
                stream.write_all(&[1])?;
                stream.flush()?;
            }
            Kind::Upload => {
                let mut buf = vec![0u8; 64 * 1024];
                let mut total = 0u64;
                let mut first = true;
                let mut last = Instant::now();
                loop {
                    let n = stream.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    if first {
                        log_app(&rec, hdr.flow, "first_byte", 0, 0);
                        first = false;
                    }
                    total += n as u64;
                    if last.elapsed() >= Duration::from_millis(100) {
                        log_app(&rec, hdr.flow, "progress", total, 0);
                        last = Instant::now();
                    }
                }
                log_app(&rec, hdr.flow, "done", total, 0);
                stream.write_all(&total.to_le_bytes())?;
                stream.flush()?;
            }
            Kind::Download => {
                let buf = vec![0xa5u8; 64 * 1024];
                let mut sent = 0u64;
                let mut last = Instant::now();
                while sent < hdr.bytes && start.elapsed() < limit {
                    let n = ((hdr.bytes - sent) as usize).min(buf.len());
                    stream.write_all(&buf[..n])?;
                    sent += n as u64;
                    if last.elapsed() >= Duration::from_millis(100) {
                        log_app(&rec, hdr.flow, "progress", sent, 0);
                        last = Instant::now();
                    }
                }
                stream.flush()?;
                log_app(&rec, hdr.flow, "done", sent, 0);
            }
            Kind::ReqResp => {
                let (req, resp) = (
                    (hdr.param >> 32) as usize,
                    (hdr.param & 0xffff_ffff) as usize,
                );
                if req > 1 << 20 || resp > 1 << 20 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "request/response too large",
                    ));
                }
                let mut reqbuf = vec![0u8; req];
                let respbuf = vec![0x24u8; resp];
                for i in 0..hdr.bytes {
                    if stream.read_exact(&mut reqbuf).is_err() {
                        break;
                    }
                    stream.write_all(&respbuf)?;
                    stream.flush()?;
                    if i % 50 == 0 {
                        log_app(
                            &rec,
                            hdr.flow,
                            "progress",
                            (i + 1) * (req + resp) as u64,
                            i as i64,
                        );
                    }
                }
                log_app(&rec, hdr.flow, "done", 0, 0);
            }
            Kind::Fetch => {}
        }
        Ok(())
    })();
    done.store(true, Ordering::Relaxed);
    if let Some(h) = sampler {
        let _ = h.join();
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_auth() {
        let k = [3u8; 32];
        let h = ConnHeader {
            session: 5,
            flow: 9,
            kind: Kind::ReqResp,
            bytes: 200,
            duration_ns: 5_000_000_000,
            param: (1024 << 32) | 1024,
        };
        let b = h.encode(&k);
        assert_eq!(ConnHeader::peek(&b), Some(h));
        assert!(ConnHeader::verify(&b, &k));
        assert!(!ConnHeader::verify(&b, &[4u8; 32]));
    }

    #[test]
    fn tls_pinning() {
        let dir = std::env::temp_dir().join(format!("pt-tls-{}", std::process::id()));
        let (cert, key) = load_or_create_cert(&dir).unwrap();
        let scfg = server_config(&cert, &key).unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let th = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let conn = rustls::ServerConnection::new(scfg).unwrap();
            let mut st = rustls::StreamOwned::new(conn, s);
            let mut b = [0u8; 4];
            st.read_exact(&mut b).unwrap();
            b
        });
        let ccfg = client_config(&cert).unwrap();
        let s = TcpStream::connect(addr).unwrap();
        let conn = rustls::ClientConnection::new(
            ccfg,
            rustls::pki_types::ServerName::try_from("pathtrace-responder").unwrap(),
        )
        .unwrap();
        let mut st = rustls::StreamOwned::new(conn, s);
        st.write_all(b"ping").unwrap();
        st.flush().unwrap();
        assert_eq!(&th.join().unwrap(), b"ping");
        // A different pinned certificate must fail the handshake.
        let other = rcgen::generate_simple_self_signed(vec!["x".into()])
            .unwrap()
            .cert
            .der()
            .to_vec();
        let ccfg = client_config(&other).unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let scfg = server_config(&cert, &key).unwrap();
        std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let conn = rustls::ServerConnection::new(scfg).unwrap();
            let mut st = rustls::StreamOwned::new(conn, s);
            let mut b = [0u8; 1];
            let _ = st.read(&mut b);
        });
        let s = TcpStream::connect(addr).unwrap();
        let conn = rustls::ClientConnection::new(
            ccfg,
            rustls::pki_types::ServerName::try_from("pathtrace-responder").unwrap(),
        )
        .unwrap();
        let mut st = rustls::StreamOwned::new(conn, s);
        assert!(
            st.write_all(b"x")
                .and_then(|()| st.flush())
                .and_then(|()| {
                    let mut b = [0u8; 1];
                    st.read(&mut b).map(|_| ())
                })
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
