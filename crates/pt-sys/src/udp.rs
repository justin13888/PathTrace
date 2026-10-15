//! UDP probe sockets: send/receive with per-packet TOS, kernel timestamps, TTL, socket drop
//! counts, and error-queue TX stamps / ICMP (R-0010, R-0011, R-0015).
//!
//! Linux batches with `sendmmsg`/`recvmmsg` and reads TX stamps and ICMP errors from the error
//! queue. macOS (probe.md §9.2 to §9.5, R-0017) sends and receives one datagram per
//! `sendmsg`/`recvmsg`, stamps arrivals with `SO_TIMESTAMP` (µs), sets `IP_DONTFRAG`/
//! `IPV6_DONTFRAG`, and has no error queue, kernel TX stamps or per-socket drop counts: its
//! sockets report `kernel_tx`, `icmp_errors` and `rxq_ovfl` false in [`TsCaps`].

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU8};
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_os = "linux")]
use crate::cvt_ssize;
use crate::{cvt, getsockopt_int, setsockopt};

/// Maximum datagram we ever receive (probe packets are ≤ path MTU; jumbo frames are out of scope).
pub const MAX_DATAGRAM: usize = 9216;
const CMSG_BUF: usize = 256;

// Values from include/uapi/linux/errqueue.h and net_tstamp.h (R-0010).
#[cfg(target_os = "linux")]
const SCM_TSTAMP_SND: u32 = 0;
#[cfg(target_os = "linux")]
const SCM_TSTAMP_SCHED: u32 = 1;
#[cfg(target_os = "linux")]
const SO_EE_ORIGIN_LOCAL: u8 = 1;
#[cfg(target_os = "linux")]
const SO_EE_ORIGIN_ICMP: u8 = 2;
#[cfg(target_os = "linux")]
const SO_EE_ORIGIN_ICMP6: u8 = 3;
#[cfg(target_os = "linux")]
const SO_EE_ORIGIN_TIMESTAMPING: u8 = 4;
#[cfg(target_os = "linux")]
const IP_PMTUDISC_PROBE: libc::c_int = 3;
#[cfg(target_os = "linux")]
const IPV6_PMTUDISC_PROBE: libc::c_int = 3;
// asm-generic/socket.h (x86_64 and aarch64 use the generic values; R-0015). Linux only: on
// macOS 32 is SO_BROADCAST and the others do not exist (R-0017).
#[cfg(target_os = "linux")]
const SO_RXQ_OVFL: libc::c_int = 40;
#[cfg(target_os = "linux")]
const SO_RCVBUFFORCE: libc::c_int = 33;
#[cfg(target_os = "linux")]
const SO_SNDBUFFORCE: libc::c_int = 32;
#[cfg(target_os = "linux")]
const SCM_TS_OPT_ID: libc::c_int = 81;
/// The smallest buffer macOS is asked for when it rejects a larger request (it refuses sizes
/// above `kern.ipc.maxsockbuf` instead of capping them).
#[cfg(target_os = "macos")]
const MIN_BUF: usize = 64 << 10;

/// How the OPT_IDs of sent datagrams are known (docs/design/probe.md §4.1, R-0015).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxIdMode {
    /// No kernel TX stamps: ids are only a local counter.
    None,
    /// Every datagram carries its id in `SCM_TS_OPT_ID` (kernel ≥ 6.13): exact.
    Explicit,
    /// The kernel assigns ids; they are predicted, and failures are assumed to consume one.
    Predicted,
}

impl TxIdMode {
    pub fn name(self) -> &'static str {
        match self {
            TxIdMode::None => "none",
            TxIdMode::Explicit => "explicit",
            TxIdMode::Predicted => "predicted",
        }
    }
    #[cfg(target_os = "linux")]
    fn code(self) -> u8 {
        match self {
            TxIdMode::None => 0,
            TxIdMode::Explicit => 1,
            TxIdMode::Predicted => 2,
        }
    }
    #[cfg(target_os = "linux")]
    fn from_code(c: u8) -> TxIdMode {
        match c {
            1 => TxIdMode::Explicit,
            2 => TxIdMode::Predicted,
            _ => TxIdMode::None,
        }
    }
}

/// Whether the running kernel accepts `SCM_TS_OPT_ID` (added in 6.13, R-0015); false on macOS.
pub fn kernel_has_ts_opt_id() -> bool {
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut it = rel
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let (major, minor) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    (major, minor) >= (6, 13)
}

/// Errors a kernel raises before the append stage, which therefore never consume an OPT_ID
/// (R-0015).
#[cfg(target_os = "linux")]
fn error_before_append(errno: i32) -> bool {
    matches!(
        errno,
        libc::ENETUNREACH | libc::EINVAL | libc::EAFNOSUPPORT | libc::EACCES | libc::EDESTADDRREQ
    )
}

/// Errors raised after the append stage (a qdisc drop with `IP_RECVERR`, a netfilter drop),
/// which consume an OPT_ID on every kernel (R-0015).
#[cfg(target_os = "linux")]
fn error_after_append(errno: i32) -> bool {
    matches!(errno, libc::ENOBUFS | libc::EPERM)
}

/// Whether a failed datagram consumed an OPT_ID in `Predicted` mode (R-0015). `error` is
/// `None` after a partial `sendmmsg`, whose errno is unknown: assumed consumed.
/// `restores_append_ids`: the kernel (≥ 6.13) returns the id on append-stage errors (EAGAIN,
/// EMSGSIZE, a pending ICMP error such as ECONNREFUSED), so only errors after the append
/// stage consume one; older kernels consume one on every error except those before append.
#[cfg(target_os = "linux")]
fn predicted_consumes(error: Option<&io::Error>, restores_append_ids: bool) -> bool {
    let Some(errno) = error.and_then(io::Error::raw_os_error) else {
        return true;
    };
    if error_before_append(errno) {
        return false;
    }
    !restores_append_ids || error_after_append(errno)
}

/// Whether the running kernel returns the OPT_ID of a datagram that fails in the append stage
/// (6.13 and later, R-0015).
#[cfg(target_os = "linux")]
fn kernel_restores_append_ids() -> bool {
    kernel_has_ts_opt_id()
}

/// Id accounting after one `sendmmsg` call (docs/design/probe.md §4.1).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IdAccount {
    /// Id of the batch's first datagram.
    first_id: u32,
    /// Id the next datagram gets.
    next_id: u32,
    burned_id: Option<u32>,
    unburned_id: Option<u32>,
    /// A burn was assumed for a datagram whose errno is unknown (partial send).
    provisional: bool,
}

/// Settle ids for a call that started at `first_id` and had `sent` datagrams accepted.
/// `provisional`: the previous call on this socket assumed a burn after a partial send. The
/// pacer retries the failed datagram alone right away, so if this call fails at once with an
/// error that consumes no id, that datagram did not consume one either: the burn is undone.
#[cfg(target_os = "linux")]
fn settle_ids(
    mode: TxIdMode,
    first_id: u32,
    sent: usize,
    failed: bool,
    error: Option<&io::Error>,
    restores_append_ids: bool,
    provisional: bool,
) -> IdAccount {
    let consumed = failed
        && match mode {
            TxIdMode::Explicit => true,
            TxIdMode::Predicted | TxIdMode::None => predicted_consumes(error, restores_append_ids),
        };
    let undo = provisional && mode != TxIdMode::Explicit && failed && sent == 0 && !consumed;
    let first_id = if undo {
        first_id.wrapping_sub(1)
    } else {
        first_id
    };
    IdAccount {
        first_id,
        next_id: first_id.wrapping_add(sent as u32 + u32::from(consumed)),
        burned_id: consumed.then(|| first_id.wrapping_add(sent as u32)),
        unburned_id: undo.then_some(first_id),
        provisional: consumed && mode != TxIdMode::Explicit && error.is_none(),
    }
}

/// Socket configuration.
#[derive(Debug, Clone, Copy)]
pub struct SockOpts {
    /// Enable kernel RX/TX software timestamps with OPT_ID + OPT_TSONLY (macOS: RX stamps with
    /// `SO_TIMESTAMP`).
    pub timestamping: bool,
    /// Set DF and ignore the cached PMTU (`IP_PMTUDISC_PROBE`), and receive ICMP errors (macOS:
    /// set DF with `IP_DONTFRAG`/`IPV6_DONTFRAG`; ICMP errors are not observable).
    pub pmtu_probe: bool,
    pub recv_buf: usize,
    pub send_buf: usize,
    /// Force `Predicted` transmit ids even where `Explicit` is available (ground-truth tests
    /// of the prediction rules, R-0015).
    pub force_predicted_ids: bool,
}

impl Default for SockOpts {
    fn default() -> Self {
        SockOpts {
            timestamping: true,
            pmtu_probe: true,
            recv_buf: 8 << 20,
            send_buf: 8 << 20,
            force_predicted_ids: false,
        }
    }
}

/// Which timestamping and drop accounting the socket actually got.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TsCaps {
    pub kernel_rx: bool,
    pub kernel_tx: bool,
    /// Effective buffer sizes (after the kernel's `rmem_max`/`wmem_max` caps).
    pub recv_buf: usize,
    pub send_buf: usize,
    /// `SO_RXQ_OVFL` is enabled: every received datagram reports the socket's drop count.
    pub rxq_ovfl: bool,
    /// ICMP errors reach the socket's error queue (`IP_RECVERR`), so the absence of an `icmp`
    /// event is evidence (PTF 1.2 `icmp_errors`; false on macOS, probe.md §9.5).
    pub icmp_errors: bool,
}

/// Result of [`UdpSock::send_batch`].
#[derive(Debug)]
pub struct SendOutcome {
    /// Datagrams the kernel accepted, from the start of the batch.
    pub sent: usize,
    /// OPT_ID of the first datagram of the batch; accepted datagram `i` has `first_id + i`.
    pub first_id: u32,
    /// The datagram at index `sent` failed (fewer than all were accepted).
    pub failed: bool,
    /// The failed datagram's error, when the kernel reported it. `sendmmsg` reports an errno
    /// only when the first datagram fails, so after a partial send it is unknown (`None`). On
    /// macOS each datagram has its own `sendmsg`, so it is always known.
    pub error: Option<io::Error>,
    /// The id the failed attempt consumed: exact in `Explicit` mode, assumed in `Predicted`
    /// mode, `None` when no id was consumed.
    pub burned_id: Option<u32>,
    /// `Predicted` mode: the id the previous call reported as `burned_id` after a partial
    /// send (errno unknown) was not consumed after all, because this call, the retry of that
    /// datagram, failed at once with an error that consumes no id. Ids are back to before
    /// that burn.
    pub unburned_id: Option<u32>,
}

impl SendOutcome {
    /// The failed datagram hit a full send buffer.
    pub fn would_block(&self) -> bool {
        self.error
            .as_ref()
            .is_some_and(|e| e.kind() == io::ErrorKind::WouldBlock)
    }
}

/// An outgoing datagram.
#[derive(Debug, Clone, Copy)]
pub struct OutMsg<'a> {
    pub dst: SocketAddr,
    pub payload: &'a [u8],
    /// Full TOS / traffic-class byte (DSCP << 2 | ECN).
    pub tos: u8,
}

/// A received datagram's metadata (payload is in the caller's buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InMsg {
    pub len: usize,
    pub src: SocketAddr,
    /// Kernel software RX timestamp, CLOCK_REALTIME ns (macOS: `SO_TIMESTAMP`, whole µs).
    pub rx_kernel: Option<u64>,
    /// The socket's cumulative drop count when this datagram was queued (`SO_RXQ_OVFL`);
    /// `None` if the option is off.
    pub rxq_drops: Option<u32>,
    /// User-space CLOCK_REALTIME right after `recvmmsg` (macOS: `recvmsg`) returned (fallback).
    pub rx_user: u64,
    pub tos: Option<u8>,
    pub ttl: Option<u8>,
    /// Datagram was truncated (larger than the buffer).
    pub truncated: bool,
}

/// Kind of a kernel TX timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    /// Taken at qdisc enqueue (`SCM_TSTAMP_SCHED`).
    Sched,
    /// Taken at the driver, after the local qdisc (`SCM_TSTAMP_SND`).
    Snd,
}

/// An entry from the socket error queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrEvent {
    TxStamp {
        id: u32,
        kind: TxKind,
        real: u64,
    },
    /// ICMP/ICMPv6 error (e.g. Packet Too Big). `payload` is the start of our quoted datagram.
    Icmp {
        errno: u32,
        icmp_type: u8,
        code: u8,
        info: u32,
        offender: Option<IpAddr>,
        payload: Vec<u8>,
    },
    /// Locally generated error (e.g. EMSGSIZE above the device MTU).
    Local {
        errno: u32,
        info: u32,
    },
}

#[derive(Debug)]
pub struct UdpSock {
    fd: OwnedFd,
    v6: bool,
    caps: TsCaps,
    /// Next OPT_ID to use (explicit) or that the kernel will assign (predicted). Only
    /// meaningful if a single thread sends on this socket (the pacer), which is how pt-probe
    /// uses it.
    next_id: AtomicU32,
    /// [`TxIdMode`] code; may fall back from explicit to predicted on the first send.
    #[cfg(target_os = "linux")]
    id_mode: AtomicU8,
    /// Whether a send has confirmed the id mode yet.
    #[cfg(target_os = "linux")]
    mode_confirmed: AtomicBool,
    /// The kernel returns ids on append-stage errors (≥ 6.13), for `Predicted` mode.
    #[cfg(target_os = "linux")]
    restores_append_ids: bool,
    /// `Predicted` mode: the last call assumed a burn after a partial send (errno unknown).
    #[cfg(target_os = "linux")]
    provisional_burn: AtomicBool,
    /// Control message type that carries an explicit id (`SCM_TS_OPT_ID`; tests replace it
    /// with an unknown type to get the EINVAL of a kernel without it).
    #[cfg(target_os = "linux")]
    opt_id_cmsg: libc::c_int,
}

pub(crate) fn sockaddr_from(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain data; all-zero is a valid (AF_UNSPEC) value.
    let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            // SAFETY: sockaddr_in is plain data; all-zero is a valid value, set below.
            let mut sin: libc::sockaddr_in = unsafe { zeroed() };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(a.ip().octets()),
            };
            #[cfg(target_os = "macos")]
            {
                sin.sin_len = size_of::<libc::sockaddr_in>() as u8;
            }
            // SAFETY: sockaddr_storage is larger than and suitably aligned for sockaddr_in.
            unsafe { std::ptr::write((&raw mut ss).cast::<libc::sockaddr_in>(), sin) };
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            // SAFETY: sockaddr_in6 is plain data; all-zero is a valid value, set below.
            let mut sin6: libc::sockaddr_in6 = unsafe { zeroed() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_flowinfo = a.flowinfo();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: a.ip().octets(),
            };
            sin6.sin6_scope_id = a.scope_id();
            #[cfg(target_os = "macos")]
            {
                sin6.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
            }
            // SAFETY: sockaddr_storage is larger than and suitably aligned for sockaddr_in6.
            unsafe { std::ptr::write((&raw mut ss).cast::<libc::sockaddr_in6>(), sin6) };
            size_of::<libc::sockaddr_in6>()
        }
    };
    (ss, len as libc::socklen_t)
}

pub(crate) fn sockaddr_to(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: family says this storage holds a sockaddr_in.
            let sin = unsafe { &*(std::ptr::from_ref(ss).cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: family says this storage holds a sockaddr_in6.
            let sin6 = unsafe { &*(std::ptr::from_ref(ss).cast::<libc::sockaddr_in6>()) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn ts_ns(ts: &libc::timespec) -> u64 {
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Iterate the cmsgs of a received `msghdr`, calling `f(level, type, data)`.
fn for_each_cmsg(msg: &libc::msghdr, mut f: impl FnMut(libc::c_int, libc::c_int, &[u8])) {
    // SAFETY: `msg` was filled by the kernel (recvmsg/recvmmsg); msg_control/msg_controllen
    // describe our own buffer, and the CMSG_* macros only walk within msg_controllen.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(msg);
        while !c.is_null() {
            let hdr = &*c;
            let data = libc::CMSG_DATA(c);
            let hdr_len = libc::CMSG_LEN(0) as usize;
            let len = (hdr.cmsg_len as usize).saturating_sub(hdr_len);
            f(
                hdr.cmsg_level,
                hdr.cmsg_type,
                std::slice::from_raw_parts(data, len),
            );
            c = libc::CMSG_NXTHDR(msg, c);
        }
    }
}

fn read_int(data: &[u8]) -> Option<i32> {
    Some(i32::from_ne_bytes(data.get(..4)?.try_into().ok()?))
}

/// A close-on-exec, non-blocking UDP socket. macOS has no `SOCK_CLOEXEC`/`SOCK_NONBLOCK`, so
/// both are set with `fcntl` before the socket is used.
#[cfg(target_os = "macos")]
fn udp_socket(domain: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) call; the returned fd is owned below.
    let raw = cvt(unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) })?;
    // SAFETY: `raw` is a fresh, valid fd we exclusively own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let f = fd.as_raw_fd();
    // SAFETY: fcntl on a valid fd with integer arguments.
    cvt(unsafe { libc::fcntl(f, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    // SAFETY: as above.
    let fl = cvt(unsafe { libc::fcntl(f, libc::F_GETFL) })?;
    // SAFETY: as above.
    cvt(unsafe { libc::fcntl(f, libc::F_SETFL, fl | libc::O_NONBLOCK) })?;
    Ok(fd)
}

/// Ask for a `size`-byte buffer with `opt`; macOS refuses a request above
/// `kern.ipc.maxsockbuf` rather than capping it, so halve the request until it is accepted or
/// reaches [`MIN_BUF`]. The effective size is read back by the caller.
#[cfg(target_os = "macos")]
fn set_buf(f: RawFd, opt: libc::c_int, size: usize) {
    let mut s = size;
    while setsockopt(f, libc::SOL_SOCKET, opt, s as libc::c_int).is_err() && s > MIN_BUF {
        s = (s / 2).max(MIN_BUF);
    }
}

impl UdpSock {
    /// Create and bind a UDP socket. IPv6 sockets are v6-only.
    #[cfg(target_os = "macos")]
    pub fn bind(addr: SocketAddr, opts: SockOpts) -> io::Result<UdpSock> {
        let v6 = addr.is_ipv6();
        let fd = udp_socket(if v6 { libc::AF_INET6 } else { libc::AF_INET })?;
        let f = fd.as_raw_fd();
        if v6 {
            setsockopt(f, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1 as libc::c_int)?;
        }
        setsockopt(f, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as libc::c_int)?;
        set_buf(f, libc::SO_RCVBUF, opts.recv_buf);
        set_buf(f, libc::SO_SNDBUF, opts.send_buf);
        if v6 {
            setsockopt(
                f,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                1 as libc::c_int,
            )?;
            setsockopt(
                f,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVHOPLIMIT,
                1 as libc::c_int,
            )?;
            if opts.pmtu_probe {
                setsockopt(f, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1 as libc::c_int)?;
            }
        } else {
            setsockopt(f, libc::IPPROTO_IP, libc::IP_RECVTOS, 1 as libc::c_int)?;
            setsockopt(f, libc::IPPROTO_IP, libc::IP_RECVTTL, 1 as libc::c_int)?;
            if opts.pmtu_probe {
                setsockopt(f, libc::IPPROTO_IP, libc::IP_DONTFRAG, 1 as libc::c_int)?;
            }
        }
        let mut caps = TsCaps::default();
        if opts.timestamping {
            caps.kernel_rx =
                setsockopt(f, libc::SOL_SOCKET, libc::SO_TIMESTAMP, 1 as libc::c_int).is_ok();
        }
        caps.recv_buf = getsockopt_int(f, libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap_or(0) as usize;
        caps.send_buf = getsockopt_int(f, libc::SOL_SOCKET, libc::SO_SNDBUF).unwrap_or(0) as usize;
        let (ss, len) = sockaddr_from(&addr);
        // SAFETY: `ss`/`len` describe a valid sockaddr for this socket's family.
        cvt(unsafe { libc::bind(f, (&raw const ss).cast(), len) })?;
        Ok(UdpSock {
            fd,
            v6,
            caps,
            next_id: AtomicU32::new(0),
        })
    }

    /// Create and bind a UDP socket. IPv6 sockets are v6-only.
    #[cfg(target_os = "linux")]
    pub fn bind(addr: SocketAddr, opts: SockOpts) -> io::Result<UdpSock> {
        let v6 = addr.is_ipv6();
        let domain = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        // SAFETY: plain socket(2) call; the returned fd is owned below.
        let raw = cvt(unsafe {
            libc::socket(
                domain,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        })?;
        // SAFETY: `raw` is a fresh, valid fd we exclusively own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let f = fd.as_raw_fd();
        if v6 {
            setsockopt(f, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 1 as libc::c_int)?;
        }
        setsockopt(f, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as libc::c_int)?;
        // The FORCE variants bypass rmem_max/wmem_max with CAP_NET_ADMIN; otherwise the kernel
        // caps the plain request. The effective sizes are read back below and recorded.
        for (force, plain, size) in [
            (SO_RCVBUFFORCE, libc::SO_RCVBUF, opts.recv_buf),
            (SO_SNDBUFFORCE, libc::SO_SNDBUF, opts.send_buf),
        ] {
            if setsockopt(f, libc::SOL_SOCKET, force, size as libc::c_int).is_err() {
                let _ = setsockopt(f, libc::SOL_SOCKET, plain, size as libc::c_int);
            }
        }
        if v6 {
            setsockopt(
                f,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVTCLASS,
                1 as libc::c_int,
            )?;
            setsockopt(
                f,
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVHOPLIMIT,
                1 as libc::c_int,
            )?;
            setsockopt(f, libc::IPPROTO_IPV6, libc::IPV6_RECVERR, 1 as libc::c_int)?;
            if opts.pmtu_probe {
                setsockopt(
                    f,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    IPV6_PMTUDISC_PROBE,
                )?;
                setsockopt(f, libc::IPPROTO_IPV6, libc::IPV6_DONTFRAG, 1 as libc::c_int)?;
            }
        } else {
            setsockopt(f, libc::IPPROTO_IP, libc::IP_RECVTOS, 1 as libc::c_int)?;
            setsockopt(f, libc::IPPROTO_IP, libc::IP_RECVTTL, 1 as libc::c_int)?;
            setsockopt(f, libc::IPPROTO_IP, libc::IP_RECVERR, 1 as libc::c_int)?;
            if opts.pmtu_probe {
                setsockopt(
                    f,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    IP_PMTUDISC_PROBE,
                )?;
            }
        }
        let mut caps = TsCaps::default();
        if opts.timestamping {
            let flags = libc::SOF_TIMESTAMPING_RX_SOFTWARE
                | libc::SOF_TIMESTAMPING_TX_SOFTWARE
                | libc::SOF_TIMESTAMPING_TX_SCHED
                | libc::SOF_TIMESTAMPING_SOFTWARE
                | libc::SOF_TIMESTAMPING_OPT_ID
                | libc::SOF_TIMESTAMPING_OPT_TSONLY;
            if setsockopt(
                f,
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMPING,
                flags as libc::c_int,
            )
            .is_ok()
            {
                caps.kernel_rx = true;
                caps.kernel_tx = true;
            } else if setsockopt(f, libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, 1 as libc::c_int)
                .is_ok()
            {
                caps.kernel_rx = true;
            }
        }
        caps.rxq_ovfl = setsockopt(f, libc::SOL_SOCKET, SO_RXQ_OVFL, 1 as libc::c_int).is_ok();
        // IP_RECVERR / IPV6_RECVERR were enabled above, or bind failed.
        caps.icmp_errors = true;
        caps.recv_buf = getsockopt_int(f, libc::SOL_SOCKET, libc::SO_RCVBUF).unwrap_or(0) as usize;
        caps.send_buf = getsockopt_int(f, libc::SOL_SOCKET, libc::SO_SNDBUF).unwrap_or(0) as usize;
        let (ss, len) = sockaddr_from(&addr);
        // SAFETY: `ss`/`len` describe a valid sockaddr for this socket's family.
        cvt(unsafe { libc::bind(f, (&raw const ss).cast(), len) })?;
        let mode = if !caps.kernel_tx {
            TxIdMode::None
        } else if kernel_has_ts_opt_id() && !opts.force_predicted_ids {
            TxIdMode::Explicit
        } else {
            TxIdMode::Predicted
        };
        Ok(UdpSock {
            fd,
            v6,
            caps,
            next_id: AtomicU32::new(0),
            id_mode: AtomicU8::new(mode.code()),
            mode_confirmed: AtomicBool::new(false),
            restores_append_ids: kernel_restores_append_ids(),
            provisional_burn: AtomicBool::new(false),
            opt_id_cmsg: SCM_TS_OPT_ID,
        })
    }

    pub fn caps(&self) -> TsCaps {
        self.caps
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        // SAFETY: zeroed sockaddr_storage is valid; getsockname writes at most `len` bytes.
        let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
        let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: valid fd and out-pointers.
        cvt(unsafe { libc::getsockname(self.fd.as_raw_fd(), (&raw mut ss).cast(), &mut len) })?;
        sockaddr_to(&ss).ok_or_else(|| io::Error::other("unknown address family"))
    }

    /// The OPT_ID that the next sent datagram will get.
    pub fn next_tx_id(&self) -> u32 {
        self.next_id.load(Ordering::Relaxed)
    }

    /// How this socket's transmit ids are known.
    #[cfg(target_os = "linux")]
    pub fn tx_id_mode(&self) -> TxIdMode {
        TxIdMode::from_code(self.id_mode.load(Ordering::Relaxed))
    }

    /// How this socket's transmit ids are known: on macOS there are no kernel TX stamps, so ids
    /// are only a local counter (probe.md §9.2).
    #[cfg(target_os = "macos")]
    pub fn tx_id_mode(&self) -> TxIdMode {
        TxIdMode::None
    }

    /// Send a batch with one `sendmsg` per datagram, each with its own TOS (probe.md §9.4).
    /// Stops at the first datagram the kernel rejects, whose error is always known; no id is
    /// burned (`TxIdMode::None`), so `burned_id` and `unburned_id` are `None`.
    #[cfg(target_os = "macos")]
    pub fn send_batch(&self, msgs: &[OutMsg<'_>]) -> SendOutcome {
        let first_id = self.next_id.load(Ordering::Relaxed);
        let mut sent = 0;
        let mut error = None;
        for m in msgs {
            match self.sendmsg(m) {
                Ok(()) => sent += 1,
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        self.next_id
            .store(first_id.wrapping_add(sent as u32), Ordering::Relaxed);
        SendOutcome {
            sent,
            first_id,
            failed: sent < msgs.len(),
            error,
            burned_id: None,
            unburned_id: None,
        }
    }

    /// One `sendmsg` call carrying the datagram's TOS / traffic class in a cmsg.
    #[cfg(target_os = "macos")]
    fn sendmsg(&self, m: &OutMsg<'_>) -> io::Result<()> {
        let (mut name, namelen) = sockaddr_from(&m.dst);
        let mut iov = libc::iovec {
            iov_base: m.payload.as_ptr() as *mut libc::c_void,
            iov_len: m.payload.len(),
        };
        // u64 words keep the cmsg header aligned.
        let mut ctrl = [0u64; CMSG_BUF / 8];
        // SAFETY: msghdr is plain data; zero is a valid initial value.
        let mut h: libc::msghdr = unsafe { zeroed() };
        h.msg_name = (&raw mut name).cast();
        h.msg_namelen = namelen;
        h.msg_iov = &raw mut iov;
        h.msg_iovlen = 1;
        h.msg_control = ctrl.as_mut_ptr().cast();
        // SAFETY: CMSG_SPACE is a pure size computation.
        h.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as _;
        let (level, ty) = if self.v6 {
            (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
        } else {
            (libc::IPPROTO_IP, libc::IP_TOS)
        };
        // SAFETY: msg_control points at a CMSG_BUF-byte buffer, larger than one CMSG_SPACE(4);
        // CMSG_FIRSTHDR is non-null for a non-zero msg_controllen.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&raw const h);
            (*c).cmsg_level = level;
            (*c).cmsg_type = ty;
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
            std::ptr::write_unaligned(
                libc::CMSG_DATA(c).cast::<libc::c_int>(),
                libc::c_int::from(m.tos),
            );
        }
        // SAFETY: `h` points at live buffers (name, iov, ctrl, the payload) that outlive the
        // call.
        let r = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &raw const h, 0) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send a batch with `sendmmsg`, one datagram per message, each with its own TOS (and, in
    /// `Explicit` mode, its own OPT_ID). Stops at the first datagram the kernel rejects; the
    /// caller decides whether to retry it or the rest (docs/design/probe.md §4.1).
    #[cfg(target_os = "linux")]
    pub fn send_batch(&self, msgs: &[OutMsg<'_>]) -> SendOutcome {
        let first_id = self.next_id.load(Ordering::Relaxed);
        if msgs.is_empty() {
            return SendOutcome {
                sent: 0,
                first_id,
                failed: false,
                error: None,
                burned_id: None,
                unburned_id: None,
            };
        }
        let mode = self.tx_id_mode();
        let r = self.sendmmsg(msgs, (mode == TxIdMode::Explicit).then_some(first_id));
        if mode == TxIdMode::Explicit && !self.mode_confirmed.swap(true, Ordering::Relaxed) {
            // A kernel without SCM_TS_OPT_ID rejects the cmsg with EINVAL before taking an
            // id (R-0015): fall back to predicted ids and resend.
            if let Err(e) = &r
                && e.raw_os_error() == Some(libc::EINVAL)
            {
                self.id_mode
                    .store(TxIdMode::Predicted.code(), Ordering::Relaxed);
                return self.send_batch(msgs);
            }
        }
        let n = msgs.len();
        let (sent, error) = match r {
            Ok(k) => (k, None),
            Err(e) => (0, Some(e)),
        };
        let failed = sent < n;
        let acct = settle_ids(
            mode,
            first_id,
            sent,
            failed,
            error.as_ref(),
            self.restores_append_ids,
            self.provisional_burn.load(Ordering::Relaxed),
        );
        self.provisional_burn
            .store(acct.provisional, Ordering::Relaxed);
        self.next_id.store(acct.next_id, Ordering::Relaxed);
        SendOutcome {
            sent,
            first_id: acct.first_id,
            failed,
            error,
            burned_id: acct.burned_id,
            unburned_id: acct.unburned_id,
        }
    }

    /// One `sendmmsg` call. `first_id`: set each datagram's OPT_ID explicitly from it.
    #[cfg(target_os = "linux")]
    fn sendmmsg(&self, msgs: &[OutMsg<'_>], first_id: Option<u32>) -> io::Result<usize> {
        let n = msgs.len();
        let mut addrs = Vec::with_capacity(n);
        let mut iovs = Vec::with_capacity(n);
        let mut ctrl = vec![[0u8; CMSG_BUF]; n];
        // SAFETY: mmsghdr is plain data; zero is a valid initial value.
        let mut hdrs: Vec<libc::mmsghdr> = (0..n).map(|_| unsafe { zeroed() }).collect();
        for m in msgs {
            addrs.push(sockaddr_from(&m.dst));
            iovs.push(libc::iovec {
                iov_base: m.payload.as_ptr() as *mut libc::c_void,
                iov_len: m.payload.len(),
            });
        }
        for i in 0..n {
            let h = &mut hdrs[i].msg_hdr;
            h.msg_name = (&raw mut addrs[i].0).cast();
            h.msg_namelen = addrs[i].1;
            h.msg_iov = &raw mut iovs[i];
            h.msg_iovlen = 1;
            h.msg_control = ctrl[i].as_mut_ptr().cast();
            // SAFETY: CMSG_SPACE is a pure size computation.
            let int_space = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
            let id_space = if first_id.is_some() {
                // SAFETY: as above.
                unsafe { libc::CMSG_SPACE(size_of::<u32>() as u32) as usize }
            } else {
                0
            };
            // `as _`: msg_controllen and cmsg_len are size_t on glibc, socklen_t on musl.
            h.msg_controllen = (int_space + id_space) as _;
            let (level, ty) = if self.v6 {
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
            } else {
                (libc::IPPROTO_IP, libc::IP_TOS)
            };
            // SAFETY: msg_control points at a CMSG_BUF-byte buffer, larger than both cmsgs
            // together (2 × CMSG_SPACE(4) = 32 bytes); CMSG_FIRSTHDR is non-null for a non-zero
            // msg_controllen, and CMSG_NXTHDR stays within msg_controllen, which covers the
            // second cmsg exactly.
            unsafe {
                let c = libc::CMSG_FIRSTHDR(h);
                (*c).cmsg_level = level;
                (*c).cmsg_type = ty;
                (*c).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as _;
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(c).cast::<libc::c_int>(),
                    libc::c_int::from(msgs[i].tos),
                );
                if let Some(id0) = first_id {
                    let c2 = libc::CMSG_NXTHDR(h, c);
                    (*c2).cmsg_level = libc::SOL_SOCKET;
                    (*c2).cmsg_type = self.opt_id_cmsg;
                    (*c2).cmsg_len = libc::CMSG_LEN(size_of::<u32>() as u32) as _;
                    std::ptr::write_unaligned(
                        libc::CMSG_DATA(c2).cast::<u32>(),
                        id0.wrapping_add(i as u32),
                    );
                }
            }
        }
        // SAFETY: every mmsghdr points at live buffers (addrs, iovs, ctrl, payloads) that outlive
        // the call; `n` matches the array length.
        let r =
            unsafe { libc::sendmmsg(self.fd.as_raw_fd(), hdrs.as_mut_ptr(), n as libc::c_uint, 0) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(r as usize)
    }

    /// Wait up to `timeout_ms` for readability or error-queue entries.
    /// Returns (readable, error_queue_pending); the latter is always false on macOS.
    pub fn poll(&self, timeout_ms: i32) -> io::Result<(bool, bool)> {
        let mut p = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        let r = unsafe { libc::poll(&mut p, 1, timeout_ms) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok((false, false));
            }
            return Err(e);
        }
        Ok(revents(&p))
    }

    /// Receive up to `bufs.len()` datagrams without blocking, one `recvmsg` each (probe.md
    /// §9.3, §9.4). Metadata is appended to `out`.
    #[cfg(target_os = "macos")]
    pub fn recv_batch(
        &self,
        bufs: &mut [[u8; MAX_DATAGRAM]],
        out: &mut Vec<InMsg>,
    ) -> io::Result<usize> {
        let mut got = 0;
        for buf in bufs.iter_mut() {
            // SAFETY: plain data, zero-initialised.
            let mut name: libc::sockaddr_storage = unsafe { zeroed() };
            let mut ctrl = [0u64; CMSG_BUF / 8];
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: MAX_DATAGRAM,
            };
            // SAFETY: plain data, zero-initialised.
            let mut h: libc::msghdr = unsafe { zeroed() };
            h.msg_name = (&raw mut name).cast();
            h.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_iov = &raw mut iov;
            h.msg_iovlen = 1;
            h.msg_control = ctrl.as_mut_ptr().cast();
            h.msg_controllen = CMSG_BUF as _;
            // SAFETY: all pointers reference live local buffers of the stated sizes.
            let r = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &raw mut h, libc::MSG_DONTWAIT) };
            let rx_user = crate::clock::realtime();
            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock || got > 0 {
                    // Like recvmmsg, report what was received; a later call sees the error.
                    return Ok(got);
                }
                return Err(e);
            }
            let mut m = InMsg {
                len: r as usize,
                src: sockaddr_to(&name).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
                rx_kernel: None,
                rxq_drops: None,
                rx_user,
                tos: None,
                ttl: None,
                truncated: h.msg_flags & libc::MSG_TRUNC != 0,
            };
            for_each_cmsg(&h, |level, ty, data| rx_cmsg(&mut m, level, ty, data));
            out.push(m);
            got += 1;
        }
        Ok(got)
    }

    /// Receive up to `bufs.len()` datagrams without blocking. Metadata is appended to `out`.
    #[cfg(target_os = "linux")]
    pub fn recv_batch(
        &self,
        bufs: &mut [[u8; MAX_DATAGRAM]],
        out: &mut Vec<InMsg>,
    ) -> io::Result<usize> {
        let n = bufs.len();
        // SAFETY: plain data, zero-initialised.
        let mut addrs: Vec<libc::sockaddr_storage> = (0..n).map(|_| unsafe { zeroed() }).collect();
        let mut ctrl = vec![[0u8; CMSG_BUF]; n];
        let mut iovs: Vec<libc::iovec> = bufs
            .iter_mut()
            .map(|b| libc::iovec {
                iov_base: b.as_mut_ptr().cast(),
                iov_len: MAX_DATAGRAM,
            })
            .collect();
        // SAFETY: plain data, zero-initialised.
        let mut hdrs: Vec<libc::mmsghdr> = (0..n).map(|_| unsafe { zeroed() }).collect();
        for i in 0..n {
            let h = &mut hdrs[i].msg_hdr;
            h.msg_name = (&raw mut addrs[i]).cast();
            h.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_iov = &raw mut iovs[i];
            h.msg_iovlen = 1;
            h.msg_control = ctrl[i].as_mut_ptr().cast();
            h.msg_controllen = CMSG_BUF as _;
        }
        // SAFETY: all pointers reference live buffers of the stated sizes.
        let r = unsafe {
            libc::recvmmsg(
                self.fd.as_raw_fd(),
                hdrs.as_mut_ptr(),
                n as libc::c_uint,
                // The flags argument is int on glibc, unsigned on musl.
                libc::MSG_DONTWAIT as _,
                std::ptr::null_mut(),
            )
        };
        let rx_user = crate::clock::realtime();
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(e);
        }
        let r = r as usize;
        for i in 0..r {
            let h = &hdrs[i].msg_hdr;
            let mut m = InMsg {
                len: hdrs[i].msg_len as usize,
                src: sockaddr_to(&addrs[i]).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
                rx_kernel: None,
                rxq_drops: self.caps.rxq_ovfl.then_some(0),
                rx_user,
                tos: None,
                ttl: None,
                truncated: h.msg_flags & libc::MSG_TRUNC != 0,
            };
            for_each_cmsg(h, |level, ty, data| match (level, ty) {
                (libc::SOL_SOCKET, libc::SO_TIMESTAMPING)
                    if data.len() >= size_of::<libc::timespec>() =>
                {
                    // SAFETY: scm_timestamping starts with timespec ts[0] (software stamp);
                    // the length was checked; read_unaligned tolerates cmsg alignment.
                    let ts: libc::timespec =
                        unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
                    if ts.tv_sec != 0 || ts.tv_nsec != 0 {
                        m.rx_kernel = Some(ts_ns(&ts));
                    }
                }
                (libc::SOL_SOCKET, libc::SO_TIMESTAMPNS)
                    if data.len() >= size_of::<libc::timespec>() =>
                {
                    // SAFETY: SCM_TIMESTAMPNS carries one timespec; length checked.
                    let ts: libc::timespec =
                        unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
                    m.rx_kernel = Some(ts_ns(&ts));
                }
                // R-0011: received IP_TOS is one byte; the others are ints.
                // R-0015: present only when the count is non-zero (0 otherwise).
                (libc::SOL_SOCKET, SO_RXQ_OVFL) => {
                    if let Some(v) = read_int(data) {
                        m.rxq_drops = Some(v as u32);
                    }
                }
                (libc::IPPROTO_IP, libc::IP_TOS) => m.tos = data.first().copied(),
                (libc::IPPROTO_IP, libc::IP_TTL) => m.ttl = read_int(data).map(|v| v as u8),
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => m.tos = read_int(data).map(|v| v as u8),
                (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => {
                    m.ttl = read_int(data).map(|v| v as u8)
                }
                _ => {}
            });
            out.push(m);
        }
        Ok(r)
    }

    /// Drain the error queue without blocking: macOS has none (probe.md §9.2, §9.5), so there
    /// is never anything to drain.
    #[cfg(target_os = "macos")]
    pub fn drain_errqueue(&self, _out: &mut Vec<ErrEvent>) -> io::Result<usize> {
        Ok(0)
    }

    /// Drain the error queue (TX timestamps, ICMP errors, local errors) without blocking.
    #[cfg(target_os = "linux")]
    pub fn drain_errqueue(&self, out: &mut Vec<ErrEvent>) -> io::Result<usize> {
        let mut count = 0;
        loop {
            let mut data = [0u8; 128];
            let mut ctrl = [0u8; 512];
            let mut iov = libc::iovec {
                iov_base: data.as_mut_ptr().cast(),
                iov_len: data.len(),
            };
            // SAFETY: zeroed msghdr/sockaddr_storage are valid initial values.
            let mut name: libc::sockaddr_storage = unsafe { zeroed() };
            // SAFETY: as above.
            let mut h: libc::msghdr = unsafe { zeroed() };
            h.msg_name = (&raw mut name).cast();
            h.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_iov = &raw mut iov;
            h.msg_iovlen = 1;
            h.msg_control = ctrl.as_mut_ptr().cast();
            h.msg_controllen = ctrl.len() as _;
            // SAFETY: all pointers reference live local buffers of the stated sizes.
            let r = unsafe {
                libc::recvmsg(
                    self.fd.as_raw_fd(),
                    &mut h,
                    libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
                )
            };
            let len = match cvt_ssize(r) {
                Ok(l) => l,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(count),
                Err(e) => return Err(e),
            };
            let mut stamp: Option<u64> = None;
            let mut ee: Option<(libc::sock_extended_err, Option<IpAddr>)> = None;
            for_each_cmsg(&h, |level, ty, d| match (level, ty) {
                (libc::SOL_SOCKET, libc::SO_TIMESTAMPING)
                    if d.len() >= size_of::<libc::timespec>() =>
                {
                    // SAFETY: ts[0] of scm_timestamping; length checked.
                    let ts: libc::timespec = unsafe { std::ptr::read_unaligned(d.as_ptr().cast()) };
                    stamp = Some(ts_ns(&ts));
                }
                (libc::IPPROTO_IP, libc::IP_RECVERR) | (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
                    if d.len() >= size_of::<libc::sock_extended_err>() =>
                {
                    // SAFETY: the cmsg holds a sock_extended_err followed by the offender
                    // sockaddr (SO_EE_OFFENDER); lengths checked before each read.
                    let e: libc::sock_extended_err =
                        unsafe { std::ptr::read_unaligned(d.as_ptr().cast()) };
                    let off = &d[size_of::<libc::sock_extended_err>()..];
                    let offender = if off.len() >= size_of::<libc::sockaddr_in6>()
                        || off.len() >= size_of::<libc::sockaddr_in>()
                    {
                        // SAFETY: zeroed storage, then copy at most its size from the cmsg.
                        let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
                        let k = off.len().min(size_of::<libc::sockaddr_storage>());
                        // SAFETY: k bytes fit in both buffers.
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                off.as_ptr(),
                                (&raw mut ss).cast::<u8>(),
                                k,
                            )
                        };
                        sockaddr_to(&ss).map(|a| a.ip())
                    } else {
                        None
                    };
                    ee = Some((e, offender));
                }
                _ => {}
            });
            count += 1;
            let Some((e, offender)) = ee else { continue };
            match e.ee_origin {
                SO_EE_ORIGIN_TIMESTAMPING => {
                    let kind = match e.ee_info {
                        SCM_TSTAMP_SND => TxKind::Snd,
                        SCM_TSTAMP_SCHED => TxKind::Sched,
                        _ => continue,
                    };
                    if let Some(real) = stamp {
                        out.push(ErrEvent::TxStamp {
                            id: e.ee_data,
                            kind,
                            real,
                        });
                    }
                }
                SO_EE_ORIGIN_ICMP | SO_EE_ORIGIN_ICMP6 => out.push(ErrEvent::Icmp {
                    errno: e.ee_errno,
                    icmp_type: e.ee_type,
                    code: e.ee_code,
                    info: e.ee_info,
                    offender,
                    payload: data[..len.min(data.len())].to_vec(),
                }),
                SO_EE_ORIGIN_LOCAL => out.push(ErrEvent::Local {
                    errno: e.ee_errno,
                    info: e.ee_info,
                }),
                _ => {}
            }
        }
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Poll several sockets at once. Returns (readable, error-queue pending) per socket; the latter
/// is always false on macOS.
pub fn poll_many(socks: &[&UdpSock], timeout_ms: i32) -> io::Result<Vec<(bool, bool)>> {
    let mut fds: Vec<libc::pollfd> = socks
        .iter()
        .map(|s| libc::pollfd {
            fd: s.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    // SAFETY: `fds` is a valid array of `fds.len()` pollfd structs.
    let r = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(vec![(false, false); socks.len()]);
        }
        return Err(e);
    }
    Ok(fds.iter().map(revents).collect())
}

/// (readable, error-queue pending) of a polled socket. macOS has no error queue, so `POLLERR`
/// there means a pending socket error, which the next send or receive reports.
fn revents(p: &libc::pollfd) -> (bool, bool) {
    (
        p.revents & libc::POLLIN != 0,
        cfg!(target_os = "linux") && p.revents & libc::POLLERR != 0,
    )
}

/// Record one cmsg of a received datagram (macOS, probe.md §9.3): `SO_TIMESTAMP` is a
/// `struct timeval` in CLOCK_REALTIME; the received TOS and TTL are one byte each under their
/// `IP_RECV*` types; IPv6 traffic class and hop limit are ints.
#[cfg(target_os = "macos")]
fn rx_cmsg(m: &mut InMsg, level: libc::c_int, ty: libc::c_int, data: &[u8]) {
    match (level, ty) {
        (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) if data.len() >= size_of::<libc::timeval>() => {
            // SAFETY: SCM_TIMESTAMP carries one timeval; length checked; read_unaligned
            // tolerates cmsg alignment.
            let tv: libc::timeval = unsafe { std::ptr::read_unaligned(data.as_ptr().cast()) };
            m.rx_kernel = Some(tv.tv_sec as u64 * 1_000_000_000 + tv.tv_usec as u64 * 1_000);
        }
        (libc::IPPROTO_IP, libc::IP_RECVTOS) => m.tos = data.first().copied(),
        (libc::IPPROTO_IP, libc::IP_RECVTTL) => m.ttl = data.first().copied(),
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) => m.tos = read_int(data).map(|v| v as u8),
        (libc::IPPROTO_IPV6, libc::IPV6_HOPLIMIT) => m.ttl = read_int(data).map(|v| v as u8),
        _ => {}
    }
}

impl AsRawFd for UdpSock {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn loopback_tos_ttl_and_timestamps() {
        let a = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let b = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        assert!(b.caps().icmp_errors, "IP_RECVERR: {:?}", b.caps());
        let dst = b.local_addr().unwrap();
        let payload = [7u8; 100];
        let msgs: Vec<OutMsg<'_>> = (0..4u8)
            .map(|i| OutMsg {
                dst,
                payload: &payload,
                tos: (34 << 2) | i,
            })
            .collect();
        let o = a.send_batch(&msgs);
        assert_eq!((o.sent, o.failed, o.first_id), (4, false, 0));
        assert_eq!(a.next_tx_id(), 4);
        let mut bufs = vec![[0u8; MAX_DATAGRAM]; 8];
        let mut got = Vec::new();
        for _ in 0..100 {
            b.poll(10).unwrap();
            b.recv_batch(&mut bufs, &mut got).unwrap();
            if got.len() >= 4 {
                break;
            }
        }
        assert_eq!(got.len(), 4);
        for (i, m) in got.iter().enumerate() {
            assert_eq!(m.len, 100);
            assert_eq!(m.tos, Some((34 << 2) | i as u8));
            assert!(m.ttl.is_some());
        }
        // The kernel enables RX timestamping lazily (deferred static-key work after the first
        // socket asks for it), so the very first packets after bind may arrive unstamped; the
        // probe records those with rx_src = user. Stamps must appear within a short warm-up.
        let mut stamped = got.iter().any(|m| m.rx_kernel.is_some());
        for _ in 0..50 {
            if stamped {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            assert_eq!(a.send_batch(&msgs[..1]).sent, 1);
            let mut more = Vec::new();
            b.poll(50).unwrap();
            b.recv_batch(&mut bufs, &mut more).unwrap();
            stamped = more.iter().any(|m| m.rx_kernel.is_some());
        }
        assert!(
            stamped,
            "kernel RX stamps expected on loopback after warm-up"
        );
        let mut errs = Vec::new();
        for _ in 0..50 {
            a.poll(10).unwrap();
            a.drain_errqueue(&mut errs).unwrap();
            if errs.len() >= 8 {
                break;
            }
        }
        let ids: Vec<u32> = errs
            .iter()
            .filter_map(|e| match e {
                ErrEvent::TxStamp { id, .. } => Some(*id),
                _ => None,
            })
            .collect();
        assert!(ids.contains(&0) && ids.contains(&3), "{errs:?}");
    }

    #[cfg(target_os = "linux")]
    fn drain_stamp_ids(s: &UdpSock, want: usize) -> Vec<u32> {
        let mut errs = Vec::new();
        for _ in 0..50 {
            s.poll(10).unwrap();
            s.drain_errqueue(&mut errs).unwrap();
            if errs.len() >= want {
                break;
            }
        }
        errs.iter()
            .filter_map(|e| match e {
                ErrEvent::TxStamp { id, .. } => Some(*id),
                _ => None,
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_sends_burn_ids_and_stamps_stay_aligned() {
        let a = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let b = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let dst = b.local_addr().unwrap();
        let ok = [1u8; 100];
        let big = vec![2u8; 70_000]; // > 65535: EMSGSIZE
        let m = |p: &'static [u8]| OutMsg {
            dst,
            payload: p,
            tos: 0,
        };
        let big: &'static [u8] = Box::leak(big.into_boxed_slice());
        let ok: &'static [u8] = Box::leak(Box::new(ok));
        let batch = [m(ok), m(big), m(ok)];
        // sendmmsg stops at the oversized datagram without reporting its errno.
        let o = a.send_batch(&batch);
        assert_eq!((o.sent, o.failed, o.first_id), (1, true, 0));
        assert!(o.error.is_none());
        // Retried alone, the failure and its errno become visible.
        let o = a.send_batch(&batch[1..]);
        assert_eq!(o.sent, 0);
        assert_eq!(
            o.error.as_ref().and_then(io::Error::raw_os_error),
            Some(libc::EMSGSIZE)
        );
        let o = a.send_batch(&batch[2..]);
        assert_eq!(o.sent, 1);
        if a.tx_id_mode() != TxIdMode::Explicit {
            return; // predicted ids on old kernels are checked by the merge (probe.md §4.1)
        }
        // Explicit ids: each failed attempt burned its own id; stamps carry the ids we set.
        let ids = drain_stamp_ids(&a, 4);
        let last = o.first_id;
        assert!(
            ids.contains(&0) && ids.contains(&last),
            "{ids:?} last {last}"
        );
        assert!(ids.iter().all(|i| *i == 0 || *i == last), "{ids:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn predicted_consumption_rules() {
        let e = io::Error::from_raw_os_error;
        for restores in [false, true] {
            // A partial send's errno is unknown: assumed consumed.
            assert!(predicted_consumes(None, restores));
            for n in [
                libc::ENETUNREACH,
                libc::EINVAL,
                libc::EAFNOSUPPORT,
                libc::EACCES,
                libc::EDESTADDRREQ,
            ] {
                assert!(!predicted_consumes(Some(&e(n)), restores), "{n} {restores}");
            }
            for n in [libc::ENOBUFS, libc::EPERM] {
                assert!(predicted_consumes(Some(&e(n)), restores), "{n} {restores}");
            }
        }
        // Append-stage errors consume an id before 6.13 only.
        for n in [libc::EAGAIN, libc::EMSGSIZE, libc::ECONNREFUSED] {
            assert!(predicted_consumes(Some(&e(n)), false), "{n}");
            assert!(!predicted_consumes(Some(&e(n)), true), "{n}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn partial_send_burn_is_undone_by_a_retry_that_consumes_nothing() {
        use TxIdMode::{Explicit, Predicted};
        let e = io::Error::from_raw_os_error;
        let acct = |first_id, next_id, burned_id, unburned_id, provisional| IdAccount {
            first_id,
            next_id,
            burned_id,
            unburned_id,
            provisional,
        };
        // 3 of 5 accepted, errno unknown: id 13 assumed burned, provisionally.
        assert_eq!(
            settle_ids(Predicted, 10, 3, true, None, false, false),
            acct(10, 14, Some(13), None, true)
        );
        // The retry fails at once before the append stage: the burn is undone.
        let enet = e(libc::ENETUNREACH);
        assert_eq!(
            settle_ids(Predicted, 14, 0, true, Some(&enet), false, true),
            acct(13, 13, None, Some(13), false)
        );
        // The retry fails with an error that consumes an id: both burns stand.
        let nobufs = e(libc::ENOBUFS);
        assert_eq!(
            settle_ids(Predicted, 14, 0, true, Some(&nobufs), false, true),
            acct(14, 15, Some(14), None, false)
        );
        // The retry succeeds: the burn stands.
        assert_eq!(
            settle_ids(Predicted, 14, 1, false, None, false, true),
            acct(14, 15, None, None, false)
        );
        // EAGAIN consumes nothing from 6.13 on, so it undoes the burn there only.
        let eagain = e(libc::EAGAIN);
        assert_eq!(
            settle_ids(Predicted, 14, 0, true, Some(&eagain), true, true).unburned_id,
            Some(13)
        );
        assert_eq!(
            settle_ids(Predicted, 14, 0, true, Some(&eagain), false, true),
            acct(14, 15, Some(14), None, false)
        );
        // Explicit ids: every failed attempt burns its own id, nothing is provisional.
        assert_eq!(
            settle_ids(Explicit, 10, 3, true, None, true, false),
            acct(10, 14, Some(13), None, false)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forced_predicted_ids_match_the_kernel_after_partial_send_and_retry() {
        let a = UdpSock::bind(
            "127.0.0.1:0".parse().unwrap(),
            SockOpts {
                force_predicted_ids: true,
                ..SockOpts::default()
            },
        )
        .unwrap();
        if a.tx_id_mode() != TxIdMode::Predicted || !a.restores_append_ids {
            // Below 6.13 the oversized datagram's EMSGSIZE (an early length check that
            // consumes no id) cannot be told from an append-stage EMSGSIZE (which does); the
            // rules are covered by `predicted_consumption_rules`.
            return;
        }
        let b = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let dst = b.local_addr().unwrap();
        let ok: &'static [u8] = Box::leak(Box::new([1u8; 100]));
        let big: &'static [u8] = Box::leak(vec![2u8; 70_000].into_boxed_slice());
        let m = |p: &'static [u8]| OutMsg {
            dst,
            payload: p,
            tos: 0,
        };
        let batch = [m(ok), m(big), m(ok)];
        let o = a.send_batch(&batch);
        assert_eq!((o.sent, o.burned_id), (1, Some(1)));
        // The retry reveals EMSGSIZE, which consumes no id on 6.13+: the burn is undone.
        let o = a.send_batch(&batch[1..]);
        assert_eq!(o.sent, 0);
        assert_eq!((o.burned_id, o.unburned_id), (None, Some(1)));
        let o = a.send_batch(&batch[2..]);
        assert_eq!((o.sent, o.first_id), (1, 1));
        let mut ids = drain_stamp_ids(&a, 4);
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids, vec![0, 1], "kernel ids must match the predicted ones");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explicit_ids_fall_back_to_predicted_on_einval() {
        let mut a = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        if !a.caps().kernel_tx {
            return;
        }
        // An unknown SOL_SOCKET cmsg gets the EINVAL a kernel without SCM_TS_OPT_ID returns.
        a.opt_id_cmsg = 0x7fff;
        a.id_mode
            .store(TxIdMode::Explicit.code(), Ordering::Relaxed);
        let b = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let dst = b.local_addr().unwrap();
        let p = [5u8; 100];
        let msgs = [
            OutMsg {
                dst,
                payload: &p,
                tos: 0,
            },
            OutMsg {
                dst,
                payload: &p,
                tos: 0,
            },
        ];
        let o = a.send_batch(&msgs);
        assert_eq!((o.sent, o.failed, o.first_id), (2, false, 0));
        assert_eq!(a.tx_id_mode(), TxIdMode::Predicted);
        let mut ids = drain_stamp_ids(&a, 4);
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids, vec![0, 1]);
    }

    /// probe.md §9.3: every datagram carries the `SO_TIMESTAMP` cmsg, and its time lies
    /// between a CLOCK_REALTIME read before the send and one after the receive.
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_loopback_tos_ttl_and_timestamps() {
        for (bind, v6) in [("127.0.0.1:0", false), ("[::1]:0", true)] {
            let a = UdpSock::bind(bind.parse().unwrap(), SockOpts::default()).unwrap();
            let b = UdpSock::bind(bind.parse().unwrap(), SockOpts::default()).unwrap();
            let caps = b.caps();
            assert!(caps.kernel_rx && !caps.kernel_tx, "{caps:?}");
            assert!(!caps.rxq_ovfl && !caps.icmp_errors, "{caps:?}");
            assert!(caps.recv_buf > 0 && caps.send_buf > 0, "{caps:?}");
            assert_eq!((a.tx_id_mode(), a.is_v6()), (TxIdMode::None, v6));
            let dst = b.local_addr().unwrap();
            let payload = [7u8; 100];
            let msgs: Vec<OutMsg<'_>> = (0..4u8)
                .map(|i| OutMsg {
                    dst,
                    payload: &payload,
                    tos: (34 << 2) | i,
                })
                .collect();
            let before = crate::clock::realtime();
            let o = a.send_batch(&msgs);
            assert_eq!((o.sent, o.failed, o.first_id), (4, false, 0));
            assert_eq!(a.next_tx_id(), 4);
            let mut bufs = vec![[0u8; MAX_DATAGRAM]; 8];
            let mut got = Vec::new();
            for _ in 0..100 {
                b.poll(10).unwrap();
                b.recv_batch(&mut bufs, &mut got).unwrap();
                if got.len() >= 4 {
                    break;
                }
            }
            let after = crate::clock::realtime();
            assert_eq!(got.len(), 4);
            for (i, m) in got.iter().enumerate() {
                assert_eq!((m.len, m.src), (100, a.local_addr().unwrap()));
                assert_eq!(m.tos, Some((34 << 2) | i as u8), "v6 {v6}");
                assert!(m.ttl.is_some_and(|t| t > 0), "v6 {v6}");
                let rx = m.rx_kernel.expect("SO_TIMESTAMP on every datagram");
                // The stamp is whole µs, truncated.
                assert_eq!(rx % 1_000, 0);
                assert!(
                    rx >= before / 1_000 * 1_000 && rx <= after,
                    "{before} {rx} {after}"
                );
                assert!(m.rx_user >= rx && m.rxq_drops.is_none() && !m.truncated);
            }
            let mut errs = Vec::new();
            assert_eq!(a.drain_errqueue(&mut errs).unwrap(), 0);
            assert!(!a.poll(0).unwrap().1, "no error queue");
        }
    }

    /// A failed `sendmsg` stops the batch with its errno known and burns no id (probe.md §9.4).
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_failed_send_reports_its_errno() {
        let a = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let b = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let dst = b.local_addr().unwrap();
        let ok = [1u8; 100];
        let big = vec![2u8; 70_000]; // > 65535: EMSGSIZE
        let batch = [
            OutMsg {
                dst,
                payload: &ok,
                tos: 0,
            },
            OutMsg {
                dst,
                payload: &big,
                tos: 0,
            },
            OutMsg {
                dst,
                payload: &ok,
                tos: 0,
            },
        ];
        let o = a.send_batch(&batch);
        assert_eq!((o.sent, o.failed, o.first_id), (1, true, 0));
        assert_eq!(
            o.error.as_ref().and_then(io::Error::raw_os_error),
            Some(libc::EMSGSIZE)
        );
        assert_eq!((o.burned_id, o.unburned_id), (None, None));
        let o = a.send_batch(&batch[2..]);
        assert_eq!((o.sent, o.failed, o.first_id), (1, false, 1));
        assert!(a.send_batch(&[]).sent == 0 && a.next_tx_id() == 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_drops_are_reported_per_datagram() {
        let a = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let b = UdpSock::bind(
            "127.0.0.1:0".parse().unwrap(),
            SockOpts {
                recv_buf: 1,
                ..SockOpts::default()
            },
        )
        .unwrap();
        assert!(b.caps().rxq_ovfl);
        let dst = b.local_addr().unwrap();
        let payload = [3u8; 1000];
        let msgs = vec![
            OutMsg {
                dst,
                payload: &payload,
                tos: 0,
            };
            32
        ];
        let mut sent = 0;
        for _ in 0..8 {
            sent += a.send_batch(&msgs).sent;
        }
        let mut bufs = vec![[0u8; MAX_DATAGRAM]; 32];
        let mut got = Vec::new();
        while b.recv_batch(&mut bufs, &mut got).unwrap() > 0 {}
        assert!(
            !got.is_empty() && got.len() < sent,
            "{} of {sent}",
            got.len()
        );
        // The count is read when a datagram is queued, so the next datagram queued after the
        // burst reports every drop of the burst (loopback loses nothing else).
        assert_eq!(a.send_batch(&msgs[..1]).sent, 1);
        let mut late = Vec::new();
        for _ in 0..50 {
            b.poll(10).unwrap();
            if b.recv_batch(&mut bufs, &mut late).unwrap() > 0 {
                break;
            }
        }
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].rxq_drops, Some((sent - got.len()) as u32));
        let drops: Vec<u32> = got.iter().map(|m| m.rxq_drops.unwrap()).collect();
        assert!(
            drops.windows(2).all(|w| w[0] <= w[1]),
            "cumulative: {drops:?}"
        );
    }
}
