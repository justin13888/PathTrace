//! UDP probe sockets: batched send/receive with per-packet TOS, kernel timestamps, TTL, socket
//! drop counts, and error-queue TX stamps / ICMP (R-0010, R-0011, R-0015).

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use crate::{cvt, cvt_ssize, getsockopt_int, setsockopt};

/// Maximum datagram we ever receive (probe packets are ≤ path MTU; jumbo frames are out of scope).
pub const MAX_DATAGRAM: usize = 9216;
const CMSG_BUF: usize = 256;

// Values from include/uapi/linux/errqueue.h and net_tstamp.h (R-0010).
const SCM_TSTAMP_SND: u32 = 0;
const SCM_TSTAMP_SCHED: u32 = 1;
const SO_EE_ORIGIN_LOCAL: u8 = 1;
const SO_EE_ORIGIN_ICMP: u8 = 2;
const SO_EE_ORIGIN_ICMP6: u8 = 3;
const SO_EE_ORIGIN_TIMESTAMPING: u8 = 4;
const IP_PMTUDISC_PROBE: libc::c_int = 3;
const IPV6_PMTUDISC_PROBE: libc::c_int = 3;
// asm-generic/socket.h (x86_64 and aarch64 use the generic values; R-0015).
const SO_RXQ_OVFL: libc::c_int = 40;
const SO_RCVBUFFORCE: libc::c_int = 33;
const SO_SNDBUFFORCE: libc::c_int = 32;
const SCM_TS_OPT_ID: libc::c_int = 81;

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
    fn code(self) -> u8 {
        match self {
            TxIdMode::None => 0,
            TxIdMode::Explicit => 1,
            TxIdMode::Predicted => 2,
        }
    }
    fn from_code(c: u8) -> TxIdMode {
        match c {
            1 => TxIdMode::Explicit,
            2 => TxIdMode::Predicted,
            _ => TxIdMode::None,
        }
    }
}

/// Whether the running kernel accepts `SCM_TS_OPT_ID` (added in 6.13, R-0015).
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
/// (R-0015). Every other send error is assumed to consume one in `Predicted` mode.
fn error_before_append(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::ENETUNREACH
                | libc::EINVAL
                | libc::EAFNOSUPPORT
                | libc::EACCES
                | libc::EDESTADDRREQ
        )
    )
}

/// Socket configuration.
#[derive(Debug, Clone, Copy)]
pub struct SockOpts {
    /// Enable kernel RX/TX software timestamps with OPT_ID + OPT_TSONLY.
    pub timestamping: bool,
    /// Set DF and ignore the cached PMTU (`IP_PMTUDISC_PROBE`), and receive ICMP errors.
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
    /// only when the first datagram fails, so after a partial send it is unknown (`None`).
    pub error: Option<io::Error>,
    /// The id the failed attempt consumed: exact in `Explicit` mode, assumed in `Predicted`
    /// mode, `None` when no id was consumed.
    pub burned_id: Option<u32>,
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
    /// Kernel software RX timestamp, CLOCK_REALTIME ns.
    pub rx_kernel: Option<u64>,
    /// The socket's cumulative drop count when this datagram was queued (`SO_RXQ_OVFL`);
    /// `None` if the option is off.
    pub rxq_drops: Option<u32>,
    /// User-space CLOCK_REALTIME right after `recvmmsg` returned (fallback).
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
    id_mode: AtomicU8,
    /// Whether a send has confirmed the id mode yet.
    mode_confirmed: AtomicBool,
}

pub(crate) fn sockaddr_from(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: sockaddr_storage is plain data; all-zero is a valid (AF_UNSPEC) value.
    let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: a.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is larger than and suitably aligned for sockaddr_in.
            unsafe { std::ptr::write((&raw mut ss).cast::<libc::sockaddr_in>(), sin) };
            size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: a.port().to_be(),
                sin6_flowinfo: a.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: a.ip().octets(),
                },
                sin6_scope_id: a.scope_id(),
            };
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

impl UdpSock {
    /// Create and bind a UDP socket. IPv6 sockets are v6-only.
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
    pub fn tx_id_mode(&self) -> TxIdMode {
        TxIdMode::from_code(self.id_mode.load(Ordering::Relaxed))
    }

    /// Send a batch with `sendmmsg`, one datagram per message, each with its own TOS (and, in
    /// `Explicit` mode, its own OPT_ID). Stops at the first datagram the kernel rejects; the
    /// caller decides whether to retry it or the rest (docs/design/probe.md §4.1).
    pub fn send_batch(&self, msgs: &[OutMsg<'_>]) -> SendOutcome {
        let first_id = self.next_id.load(Ordering::Relaxed);
        if msgs.is_empty() {
            return SendOutcome {
                sent: 0,
                first_id,
                failed: false,
                error: None,
                burned_id: None,
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
        let consumed = failed
            && match mode {
                TxIdMode::Explicit => true,
                TxIdMode::Predicted | TxIdMode::None => {
                    !error.as_ref().is_some_and(error_before_append)
                }
            };
        let burned_id = consumed.then(|| first_id.wrapping_add(sent as u32));
        self.next_id.store(
            first_id.wrapping_add(sent as u32 + u32::from(consumed)),
            Ordering::Relaxed,
        );
        SendOutcome {
            sent,
            first_id,
            failed,
            error,
            burned_id,
        }
    }

    /// One `sendmmsg` call. `first_id`: set each datagram's OPT_ID explicitly from it.
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
                    (*c2).cmsg_type = SCM_TS_OPT_ID;
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
    /// Returns (readable, error_queue_pending).
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
        Ok((
            p.revents & libc::POLLIN != 0,
            p.revents & libc::POLLERR != 0,
        ))
    }

    /// Receive up to `bufs.len()` datagrams without blocking. Metadata is appended to `out`.
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

    /// Drain the error queue (TX timestamps, ICMP errors, local errors) without blocking.
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

/// Poll several sockets at once. Returns (readable, error-queue pending) per socket.
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
    Ok(fds
        .iter()
        .map(|p| {
            (
                p.revents & libc::POLLIN != 0,
                p.revents & libc::POLLERR != 0,
            )
        })
        .collect())
}

impl AsRawFd for UdpSock {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_tos_ttl_and_timestamps() {
        let a = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
        let b = UdpSock::bind("127.0.0.1:0".parse().unwrap(), SockOpts::default()).unwrap();
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
