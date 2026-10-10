//! UDP probe sockets: batched send/receive with per-packet TOS, kernel timestamps, TTL, and
//! error-queue TX stamps / ICMP (R-0010, R-0011).

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};

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

/// Socket configuration.
#[derive(Debug, Clone, Copy)]
pub struct SockOpts {
    /// Enable kernel RX/TX software timestamps with OPT_ID + OPT_TSONLY.
    pub timestamping: bool,
    /// Set DF and ignore the cached PMTU (`IP_PMTUDISC_PROBE`), and receive ICMP errors.
    pub pmtu_probe: bool,
    pub recv_buf: usize,
    pub send_buf: usize,
}

impl Default for SockOpts {
    fn default() -> Self {
        SockOpts {
            timestamping: true,
            pmtu_probe: true,
            recv_buf: 8 << 20,
            send_buf: 8 << 20,
        }
    }
}

/// Which timestamping the socket actually got.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TsCaps {
    pub kernel_rx: bool,
    pub kernel_tx: bool,
    pub recv_buf: usize,
    pub send_buf: usize,
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
    /// Next OPT_ID the kernel will assign (one per datagram sent). Only meaningful if a single
    /// thread sends on this socket (the pacer), which is how pt-probe uses it.
    next_id: AtomicU32,
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
        let _ = setsockopt(
            f,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            opts.recv_buf as libc::c_int,
        );
        let _ = setsockopt(
            f,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            opts.send_buf as libc::c_int,
        );
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

    /// Send a batch with `sendmmsg`, one datagram per message, each with its own TOS.
    /// Returns how many were sent (the rest should be retried or counted as send failures).
    pub fn send_batch(&self, msgs: &[OutMsg<'_>]) -> io::Result<usize> {
        if msgs.is_empty() {
            return Ok(0);
        }
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
            h.msg_controllen =
                unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as u32) } as usize;
            let (level, ty) = if self.v6 {
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
            } else {
                (libc::IPPROTO_IP, libc::IP_TOS)
            };
            // SAFETY: msg_control points at a CMSG_BUF-byte buffer, larger than
            // CMSG_SPACE(int); CMSG_FIRSTHDR is non-null for a non-zero msg_controllen.
            unsafe {
                let c = libc::CMSG_FIRSTHDR(h);
                (*c).cmsg_level = level;
                (*c).cmsg_type = ty;
                (*c).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as u32) as usize;
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(c).cast::<libc::c_int>(),
                    libc::c_int::from(msgs[i].tos),
                );
            }
        }
        // SAFETY: every mmsghdr points at live buffers (addrs, iovs, ctrl, payloads) that outlive
        // the call; `n` matches the array length.
        let r =
            unsafe { libc::sendmmsg(self.fd.as_raw_fd(), hdrs.as_mut_ptr(), n as libc::c_uint, 0) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok(0);
            }
            return Err(e);
        }
        self.next_id.fetch_add(r as u32, Ordering::Relaxed);
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
            h.msg_controllen = CMSG_BUF;
        }
        // SAFETY: all pointers reference live buffers of the stated sizes.
        let r = unsafe {
            libc::recvmmsg(
                self.fd.as_raw_fd(),
                hdrs.as_mut_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
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
            h.msg_controllen = ctrl.len();
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
        assert_eq!(a.send_batch(&msgs).unwrap(), 4);
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
            assert!(
                m.rx_kernel.is_some(),
                "kernel RX stamp expected on loopback"
            );
        }
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
}
