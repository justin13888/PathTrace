//! Linux and macOS system interface for PathTrace. The only workspace crate allowed `unsafe`;
//! every unsafe block documents why it is sound.
//!
//! Facts relied upon are verified in docs/research/R-0010 … R-0017. Each module has a Linux and a
//! macOS backend behind `cfg(target_os)` with the same public API (ADR 0014, probe.md §9); what
//! a platform cannot observe is reported through [`PLATFORM`] and per-socket capabilities
//! ([`udp::TsCaps`]), or as an [`io::ErrorKind::Unsupported`] error, so callers never need `cfg`.

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("pt-sys supports only Linux and macOS (ADR 0014)");

pub mod clock;
pub mod ethtool;
pub mod netif;
pub mod netlink;
pub mod power;
pub mod signal;
pub mod tcp;
pub mod udp;

use std::io;

/// What this platform's backend can observe (probe.md §9). Callers branch on these, never on
/// `cfg`; what a socket actually got is in [`udp::TsCaps`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platform {
    /// PTF 1.2 `endpoint.os_family`: `linux` or `darwin`.
    pub os_family: &'static str,
    /// Kernel transmit timestamps can be requested (`SO_TIMESTAMPING`).
    pub kernel_tx_stamps: bool,
    /// Sockets have an error queue carrying TX stamps and ICMP errors (`MSG_ERRQUEUE`).
    pub error_queue: bool,
    /// One system call sends or receives many datagrams (`sendmmsg`/`recvmmsg`); otherwise one
    /// call per datagram.
    pub batched_io: bool,
    /// Per-socket receive drop counts (`SO_RXQ_OVFL`).
    pub socket_rx_drops: bool,
    /// Egress qdisc statistics ([`netlink::QdiscReader`]).
    pub qdisc_stats: bool,
    /// [`netif::IfStats::tx_dropped`] is a real counter. Where false it is 0 and must be
    /// recorded as unknown (null), never as 0 (probe.md §9.6).
    pub iface_tx_dropped: bool,
    /// Wi-Fi link state ([`netlink::Nl80211`]).
    pub wifi_link: bool,
    /// Routing change events ([`netlink::RtMonitor`]).
    pub route_events: bool,
    /// Interface offload features ([`ethtool::features`]).
    pub offload_features: bool,
    /// Which TCP state the kernel reports.
    pub tcp_state: tcp::TcpStateKind,
    /// A power assertion can keep the system awake for a session ([`power`]).
    pub power_assertion: bool,
}

/// The capabilities of the platform this was compiled for.
#[cfg(target_os = "linux")]
pub const PLATFORM: Platform = Platform {
    os_family: "linux",
    kernel_tx_stamps: true,
    error_queue: true,
    batched_io: true,
    socket_rx_drops: true,
    qdisc_stats: true,
    iface_tx_dropped: true,
    wifi_link: true,
    route_events: true,
    offload_features: true,
    tcp_state: tcp::TcpStateKind::TcpInfo,
    power_assertion: false,
};

/// The capabilities of the platform this was compiled for.
#[cfg(target_os = "macos")]
pub const PLATFORM: Platform = Platform {
    os_family: "darwin",
    kernel_tx_stamps: false,
    error_queue: false,
    batched_io: false,
    socket_rx_drops: false,
    qdisc_stats: false,
    iface_tx_dropped: false,
    wifi_link: false,
    route_events: false,
    offload_features: false,
    tcp_state: tcp::TcpStateKind::ConnectionInfo,
    power_assertion: true,
};

/// The error a facility this platform lacks returns.
pub(crate) fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} is not available on {}", PLATFORM.os_family),
    )
}

/// Convert a libc return value into `io::Result`.
pub(crate) fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn cvt_ssize(ret: libc::ssize_t) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as usize)
    }
}

/// `setsockopt` for plain-old-data values.
pub(crate) fn setsockopt<T: Copy>(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    val: T,
) -> io::Result<()> {
    // SAFETY: `val` is a live, properly aligned `T` for the duration of the call and we pass
    // its exact size; the kernel only reads `size_of::<T>()` bytes.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            (&raw const val).cast::<libc::c_void>(),
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    cvt(r).map(|_| ())
}

/// `getsockopt` for an `int` option.
pub(crate) fn getsockopt_int(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v` and `len` are valid for writes; `len` holds the buffer size.
    let r = unsafe { libc::getsockopt(fd, level, name, (&raw mut v).cast(), &mut len) };
    cvt(r).map(|_| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PTF 1.2 `endpoint.os_family` and TCP state kind of each platform (probe.md §9).
    #[cfg(target_os = "linux")]
    #[test]
    fn platform_linux() {
        assert_eq!(PLATFORM.os_family, "linux");
        assert_eq!(PLATFORM.tcp_state, tcp::TcpStateKind::TcpInfo);
        assert_eq!(PLATFORM.tcp_state.table(), "tcpinfo");
        let p = PLATFORM;
        assert_eq!(
            (
                p.kernel_tx_stamps,
                p.socket_rx_drops,
                p.iface_tx_dropped,
                p.power_assertion
            ),
            (true, true, true, false)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn platform_macos() {
        assert_eq!(PLATFORM.os_family, "darwin");
        assert_eq!(PLATFORM.tcp_state, tcp::TcpStateKind::ConnectionInfo);
        assert_eq!(PLATFORM.tcp_state.table(), "tcpinfo_darwin");
        let p = PLATFORM;
        assert_eq!(
            (
                p.kernel_tx_stamps,
                p.socket_rx_drops,
                p.iface_tx_dropped,
                p.qdisc_stats,
                p.power_assertion
            ),
            (false, false, false, false, true)
        );
    }
}
