//! TCP introspection: `TCP_INFO`, `TCP_CONGESTION`, `TCP_SAVE_SYN`/`TCP_SAVED_SYN` on Linux
//! (R-0012); `TCP_CONNECTION_INFO` on macOS (R-0017, probe.md §9.7).
//!
//! `struct tcp_info` changed layout in kernel 7.0 and `libc::tcp_info` follows glibc's 6.18
//! layout, so we read the raw bytes and decode a fixed field table by offset, validating each
//! field against the length the kernel returned. macOS `struct tcp_connection_info` is read the
//! same way with its own table (`libc` models its TFO bit-field as separate words), and its
//! fields are never mapped onto `tcp_info` names: units and meanings differ.

use std::io;
use std::os::fd::RawFd;

use crate::cvt;

/// Which TCP state structure the platform's kernel reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpStateKind {
    /// Linux `TCP_INFO` (`struct tcp_info`, [`TCP_INFO_FIELDS`]), recorded in `tcpinfo`.
    TcpInfo,
    /// macOS `TCP_CONNECTION_INFO` (`struct tcp_connection_info`,
    /// [`TCP_CONNECTION_INFO_FIELDS`]), recorded in `tcpinfo_darwin` (PTF 1.2).
    ConnectionInfo,
}

impl TcpStateKind {
    /// The PTF table its samples go to.
    pub fn table(self) -> &'static str {
        match self {
            TcpStateKind::TcpInfo => "tcpinfo",
            TcpStateKind::ConnectionInfo => "tcpinfo_darwin",
        }
    }

    /// Its field table.
    pub fn fields(self) -> &'static [(&'static str, usize, usize)] {
        match self {
            TcpStateKind::TcpInfo => TCP_INFO_FIELDS,
            TcpStateKind::ConnectionInfo => TCP_CONNECTION_INFO_FIELDS,
        }
    }
}

/// (name, byte offset, size) of every macOS `struct tcp_connection_info` field (`netinet/tcp.h`,
/// 112 bytes), named without the `tcpi_` prefix in struct order as the `tcpinfo_darwin` columns
/// are (ptf-format.md). `tfo` is the 32-bit word holding the TFO flag bits, as is.
pub const TCP_CONNECTION_INFO_FIELDS: &[(&str, usize, usize)] = &[
    ("state", 0, 1),
    ("snd_wscale", 1, 1),
    ("rcv_wscale", 2, 1),
    ("options", 4, 4),
    ("flags", 8, 4),
    ("rto", 12, 4),
    ("maxseg", 16, 4),
    ("snd_ssthresh", 20, 4),
    ("snd_cwnd", 24, 4),
    ("snd_wnd", 28, 4),
    ("snd_sbbytes", 32, 4),
    ("rcv_wnd", 36, 4),
    ("rttcur", 40, 4),
    ("srtt", 44, 4),
    ("rttvar", 48, 4),
    ("tfo", 52, 4),
    ("txpackets", 56, 8),
    ("txbytes", 64, 8),
    ("txretransmitbytes", 72, 8),
    ("rxpackets", 80, 8),
    ("rxbytes", 88, 8),
    ("rxoutoforderbytes", 96, 8),
    ("txretransmitpackets", 104, 8),
];

/// Size of macOS `struct tcp_connection_info`.
pub const TCP_CONNECTION_INFO_LEN: usize = 112;

/// (name, byte offset, size) of every `tcp_info` field PathTrace records, up to kernel 6.7.
/// Offsets follow include/uapi/linux/tcp.h. Fields beyond the kernel-returned length are absent.
pub const TCP_INFO_FIELDS: &[(&str, usize, usize)] = &[
    ("state", 0, 1),
    ("ca_state", 1, 1),
    ("retransmits", 2, 1),
    ("probes", 3, 1),
    ("backoff", 4, 1),
    ("options", 5, 1),
    ("wscale", 6, 1),
    ("flags7", 7, 1),
    ("rto", 8, 4),
    ("ato", 12, 4),
    ("snd_mss", 16, 4),
    ("rcv_mss", 20, 4),
    ("unacked", 24, 4),
    ("sacked", 28, 4),
    ("lost", 32, 4),
    ("retrans", 36, 4),
    ("fackets", 40, 4),
    ("last_data_sent", 44, 4),
    ("last_ack_sent", 48, 4),
    ("last_data_recv", 52, 4),
    ("last_ack_recv", 56, 4),
    ("pmtu", 60, 4),
    ("rcv_ssthresh", 64, 4),
    ("rtt", 68, 4),
    ("rttvar", 72, 4),
    ("snd_ssthresh", 76, 4),
    ("snd_cwnd", 80, 4),
    ("advmss", 84, 4),
    ("reordering", 88, 4),
    ("rcv_rtt", 92, 4),
    ("rcv_space", 96, 4),
    ("total_retrans", 100, 4),
    ("pacing_rate", 104, 8),
    ("max_pacing_rate", 112, 8),
    ("bytes_acked", 120, 8),
    ("bytes_received", 128, 8),
    ("segs_out", 136, 4),
    ("segs_in", 140, 4),
    ("notsent_bytes", 144, 4),
    ("min_rtt", 148, 4),
    ("data_segs_in", 152, 4),
    ("data_segs_out", 156, 4),
    ("delivery_rate", 160, 8),
    ("busy_time", 168, 8),
    ("rwnd_limited", 176, 8),
    ("sndbuf_limited", 184, 8),
    ("delivered", 192, 4),
    ("delivered_ce", 196, 4),
    ("bytes_sent", 200, 8),
    ("bytes_retrans", 208, 8),
    ("dsack_dups", 216, 4),
    ("reord_seen", 220, 4),
    ("rcv_ooopack", 224, 4),
    ("snd_wnd", 228, 4),
    ("rcv_wnd", 232, 4),
    ("rehash", 236, 4),
    ("total_rto", 240, 2),
    ("total_rto_recoveries", 242, 2),
    ("total_rto_time", 244, 4),
];

/// A raw `TCP_INFO` (Linux) or `TCP_CONNECTION_INFO` (macOS) sample.
#[derive(Debug, Clone)]
pub struct TcpInfoRaw {
    pub bytes: [u8; 512],
    /// Length the kernel wrote.
    pub len: usize,
    kind: TcpStateKind,
}

impl TcpInfoRaw {
    /// Which structure the bytes hold; [`TcpInfoRaw::get`] reads names from its field table.
    pub fn kind(&self) -> TcpStateKind {
        self.kind
    }

    /// Field value, or `None` if the kernel's struct is too short to contain it.
    pub fn field(&self, offset: usize, size: usize) -> Option<u64> {
        if offset + size > self.len {
            return None;
        }
        let b = &self.bytes[offset..offset + size];
        Some(match size {
            1 => u64::from(b[0]),
            2 => u64::from(u16::from_ne_bytes([b[0], b[1]])),
            4 => u64::from(u32::from_ne_bytes(b.try_into().ok()?)),
            8 => u64::from_ne_bytes(b.try_into().ok()?),
            _ => return None,
        })
    }

    pub fn get(&self, name: &str) -> Option<u64> {
        let (_, off, size) = self.kind.fields().iter().find(|f| f.0 == name)?;
        self.field(*off, *size)
    }
}

/// `getsockopt(IPPROTO_TCP, opt)` into a 512-byte buffer.
fn tcp_state(fd: RawFd, opt: libc::c_int, kind: TcpStateKind) -> io::Result<TcpInfoRaw> {
    let mut info = TcpInfoRaw {
        bytes: [0; 512],
        len: 0,
        kind,
    };
    let mut len = info.bytes.len() as libc::socklen_t;
    // SAFETY: the buffer is 512 writable bytes and `len` says so; the kernel copies at most
    // min(len, sizeof(struct)) and writes the copied length back.
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            opt,
            info.bytes.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    info.len = len as usize;
    Ok(info)
}

/// A Linux `TCP_INFO` sample; unsupported on macOS (use [`tcp_connection_info`]).
#[cfg(target_os = "linux")]
pub fn tcp_info(fd: RawFd) -> io::Result<TcpInfoRaw> {
    tcp_state(fd, libc::TCP_INFO, TcpStateKind::TcpInfo)
}

/// A Linux `TCP_INFO` sample; unsupported on macOS (use [`tcp_connection_info`]).
#[cfg(target_os = "macos")]
pub fn tcp_info(_fd: RawFd) -> io::Result<TcpInfoRaw> {
    Err(crate::unsupported("TCP_INFO"))
}

/// A macOS `TCP_CONNECTION_INFO` sample; unsupported on Linux (use [`tcp_info`]).
#[cfg(target_os = "macos")]
pub fn tcp_connection_info(fd: RawFd) -> io::Result<TcpInfoRaw> {
    tcp_state(fd, libc::TCP_CONNECTION_INFO, TcpStateKind::ConnectionInfo)
}

/// A macOS `TCP_CONNECTION_INFO` sample; unsupported on Linux (use [`tcp_info`]).
#[cfg(target_os = "linux")]
pub fn tcp_connection_info(_fd: RawFd) -> io::Result<TcpInfoRaw> {
    Err(crate::unsupported("TCP_CONNECTION_INFO"))
}

/// Current congestion-control algorithm name; unsupported on macOS.
#[cfg(target_os = "macos")]
pub fn congestion(_fd: RawFd) -> io::Result<String> {
    Err(crate::unsupported("TCP_CONGESTION"))
}

/// Ask a listening socket to save the headers of incoming SYNs; unsupported on macOS.
#[cfg(target_os = "macos")]
pub fn set_save_syn(_listen_fd: RawFd) -> io::Result<()> {
    Err(crate::unsupported("TCP_SAVE_SYN"))
}

/// The IP+TCP headers of the SYN that created an accepted connection; unsupported on macOS.
#[cfg(target_os = "macos")]
pub fn saved_syn(_fd: RawFd) -> io::Result<Vec<u8>> {
    Err(crate::unsupported("TCP_SAVED_SYN"))
}

/// Current congestion-control algorithm name.
#[cfg(target_os = "linux")]
pub fn congestion(fd: RawFd) -> io::Result<String> {
    let mut buf = [0u8; 16];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: 16-byte writable buffer (TCP_CA_NAME_MAX), length passed.
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    let end = buf.iter().position(|b| *b == 0).unwrap_or(len as usize);
    Ok(String::from_utf8_lossy(&buf[..end]).into_owned())
}

/// Ask a listening socket to save the headers of incoming SYNs (unprivileged; R-0012).
#[cfg(target_os = "linux")]
pub fn set_save_syn(listen_fd: RawFd) -> io::Result<()> {
    crate::setsockopt(
        listen_fd,
        libc::IPPROTO_TCP,
        libc::TCP_SAVE_SYN,
        1 as libc::c_int,
    )
}

/// The IP+TCP headers of the SYN that created an accepted connection (readable once).
#[cfg(target_os = "linux")]
pub fn saved_syn(fd: RawFd) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: writable buffer of `len` bytes.
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_SAVED_SYN,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    buf.truncate(len as usize);
    Ok(buf)
}

/// Disable Nagle.
pub fn set_nodelay(fd: RawFd) -> io::Result<()> {
    crate::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1 as libc::c_int)
}

/// Set the TOS byte on a socket.
pub fn set_tos(fd: RawFd, v6: bool, tos: u8) -> io::Result<()> {
    if v6 {
        crate::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_TCLASS,
            libc::c_int::from(tos),
        )
    } else {
        crate::setsockopt(fd, libc::IPPROTO_IP, libc::IP_TOS, libc::c_int::from(tos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;

    #[test]
    fn field_tables_fit_their_structs() {
        for (kind, len) in [
            (TcpStateKind::TcpInfo, 248),
            (TcpStateKind::ConnectionInfo, TCP_CONNECTION_INFO_LEN),
        ] {
            let mut end = 0;
            for (name, off, size) in kind.fields() {
                assert!(*off >= end, "{name} overlaps the previous field");
                assert_eq!(off % size, 0, "{name} is misaligned");
                end = off + size;
            }
            assert_eq!(end, len, "{}", kind.table());
        }
    }

    /// probe.md §9.7: `optlen` is the struct size and `srtt` and `txbytes` are filled.
    #[cfg(target_os = "macos")]
    #[test]
    fn connection_info_on_loopback() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 100_000];
            s.read_exact(&mut buf).unwrap();
            s.write_all(&[0]).unwrap();
            // Keep the connection open until the client has sampled it.
            let _ = done_rx.recv();
        });
        let mut c = TcpStream::connect(addr).unwrap();
        set_nodelay(c.as_raw_fd()).unwrap();
        set_tos(c.as_raw_fd(), false, 0x10).unwrap();
        c.write_all(&[1u8; 100_000]).unwrap();
        let mut ack = [0u8; 1];
        c.read_exact(&mut ack).unwrap();
        let info = tcp_connection_info(c.as_raw_fd()).unwrap();
        done_tx.send(()).unwrap();
        t.join().unwrap();
        assert_eq!(info.kind(), TcpStateKind::ConnectionInfo);
        assert_eq!(info.len, TCP_CONNECTION_INFO_LEN);
        assert!(info.get("srtt").is_some());
        assert_eq!(info.get("txbytes"), Some(100_000));
        assert_eq!(info.get("state"), Some(4), "TCPS_ESTABLISHED");
        assert!(info.get("rttcur").is_some() && info.get("snd_cwnd").unwrap() > 0);
        assert!(info.get("min_rtt").is_none(), "no Linux names");
        for e in [
            tcp_info(c.as_raw_fd()).unwrap_err(),
            congestion(c.as_raw_fd()).unwrap_err(),
            saved_syn(c.as_raw_fd()).unwrap_err(),
            set_save_syn(c.as_raw_fd()).unwrap_err(),
        ] {
            assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        }
    }

    /// The PTF table each kind of TCP state goes to (probe.md §9.7).
    #[test]
    fn state_kind_tables() {
        assert_eq!(TcpStateKind::TcpInfo.table(), "tcpinfo");
        assert_eq!(TcpStateKind::ConnectionInfo.table(), "tcpinfo_darwin");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn info_congestion_and_saved_syn() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        set_save_syn(l.as_raw_fd()).unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(&[1u8; 100_000]).unwrap();
            let info = tcp_info(c.as_raw_fd()).unwrap();
            (
                info.len,
                info.get("bytes_acked"),
                congestion(c.as_raw_fd()).unwrap(),
            )
        });
        let (mut s, _) = l.accept().unwrap();
        let syn = saved_syn(s.as_raw_fd()).unwrap();
        assert!(syn.len() >= 40, "saved SYN length {}", syn.len());
        assert_eq!(syn[0] >> 4, 4, "IPv4 header");
        let mut buf = vec![0u8; 100_000];
        s.read_exact(&mut buf).unwrap();
        let (len, acked, cc) = t.join().unwrap();
        assert!(len >= 104);
        assert!(acked.is_some());
        assert!(!cc.is_empty());
        assert_eq!(
            tcp_connection_info(s.as_raw_fd()).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
