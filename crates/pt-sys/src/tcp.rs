//! TCP introspection: `TCP_INFO`, `TCP_CONGESTION`, `TCP_SAVE_SYN`/`TCP_SAVED_SYN` (R-0012).
//!
//! `struct tcp_info` changed layout in kernel 7.0 and `libc::tcp_info` follows glibc's 6.18
//! layout, so we read the raw bytes and decode a fixed field table by offset, validating each
//! field against the length the kernel returned.

use std::io;
use std::os::fd::RawFd;

use crate::cvt;

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

/// A raw `TCP_INFO` sample.
#[derive(Debug, Clone)]
pub struct TcpInfoRaw {
    pub bytes: [u8; 512],
    /// Length the kernel wrote.
    pub len: usize,
}

impl TcpInfoRaw {
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
        let (_, off, size) = TCP_INFO_FIELDS.iter().find(|f| f.0 == name)?;
        self.field(*off, *size)
    }
}

pub fn tcp_info(fd: RawFd) -> io::Result<TcpInfoRaw> {
    let mut info = TcpInfoRaw {
        bytes: [0; 512],
        len: 0,
    };
    let mut len = info.bytes.len() as libc::socklen_t;
    // SAFETY: the buffer is 512 writable bytes and `len` says so; the kernel copies at most
    // min(len, sizeof(struct tcp_info)) and writes the copied length back.
    cvt(unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            info.bytes.as_mut_ptr().cast(),
            &mut len,
        )
    })?;
    info.len = len as usize;
    Ok(info)
}

/// Current congestion-control algorithm name.
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
pub fn set_save_syn(listen_fd: RawFd) -> io::Result<()> {
    crate::setsockopt(
        listen_fd,
        libc::IPPROTO_TCP,
        libc::TCP_SAVE_SYN,
        1 as libc::c_int,
    )
}

/// The IP+TCP headers of the SYN that created an accepted connection (readable once).
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
    }
}
