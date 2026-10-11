//! Minimal netlink: rtnetlink change events, qdisc statistics (R-0015) and nl80211 Wi-Fi link
//! state (R-0013).
//!
//! Hand-rolled over libc to stay free of async netlink stacks (R-0014). Only the attributes
//! PathTrace records are parsed; everything else is skipped.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::{cvt, cvt_ssize, setsockopt};

const NLMSG_HDR: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[derive(Debug)]
struct NlSocket {
    fd: OwnedFd,
    seq: u32,
}

impl NlSocket {
    fn open(proto: libc::c_int, groups: u32, nonblock: bool) -> io::Result<NlSocket> {
        let flags =
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | if nonblock { libc::SOCK_NONBLOCK } else { 0 };
        // SAFETY: plain socket(2); fd owned below.
        let raw = cvt(unsafe { libc::socket(libc::AF_NETLINK, flags, proto) })?;
        // SAFETY: fresh fd we exclusively own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zeroed sockaddr_nl is valid; fields set below.
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_groups = groups;
        // SAFETY: valid sockaddr_nl of the stated size.
        cvt(unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const sa).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        })?;
        if !nonblock {
            let tv = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, tv)?;
        }
        Ok(NlSocket { fd, seq: 1 })
    }

    fn send(&mut self, ty: u16, flags: u16, payload: &[u8]) -> io::Result<u32> {
        self.seq += 1;
        let len = NLMSG_HDR + payload.len();
        let mut msg = Vec::with_capacity(len);
        msg.extend_from_slice(&(len as u32).to_ne_bytes());
        msg.extend_from_slice(&ty.to_ne_bytes());
        msg.extend_from_slice(&flags.to_ne_bytes());
        msg.extend_from_slice(&self.seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes());
        msg.extend_from_slice(payload);
        // SAFETY: sending our own initialised buffer to the kernel (dest is the kernel, pid 0).
        cvt_ssize(unsafe { libc::send(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) })?;
        Ok(self.seq)
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: writable buffer of buf.len() bytes.
        cvt_ssize(unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) })
    }

    /// Send a request and collect (type, payload) of all reply messages until DONE/ACK.
    fn request(&mut self, ty: u16, flags: u16, payload: &[u8]) -> io::Result<Vec<(u16, Vec<u8>)>> {
        let seq = self.send(ty, flags | NLM_F_REQUEST | NLM_F_ACK, payload)?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let n = self.recv(&mut buf)?;
            for (mty, mseq, body) in messages(&buf[..n]) {
                if mseq != seq {
                    continue;
                }
                match mty {
                    NLMSG_DONE => return Ok(out),
                    NLMSG_ERROR => {
                        let code = body
                            .get(..4)
                            .map(|b| i32::from_ne_bytes(b.try_into().expect("4")))
                            .unwrap_or(0);
                        if code == 0 {
                            if flags & NLM_F_DUMP == 0 {
                                return Ok(out);
                            }
                            continue;
                        }
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                    _ => out.push((mty, body.to_vec())),
                }
            }
        }
    }
}

/// Split a netlink datagram into (type, seq, payload).
fn messages(buf: &[u8]) -> Vec<(u16, u32, &[u8])> {
    let mut out = Vec::new();
    let mut pos = 0;
    while buf.len() - pos >= NLMSG_HDR {
        let len = u32::from_ne_bytes(buf[pos..pos + 4].try_into().expect("4")) as usize;
        if len < NLMSG_HDR || pos + len > buf.len() {
            break;
        }
        let ty = u16::from_ne_bytes([buf[pos + 4], buf[pos + 5]]);
        let seq = u32::from_ne_bytes(buf[pos + 8..pos + 12].try_into().expect("4"));
        out.push((ty, seq, &buf[pos + NLMSG_HDR..pos + len]));
        pos += align4(len);
    }
    out
}

/// Parse attributes into (type with nested/byteorder flags masked, payload).
fn attrs(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    let mut pos = 0;
    while buf.len() - pos >= 4 {
        let len = u16::from_ne_bytes([buf[pos], buf[pos + 1]]) as usize;
        let ty = u16::from_ne_bytes([buf[pos + 2], buf[pos + 3]]) & 0x3fff;
        if len < 4 || pos + len > buf.len() {
            break;
        }
        out.push((ty, &buf[pos + 4..pos + len]));
        pos += align4(len);
    }
    out
}

fn attr(ty: u16, data: &[u8]) -> Vec<u8> {
    let len = 4 + data.len();
    let mut v = Vec::with_capacity(align4(len));
    v.extend_from_slice(&(len as u16).to_ne_bytes());
    v.extend_from_slice(&ty.to_ne_bytes());
    v.extend_from_slice(data);
    v.resize(align4(len), 0);
    v
}

fn u32_of(b: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(..4)?.try_into().ok()?))
}

// ---------------------------------------------------------------- rtnetlink

/// Kind of a routing change event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtKind {
    NewLink,
    DelLink,
    NewAddr,
    DelAddr,
    NewRoute,
    DelRoute,
}

impl RtKind {
    pub fn name(self) -> &'static str {
        match self {
            RtKind::NewLink => "link_new",
            RtKind::DelLink => "link_del",
            RtKind::NewAddr => "addr_new",
            RtKind::DelAddr => "addr_del",
            RtKind::NewRoute => "route_new",
            RtKind::DelRoute => "route_del",
        }
    }
}

/// A routing change event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtEvent {
    pub kind: RtKind,
    pub ifindex: u32,
    pub addr: Option<IpAddr>,
    /// For routes: whether it is a default route (dst_len 0).
    pub default_route: bool,
}

/// Non-blocking subscriber to link/address/route changes (groups 0x551, unprivileged).
#[derive(Debug)]
pub struct RtMonitor {
    sock: NlSocket,
}

impl RtMonitor {
    pub fn open() -> io::Result<RtMonitor> {
        let groups = libc::RTMGRP_LINK as u32
            | libc::RTMGRP_IPV4_IFADDR as u32
            | libc::RTMGRP_IPV6_IFADDR as u32
            | libc::RTMGRP_IPV4_ROUTE as u32
            | libc::RTMGRP_IPV6_ROUTE as u32;
        Ok(RtMonitor {
            sock: NlSocket::open(libc::NETLINK_ROUTE, groups, true)?,
        })
    }

    /// Read all pending events. ENOBUFS (overrun) is reported as an error so callers can log it.
    pub fn poll_events(&self, out: &mut Vec<RtEvent>) -> io::Result<()> {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match self.sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            };
            for (ty, _, body) in messages(&buf[..n]) {
                if let Some(ev) = parse_rt(ty, body) {
                    out.push(ev);
                }
            }
        }
    }
}

fn parse_rt(ty: u16, body: &[u8]) -> Option<RtEvent> {
    let kind = match ty {
        libc::RTM_NEWLINK => RtKind::NewLink,
        libc::RTM_DELLINK => RtKind::DelLink,
        libc::RTM_NEWADDR => RtKind::NewAddr,
        libc::RTM_DELADDR => RtKind::DelAddr,
        libc::RTM_NEWROUTE => RtKind::NewRoute,
        libc::RTM_DELROUTE => RtKind::DelRoute,
        _ => return None,
    };
    match kind {
        RtKind::NewLink | RtKind::DelLink => {
            let index = i32::from_ne_bytes(body.get(4..8)?.try_into().ok()?);
            Some(RtEvent {
                kind,
                ifindex: index as u32,
                addr: None,
                default_route: false,
            })
        }
        RtKind::NewAddr | RtKind::DelAddr => {
            let family = *body.first()?;
            let index = u32_of(body.get(4..8)?)?;
            let mut addr = None;
            for (t, d) in attrs(body.get(8..)?) {
                // IFA_ADDRESS = 1, IFA_LOCAL = 2
                if t == 1 || (t == 2 && addr.is_none()) {
                    addr = ip_of(family, d);
                }
            }
            Some(RtEvent {
                kind,
                ifindex: index,
                addr,
                default_route: false,
            })
        }
        RtKind::NewRoute | RtKind::DelRoute => {
            let family = *body.first()?;
            let dst_len = *body.get(1)?;
            let table = *body.get(4)?;
            if table != libc::RT_TABLE_MAIN {
                return None;
            }
            let mut out_ifindex = 0;
            let mut gw = None;
            for (t, d) in attrs(body.get(12..)?) {
                match t {
                    4 => out_ifindex = u32_of(d).unwrap_or(0),
                    5 => gw = ip_of(family, d),
                    _ => {}
                }
            }
            Some(RtEvent {
                kind,
                ifindex: out_ifindex,
                addr: gw,
                default_route: dst_len == 0,
            })
        }
    }
}

// ---------------------------------------------------------------- qdisc statistics (R-0015)

const RTM_NEWQDISC: u16 = 36;
const RTM_GETQDISC: u16 = 38;
const TCA_KIND: u16 = 1;
const TCA_STATS2: u16 = 7;
const TCA_STATS_BASIC: u16 = 1;
const TCA_STATS_QUEUE: u16 = 3;
const TC_H_ROOT: u32 = 0xFFFF_FFFF;
const TCMSG_LEN: usize = 20;

/// Counters of one qdisc (`tc -s qdisc`): basic and queue statistics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QdiscStats {
    pub kind: String,
    pub handle: u32,
    pub bytes: u64,
    pub packets: u32,
    pub qlen: u32,
    pub backlog: u32,
    pub drops: u32,
    pub requeues: u32,
    pub overlimits: u32,
}

/// Reads qdisc statistics with an unprivileged `RTM_GETQDISC` dump.
#[derive(Debug)]
pub struct QdiscReader {
    sock: NlSocket,
}

impl QdiscReader {
    pub fn open() -> io::Result<QdiscReader> {
        Ok(QdiscReader {
            sock: NlSocket::open(libc::NETLINK_ROUTE, 0, false)?,
        })
    }

    /// Statistics of the root qdisc of interface `ifindex`, if it has one.
    pub fn root(&mut self, ifindex: u32) -> io::Result<Option<QdiscStats>> {
        let mut req = [0u8; TCMSG_LEN];
        req[4..8].copy_from_slice(&(ifindex as i32).to_ne_bytes());
        let msgs = self.sock.request(RTM_GETQDISC, NLM_F_DUMP, &req)?;
        Ok(msgs
            .iter()
            .filter(|(ty, _)| *ty == RTM_NEWQDISC)
            .filter_map(|(_, body)| parse_qdisc(body))
            .find(|(ifi, parent, _)| *ifi == ifindex && *parent == TC_H_ROOT)
            .map(|(_, _, q)| q))
    }
}

/// Parse an `RTM_NEWQDISC` body into (ifindex, parent, stats).
fn parse_qdisc(body: &[u8]) -> Option<(u32, u32, QdiscStats)> {
    let ifindex = u32_of(body.get(4..8)?)?;
    let handle = u32_of(body.get(8..12)?)?;
    let parent = u32_of(body.get(12..16)?)?;
    let mut q = QdiscStats {
        handle,
        ..Default::default()
    };
    for (t, d) in attrs(body.get(TCMSG_LEN..)?) {
        match t {
            TCA_KIND => {
                q.kind = String::from_utf8_lossy(d.split(|b| *b == 0).next().unwrap_or(&[]))
                    .into_owned();
            }
            TCA_STATS2 => {
                for (st, sd) in attrs(d) {
                    match st {
                        // struct gnet_stats_basic { u64 bytes; u32 packets; }
                        TCA_STATS_BASIC => {
                            q.bytes = u64::from_ne_bytes(sd.get(..8)?.try_into().ok()?);
                            q.packets = u32_of(sd.get(8..12)?)?;
                        }
                        // struct gnet_stats_queue { qlen, backlog, drops, requeues, overlimits }
                        TCA_STATS_QUEUE => {
                            q.qlen = u32_of(sd.get(0..4)?)?;
                            q.backlog = u32_of(sd.get(4..8)?)?;
                            q.drops = u32_of(sd.get(8..12)?)?;
                            q.requeues = u32_of(sd.get(12..16)?)?;
                            q.overlimits = u32_of(sd.get(16..20)?)?;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Some((ifindex, parent, q))
}

fn ip_of(family: u8, d: &[u8]) -> Option<IpAddr> {
    match i32::from(family) {
        libc::AF_INET => Some(IpAddr::from(<[u8; 4]>::try_from(d.get(..4)?).ok()?)),
        libc::AF_INET6 => Some(IpAddr::from(<[u8; 16]>::try_from(d.get(..16)?).ok()?)),
        _ => None,
    }
}

// ---------------------------------------------------------------- nl80211

const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_GET_STATION: u8 = 17;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const STA_INFO_SIGNAL: u16 = 7;
const STA_INFO_TX_BITRATE: u16 = 8;
const STA_INFO_TX_RETRIES: u16 = 11;
const STA_INFO_TX_FAILED: u16 = 12;
const STA_INFO_RX_BITRATE: u16 = 14;
const STA_INFO_BEACON_SIGNAL_AVG: u16 = 30;
const RATE_INFO_BITRATE: u16 = 1;
const RATE_INFO_BITRATE32: u16 = 5;

/// One nl80211 sample for the associated station (the AP, in managed mode).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WifiSample {
    pub freq_mhz: Option<u32>,
    pub channel_width: Option<u32>,
    pub bssid: Option<[u8; 6]>,
    pub signal_dbm: Option<i8>,
    pub beacon_signal_dbm: Option<i8>,
    /// 100 kbit/s units.
    pub tx_bitrate: Option<u32>,
    pub rx_bitrate: Option<u32>,
    pub tx_retries: Option<u32>,
    pub tx_failed: Option<u32>,
}

/// nl80211 client (unprivileged reads only).
#[derive(Debug)]
pub struct Nl80211 {
    sock: NlSocket,
    family: u16,
}

fn genl_payload(cmd: u8, attrs_bytes: &[u8]) -> Vec<u8> {
    let mut p = vec![cmd, 1, 0, 0];
    p.extend_from_slice(attrs_bytes);
    p
}

fn bitrate(nested: &[u8]) -> Option<u32> {
    let a = attrs(nested);
    a.iter()
        .find(|(t, _)| *t == RATE_INFO_BITRATE32)
        .and_then(|(_, d)| u32_of(d))
        .or_else(|| {
            a.iter()
                .find(|(t, _)| *t == RATE_INFO_BITRATE)
                .map(|(_, d)| u32::from(u16::from_ne_bytes([d[0], d[1]])))
        })
}

impl Nl80211 {
    /// Resolve the nl80211 family. Fails if the kernel has no cfg80211.
    pub fn open() -> io::Result<Nl80211> {
        let mut sock = NlSocket::open(libc::NETLINK_GENERIC, 0, false)?;
        let mut name = b"nl80211".to_vec();
        name.push(0);
        let reply = sock.request(
            GENL_ID_CTRL,
            0,
            &genl_payload(CTRL_CMD_GETFAMILY, &attr(CTRL_ATTR_FAMILY_NAME, &name)),
        )?;
        let family = reply
            .iter()
            .flat_map(|(_, b)| {
                attrs(b.get(4..).unwrap_or(&[]))
                    .into_iter()
                    .map(|(t, d)| (t, d.to_vec()))
                    .collect::<Vec<_>>()
            })
            .find(|(t, _)| *t == CTRL_ATTR_FAMILY_ID)
            .map(|(_, d)| u16::from_ne_bytes([d[0], d[1]]))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "nl80211 family not found"))?;
        Ok(Nl80211 { sock, family })
    }

    /// Sample the interface and its associated station.
    pub fn sample(&mut self, ifindex: u32) -> io::Result<WifiSample> {
        let mut s = WifiSample::default();
        let ifa = attr(NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
        for (_, b) in self.sock.request(
            self.family,
            0,
            &genl_payload(NL80211_CMD_GET_INTERFACE, &ifa),
        )? {
            for (t, d) in attrs(b.get(4..).unwrap_or(&[])) {
                match t {
                    NL80211_ATTR_WIPHY_FREQ => s.freq_mhz = u32_of(d),
                    NL80211_ATTR_CHANNEL_WIDTH => s.channel_width = u32_of(d),
                    _ => {}
                }
            }
        }
        let stations = self.sock.request(
            self.family,
            NLM_F_DUMP,
            &genl_payload(NL80211_CMD_GET_STATION, &ifa),
        )?;
        if let Some((_, b)) = stations.first() {
            for (t, d) in attrs(b.get(4..).unwrap_or(&[])) {
                match t {
                    NL80211_ATTR_MAC => s.bssid = d.get(..6).and_then(|m| m.try_into().ok()),
                    NL80211_ATTR_STA_INFO => {
                        for (st, sd) in attrs(d) {
                            match st {
                                STA_INFO_SIGNAL => s.signal_dbm = sd.first().map(|v| *v as i8),
                                STA_INFO_BEACON_SIGNAL_AVG => {
                                    s.beacon_signal_dbm = sd.first().map(|v| *v as i8)
                                }
                                STA_INFO_TX_BITRATE => s.tx_bitrate = bitrate(sd),
                                STA_INFO_RX_BITRATE => s.rx_bitrate = bitrate(sd),
                                STA_INFO_TX_RETRIES => s.tx_retries = u32_of(sd),
                                STA_INFO_TX_FAILED => s.tx_failed = u32_of(sd),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_roundtrip_and_alignment() {
        let a = attr(3, &[1, 2, 3]);
        assert_eq!(a.len(), 8);
        let parsed = attrs(&a);
        assert_eq!(parsed, vec![(3, &[1u8, 2, 3][..])]);
    }

    #[test]
    fn rt_monitor_opens() {
        let m = RtMonitor::open().unwrap();
        let mut ev = Vec::new();
        m.poll_events(&mut ev).unwrap();
    }

    #[test]
    fn parse_qdisc_stats() {
        let mut body = vec![0u8; TCMSG_LEN];
        body[4..8].copy_from_slice(&3u32.to_ne_bytes());
        body[8..12].copy_from_slice(&0x8001_0000u32.to_ne_bytes());
        body[12..16].copy_from_slice(&TC_H_ROOT.to_ne_bytes());
        body.extend(attr(TCA_KIND, b"fq_codel\0"));
        let mut basic = 1_000_000u64.to_ne_bytes().to_vec();
        basic.extend(700u32.to_ne_bytes());
        basic.extend(0u32.to_ne_bytes()); // padding
        let mut queue = Vec::new();
        for v in [2u32, 3000, 5, 1, 9] {
            queue.extend(v.to_ne_bytes());
        }
        let mut st = attr(TCA_STATS_BASIC, &basic);
        st.extend(attr(TCA_STATS_QUEUE, &queue));
        body.extend(attr(TCA_STATS2, &st));
        let (ifi, parent, q) = parse_qdisc(&body).unwrap();
        assert_eq!((ifi, parent), (3, TC_H_ROOT));
        assert_eq!(q.kind, "fq_codel");
        assert_eq!((q.bytes, q.packets), (1_000_000, 700));
        assert_eq!(
            (q.qlen, q.backlog, q.drops, q.requeues, q.overlimits),
            (2, 3000, 5, 1, 9)
        );
    }

    #[test]
    fn qdisc_reader_reads_loopback() {
        // Loopback has a root qdisc (noqueue) on every kernel PathTrace supports.
        let mut r = QdiscReader::open().unwrap();
        let q = r.root(1).unwrap().expect("lo root qdisc");
        assert!(!q.kind.is_empty());
    }

    #[test]
    fn parse_newaddr() {
        // ifaddrmsg: family=2, prefixlen=24, flags=0, scope=0, index=7; IFA_ADDRESS=10.0.0.1
        let mut body = vec![2u8, 24, 0, 0];
        body.extend_from_slice(&7u32.to_ne_bytes());
        body.extend(attr(1, &[10, 0, 0, 1]));
        let ev = parse_rt(libc::RTM_NEWADDR, &body).unwrap();
        assert_eq!(
            ev,
            RtEvent {
                kind: RtKind::NewAddr,
                ifindex: 7,
                addr: Some(IpAddr::from([10, 0, 0, 1])),
                default_route: false
            }
        );
    }
}
