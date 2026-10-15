//! Network interface facts (R-0013, R-0017): sysfs, procfs and getifaddrs on Linux; on macOS
//! getifaddrs, the routing sysctl's 64-bit `if_data`, `SIOCGIFMEDIA` and sysctl
//! `net.inet.udp.stats` (probe.md §9.6).

#[cfg(target_os = "linux")]
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
#[cfg(target_os = "linux")]
use std::path::Path;

/// Coarse interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfType {
    Loopback,
    Wifi,
    Wwan,
    UsbTether,
    Ethernet,
    Tunnel,
    Virtual,
    Other,
}

impl IfType {
    pub fn name(self) -> &'static str {
        match self {
            IfType::Loopback => "loopback",
            IfType::Wifi => "wifi",
            IfType::Wwan => "wwan",
            IfType::UsbTether => "usb-tether",
            IfType::Ethernet => "ethernet",
            IfType::Tunnel => "tunnel",
            IfType::Virtual => "virtual",
            IfType::Other => "other",
        }
    }
}

/// Facts about one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfInfo {
    pub name: String,
    pub index: u32,
    pub kind: IfType,
    /// Kernel driver (Linux; `None` on macOS).
    pub driver: Option<String>,
    pub mtu: Option<u32>,
    /// Behind USB (Linux; always false on macOS, which does not expose it without IOKit).
    pub usb: bool,
    /// Device transmit queue length in packets (`tx_queue_len`; `None` on macOS, which has no
    /// qdisc, probe.md §9.6).
    pub txqueuelen: Option<u32>,
}

/// Local address the kernel would use to reach `dst` (no packets are sent).
pub fn local_addr_for(dst: SocketAddr) -> io::Result<IpAddr> {
    let bind: SocketAddr = if dst.is_ipv6() {
        "[::]:0".parse().expect("addr")
    } else {
        "0.0.0.0:0".parse().expect("addr")
    };
    let s = UdpSocket::bind(bind)?;
    s.connect(dst)?;
    Ok(s.local_addr()?.ip())
}

/// Name of the interface holding `addr`.
pub fn iface_with_addr(addr: IpAddr) -> io::Result<Option<String>> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list head into `ifap`; freed below with freeifaddrs.
    crate::cvt(unsafe { libc::getifaddrs(&mut ifap) })?;
    let mut found = None;
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list returned by getifaddrs, valid until freeifaddrs.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_addr points at a sockaddr whose family determines its real size; we copy
            // only the bytes the family implies into a zeroed storage.
            let sa = unsafe {
                let fam = (*ifa.ifa_addr).sa_family as libc::c_int;
                let len = match fam {
                    libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
                    libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
                    _ => 0,
                };
                let mut ss: libc::sockaddr_storage = std::mem::zeroed();
                std::ptr::copy_nonoverlapping(
                    ifa.ifa_addr.cast::<u8>(),
                    (&raw mut ss).cast::<u8>(),
                    len,
                );
                crate::udp::sockaddr_to(&ss)
            };
            if sa.map(|s| s.ip()) == Some(addr) {
                // SAFETY: ifa_name is a NUL-terminated C string owned by the list.
                let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
                found = Some(name.to_string_lossy().into_owned());
                break;
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: `ifap` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(ifap) };
    Ok(found)
}

/// Whether a Linux ARP hardware type (`/sys/class/net/<name>/type`) is a layer-3 tunnel
/// (probe.md §9.9): `ARPHRD_NONE` (65534: TUN, WireGuard, xfrm), `ARPHRD_TUNNEL` (768: ipip,
/// vti), `ARPHRD_TUNNEL6` (769: ip6tnl, vti6), `ARPHRD_SIT` (776), `ARPHRD_IPGRE` (778: gre)
/// and `ARPHRD_IP6GRE` (823: ip6gre).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn linux_arphrd_is_tunnel(arphrd: u32) -> bool {
    matches!(arphrd, 65534 | 768 | 769 | 776 | 778 | 823)
}

#[cfg(target_os = "linux")]
fn read_trim(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// Classify an interface from its name, `if_data` type and media word (macOS, R-0017).
/// Tunnels are named `utun`, `ipsec`, `tun` or `tap` (NetworkExtension VPNs, Tailscale and the
/// WireGuard app use `utun`, probe.md §9.9); Wi-Fi and wired Ethernet share the Ethernet type
/// and differ in their media (`IFM_IEEE80211` vs `IFM_ETHER`).
#[cfg(target_os = "macos")]
fn classify_darwin(name: &str, ifi_type: u8, media: Option<i32>) -> IfType {
    // <net/if_types.h> and <net/if_media.h>.
    const IFT_ETHER: u8 = 0x06;
    const IFT_LOOP: u8 = 0x18;
    const IFT_GIF: u8 = 0x37;
    const IFT_STF: u8 = 0x39;
    const IFT_BRIDGE: u8 = 0xd1;
    const IFT_CELLULAR: u8 = 0xff;
    const IFM_NMASK: i32 = 0xe0;
    const IFM_IEEE80211: i32 = 0x80;
    let tunnel = ["utun", "ipsec", "tun", "tap"].iter().any(|p| {
        name.strip_prefix(p)
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
    });
    if ifi_type == IFT_LOOP {
        IfType::Loopback
    } else if tunnel || matches!(ifi_type, IFT_GIF | IFT_STF) {
        IfType::Tunnel
    } else if ifi_type == IFT_CELLULAR || name.starts_with("pdp_ip") {
        IfType::Wwan
    } else if ifi_type == IFT_BRIDGE
        || ["bridge", "awdl", "llw", "anpi", "ap"].iter().any(|p| {
            name.strip_prefix(p)
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
    {
        IfType::Virtual
    } else if ifi_type == IFT_ETHER {
        if media.is_some_and(|m| m & IFM_NMASK == IFM_IEEE80211) {
            IfType::Wifi
        } else {
            IfType::Ethernet
        }
    } else {
        IfType::Other
    }
}

/// The 64-bit `if_data` and index of interface `name` from sysctl `NET_RT_IFLIST2`
/// (`if_msghdr2`); `getifaddrs` would give the 32-bit `if_data`, whose byte counters wrap in
/// 34 s at 1 Gbit/s.
#[cfg(target_os = "macos")]
fn link_data(name: &str) -> Option<(u32, libc::if_data64)> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: `cname` is a valid NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return None;
    }
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        0,
        libc::NET_RT_IFLIST2,
        index as libc::c_int,
    ];
    let buf = sysctl_bytes(&mut mib)?;
    let mut pos = 0;
    while pos + size_of::<libc::if_msghdr2>() <= buf.len() {
        // SAFETY: at least size_of::<if_msghdr2>() bytes remain; read_unaligned copies a
        // plain-data struct out of the byte buffer whatever its alignment. Messages of other
        // types are shorter than that or only their length and type fields are used.
        let h: libc::if_msghdr2 = unsafe { std::ptr::read_unaligned(buf[pos..].as_ptr().cast()) };
        let len = usize::from(h.ifm_msglen);
        if len == 0 {
            break;
        }
        if i32::from(h.ifm_type) == libc::RTM_IFINFO2 && u32::from(h.ifm_index) == index {
            return Some((index, h.ifm_data));
        }
        pos += len;
    }
    None
}

/// Read a sysctl MIB into a buffer of the size the kernel reports.
#[cfg(target_os = "macos")]
fn sysctl_bytes(mib: &mut [libc::c_int]) -> Option<Vec<u8>> {
    let mut len = 0usize;
    // SAFETY: a size query: null output buffer, `len` receives the size.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 || len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` has `len` writable bytes and `len` says so; the kernel writes at most that
    // and stores the written length back.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

/// The current media word (`ifm_current`) of interface `name` (`SIOCGIFMEDIA`), unprivileged.
#[cfg(target_os = "macos")]
fn media(name: &str) -> Option<i32> {
    /// `_IOWR('i', 56, struct ifmediareq)`: `struct ifmediareq` is 44 bytes, the name in its
    /// first 16 and `ifm_current` at offset 16.
    const SIOCGIFMEDIA: libc::c_ulong = 0xc02c_6938;
    let b = name.as_bytes();
    if b.is_empty() || b.len() >= libc::IFNAMSIZ || b.contains(&0) {
        return None;
    }
    // u32 words keep the struct 4-byte aligned; zero leaves `ifm_ulist` null and
    // `ifm_count` 0, so the kernel writes no media list.
    let mut req = [0u32; 11];
    let mut name_bytes = [0u8; 16];
    name_bytes[..b.len()].copy_from_slice(b);
    for (i, w) in name_bytes.as_chunks::<4>().0.iter().enumerate() {
        req[i] = u32::from_ne_bytes(*w);
    }
    // SAFETY: plain socket(2); closed below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: `req` is a 44-byte ifmediareq naming a NUL-terminated interface with a null
    // media list, so the kernel writes only within the struct.
    let r = unsafe { libc::ioctl(fd, SIOCGIFMEDIA, req.as_mut_ptr()) };
    // SAFETY: `fd` is the descriptor opened above, closed exactly once.
    unsafe { libc::close(fd) };
    (r == 0).then_some(req[4] as i32)
}

/// Classify an interface (macOS: from its name, `if_data` type and media word).
#[cfg(target_os = "macos")]
pub fn iface_info(name: &str) -> IfInfo {
    let data = link_data(name);
    let (index, ifi_type, mtu) = data
        .map(|(i, d)| (i, d.ifi_type, Some(d.ifi_mtu)))
        .unwrap_or((0, 0, None));
    IfInfo {
        name: name.to_string(),
        index,
        kind: classify_darwin(name, ifi_type, media(name)),
        driver: None,
        mtu,
        usb: false,
        txqueuelen: None,
    }
}

/// Classify an interface from `/sys/class/net/<name>/` (R-0013).
#[cfg(target_os = "linux")]
pub fn iface_info(name: &str) -> IfInfo {
    let base = Path::new("/sys/class/net").join(name);
    let index = read_trim(&base.join("ifindex"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mtu = read_trim(&base.join("mtu")).and_then(|s| s.parse().ok());
    let txqueuelen = read_trim(&base.join("tx_queue_len")).and_then(|s| s.parse().ok());
    let arphrd: u32 = read_trim(&base.join("type"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let uevent = fs::read_to_string(base.join("uevent")).unwrap_or_default();
    let devtype = uevent
        .lines()
        .find_map(|l| l.strip_prefix("DEVTYPE="))
        .map(str::to_string);
    let driver = fs::read_link(base.join("device/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()));
    let devpath = fs::canonicalize(base.join("device")).ok();
    let usb = devpath
        .as_ref()
        .is_some_and(|p| p.to_string_lossy().contains("/usb"));
    let d = driver.as_deref().unwrap_or("");
    let kind = if arphrd == 772 {
        IfType::Loopback
    } else if base.join("wireless").exists() || devtype.as_deref() == Some("wlan") {
        IfType::Wifi
    } else if devtype.as_deref() == Some("wwan")
        || matches!(d, "qmi_wwan" | "cdc_mbim" | "mhi_net" | "ipa")
    {
        IfType::Wwan
    } else if matches!(d, "rndis_host" | "cdc_ether" | "cdc_ncm" | "ipheth") {
        IfType::UsbTether
    } else if base.join("tun_flags").exists() || linux_arphrd_is_tunnel(arphrd) {
        IfType::Tunnel
    } else if devpath.is_none() {
        IfType::Virtual
    } else if arphrd == 1 {
        IfType::Ethernet
    } else {
        IfType::Other
    };
    IfInfo {
        name: name.to_string(),
        index,
        kind,
        driver,
        mtu,
        usb,
        txqueuelen,
    }
}

/// Interface counters (Linux `/sys/class/net/<if>/statistics`; macOS 64-bit `if_data`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// macOS: `ifi_iqdrops`.
    pub rx_dropped: u64,
    /// 0 where [`crate::PLATFORM`]`.iface_tx_dropped` is false (macOS has no such counter,
    /// R-0017): record it as null there, never as 0 (probe.md §9.6).
    pub tx_dropped: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// Counters of interface `name` from the routing sysctl's 64-bit `if_data`.
#[cfg(target_os = "macos")]
pub fn if_stats(name: &str) -> Option<IfStats> {
    let (_, d) = link_data(name)?;
    Some(IfStats {
        rx_bytes: d.ifi_ibytes,
        tx_bytes: d.ifi_obytes,
        rx_packets: d.ifi_ipackets,
        tx_packets: d.ifi_opackets,
        rx_dropped: d.ifi_iqdrops,
        tx_dropped: 0,
        rx_errors: d.ifi_ierrors,
        tx_errors: d.ifi_oerrors,
    })
}

/// Counters of interface `name` from `/sys/class/net/<name>/statistics`.
#[cfg(target_os = "linux")]
pub fn if_stats(name: &str) -> Option<IfStats> {
    let base = Path::new("/sys/class/net").join(name).join("statistics");
    let r = |f: &str| read_trim(&base.join(f)).and_then(|s| s.parse().ok());
    Some(IfStats {
        rx_bytes: r("rx_bytes")?,
        tx_bytes: r("tx_bytes")?,
        rx_packets: r("rx_packets")?,
        tx_packets: r("tx_packets")?,
        rx_dropped: r("rx_dropped").unwrap_or(0),
        tx_dropped: r("tx_dropped").unwrap_or(0),
        rx_errors: r("rx_errors").unwrap_or(0),
        tx_errors: r("tx_errors").unwrap_or(0),
    })
}

/// Host network-stack drop counters (cumulative; `None` where unreadable): UDP and UDP6 from
/// `/proc/net/snmp` and `/proc/net/snmp6`, softnet backlog drops and squeezes summed over CPUs
/// from `/proc/net/softnet_stat` (R-0015). On macOS only `udp_fullsock` is readable and every
/// other field is `None` (probe.md §9.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StackStats {
    /// macOS `udps_fullsock` (sysctl `net.inet.udp.stats`): host-wide datagrams not delivered
    /// because the receiving socket was full; a 32-bit counter. `None` on Linux (PTF 1.2
    /// `netstack.udp_fullsock`).
    pub udp_fullsock: Option<u64>,
    pub udp_in_errors: Option<u64>,
    pub udp_rcvbuf_errors: Option<u64>,
    pub udp_sndbuf_errors: Option<u64>,
    pub udp_in_csum_errors: Option<u64>,
    pub udp6_in_errors: Option<u64>,
    pub udp6_rcvbuf_errors: Option<u64>,
    pub udp6_sndbuf_errors: Option<u64>,
    pub udp6_in_csum_errors: Option<u64>,
    pub softnet_dropped: Option<u64>,
    pub softnet_squeezed: Option<u64>,
}

/// Value of `field` in the `Udp:` header/value line pair of /proc/net/snmp.
#[cfg(target_os = "linux")]
fn snmp_field(text: &str, proto: &str, field: &str) -> Option<u64> {
    let mut lines = text.lines().filter(|l| l.starts_with(proto));
    let names = lines.next()?;
    let values = lines.next()?;
    let i = names.split_whitespace().position(|n| n == field)?;
    values.split_whitespace().nth(i)?.parse().ok()
}

/// Value of `name` in /proc/net/snmp6 (`name value` per line).
#[cfg(target_os = "linux")]
fn snmp6_field(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == name).then(|| it.next()?.parse().ok())?
    })
}

/// Sum of hex column `col` over every CPU line of /proc/net/softnet_stat.
#[cfg(target_os = "linux")]
fn softnet_sum(text: &str, col: usize) -> Option<u64> {
    let mut any = false;
    let mut sum = 0u64;
    for l in text.lines() {
        let v = u64::from_str_radix(l.split_whitespace().nth(col)?, 16).ok()?;
        sum = sum.wrapping_add(v);
        any = true;
    }
    any.then_some(sum)
}

#[cfg(target_os = "linux")]
fn parse_stack(snmp: &str, snmp6: &str, softnet: &str) -> StackStats {
    let u = |f| snmp_field(snmp, "Udp:", f);
    let u6 = |f| snmp6_field(snmp6, f);
    StackStats {
        udp_fullsock: None,
        udp_in_errors: u("InErrors"),
        udp_rcvbuf_errors: u("RcvbufErrors"),
        udp_sndbuf_errors: u("SndbufErrors"),
        udp_in_csum_errors: u("InCsumErrors"),
        udp6_in_errors: u6("Udp6InErrors"),
        udp6_rcvbuf_errors: u6("Udp6RcvbufErrors"),
        udp6_sndbuf_errors: u6("Udp6SndbufErrors"),
        udp6_in_csum_errors: u6("Udp6InCsumErrors"),
        softnet_dropped: softnet_sum(softnet, 1),
        softnet_squeezed: softnet_sum(softnet, 2),
    }
}

/// `udps_fullsock` from the bytes of a `struct udpstat` (`netinet/udp_var.h`: the seventh
/// u32, offset 24).
#[cfg(target_os = "macos")]
fn udp_fullsock(udpstat: &[u8]) -> Option<u64> {
    let b = udpstat.get(24..28)?;
    Some(u64::from(u32::from_ne_bytes(b.try_into().ok()?)))
}

/// Read the host's stack drop counters: on macOS only `udps_fullsock` (probe.md §9.6).
#[cfg(target_os = "macos")]
pub fn stack_stats() -> StackStats {
    let mut buf = [0u8; 256];
    let mut len = buf.len();
    // SAFETY: the name is a NUL-terminated literal; `buf` has `len` writable bytes and the
    // kernel writes at most that, storing the written length back; nothing is set.
    let r = unsafe {
        libc::sysctlbyname(
            c"net.inet.udp.stats".as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    StackStats {
        udp_fullsock: if r == 0 {
            udp_fullsock(&buf[..len.min(buf.len())])
        } else {
            None
        },
        ..StackStats::default()
    }
}

/// Read the host's (network namespace's) stack drop counters.
#[cfg(target_os = "linux")]
pub fn stack_stats() -> StackStats {
    let r = |p: &str| fs::read_to_string(p).unwrap_or_default();
    parse_stack(
        &r("/proc/net/snmp"),
        &r("/proc/net/snmp6"),
        &r("/proc/net/softnet_stat"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_stack_counters() {
        let snmp = "Ip: Forwarding DefaultTTL\nIp: 1 64\n\
                    Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
                    Udp: 100 2 7 90 5 1 3 0 0\n\
                    UdpLite: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti MemErrors\n\
                    UdpLite: 0 0 0 0 0 0 0 0 0\n";
        let snmp6 = "Udp6InDatagrams                 \t10\nUdp6InErrors 4\nUdp6RcvbufErrors 2\nUdp6SndbufErrors 0\nUdp6InCsumErrors 1\n";
        let softnet = "0000a000 00000002 00000010 00000000\n0000b000 00000003 00000001 00000000\n";
        let s = parse_stack(snmp, snmp6, softnet);
        assert_eq!(s.udp_in_errors, Some(7));
        assert_eq!(s.udp_rcvbuf_errors, Some(5));
        assert_eq!(s.udp_sndbuf_errors, Some(1));
        assert_eq!(s.udp_in_csum_errors, Some(3));
        assert_eq!(s.udp6_in_errors, Some(4));
        assert_eq!(s.udp6_rcvbuf_errors, Some(2));
        assert_eq!(s.udp6_in_csum_errors, Some(1));
        assert_eq!(s.softnet_dropped, Some(5));
        assert_eq!(s.softnet_squeezed, Some(17));
        assert_eq!(parse_stack("", "", ""), StackStats::default());
        // The live files parse on this host.
        assert!(stack_stats().udp_in_errors.is_some());
    }

    #[test]
    fn loopback_facts() {
        let ip = local_addr_for("127.0.0.1:9".parse().unwrap()).unwrap();
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
        let name = iface_with_addr(ip).unwrap().expect("lo");
        let info = iface_info(&name);
        assert_eq!(info.kind, IfType::Loopback);
        assert!(info.index > 0 && info.mtu.is_some(), "{info:?}");
        assert!(if_stats(&name).is_some());
    }

    #[test]
    fn linux_tunnel_arp_types() {
        for t in [65534, 768, 769, 776, 778, 823] {
            assert!(linux_arphrd_is_tunnel(t), "{t}");
        }
        for t in [0, 1, 772, 801] {
            assert!(!linux_arphrd_is_tunnel(t), "{t}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_interface_classes() {
        let ether = 0x06;
        assert_eq!(classify_darwin("lo0", 0x18, None), IfType::Loopback);
        for n in ["utun3", "ipsec0", "tun1", "tap0"] {
            assert_eq!(classify_darwin(n, 0xff, None), IfType::Tunnel, "{n}");
        }
        assert_eq!(classify_darwin("gif0", 0x37, None), IfType::Tunnel);
        assert_eq!(classify_darwin("en0", ether, Some(0x80)), IfType::Wifi);
        assert_eq!(classify_darwin("en7", ether, Some(0x20)), IfType::Ethernet);
        assert_eq!(classify_darwin("en7", ether, None), IfType::Ethernet);
        assert_eq!(classify_darwin("pdp_ip0", 0xff, None), IfType::Wwan);
        assert_eq!(classify_darwin("bridge0", 0xd1, None), IfType::Virtual);
        assert_eq!(classify_darwin("awdl0", ether, Some(0x80)), IfType::Virtual);
        assert_eq!(classify_darwin("utunnel", 0x01, None), IfType::Other);
        assert_eq!(udp_fullsock(&[0; 23]), None);
        let mut st = [0u8; 104];
        st[24..28].copy_from_slice(&7u32.to_ne_bytes());
        assert_eq!(udp_fullsock(&st), Some(7));
    }

    /// probe.md §9.6: on macOS only `udp_fullsock` is readable; the Linux counters are unknown.
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_stack_stats() {
        let s = stack_stats();
        assert!(s.udp_fullsock.is_some(), "{s:?}");
        assert_eq!(
            StackStats {
                udp_fullsock: None,
                ..s
            },
            StackStats::default()
        );
        // The loopback counters advance with traffic.
        let before = if_stats("lo0").unwrap();
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.send_to(&[0; 100], s.local_addr().unwrap()).unwrap();
        let after = if_stats("lo0").unwrap();
        assert!(after.tx_packets > before.tx_packets, "{before:?} {after:?}");
        assert_eq!(after.tx_dropped, 0);
    }
}
