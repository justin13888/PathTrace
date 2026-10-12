//! Network interface facts from sysfs and getifaddrs (R-0013).

use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
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
    pub driver: Option<String>,
    pub mtu: Option<u32>,
    pub usb: bool,
    /// Device transmit queue length in packets (`tx_queue_len`).
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

fn read_trim(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// Classify an interface from /sys/class/net/<name>/ (R-0013).
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
    } else if base.join("tun_flags").exists()
        || arphrd == 65534
        || matches!(arphrd, 768 | 769 | 776)
    {
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

/// Interface counters (/sys/class/net/<if>/statistics).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

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
/// from `/proc/net/softnet_stat` (R-0015).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StackStats {
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
fn snmp_field(text: &str, proto: &str, field: &str) -> Option<u64> {
    let mut lines = text.lines().filter(|l| l.starts_with(proto));
    let names = lines.next()?;
    let values = lines.next()?;
    let i = names.split_whitespace().position(|n| n == field)?;
    values.split_whitespace().nth(i)?.parse().ok()
}

/// Value of `name` in /proc/net/snmp6 (`name value` per line).
fn snmp6_field(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        (it.next()? == name).then(|| it.next()?.parse().ok())?
    })
}

/// Sum of hex column `col` over every CPU line of /proc/net/softnet_stat.
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

fn parse_stack(snmp: &str, snmp6: &str, softnet: &str) -> StackStats {
    let u = |f| snmp_field(snmp, "Udp:", f);
    let u6 = |f| snmp6_field(snmp6, f);
    StackStats {
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

/// Read the host's (network namespace's) stack drop counters.
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
        assert!(if_stats(&name).is_some());
    }
}
