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

#[cfg(test)]
mod tests {
    use super::*;

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
