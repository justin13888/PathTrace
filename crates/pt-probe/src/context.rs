//! Context that cannot be recovered after the session (REQ-PRB-019): host facts, interface,
//! Wi-Fi link state, interface counters, routing changes, clock pairs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use pt_format::{Key, Value};
use pt_sys::clock::ClockPair;
use pt_sys::clock::{mono_raw, pair};
use pt_sys::netif::{IfType, if_stats, iface_info, iface_with_addr, local_addr_for, stack_stats};
use pt_sys::netlink::{Nl80211, QdiscReader, RtMonitor};

use crate::record::{Recorder, pii};

fn read(p: &str) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

/// The value of `key` in an os-release file (`KEY=value`, optionally quoted).
fn os_release_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        l.strip_prefix(key)?
            .strip_prefix('=')
            .map(|v| v.trim_matches('"').to_string())
    })
}

/// Static facts about this host for META (`endpoints.<role>`), with the PTF 1.2 `os_family`
/// and `os_version` (probe.md §9.8).
pub fn host_facts() -> Value {
    let family = pt_sys::PLATFORM.os_family;
    if family == "darwin" {
        return darwin_host_facts();
    }
    let os_release = read("/etc/os-release");
    let field = |k: &str| os_release.as_deref().and_then(|s| os_release_field(s, k));
    let os = field("PRETTY_NAME").unwrap_or_else(|| "unknown".into());
    let cpu = read("/proc/cpuinfo")
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("model name")
                    .map(|v| v.trim_start_matches([' ', '\t', ':']).to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into());
    Value::map()
        .with("os", os)
        .with("os_family", family)
        .with("os_version", field("VERSION_ID"))
        .with(
            "kernel",
            read("/proc/sys/kernel/osrelease").unwrap_or_default(),
        )
        .with("arch", std::env::consts::ARCH)
        .with(
            "hostname",
            read("/proc/sys/kernel/hostname").unwrap_or_default(),
        )
        .with("cpu", cpu)
        .with("cpus", cpus())
        .with(
            "clocksource",
            read("/sys/devices/system/clocksource/clocksource0/current_clocksource")
                .unwrap_or_default(),
        )
        .with(
            "tcp_cc_default",
            read("/proc/sys/net/ipv4/tcp_congestion_control").unwrap_or_default(),
        )
        .with(
            "tcp_cc_available",
            read("/proc/sys/net/ipv4/tcp_available_congestion_control").unwrap_or_default(),
        )
        .with(
            "rmem_max",
            read("/proc/sys/net/core/rmem_max").and_then(|s| s.parse::<u64>().ok()),
        )
        .with(
            "wmem_max",
            read("/proc/sys/net/core/wmem_max").and_then(|s| s.parse::<u64>().ok()),
        )
}

fn cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}

/// macOS host facts from sysctl (probe.md §9.8): `os` is "macOS " and the product version,
/// `kernel` the Darwin release, and `clocksource` is absent (one timebase). The Linux-only
/// procfs facts (congestion control, socket buffer limits) are not recorded.
fn darwin_host_facts() -> Value {
    let s = pt_sys::host::sysctl_string;
    let version = s("kern.osproductversion");
    Value::map()
        .with(
            "os",
            version
                .as_deref()
                .map_or_else(|| "macOS".to_string(), |v| format!("macOS {v}")),
        )
        .with("os_family", "darwin")
        .with("os_version", version)
        .with("kernel", s("kern.osrelease").unwrap_or_default())
        .with("arch", std::env::consts::ARCH)
        .with("hostname", s("kern.hostname").unwrap_or_default())
        .with(
            "cpu",
            s("machdep.cpu.brand_string").unwrap_or_else(|| "unknown".into()),
        )
        .with("cpus", cpus())
}

/// Linux link kinds that are tunnels (probe.md §9.9).
const TUNNEL_LINK_KINDS: &[&str] = &[
    "wireguard",
    "tun",
    "ipip",
    "sit",
    "gre",
    "ip6tnl",
    "vti",
    "xfrm",
];

/// macOS tunnel interface name prefixes (probe.md §9.9): NetworkExtension VPNs, Tailscale and
/// the WireGuard app use `utun`.
const TUNNEL_NAME_PREFIXES: &[&str] = &["utun", "ipsec", "tun", "tap"];

/// The tunnel kind of an egress interface, or `None` when it is not a tunnel (probe.md §9.9).
/// `link_kind` is the rtnetlink answer where rtnetlink exists (`Some`, holding the link kind
/// or `None` for a device without one); without rtnetlink (macOS) the interface name's prefix
/// decides.
fn tunnel_kind(link_kind: Option<Option<&str>>, name: &str) -> Option<String> {
    match link_kind {
        Some(k) => k
            .filter(|k| TUNNEL_LINK_KINDS.contains(k))
            .map(str::to_string),
        None => TUNNEL_NAME_PREFIXES
            .iter()
            .find(|p| {
                name.strip_prefix(**p)
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            })
            .map(|p| (*p).to_string()),
    }
}

/// The provider hint of a tunnel from the local address on it: `tailscale` inside
/// 100.64.0.0/10 or fd7a:115c:a1e0::/48 (Tailscale's address ranges), else none.
fn tunnel_provider(local: IpAddr) -> Option<&'static str> {
    let tailscale = match local {
        IpAddr::V4(a) => {
            let o = a.octets();
            o[0] == 100 && o[1] & 0xc0 == 64
        }
        IpAddr::V6(a) => a.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    };
    tailscale.then_some("tailscale")
}

/// META `endpoint.iface.tunnel {kind, provider}` of interface `name` holding the local address
/// `local`, or `None` when it is not a tunnel (PTF 1.2, probe.md §9.9).
pub fn tunnel_fact(name: &str, index: u32, local: Option<IpAddr>) -> Option<Value> {
    // Without rtnetlink (macOS, or a failed query) the interface name decides.
    let link_kind = pt_sys::netlink::link_kind(index).ok();
    let kind = tunnel_kind(link_kind.as_ref().map(Option::as_deref), name)?;
    Some(
        Value::map()
            .with("kind", kind)
            .with("provider", local.and_then(tunnel_provider)),
    )
}

/// NetworkManager metered state via `nmcli` with a timeout (R-0013). Runs before measurement,
/// never during. Returns `unknown` if NetworkManager is unavailable.
pub fn metered(iface: &str) -> String {
    let child = std::process::Command::new("nmcli")
        .args(["-t", "-g", "GENERAL.METERED", "device", "show", iface])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return "unknown".into();
    };
    for _ in 0..30 {
        if let Ok(Some(_)) = child.try_wait() {
            let mut out = String::new();
            if let Some(mut so) = child.stdout.take() {
                use std::io::Read;
                let _ = so.read_to_string(&mut out);
            }
            let v = out.trim();
            return if v.is_empty() {
                "unknown".into()
            } else {
                v.to_string()
            };
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    "unknown".into()
}

/// Interface facts for META. `local` is this host's address on the interface, which names
/// the tunnel provider (`tunnel`, PTF 1.2, present only when the interface is a tunnel).
pub fn iface_facts(name: &str, local: Option<IpAddr>) -> Value {
    let i = iface_info(name);
    let v = Value::map()
        .with("name", i.name.clone())
        .with("index", i.index)
        .with("type", i.kind.name())
        .with("driver", i.driver.clone())
        .with("mtu", i.mtu)
        .with("usb", i.usb);
    match tunnel_fact(name, i.index, local) {
        Some(t) => v.with("tunnel", t),
        None => v,
    }
}

/// The detail of an `iface_change` event (probe.md §4.4). Interface names are `pii: quasi`, as
/// META's `/endpoint/iface/name`; only top-level detail values carry a `pii` wrapper, so the
/// name is dropped from `iface` (`to` carries it).
fn iface_change_detail(
    from: Option<String>,
    to: &str,
    mut iface: Value,
    qdisc: Value,
    txqueuelen: Option<u32>,
    local: IpAddr,
) -> Value {
    if let Value::Map(m) = &mut iface {
        m.remove(&Key::from("name"));
    }
    Value::map()
        .with("from", pii(from, "quasi"))
        .with("to", pii(to, "quasi"))
        .with("iface", iface)
        .with("qdisc", qdisc)
        .with("txqueuelen", txqueuelen)
        .with("addr", pii(local.to_string(), "id"))
}

/// Egress queueing facts for META (`endpoint.qdisc`, `endpoint.txqueuelen`; PTF 1.1).
pub fn egress_facts(name: &str) -> (Value, Option<u32>) {
    let i = iface_info(name);
    let q = QdiscReader::open()
        .ok()
        .and_then(|mut r| r.root(i.index).ok().flatten());
    let v = match q {
        Some(q) => Value::map()
            .with("kind", q.kind.as_str())
            .with("handle", q.handle),
        None => Value::Null,
    };
    (v, i.txqueuelen)
}

fn pair_row(p: &ClockPair) -> Vec<Option<i64>> {
    vec![
        Some(p.mono as i64),
        Some(p.real as i64),
        Some(p.width as i64),
        Some(p.boot as i64),
    ]
}

/// Background sampler: interface, stack and qdisc counters (10 Hz), Wi-Fi (1 Hz), clock pairs
/// (1 Hz), routing events (docs/design/probe.md §1, §4.2).
#[derive(Debug)]
pub struct Sampler {
    stop: Arc<AtomicBool>,
    h: Option<JoinHandle<()>>,
}

impl Sampler {
    /// Sample `iface`, then follow the interface that carries the route to `peer` whenever
    /// routing changes (docs/design/probe.md §4.4). Wi-Fi link state is sampled only when
    /// `wifi` is set and the followed interface is Wi-Fi.
    pub fn start(
        iface: Option<String>,
        peer: Option<IpAddr>,
        rec: Recorder,
        wifi: bool,
    ) -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let h = std::thread::Builder::new()
            .name("context".into())
            .spawn(move || run(iface, peer, rec, wifi, s2))
            .expect("spawn context thread");
        Sampler { stop, h: Some(h) }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.h.take() {
            let _ = h.join();
        }
    }
}

/// The interface the sampler follows, identified by name and index (a re-created interface
/// keeps its name but gets a new index and fresh counters).
#[derive(Debug, Default)]
struct Follow {
    cur: Option<(String, u32)>,
}

impl Follow {
    /// Take the interface the route to the peer now uses. Returns the previous one when it
    /// changed; an unresolved route (`None`, as in the middle of a switch) keeps the current.
    fn update(&mut self, resolved: Option<(String, u32)>) -> Option<Option<(String, u32)>> {
        let to = resolved.filter(|(n, _)| !n.is_empty())?;
        if self.cur.as_ref() == Some(&to) {
            return None;
        }
        Some(self.cur.replace(to))
    }
}

/// The local address the kernel would use to reach `peer`, and the interface holding it.
/// Nothing is sent.
fn route_to(peer: IpAddr) -> Option<(IpAddr, String)> {
    let local = local_addr_for(SocketAddr::new(peer, 9)).ok()?;
    let name = iface_with_addr(local).ok().flatten()?;
    Some((local, name))
}

fn open_wifi(rec: &Recorder) -> Option<Nl80211> {
    match Nl80211::open() {
        Ok(n) => Some(n),
        Err(e) => {
            rec.event(
                "wifi_unavailable",
                Value::map().with("error", e.to_string()),
            );
            None
        }
    }
}

fn run(
    iface: Option<String>,
    peer: Option<IpAddr>,
    rec: Recorder,
    wifi: bool,
    stop: Arc<AtomicBool>,
) {
    let mut info = iface.as_deref().filter(|n| !n.is_empty()).map(iface_info);
    let mut follow = Follow {
        cur: info.as_ref().map(|i| (i.name.clone(), i.index)),
    };
    let mut nl = None;
    let mut wifi_tried = false;
    if wifi && info.as_ref().is_some_and(|i| i.kind == IfType::Wifi) {
        wifi_tried = true;
        nl = open_wifi(&rec);
    }
    let rt = RtMonitor::open().ok();
    let mut qd = QdiscReader::open().ok();
    let mut tick = 0u64;
    let mut wifi_rows = Vec::new();
    let mut if_rows = Vec::new();
    let mut pair_rows = Vec::new();
    let mut stack_rows = Vec::new();
    let mut qdisc_rows = Vec::new();
    let u = |v: Option<u64>| v.map(|x| x as i64);
    while !stop.load(Ordering::Relaxed) {
        let t = mono_raw();
        let st = stack_stats();
        stack_rows.push(vec![
            Some(t as i64),
            u(st.udp_in_errors),
            u(st.udp_rcvbuf_errors),
            u(st.udp_sndbuf_errors),
            u(st.udp_in_csum_errors),
            u(st.udp6_in_errors),
            u(st.udp6_rcvbuf_errors),
            u(st.udp6_sndbuf_errors),
            u(st.udp6_in_csum_errors),
            u(st.softnet_dropped),
            u(st.softnet_squeezed),
            u(st.udp_fullsock),
        ]);
        if let (Some(r), Some(i)) = (qd.as_mut(), info.as_ref())
            && let Ok(q) = r.root(i.index)
        {
            let q = q.unwrap_or_default();
            let has = !q.kind.is_empty();
            let v = |x: u64| has.then_some(x as i64);
            qdisc_rows.push(vec![
                Some(t as i64),
                v(q.bytes),
                v(q.packets),
                v(u64::from(q.drops)),
                v(u64::from(q.requeues)),
                v(u64::from(q.overlimits)),
                v(u64::from(q.qlen)),
                v(u64::from(q.backlog)),
            ]);
        }
        if let Some(i) = info.as_ref()
            && let Some(s) = if_stats(&i.name)
        {
            if_rows.push(vec![
                Some(t as i64),
                Some(s.rx_bytes as i64),
                Some(s.tx_bytes as i64),
                Some(s.rx_packets as i64),
                Some(s.tx_packets as i64),
                Some(s.rx_dropped as i64),
                // A counter the platform lacks is unknown, never 0 (probe.md §9.6).
                pt_sys::PLATFORM
                    .iface_tx_dropped
                    .then_some(s.tx_dropped as i64),
                Some(s.rx_errors as i64),
                Some(s.tx_errors as i64),
            ]);
        }
        if tick.is_multiple_of(10) {
            pair_rows.push(pair_row(&pair(8)));
            if let (Some(n), Some(i)) = (nl.as_mut(), info.as_ref())
                && i.kind == IfType::Wifi
                && let Ok(w) = n.sample(i.index)
            {
                let bss = w.bssid.map(|b| {
                    let h = blake3::hash(&b);
                    i64::from_le_bytes(h.as_bytes()[..8].try_into().expect("8")) & i64::MAX
                });
                wifi_rows.push(vec![
                    Some(t as i64),
                    w.freq_mhz.map(i64::from),
                    w.channel_width.map(i64::from),
                    w.signal_dbm.map(i64::from),
                    w.beacon_signal_dbm.map(i64::from),
                    w.tx_bitrate.map(i64::from),
                    w.rx_bitrate.map(i64::from),
                    w.tx_retries.map(i64::from),
                    w.tx_failed.map(i64::from),
                    bss,
                ]);
            }
            rec.rows("ifstats", std::mem::take(&mut if_rows));
            rec.rows("netstack", std::mem::take(&mut stack_rows));
            rec.rows("qdisc", std::mem::take(&mut qdisc_rows));
            rec.rows("wifi", std::mem::take(&mut wifi_rows));
            rec.rows("pairs", std::mem::take(&mut pair_rows));
        }
        // Without rtnetlink the route to the peer is re-resolved once per second.
        let mut recheck = rt.is_none() && tick.is_multiple_of(10);
        if let Some(m) = rt.as_ref() {
            let mut evs = Vec::new();
            match m.poll_events(&mut evs) {
                Ok(()) => {}
                Err(e) => {
                    recheck = true;
                    rec.event(
                        "rtnetlink_overrun",
                        Value::map().with("error", e.to_string()),
                    );
                }
            }
            recheck |= !evs.is_empty();
            for e in evs {
                rec.event(
                    e.kind.name(),
                    Value::map()
                        .with("ifindex", e.ifindex)
                        .with("default_route", e.default_route)
                        .with("addr", pii(e.addr.map(|a| a.to_string()), "id")),
                );
            }
        }
        if recheck && let Some((local, name)) = peer.and_then(route_to) {
            let to = iface_info(&name);
            if let Some(from) = follow.update(Some((to.name.clone(), to.index))) {
                let (qdisc, txqueuelen) = egress_facts(&name);
                rec.event(
                    "iface_change",
                    iface_change_detail(
                        from.map(|f| f.0),
                        &name,
                        iface_facts(&name, Some(local)),
                        qdisc,
                        txqueuelen,
                        local,
                    ),
                );
                if wifi && to.kind == IfType::Wifi && nl.is_none() && !wifi_tried {
                    wifi_tried = true;
                    nl = open_wifi(&rec);
                }
                info = Some(to);
            }
        }
        tick += 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    pair_rows.push(pair_row(&pair(8)));
    rec.rows("ifstats", if_rows);
    rec.rows("netstack", stack_rows);
    rec.rows("qdisc", qdisc_rows);
    rec.rows("wifi", wifi_rows);
    rec.rows("pairs", pair_rows);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(name: &str, index: u32) -> Option<(String, u32)> {
        Some((name.to_string(), index))
    }

    #[test]
    fn follow_reports_each_switch_once() {
        let mut f = Follow {
            cur: at("wlan0", 3),
        };
        assert_eq!(f.update(at("wlan0", 3)), None);
        // Mid-switch there is no route to the peer: keep sampling the current interface.
        assert_eq!(f.update(None), None);
        assert_eq!(f.update(at("", 0)), None);
        assert_eq!(f.update(at("usb0", 7)), Some(at("wlan0", 3)));
        assert_eq!(f.update(at("usb0", 7)), None);
        // Re-plugged: same name, new index, fresh counters.
        assert_eq!(f.update(at("usb0", 9)), Some(at("usb0", 7)));
        // A session that started without a known interface picks the first one it resolves.
        let mut f = Follow::default();
        assert_eq!(f.update(at("eth0", 2)), Some(None));
    }

    #[test]
    fn iface_change_tags_names_at_top_level() {
        let iface = Value::map().with("name", "usb0").with("index", 7u32);
        let d = iface_change_detail(
            Some("wlan0".into()),
            "usb0",
            iface,
            Value::Null,
            Some(1000),
            "10.0.0.2".parse().unwrap(),
        );
        for (k, v, class) in [
            ("from", "wlan0", "quasi"),
            ("to", "usb0", "quasi"),
            ("addr", "10.0.0.2", "id"),
        ] {
            let w = d.get(k).unwrap();
            assert_eq!(w.get("pii").and_then(Value::as_str), Some(class), "{k}");
            assert_eq!(w.get("value").and_then(Value::as_str), Some(v), "{k}");
        }
        let iface = d.get("iface").unwrap();
        assert!(iface.get("name").is_none());
        assert_eq!(iface.get("index").and_then(Value::as_u64), Some(7));
    }

    #[test]
    fn resolves_loopback_route() {
        let (local, name) = route_to("127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(local, "127.0.0.1".parse::<IpAddr>().unwrap());
        // `lo` on Linux, `lo0` on macOS.
        assert!(name.starts_with("lo"), "{name}");
        // Loopback is not a tunnel on either platform.
        assert!(iface_facts(&name, Some(local)).get("tunnel").is_none());
    }

    #[test]
    fn classifies_linux_link_kinds() {
        for k in TUNNEL_LINK_KINDS {
            assert_eq!(tunnel_kind(Some(Some(*k)), "x0").as_deref(), Some(*k));
        }
        // rtnetlink answered: the link kind decides, not the name.
        for k in [
            None,
            Some("veth"),
            Some("bridge"),
            Some("vlan"),
            Some("dummy"),
        ] {
            assert_eq!(tunnel_kind(Some(k), "tun0"), None, "{k:?}");
        }
    }

    #[test]
    fn classifies_macos_interface_names() {
        for (name, kind) in [
            ("utun4", Some("utun")),
            ("ipsec0", Some("ipsec")),
            ("tun1", Some("tun")),
            ("tap0", Some("tap")),
            ("utun", None),
            ("utunnel", None),
            ("en0", None),
            ("lo0", None),
            ("bridge100", None),
        ] {
            assert_eq!(tunnel_kind(None, name).as_deref(), kind, "{name}");
        }
    }

    #[test]
    fn tailscale_address_ranges() {
        for (a, p) in [
            ("100.64.0.1", Some("tailscale")),
            ("100.101.102.103", Some("tailscale")),
            ("100.127.255.254", Some("tailscale")),
            ("100.63.255.255", None),
            ("100.128.0.1", None),
            ("10.0.0.1", None),
            ("fd7a:115c:a1e0::1", Some("tailscale")),
            ("fd7a:115c:a1e1::1", None),
            ("2001:db8::1", None),
        ] {
            assert_eq!(tunnel_provider(a.parse().unwrap()), p, "{a}");
        }
    }

    #[test]
    fn os_release_fields() {
        let t = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nID=ubuntu\n";
        assert_eq!(os_release_field(t, "VERSION_ID").as_deref(), Some("24.04"));
        assert_eq!(
            os_release_field(t, "PRETTY_NAME").as_deref(),
            Some("Ubuntu 24.04.1 LTS")
        );
        assert_eq!(os_release_field(t, "ID").as_deref(), Some("ubuntu"));
        assert_eq!(os_release_field(t, "VERSION"), None);
    }

    /// PTF 1.2 host identity (probe.md §9.8) on the platform the tests run on.
    #[test]
    fn host_facts_carry_the_platform() {
        let f = host_facts();
        let family = pt_sys::PLATFORM.os_family;
        assert_eq!(f.get("os_family").and_then(Value::as_str), Some(family));
        if family == "darwin" {
            let v = f.get("os_version").and_then(Value::as_str).unwrap();
            assert_eq!(
                f.get("os").and_then(Value::as_str),
                Some(format!("macOS {v}").as_str())
            );
            assert!(f.get("clocksource").is_none());
            assert!(
                f.get("kernel")
                    .and_then(Value::as_str)
                    .is_some_and(|k| !k.is_empty())
            );
        } else {
            assert!(f.get("clocksource").is_some());
        }
    }
}
