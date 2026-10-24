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
use pt_sys::netif::{
    IfInfo, IfType, if_stats, iface_info, iface_with_addr, local_addr_for, stack_stats,
};
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
    "ip6gre",
    "ip6tnl",
    "vti",
    "vti6",
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

/// A tunnel egress interface as probe.md §9.9 classifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tunnel {
    /// The rtnetlink link kind on Linux, the name prefix on macOS.
    pub kind: String,
    /// The provider hint from the local address (`tailscale`), when one matches.
    pub provider: Option<&'static str>,
}

/// The tunnel classification of interface `name` (index `index`) holding the local address
/// `local`, or `None` when it is not a tunnel (probe.md §9.9). The one classifier behind META
/// `endpoint.iface.tunnel` and `doctor`'s `tunnel` check.
pub fn tunnel(name: &str, index: u32, local: Option<IpAddr>) -> Option<Tunnel> {
    // Without rtnetlink (macOS, or a failed query) the interface name decides.
    let link_kind = pt_sys::netlink::link_kind(index).ok();
    let kind = tunnel_kind(link_kind.as_ref().map(Option::as_deref), name)?;
    Some(Tunnel {
        kind,
        provider: local.and_then(tunnel_provider),
    })
}

/// META `endpoint.iface.tunnel {kind, provider}` of interface `name` holding the local address
/// `local`, or `None` when it is not a tunnel (PTF 1.2, probe.md §9.9).
pub fn tunnel_fact(name: &str, index: u32, local: Option<IpAddr>) -> Option<Value> {
    tunnel(name, index, local).map(|t| {
        Value::map()
            .with("kind", t.kind)
            .with("provider", t.provider)
    })
}

/// The metered state of `iface` (probe.md §9.11). Runs before measurement, never during. On
/// macOS it is Network.framework's path cost ([`metered_from_cost`]); on Linux, where that
/// reader is unsupported, NetworkManager's state via `nmcli`. `unknown` when neither answers.
pub fn metered(iface: &str) -> String {
    match pt_sys::netpath::path_cost(iface, Duration::from_secs(2)) {
        Ok(cost) => metered_from_cost(cost),
        Err(e) if e.kind() == std::io::ErrorKind::Unsupported => nm_metered(iface),
        Err(_) => "unknown".into(),
    }
}

/// The metered state of a Network.framework path cost, in the vocabulary
/// [`crate::plan::auto_profile`] reads: `yes (…)` naming the flags that are set, `no`, or
/// `unknown` when the current path does not use the interface (cli.md, "Metered state on
/// macOS").
pub fn metered_from_cost(cost: Option<pt_sys::netpath::PathCost>) -> String {
    let Some(c) = cost else {
        return "unknown".into();
    };
    match (c.expensive, c.constrained) {
        (true, true) => "yes (expensive, constrained)",
        (true, false) => "yes (expensive)",
        (false, true) => "yes (constrained)",
        (false, false) => "no",
    }
    .into()
}

/// NetworkManager metered state via `nmcli` with a timeout (R-0013). Returns `unknown` if
/// NetworkManager is unavailable.
fn nm_metered(iface: &str) -> String {
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

/// One entry of `/sys/class/power_supply` (Linux).
#[derive(Debug, Clone)]
pub struct Supply {
    /// `type`: Mains, Battery, USB, UPS, Wireless.
    pub kind: String,
    /// `scope`: `Device` for a peripheral's battery (mouse, headset), which says nothing about
    /// this machine's power.
    pub scope: String,
    pub online: bool,
    /// `status` of a battery: Charging, Discharging, Full, Not charging.
    pub status: String,
}

/// The entries of `/sys/class/power_supply`; empty where it does not exist (macOS, most VMs).
pub fn read_supplies() -> Vec<Supply> {
    let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") else {
        return Vec::new();
    };
    let attr = |d: &std::path::Path, a: &str| {
        std::fs::read_to_string(d.join(a))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    rd.flatten()
        .map(|e| {
            let d = e.path();
            Supply {
                kind: attr(&d, "type"),
                scope: attr(&d, "scope"),
                online: attr(&d, "online") == "1",
                status: attr(&d, "status"),
            }
        })
        .collect()
}

/// The power source `supplies` describe, in META `power.source` terms (probe.md §4.5): `none`
/// when this machine reports no supply of its own, `ac` (or `ups`) when an external supply is
/// online, `battery` when only a battery is left.
pub fn supply_source(supplies: &[Supply]) -> &'static str {
    let own: Vec<&Supply> = supplies.iter().filter(|s| s.scope != "Device").collect();
    if own.is_empty() {
        return "none";
    }
    if let Some(s) = own.iter().find(|s| s.kind != "Battery" && s.online) {
        return if s.kind == "UPS" { "ups" } else { "ac" };
    }
    if own.iter().any(|s| s.kind == "Battery") {
        "battery"
    } else {
        "unknown"
    }
}

/// META `power.source` of a macOS providing power source.
fn darwin_source(s: &pt_sys::power::PowerSource) -> String {
    use pt_sys::power::PowerSource;
    match s {
        PowerSource::Ac => "ac".into(),
        PowerSource::Battery => "battery".into(),
        PowerSource::Ups => "ups".into(),
        PowerSource::Other(o) if o.is_empty() => "none".into(),
        PowerSource::Other(o) => o.clone(),
    }
}

/// META `endpoint.power {source, low_power}` and the `power` of `host_state` (PTF 1.3,
/// probe.md §4.5).
pub fn power_fact() -> Value {
    if pt_sys::PLATFORM.os_family == "darwin" {
        return match pt_sys::power::power_state() {
            Ok(s) => Value::map()
                .with("source", darwin_source(&s.source))
                .with("low_power", s.low_power_mode),
            Err(_) => Value::map()
                .with("source", "unknown")
                .with("low_power", Value::Null),
        };
    }
    let low = read("/sys/firmware/acpi/platform_profile").map(|p| p == "low-power");
    Value::map()
        .with("source", supply_source(&read_supplies()))
        .with("low_power", low)
}

/// META `endpoint.clock_sync {status, est_error_us, max_error_us}` and the `clock_sync` of
/// `host_state` (PTF 1.3, probe.md §4.5). macOS does not maintain the kernel NTP fields
/// (R-0019), so its state is unknown.
pub fn clock_sync_fact() -> Value {
    let unknown = || {
        Value::map()
            .with("status", "unknown")
            .with("est_error_us", Value::Null)
            .with("max_error_us", Value::Null)
    };
    if pt_sys::PLATFORM.os_family == "darwin" {
        return unknown();
    }
    match pt_sys::clock::ntp_state() {
        Ok(s) => Value::map()
            .with("status", if s.synced { "synced" } else { "unsynced" })
            .with("est_error_us", s.esterror_us)
            .with("max_error_us", s.maxerror_us),
        Err(_) => unknown(),
    }
}

/// META `endpoint.pacing {best_late_ns, policy_error, background}` (PTF 1.3, probe.md §4.5).
/// `best_late_ns` and `background` are null when the check could not run.
pub fn pacing_fact(p: &std::io::Result<pt_sys::clock::PacingCheck>) -> Value {
    match p {
        Ok(p) => Value::map()
            .with("best_late_ns", p.best_late_ns)
            .with("policy_error", p.policy.as_ref().map(|e| e.to_string()))
            .with("background", p.background),
        Err(e) => Value::map()
            .with("best_late_ns", Value::Null)
            .with("policy_error", e.to_string())
            .with("background", Value::Null),
    }
}

/// The interface and local address of the default route of one address family: a route
/// lookup to a documentation address, nothing is sent.
pub fn default_route(v6: bool) -> Option<(String, IpAddr)> {
    let a: SocketAddr = if v6 { "[2001:db8::1]:9" } else { "192.0.2.1:9" }
        .parse()
        .expect("addr");
    let ip = local_addr_for(a).ok()?;
    Some((iface_with_addr(ip).ok().flatten()?, ip))
}

/// The underlay beneath egress interface `egress` (probe.md §4.5): the default-route
/// interface of the family, unless it is `egress` itself or another tunnel.
fn underlay_of(egress: &str, v6: bool) -> Option<(String, IpAddr)> {
    default_route(v6)
        .filter(|(n, ip)| n != egress && tunnel(n, iface_info(n).index, Some(*ip)).is_none())
}

/// META `endpoint.underlay` (PTF 1.3, probe.md §4.5) for egress interface `egress` holding
/// `local`: `None` (key absent) when the egress is not a tunnel, `Null` when no distinct
/// underlay resolves, else the underlay's interface facts.
pub fn underlay_facts(egress: &str, local: IpAddr) -> Option<Value> {
    tunnel(egress, iface_info(egress).index, Some(local))?;
    Some(match underlay_of(egress, local.is_ipv6()) {
        Some((name, ip)) => iface_facts(&name, Some(ip)),
        None => Value::Null,
    })
}

/// The PTF 1.3 host facts of an endpoint for META (`clock_sync`, `power`, `pacing`, and
/// `underlay` when the egress `iface` holding `local` is a tunnel; probe.md §4.5), with the
/// result of the endpoint's pacing check.
pub fn host_state_facts(
    facts: Value,
    iface: &str,
    local: IpAddr,
    pacing: &std::io::Result<pt_sys::clock::PacingCheck>,
) -> Value {
    let v = facts
        .with("clock_sync", clock_sync_fact())
        .with("power", power_fact())
        .with("pacing", pacing_fact(pacing));
    match underlay_facts(iface, local) {
        Some(u) => v.with("underlay", u),
        None => v,
    }
}

/// What a `host_state` event compares (probe.md §4.5): the sync status and the power fact.
/// The NTP error estimates move on every read, so they are recorded but not compared.
fn host_state_key(clock_sync: &Value, power: &Value) -> (Option<Value>, Value) {
    (clock_sync.get("status").cloned(), power.clone())
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

fn is_tunnel(i: &IfInfo) -> bool {
    tunnel(&i.name, i.index, None).is_some()
}

/// The underlay of the followed interface `i` when it is a tunnel (probe.md §4.5).
fn underlay_info(i: &IfInfo, v6: bool) -> Option<IfInfo> {
    if !is_tunnel(i) {
        return None;
    }
    underlay_of(&i.name, v6).map(|(n, _)| iface_info(&n))
}

/// The Wi-Fi link the path crosses: the followed interface, else its underlay (probe.md §4.5).
fn wifi_iface<'a>(info: Option<&'a IfInfo>, under: Option<&'a IfInfo>) -> Option<&'a IfInfo> {
    info.filter(|i| i.kind == IfType::Wifi)
        .or(under.filter(|u| u.kind == IfType::Wifi))
}

/// One `ifstats` / `ifstats_underlay` row of interface `name` at `t`.
fn ifstats_row(t: u64, name: &str) -> Option<Vec<Option<i64>>> {
    let s = if_stats(name)?;
    Some(vec![
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
    ])
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
    // The underlay beneath a tunnel egress (probe.md §4.5), followed like the egress.
    let v6 = peer.is_some_and(|p| p.is_ipv6());
    let mut under = info.as_ref().and_then(|i| underlay_info(i, v6));
    let mut nl = None;
    let mut wifi_tried = false;
    if wifi && wifi_iface(info.as_ref(), under.as_ref()).is_some() {
        wifi_tried = true;
        nl = open_wifi(&rec);
    }
    let mut host_last = host_state_key(&clock_sync_fact(), &power_fact());
    let rt = RtMonitor::open().ok();
    let mut qd = QdiscReader::open().ok();
    let mut tick = 0u64;
    let mut wifi_rows = Vec::new();
    let mut if_rows = Vec::new();
    let mut under_rows = Vec::new();
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
        if let Some(r) = info.as_ref().and_then(|i| ifstats_row(t, &i.name)) {
            if_rows.push(r);
        }
        if let Some(r) = under.as_ref().and_then(|u| ifstats_row(t, &u.name)) {
            under_rows.push(r);
        }
        if tick.is_multiple_of(10) {
            pair_rows.push(pair_row(&pair(8)));
            if let (Some(n), Some(i)) = (nl.as_mut(), wifi_iface(info.as_ref(), under.as_ref()))
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
            rec.rows("ifstats_underlay", std::mem::take(&mut under_rows));
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
                info = Some(to);
            }
        }
        if recheck {
            let now = info.as_ref().and_then(|i| underlay_info(i, v6));
            let tunnel_egress = info.as_ref().is_some_and(is_tunnel);
            // An unresolved underlay keeps the current one while the egress is still a tunnel
            // (as §4.4); an egress that is no longer a tunnel has none.
            let changed = match (&under, &now) {
                (Some(a), Some(b)) => a.name != b.name || a.index != b.index,
                (None, Some(_)) => true,
                (Some(_), None) => !tunnel_egress,
                (None, None) => false,
            };
            if changed {
                let iface = now.as_ref().map(|u| {
                    let mut v = iface_facts(&u.name, None);
                    if let Value::Map(m) = &mut v {
                        m.remove(&Key::from("name"));
                    }
                    v
                });
                rec.event(
                    "underlay_change",
                    Value::map()
                        .with("from", pii(under.as_ref().map(|u| u.name.clone()), "quasi"))
                        .with("to", pii(now.as_ref().map(|u| u.name.clone()), "quasi"))
                        .with("iface", iface),
                );
                under = now;
            }
        }
        if wifi
            && nl.is_none()
            && !wifi_tried
            && wifi_iface(info.as_ref(), under.as_ref()).is_some()
        {
            wifi_tried = true;
            nl = open_wifi(&rec);
        }
        if tick > 0 && tick.is_multiple_of(100) {
            let (cs, pw) = (clock_sync_fact(), power_fact());
            let key = host_state_key(&cs, &pw);
            if key != host_last {
                rec.event(
                    "host_state",
                    Value::map().with("clock_sync", cs).with("power", pw),
                );
                host_last = key;
            }
        }
        tick += 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    pair_rows.push(pair_row(&pair(8)));
    rec.rows("ifstats", if_rows);
    rec.rows("ifstats_underlay", under_rows);
    rec.rows("netstack", stack_rows);
    rec.rows("qdisc", qdisc_rows);
    rec.rows("wifi", wifi_rows);
    rec.rows("pairs", pair_rows);
}

#[cfg(test)]
mod tests {
    use super::*;
    use pt_sys::netpath::PathCost;

    /// Expensive or constrained paths are metered, in the vocabulary `auto_profile` reads.
    #[test]
    fn path_cost_maps_to_metered_state() {
        let cost = |expensive, constrained| {
            metered_from_cost(Some(PathCost {
                expensive,
                constrained,
            }))
        };
        assert_eq!(cost(false, false), "no");
        assert_eq!(cost(true, false), "yes (expensive)");
        assert_eq!(cost(false, true), "yes (constrained)");
        assert_eq!(cost(true, true), "yes (expensive, constrained)");
        assert_eq!(metered_from_cost(None), "unknown");
        for (e, c) in [(true, false), (false, true), (true, true)] {
            assert_eq!(crate::plan::auto_profile(&cost(e, c)), "light");
        }
        assert_eq!(crate::plan::auto_profile(&cost(false, false)), "standard");
    }

    /// An interface no path uses is `unknown` on macOS; Linux reads NetworkManager, which
    /// knows no such device either.
    #[test]
    fn metered_unknown_for_absent_interface() {
        assert_eq!(metered("pt-none0"), "unknown");
    }

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

    fn supply(kind: &str, scope: &str, online: bool, status: &str) -> Supply {
        Supply {
            kind: kind.into(),
            scope: scope.into(),
            online,
            status: status.into(),
        }
    }

    /// META `power.source` from `/sys/class/power_supply` (probe.md §4.5).
    #[test]
    fn supply_sources() {
        assert_eq!(supply_source(&[]), "none");
        // A mouse battery says nothing about this machine.
        assert_eq!(
            supply_source(&[supply("Battery", "Device", false, "Discharging")]),
            "none"
        );
        let bat = || supply("Battery", "", false, "Discharging");
        assert_eq!(supply_source(&[supply("Mains", "", true, ""), bat()]), "ac");
        // USB-C power delivery reports as USB, not Mains.
        assert_eq!(supply_source(&[supply("USB", "", true, ""), bat()]), "ac");
        assert_eq!(supply_source(&[supply("UPS", "", true, "")]), "ups");
        assert_eq!(
            supply_source(&[supply("Mains", "", false, ""), bat()]),
            "battery"
        );
        assert_eq!(supply_source(&[supply("Mains", "", false, "")]), "unknown");
    }

    /// A `host_state` event marks a change of sync status or power, not the NTP error
    /// estimates that move on every read (probe.md §4.5).
    #[test]
    fn host_state_compares_status_and_power() {
        let cs = |status: &str, est: i64| {
            Value::map()
                .with("status", status)
                .with("est_error_us", est)
                .with("max_error_us", est * 2)
        };
        let pw = |source: &str| Value::map().with("source", source).with("low_power", false);
        let base = host_state_key(&cs("synced", 10), &pw("ac"));
        assert_eq!(base, host_state_key(&cs("synced", 250), &pw("ac")));
        assert_ne!(base, host_state_key(&cs("unsynced", 10), &pw("ac")));
        assert_ne!(base, host_state_key(&cs("synced", 10), &pw("battery")));
    }

    /// The host facts every endpoint records (PTF 1.3): known shapes on both platforms, and
    /// no `underlay` key for an egress that is not a tunnel.
    #[test]
    fn host_state_facts_shape() {
        let (local, name) = route_to("127.0.0.1".parse().unwrap()).unwrap();
        let f = host_state_facts(Value::map(), &name, local, &pt_sys::clock::pacing_check());
        let status = f
            .get("clock_sync")
            .and_then(|c| c.get("status"))
            .and_then(Value::as_str);
        assert!(
            matches!(status, Some("synced" | "unsynced" | "unknown")),
            "{status:?}"
        );
        if pt_sys::PLATFORM.os_family == "darwin" {
            assert_eq!(status, Some("unknown"));
        }
        assert!(f.get("power").and_then(|p| p.get("source")).is_some());
        assert!(
            f.get("pacing")
                .and_then(|p| p.get("best_late_ns"))
                .is_some()
        );
        assert!(f.get("underlay").is_none());
        assert!(underlay_facts(&name, local).is_none());
    }

    /// The Wi-Fi link sampled is the followed interface's, else its underlay's (probe.md §4.5).
    #[test]
    fn wifi_follows_the_underlay_of_a_tunnel() {
        let i = |name: &str, kind| IfInfo {
            name: name.into(),
            index: 1,
            kind,
            driver: None,
            mtu: None,
            usb: false,
            txqueuelen: None,
        };
        let wlan = i("wlan0", IfType::Wifi);
        let tun = i("utun4", IfType::Tunnel);
        let eth = i("eth0", IfType::Ethernet);
        assert_eq!(
            wifi_iface(Some(&wlan), None).map(|x| x.name.as_str()),
            Some("wlan0")
        );
        assert_eq!(
            wifi_iface(Some(&tun), Some(&wlan)).map(|x| x.name.as_str()),
            Some("wlan0")
        );
        assert!(wifi_iface(Some(&tun), Some(&eth)).is_none());
        assert!(wifi_iface(Some(&tun), None).is_none());
    }
}
