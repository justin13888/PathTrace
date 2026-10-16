//! `pathtrace doctor`: preflight checks before a field session (REQ-PRB-025). The checks, which
//! of them run on each platform, and why `doctor` opens no session: docs/design/cli.md.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use pt_probe::config::{self, Responder};
use pt_probe::context::Tunnel;
use pt_sys::PLATFORM;
use pt_sys::clock::NtpState;
use pt_sys::netif::{IfInfo, IfType};
use pt_sys::power::{PowerSource, PowerState};
use pt_sys::udp::{MAX_DATAGRAM, OutMsg, SockOpts, UdpSock};

const TCP_TIMEOUT: Duration = Duration::from_secs(3);

/// The oldest supported macOS release (ADR 0014).
const MACOS_FLOOR: u32 = 15;

/// Whether this is the macOS build. Checks branch on [`PLATFORM`], never on `cfg`.
fn darwin() -> bool {
    PLATFORM.os_family == "darwin"
}

/// Sent on every connected TCP port. At least 64 bytes (the responder's connection header), so
/// the responder reads it whole, rejects it, and closes without writing anything.
const HTTP_PROBE: &[u8] = b"GET / HTTP/1.1\r\nHost: pathtrace-doctor.invalid\r\nUser-Agent: pathtrace-doctor\r\nConnection: close\r\n\r\n";

struct Check {
    name: String,
    ok: bool,
    detail: String,
    fatal: bool,
}

fn check(out: &mut Vec<Check>, name: &str, ok: bool, detail: impl Into<String>, fatal: bool) {
    out.push(Check {
        name: name.into(),
        ok,
        detail: detail.into(),
        fatal,
    });
}

/// Verify kernel RX and TX timestamps on loopback. The kernel enables RX timestamping lazily, so
/// the first datagrams after bind may arrive unstamped: keep sending (10 ms apart, up to 0.5 s)
/// until both kinds of stamp have been seen, or only an RX stamp where the platform has no
/// kernel TX stamps (docs/design/cli.md). Returns whether the check passes, and its detail.
fn timestamps() -> (bool, String) {
    let (Ok(a), Ok(b)) = (
        UdpSock::bind("127.0.0.1:0".parse().expect("addr"), SockOpts::default()),
        UdpSock::bind("127.0.0.1:0".parse().expect("addr"), SockOpts::default()),
    ) else {
        return (false, "cannot bind loopback UDP".into());
    };
    let Ok(dst) = b.local_addr() else {
        return (false, "no local addr".into());
    };
    let want_tx = PLATFORM.kernel_tx_stamps;
    let p = [0u8; 64];
    let mut bufs = vec![[0u8; MAX_DATAGRAM]; 4];
    let mut errs = Vec::new();
    let (mut rx, mut tx) = (false, false);
    for i in 0..50 {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = a.send_batch(&[OutMsg {
            dst,
            payload: &p,
            tos: 0,
        }]);
        let mut got = Vec::new();
        let _ = b.poll(10);
        let _ = b.recv_batch(&mut bufs, &mut got);
        rx |= got.iter().any(|m| m.rx_kernel.is_some());
        let _ = a.poll(1);
        let _ = a.drain_errqueue(&mut errs);
        tx |= errs
            .iter()
            .any(|e| matches!(e, pt_sys::udp::ErrEvent::TxStamp { .. }));
        if rx && (tx || !want_tx) {
            break;
        }
    }
    timestamps_detail(rx, tx, want_tx)
}

/// The `kernel timestamps` verdict. Where the platform has no kernel TX stamps (macOS), RX alone
/// passes and the detail says that TX times are user-space (probe.md §9.2).
fn timestamps_detail(rx: bool, tx: bool, want_tx: bool) -> (bool, String) {
    if want_tx {
        (
            rx && tx,
            format!("kernel RX stamps {rx}, kernel TX stamps {tx}"),
        )
    } else {
        (
            rx,
            format!(
                "kernel RX stamps {rx}; TX times are user-space (macOS has no kernel TX stamps)"
            ),
        )
    }
}

/// `ProductVersion` from `/System/Library/CoreServices/SystemVersion.plist`, the file `sw_vers`
/// reads (an XML property list).
fn plist_product_version(plist: &str) -> Option<&str> {
    const KEY: &str = "<key>ProductVersion</key>";
    let rest = plist[plist.find(KEY)? + KEY.len()..]
        .trim_start()
        .strip_prefix("<string>")?;
    Some(rest[..rest.find("</string>")?].trim())
}

/// macOS release at least [`MACOS_FLOOR`].
fn macos_ok(version: &str) -> bool {
    version
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok())
        .is_some_and(|m| m >= MACOS_FLOOR)
}

/// The fatal OS check: `kernel >= 6.1` on Linux, `macos >= 15` on macOS (ADR 0014).
fn os_check(c: &mut Vec<Check>) {
    if darwin() {
        let plist = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
            .unwrap_or_default();
        let v = plist_product_version(&plist)
            .unwrap_or_default()
            .to_string();
        check(c, &format!("macos >= {MACOS_FLOOR}"), macos_ok(&v), v, true);
    } else {
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string();
        let kok = kernel_ok(&kernel);
        check(c, "kernel >= 6.1", kok, kernel, true);
    }
}

/// Kernel release at least 6.1.
fn kernel_ok(release: &str) -> bool {
    let ver: Vec<u32> = release
        .split(['.', '-'])
        .take(2)
        .filter_map(|s| s.parse().ok())
        .collect();
    ver.len() == 2 && (ver[0], ver[1]) >= (6, 1)
}

/// The `clock sync` verdict on Linux, from `adjtimex(2)`.
fn clock_sync(s: &NtpState) -> (bool, String) {
    if s.synced {
        (
            true,
            format!(
                "synchronised (estimated error {} us, maximum {} us)",
                s.esterror_us, s.maxerror_us
            ),
        )
    } else {
        (
            false,
            "not synchronised: start an NTP daemon (chrony, systemd-timesyncd) and wait for sync"
                .into(),
        )
    }
}

/// The `clock sync` verdict on macOS: always unknown. `timed` never writes `esterror`, resets
/// `maxerror` to undocumented values and never sets `STA_UNSYNC` again once cleared, and its own
/// state needs root (R-0019), so no `ntp_adjtime` figure is shown and nothing reads as synchronised.
fn mac_clock_sync() -> (bool, String) {
    (
        false,
        "sync state unknown: macOS does not report it to an unprivileged process; check that \"Set time and date automatically\" is on (System Settings > General > Date & Time)"
            .into(),
    )
}

/// One entry of `/sys/class/power_supply`.
struct Supply {
    /// `type`: Mains, Battery, USB, UPS, Wireless.
    kind: String,
    /// `scope`: `Device` for a peripheral's battery (mouse, headset), which says nothing about
    /// this machine's power.
    scope: String,
    online: bool,
    /// `status` of a battery: Charging, Discharging, Full, Not charging.
    status: String,
}

fn power(supplies: &[Supply]) -> (bool, String) {
    let own: Vec<&Supply> = supplies.iter().filter(|s| s.scope != "Device").collect();
    if own.is_empty() {
        return (true, "no power supply reported (desktop or server)".into());
    }
    if own.iter().any(|s| s.kind != "Battery" && s.online) {
        return (true, "on external power".into());
    }
    match own.iter().find(|s| s.kind == "Battery") {
        Some(b) if b.status == "Discharging" => (
            false,
            "on battery: plug in (power saving adds timing noise)".into(),
        ),
        Some(b) => (true, format!("battery {}", b.status)),
        None => (true, "no battery".into()),
    }
}

/// The `power` check on macOS, from the providing power source and Low Power Mode, with the
/// Linux check's wording where the facts are the same.
fn mac_power(state: &io::Result<PowerState>) -> (bool, String) {
    let s = match state {
        Ok(s) => s,
        Err(e) => return (false, format!("cannot read the power source: {e}")),
    };
    let (ok, source) = match &s.source {
        PowerSource::Ac => (true, "on external power".to_string()),
        PowerSource::Ups => (true, "on UPS power".to_string()),
        PowerSource::Battery => (false, "on battery".to_string()),
        PowerSource::Other(o) if o.is_empty() => (true, "no power source reported".to_string()),
        PowerSource::Other(o) => (true, format!("power source {o}")),
    };
    match (ok, s.low_power_mode) {
        (true, false) => (true, source),
        (false, false) => (
            false,
            format!("{source}: plug in (power saving adds timing noise)"),
        ),
        (true, true) => (
            false,
            format!("{source}, Low Power Mode on: turn it off (power saving adds timing noise)"),
        ),
        (false, true) => (
            false,
            format!(
                "{source}, Low Power Mode on: plug in and turn it off (power saving adds timing noise)"
            ),
        ),
    }
}

fn read_supplies() -> Vec<Supply> {
    let Ok(rd) = std::fs::read_dir("/sys/class/power_supply") else {
        return Vec::new();
    };
    let attr = |d: &Path, a: &str| {
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

/// `powersave` pins the lowest frequency under generic cpufreq drivers; under `intel_pstate`
/// (active mode) and `amd-pstate-epp` it is a dynamic policy.
fn governor(driver: &str, governors: &[String]) -> (bool, String) {
    if governors.is_empty() {
        return (true, "no cpufreq (VM or fixed frequency)".into());
    }
    let pinned = governors.iter().any(|g| g == "powersave")
        && !matches!(driver, "intel_pstate" | "amd-pstate-epp");
    let d = format!("driver {driver}, governor {}", governors.join(","));
    if pinned {
        (
            false,
            format!("{d}: pins the lowest frequency; set schedutil or performance"),
        )
    } else {
        (true, d)
    }
}

fn read_governors() -> (String, Vec<String>) {
    let base = Path::new("/sys/devices/system/cpu");
    let mut govs: Vec<String> = std::fs::read_dir(base)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.strip_prefix("cpu")
                .is_some_and(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter_map(|e| std::fs::read_to_string(e.path().join("cpufreq/scaling_governor")).ok())
        .map(|g| g.trim().to_string())
        .collect();
    govs.sort();
    govs.dedup();
    let driver = std::fs::read_to_string(base.join("cpu0/cpufreq/scaling_driver"))
        .unwrap_or_default()
        .trim()
        .to_string();
    (driver, govs)
}

/// Offloads the `offloads` check reports, in this order (docs/design/cli.md, R-0016).
const OFFLOADS: [&str; 9] = [
    "rx-gro",
    "rx-gro-hw",
    "rx-gro-list",
    "rx-lro",
    "rx-udp-gro-forwarding",
    "tx-generic-segmentation",
    "tx-tcp-segmentation",
    "tx-tcp6-segmentation",
    "tx-udp-segmentation",
];

/// Offloads that change what the probe records on this host, and why: fraglist GRO coalesces
/// the probe's UDP datagrams under one RX timestamp, and LRO merges TCP segments without
/// keeping their headers.
const HARMFUL_OFFLOADS: [(&str, &str); 2] = [
    ("rx-gro-list", "probe datagrams share one RX timestamp"),
    ("rx-lro", "the NIC rewrites received TCP segments"),
];

/// The `offloads` check over the features of `iface`.
fn offloads(
    iface: &str,
    features: &std::io::Result<Vec<pt_sys::ethtool::Feature>>,
) -> (bool, String) {
    let f = match features {
        Ok(f) => f,
        Err(e) => return (false, format!("{iface}: not read: {e}")),
    };
    let on = |name: &str| f.iter().find(|x| x.name == name).map(|x| x.active);
    let state: Vec<String> = OFFLOADS
        .iter()
        .filter_map(|&n| on(n).map(|a| format!("{n} {}", if a { "on" } else { "off" })))
        .collect();
    let mut d = format!("{iface}: {}", state.join(", "));
    let bad: Vec<(&str, &str)> = HARMFUL_OFFLOADS
        .iter()
        .copied()
        .filter(|(n, _)| on(n) == Some(true))
        .collect();
    if bad.is_empty() {
        return (true, d);
    }
    for (n, why) in &bad {
        d.push_str(&format!("; {n} is on: {why}"));
    }
    let names: Vec<String> = bad.iter().map(|(n, _)| format!("{n} off")).collect();
    d.push_str(&format!(
        "; turn off with `sudo ethtool -K {iface} {}`",
        names.join(" ")
    ));
    (false, d)
}

/// Interface and local address of the default route, IPv4 first (a route lookup only: nothing
/// is sent to the documentation addresses).
fn default_route() -> Option<(String, IpAddr)> {
    ["192.0.2.1:9", "[2001:db8::1]:9"].iter().find_map(|a| {
        let ip = pt_sys::netif::local_addr_for(a.parse().expect("addr")).ok()?;
        Some((pt_sys::netif::iface_with_addr(ip).ok().flatten()?, ip))
    })
}

/// The `tunnel` verdict for egress interface `name`: a tunnel warns, because what the probe
/// then measures for some verdicts is the tunnel's behaviour (probe.md §9.9).
fn tunnel_detail(name: &str, tunnel: Option<&Tunnel>) -> (bool, String) {
    let Some(t) = tunnel else {
        return (true, "not a tunnel".into());
    };
    let provider = t
        .provider
        .map_or_else(String::new, |p| format!(", provider {p}"));
    (
        false,
        format!(
            "{name} is a tunnel (kind {}{provider}): per-transport treatment, policers, MTU, DSCP and ECN will describe the tunnel, not the network under it; delay, jitter, loss, capacity and reorder stay end-to-end",
            t.kind
        ),
    )
}

/// The `tunnel` check, classified by the same rule as META `endpoint.iface.tunnel`, so the
/// warning names exactly the kind the trace records.
fn tunnel_check(c: &mut Vec<Check>, info: &IfInfo, local: IpAddr, suffix: &str) {
    let t = pt_probe::context::tunnel(&info.name, info.index, Some(local));
    let (ok, d) = tunnel_detail(&info.name, t.as_ref());
    check(c, &format!("tunnel{suffix}"), ok, d, false);
}

/// What an empty UDP datagram to a port provoked.
#[derive(Debug, PartialEq, Eq)]
enum Udp {
    /// No ICMP error: not rejected, but delivery is unconfirmed.
    NotRefused,
    /// Something answered (the responder never does).
    Answered,
    /// ICMP port unreachable.
    Refused,
    /// ICMP host or network unreachable.
    Unreachable,
    Error(String),
}

/// Map a socket error to a verdict; `None` for a timeout (keep waiting).
fn udp_error(kind: ErrorKind, e: &std::io::Error) -> Option<Udp> {
    match kind {
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => None,
        ErrorKind::ConnectionRefused => Some(Udp::Refused),
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => Some(Udp::Unreachable),
        _ => Some(Udp::Error(e.to_string())),
    }
}

/// Send three empty datagrams 300 ms apart from a connected socket and collect any ICMP error
/// the kernel reports on it (docs/design/cli.md, "`doctor` does not open a session").
fn udp_probe(dst: SocketAddr) -> Udp {
    let any: SocketAddr = if dst.is_ipv6() {
        "[::]:0".parse().expect("addr")
    } else {
        "0.0.0.0:0".parse().expect("addr")
    };
    let s = match UdpSocket::bind(any).and_then(|s| s.connect(dst).map(|()| s)) {
        Ok(s) => s,
        Err(e) => return udp_error(e.kind(), &e).unwrap_or(Udp::Error(e.to_string())),
    };
    if let Err(e) = s.set_read_timeout(Some(Duration::from_millis(300))) {
        return Udp::Error(e.to_string());
    }
    let mut buf = [0u8; 64];
    for _ in 0..3 {
        if let Err(e) = s.send(&[])
            && let Some(v) = udp_error(e.kind(), &e)
        {
            return v;
        }
        match s.recv(&mut buf) {
            Ok(_) => return Udp::Answered,
            Err(e) => {
                if let Some(v) = udp_error(e.kind(), &e) {
                    return v;
                }
            }
        }
    }
    Udp::NotRefused
}

fn udp_detail(v: &Udp) -> (bool, String) {
    match v {
        Udp::NotRefused => (
            true,
            "no ICMP error (delivery unconfirmed: only a session gets a reply; run a smoke probe)"
                .into(),
        ),
        Udp::Answered => (true, "answered".into()),
        Udp::Refused => (
            false,
            "refused (ICMP port unreachable): the responder is not listening there or a firewall rejects UDP".into(),
        ),
        Udp::Unreachable => (false, "ICMP host or network unreachable".into()),
        Udp::Error(e) => (false, e.clone()),
    }
}

/// What came back on a connected TCP port after [`HTTP_PROBE`]. The responder never writes to a
/// connection whose header it rejects, so any bytes come from something in between.
fn interception(reply: &[u8]) -> Option<String> {
    if reply.is_empty() {
        return None;
    }
    if reply.starts_with(b"HTTP/") {
        let line = reply
            .split(|&b| b == b'\r' || b == b'\n')
            .next()
            .unwrap_or(reply);
        return Some(format!(
            "answered HTTP ({}): a captive portal or transparent proxy; log in or use another network",
            String::from_utf8_lossy(line)
        ));
    }
    Some(format!(
        "answered {} bytes the responder never sends: a middlebox intercepts this port",
        reply.len()
    ))
}

fn http_probe(dst: SocketAddr) -> Result<Option<String>, String> {
    let mut s = TcpStream::connect_timeout(&dst, TCP_TIMEOUT).map_err(|e| e.to_string())?;
    let _ = s.set_read_timeout(Some(TCP_TIMEOUT));
    let _ = s.set_write_timeout(Some(TCP_TIMEOUT));
    s.write_all(HTTP_PROBE).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 512];
    let mut n = 0;
    while n < buf.len() {
        match s.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    Ok(interception(&buf[..n]))
}

/// Whether a port is known clean after [`http_probe`], and the check's detail. A probe that
/// could not run (the second connect or the write failed) leaves interception untested, so the
/// port is not clean: it must not count towards `responder reachable`.
fn intercept_detail(r: Result<Option<String>, String>) -> (bool, String) {
    match r {
        Ok(None) => (true, String::new()),
        Ok(Some(d)) => (false, d),
        Err(e) => (false, format!("not tested: {e}")),
    }
}

/// Checks for one address family of the responder. `suffix` is empty for the first family
/// `probe` would use (1.0 check names) and ` (ipv6)`/` (ipv4)` for the other. Returns whether
/// the responder port took a TCP connection that nothing intercepted.
fn family_checks(c: &mut Vec<Check>, dst: SocketAddr, suffix: &str) -> bool {
    if let Ok(ip) = pt_sys::netif::local_addr_for(dst) {
        let iface = pt_sys::netif::iface_with_addr(ip)
            .ok()
            .flatten()
            .unwrap_or_default();
        let info = pt_sys::netif::iface_info(&iface);
        check(
            c,
            &format!("egress interface{suffix}"),
            true,
            format!(
                "{iface} type={} driver={:?} mtu={:?}",
                info.kind.name(),
                info.driver,
                info.mtu
            ),
            false,
        );
        if PLATFORM.offload_features {
            let (ok, d) = offloads(&iface, &pt_sys::ethtool::features(&iface));
            check(c, &format!("offloads{suffix}"), ok, d, false);
        }
        check(
            c,
            &format!("metered{suffix}"),
            true,
            pt_probe::context::metered(&iface),
            false,
        );
        if PLATFORM.wifi_link && info.kind == IfType::Wifi {
            let w = pt_sys::netlink::Nl80211::open().and_then(|mut n| n.sample(info.index));
            check(
                c,
                &format!("wifi link stats{suffix}"),
                w.is_ok(),
                format!("{w:?}"),
                false,
            );
        }
        tunnel_check(c, &info, ip, suffix);
    }
    let main = dst.port();
    let mut reachable = false;
    for port in [main, 443, 80] {
        let a = SocketAddr::new(dst.ip(), port);
        let ok = TcpStream::connect_timeout(&a, TCP_TIMEOUT).is_ok();
        check(
            c,
            &format!("tcp/{port} reachable{suffix}"),
            ok,
            if ok {
                ""
            } else {
                "no connection: closed, filtered, or held by a captive portal until you log in"
            },
            false,
        );
        if !ok {
            continue;
        }
        // Non-fatal per family: `responder reachable` is the fatal summary over all families.
        let (clean, d) = intercept_detail(http_probe(a));
        check(
            c,
            &format!("tcp/{port} not intercepted{suffix}"),
            clean,
            d,
            false,
        );
        reachable |= port == main && clean;
    }
    for port in [main, 443] {
        let (ok, d) = udp_detail(&udp_probe(SocketAddr::new(dst.ip(), port)));
        check(c, &format!("udp/{port} not refused{suffix}"), ok, d, false);
    }
    reachable
}

fn responder_checks(c: &mut Vec<Check>, r: &Responder) {
    let all = match pt_probe::session::resolve(&r.addr, false) {
        Ok((_, all)) => all,
        Err(e) => {
            check(c, "resolve responder", false, e.to_string(), true);
            return;
        }
    };
    check(
        c,
        "resolve responder",
        true,
        all.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        true,
    );
    // `probe` tries IPv4 first unless `--ipv6`, then the other family (probe.md §3.1).
    let mut first = true;
    let mut reachable = false;
    let mut why = Vec::new();
    for (v6, fam) in [(false, "ipv4"), (true, "ipv6")] {
        let Some(&dst) = all.iter().find(|a| a.is_ipv6() == v6) else {
            check(
                c,
                fam,
                false,
                format!("not tested: the responder has no {fam} address"),
                false,
            );
            why.push(format!("no {fam} address"));
            continue;
        };
        match pt_sys::netif::local_addr_for(dst) {
            Ok(ip) => check(c, fam, true, format!("{dst} via local {ip}"), false),
            Err(e) => {
                check(
                    c,
                    fam,
                    false,
                    format!("no local route to {dst}: {e}"),
                    false,
                );
                why.push(format!("{fam}: no route"));
                continue;
            }
        }
        let suffix = if first {
            String::new()
        } else {
            format!(" ({fam})")
        };
        first = false;
        if family_checks(c, dst, &suffix) {
            reachable = true;
        } else {
            why.push(format!(
                "{fam}: tcp/{} unreachable, intercepted, or not tested for interception",
                dst.port()
            ));
        }
    }
    check(
        c,
        "responder reachable",
        reachable,
        if reachable {
            "the responder port takes TCP connections".into()
        } else {
            why.join("; ")
        },
        true,
    );
}

/// The checks of this host alone, in output order. A check that cannot apply on the platform is
/// not run and not shown (docs/design/cli.md, "`doctor` on macOS").
fn local_checks(cfg: &Path) -> Vec<Check> {
    let mut c = Vec::new();
    let linux = !darwin();
    os_check(&mut c);
    match config::load_keypair(cfg) {
        Ok(k) => check(
            &mut c,
            "key",
            true,
            format!("public {}", config::hex(&k.public)),
            true,
        ),
        Err(e) => check(&mut c, "key", false, e.to_string(), true),
    }
    let (ok, d) = timestamps();
    check(&mut c, "kernel timestamps", ok, d, false);
    if linux {
        let cs = std::fs::read_to_string(
            "/sys/devices/system/clocksource/clocksource0/current_clocksource",
        )
        .unwrap_or_default()
        .trim()
        .to_string();
        check(
            &mut c,
            "clocksource",
            cs == "tsc" || cs == "arch_sys_counter",
            cs,
            false,
        );
    }
    let (ok, d) = if linux {
        match pt_sys::clock::ntp_state() {
            Ok(s) => clock_sync(&s),
            Err(e) => (false, format!("adjtimex: {e}")),
        }
    } else {
        mac_clock_sync()
    };
    check(&mut c, "clock sync", ok, d, false);
    // macOS has no /sys/class/power_supply: it reads IOKit power sources instead.
    let (ok, d) = if linux {
        power(&read_supplies())
    } else {
        mac_power(&pt_sys::power::power_state())
    };
    check(&mut c, "power", ok, d, false);
    if PLATFORM.power_assertion {
        let (ok, d) = match pt_sys::power::prevent_idle_sleep("pathtrace doctor") {
            // The assertion is released when `_assertion` goes out of scope at the end of
            // this arm. An explicit drop() trips clippy::drop_non_drop on Linux, where
            // PowerAssertion is a stub without a Drop impl.
            Ok(_assertion) => (true, "a session can keep the system from idle sleep".into()),
            Err(e) => (
                false,
                format!(
                    "cannot create an idle-sleep assertion ({e}): an idle sleep can interrupt a session"
                ),
            ),
        };
        check(&mut c, "sleep assertion", ok, d, false);
    }
    if darwin() {
        // A thread cannot rise above its process's QoS clamp or background policy, so measure
        // whether the pacing policy took effect (probe.md §9.4).
        let (ok, d) = match pt_sys::clock::pacing_check() {
            Ok(p) => pt_probe::io::pacing_verdict(&p),
            Err(e) => (false, format!("cannot run the pacing check: {e}")),
        };
        check(&mut c, "pacing", ok, d, false);
    }
    if linux {
        let (driver, govs) = read_governors();
        let (ok, d) = governor(&driver, &govs);
        check(&mut c, "cpu governor", ok, d, false);
    }
    c
}

pub fn run(cfg: &Path, responder: Option<&Responder>, json: bool) -> ExitCode {
    let mut c = local_checks(cfg);
    if let Some(r) = responder {
        responder_checks(&mut c, r);
    } else if let Some((iface, ip)) = default_route() {
        if PLATFORM.offload_features {
            let (ok, d) = offloads(&iface, &pt_sys::ethtool::features(&iface));
            check(&mut c, "offloads", ok, d, false);
        }
        tunnel_check(&mut c, &pt_sys::netif::iface_info(&iface), ip, "");
    }
    let failed = c.iter().any(|x| !x.ok && x.fatal);
    if json {
        let v: Vec<serde_json::Value> = c.iter().map(|x| serde_json::json!({"check": x.name, "ok": x.ok, "fatal": x.fatal, "detail": x.detail})).collect();
        println!("{}", serde_json::json!({"ok": !failed, "checks": v}));
    } else {
        for x in &c {
            println!(
                "{} {:<34} {}",
                if x.ok {
                    "ok  "
                } else if x.fatal {
                    "FAIL"
                } else {
                    "warn"
                },
                x.name,
                x.detail
            );
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_release() {
        assert!(kernel_ok("6.1.0-13-amd64"));
        assert!(kernel_ok("7.2.4-200.fc44.x86_64"));
        assert!(!kernel_ok("5.15.0-91-generic"));
        assert!(!kernel_ok("garbage"));
    }

    #[test]
    fn clock_sync_reports_errors() {
        let synced = NtpState {
            synced: true,
            esterror_us: 120,
            maxerror_us: 4000,
        };
        let unsynced = NtpState {
            synced: false,
            esterror_us: 0,
            maxerror_us: 16_000_000,
        };
        let (ok, d) = clock_sync(&synced);
        assert_eq!(d, "synchronised (estimated error 120 us, maximum 4000 us)");
        assert!(ok);
        let (ok, d) = clock_sync(&unsynced);
        assert!(!ok && d.contains("NTP") && d.contains("chrony"), "{d}");
    }

    /// macOS cannot show the sync state (R-0019): a warning with the Date & Time advice, no
    /// `ntp_adjtime` figure, no Linux daemon advice, and never "synchronised".
    #[test]
    fn mac_clock_sync_is_unknown() {
        let (ok, d) = mac_clock_sync();
        assert!(!ok, "{d}");
        assert!(d.starts_with("sync state unknown"), "{d}");
        assert!(d.contains("System Settings > General > Date & Time"), "{d}");
        assert!(
            !d.contains(" us") && !d.contains("error") && !d.contains("chrony"),
            "{d}"
        );
        assert!(!d.contains("synchronised"), "{d}");
    }

    #[test]
    fn macos_version_floor() {
        let plist = "<?xml version=\"1.0\"?>\n<plist version=\"1.0\">\n<dict>\n\t<key>ProductUserVisibleVersion</key>\n\t<string>26.6.1</string>\n\t<key>ProductVersion</key>\n\t<string>15.7.1</string>\n</dict>\n</plist>\n";
        assert_eq!(plist_product_version(plist), Some("15.7.1"));
        assert_eq!(plist_product_version("<dict></dict>"), None);
        assert_eq!(
            plist_product_version("<key>ProductVersion</key><integer>1</integer>"),
            None
        );
        assert!(macos_ok("15.0"));
        assert!(macos_ok("26.6.1"));
        assert!(!macos_ok("14.7.2"));
        assert!(!macos_ok(""));
        assert!(!macos_ok("garbage"));
    }

    #[test]
    fn timestamps_without_kernel_tx() {
        assert_eq!(
            timestamps_detail(true, false, true),
            (
                false,
                "kernel RX stamps true, kernel TX stamps false".into()
            )
        );
        assert!(timestamps_detail(true, true, true).0);
        let (ok, d) = timestamps_detail(true, false, false);
        assert!(ok && d.contains("user-space"), "{d}");
        assert!(!timestamps_detail(false, false, false).0);
    }

    /// The local checks on this platform, by name: Linux-only checks are not shown on macOS.
    #[test]
    fn local_check_list_per_platform() {
        let c = local_checks(Path::new("/nonexistent/pathtrace-doctor-test"));
        let names: Vec<&str> = c.iter().map(|x| x.name.as_str()).collect();
        if darwin() {
            assert_eq!(
                names,
                [
                    "macos >= 15",
                    "key",
                    "kernel timestamps",
                    "clock sync",
                    "power",
                    "sleep assertion",
                    "pacing"
                ]
            );
            // A supported Mac has no fatal finding but the missing key.
            for x in &c {
                assert!(
                    x.ok || !x.fatal || x.name == "key",
                    "{}: {}",
                    x.name,
                    x.detail
                );
                assert!(!x.detail.contains("ethtool"), "{}", x.detail);
            }
            // The row is the unknown verdict, whatever ntp_adjtime would say (R-0019).
            let cs = c.iter().find(|x| x.name == "clock sync").unwrap();
            assert_eq!((cs.ok, cs.detail.clone()), mac_clock_sync());
        } else {
            assert_eq!(
                names,
                [
                    "kernel >= 6.1",
                    "key",
                    "kernel timestamps",
                    "clocksource",
                    "clock sync",
                    "power",
                    "cpu governor"
                ]
            );
        }
    }

    #[test]
    fn tunnel_warning() {
        assert_eq!(tunnel_detail("en0", None), (true, "not a tunnel".into()));
        let wg = Tunnel {
            kind: "wireguard".into(),
            provider: None,
        };
        let (ok, d) = tunnel_detail("wg0", Some(&wg));
        assert!(!ok);
        assert!(d.starts_with("wg0 is a tunnel (kind wireguard): "), "{d}");
        assert!(d.contains("policers") && d.contains("DSCP"), "{d}");
        let ts = Tunnel {
            kind: "utun".into(),
            provider: Some("tailscale"),
        };
        let (_, d) = tunnel_detail("utun4", Some(&ts));
        assert!(
            d.starts_with("utun4 is a tunnel (kind utun, provider tailscale): "),
            "{d}"
        );
    }

    #[test]
    fn tunnel_check_on_loopback() {
        // The shared classifier (pt_probe::context::tunnel) decides: loopback is not a tunnel
        // on either platform, so the check is `ok`.
        let name = if darwin() { "lo0" } else { "lo" };
        let mut c = Vec::new();
        tunnel_check(
            &mut c,
            &pt_sys::netif::iface_info(name),
            "127.0.0.1".parse().unwrap(),
            " (IPv4)",
        );
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name, "tunnel (IPv4)");
        assert!(c[0].ok && !c[0].fatal, "{}", c[0].detail);
        assert_eq!(c[0].detail, "not a tunnel");
    }

    fn supply(kind: &str, scope: &str, online: bool, status: &str) -> Supply {
        Supply {
            kind: kind.into(),
            scope: scope.into(),
            online,
            status: status.into(),
        }
    }

    #[test]
    fn power_states() {
        assert!(power(&[]).0);
        // A mouse battery says nothing about this machine.
        assert!(power(&[supply("Battery", "Device", false, "Discharging")]).0);
        let ac = supply("Mains", "", true, "");
        let bat = supply("Battery", "", false, "Discharging");
        assert!(power(&[supply("Mains", "", true, ""), bat]).0);
        let (ok, d) = power(&[
            supply("Mains", "", false, ""),
            supply("Battery", "", false, "Discharging"),
        ]);
        assert!(!ok && d.contains("battery"), "{d}");
        assert!(power(&[ac, supply("Battery", "", false, "Full")]).0);
        // USB-C power delivery reports as USB, not Mains.
        assert!(
            power(&[
                supply("USB", "", true, ""),
                supply("Battery", "", false, "Charging")
            ])
            .0
        );
    }

    #[test]
    fn mac_power_states() {
        let st = |source, low_power_mode| {
            Ok(PowerState {
                source,
                low_power_mode,
            })
        };
        assert_eq!(
            mac_power(&st(PowerSource::Ac, false)),
            (true, "on external power".into())
        );
        assert_eq!(
            mac_power(&st(PowerSource::Ups, false)),
            (true, "on UPS power".into())
        );
        // The same advice as a discharging battery on Linux.
        assert_eq!(
            mac_power(&st(PowerSource::Battery, false)),
            (
                false,
                "on battery: plug in (power saving adds timing noise)".into()
            )
        );
        let (ok, d) = mac_power(&st(PowerSource::Ac, true));
        assert!(!ok && d.contains("Low Power Mode on: turn it off"), "{d}");
        let (ok, d) = mac_power(&st(PowerSource::Battery, true));
        assert!(
            !ok && d.starts_with("on battery, Low Power Mode on: plug in"),
            "{d}"
        );
        assert!(mac_power(&st(PowerSource::Other(String::new()), false)).0);
        assert_eq!(
            mac_power(&st(PowerSource::Other("Weird".into()), false)),
            (true, "power source Weird".into())
        );
        let (ok, d) = mac_power(&Err(io::Error::other("boom")));
        assert!(!ok && d.contains("boom"), "{d}");
    }

    #[test]
    fn governors() {
        assert!(governor("", &[]).0);
        assert!(governor("intel_pstate", &["powersave".into()]).0);
        assert!(governor("amd-pstate-epp", &["powersave".into()]).0);
        assert!(governor("acpi-cpufreq", &["schedutil".into()]).0);
        assert!(!governor("acpi-cpufreq", &["powersave".into()]).0);
        assert!(!governor("intel_cpufreq", &["performance".into(), "powersave".into()]).0);
    }

    fn feature(name: &str, active: bool) -> pt_sys::ethtool::Feature {
        pt_sys::ethtool::Feature {
            name: name.into(),
            available: true,
            requested: active,
            active,
            never_changed: false,
        }
    }

    #[test]
    fn offload_warnings() {
        // GRO and TSO on, as on most hosts: reported, not warned.
        let common = vec![
            feature("rx-gro", true),
            feature("rx-lro", false),
            feature("rx-gro-list", false),
            feature("tx-tcp-segmentation", true),
            feature("rx-checksum", true),
        ];
        let (ok, d) = offloads("eth0", &Ok(common.clone()));
        assert!(ok, "{d}");
        assert_eq!(
            d,
            "eth0: rx-gro on, rx-gro-list off, rx-lro off, tx-tcp-segmentation on"
        );
        let mut bad = common;
        bad[1].active = true;
        bad[2].active = true;
        let (ok, d) = offloads("eth0", &Ok(bad));
        assert!(!ok);
        assert!(
            d.contains("rx-gro-list is on: probe datagrams share one RX timestamp"),
            "{d}"
        );
        assert!(d.contains("rx-lro is on"), "{d}");
        assert!(
            d.ends_with("`sudo ethtool -K eth0 rx-gro-list off rx-lro off`"),
            "{d}"
        );
        let (ok, d) = offloads("wg0", &Err(std::io::Error::from(ErrorKind::Unsupported)));
        assert!(!ok && d.starts_with("wg0: not read: "), "{d}");
    }

    #[test]
    fn loopback_offloads_read() {
        if !PLATFORM.offload_features {
            return;
        }
        let (_, d) = offloads("lo", &pt_sys::ethtool::features("lo"));
        assert!(d.starts_with("lo: rx-gro on"), "{d}");
    }

    #[test]
    fn http_probe_is_a_whole_responder_header() {
        assert!(HTTP_PROBE.len() >= 64);
    }

    #[test]
    fn interception_detected() {
        assert_eq!(interception(b""), None);
        let d = interception(b"HTTP/1.1 302 Found\r\nLocation: http://portal/\r\n\r\n").unwrap();
        assert!(
            d.contains("HTTP/1.1 302 Found") && d.contains("captive portal"),
            "{d}"
        );
        assert!(interception(b"\x15\x03\x01").unwrap().contains("3 bytes"));
    }

    #[test]
    fn untested_interception_is_not_clean() {
        assert_eq!(intercept_detail(Ok(None)), (true, String::new()));
        assert!(!intercept_detail(Ok(Some("answered HTTP".into()))).0);
        let (clean, d) = intercept_detail(Err("connection timed out".into()));
        assert!(!clean);
        assert_eq!(d, "not tested: connection timed out");
    }

    #[test]
    fn udp_errors_classified() {
        let e = |k: ErrorKind| udp_error(k, &std::io::Error::from(k));
        assert_eq!(e(ErrorKind::WouldBlock), None);
        assert_eq!(e(ErrorKind::TimedOut), None);
        assert_eq!(e(ErrorKind::ConnectionRefused), Some(Udp::Refused));
        assert_eq!(e(ErrorKind::HostUnreachable), Some(Udp::Unreachable));
        assert_eq!(e(ErrorKind::NetworkUnreachable), Some(Udp::Unreachable));
        assert!(!udp_detail(&Udp::Refused).0);
        assert!(udp_detail(&Udp::NotRefused).0);
    }

    #[test]
    fn udp_probe_sees_a_closed_loopback_port() {
        // Bind and drop a socket to find a port nothing listens on; loopback answers ICMP port
        // unreachable at once.
        let port = UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .unwrap()
            .port();
        assert_eq!(
            udp_probe(SocketAddr::from(([127, 0, 0, 1], port))),
            Udp::Refused
        );
        let open = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            udp_probe(open.local_addr().unwrap()),
            Udp::NotRefused,
            "a listening socket that never answers"
        );
    }

    #[test]
    fn http_probe_on_loopback() {
        // A silent listener that closes (like the responder rejecting a header) is clean; one
        // that answers HTTP is a portal.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            for (i, s) in l.incoming().take(2).enumerate() {
                let mut s = s.unwrap();
                // The silent one reads only a header's worth, as the responder does; the
                // portal reads the whole request so that its close sends no reset.
                let mut b = vec![0u8; if i == 1 { HTTP_PROBE.len() } else { 64 }];
                s.read_exact(&mut b).unwrap();
                if i == 1 {
                    s.write_all(b"HTTP/1.1 302 Found\r\n\r\n").unwrap();
                }
            }
        });
        assert_eq!(http_probe(a), Ok(None));
        assert!(http_probe(a).unwrap().unwrap().contains("302"));
        t.join().unwrap();
    }
}
