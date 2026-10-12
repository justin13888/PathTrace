//! `pathtrace doctor`: preflight checks before a field session (REQ-PRB-025). The checks and
//! why `doctor` opens no session: docs/design/cli.md.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use pt_probe::config::{self, Responder};
use pt_sys::clock::NtpState;
use pt_sys::udp::{MAX_DATAGRAM, OutMsg, SockOpts, UdpSock};

const TCP_TIMEOUT: Duration = Duration::from_secs(3);

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
/// until both kinds of stamp have been seen (docs/design/cli.md).
fn timestamps() -> (bool, bool, String) {
    let (Ok(a), Ok(b)) = (
        UdpSock::bind("127.0.0.1:0".parse().expect("addr"), SockOpts::default()),
        UdpSock::bind("127.0.0.1:0".parse().expect("addr"), SockOpts::default()),
    ) else {
        return (false, false, "cannot bind loopback UDP".into());
    };
    let Ok(dst) = b.local_addr() else {
        return (false, false, "no local addr".into());
    };
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
        if rx && tx {
            break;
        }
    }
    (
        rx,
        tx,
        format!("kernel RX stamps {rx}, kernel TX stamps {tx}"),
    )
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
        check(
            c,
            &format!("metered{suffix}"),
            true,
            pt_probe::context::metered(&iface),
            false,
        );
        if info.kind == pt_sys::netif::IfType::Wifi {
            let w = pt_sys::netlink::Nl80211::open().and_then(|mut n| n.sample(info.index));
            check(
                c,
                &format!("wifi link stats{suffix}"),
                w.is_ok(),
                format!("{w:?}"),
                false,
            );
        }
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
        let clean = match http_probe(a) {
            Ok(None) => {
                check(
                    c,
                    &format!("tcp/{port} not intercepted{suffix}"),
                    true,
                    "",
                    false,
                );
                true
            }
            Ok(Some(d)) => {
                check(
                    c,
                    &format!("tcp/{port} not intercepted{suffix}"),
                    false,
                    d,
                    port == main,
                );
                false
            }
            Err(e) => {
                check(
                    c,
                    &format!("tcp/{port} not intercepted{suffix}"),
                    false,
                    format!("not tested: {e}"),
                    false,
                );
                true
            }
        };
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
                "{fam}: tcp/{} unreachable or intercepted",
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

pub fn run(cfg: &Path, responder: Option<&Responder>, json: bool) -> ExitCode {
    let mut c = Vec::new();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let kok = kernel_ok(&kernel);
    check(&mut c, "kernel >= 6.1", kok, kernel, true);
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
    let (rx, tx, d) = timestamps();
    check(&mut c, "kernel timestamps", rx && tx, d, false);
    let cs =
        std::fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource")
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
    let (ok, d) = match pt_sys::clock::ntp_state() {
        Ok(s) => clock_sync(&s),
        Err(e) => (false, format!("adjtimex: {e}")),
    };
    check(&mut c, "clock sync", ok, d, false);
    let (ok, d) = power(&read_supplies());
    check(&mut c, "power", ok, d, false);
    let (driver, govs) = read_governors();
    let (ok, d) = governor(&driver, &govs);
    check(&mut c, "cpu governor", ok, d, false);
    if let Some(r) = responder {
        responder_checks(&mut c, r);
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
        let (ok, d) = clock_sync(&NtpState {
            synced: true,
            esterror_us: 120,
            maxerror_us: 4000,
        });
        assert!(ok && d.contains("120 us") && d.contains("4000 us"), "{d}");
        let (ok, d) = clock_sync(&NtpState {
            synced: false,
            esterror_us: 0,
            maxerror_us: 16_000_000,
        });
        assert!(!ok && d.contains("NTP"), "{d}");
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
    fn governors() {
        assert!(governor("", &[]).0);
        assert!(governor("intel_pstate", &["powersave".into()]).0);
        assert!(governor("amd-pstate-epp", &["powersave".into()]).0);
        assert!(governor("acpi-cpufreq", &["schedutil".into()]).0);
        assert!(!governor("acpi-cpufreq", &["powersave".into()]).0);
        assert!(!governor("intel_cpufreq", &["performance".into(), "powersave".into()]).0);
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
