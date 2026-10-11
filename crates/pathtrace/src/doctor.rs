//! `pathtrace doctor`: preflight checks before a field session (REQ-PRB-025).

use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use pt_probe::config::{self, Responder};
use pt_sys::udp::{MAX_DATAGRAM, OutMsg, SockOpts, UdpSock};

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

pub fn run(cfg: &Path, responder: Option<&Responder>, json: bool) -> ExitCode {
    let mut c = Vec::new();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    let ver: Vec<u32> = kernel
        .split(['.', '-'])
        .take(2)
        .filter_map(|s| s.parse().ok())
        .collect();
    let kok = ver.len() == 2 && (ver[0], ver[1]) >= (6, 1);
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
    check(&mut c, "kernel timestamps", rx, d, false);
    let _ = tx;
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
    if let Some(r) = responder {
        match pt_probe::session::resolve(&r.addr, false) {
            Ok((dst, all)) => {
                check(
                    &mut c,
                    "resolve responder",
                    true,
                    all.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                    true,
                );
                if let Ok(ip) = pt_sys::netif::local_addr_for(dst) {
                    let iface = pt_sys::netif::iface_with_addr(ip)
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let info = pt_sys::netif::iface_info(&iface);
                    check(
                        &mut c,
                        "egress interface",
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
                        &mut c,
                        "metered",
                        true,
                        pt_probe::context::metered(&iface),
                        false,
                    );
                    if info.kind == pt_sys::netif::IfType::Wifi {
                        let w =
                            pt_sys::netlink::Nl80211::open().and_then(|mut n| n.sample(info.index));
                        check(
                            &mut c,
                            "wifi link stats",
                            w.is_ok(),
                            format!("{w:?}"),
                            false,
                        );
                    }
                }
                for port in [r_port(dst), 443, 80] {
                    let ok = TcpStream::connect_timeout(
                        &SocketAddr::new(dst.ip(), port),
                        Duration::from_secs(3),
                    )
                    .is_ok();
                    check(
                        &mut c,
                        &format!("tcp/{port} reachable"),
                        ok,
                        "",
                        port == r_port(dst),
                    );
                }
                // UDP: an unauthenticated datagram gets no reply by design; report only that it
                // was sent. Run `pathtrace probe <responder> --profile smoke` for an end-to-end test.
                check(
                    &mut c,
                    "udp handshake",
                    true,
                    "not tested here (no reply without a session); run a smoke probe",
                    false,
                );
            }
            Err(e) => check(&mut c, "resolve responder", false, e.to_string(), true),
        }
    }
    let failed = c.iter().any(|x| !x.ok && x.fatal);
    if json {
        let v: Vec<serde_json::Value> = c.iter().map(|x| serde_json::json!({"check": x.name, "ok": x.ok, "fatal": x.fatal, "detail": x.detail})).collect();
        println!("{}", serde_json::json!({"ok": !failed, "checks": v}));
    } else {
        for x in &c {
            println!(
                "{} {:<22} {}",
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

fn r_port(a: SocketAddr) -> u16 {
    a.port()
}
