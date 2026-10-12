//! Context that cannot be recovered after the session (REQ-PRB-019): host facts, interface,
//! Wi-Fi link state, interface counters, routing changes, clock pairs.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use pt_format::Value;
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

/// Static facts about this host for META (`endpoints.<role>`).
pub fn host_facts() -> Value {
    let os = read("/etc/os-release")
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into());
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
        .with(
            "cpus",
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
        )
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

/// Interface facts for META.
pub fn iface_facts(name: &str) -> Value {
    let i = iface_info(name);
    Value::map()
        .with("name", i.name.clone())
        .with("index", i.index)
        .with("type", i.kind.name())
        .with("driver", i.driver.clone())
        .with("mtu", i.mtu)
        .with("usb", i.usb)
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
                Some(s.tx_dropped as i64),
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
                    Value::map()
                        .with("from", from.map(|f| f.0))
                        .with("to", name.clone())
                        .with("iface", iface_facts(&name))
                        .with("qdisc", qdisc)
                        .with("txqueuelen", txqueuelen)
                        .with("addr", pii(local.to_string(), "id")),
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
    fn resolves_loopback_route() {
        let (local, name) = route_to("127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(local, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(name, "lo");
    }
}
