//! Context that cannot be recovered after the session (REQ-PRB-019): host facts, interface,
//! Wi-Fi link state, interface counters, routing changes, clock pairs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use pt_format::Value;
use pt_sys::clock::{mono_raw, pair};
use pt_sys::netif::{IfType, if_stats, iface_info};
use pt_sys::netlink::{Nl80211, RtMonitor};

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

/// Background sampler: interface counters (10 Hz), Wi-Fi (1 Hz), clock pairs (1 Hz), routing events.
#[derive(Debug)]
pub struct Sampler {
    stop: Arc<AtomicBool>,
    h: Option<JoinHandle<()>>,
}

impl Sampler {
    pub fn start(iface: Option<String>, rec: Recorder, wifi: bool) -> Sampler {
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let h = std::thread::Builder::new()
            .name("context".into())
            .spawn(move || run(iface, rec, wifi, s2))
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

fn run(iface: Option<String>, rec: Recorder, wifi: bool, stop: Arc<AtomicBool>) {
    let info = iface.as_deref().map(iface_info);
    let mut nl = if wifi && info.as_ref().is_some_and(|i| i.kind == IfType::Wifi) {
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
    } else {
        None
    };
    let rt = RtMonitor::open().ok();
    let mut tick = 0u64;
    let mut wifi_rows = Vec::new();
    let mut if_rows = Vec::new();
    let mut pair_rows = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let t = mono_raw();
        if let Some(name) = iface.as_deref()
            && let Some(s) = if_stats(name)
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
            let p = pair(8);
            pair_rows.push(vec![
                Some(p.mono as i64),
                Some(p.real as i64),
                Some(p.width as i64),
            ]);
            if let (Some(n), Some(i)) = (nl.as_mut(), info.as_ref())
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
            rec.rows("wifi", std::mem::take(&mut wifi_rows));
            rec.rows("pairs", std::mem::take(&mut pair_rows));
        }
        if let Some(m) = rt.as_ref() {
            let mut evs = Vec::new();
            match m.poll_events(&mut evs) {
                Ok(()) => {}
                Err(e) => rec.event(
                    "rtnetlink_overrun",
                    Value::map().with("error", e.to_string()),
                ),
            }
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
        tick += 1;
        std::thread::sleep(Duration::from_millis(100));
    }
    let p = pair(8);
    pair_rows.push(vec![
        Some(p.mono as i64),
        Some(p.real as i64),
        Some(p.width as i64),
    ]);
    rec.rows("ifstats", if_rows);
    rec.rows("wifi", wifi_rows);
    rec.rows("pairs", pair_rows);
}
