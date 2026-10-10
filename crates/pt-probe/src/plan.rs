//! Profiles, flow-id allocation and the saturation controller
//! (docs/design/probe.md §6–7, REQ-PRB-010/011/014/016, ADR 0010).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::mpsc::Sender;

use pt_format::Value;
use pt_sys::clock::mono_raw;
use pt_wire::ctrl::BodyExt;

use crate::flows::{FlowSpec, Pattern, Role, Sock, Tos};
use crate::io::PacerCmd;

/// Session profile (REQ-PRB-014).
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub name: &'static str,
    pub data_cap: u64,
    pub quiet_s: f64,
    pub chirp_s: f64,
    /// Saturation per direction (P4, P5) and both (P6), seconds; 0 skips.
    pub sat_s: f64,
    pub both_s: f64,
    /// Per-class short saturation (P7), seconds; 0 skips.
    pub class_sat_s: f64,
    /// Reference flows (P8).
    pub refs: bool,
    pub train_count: u32,
    pub train_period_ms: u64,
    pub nat_timeouts_s: Vec<u64>,
    /// Extra tracking time with periodic short saturations (deep), seconds.
    pub track_s: u64,
}

impl Profile {
    pub fn by_name(name: &str) -> Option<Profile> {
        let standard = Profile {
            name: "standard",
            data_cap: 200_000_000,
            quiet_s: 10.0,
            chirp_s: 5.0,
            sat_s: 10.0,
            both_s: 5.0,
            class_sat_s: 3.0,
            refs: true,
            train_count: 8,
            train_period_ms: 500,
            nat_timeouts_s: vec![15, 30, 60],
            track_s: 0,
        };
        Some(match name {
            "standard" => standard,
            "smoke" => Profile {
                name: "smoke",
                data_cap: 50_000_000,
                quiet_s: 3.0,
                chirp_s: 2.0,
                sat_s: 2.0,
                both_s: 0.0,
                class_sat_s: 0.0,
                refs: true,
                nat_timeouts_s: vec![5],
                ..standard
            },
            "light" => Profile {
                name: "light",
                data_cap: 2_000_000,
                quiet_s: 10.0,
                chirp_s: 3.0,
                sat_s: 0.0,
                both_s: 0.0,
                class_sat_s: 0.0,
                refs: false,
                train_count: 4,
                train_period_ms: 2000,
                nat_timeouts_s: vec![15, 30],
                ..standard
            },
            "deep" => Profile {
                name: "deep",
                data_cap: 1_000_000_000,
                nat_timeouts_s: vec![15, 30, 60, 120, 300],
                track_s: 600,
                ..standard
            },
            _ => return None,
        })
    }
}

/// Fixed flow ids (docs/design/probe.md §6). Deep-tracking saturations use 100+.
pub mod ids {
    pub const LIGHT_A: u8 = 1;
    pub const LIGHT_B: u8 = 2;
    pub const TRAIN_A: u8 = 3;
    pub const TRAIN_B: u8 = 4;
    pub const CHIRP_A: u8 = 5;
    pub const CHIRP_B: u8 = 6;
    pub const HEAVY_A: u8 = 7;
    pub const HEAVY_B: u8 = 8;
    pub const PMTU_A: u8 = 9;
    pub const PMTU_B: u8 = 10;
    pub const CLASS_443: u8 = 11;
    pub const CLASS_QUIC: u8 = 12;
    pub const CLASS_MAIN: u8 = 13;
    pub const CSAT_443: u8 = 14;
    pub const CSAT_QUIC: u8 = 15;
    pub const CSAT_MAIN: u8 = 16;
    pub const CBR_A: u8 = 17;
    pub const CBR_B: u8 = 18;
    pub const BOTH_A: u8 = 19;
    pub const BOTH_B: u8 = 20;
    pub const NAT0: u8 = 30;
    pub const TCP_PROBE80: u8 = 40;
    pub const TCP_PROBE443: u8 = 41;
    pub const TCP_PROBE4433: u8 = 42;
    pub const TCP_BULK_UP: u8 = 43;
    pub const TCP_BULK_DOWN: u8 = 44;
    pub const TCP_RR: u8 = 45;
    pub const TRACK0: u8 = 100;
}

/// Builder for a flow spec with common defaults.
#[allow(clippy::too_many_arguments)]
pub fn spec(
    id: u8,
    kind: &str,
    sender: Role,
    sock: Sock,
    size: u32,
    pattern: Pattern,
    phase: u16,
    duration_ns: u64,
    main_port: u16,
) -> FlowSpec {
    let (dst_port, class, quic) = match sock {
        Sock::Udp443 => (
            443,
            if kind.contains("quic") {
                "udp/443-quic"
            } else {
                "udp/443"
            },
            false,
        ),
        _ => (main_port, "udp/high-port", false),
    };
    FlowSpec {
        id,
        kind: kind.to_string(),
        sender,
        sock,
        dst_port,
        class: class.to_string(),
        quic,
        phase,
        size,
        pattern,
        tos: Tos::Fixed(0),
        duration_ns,
        echo: false,
        echo_delay_ns: 0,
    }
}

/// Profile chosen by `--profile auto` from NetworkManager's metered state (REQ-PRB-016):
/// `yes` and `yes (guessed)` select `light`; anything else (no, unknown, absent) `standard`.
pub fn auto_profile(metered: &str) -> &'static str {
    if metered.trim_start().starts_with("yes") {
        "light"
    } else {
        "standard"
    }
}

/// Flow specs under which control datagrams are observed (flows 250/251; seq = Noise nonce).
pub fn control_specs(main_port: u16) -> Vec<FlowSpec> {
    [
        (crate::io::CONTROL_FLOW_A, Role::A),
        (crate::io::CONTROL_FLOW_B, Role::B),
    ]
    .into_iter()
    .map(|(id, sender)| {
        spec(
            id,
            "control",
            sender,
            Sock::Main,
            0,
            Pattern::Burst {
                count: 0,
                gap_ns: 0,
            },
            0,
            0,
            main_port,
        )
    })
    .collect()
}

/// PMTU ladder IP sizes, capped by the local interface MTU (docs/design/probe.md §6).
pub fn pmtu_ladder(v6: bool, if_mtu: u32) -> Vec<u32> {
    let base: &[u32] = if v6 {
        &[1280, 1350, 1400, 1420, 1440, 1460, 1472, 1480, 1492, 1500]
    } else {
        &[1200, 1350, 1400, 1420, 1440, 1460, 1472, 1480, 1492, 1500]
    };
    let mut v: Vec<u32> = base.iter().copied().filter(|s| *s <= if_mtu).collect();
    if !v.contains(&if_mtu) && if_mtu < 1500 && if_mtu >= base[0] {
        v.push(if_mtu);
    }
    v
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    SlowStart,
    Hold,
}

#[derive(Debug, Clone)]
struct CtlState {
    rate: f64,
    mode: Mode,
    last_double: u64,
    /// MONO_RAW time from which to overdrive (fill the bottleneck buffer), or u64::MAX.
    overdrive_at: u64,
}

/// Saturation controller (docs/design/probe.md §7): slow start doubling every 50 ms until the
/// queueing delay exceeds the target, then hold a standing queue around the target.
#[derive(Debug)]
pub struct Controller {
    pub role: Role,
    pacer: Sender<PacerCmd>,
    flows: Mutex<HashMap<u8, CtlState>>,
    pub q_target_ns: Mutex<u64>,
    pub rate_cap: f64,
}

pub const START_BPS: f64 = 2_000_000.0;
/// Length of the buffer-filling overdrive at the end of a saturation.
pub const OVERDRIVE_NS: u64 = 1_500_000_000;
pub const FLOOR_BPS: f64 = 100_000.0;

impl Controller {
    pub fn new(role: Role, pacer: Sender<PacerCmd>, rate_cap: u64) -> Controller {
        Controller {
            role,
            pacer,
            flows: Mutex::new(HashMap::new()),
            q_target_ns: Mutex::new(10_000_000),
            rate_cap: rate_cap as f64,
        }
    }

    /// Register a controlled flow owned by this endpoint. `duration_ns` > 3 s enables the
    /// overdrive step in its last 1.5 s (docs/design/probe.md §7).
    pub fn add(&self, id: u8, start: u64, duration_ns: u64) {
        let overdrive_at = if duration_ns > 3_000_000_000 {
            start + duration_ns - OVERDRIVE_NS
        } else {
            u64::MAX
        };
        self.flows.lock().expect("lock").insert(
            id,
            CtlState {
                rate: START_BPS,
                mode: Mode::SlowStart,
                last_double: mono_raw(),
                overdrive_at,
            },
        );
    }

    pub fn remove(&self, id: u8) {
        self.flows.lock().expect("lock").remove(&id);
    }

    /// Handle a feedback message from the peer.
    pub fn on_feedback(&self, body: &Value) {
        let Some(list) = body.get("flows").and_then(Value::as_array) else {
            return;
        };
        let qt_base = *self.q_target_ns.lock().expect("lock") as f64;
        let now = mono_raw();
        let mut flows = self.flows.lock().expect("lock");
        for f in list {
            let id = f.u64_or("flow", 999);
            let Some(st) = u8::try_from(id).ok().and_then(|id| flows.get_mut(&id)) else {
                continue;
            };
            let q = f.u64_or("qdelay_ns", 0) as f64;
            let d = f.u64_or("rate_bps", 0) as f64;
            // Target: 10 ms standing queue, but at least three MTU packet times at the delivery
            // rate so slow paths still keep a backlog (docs/design/probe.md §7).
            let qt = qt_base.max(if d > 0.0 {
                3.0 * 1500.0 * 8.0 / d * 1e9
            } else {
                0.0
            });
            match st.mode {
                Mode::SlowStart => {
                    // Leave slow start when the queue builds or we send much faster than the
                    // path delivers; continue at the delivery rate.
                    if q > qt
                        || (d > 0.0 && st.rate > 2.0 * d && now - st.last_double >= 50_000_000)
                    {
                        st.mode = Mode::Hold;
                        st.rate = if d > 0.0 { d } else { st.rate / 2.0 };
                    } else if now - st.last_double >= 50_000_000 {
                        st.rate *= 2.0;
                        st.last_double = now;
                    }
                }
                Mode::Hold if now >= st.overdrive_at => {
                    // Overdrive: exceed the delivery rate so a tail-drop buffer fills and its
                    // depth becomes observable at loss onset.
                    st.rate = (d * 1.5).max(st.rate);
                }
                Mode::Hold => {
                    if d < 1000.0 {
                        st.rate *= 0.8;
                    } else {
                        st.rate = d * (1.0 + 0.5 * (qt - q) / qt).clamp(0.7, 1.3);
                    }
                }
            }
            st.rate = st.rate.clamp(FLOOR_BPS, self.rate_cap);
            let _ = self.pacer.send(PacerCmd::SetRate(id as u8, st.rate as u64));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_profile_follows_metered_state() {
        assert_eq!(auto_profile("yes"), "light");
        assert_eq!(auto_profile("yes (guessed)"), "light");
        assert_eq!(auto_profile("no"), "standard");
        assert_eq!(auto_profile("no (guessed)"), "standard");
        assert_eq!(auto_profile("unknown"), "standard");
        assert_eq!(auto_profile(""), "standard");
    }

    #[test]
    fn profiles_exist() {
        for p in ["smoke", "light", "standard", "deep"] {
            assert!(Profile::by_name(p).is_some());
        }
        assert_eq!(Profile::by_name("light").unwrap().data_cap, 2_000_000);
    }

    #[test]
    fn ladder_respects_mtu() {
        assert_eq!(*pmtu_ladder(false, 1500).last().unwrap(), 1500);
        let l = pmtu_ladder(false, 1400);
        assert!(l.iter().all(|s| *s <= 1400));
    }

    #[test]
    fn controller_slow_start_then_hold() {
        let (tx, rx) = std::sync::mpsc::channel();
        let c = Controller::new(Role::A, tx, 500_000_000);
        c.add(7, mono_raw(), 0);
        // Low queue: rate should double (after 50 ms).
        std::thread::sleep(std::time::Duration::from_millis(60));
        c.on_feedback(&Value::map().with(
            "flows",
            Value::Array(vec![
                    Value::map()
                        .with("flow", 7u64)
                        .with("qdelay_ns", 0u64)
                        .with("rate_bps", 1_000_000u64),
                ]),
        ));
        let PacerCmd::SetRate(7, r) = rx.recv().unwrap() else {
            panic!()
        };
        assert_eq!(r, 4_000_000);
        // High queue: switch to hold at the delivery rate.
        c.on_feedback(&Value::map().with(
            "flows",
            Value::Array(vec![
                    Value::map()
                        .with("flow", 7u64)
                        .with("qdelay_ns", 50_000_000u64)
                        .with("rate_bps", 3_000_000u64),
                ]),
        ));
        let PacerCmd::SetRate(7, r) = rx.recv().unwrap() else {
            panic!()
        };
        assert_eq!(r, 3_000_000);
    }
}
