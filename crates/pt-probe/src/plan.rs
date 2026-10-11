//! Profiles, flow-id allocation and the saturation controller
//! (docs/design/probe.md §6–7, REQ-PRB-010/011/014/016, ADR 0010).

use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use pt_format::Value;
use pt_sys::clock::mono_raw;
use pt_wire::ctrl::BodyExt;

use crate::flows::{FlowSpec, Pattern, Role, Sock, Tos};
use crate::io::{FlowBytes, PacerCmd};

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

impl Profile {
    /// Tracking rounds (one short saturation per minute) for a tracking time of `track_s`.
    pub fn track_rounds(track_s: u64) -> u64 {
        track_s / 60
    }

    /// Saturation seconds `sender` runs over the whole session (P4–P7 and tracking rounds,
    /// which alternate starting with the initiator).
    pub fn saturation_s(&self, sender: Role, track_s: u64) -> f64 {
        let r = Self::track_rounds(track_s);
        match sender {
            Role::A => {
                self.sat_s + self.both_s + 3.0 * self.class_sat_s + r.div_ceil(2) as f64 * 3.0
            }
            Role::B => self.sat_s + self.both_s + (r / 2) as f64 * 3.0,
        }
    }

    /// Planned session length in seconds (an upper estimate, for the background reserve).
    pub fn planned_s(&self, track_s: u64) -> f64 {
        let nat = self.nat_timeouts_s.iter().max().copied().unwrap_or(0) as f64 + 2.0;
        let phases = 2.0
            + 10.0
            + self.quiet_s
            + self.chirp_s
            + 0.5
            + 2.0 * (self.sat_s + 1.0)
            + (self.both_s + 1.0)
            + 3.0 * (self.class_sat_s + 0.5)
            + if self.refs { 35.0 } else { 0.0 }
            + track_s as f64;
        phases.max(nat) + 5.0
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
        max_bytes: 0,
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
    /// Byte allowance of the flow (0 = none).
    max_bytes: u64,
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
    bytes: Arc<FlowBytes>,
}

pub const START_BPS: f64 = 2_000_000.0;
/// Length of the buffer-filling overdrive at the end of a saturation.
pub const OVERDRIVE_NS: u64 = 1_500_000_000;
pub const FLOOR_BPS: f64 = 100_000.0;

/// Bytes the overdrive step sends at 1.5× delivery rate `d` (bit/s).
fn overdrive_bytes(d: f64) -> f64 {
    1.5 * d / 8.0 * OVERDRIVE_NS as f64 / 1e9
}

/// Smallest byte allowance worth starting a saturation for (docs/design/probe.md §6).
pub const MIN_ALLOWANCE: u64 = 1_000_000;

/// Byte allowance for one saturation phase of a sender: what the sender may still send, minus
/// the reserve for background traffic, shared by this phase in proportion to its share of the
/// sender's remaining saturation time.
pub fn allowance(cap: u64, spent: u64, reserve: u64, this_s: f64, left_s: f64) -> u64 {
    if this_s <= 0.0 || left_s <= 0.0 {
        return 0;
    }
    let avail = cap.saturating_sub(spent).saturating_sub(reserve) as f64;
    (avail * (this_s / left_s).min(1.0)) as u64
}

/// Background bytes per second one endpoint sends during a session (light flow, trains,
/// control datagrams) for profile `p` at path MTU `mtu` (docs/design/probe.md §6).
pub fn background_bps(p: &Profile, mtu: u32) -> f64 {
    let light = 50.0 * 128.0;
    let trains = f64::from(p.train_count) * f64::from(mtu) * 1000.0 / p.train_period_ms as f64;
    let control = 6000.0;
    light + trains + control
}

impl Controller {
    pub fn new(
        role: Role,
        pacer: Sender<PacerCmd>,
        rate_cap: u64,
        bytes: Arc<FlowBytes>,
    ) -> Controller {
        Controller {
            role,
            pacer,
            flows: Mutex::new(HashMap::new()),
            q_target_ns: Mutex::new(10_000_000),
            rate_cap: rate_cap as f64,
            bytes,
        }
    }

    /// Register a controlled flow owned by this endpoint. `duration_ns` > 3 s enables the
    /// overdrive step in its last 1.5 s, or earlier when `max_bytes` (0 = none) would run out
    /// first (docs/design/probe.md §7).
    pub fn add(&self, id: u8, start: u64, duration_ns: u64, max_bytes: u64) {
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
                max_bytes,
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
                Mode::Hold
                    if st.overdrive_at != u64::MAX
                        && st.max_bytes > 0
                        && now < st.overdrive_at
                        && (st.max_bytes.saturating_sub(self.bytes.get(id as u8)) as f64)
                            <= overdrive_bytes(d) =>
                {
                    // The allowance only covers the overdrive now: start it, so the buffer is
                    // still revealed before the flow stops.
                    st.overdrive_at = now;
                    st.rate = (d * 1.5).max(st.rate);
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
    fn allowances_share_what_is_left() {
        // 200 MB cap, 10 MB spent, 10 MB reserve: 180 MB over 30 s of saturation; a 10 s
        // phase gets a third.
        assert_eq!(
            allowance(200_000_000, 10_000_000, 10_000_000, 10.0, 30.0),
            60_000_000
        );
        // The last phase gets everything left; nothing left gives nothing.
        assert_eq!(allowance(100, 0, 0, 5.0, 5.0), 100);
        assert_eq!(allowance(100, 120, 0, 5.0, 5.0), 0);
        assert_eq!(allowance(100, 0, 0, 0.0, 5.0), 0);
        let std = Profile::by_name("standard").unwrap();
        assert_eq!(std.saturation_s(Role::A, 0), 10.0 + 5.0 + 9.0);
        assert_eq!(std.saturation_s(Role::B, 0), 15.0);
        let deep = Profile::by_name("deep").unwrap();
        assert_eq!(deep.saturation_s(Role::A, 600), 24.0 + 15.0);
        assert_eq!(deep.saturation_s(Role::B, 600), 15.0 + 15.0);
        assert!(std.planned_s(0) > 70.0 && std.planned_s(0) < 200.0);
        // Background: light 6.4 kB/s + trains 8 × 1500 B / 0.5 s + control.
        assert_eq!(background_bps(&std, 1500), 6400.0 + 24_000.0 + 6000.0);
    }

    #[test]
    fn overdrive_starts_early_when_the_allowance_runs_low() {
        let (tx, rx) = std::sync::mpsc::channel();
        let bytes: Arc<FlowBytes> = Arc::default();
        let c = Controller::new(Role::A, tx, 500_000_000, bytes.clone());
        // 10 s flow with a 10 MB allowance at 10 Mbit/s delivery: overdrive needs 2.8 MB.
        c.add(7, mono_raw(), 10_000_000_000, 10_000_000);
        let fb = |q: u64| {
            Value::map().with(
                "flows",
                Value::Array(vec![
                    Value::map()
                        .with("flow", 7u64)
                        .with("qdelay_ns", q)
                        .with("rate_bps", 10_000_000u64),
                ]),
            )
        };
        c.on_feedback(&fb(50_000_000)); // queue builds: hold at the delivery rate
        assert!(matches!(
            rx.recv().unwrap(),
            PacerCmd::SetRate(7, 10_000_000)
        ));
        bytes.add(7, 5_000_000); // 5 MB left: still holding
        c.on_feedback(&fb(10_000_000));
        let PacerCmd::SetRate(7, r) = rx.recv().unwrap() else {
            panic!()
        };
        assert!(r < 15_000_000, "{r}");
        bytes.add(7, 3_000_000); // 2 MB left < 2.8 MB: overdrive now at 1.5x
        c.on_feedback(&fb(10_000_000));
        assert!(matches!(
            rx.recv().unwrap(),
            PacerCmd::SetRate(7, 15_000_000)
        ));
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
        let c = Controller::new(Role::A, tx, 500_000_000, Arc::default());
        c.add(7, mono_raw(), 0, 0);
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
