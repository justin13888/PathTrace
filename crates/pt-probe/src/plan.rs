//! Profiles, flow-id allocation and the saturation controller
//! (docs/design/probe.md §6–7, REQ-PRB-010/011/014/016, ADR 0010).

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use pt_format::Value;
use pt_sys::clock::mono_raw;
use pt_wire::ctrl::BodyExt;

use crate::flows::{FlowSpec, Pattern, Role, Sock, Tos};
use crate::io::{FEEDBACK_INTERVAL_NS, FlowBytes, PacerCmd};

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

    /// Planned seconds per phase, in session order (upper estimates, for the background
    /// reserve; docs/design/probe.md §6).
    pub fn phase_plan(&self, track_s: u64) -> Vec<(u16, f64)> {
        vec![
            (0, 2.0),
            (1, 10.0),
            (2, self.quiet_s),
            (3, self.chirp_s + 0.5),
            (4, self.sat_s + 1.0),
            (5, self.sat_s + 1.0),
            (6, self.both_s + 1.0),
            (7, 3.0 * (self.class_sat_s + 0.5)),
            (8, if self.refs { 35.0 } else { 0.0 }),
            (10, track_s as f64),
        ]
    }

    /// Seconds the session lasts at least, because of the NAT binding probes.
    pub fn nat_s(&self) -> f64 {
        self.nat_timeouts_s.iter().max().copied().unwrap_or(0) as f64 + 2.0
    }

    /// Planned session length in seconds (an upper estimate, for the background reserve).
    pub fn planned_s(&self, track_s: u64) -> f64 {
        let phases: f64 = self.phase_plan(track_s).iter().map(|p| p.1).sum();
        phases.max(self.nat_s()) + 5.0
    }
}

/// Bytes the P8 TCP bulk transfer of a sender with data cap `cap` may send: reserved from the
/// start of the session, so the saturations before it leave room for it (docs/design/probe.md
/// §6).
pub fn ref_tcp_bytes(cap: u64) -> u64 {
    (cap / 8).min(100_000_000)
}

/// UDP CBR reference flow bytes per sender in P8 (2 Mbit/s for 5 s).
pub const REF_CBR_BYTES: u64 = 2_000_000 / 8 * 5;

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

/// Line `probe` prints whenever `--profile auto` decides: the chosen profile, the egress
/// interface, and the metered state. A state that is neither `yes…` nor `no…` (no
/// NetworkManager, unmanaged interface, timeout) makes it a warning: `standard` was picked
/// without knowing whether the link is capped, and phone hotspots are rarely flagged metered.
pub fn auto_profile_notice(iface: &str, metered: &str) -> String {
    let chosen = auto_profile(metered);
    let iface = if iface.is_empty() {
        "egress interface"
    } else {
        iface
    };
    let m = metered.trim();
    if m.starts_with("yes") || m.starts_with("no") {
        format!("profile auto: {chosen} ({iface} metered: {m}); override with --profile")
    } else {
        let m = if m.is_empty() { "unknown" } else { m };
        format!(
            "warning: profile auto: {chosen}, but the metered state of {iface} is {m} \
             (NetworkManager unavailable or not managing it); on a capped link \
             (phone hotspot, roaming SIM, in-flight Wi-Fi) pass --profile light"
        )
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
    /// MONO_RAW time the flow starts sending.
    start: u64,
    /// Feedback lag: time from the flow's start to the first feedback reporting a delivery,
    /// about one RTT (None until that feedback arrives).
    lag: Option<u64>,
    /// MONO_RAW time from which to overdrive (fill the bottleneck buffer), or u64::MAX.
    overdrive_at: u64,
    /// Byte allowance of the flow (0 = none).
    max_bytes: u64,
    /// Rates set during the last feedback lag plus [`RATE_HISTORY_NS`], oldest first:
    /// (MONO_RAW time, bit/s). The first entry is the rate in effect at the window's start.
    sent: VecDeque<(u64, f64)>,
}

/// Saturation controller (docs/design/probe.md §7): slow start doubling once per slow-start
/// step (50 ms, or one feedback lag on long-RTT paths) until the queueing delay exceeds the
/// target or the delivery rate stops catching up, then hold a standing queue around the target.
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
/// Shortest slow-start step (one doubling, or the exit test).
pub const SS_STEP_NS: u64 = 50_000_000;
/// Margin added to the feedback lag before a slow-start step: one feedback interval, so the
/// delivery-rate window reports packets sent after the previous doubling.
pub const SS_LAG_MARGIN_NS: u64 = 20_000_000;

/// Slow-start step for a flow whose feedback lag is `lag` (docs/design/probe.md §7): the rate
/// may only double, or slow start exit on the delivery rate, once the feedback reflects the
/// rate set at the previous step.
fn ss_step(lag: Option<u64>) -> u64 {
    lag.map_or(SS_STEP_NS, |l| SS_STEP_NS.max(l + SS_LAG_MARGIN_NS))
}

/// Bytes the overdrive step sends at 1.5× delivery rate `d` (bit/s).
fn overdrive_bytes(d: f64) -> f64 {
    1.5 * d / 8.0 * OVERDRIVE_NS as f64 / 1e9
}

/// Rate history kept beyond the feedback lag, so the age of a report whose packet queued for
/// up to this long is still covered (docs/design/probe.md §7).
pub const RATE_HISTORY_NS: u64 = 1_000_000_000;

/// Age of the queueing delay `q` (ns) a feedback reports, for a flow whose feedback lag is
/// `lag` (docs/design/probe.md §7): how long ago the sender sent the packet it describes. That
/// packet took the base RTT plus its own queueing delay. The lag, measured on the flow's first
/// packets through an empty queue, overstates the base RTT by the wait for the receiver's next
/// report, 0 to one feedback interval, so half an interval is taken off.
fn q_age(lag: Option<u64>, q: f64) -> u64 {
    lag.map_or(0, |l| l.saturating_sub(FEEDBACK_INTERVAL_NS / 2) + q as u64)
}

/// Bits sent in excess of delivery rate `d` (bit/s) during the window `[now − window, now]`,
/// from the rate history `sent` (docs/design/probe.md §7). Negative when the sender sent less
/// than `d`. The latest queue report does not reflect these bits yet: they are in flight or
/// were sent after the reported packet.
fn excess_bits(sent: &VecDeque<(u64, f64)>, now: u64, window: u64, d: f64) -> f64 {
    let from = now.saturating_sub(window);
    let mut bits = 0.0;
    for (i, &(t, r)) in sent.iter().enumerate() {
        let t0 = t.max(from);
        let t1 = sent.get(i + 1).map_or(now, |&(t, _)| t).min(now);
        if t1 > t0 {
            bits += (r - d) * (t1 - t0) as f64 / 1e9;
        }
    }
    bits
}

/// Record that the rate `r` was set at `now`, keeping only the rates in effect during the
/// last `window` ns.
fn push_rate(sent: &mut VecDeque<(u64, f64)>, now: u64, window: u64, r: f64) {
    sent.push_back((now, r));
    let from = now.saturating_sub(window);
    while sent.len() > 1 && sent[1].0 <= from {
        sent.pop_front();
    }
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
                start,
                lag: None,
                overdrive_at,
                max_bytes,
                sent: VecDeque::new(),
            },
        );
    }

    pub fn remove(&self, id: u8) {
        self.flows.lock().expect("lock").remove(&id);
    }

    /// Handle a feedback message from the peer.
    pub fn on_feedback(&self, body: &Value) {
        self.feedback_at(body, mono_raw());
    }

    /// Handle a feedback message that arrived at MONO_RAW time `now`.
    fn feedback_at(&self, body: &Value, now: u64) {
        let Some(list) = body.get("flows").and_then(Value::as_array) else {
            return;
        };
        let qt_base = *self.q_target_ns.lock().expect("lock") as f64;
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
            if st.lag.is_none() && d > 0.0 {
                st.lag = Some(now.saturating_sub(st.start));
            }
            match st.mode {
                Mode::SlowStart => {
                    // Leave slow start when the queue builds, or when the delivery rate has not
                    // caught up with the rate set one step ago (it reports what was sent one
                    // feedback lag earlier, so a shorter step would exit on every long-RTT
                    // path); continue at the delivery rate. Otherwise double once per step.
                    let step_due = now.saturating_sub(st.last_double) >= ss_step(st.lag);
                    if q > qt || (d > 0.0 && st.rate > 2.0 * d && step_due) {
                        st.mode = Mode::Hold;
                        st.rate = if d > 0.0 { d } else { st.rate / 2.0 };
                    } else if step_due {
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
                        // q is about one RTT old: add the queue the bits sent since then will
                        // build or drain at the delivery rate, so the gain acts on the queue
                        // the new rate meets rather than on one it already corrected (issue
                        // #40: without this, hold oscillates on long-RTT paths).
                        let w = q_age(st.lag, q);
                        let qp = (q + excess_bits(&st.sent, now, w, d) / d * 1e9).max(0.0);
                        st.rate = d * (1.0 + 0.5 * (qt - qp) / qt).clamp(0.7, 1.3);
                    }
                }
            }
            st.rate = st.rate.clamp(FLOOR_BPS, self.rate_cap);
            let keep = st.lag.unwrap_or(0) + RATE_HISTORY_NS;
            push_rate(&mut st.sent, now, keep, st.rate);
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
    fn auto_profile_notice_always_names_choice_and_warns_when_blind() {
        let yes = auto_profile_notice("wlan0", "yes (guessed)");
        assert!(yes.starts_with("profile auto: light (wlan0 metered: yes (guessed))"));
        let no = auto_profile_notice("eth0", "no");
        assert!(no.starts_with("profile auto: standard (eth0 metered: no)"));
        for m in ["unknown", "", "  "] {
            let w = auto_profile_notice("wlan0", m);
            assert!(w.starts_with("warning: profile auto: standard"), "{w}");
            assert!(w.contains("wlan0 is unknown"), "{w}");
            assert!(w.contains("--profile light"), "{w}");
        }
        let w = auto_profile_notice("", "unknown");
        assert!(w.contains("egress interface is unknown"), "{w}");
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

    /// Feedback for flow 7 with queueing delay `q` (ns) and delivery rate `d` (bit/s).
    fn fb7(q: u64, d: u64) -> Value {
        Value::map().with(
            "flows",
            Value::Array(vec![
                Value::map()
                    .with("flow", 7u64)
                    .with("qdelay_ns", q)
                    .with("rate_bps", d),
            ]),
        )
    }

    fn set_rate(rx: &std::sync::mpsc::Receiver<PacerCmd>) -> u64 {
        let PacerCmd::SetRate(7, r) = rx.recv().unwrap() else {
            panic!()
        };
        r
    }

    const MS: u64 = 1_000_000;

    #[test]
    fn controller_slow_start_then_hold() {
        let (tx, rx) = std::sync::mpsc::channel();
        let c = Controller::new(Role::A, tx, 500_000_000, Arc::default());
        let t0 = mono_raw();
        c.add(7, t0, 0, 0);
        // Short path: first feedback after 20 ms; the step stays 50 ms.
        c.feedback_at(&fb7(0, 2_000_000), t0 + 20 * MS);
        assert_eq!(set_rate(&rx), 2_000_000);
        // Low queue: rate doubles once the step has passed.
        c.feedback_at(&fb7(0, 2_000_000), t0 + 60 * MS);
        assert_eq!(set_rate(&rx), 4_000_000);
        // High queue: switch to hold at the delivery rate.
        c.feedback_at(&fb7(50 * MS, 3_000_000), t0 + 80 * MS);
        assert_eq!(set_rate(&rx), 3_000_000);
    }

    #[test]
    fn slow_start_exits_when_delivery_stops_catching_up() {
        let (tx, rx) = std::sync::mpsc::channel();
        let c = Controller::new(Role::A, tx, 500_000_000, Arc::default());
        let t0 = mono_raw();
        c.add(7, t0, 0, 0);
        // A 3 Mbit/s policer (no queue): delivery reaches 2, then stays at 3.
        c.feedback_at(&fb7(0, 2_000_000), t0 + 20 * MS);
        assert_eq!(set_rate(&rx), 2_000_000);
        c.feedback_at(&fb7(0, 2_000_000), t0 + 60 * MS);
        assert_eq!(set_rate(&rx), 4_000_000);
        c.feedback_at(&fb7(0, 3_000_000), t0 + 120 * MS);
        assert_eq!(set_rate(&rx), 8_000_000);
        // 8 > 2 × 3 after a full step: hold at the delivery rate.
        c.feedback_at(&fb7(0, 3_000_000), t0 + 180 * MS);
        assert_eq!(set_rate(&rx), 3_000_000);
    }

    #[test]
    fn slow_start_waits_one_feedback_lag_on_long_rtt_paths() {
        let (tx, rx) = std::sync::mpsc::channel();
        let c = Controller::new(Role::A, tx, 500_000_000, Arc::default());
        let t0 = mono_raw();
        c.add(7, t0, 0, 0);
        // 600 ms RTT: the first delivery report arrives after 600 ms.
        c.feedback_at(&fb7(0, 2_000_000), t0 + 600 * MS);
        assert_eq!(set_rate(&rx), 2_000_000);
        c.feedback_at(&fb7(0, 2_000_000), t0 + 625 * MS);
        assert_eq!(set_rate(&rx), 4_000_000);
        // The delivery rate still reports 2 Mbit/s for one more lag: neither double nor exit.
        for ms in [700, 800, 1000, 1200] {
            c.feedback_at(&fb7(0, 2_000_000), t0 + ms * MS);
            assert_eq!(set_rate(&rx), 4_000_000, "at {ms} ms");
        }
        // Delivery caught up one lag after the doubling: double again.
        c.feedback_at(&fb7(0, 4_000_000), t0 + 1250 * MS);
        assert_eq!(set_rate(&rx), 8_000_000);
    }

    /// Simulated path in 1 ms steps: rate-limited bottleneck with a FIFO at the receiver end,
    /// one-way delay `owd_ms` each way. Like the responder, the receiver reports every 20 ms
    /// once the flow arrives (at 11, 31, 51 … ms, so the first report waits a path-dependent
    /// part of an interval): the delivery rate over the interval and the queueing delay of the
    /// last packet delivered.
    fn simulate(cap_bps: f64, owd_ms: u64, secs: u64) -> Sim {
        let (tx, rx) = std::sync::mpsc::channel();
        let c = Controller::new(Role::A, tx, 500_000_000, Arc::default());
        let t0 = mono_raw();
        c.add(7, t0, 0, 0);
        let n = (secs * 1000) as usize;
        let owd = owd_ms as usize;
        let cap = cap_bps / 1000.0; // bits per ms
        // Rate sent in each ms; cumulative bits arrived at and delivered by the bottleneck at
        // the end of each ms; reports in flight to the sender (arrival ms, q ns, rate bit/s).
        let mut sent = vec![0.0; n];
        let (mut arr, mut del) = (vec![0.0f64; n + 1], vec![0.0f64; n + 1]);
        let mut reports = std::collections::VecDeque::new();
        let mut rate = START_BPS;
        let mut reached = None;
        let mut queued = 0u32;
        for t in 0..n {
            while reports
                .front()
                .is_some_and(|r: &(usize, f64, f64)| r.0 == t)
            {
                let (_, q, d) = reports.pop_front().unwrap();
                c.feedback_at(&fb7(q as u64, d as u64), t0 + t as u64 * MS);
                rate = set_rate(&rx) as f64;
                if reached.is_none() && rate >= 0.9 * cap_bps {
                    reached = Some(t as f64 / 1000.0);
                }
            }
            sent[t] = rate;
            let arriving = if t >= owd {
                sent[t - owd] / 1000.0
            } else {
                0.0
            };
            arr[t + 1] = arr[t] + arriving;
            del[t + 1] = arr[t + 1].min(del[t] + cap);
            let now = t + 1;
            if (arr[now] - del[now]) / cap >= 2.0 {
                queued += 1;
            }
            if now % 20 == 11 && del[now] > 0.0 {
                let d = (del[now] - del[now.saturating_sub(20)]) * 50.0;
                // When the last delivered bit arrived: interpolate the cumulative arrivals.
                let k = arr[..=now].partition_point(|a| *a < del[now]).max(1);
                let at = (k - 1) as f64 + (del[now] - arr[k - 1]) / (arr[k] - arr[k - 1]);
                let q = (now as f64 - at).max(0.0) * 1e6;
                reports.push_back((now + owd, q, d));
            }
        }
        // Queue (ms) at the end of each ms of the second half: every ramp here is over by then,
        // so the controller holds.
        let held: Vec<f64> = (n / 2..=n).map(|t| (arr[t] - del[t]) / cap).collect();
        let last = &held[held.len() - 2000..];
        Sim {
            reached,
            queued_s: f64::from(queued) / 1000.0,
            idle_s: held.iter().filter(|q| **q < 2.0).count() as f64 / 1000.0,
            settled_ms: (
                last.iter().fold(f64::MAX, |m, q| m.min(*q)),
                last.iter().fold(0.0f64, |m, q| m.max(*q)),
            ),
        }
    }

    /// Outcome of [`simulate`].
    #[derive(Debug)]
    struct Sim {
        /// Seconds until the sent rate first reaches 90% of capacity.
        reached: Option<f64>,
        /// Seconds the bottleneck holds at least 2 ms of queue, which is what capacity
        /// derivation needs.
        queued_s: f64,
        /// Seconds of the second half (hold) with less than 2 ms of queue: the bottleneck
        /// idles or nearly so.
        idle_s: f64,
        /// Smallest and largest queue (ms) in the last 2 s.
        settled_ms: (f64, f64),
    }

    #[test]
    fn saturation_reaches_capacity_on_geo_paths() {
        // 300 ms each way at 100 Mbit/s (issue #30). Exiting slow start on lagged delivery
        // feedback took 6.7 s to reach 90% of capacity here.
        let s = simulate(100e6, 300, 10);
        assert!(s.reached.is_some_and(|t| t < 5.0), "{s:?}");
        assert!(s.queued_s >= 2.0, "{s:?}");
        // 20 Mbit/s (the `geo` ground-truth scenario).
        let s = simulate(20e6, 300, 10);
        assert!(s.reached.is_some_and(|t| t < 4.0), "{s:?}");
        assert!(s.queued_s >= 2.0, "{s:?}");
        // Short path: unchanged 50 ms steps.
        let s = simulate(100e6, 10, 10);
        assert!(s.reached.is_some_and(|t| t < 1.0), "{s:?}");
        assert!(s.queued_s >= 5.0, "{s:?}");
    }

    #[test]
    fn hold_keeps_a_queue_on_long_rtt_paths() {
        // Issue #40: hold acted on a queue one feedback lag old. At 300 ms one way it held 0.7×
        // capacity for a whole RTT after the queue had drained, so the bottleneck idled about
        // half the hold time (2.3 of 5 s here at 100 Mbit/s, 2.6 s at 20 Mbit/s, 0.8 s even at
        // 10 ms one way) and the rate swung 70–130 Mbit/s. Corrected for the bits sent since
        // the reported packet, the queue never empties in hold and settles at the 10 ms target
        // (9.8–10.2 ms here).
        for (cap, owd) in [
            (100e6, 300),
            (20e6, 300),
            (100e6, 250),
            (100e6, 150),
            (10e6, 150),
            (100e6, 50),
            (100e6, 10),
        ] {
            let s = simulate(cap, owd, 10);
            assert!(s.idle_s < 0.05, "{cap} bit/s, {owd} ms: {s:?}");
            let (lo, hi) = s.settled_ms;
            assert!(lo > 9.0 && hi < 11.0, "{cap} bit/s, {owd} ms: {s:?}");
        }
    }

    #[test]
    fn excess_bits_integrates_the_rate_history_over_the_window() {
        let mut h = VecDeque::new();
        push_rate(&mut h, 0, 100 * MS, 10e6);
        push_rate(&mut h, 50 * MS, 100 * MS, 20e6);
        // [0, 50) at 10 Mbit/s, [50, 100) at 20 Mbit/s, against a 10 Mbit/s delivery rate.
        assert!((excess_bits(&h, 100 * MS, 100 * MS, 10e6) - 500_000.0).abs() < 1.0);
        // Only the last 20 ms count.
        assert!((excess_bits(&h, 100 * MS, 20 * MS, 10e6) - 200_000.0).abs() < 1.0);
        // Below the delivery rate the excess is negative (the queue drains).
        assert!((excess_bits(&h, 100 * MS, 100 * MS, 30e6) + 1_500_000.0).abs() < 1.0);
        // Entries older than the window, other than the one in effect at its start, go.
        push_rate(&mut h, 200 * MS, 100 * MS, 5e6);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].0, 50 * MS);
    }
}
