//! Flow specifications shared by both endpoints and the pacer's packet generators.
//!
//! A [`FlowSpec`] fully determines what a sender transmits, so the initiator can define every
//! flow and send the definition to the responder; both sides log the same definitions to FLOW.

use pt_format::Value;
use pt_wire::ctrl::BodyExt;

/// Which endpoint sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiator.
    A,
    /// Responder.
    B,
}

impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Role::A => "a",
            Role::B => "b",
        }
    }
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "a" => Some(Role::A),
            "b" => Some(Role::B),
            _ => None,
        }
    }
    pub fn other(self) -> Role {
        match self {
            Role::A => Role::B,
            Role::B => Role::A,
        }
    }
}

/// Logical UDP socket a flow uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sock {
    /// Main socket: `udp/high-port` (responder 4433).
    Main,
    /// `udp/443` socket (opaque and QUIC-shaped classes).
    Udp443,
    /// Initiator spare socket `k` (NAT binding probes).
    Spare(u8),
}

impl Sock {
    pub fn name(self) -> String {
        match self {
            Sock::Main => "main".into(),
            Sock::Udp443 => "udp443".into(),
            Sock::Spare(k) => format!("spare{k}"),
        }
    }
    pub fn parse(s: &str) -> Option<Sock> {
        match s {
            "main" => Some(Sock::Main),
            "udp443" => Some(Sock::Udp443),
            _ => s.strip_prefix("spare")?.parse().ok().map(Sock::Spare),
        }
    }
}

/// Send pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// Isochronous: one packet every `interval_ns`.
    Iso { interval_ns: u64 },
    /// Trains of `count` back-to-back packets every `period_ns`.
    Train { count: u32, period_ns: u64 },
    /// Chirps: `count` packets with gaps shrinking geometrically from `gap0_ns` by `factor`,
    /// repeated every `period_ns`.
    Chirp {
        count: u32,
        gap0_ns: u64,
        factor: f64,
        period_ns: u64,
    },
    /// Rate-paced at a controllable rate (heavy / CBR). `controlled` = saturation controller.
    Rate { bps: u64, controlled: bool },
    /// PMTU ladder: each IP size `reps` times, `gap_ns` apart.
    Ladder {
        sizes: Vec<u32>,
        reps: u32,
        gap_ns: u64,
    },
    /// Exactly `count` packets, `gap_ns` apart (class / NAT probes).
    Burst { count: u32, gap_ns: u64 },
}

/// TOS byte policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tos {
    Fixed(u8),
    /// Cycle ECN {not-ECT, ECT(0), ECT(1), CE} × DSCP {0, CS1, AF41, EF} per packet
    /// (docs/design/probe.md §6).
    Cycle,
}

pub const TOS_CYCLE: [u8; 16] = {
    let dscp = [0u8, 8, 34, 46];
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = (dscp[i / 4] << 2) | (i % 4) as u8;
        i += 1;
    }
    out
};

/// Flow purpose (recorded; drives derivation).
pub const KINDS: &[&str] = &[
    "light",
    "train",
    "chirp",
    "heavy",
    "cbr",
    "class",
    "nat",
    "pmtu",
    "class-sat",
];

#[derive(Debug, Clone, PartialEq)]
pub struct FlowSpec {
    pub id: u8,
    pub kind: String,
    pub sender: Role,
    pub sock: Sock,
    /// Destination port at the responder (initiator-sent flows) — the responder replies to
    /// observed source tuples.
    pub dst_port: u16,
    /// Transport class label (`udp/high-port`, `udp/443`, `udp/443-quic`).
    pub class: String,
    /// QUIC header framing (`header/1`) or none.
    pub quic: bool,
    pub phase: u16,
    /// IP packet size in bytes (ladder flows override per packet).
    pub size: u32,
    pub pattern: Pattern,
    pub tos: Tos,
    /// Duration from start; 0 = until stopped.
    pub duration_ns: u64,
    /// Packets that the receiver should echo straight back (class/NAT probes).
    pub echo: bool,
    /// Echo delay at the receiver (NAT binding probes), ns.
    pub echo_delay_ns: u64,
    /// Byte allowance: the sender stops the flow once it has sent this many IP bytes
    /// (0 = none; docs/design/probe.md §6).
    pub max_bytes: u64,
}

impl FlowSpec {
    pub fn to_value(&self) -> Value {
        let pat = match &self.pattern {
            Pattern::Iso { interval_ns } => Value::map()
                .with("type", "iso")
                .with("interval_ns", *interval_ns),
            Pattern::Train { count, period_ns } => Value::map()
                .with("type", "train")
                .with("count", *count)
                .with("period_ns", *period_ns),
            Pattern::Chirp {
                count,
                gap0_ns,
                factor,
                period_ns,
            } => Value::map()
                .with("type", "chirp")
                .with("count", *count)
                .with("gap0_ns", *gap0_ns)
                .with("factor", *factor)
                .with("period_ns", *period_ns),
            Pattern::Rate { bps, controlled } => Value::map()
                .with("type", "rate")
                .with("bps", *bps)
                .with("controlled", *controlled),
            Pattern::Ladder {
                sizes,
                reps,
                gap_ns,
            } => Value::map()
                .with("type", "ladder")
                .with(
                    "sizes",
                    Value::Array(sizes.iter().map(|s| Value::from(*s)).collect()),
                )
                .with("reps", *reps)
                .with("gap_ns", *gap_ns),
            Pattern::Burst { count, gap_ns } => Value::map()
                .with("type", "burst")
                .with("count", *count)
                .with("gap_ns", *gap_ns),
        };
        let tos = match self.tos {
            Tos::Fixed(t) => Value::from(u64::from(t)),
            Tos::Cycle => Value::from("cycle"),
        };
        let v = Value::map()
            .with("id", self.id)
            .with("kind", self.kind.as_str())
            .with("sender", self.sender.name())
            .with("sock", self.sock.name())
            .with("dst_port", self.dst_port)
            .with("class", self.class.as_str())
            .with(
                "quic_shape",
                if self.quic {
                    Value::from("header/1")
                } else {
                    Value::Null
                },
            )
            .with("phase", self.phase)
            .with("size", self.size)
            .with("pattern", pat)
            .with("tos", tos)
            .with("duration_ns", self.duration_ns)
            .with("echo", self.echo)
            .with("echo_delay_ns", self.echo_delay_ns);
        if self.max_bytes > 0 {
            v.with("max_bytes", self.max_bytes)
        } else {
            v
        }
    }

    pub fn from_value(v: &Value) -> Option<FlowSpec> {
        let p = v.get("pattern")?;
        let pattern = match p.get("type")?.as_str()? {
            "iso" => Pattern::Iso {
                interval_ns: p.get("interval_ns")?.as_u64()?,
            },
            "train" => Pattern::Train {
                count: p.get("count")?.as_u64()? as u32,
                period_ns: p.get("period_ns")?.as_u64()?,
            },
            "chirp" => Pattern::Chirp {
                count: p.get("count")?.as_u64()? as u32,
                gap0_ns: p.get("gap0_ns")?.as_u64()?,
                factor: p.get("factor")?.as_f64()?,
                period_ns: p.get("period_ns")?.as_u64()?,
            },
            "rate" => Pattern::Rate {
                bps: p.get("bps")?.as_u64()?,
                controlled: p.get("controlled")?.as_bool()?,
            },
            "ladder" => Pattern::Ladder {
                sizes: p
                    .get("sizes")?
                    .as_array()?
                    .iter()
                    .filter_map(|s| s.as_u64().map(|x| x as u32))
                    .collect(),
                reps: p.get("reps")?.as_u64()? as u32,
                gap_ns: p.get("gap_ns")?.as_u64()?,
            },
            "burst" => Pattern::Burst {
                count: p.get("count")?.as_u64()? as u32,
                gap_ns: p.get("gap_ns")?.as_u64()?,
            },
            _ => return None,
        };
        let tos = match v.get("tos")? {
            Value::Text(t) if t == "cycle" => Tos::Cycle,
            other => Tos::Fixed(other.as_u64()? as u8),
        };
        Some(FlowSpec {
            id: v.get("id")?.as_u64()? as u8,
            kind: v.get("kind")?.as_str()?.to_string(),
            sender: Role::parse(v.get("sender")?.as_str()?)?,
            sock: Sock::parse(v.get("sock")?.as_str()?)?,
            dst_port: v.get("dst_port")?.as_u64()? as u16,
            class: v.str_or("class", "udp/high-port").to_string(),
            quic: v.get("quic_shape").and_then(Value::as_str).is_some(),
            phase: v.u64_or("phase", 0) as u16,
            size: v.get("size")?.as_u64()? as u32,
            pattern,
            tos,
            duration_ns: v.u64_or("duration_ns", 0),
            echo: v.get("echo").and_then(Value::as_bool).unwrap_or(false),
            echo_delay_ns: v.u64_or("echo_delay_ns", 0),
            max_bytes: v.u64_or("max_bytes", 0),
        })
    }
}

/// Per-flow packet schedule state in the pacer.
#[derive(Debug, Clone)]
pub struct Gen {
    pub spec: FlowSpec,
    pub start: u64,
    pub next_due: u64,
    pub seq: u64,
    pub train: u32,
    pub idx: u32,
    /// Current rate for `Rate` patterns (bit/s).
    pub bps: u64,
    pub done: bool,
    /// Paused by the dead-man switch (session-long observers only).
    pub paused: bool,
}

/// One packet the pacer should send now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Due {
    pub seq: u64,
    pub t_intended: u64,
    pub size: u32,
    pub tos: u8,
    pub train: u32,
    pub train_idx: u16,
    pub last_of_train: bool,
}

impl Gen {
    pub fn new(spec: FlowSpec, start: u64) -> Gen {
        let bps = match spec.pattern {
            Pattern::Rate { bps, .. } => bps,
            _ => 0,
        };
        Gen {
            spec,
            start,
            next_due: start,
            seq: 0,
            train: 0,
            idx: 0,
            bps,
            done: false,
            paused: false,
        }
    }

    fn ended(&self, t: u64) -> bool {
        self.spec.duration_ns > 0 && t >= self.start + self.spec.duration_ns
    }

    /// Produce the packet due at `next_due` and advance the schedule. Returns `None` when the
    /// flow has finished.
    pub fn take(&mut self) -> Option<Due> {
        if self.done || self.ended(self.next_due) {
            self.done = true;
            return None;
        }
        let t = self.next_due;
        let tos = match self.spec.tos {
            Tos::Fixed(v) => v,
            Tos::Cycle => TOS_CYCLE[(self.seq % 16) as usize],
        };
        let mut due = Due {
            seq: self.seq,
            t_intended: t,
            size: self.spec.size,
            tos,
            train: self.train,
            train_idx: self.idx as u16,
            last_of_train: false,
        };
        match &self.spec.pattern {
            Pattern::Iso { interval_ns } => self.next_due += interval_ns,
            Pattern::Train { count, period_ns } => {
                self.idx += 1;
                if self.idx >= *count {
                    due.last_of_train = true;
                    self.idx = 0;
                    self.train += 1;
                    self.next_due = self.start + u64::from(self.train) * period_ns;
                }
                // Back-to-back: next packet due immediately (same deadline).
            }
            Pattern::Chirp {
                count,
                gap0_ns,
                factor,
                period_ns,
            } => {
                self.idx += 1;
                if self.idx >= *count {
                    due.last_of_train = true;
                    self.idx = 0;
                    self.train += 1;
                    self.next_due = self.start + u64::from(self.train) * period_ns;
                } else {
                    let gap = (*gap0_ns as f64 * factor.powi(self.idx as i32 - 1)).max(1.0) as u64;
                    self.next_due += gap;
                }
            }
            Pattern::Rate { .. } => {
                let bps = self.bps.max(1000);
                self.next_due += (u64::from(self.spec.size) * 8 * 1_000_000_000) / bps;
            }
            Pattern::Ladder {
                sizes,
                reps,
                gap_ns,
            } => {
                let i = (self.seq / u64::from((*reps).max(1))) as usize;
                let Some(sz) = sizes.get(i) else {
                    self.done = true;
                    return None;
                };
                due.size = *sz;
                self.next_due += gap_ns;
            }
            Pattern::Burst { count, gap_ns } => {
                if self.seq >= u64::from(*count) {
                    self.done = true;
                    return None;
                }
                self.next_due += gap_ns;
            }
        }
        self.seq += 1;
        Some(due)
    }

    /// Bring a schedule that is more than `max_late` ns behind `now` back to `now`
    /// (docs/design/probe.md §4.3). A stream (iso, train, chirp, rate) skips every overdue
    /// packet: its sequence numbers are consumed and never sent. A counted pattern (ladder,
    /// burst), whose every packet is needed, keeps its packets and shifts the rest of its
    /// schedule by the delay. Returns `None` when the flow is not stalled.
    pub fn skip_overdue(&mut self, now: u64, max_late: u64) -> Option<Catchup> {
        if self.done || self.next_due.saturating_add(max_late) >= now {
            return None;
        }
        let late_ns = now - self.next_due;
        let mut c = Catchup {
            late_ns,
            skipped: 0,
            shifted_ns: 0,
        };
        match self.spec.pattern {
            Pattern::Ladder { .. } | Pattern::Burst { .. } => {
                self.next_due = now;
                c.shifted_ns = late_ns;
            }
            _ => {
                while self.next_due < now && self.take().is_some() {
                    c.skipped += 1;
                }
            }
        }
        Some(c)
    }
}

/// What [`Gen::skip_overdue`] did to a stalled flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Catchup {
    /// How far the flow's next deadline was behind, ns.
    pub late_ns: u64,
    /// Overdue packets skipped (streams).
    pub skipped: u64,
    /// How far the schedule was shifted, ns (counted patterns).
    pub shifted_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(pattern: Pattern) -> FlowSpec {
        FlowSpec {
            id: 1,
            kind: "light".into(),
            sender: Role::A,
            sock: Sock::Main,
            dst_port: 4433,
            class: "udp/high-port".into(),
            quic: false,
            phase: 2,
            size: 128,
            pattern,
            tos: Tos::Cycle,
            duration_ns: 1_000_000_000,
            echo: false,
            echo_delay_ns: 0,
            max_bytes: 0,
        }
    }

    #[test]
    fn spec_roundtrip() {
        for p in [
            Pattern::Iso {
                interval_ns: 20_000_000,
            },
            Pattern::Train {
                count: 8,
                period_ns: 500_000_000,
            },
            Pattern::Chirp {
                count: 20,
                gap0_ns: 1_000_000,
                factor: 0.85,
                period_ns: 250_000_000,
            },
            Pattern::Rate {
                bps: 10_000_000,
                controlled: true,
            },
            Pattern::Ladder {
                sizes: vec![1200, 1500],
                reps: 3,
                gap_ns: 10_000_000,
            },
            Pattern::Burst {
                count: 3,
                gap_ns: 100_000_000,
            },
        ] {
            let s = spec(p);
            assert_eq!(FlowSpec::from_value(&s.to_value()), Some(s));
        }
    }

    #[test]
    fn iso_and_train_schedules() {
        let mut g = Gen::new(
            spec(Pattern::Iso {
                interval_ns: 20_000_000,
            }),
            0,
        );
        let mut n = 0;
        while g.take().is_some() {
            n += 1;
        }
        assert_eq!(n, 50);
        let mut g = Gen::new(
            spec(Pattern::Train {
                count: 8,
                period_ns: 500_000_000,
            }),
            0,
        );
        let first: Vec<Due> = (0..9).map(|_| g.take().unwrap()).collect();
        assert!(first[..8].iter().all(|d| d.t_intended == 0));
        assert!(first[7].last_of_train);
        assert_eq!(first[8].t_intended, 500_000_000);
        assert_eq!(first[8].train, 1);
    }

    #[test]
    fn ladder_and_tos_cycle() {
        let mut g = Gen::new(
            spec(Pattern::Ladder {
                sizes: vec![1200, 1400],
                reps: 2,
                gap_ns: 1,
            }),
            0,
        );
        let sizes: Vec<u32> = std::iter::from_fn(|| g.take().map(|d| d.size)).collect();
        assert_eq!(sizes, vec![1200, 1200, 1400, 1400]);
        assert_eq!(TOS_CYCLE[0], 0);
        assert_eq!(TOS_CYCLE[3], 3);
        assert_eq!(TOS_CYCLE[15], (46 << 2) | 3);
    }

    const MS: u64 = 1_000_000;

    #[test]
    fn stalled_stream_skips_overdue_packets_and_keeps_its_phase() {
        let mut g = Gen::new(
            spec(Pattern::Iso {
                interval_ns: 20 * MS,
            }),
            0,
        );
        g.take().unwrap();
        // Woken 101 ms after the deadline at 20 ms: the packets due at 20 … 120 ms are overdue.
        let c = g.skip_overdue(121 * MS, 2 * MS).unwrap();
        assert_eq!(
            c,
            Catchup {
                late_ns: 101 * MS,
                skipped: 6,
                shifted_ns: 0
            }
        );
        let d = g.take().unwrap();
        assert_eq!((d.seq, d.t_intended), (7, 140 * MS));
    }

    #[test]
    fn small_lateness_is_left_to_catch_up() {
        let mut g = Gen::new(
            spec(Pattern::Iso {
                interval_ns: 20 * MS,
            }),
            0,
        );
        assert_eq!(g.skip_overdue(2 * MS, 2 * MS), None);
        assert_eq!(g.take().unwrap().seq, 0);
    }

    #[test]
    fn mid_train_stall_skips_the_rest_of_the_train() {
        let mut g = Gen::new(
            spec(Pattern::Train {
                count: 8,
                period_ns: 500 * MS,
            }),
            0,
        );
        for _ in 0..3 {
            g.take().unwrap();
        }
        let c = g.skip_overdue(10 * MS, 2 * MS).unwrap();
        assert_eq!(c.skipped, 5);
        let d = g.take().unwrap();
        assert_eq!((d.train, d.train_idx, d.t_intended), (1, 0, 500 * MS));
    }

    #[test]
    fn stall_past_the_end_finishes_the_flow() {
        let mut g = Gen::new(
            spec(Pattern::Iso {
                interval_ns: 20 * MS,
            }),
            0,
        );
        let c = g.skip_overdue(5_000 * MS, 2 * MS).unwrap();
        assert_eq!(c.skipped, 50);
        assert!(g.take().is_none());
        assert_eq!(g.skip_overdue(6_000 * MS, 2 * MS), None);
    }

    #[test]
    fn counted_patterns_shift_and_lose_nothing() {
        let mut g = Gen::new(
            spec(Pattern::Ladder {
                sizes: vec![1200, 1400],
                reps: 2,
                gap_ns: 20 * MS,
            }),
            0,
        );
        g.take().unwrap();
        let c = g.skip_overdue(100 * MS, 2 * MS).unwrap();
        assert_eq!(
            c,
            Catchup {
                late_ns: 80 * MS,
                skipped: 0,
                shifted_ns: 80 * MS
            }
        );
        let rest: Vec<(u32, u64)> =
            std::iter::from_fn(|| g.take().map(|d| (d.size, d.t_intended))).collect();
        assert_eq!(
            rest,
            vec![(1200, 100 * MS), (1400, 120 * MS), (1400, 140 * MS)]
        );
        let mut g = Gen::new(
            spec(Pattern::Burst {
                count: 3,
                gap_ns: 100 * MS,
            }),
            0,
        );
        g.take().unwrap();
        assert_eq!(
            g.skip_overdue(300 * MS, 2 * MS).unwrap().shifted_ns,
            200 * MS
        );
        let seqs: Vec<u64> = std::iter::from_fn(|| g.take().map(|d| d.seq)).collect();
        assert_eq!(seqs, vec![1, 2]);
    }
}
