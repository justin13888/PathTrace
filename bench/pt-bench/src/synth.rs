//! Synthetic, seeded observation streams shaped like a PathTrace `standard` session.
//!
//! The goal is realistic *entropy*, since that is what determines encoded size: paced send
//! times with pacing error, bottleneck-spaced arrivals with timestamp noise, Wi-Fi-style
//! aggregation bursts, queueing and drops at a finite buffer, Gilbert-Elliott intrinsic loss,
//! and clock offset/skew between endpoints.

/// One observed probe packet (one row of the joined per-packet table).
#[derive(Debug, Clone)]
pub struct Pkt {
    pub flow: u64,
    pub seq: u64,
    /// IP bytes.
    pub size: u64,
    /// Scheduled send time, sender CLOCK_MONOTONIC_RAW, ns.
    pub tx_intended: u64,
    /// Kernel transmit timestamp, sender CLOCK_REALTIME, ns.
    pub tx: u64,
    /// Kernel receive timestamp, receiver CLOCK_REALTIME, ns; None if lost.
    pub rx: Option<u64>,
    pub tos: Option<u64>,
    pub ttl: Option<u64>,
    pub phase: u64,
}

/// Small deterministic PRNG (SplitMix64); no external dependency so results are stable.
#[derive(Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn normal(&mut self) -> f64 {
        let u1 = self.unit().max(1e-300);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
    pub fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.unit()).ln()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    pub name: &'static str,
    /// Bottleneck rate per direction, bit/s.
    pub rate_bps: f64,
    /// Wi-Fi-style receive aggregation (A-MPDU bursts).
    pub aggregated: bool,
    pub seed: u64,
}

pub const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "wired-10M",
        rate_bps: 10e6,
        aggregated: false,
        seed: 1,
    },
    Scenario {
        name: "wired-100M",
        rate_bps: 100e6,
        aggregated: false,
        seed: 2,
    },
    Scenario {
        name: "wired-500M",
        rate_bps: 500e6,
        aggregated: false,
        seed: 3,
    },
    Scenario {
        name: "wifi-100M",
        rate_bps: 100e6,
        aggregated: true,
        seed: 4,
    },
];

const S: f64 = 1e9;
const MONO0: u64 = 12_345_000_000_000;
const REAL0: u64 = 1_791_000_000_000_000_000;
const SESSION_S: f64 = 60.0;

struct Send {
    flow: u64,
    seq: u64,
    size: u64,
    t_int: f64,
    t_tx: f64,
    phase: u64,
}

/// Phases: 2 quiet, 4 saturate a→b, 5 saturate b→a, 6 both, 8 tail.
fn phase_at(t: f64) -> u64 {
    match t {
        t if t < 15.0 => 2,
        t if t < 25.0 => 4,
        t if t < 35.0 => 5,
        t if t < 40.0 => 6,
        _ => 8,
    }
}

fn heavy_active(dir: u64, t: f64) -> bool {
    let p = phase_at(t);
    p == 6 || (dir == 0 && p == 4) || (dir == 1 && p == 5)
}

/// Generate all packets of a session, both directions.
pub fn generate(sc: &Scenario) -> Vec<Pkt> {
    let mut rng = Rng::new(sc.seed);
    let mut out = Vec::new();
    for dir in 0..2u64 {
        let mut sends = Vec::new();
        // Light flow: 50 pps, 128 B.
        let mut seq = 0;
        let mut t = 0.0;
        while t < SESSION_S {
            let err = rng.exp(5e-6) + if rng.unit() < 0.005 { 200e-6 } else { 0.0 };
            sends.push(Send {
                flow: dir,
                seq,
                size: 128,
                t_int: t,
                t_tx: t + err,
                phase: phase_at(t),
            });
            seq += 1;
            t += 0.02;
        }
        // Light trains: 8 × 1500 B back-to-back every 500 ms.
        let mut seq = 0;
        let mut t = 0.25;
        while t < SESSION_S {
            let base = t + rng.exp(5e-6);
            for i in 0..8 {
                let tt = base + f64::from(i) * 12e-6 + rng.exp(0.5e-6);
                sends.push(Send {
                    flow: 2 + dir,
                    seq,
                    size: 1500,
                    t_int: t,
                    t_tx: tt,
                    phase: phase_at(t),
                });
                seq += 1;
            }
            t += 0.5;
        }
        // Heavy flow: ramp 0.5R→2R over 2 s, then hold 1.05R (feedback-controlled).
        let mut seq = 0;
        let mut t = 0.0;
        let mut started: Option<f64> = None;
        while t < SESSION_S {
            if heavy_active(dir, t) {
                let s0 = *started.get_or_insert(t);
                let el = t - s0;
                let rate = if el < 2.0 {
                    sc.rate_bps * (0.5 + 0.75 * el)
                } else {
                    sc.rate_bps * 1.05
                };
                let gap = 1500.0 * 8.0 / rate;
                let tt = t + rng.exp(3e-6);
                sends.push(Send {
                    flow: 4 + dir,
                    seq,
                    size: 1500,
                    t_int: t,
                    t_tx: tt,
                    phase: phase_at(t),
                });
                seq += 1;
                t += gap;
            } else {
                started = None;
                t += 0.001;
            }
        }
        sends.sort_by(|a, b| a.t_tx.total_cmp(&b.t_tx));

        // Bottleneck: FIFO at rate R with a 100 ms buffer, base delay, AR(1) jitter,
        // Gilbert-Elliott intrinsic loss, optional aggregation, receiver clock offset/skew.
        let buffer_bytes = sc.rate_bps / 8.0 * 0.1;
        let (offset, skew) = if dir == 0 {
            (3.2e-3, 4e-6)
        } else {
            (-3.2e-3, -4e-6)
        };
        let mut last_dep = 0.0f64;
        let mut queue: std::collections::VecDeque<(f64, f64)> = Default::default(); // (dep, bytes)
        let mut q_bytes = 0.0;
        let mut jitter = 0.0f64;
        let mut ge_bad = false;
        let mut next_burst = 0.0f64;
        for s in &sends {
            while let Some(&(dep, b)) = queue.front() {
                if dep <= s.t_tx {
                    q_bytes -= b;
                    queue.pop_front();
                } else {
                    break;
                }
            }
            let ser = s.size as f64 * 8.0 / sc.rate_bps;
            let mut rx = None;
            if q_bytes + s.size as f64 <= buffer_bytes {
                let dep = last_dep.max(s.t_tx) + ser;
                last_dep = dep;
                queue.push_back((dep, s.size as f64));
                q_bytes += s.size as f64;
                ge_bad = if ge_bad {
                    rng.unit() > 0.3
                } else {
                    rng.unit() < 0.0005
                };
                if !ge_bad {
                    jitter = 0.95 * jitter + 0.05 * rng.normal() * 2e-3;
                    let mut arr = dep + 0.020 + jitter.abs();
                    if sc.aggregated {
                        // Deliver in bursts every ~2 ms.
                        if arr > next_burst {
                            next_burst = arr + 0.0015 + rng.exp(0.0005);
                        }
                        arr = next_burst + rng.exp(8e-6);
                    }
                    let rel = offset + arr * (1.0 + skew) + rng.normal().abs() * 1e-6;
                    rx = Some(REAL0 + (rel * S) as u64);
                }
            }
            out.push(Pkt {
                flow: s.flow,
                seq: s.seq,
                size: s.size,
                tx_intended: MONO0 + (s.t_int * S) as u64,
                tx: REAL0 + (s.t_tx * S) as u64,
                rx,
                tos: rx.map(|_| 0),
                ttl: rx.map(|_| if s.seq % 50_000 == 49_999 { 51 } else { 52 }),
                phase: s.phase,
            });
        }
    }
    // Rows grouped by flow, in sequence order: the order of the canonical per-packet table.
    out.sort_by_key(|p| (p.flow, p.seq));
    out
}
