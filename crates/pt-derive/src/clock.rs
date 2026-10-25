//! Clock models (docs/design/derivation.md "Time base").

use pt_format::Value;

use crate::raw::Raw;

/// Piecewise-linear REALTIME → MONO_RAW map for one endpoint.
#[derive(Debug, Clone, Default)]
pub struct RealToMono {
    /// (real, mono) sorted by real.
    pts: Vec<(i64, i64)>,
    pub steps: Vec<(i64, i64)>,
}

impl RealToMono {
    pub fn from_raw(raw: &Raw, ep: &str) -> RealToMono {
        let mut pts: Vec<(i64, i64)> = Vec::new();
        if let Some(t) = raw.table(&format!("pairs[{ep}]")) {
            for i in 0..t.n {
                if let (Some(m), Some(r)) = (t.get("mono", i), t.get("real", i)) {
                    pts.push((r, m));
                }
            }
        }
        pts.sort();
        pts.dedup_by_key(|p| p.0);
        let mut steps = Vec::new();
        for w in pts.windows(2) {
            let (d0, d1) = (w[0].0 - w[0].1, w[1].0 - w[1].1);
            if (d1 - d0).abs() > 1_000_000 {
                steps.push((w[1].1, d1 - d0));
            }
        }
        RealToMono { pts, steps }
    }

    pub fn is_empty(&self) -> bool {
        self.pts.is_empty()
    }

    /// Map a REALTIME value to MONO_RAW.
    pub fn map(&self, real: i64) -> Option<i64> {
        let p = &self.pts;
        match p.len() {
            0 => None,
            1 => Some(real - (p[0].0 - p[0].1)),
            n => {
                let i = p.partition_point(|x| x.0 <= real).clamp(1, n - 1);
                let (a, b) = (p[i - 1], p[i]);
                let slope = (b.1 - a.1) as f64 / (b.0 - a.0).max(1) as f64;
                Some(a.1 + ((real - a.0) as f64 * slope).round() as i64)
            }
        }
    }

    /// MONO_RAW rate against REALTIME (d mono / d real) over the step-free
    /// consecutive pairs, or None when they span less than `MIN_SPAN_NS`.
    pub fn rate(&self) -> Option<f64> {
        let (mut dm, mut dr) = (0i64, 0i64);
        for w in self.pts.windows(2) {
            let (d0, d1) = (w[0].0 - w[0].1, w[1].0 - w[1].1);
            if (d1 - d0).abs() > 1_000_000 {
                continue;
            }
            dr += w[1].0 - w[0].0;
            dm += w[1].1 - w[0].1;
        }
        (dr as f64 >= MIN_SPAN_NS).then(|| dm as f64 / dr as f64)
    }

    pub fn to_value(&self, method: &str) -> Value {
        Value::map()
            .with("method", method)
            .with("pairs", self.pts.len())
            .with(
                "steps",
                Value::Array(
                    self.steps
                        .iter()
                        .map(|(t, d)| Value::map().with("mono", *t).with("jump_ns", *d))
                        .collect(),
                ),
            )
    }
}

/// Shortest span (ns) of exchanges or step-free pairs that a skew is fitted over.
const MIN_SPAN_NS: f64 = 10e9;
/// Largest believable |skew| (500 ppm, the kernel NTP discipline's MAXFREQ).
const MAX_SKEW: f64 = 500e-6;
/// Span (ns) from which an exchange skew earns full confidence.
const FULL_SPAN_NS: f64 = 60e9;

/// Where `Offset::skew` came from (derivation.md "Clock skew").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SkewSource {
    /// Lower envelopes of the two one-way delays.
    Exchange,
    /// Both endpoints' REALTIME/MONO_RAW rates.
    Pairs,
    /// Neither was usable; skew is 0.
    #[default]
    None,
}

impl SkewSource {
    fn as_str(self) -> &'static str {
        match self {
            SkewSource::Exchange => "exchange",
            SkewSource::Pairs => "pairs",
            SkewSource::None => "none",
        }
    }
}

/// One offset exchange: a sends at t1 (a.mono), b receives at t2 and replies at
/// t3 (b.mono), a receives at t4 (a.mono).
#[derive(Debug, Clone, Copy)]
pub struct Exchange {
    pub t1: i64,
    pub t2: i64,
    pub t3: i64,
    pub t4: i64,
}

/// b.mono = a.mono + offset(t) with offset(t) = theta0 + skew·(t − t_ref).
#[derive(Debug, Clone, Default)]
pub struct Offset {
    pub theta0: f64,
    pub skew: f64,
    pub t_ref: f64,
    pub uncertainty_ns: f64,
    pub min_rtt_ns: f64,
    pub samples: usize,
    pub used: usize,
    pub skew_source: SkewSource,
    /// Envelope skew, whether or not it was used.
    pub skew_exchange: Option<f64>,
    /// Half the disagreement of the two envelope slopes.
    pub skew_exchange_uncertainty: Option<f64>,
    /// Pairs skew, whether or not it was used.
    pub skew_pairs: Option<f64>,
    /// t1 span of the exchanges (ns).
    pub span_ns: f64,
}

impl Offset {
    pub fn from_raw(raw: &Raw, a: &RealToMono, b: &RealToMono) -> Option<Offset> {
        let t = raw.table("exchange[a]")?;
        let ex: Vec<Exchange> = (0..t.n)
            .filter_map(|i| {
                Some(Exchange {
                    t1: t.get("t1", i)?,
                    t2: t.get("t2", i)?,
                    t3: t.get("t3", i)?,
                    t4: t.get("t4", i)?,
                })
            })
            .collect();
        let pairs = match (a.rate(), b.rate()) {
            (Some(ra), Some(rb)) if ra > 0.0 => Some(rb / ra - 1.0),
            _ => None,
        };
        Offset::fit(&ex, pairs)
    }

    /// Fit the offset to `ex`, with `pairs` the pairs-derived skew if any
    /// (derivation.md "Time base", `clock.exchange-minfilter/2`).
    pub fn fit(ex: &[Exchange], pairs: Option<f64>) -> Option<Offset> {
        let s: Vec<&Exchange> = ex
            .iter()
            .filter(|e| (e.t4 - e.t1) - (e.t3 - e.t2) >= 0)
            .collect();
        if s.is_empty() {
            return None;
        }
        let theta = |e: &Exchange| ((e.t2 - e.t1) as f64 + (e.t3 - e.t4) as f64) / 2.0;
        let delta = |e: &Exchange| ((e.t4 - e.t1) - (e.t3 - e.t2)) as f64;
        let mut d: Vec<f64> = s.iter().map(|e| delta(e)).collect();
        d.sort_by(f64::total_cmp);
        let cut = d[(d.len() / 4).min(d.len() - 1)];
        let kept: Vec<&Exchange> = s.iter().copied().filter(|e| delta(e) <= cut).collect();
        let n = kept.len() as f64;
        let mt = kept.iter().map(|e| e.t1 as f64).sum::<f64>() / n;
        let mth = kept.iter().map(|e| theta(e)).sum::<f64>() / n;

        let (lo, hi) = s.iter().fold((i64::MAX, i64::MIN), |(lo, hi), e| {
            (lo.min(e.t1), hi.max(e.t1))
        });
        let span_ns = (hi - lo) as f64;
        // Forward delay θ(t) + owd_f against t1, backward owd_b − θ(t) against t4.
        let fwd: Vec<(f64, f64)> = s
            .iter()
            .map(|e| (e.t1 as f64, (e.t2 - e.t1) as f64))
            .collect();
        let bwd: Vec<(f64, f64)> = s
            .iter()
            .map(|e| (e.t4 as f64, (e.t4 - e.t3) as f64))
            .collect();
        let env = match (envelope_slope(fwd), envelope_slope(bwd)) {
            (Some(sf), Some(sb)) => Some((sf, sb)),
            _ => None,
        };
        let skew_exchange = env.map(|(sf, sb)| (sf - sb) / 2.0);
        let skew_exchange_uncertainty = env.map(|(sf, sb)| (sf + sb).abs() / 2.0);
        let env_ok = span_ns >= MIN_SPAN_NS
            && env.is_some_and(|(sf, sb)| sf.abs() <= MAX_SKEW && sb.abs() <= MAX_SKEW);
        let pairs_ok = pairs.filter(|p| p.abs() <= MAX_SKEW);
        let (skew, skew_source) = match (env_ok, skew_exchange, pairs_ok) {
            (true, Some(k), _) => (k, SkewSource::Exchange),
            (_, _, Some(p)) => (p, SkewSource::Pairs),
            _ => (0.0, SkewSource::None),
        };
        Some(Offset {
            theta0: mth,
            skew,
            t_ref: mt,
            uncertainty_ns: d[0] / 2.0,
            min_rtt_ns: d[0],
            samples: s.len(),
            used: kept.len(),
            skew_source,
            skew_exchange,
            skew_exchange_uncertainty,
            skew_pairs: pairs,
            span_ns,
        })
    }

    pub fn confidence(&self) -> f64 {
        match self.skew_source {
            _ if self.used < 3 => 0.4,
            SkewSource::None => 0.4,
            SkewSource::Pairs => 0.6,
            SkewSource::Exchange if self.used >= 8 && self.span_ns >= FULL_SPAN_NS => 0.9,
            SkewSource::Exchange => 0.7,
        }
    }

    /// Convert b.mono to a.mono.
    pub fn b_to_a(&self, b_mono: i64) -> i64 {
        // Solve a = b - theta0 - skew*(a - t_ref) ≈ b - offset(b - theta0).
        let a0 = b_mono as f64 - self.theta0;
        (b_mono as f64 - (self.theta0 + self.skew * (a0 - self.t_ref))).round() as i64
    }

    pub fn to_value(&self) -> Value {
        Value::map()
            .with("method", OFFSET_METHOD)
            .with("offset_ns", self.theta0)
            .with("skew_ppb", self.skew * 1e9)
            .with("skew_source", self.skew_source.as_str())
            .with("skew_exchange_ppb", self.skew_exchange.map(|k| k * 1e9))
            .with(
                "skew_uncertainty_ppb",
                self.skew_exchange_uncertainty.map(|k| k * 1e9),
            )
            .with("skew_pairs_ppb", self.skew_pairs.map(|k| k * 1e9))
            .with("span_ns", self.span_ns)
            .with("t_ref_a_mono", self.t_ref)
            .with("uncertainty_ns", self.uncertainty_ns)
            .with("min_rtt_ns", self.min_rtt_ns)
            .with("samples", self.samples)
            .with("used", self.used)
            .with("split_method", "symmetric_assumed")
            .with("confidence", self.confidence())
    }
}

/// Method name of the b.mono → a.mono offset.
pub const OFFSET_METHOD: &str = "clock.exchange-minfilter/2";

/// Slope of the line under every point that minimises the summed vertical
/// distance to them: the lower convex hull's edge spanning the points' mean x.
/// None without two distinct x.
fn envelope_slope(mut p: Vec<(f64, f64)>) -> Option<f64> {
    let n = p.len() as f64;
    let mx = p.iter().map(|q| q.0).sum::<f64>() / n;
    p.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.total_cmp(&b.1)));
    // Keep the lowest y of each x, then Andrew's monotone chain (lower hull).
    p.dedup_by(|b, a| a.0 == b.0);
    let mut h: Vec<(f64, f64)> = Vec::with_capacity(p.len());
    for q in p {
        while h.len() >= 2 {
            let (o, a) = (h[h.len() - 2], h[h.len() - 1]);
            // Pop a unless o → a → q turns left (counter-clockwise).
            if (a.0 - o.0) * (q.1 - o.1) - (a.1 - o.1) * (q.0 - o.0) <= 0.0 {
                h.pop();
            } else {
                break;
            }
        }
        h.push(q);
    }
    if h.len() < 2 {
        return None;
    }
    let i = h
        .windows(2)
        .position(|w| w[1].0 >= mx)
        .unwrap_or(h.len() - 2);
    let (a, b) = (h[i], h[i + 1]);
    Some((b.1 - a.1) / (b.0 - a.0))
}

/// Everything needed to put any raw time column onto the trace time axis.
#[derive(Debug, Clone, Default)]
pub struct TimeBase {
    pub a: RealToMono,
    pub b: RealToMono,
    pub off: Option<Offset>,
    pub t0: i64,
}

impl TimeBase {
    pub fn from_raw(raw: &Raw) -> TimeBase {
        let a = RealToMono::from_raw(raw, "a");
        let b = RealToMono::from_raw(raw, "b");
        let off = Offset::from_raw(raw, &a, &b);
        TimeBase {
            a,
            b,
            off,
            t0: raw.t0_a(),
        }
    }

    /// Endpoint real → trace ns.
    pub fn real(&self, ep: &str, real: i64) -> Option<i64> {
        match ep {
            "a" => self.a.map(real).map(|m| m - self.t0),
            _ => {
                let m = self.b.map(real)?;
                Some(self.off.as_ref()?.b_to_a(m) - self.t0)
            }
        }
    }

    /// Endpoint mono → trace ns.
    pub fn mono(&self, ep: &str, mono: i64) -> Option<i64> {
        match ep {
            "a" => Some(mono - self.t0),
            _ => Some(self.off.as_ref()?.b_to_a(mono) - self.t0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piecewise_map() {
        let m = RealToMono {
            pts: vec![(1_000, 100), (2_000, 1_100)],
            steps: vec![],
        };
        assert_eq!(m.map(1_500), Some(600));
        assert_eq!(m.map(3_000), Some(2_100));
    }

    #[test]
    fn offset_inverse() {
        let o = Offset {
            theta0: 5_000_000.0,
            skew: 1e-5,
            t_ref: 1e9,
            ..Default::default()
        };
        let a = 2_000_000_000i64;
        let b = a + (o.theta0 + o.skew * (a as f64 - o.t_ref)) as i64;
        assert!((o.b_to_a(b) - a).abs() < 10);
    }

    /// Deterministic uniform [0, 1).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> f64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    const T0: i64 = 1_000_000_000_000;
    const THETA0: f64 = 5_000_000.0;

    /// Exchanges every `step` ns over `n` steps, with b.mono = a.mono + THETA0 +
    /// skew·(a.mono − T0) and one-way delays `owd(i) -> (fwd, bwd)` in ns.
    fn exchanges(
        n: usize,
        step: i64,
        skew: f64,
        mut owd: impl FnMut(usize) -> (f64, f64),
    ) -> Vec<Exchange> {
        let b = |a: f64| (a + THETA0 + skew * (a - T0 as f64)).round() as i64;
        (0..n)
            .map(|i| {
                let t1 = T0 + i as i64 * step;
                let (f, w) = owd(i);
                let at_b = t1 as f64 + f;
                Exchange {
                    t1,
                    t2: b(at_b),
                    t3: b(at_b + 1e6),
                    t4: (at_b + 1e6 + w).round() as i64,
                }
            })
            .collect()
    }

    #[test]
    fn envelope_recovers_skew_under_one_sided_queueing() {
        // 20 ppm over 120 s; 10 ms floor each way, forward queueing up to
        // 200 ms on 9 of 10 exchanges and backward up to 2 ms.
        let mut r = Lcg(7);
        let ex = exchanges(240, 500_000_000, 20e-6, |_| {
            let q = if r.next() < 0.9 {
                r.next() * 200e6
            } else {
                0.0
            };
            (10e6 + q, 10e6 + r.next() * 2e6)
        });
        let o = Offset::fit(&ex, Some(-300e-6)).unwrap();
        assert_eq!(o.skew_source, SkewSource::Exchange);
        assert!((o.skew - 20e-6).abs() < 1e-6, "skew {}", o.skew);
        assert!(o.skew_exchange_uncertainty.unwrap() < 20e-6);
        assert_eq!(o.confidence(), 0.9);
        let v = o.to_value();
        assert_eq!(v.get("method").and_then(Value::as_str), Some(OFFSET_METHOD));
        assert_eq!(
            v.get("skew_source").and_then(Value::as_str),
            Some("exchange")
        );
    }

    #[test]
    fn short_high_variance_session_falls_back_to_pairs() {
        // Issue #105: 34 s, 52 exchanges, RTT 0.25-39 s with a floor that
        // moves (a relay change mid-session). The envelope slope is far
        // beyond any clock, so the pairs' 16 ppm is used.
        let mut r = Lcg(105);
        let ex = exchanges(52, 650_000_000, 16e-6, |i| {
            let floor = if i < 26 { 150e6 } else { 100e6 };
            let tail = |r: &mut Lcg| r.next().powi(8) * 19e9;
            (floor + tail(&mut r), 100e6 + tail(&mut r))
        });
        let o = Offset::fit(&ex, Some(16e-6)).unwrap();
        assert!(o.skew_exchange.unwrap().abs() > MAX_SKEW);
        assert_eq!(o.skew_source, SkewSource::Pairs);
        assert_eq!(o.skew, 16e-6);
        assert_eq!(o.confidence(), 0.6);
        // Without pairs the skew is 0, not the envelope's.
        let o = Offset::fit(&ex, None).unwrap();
        assert_eq!((o.skew, o.skew_source), (0.0, SkewSource::None));
        assert_eq!(o.confidence(), 0.4);
        // An out-of-bound pairs skew is not used either.
        let o = Offset::fit(&ex, Some(2e-3)).unwrap();
        assert_eq!(o.skew_source, SkewSource::None);
    }

    #[test]
    fn short_span_does_not_fit_a_skew() {
        // 5 s of clean exchanges: the envelope is computed but not used.
        let ex = exchanges(20, 250_000_000, 50e-6, |_| (10e6, 10e6));
        let o = Offset::fit(&ex, Some(16e-6)).unwrap();
        assert!((o.skew_exchange.unwrap() - 50e-6).abs() < 1e-6);
        assert_eq!(o.skew_source, SkewSource::Pairs);
        let o = Offset::fit(&ex, None).unwrap();
        assert_eq!(o.skew_source, SkewSource::None);
    }

    #[test]
    fn exchange_skew_between_full_and_short_span_is_less_confident() {
        let ex = exchanges(60, 500_000_000, -40e-6, |_| (10e6, 10e6));
        let o = Offset::fit(&ex, None).unwrap();
        assert_eq!(o.skew_source, SkewSource::Exchange);
        assert!((o.skew + 40e-6).abs() < 1e-6, "skew {}", o.skew);
        assert_eq!(o.confidence(), 0.7);
    }

    #[test]
    fn pairs_rate_skips_steps_and_short_spans() {
        // mono runs 10 ppm slow against real; a 5 ms step at real = 20 s.
        let mut pts: Vec<(i64, i64)> = (0..=30i64)
            .map(|s| {
                let real = s * 1_000_000_000;
                let mono = real - real / 100_000;
                (real, mono + if s >= 20 { 5_000_000 } else { 0 })
            })
            .collect();
        let m = RealToMono {
            pts: pts.clone(),
            steps: vec![],
        };
        assert!((m.rate().unwrap() - (1.0 - 10e-6)).abs() < 1e-9);
        pts.truncate(9);
        let m = RealToMono { pts, steps: vec![] };
        assert_eq!(m.rate(), None);
    }
}
