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
}

impl Offset {
    pub fn from_raw(raw: &Raw) -> Option<Offset> {
        let t = raw.table("exchange[a]")?;
        let mut s: Vec<(f64, f64, f64)> = Vec::new(); // (t1, theta, delta)
        for i in 0..t.n {
            let (Some(t1), Some(t2), Some(t3), Some(t4)) = (
                t.get("t1", i),
                t.get("t2", i),
                t.get("t3", i),
                t.get("t4", i),
            ) else {
                continue;
            };
            let theta = ((t2 - t1) as f64 + (t3 - t4) as f64) / 2.0;
            let delta = ((t4 - t1) - (t3 - t2)) as f64;
            if delta >= 0.0 {
                s.push((t1 as f64, theta, delta));
            }
        }
        if s.is_empty() {
            return None;
        }
        let mut d: Vec<f64> = s.iter().map(|x| x.2).collect();
        d.sort_by(f64::total_cmp);
        let cut = d[(d.len() / 4).min(d.len() - 1)];
        let kept: Vec<&(f64, f64, f64)> = s.iter().filter(|x| x.2 <= cut).collect();
        let n = kept.len() as f64;
        let mt = kept.iter().map(|x| x.0).sum::<f64>() / n;
        let mth = kept.iter().map(|x| x.1).sum::<f64>() / n;
        let var = kept.iter().map(|x| (x.0 - mt).powi(2)).sum::<f64>();
        let skew = if var > 0.0 && kept.len() >= 3 {
            kept.iter().map(|x| (x.0 - mt) * (x.1 - mth)).sum::<f64>() / var
        } else {
            0.0
        };
        Some(Offset {
            theta0: mth,
            skew,
            t_ref: mt,
            uncertainty_ns: d[0] / 2.0,
            min_rtt_ns: d[0],
            samples: s.len(),
            used: kept.len(),
        })
    }

    /// Convert b.mono to a.mono.
    pub fn b_to_a(&self, b_mono: i64) -> i64 {
        // Solve a = b - theta0 - skew*(a - t_ref) ≈ b - offset(b - theta0).
        let a0 = b_mono as f64 - self.theta0;
        (b_mono as f64 - (self.theta0 + self.skew * (a0 - self.t_ref))).round() as i64
    }

    pub fn to_value(&self) -> Value {
        Value::map()
            .with("method", "clock.exchange-minfilter/1")
            .with("offset_ns", self.theta0)
            .with("skew_ppb", self.skew * 1e9)
            .with("t_ref_a_mono", self.t_ref)
            .with("uncertainty_ns", self.uncertainty_ns)
            .with("min_rtt_ns", self.min_rtt_ns)
            .with("samples", self.samples)
            .with("used", self.used)
            .with("split_method", "symmetric_assumed")
            .with("confidence", if self.used >= 3 { 0.9 } else { 0.4 })
    }
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
        TimeBase {
            a: RealToMono::from_raw(raw, "a"),
            b: RealToMono::from_raw(raw, "b"),
            off: Offset::from_raw(raw),
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
}
