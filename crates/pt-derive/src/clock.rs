//! Clock models (docs/design/derivation.md "Time base").

use pt_format::Value;

use crate::raw::Raw;

/// Method name of the REALTIME → MONO_RAW map.
pub const PAIRS_METHOD: &str = "clock.pairs-piecewise/4";

/// Growth of boot − mono between consecutive clock pairs above which the endpoint was
/// suspended (the prober's `STALL_NS`, probe.md §4.3).
const SUSPEND_NS: i64 = 2_000_000;

/// How far a suspend event's `suspended_ns` may differ from the pairs' growth `grew` of the same
/// suspend: the two measure it between different reads, with BOOTTIME slewed against MONO_RAW
/// in between (derivation.md "Suspends").
fn len_tol(grew: i64) -> i64 {
    SUSPEND_NS.max(grew / 10)
}

/// Whether an event's `suspended_ns` is the length `grew` the pairs found for a suspend.
fn matches_len(ns: i64, grew: i64) -> bool {
    (ns - grew).abs() <= len_tol(grew)
}

/// One suspend of an endpoint: MONO_RAW stood still for `ns` while the clocks that count
/// suspend ran, somewhere between the clock pairs at mono `since` and `pair`. It is placed at
/// `at`: the endpoint's first `stall {cause: "suspend"}` event in that interval that is not
/// another suspend's, else `pair` (derivation.md "Suspends").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Suspend {
    pub at: i64,
    pub pair: i64,
    pub since: i64,
    pub ns: i64,
}

impl Suspend {
    fn placed_by(&self) -> &'static str {
        if self.at < self.pair {
            "stall_event"
        } else {
            "pair"
        }
    }
}

/// Suspends of one endpoint's MONO_RAW (derivation.md "Suspends"), sorted by `at`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Suspends {
    pub list: Vec<Suspend>,
}

impl Suspends {
    /// mono → the suspend-continuous clock: mono plus every suspend placed at or before it.
    pub fn to_cont(&self, mono: i64) -> i64 {
        mono + self
            .list
            .iter()
            .take_while(|s| s.at <= mono)
            .map(|s| s.ns)
            .sum::<i64>()
    }

    /// The inverse of [`Suspends::to_cont`]; a time inside a suspend maps to the mono at which
    /// that suspend is placed.
    pub fn from_cont(&self, cont: i64) -> i64 {
        let mut acc = 0;
        for s in &self.list {
            if cont < s.at + acc {
                break;
            }
            if cont < s.at + acc + s.ns {
                return s.at;
            }
            acc += s.ns;
        }
        cont - acc
    }

    /// Whether `mono` lies strictly between the earlier pair and the placement of a suspend,
    /// where it is unknown whether it was before or after the suspend.
    pub fn ambiguous(&self, mono: i64) -> bool {
        self.list.iter().any(|s| mono > s.since && mono < s.at)
    }
}

/// A jump of real − mono between neighbouring pairs above which REALTIME stepped.
const STEP_NS: i64 = 1_000_000;

/// How far before a mono hint a stamp may still map: the step threshold, so an offset error
/// below it never moves a stamp to the other side of a step (derivation.md "Clock steps").
const HINT_SLACK_NS: i64 = STEP_NS;

/// Piecewise-linear REALTIME → MONO_RAW map for one endpoint, cut into step-free segments at
/// every clock step and suspend (derivation.md "Clock steps").
#[derive(Debug, Clone, Default)]
pub struct RealToMono {
    /// (real, mono) sorted by mono.
    pts: Vec<(i64, i64)>,
    /// Index into `pts` of the first pair of each segment after the first, ascending.
    cuts: Vec<usize>,
    pub steps: Vec<(i64, i64)>,
    pub suspends: Suspends,
}

impl RealToMono {
    pub fn from_raw(raw: &Raw, ep: &str) -> RealToMono {
        let mut pts: Vec<(i64, i64, Option<i64>)> = Vec::new();
        if let Some(t) = raw.table(&format!("pairs[{ep}]")) {
            for i in 0..t.n {
                if let (Some(m), Some(r)) = (t.get("mono", i), t.get("real", i)) {
                    pts.push((r, m, t.get("boot", i)));
                }
            }
        }
        // MONO_RAW never steps, so mono order is the order the pairs were taken in; REALTIME
        // may step back, where sorting by it would interleave the pairs of both sides.
        pts.sort_by_key(|p| (p.1, p.0, p.2));
        pts.dedup_by_key(|p| p.1);
        // The pacer's suspend events (probe.md §4.3), each recorded after a wake: (t,
        // suspended_ns).
        let mut woke: Vec<(i64, Option<i64>)> = raw
            .events_of("stall")
            .filter(|e| e.get("endpoint").and_then(Value::as_str) == Some(ep))
            .filter(|e| {
                e.get("detail")
                    .and_then(|d| d.get("cause"))
                    .and_then(Value::as_str)
                    == Some("suspend")
            })
            .filter_map(|e| {
                let ns = e
                    .get("detail")
                    .and_then(|d| d.get("suspended_ns"))
                    .and_then(Value::as_u64)
                    .map(|n| n as i64);
                Some((e.get("t")?.as_u64()? as i64, ns))
            })
            .collect();
        woke.sort_unstable();
        let mut steps = Vec::new();
        let mut cuts = Vec::new();
        let mut suspends = Suspends::default();
        // The previous interval's suspend, while no event has placed it: its event may be
        // recorded after its later pair, that is in this interval.
        let mut unplaced: Option<i64> = None;
        for (i, w) in pts.windows(2).enumerate() {
            let (d0, d1) = (w[0].0 - w[0].1, w[1].0 - w[1].1);
            if (d1 - d0).abs() > STEP_NS {
                steps.push((w[1].1, d1 - d0));
                cuts.push(i + 1);
            }
            if let (Some(b0), Some(b1)) = (w[0].2, w[1].2) {
                let grew = (b1 - w[1].1) - (b0 - w[0].1);
                let (since, pair) = (w[0].1, w[1].1);
                let mut events = woke[woke.partition_point(|e| e.0 <= since)..]
                    .iter()
                    .take_while(|e| e.0 <= pair)
                    .peekable();
                // The first event after an unplaced suspend's later pair is taken as that
                // suspend's when its length matches (or is not recorded), never as this one's.
                if let Some(prev) = unplaced.take()
                    && events
                        .peek()
                        .is_some_and(|e| e.1.is_none_or(|ns| matches_len(ns, prev)))
                {
                    events.next();
                }
                if grew > SUSPEND_NS {
                    // Placed at the earliest time known to follow this interval's wake: an event
                    // longer than this interval's growth belongs to another suspend.
                    let at = events
                        .find(|e| e.1.is_none_or(|ns| ns <= grew + len_tol(grew)))
                        .map_or(pair, |e| e.0);
                    suspends.list.push(Suspend {
                        at,
                        pair,
                        since,
                        ns: grew,
                    });
                    if cuts.last() != Some(&(i + 1)) {
                        cuts.push(i + 1);
                    }
                    if at == pair {
                        unplaced = Some(grew);
                    }
                }
            } else {
                unplaced = None;
            }
        }
        suspends.list.sort();
        RealToMono {
            pts: pts.into_iter().map(|(r, m, _)| (r, m)).collect(),
            cuts,
            steps,
            suspends,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pts.is_empty()
    }

    /// The pairs of segment `k`.
    fn segment(&self, k: usize) -> &[(i64, i64)] {
        let lo = if k == 0 { 0 } else { self.cuts[k - 1] };
        let hi = self.cuts.get(k).copied().unwrap_or(self.pts.len());
        &self.pts[lo..hi]
    }

    /// The suspend at cut `c`, if the cut is one.
    fn cut_suspend(&self, c: usize) -> Option<&Suspend> {
        let pair = self.pts[self.cuts[c]].1;
        self.suspends.list.iter().find(|s| s.pair == pair)
    }

    /// Whether `mono` lies before cut `c`: below a suspend's placement, or below the later
    /// pair of a step, whose place in the pair interval is unknown.
    fn before_cut(&self, c: usize, mono: i64) -> bool {
        match self.cut_suspend(c) {
            Some(s) => mono < s.at,
            None => mono < self.pts[self.cuts[c]].1,
        }
    }

    /// Whether `mono` lies after cut `c`: at or above a suspend's placement, or above the
    /// earlier pair of a step.
    fn after_cut(&self, c: usize, mono: i64) -> bool {
        match self.cut_suspend(c) {
            Some(s) => mono >= s.at,
            None => mono > self.pts[self.cuts[c] - 1].1,
        }
    }

    /// The mono of a real stamp in the range cut `c` skipped: a suspend's placement, else the
    /// linear interpolation between the cut's two pairs (`/3`'s result).
    fn fill(&self, c: usize, real: i64) -> i64 {
        if let Some(s) = self.cut_suspend(c) {
            return s.at;
        }
        let j = self.cuts[c];
        let (a, b) = (self.pts[j - 1], self.pts[j]);
        let slope = (b.1 - a.1) as f64 / (b.0 - a.0).max(1) as f64;
        (a.1 + ((real - a.0) as f64 * slope).round() as i64).clamp(a.1, b.1)
    }

    /// Map a REALTIME value to MONO_RAW (derivation.md "Clock steps"). Each step-free segment
    /// whose mapping of `real` lies on its own side of the cuts beside it gives a candidate.
    /// Where several do, `hint` (a mono the stamp is not expected to precede) picks the
    /// earliest at or after `hint − HINT_SLACK_NS`, else the latest; without a hint the mono
    /// is unknown. The hint is only a lower bound: a stamp that lags it by |J| − 1 ms or more
    /// (a receive stamp over a one-way delay that large) maps |J| early when the wrong
    /// candidate is the earlier one, and not to unknown. Across a suspend the map is a step: the earlier segment below the
    /// placement, then the later one, never below the placement.
    pub fn map(&self, real: i64, hint: Option<i64>) -> Option<i64> {
        if self.pts.is_empty() {
            return None;
        }
        if self.cuts.is_empty() {
            return Some(interp(&self.pts, real));
        }
        let n = self.cuts.len() + 1;
        let at: Vec<i64> = (0..n).map(|k| interp(self.segment(k), real)).collect();
        let mut cand: Vec<i64> = (0..n)
            .filter(|&k| {
                (k == 0 || self.after_cut(k - 1, at[k]))
                    && (k == n - 1 || self.before_cut(k, at[k]))
            })
            .map(|k| at[k])
            .collect();
        if cand.is_empty() {
            // In the real range a forward step or suspend skipped.
            cand = (0..n - 1)
                .filter(|&c| !self.before_cut(c, at[c]) && !self.after_cut(c, at[c + 1]))
                .map(|c| self.fill(c, real))
                .collect();
        }
        cand.sort_unstable();
        cand.dedup();
        match (cand.as_slice(), hint) {
            ([], _) => None,
            ([m], _) => Some(*m),
            (_, None) => None,
            (c, Some(h)) => c
                .iter()
                .find(|&&m| m >= h - HINT_SLACK_NS)
                .or(c.last())
                .copied(),
        }
    }

    /// MONO_RAW rate against REALTIME (d mono / d real) over the step-free
    /// consecutive pairs, or None when they span less than `MIN_SPAN_NS`.
    pub fn rate(&self) -> Option<f64> {
        let (mut dm, mut dr) = (0i64, 0i64);
        for w in self.pts.windows(2) {
            let (d0, d1) = (w[0].0 - w[0].1, w[1].0 - w[1].1);
            if (d1 - d0).abs() > STEP_NS {
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
                "segments",
                if self.pts.is_empty() {
                    0
                } else {
                    self.cuts.len() + 1
                },
            )
            .with(
                "steps",
                Value::Array(
                    self.steps
                        .iter()
                        .map(|(t, d)| Value::map().with("mono", *t).with("jump_ns", *d))
                        .collect(),
                ),
            )
            .with(
                "suspends",
                Value::Array(
                    self.suspends
                        .list
                        .iter()
                        .map(|s| {
                            Value::map()
                                .with("mono", s.pair)
                                .with("since_mono", s.since)
                                .with("suspended_ns", s.ns)
                                .with("placed_mono", s.at)
                                .with("placed_by", s.placed_by())
                        })
                        .collect(),
                ),
            )
    }
}

/// Piecewise-linear interpolation of `real` between the (real, mono) pairs `p` of one
/// step-free segment, extrapolated with the end pair intervals' slope.
fn interp(p: &[(i64, i64)], real: i64) -> i64 {
    match p.len() {
        0 => real,
        1 => real - (p[0].0 - p[0].1),
        n => {
            let i = p.partition_point(|x| x.0 <= real).clamp(1, n - 1);
            let (a, b) = (p[i - 1], p[i]);
            let slope = (b.1 - a.1) as f64 / (b.0 - a.0).max(1) as f64;
            a.1 + ((real - a.0) as f64 * slope).round() as i64
        }
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
    /// Suspends of each endpoint; the fit is on their suspend-continuous clocks
    /// (derivation.md "Suspends"), and `t_ref` is on a's.
    pub suspends_a: Suspends,
    pub suspends_b: Suspends,
}

impl Offset {
    pub fn from_raw(raw: &Raw, a: &RealToMono, b: &RealToMono) -> Option<Offset> {
        let t = raw.table("exchange[a]")?;
        let (sa, sb) = (&a.suspends, &b.suspends);
        // An exchange with a time between the earlier pair and the placement of a suspend is
        // left out: on which side of the suspend that time lies is unknown, so its θ could be
        // off by all of it.
        let ex: Vec<Exchange> = (0..t.n)
            .filter_map(|i| {
                let (t1, t2, t3, t4) = (
                    t.get("t1", i)?,
                    t.get("t2", i)?,
                    t.get("t3", i)?,
                    t.get("t4", i)?,
                );
                if [t1, t4].iter().any(|&m| sa.ambiguous(m))
                    || [t2, t3].iter().any(|&m| sb.ambiguous(m))
                {
                    return None;
                }
                Some(Exchange {
                    t1: sa.to_cont(t1),
                    t2: sb.to_cont(t2),
                    t3: sb.to_cont(t3),
                    t4: sa.to_cont(t4),
                })
            })
            .collect();
        let pairs = match (a.rate(), b.rate()) {
            (Some(ra), Some(rb)) if ra > 0.0 => Some(rb / ra - 1.0),
            _ => None,
        };
        Offset::fit(&ex, pairs).map(|o| Offset {
            suspends_a: sa.clone(),
            suspends_b: sb.clone(),
            ..o
        })
    }

    /// Fit the offset to `ex`, with `pairs` the pairs-derived skew if any
    /// (derivation.md "Time base", `clock.exchange-minfilter/4`).
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
            suspends_a: Suspends::default(),
            suspends_b: Suspends::default(),
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

    /// Convert b.mono to a.mono, through both endpoints' suspend-continuous clocks.
    pub fn b_to_a(&self, b_mono: i64) -> i64 {
        // Solve a = b - theta0 - skew*(a - t_ref) ≈ b - offset(b - theta0).
        let b = self.suspends_b.to_cont(b_mono) as f64;
        let a0 = b - self.theta0;
        let a = (b - (self.theta0 + self.skew * (a0 - self.t_ref))).round() as i64;
        self.suspends_a.from_cont(a)
    }

    /// Convert a.mono to b.mono: the inverse of [`Offset::b_to_a`].
    pub fn a_to_b(&self, a_mono: i64) -> i64 {
        let a = self.suspends_a.to_cont(a_mono) as f64;
        let b = (a + self.theta0 + self.skew * (a - self.t_ref)).round() as i64;
        self.suspends_b.from_cont(b)
    }

    pub fn to_value(&self) -> Value {
        Value::map()
            .with("method", OFFSET_METHOD)
            .with("offset_ns", self.theta0)
            .with("skew_ppb", self.skew * 1e9)
            .with("skew_source", self.skew_source.as_str())
            .with("skew_exchange_ppb", self.skew_exchange.map(|k| k * 1e9))
            .with(
                "skew_exchange_uncertainty_ppb",
                self.skew_exchange_uncertainty.map(|k| k * 1e9),
            )
            .with("skew_pairs_ppb", self.skew_pairs.map(|k| k * 1e9))
            .with("span_ns", self.span_ns)
            .with(
                "t_ref_a_mono",
                if self.suspends_a.list.is_empty() {
                    self.t_ref
                } else {
                    self.suspends_a.from_cont(self.t_ref.round() as i64) as f64
                },
            )
            .with("uncertainty_ns", self.uncertainty_ns)
            .with("min_rtt_ns", self.min_rtt_ns)
            .with("samples", self.samples)
            .with("used", self.used)
            .with("split_method", "symmetric_assumed")
            .with("confidence", self.confidence())
    }
}

/// Method name of the b.mono → a.mono offset.
pub const OFFSET_METHOD: &str = "clock.exchange-minfilter/4";

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

    /// Endpoint real → trace ns. `hint` is a trace time the stamp is not expected to precede,
    /// which picks the side of a clock step a stamp in its overlap lies on (derivation.md
    /// "Clock steps").
    pub fn real(&self, ep: &str, real: i64, hint: Option<i64>) -> Option<i64> {
        match ep {
            "a" => self
                .a
                .map(real, hint.map(|h| h + self.t0))
                .map(|m| m - self.t0),
            _ => {
                let off = self.off.as_ref()?;
                let m = self.b.map(real, hint.map(|h| off.a_to_b(h + self.t0)))?;
                Some(off.b_to_a(m) - self.t0)
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
            ..Default::default()
        };
        assert_eq!(m.map(1_500, None), Some(600));
        assert_eq!(m.map(3_000, None), Some(2_100));
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
        assert!((o.a_to_b(a) - b).abs() < 10);
        assert!((o.b_to_a(o.a_to_b(a)) - a).abs() < 10);
    }

    /// Clock pairs at 1 Hz of mono over 30 s with real = mono + 7 s, and REALTIME stepped by
    /// `jump` ns between the pairs at mono 10 s and 11 s.
    fn stepped_pairs(jump: i64) -> crate::raw::Rows {
        let mono: Vec<i64> = (0..=30).map(|s| T0 + s * 1_000_000_000).collect();
        let real = mono
            .iter()
            .map(|m| m + 7_000_000_000 + if *m > T0 + 10_000_000_000 { jump } else { 0 })
            .collect();
        rows(&[("real", real), ("mono", mono)])
    }

    #[test]
    fn backward_step_overlap_maps_by_the_hint() {
        // REALTIME steps back 3 s: the real values of mono 8 s … 10 s and 11 s … 13 s overlap,
        // and /3, sorted by real, interleaved the pairs of both sides.
        let mut raw = Raw::default();
        raw.tables
            .insert("pairs[a]".into(), stepped_pairs(-3e9 as i64));
        let m = RealToMono::from_raw(&raw, "a");
        let s = |x: f64| T0 + (x * 1e9) as i64;
        assert_eq!(m.steps, vec![(s(11.0), -3_000_000_000)]);
        let v = m.to_value(PAIRS_METHOD);
        assert_eq!(v.get("segments").and_then(Value::as_i64), Some(2));
        // A stamp at mono 9.5 s, or at 12.5 s: the same real value.
        let r = s(9.5) + 7_000_000_000;
        assert_eq!(r, s(12.5) + 4_000_000_000);
        assert_eq!(m.map(r, None), None);
        assert_eq!(m.map(r, Some(s(9.49))), Some(s(9.5)));
        // A hint up to 1 ms after the stamp still finds it.
        assert_eq!(m.map(r, Some(s(9.5005))), Some(s(9.5)));
        assert_eq!(m.map(r, Some(s(12.49))), Some(s(12.5)));
        // A hint after both: the later.
        assert_eq!(m.map(r, Some(s(20.0))), Some(s(12.5)));
        // Outside the overlap there is one side, hint or not.
        for (x, real) in [
            (5.0, s(5.0) + 7_000_000_000),
            (20.0, s(20.0) + 4_000_000_000),
        ] {
            assert_eq!(m.map(real, None), Some(s(x)), "mono {x}");
            assert_eq!(m.map(real, Some(s(0.0))), Some(s(x)), "mono {x}");
        }
        // The rate skips the step.
        assert!((m.rate().unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn forward_step_is_not_interpolated_across() {
        // REALTIME steps forward 300 ms somewhere between the pairs at mono 10 s and 11 s.
        let mut raw = Raw::default();
        raw.tables
            .insert("pairs[a]".into(), stepped_pairs(300_000_000));
        let m = RealToMono::from_raw(&raw, "a");
        let s = |x: f64| T0 + (x * 1e9) as i64;
        assert_eq!(m.steps, vec![(s(11.0), 300_000_000)]);
        // A stamp of real mono + 7 s in the pair interval: before the step at mono 10.5 s, or
        // after it at 10.2 s. /3's line put it at about 10.27 s, which is neither.
        let r = s(10.5) + 7_000_000_000;
        assert_eq!(m.map(r, Some(s(10.49))), Some(s(10.5)));
        assert_eq!(m.map(r, Some(s(10.19))), Some(s(10.2)));
        assert_eq!(m.map(r, None), None);
        // Away from the step, each side's own offset.
        assert_eq!(m.map(s(9.5) + 7_000_000_000, None), Some(s(9.5)));
        assert_eq!(m.map(s(11.5) + 7_300_000_000, None), Some(s(11.5)));
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

    fn rows(cols: &[(&str, Vec<i64>)]) -> crate::raw::Rows {
        crate::raw::Rows {
            n: cols[0].1.len(),
            cols: cols
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().copied().map(Some).collect()))
                .collect(),
        }
    }

    /// Pairs at 1 Hz over 30 s for an endpoint whose MONO_RAW runs `ppm` fast
    /// against REALTIME.
    fn pairs(ppm: i64) -> crate::raw::Rows {
        let real: Vec<i64> = (0..=30i64).map(|s| T0 + s * 1_000_000_000).collect();
        let mono = real
            .iter()
            .map(|r| r + (r - T0) / 1_000_000 * ppm)
            .collect();
        rows(&[("real", real), ("mono", mono)])
    }

    #[test]
    fn from_raw_takes_the_skew_from_both_endpoints_pairs() {
        // 5 s of exchanges: too short for the envelope, so the skew comes from
        // the pairs, b's MONO_RAW 16 ppm fast and a's 4 ppm fast against
        // REALTIME: b.mono/a.mono − 1 = 1.000016 / 1.000004 − 1 ≈ +11.99996 ppm.
        let ex = exchanges(20, 250_000_000, 12e-6, |_| (10e6, 10e6));
        let col = |f: fn(&Exchange) -> i64| ex.iter().map(f).collect::<Vec<_>>();
        let mut raw = Raw::default();
        raw.tables.insert(
            "exchange[a]".into(),
            rows(&[
                ("t1", col(|e| e.t1)),
                ("t2", col(|e| e.t2)),
                ("t3", col(|e| e.t3)),
                ("t4", col(|e| e.t4)),
            ]),
        );
        raw.tables.insert("pairs[a]".into(), pairs(4));
        raw.tables.insert("pairs[b]".into(), pairs(16));
        let tb = TimeBase::from_raw(&raw);
        let o = tb.off.as_ref().unwrap();
        assert_eq!(o.skew_source, SkewSource::Pairs);
        let want = 1.000_016 / 1.000_004 - 1.0;
        assert!((o.skew - want).abs() < 1e-9, "skew {}", o.skew);
        let v = o.to_value();
        assert_eq!(v.get("skew_source").and_then(Value::as_str), Some("pairs"));
        let ppb = v.get("skew_ppb").and_then(Value::as_f64).unwrap();
        assert!((ppb - want * 1e9).abs() < 1.0, "skew_ppb {ppb}");

        // Without b's pairs there is no rate to compose: no pairs skew.
        raw.tables.remove("pairs[b]");
        let tb = TimeBase::from_raw(&raw);
        let o = tb.off.as_ref().unwrap();
        assert_eq!((o.skew_pairs, o.skew_source), (None, SkewSource::None));
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
            ..Default::default()
        };
        assert!((m.rate().unwrap() - (1.0 - 10e-6)).abs() < 1e-9);
        pts.truncate(9);
        let m = RealToMono {
            pts,
            ..Default::default()
        };
        assert_eq!(m.rate(), None);
    }

    #[test]
    fn suspend_continuous_clock_round_trips_and_collapses_the_suspend() {
        let s = Suspends {
            list: vec![
                Suspend {
                    at: 1_000,
                    pair: 1_000,
                    since: 900,
                    ns: 500,
                },
                Suspend {
                    at: 2_000,
                    pair: 2_050,
                    since: 1_900,
                    ns: 100,
                },
            ],
        };
        assert!(s.ambiguous(950) && !s.ambiguous(900) && !s.ambiguous(1_000));
        // A time at or after a placement that an event narrowed follows the wake.
        assert!(s.ambiguous(1_999) && !s.ambiguous(2_000) && !s.ambiguous(2_025));
        assert_eq!(s.to_cont(999), 999);
        assert_eq!(s.to_cont(1_000), 1_500);
        assert_eq!(s.to_cont(2_500), 3_100);
        for m in [0, 999, 1_000, 1_001, 1_999, 2_000, 5_000] {
            assert_eq!(s.from_cont(s.to_cont(m)), m, "mono {m}");
        }
        // Continuous times inside a suspend have no mono of their own.
        assert_eq!(s.from_cont(1_200), 1_000);
        assert_eq!(s.from_cont(2_550), 2_000);
    }

    /// Clock pairs at 1 Hz of mono over `secs` s, with the endpoint suspended for `susp` ns
    /// between the pairs at mono `at` and `at` + 1 s (`susp` = 0: never). REALTIME and boot
    /// keep running through it.
    fn suspended_pairs(secs: i64, at: i64, susp: i64) -> crate::raw::Rows {
        let mono: Vec<i64> = (0..=secs).map(|s| T0 + s * 1_000_000_000).collect();
        let gap = |m: &i64| if *m > T0 + at { susp } else { 0 };
        let real = mono.iter().map(|m| m + 7_000_000_000 + gap(m)).collect();
        let boot = mono.iter().map(|m| m + 3_000_000_000 + gap(m)).collect();
        rows(&[("real", real), ("mono", mono), ("boot", boot)])
    }

    #[test]
    fn pairs_find_the_suspend_and_map_realtime_across_it_as_a_step() {
        let mut raw = Raw::default();
        raw.tables.insert(
            "pairs[a]".into(),
            suspended_pairs(30, 10_000_000_000, 900e9 as i64),
        );
        let m = RealToMono::from_raw(&raw, "a");
        let at = T0 + 11_000_000_000;
        assert_eq!(
            m.suspends.list,
            vec![Suspend {
                at,
                pair: at,
                since: at - 1_000_000_000,
                ns: 900_000_000_000
            }]
        );
        let v = m.to_value(PAIRS_METHOD);
        let s = v.get("suspends").and_then(Value::as_array).unwrap();
        assert_eq!(s[0].get("mono").and_then(Value::as_i64), Some(at));
        assert_eq!(s[0].get("placed_mono").and_then(Value::as_i64), Some(at));
        assert_eq!(s[0].get("placed_by").and_then(Value::as_str), Some("pair"));
        assert_eq!(
            s[0].get("suspended_ns").and_then(Value::as_i64),
            Some(900e9 as i64)
        );
        // Before the suspend: the earlier pair's offset (real = mono + 7 s).
        let r0 = T0 + 10_000_000_000 + 7_000_000_000;
        assert_eq!(m.map(r0 + 400_000_000, None), Some(T0 + 10_400_000_000));
        // Inside the suspend and after the wake, until the later pair: its mono.
        assert_eq!(m.map(r0 + 1_000_000_000, None), Some(at));
        assert_eq!(m.map(r0 + 500_000_000_000, None), Some(at));
        // After the later pair: its offset again.
        assert_eq!(m.map(at + 907_500_000_000, None), Some(at + 500_000_000));
        // Monotonic throughout.
        let mut last = i64::MIN;
        for k in 0..2_000 {
            let mono = m.map(r0 - 1_000_000_000 + k * 1_000_000_000, None).unwrap();
            assert!(mono >= last, "step {k}");
            last = mono;
        }
        // The suspend is also a step of real − mono, so the pairs rate skips it.
        assert!((m.rate().unwrap() - 1.0).abs() < 1e-12);
        // Without boot there is no suspend, only a step: a stamp in the range it skipped maps
        // by the linear interpolation of /1 between its two pairs.
        raw.tables.get_mut("pairs[a]").unwrap().cols.remove("boot");
        let m = RealToMono::from_raw(&raw, "a");
        assert!(m.suspends.list.is_empty());
        assert_eq!(m.steps, vec![(at, 900_000_000_000)]);
        let mid = m.map(r0 + 500_000_000_000, None).unwrap();
        assert!(mid > T0 + 10_400_000_000 && mid < at);
        // Either side of it, each pair's own offset.
        assert_eq!(m.map(r0 + 400_000_000, None), Some(T0 + 10_400_000_000));
        assert_eq!(m.map(at + 907_500_000_000, None), Some(at + 500_000_000));
    }

    /// An EVNT `stall` event of `ep` at mono `t`.
    fn stall(ep: &str, t: i64, cause: &str) -> Value {
        Value::map()
            .with("t", t as u64)
            .with("clock", format!("{ep}.mono"))
            .with("endpoint", ep)
            .with("type", "stall")
            .with("detail", Value::map().with("cause", cause))
    }

    #[test]
    fn a_suspend_event_in_the_pair_interval_narrows_the_placement() {
        let susp = 900e9 as i64;
        let mut raw = Raw::default();
        raw.tables
            .insert("pairs[a]".into(), suspended_pairs(30, 10_000_000_000, susp));
        let (since, pair) = (T0 + 10_000_000_000, T0 + 11_000_000_000);
        let woke = T0 + 10_600_000_000;
        raw.events = vec![
            // Not in the interval, of the other endpoint, or not a suspend: not used.
            stall("a", since, "suspend"),
            stall("b", since + 100_000_000, "suspend"),
            stall("a", since + 200_000_000, "late"),
            stall("a", pair + 1, "suspend"),
            // The pacer's first loop after the wake, and a later one: the earliest is used.
            stall("a", woke + 300_000_000, "suspend"),
            stall("a", woke, "suspend"),
        ];
        let m = RealToMono::from_raw(&raw, "a");
        assert_eq!(
            m.suspends.list,
            vec![Suspend {
                at: woke,
                pair,
                since,
                ns: susp
            }]
        );
        let v = m.to_value(PAIRS_METHOD);
        let s = v.get("suspends").and_then(Value::as_array).unwrap();
        assert_eq!(s[0].get("mono").and_then(Value::as_i64), Some(pair));
        assert_eq!(s[0].get("since_mono").and_then(Value::as_i64), Some(since));
        assert_eq!(s[0].get("placed_mono").and_then(Value::as_i64), Some(woke));
        assert_eq!(
            s[0].get("placed_by").and_then(Value::as_str),
            Some("stall_event")
        );
        // real = mono + 7 s before the suspend, and + 907 s after it.
        let before = |mono: i64| mono + 7_000_000_000;
        let after = |mono: i64| mono + 7_000_000_000 + susp;
        assert_eq!(
            m.map(before(T0 + 10_400_000_000), None),
            Some(T0 + 10_400_000_000)
        );
        // Inside the suspend: its placement.
        assert_eq!(m.map(before(woke) + susp / 2, None), Some(woke));
        // After the wake and before the later pair: the later pair's offset, not its mono.
        assert_eq!(
            m.map(after(T0 + 10_800_000_000), None),
            Some(T0 + 10_800_000_000)
        );
        let mut last = i64::MIN;
        for k in 0..2_000 {
            let mono = m
                .map(before(since) - 1_000_000_000 + k * 500_000_000, None)
                .unwrap();
            assert!(mono >= last, "step {k}");
            last = mono;
        }
        // Without boot the events find no suspend of their own.
        raw.tables.get_mut("pairs[a]").unwrap().cols.remove("boot");
        assert!(RealToMono::from_raw(&raw, "a").suspends.list.is_empty());
    }

    /// A `stall {cause: "suspend", suspended_ns}` event of `ep` at mono `t`.
    fn stall_ns(ep: &str, t: i64, ns: i64) -> Value {
        Value::map()
            .with("t", t as u64)
            .with("clock", format!("{ep}.mono"))
            .with("endpoint", ep)
            .with("type", "stall")
            .with(
                "detail",
                Value::map()
                    .with("cause", "suspend")
                    .with("suspended_ns", ns as u64),
            )
    }

    #[test]
    fn a_late_event_of_the_previous_suspend_does_not_place_the_next() {
        // Pairs at 1 Hz; a sleeps 900 s between the pairs at 10 s and 11 s, waking just before
        // the one at 11 s, and 5 s between the pairs at 11 s and 12 s.
        let (s1, s2) = (900e9 as i64, 5e9 as i64);
        let mono: Vec<i64> = (0..=30).map(|s| T0 + s * 1_000_000_000).collect();
        let gap = |m: &i64| {
            (if *m > T0 + 10_000_000_000 { s1 } else { 0 })
                + (if *m > T0 + 11_000_000_000 { s2 } else { 0 })
        };
        let real = mono.iter().map(|m| m + 7_000_000_000 + gap(m)).collect();
        let boot = mono.iter().map(|m| m + 3_000_000_000 + gap(m)).collect();
        let mut raw = Raw::default();
        raw.tables.insert(
            "pairs[a]".into(),
            rows(&[("real", real), ("mono", mono), ("boot", boot)]),
        );
        let (p1, p2) = (T0 + 11_000_000_000, T0 + 12_000_000_000);
        let first = |raw: &Raw| RealToMono::from_raw(raw, "a").suspends.list;
        // The first suspend's event, recorded after its later pair, and the second's own.
        let woke2 = T0 + 11_600_000_000;
        raw.events = vec![stall_ns("a", p1 + 30_000_000, s1), stall_ns("a", woke2, s2)];
        let l = first(&raw);
        assert_eq!((l[0].at, l[0].pair, l[0].ns), (p1, p1, s1));
        assert_eq!((l[1].at, l[1].pair, l[1].ns), (woke2, p2, s2));
        // Without the second's event, the first's does not place it: the later pair does.
        raw.events = vec![stall_ns("a", p1 + 30_000_000, s1)];
        assert_eq!(first(&raw)[1].at, p2);
        // Nor without a recorded length.
        raw.events = vec![stall("a", p1 + 30_000_000, "suspend")];
        assert_eq!(first(&raw)[1].at, p2);
        // An event longer than the interval's growth is another suspend's, wherever it is.
        raw.events = vec![stall_ns("a", woke2, s1)];
        assert_eq!(first(&raw)[1].at, p2);
        // When an event placed the first suspend, the next interval's first event is the second's.
        let woke1 = T0 + 10_600_000_000;
        raw.events = vec![stall_ns("a", woke1, s1), stall_ns("a", p1 + 30_000_000, s2)];
        let l = first(&raw);
        assert_eq!((l[0].at, l[1].at), (woke1, p1 + 30_000_000));
    }

    #[test]
    fn initiator_suspend_is_a_clock_step_not_a_skew() {
        // 120 s of a.mono with an exchange every 0.1 s, 10 ms each way, b 20 ppm fast; a is
        // suspended for 900 s at a.mono 30.6 s: a.mono stands still, b.mono runs on. The
        // pairs (1 Hz) see it between a.mono 30 s and 31 s.
        let susp = 900_000_000_000i64;
        let s0 = T0 + 30_600_000_000;
        let at = T0 + 31_000_000_000;
        // Elapsed time (what b's clock and a's continuous clock count) at an a.mono.
        let tau = |m: f64| if m >= s0 as f64 { m + susp as f64 } else { m };
        let b = |t: f64| t + THETA0 + 20e-6 * (t - T0 as f64);
        let ex: Vec<Exchange> = (0..1_200i64)
            .map(|i| {
                let t1 = T0 + i * 100_000_000;
                let at_b = tau(t1 as f64) + 10e6;
                Exchange {
                    t1,
                    t2: b(at_b).round() as i64,
                    t3: b(at_b + 1e6).round() as i64,
                    t4: t1 + 21_000_000,
                }
            })
            .collect();
        let col = |f: fn(&Exchange) -> i64| ex.iter().map(f).collect::<Vec<_>>();
        let mut raw = Raw::default();
        raw.tables.insert(
            "exchange[a]".into(),
            rows(&[
                ("t1", col(|e| e.t1)),
                ("t2", col(|e| e.t2)),
                ("t3", col(|e| e.t3)),
                ("t4", col(|e| e.t4)),
            ]),
        );
        raw.tables.insert(
            "pairs[a]".into(),
            suspended_pairs(130, 30_000_000_000, susp),
        );
        let tb = TimeBase::from_raw(&raw);
        assert_eq!(tb.a.suspends.list.len(), 1);
        assert_eq!(
            (tb.a.suspends.list[0].at, tb.a.suspends.list[0].ns),
            (at, susp)
        );
        let o = tb.off.as_ref().unwrap();
        // The exchanges with a time between the two pairs of the suspend (t1 30.0 s … 30.9 s;
        // the one at 30.0 s ends at 30.021 s) are left out.
        assert_eq!(o.samples, 1_200 - 10);
        assert_eq!(o.skew_source, SkewSource::Exchange);
        assert!((o.skew - 20e-6).abs() < 1e-8, "skew {}", o.skew);
        // b times before the suspend and after the wake map to their a.mono.
        for m in [
            T0 + 20_000_000_000,
            T0 + 30_500_000_000,
            T0 + 31_000_000_000,
            T0 + 90_000_000_000,
        ] {
            let got = o.b_to_a(b(tau(m as f64)).round() as i64);
            assert!((got - m).abs() < 1_000, "a.mono {m}: {got}");
        }
        // A b time inside a's suspend, or after the wake but before the later pair, collapses
        // onto the suspend's placement.
        for t in [s0 + susp / 2, T0 + 30_800_000_000 + susp] {
            assert_eq!(o.b_to_a(b(t as f64).round() as i64), at);
        }
        let v = o.to_value();
        assert_eq!(v.get("method").and_then(Value::as_str), Some(OFFSET_METHOD));
        let t_ref = v.get("t_ref_a_mono").and_then(Value::as_f64).unwrap();
        assert!(t_ref > T0 as f64 && t_ref < (T0 + 120_000_000_000) as f64);
        // Fitted on a.mono as one line, as /2 did, the same exchanges put b times hundreds of
        // seconds away from their a.mono.
        let o2 = Offset::fit(&ex, None).unwrap();
        let m = T0 + 20_000_000_000;
        assert!((o2.b_to_a(b(m as f64).round() as i64) - m).abs() > 100_000_000_000);

        // With the pacer's suspend event 5 ms after the wake, the suspend is placed there.
        let woke = s0 + 5_000_000;
        raw.events = vec![stall("a", woke, "suspend")];
        let tb = TimeBase::from_raw(&raw);
        assert_eq!(
            (tb.a.suspends.list[0].at, tb.a.suspends.list[0].pair),
            (woke, at)
        );
        let o = tb.off.as_ref().unwrap();
        // Only the exchanges with a time between the earlier pair and the event are left out
        // (t1 30.0 s … 30.6 s; the one at 30.0 s ends at 30.021 s).
        assert_eq!(o.samples, 1_200 - 7);
        assert!((o.skew - 20e-6).abs() < 1e-8, "skew {}", o.skew);
        // A b time after the event maps to its a.mono, where the pair placement collapsed it
        // onto the later pair.
        for m in [
            T0 + 30_700_000_000,
            T0 + 30_900_000_000,
            T0 + 90_000_000_000,
        ] {
            let got = o.b_to_a(b(tau(m as f64)).round() as i64);
            assert!((got - m).abs() < 1_000, "a.mono {m}: {got}");
        }
        // A b time inside the suspend, or in the 5 ms from the wake to the event, collapses onto
        // the event.
        for t in [s0 + susp / 2, s0 + susp + 2_000_000] {
            assert_eq!(o.b_to_a(b(t as f64).round() as i64), woke);
        }
    }

    #[test]
    fn responder_suspend_is_a_clock_step_not_a_skew() {
        // 400 s of a.mono with an exchange every 0.1 s, 10 ms each way, b 20 ppm fast; b is
        // suspended for 300 s once its mono reaches 30.6 s past its first pair: b.mono stands
        // still while a.mono runs on, and the exchanges that reach b while it sleeps are lost.
        // b's pairs (1 Hz of b.mono) see it between 30 s and 31 s past their first.
        let susp = 300_000_000_000i64;
        let b0 = T0 + THETA0 as i64;
        let sb = b0 + 30_600_000_000;
        let at = b0 + 31_000_000_000;
        // b's suspend-continuous clock at an a.mono, and b.mono at a continuous time (None
        // while b sleeps).
        let c = |t: f64| t + THETA0 + 20e-6 * (t - T0 as f64);
        let bmono = |c: f64| {
            if c < sb as f64 {
                Some(c)
            } else if c < (sb + susp) as f64 {
                None
            } else {
                Some(c - susp as f64)
            }
        };
        let ex: Vec<Exchange> = (0..4_000i64)
            .filter_map(|i| {
                let t1 = T0 + i * 100_000_000;
                let ta = t1 as f64 + 10e6;
                Some(Exchange {
                    t1,
                    t2: bmono(c(ta))?.round() as i64,
                    t3: bmono(c(ta + 1e6))?.round() as i64,
                    t4: t1 + 21_000_000,
                })
            })
            .collect();
        let col = |f: fn(&Exchange) -> i64| ex.iter().map(f).collect::<Vec<_>>();
        let mut raw = Raw::default();
        raw.tables.insert(
            "exchange[a]".into(),
            rows(&[
                ("t1", col(|e| e.t1)),
                ("t2", col(|e| e.t2)),
                ("t3", col(|e| e.t3)),
                ("t4", col(|e| e.t4)),
            ]),
        );
        raw.tables
            .insert("pairs[a]".into(), suspended_pairs(410, 0, 0));
        let mut pb = suspended_pairs(110, 30_000_000_000, susp);
        for v in pb.cols.values_mut() {
            for x in v.iter_mut().flatten() {
                *x += b0 - T0;
            }
        }
        raw.tables.insert("pairs[b]".into(), pb);
        let tb = TimeBase::from_raw(&raw);
        assert!(tb.a.suspends.list.is_empty());
        assert_eq!(tb.b.suspends.list.len(), 1);
        assert_eq!(
            (tb.b.suspends.list[0].at, tb.b.suspends.list[0].ns),
            (at, susp)
        );
        let o = tb.off.as_ref().unwrap();
        // The exchanges with t2 or t3 between b's two pairs of the suspend are left out.
        let ambiguous = ex
            .iter()
            .filter(|e| {
                [e.t2, e.t3]
                    .iter()
                    .any(|&m| m > at - 1_000_000_000 && m < at)
            })
            .count();
        assert!(ambiguous > 0);
        assert_eq!(o.samples, ex.len() - ambiguous);
        assert_eq!(o.skew_source, SkewSource::Exchange);
        assert!((o.skew - 20e-6).abs() < 1e-8, "skew {}", o.skew);
        // b times before the suspend and after its later pair map to their a.mono.
        for m in [
            T0 + 20_000_000_000,
            T0 + 30_500_000_000,
            T0 + 332_000_000_000,
            T0 + 390_000_000_000,
        ] {
            let bm = bmono(c(m as f64)).unwrap().round() as i64;
            let got = o.b_to_a(bm);
            assert!((got - m).abs() < 1_000, "a.mono {m}: {got}");
        }
        // Fitted on b.mono as one line, as /2 did, the same exchanges put b times tens of
        // seconds away from their a.mono.
        let o2 = Offset::fit(&ex, None).unwrap();
        let m = T0 + 20_000_000_000;
        let bm = bmono(c(m as f64)).unwrap().round() as i64;
        assert!((o2.b_to_a(bm) - m).abs() > 10_000_000_000);

        // A b time after the wake and before b's later pair: placed at the pair, it counts as
        // before the suspend and maps a whole suspend early.
        let m = T0 + 330_800_000_000;
        let bm = bmono(c(m as f64)).unwrap().round() as i64;
        assert!(bm > sb && bm < at);
        assert!((m - o.b_to_a(bm)) > susp / 2);
        // With b's suspend event 5 ms after its wake, the suspend is placed there and that
        // time maps to its a.mono.
        let woke = sb + 5_000_000;
        raw.events = vec![stall("b", woke, "suspend"), stall("a", sb, "suspend")];
        let tb = TimeBase::from_raw(&raw);
        assert!(tb.a.suspends.list.is_empty());
        assert_eq!(
            (tb.b.suspends.list[0].at, tb.b.suspends.list[0].pair),
            (woke, at)
        );
        let o = tb.off.as_ref().unwrap();
        assert!((o.skew - 20e-6).abs() < 1e-8, "skew {}", o.skew);
        for m in [
            T0 + 20_000_000_000,
            T0 + 330_800_000_000,
            T0 + 390_000_000_000,
        ] {
            let bm = bmono(c(m as f64)).unwrap().round() as i64;
            let got = o.b_to_a(bm);
            assert!((got - m).abs() < 1_000, "a.mono {m}: {got}");
        }
    }
}
