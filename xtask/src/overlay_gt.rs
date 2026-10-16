//! `overlay-gt check <dir>`: compare the traces of an overlay ground-truth run
//! (tools/overlay-gt/run.sh) with the impairments impair.sh applied, with the checks and
//! tolerances fixed in docs/design/overlay-ground-truth.md.
//!
//! The run directory holds `schedule` (the steps, comments removed) and one `NN-<name>/`
//! directory per step with `ack.txt`, `probe.exit` and the step's `.ptf`. Results go to
//! `results.md`, `results.csv` and `summary.json` in the run directory, and to
//! `$PT_EVIDENCE_OUT` when set; the exit code is 0 when every check passes, 1 otherwise.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use pt_format::Value;

// The namespace harness's trace loader and check rows; groundtruth.rs is left untouched so
// its pinned evidence (EXP-0002-r14 covers it) stays current.
use crate::groundtruth::{Check, Trace, num, trace_in};

fn chk(out: &mut Vec<Check>, name: &str, truth: impl ToString, got: impl ToString, pass: bool) {
    out.push(Check {
        name: name.into(),
        truth: truth.to_string(),
        got: got.to_string(),
        pass,
    });
}

fn rel_ok(got: Option<f64>, truth: f64, tol: f64) -> bool {
    got.is_some_and(|g| ((g - truth) / truth).abs() <= tol)
}

fn fmt(v: Option<f64>) -> String {
    v.map_or("none".into(), |x| format!("{x:.4}"))
}

/// Delay tolerance: the namespace check's 1 ms plus twice the baseline's b→a jitter σ.
const DELAY_TOL_MS: f64 = 1.0;
const DELAY_TOL_SIGMAS: f64 = 2.0;
/// Jitter σ tolerance (relative), as the namespace `jitter` scenario.
const JITTER_TOL: f64 = 0.30;
/// Loss tolerance in standard errors of the step-minus-baseline difference (99 %).
const LOSS_Z: f64 = 2.576;
/// Rate tolerance (relative), as the namespace capacity checks.
const RATE_TOL: f64 = 0.10;
/// The baseline b→a capacity must be at least this multiple of a rate step's rate.
const RATE_HEADROOM: f64 = 2.0;

/// One schedule step.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub name: String,
    /// netem arguments, or `none`.
    pub spec: String,
}

impl Step {
    /// The step's directory name in a run: `NN-<name>`, NN from 1.
    pub fn dir_name(&self, index: usize) -> String {
        format!("{:02}-{}", index + 1, self.name)
    }
}

/// Parse a schedule: one step per line (name, then netem arguments or `none`); `#` comments.
pub fn parse_schedule(text: &str) -> Result<Vec<Step>> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let name = words.next().unwrap_or_default().to_string();
        let spec = words.collect::<Vec<_>>().join(" ");
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            bail!("schedule line {}: bad step name {name:?}", i + 1);
        }
        if spec.is_empty() {
            bail!(
                "schedule line {}: step {name} has no netem arguments",
                i + 1
            );
        }
        parse_netem(&spec).with_context(|| format!("schedule step {name}"))?;
        out.push(Step { name, spec });
    }
    match out.first() {
        None => bail!("schedule has no steps"),
        Some(s) if s.spec != "none" => bail!("the first step must be `none` (the baseline)"),
        _ => Ok(out),
    }
}

/// What a step's netem arguments impose on b→a.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Truth {
    pub delay_ms: f64,
    /// Standard deviation of the added delay.
    pub jitter_ms: f64,
    /// Loss probability (0–1).
    pub loss: f64,
    pub rate_bps: Option<f64>,
}

fn time_ms(s: &str) -> Option<f64> {
    let (v, scale) = if let Some(v) = s.strip_suffix("ms") {
        (v, 1.0)
    } else if let Some(v) = s.strip_suffix("us") {
        (v, 1e-3)
    } else {
        (s.strip_suffix('s')?, 1e3)
    };
    v.parse::<f64>().ok().map(|x| x * scale)
}

fn rate_bps(s: &str) -> Option<f64> {
    let units = [("gbit", 1e9), ("mbit", 1e6), ("kbit", 1e3), ("bit", 1.0)];
    let (v, scale) = units
        .iter()
        .find_map(|(u, k)| s.strip_suffix(u).map(|v| (v, *k)))?;
    v.parse::<f64>().ok().map(|x| x * scale)
}

fn percent(s: &str) -> Option<f64> {
    s.strip_suffix('%')?.parse::<f64>().ok().map(|x| x / 100.0)
}

/// The truth of netem arguments. Only the forms the design's checks can judge are accepted:
/// `delay T [J [distribution normal]]`, `loss [random] P%`, `rate R`, `limit N`, or `none`.
pub fn parse_netem(spec: &str) -> Result<Truth> {
    let mut t = Truth::default();
    if spec == "none" {
        return Ok(t);
    }
    let w: Vec<&str> = spec.split_whitespace().collect();
    let mut i = 0;
    let arg = |i: usize, what: &str| -> Result<&str> {
        w.get(i)
            .copied()
            .with_context(|| format!("{what} needs a value"))
    };
    while i < w.len() {
        match w[i] {
            "delay" => {
                let d = arg(i + 1, "delay")?;
                t.delay_ms = time_ms(d).with_context(|| format!("bad delay {d:?}"))?;
                i += 2;
                if let Some(j) = w.get(i).and_then(|j| time_ms(j)) {
                    i += 1;
                    // netem's jitter is σ for a distribution table, else a uniform ±J.
                    if w.get(i) == Some(&"distribution") {
                        let d = arg(i + 1, "distribution")?;
                        if d != "normal" {
                            bail!("distribution {d} is not checked (use normal)");
                        }
                        i += 2;
                        t.jitter_ms = j;
                    } else {
                        t.jitter_ms = j / 3f64.sqrt();
                    }
                }
            }
            "loss" => {
                if w.get(i + 1) == Some(&"random") {
                    i += 1;
                }
                let p = arg(i + 1, "loss")?;
                t.loss = percent(p).with_context(|| format!("bad loss {p:?}"))?;
                i += 2;
            }
            "rate" => {
                let r = arg(i + 1, "rate")?;
                t.rate_bps = Some(rate_bps(r).with_context(|| format!("bad rate {r:?}"))?);
                i += 2;
            }
            "limit" => {
                let n = arg(i + 1, "limit")?;
                n.parse::<u64>()
                    .with_context(|| format!("bad limit {n:?}"))?;
                i += 2;
            }
            other => bail!("netem argument {other:?} is not checked by overlay-gt"),
        }
    }
    Ok(t)
}

/// Median of a direction's quiet light-flow delay residuals, ms.
fn p50_ms(t: &Trace, dir: &str) -> Option<f64> {
    let j = t.dir(dir, "/jitter")?;
    let levels = j.get("quantile_levels")?.as_array()?;
    let at = levels
        .iter()
        .position(|l| num(l).is_some_and(|l| (l - 0.5).abs() < 1e-9))?;
    num(j.get("quantiles_ns")?.as_array()?.get(at)?).map(|v| v / 1e6)
}

/// D = base delay a→b + base delay b→a + the b→a residual median, ms (design, Tolerances).
fn delay_d(t: &Trace) -> Option<f64> {
    let a = t.num("a_to_b", "/base_delay/delay_ns")?;
    let b = t.num("b_to_a", "/base_delay/delay_ns")?;
    Some((a + b) / 1e6 + p50_ms(t, "b_to_a")?)
}

fn sigma_ms(t: &Trace) -> Option<f64> {
    t.num("b_to_a", "/jitter/stddev_ns").map(|v| v / 1e6)
}

/// (loss rate, samples) of b→a.
fn loss_b(t: &Trace) -> Option<(f64, f64)> {
    Some((
        t.num("b_to_a", "/loss/rate")?,
        t.num("b_to_a", "/loss/samples")?,
    ))
}

/// Truth checks of one step against the run's baseline.
pub fn step_checks(truth: &Truth, base: &Trace, t: &Trace) -> Vec<Check> {
    let mut c = Vec::new();
    let s0 = sigma_ms(base);
    if truth.rate_bps.is_none() {
        let got = delay_d(t).zip(delay_d(base)).map(|(s, b)| s - b);
        let tol = s0.map(|s| DELAY_TOL_MS + DELAY_TOL_SIGMAS * s);
        chk(
            &mut c,
            "b_to_a delay increase (ms; base a+b + p50 residual b, vs baseline)",
            format!("{} ± {}", truth.delay_ms, fmt(tol)),
            fmt(got),
            got.zip(tol)
                .is_some_and(|(g, tol)| (g - truth.delay_ms).abs() <= tol),
        );
    }
    if truth.jitter_ms > 0.0 {
        let got = sigma_ms(t)
            .zip(s0)
            .map(|(s, b)| (s * s - b * b).max(0.0).sqrt());
        chk(
            &mut c,
            "b_to_a added jitter σ (ms, ±30%, baseline σ removed in quadrature)",
            truth.jitter_ms,
            fmt(got),
            rel_ok(got, truth.jitter_ms, JITTER_TOL),
        );
    }
    if truth.loss > 0.0 {
        let (got, tol) = match (loss_b(t), loss_b(base)) {
            (Some((ps, ns)), Some((pb, nb))) if ns > 0.0 && nb > 0.0 => {
                let se = (ps * (1.0 - ps) / ns + pb * (1.0 - pb) / nb).sqrt();
                (Some(ps - pb), Some(LOSS_Z * se))
            }
            _ => (None, None),
        };
        chk(
            &mut c,
            "b_to_a loss increase (vs baseline, ± 2.576 s.e.)",
            format!("{} ± {}", truth.loss, fmt(tol)),
            fmt(got),
            got.zip(tol)
                .is_some_and(|(g, tol)| (g - truth.loss).abs() <= tol),
        );
    }
    if let Some(r) = truth.rate_bps {
        let cap0 = base.num("b_to_a", "/capacity/median_rate_bps");
        chk(
            &mut c,
            "baseline b_to_a capacity at least 2× the rate (netem is the bottleneck)",
            format!(">= {:.0}", RATE_HEADROOM * r),
            fmt(cap0),
            cap0.is_some_and(|v| v >= RATE_HEADROOM * r),
        );
        let cap = t.num("b_to_a", "/capacity/median_rate_bps");
        chk(
            &mut c,
            "b_to_a capacity (bit/s, ±10%, IP bytes on a TUN device)",
            format!("{r:.0}"),
            fmt(cap),
            rel_ok(cap, r, RATE_TOL),
        );
    }
    c
}

/// The netem arguments an ack says impair.sh applied.
fn ack_netem(ack: &str) -> Option<&str> {
    ack.lines().find_map(|l| l.strip_prefix("netem "))
}

fn field_str<'a>(v: Option<&'a Value>, k: &str) -> &'a str {
    v.and_then(|v| v.get(k))
        .and_then(Value::as_str)
        .unwrap_or("?")
}

/// Checks every step's trace must pass, whatever its impairment.
pub fn invariants(step: &Step, t: &Trace, ack: &str, probe_exit: &str) -> Vec<Check> {
    let mut c = Vec::new();
    let applied = ack_netem(ack).unwrap_or("none recorded");
    chk(
        &mut c,
        "ack: netem applied as scheduled",
        &step.spec,
        applied,
        applied == step.spec,
    );
    chk(
        &mut c,
        "probe exit code",
        0,
        probe_exit.trim(),
        probe_exit.trim() == "0",
    );
    let complete = t
        .meta
        .get("complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    chk(&mut c, "session complete", true, complete, complete);
    let counts = t.dir("a_to_b", "/timestamps/counts");
    let n = |k: &str| counts.and_then(|m| m.get(k)).and_then(num).unwrap_or(0.0);
    let (user, snd, sched) = (n("user"), n("snd"), n("sched"));
    chk(
        &mut c,
        "a_to_b transmit times user-space only (macOS sender)",
        "user > 0, snd = sched = 0",
        format!("user {user}, snd {snd}, sched {sched}"),
        counts.is_some() && user > 0.0 && snd == 0.0 && sched == 0.0,
    );
    let q = t.dir("a_to_b", "/local_qdisc_drops");
    let qs = field_str(q, "status");
    chk(
        &mut c,
        "a_to_b local_qdisc_drops unknown (macOS sender has no qdisc)",
        "unknown",
        qs,
        qs == "unknown",
    );
    let h = t.dir("b_to_a", "/host_drops");
    let (hs, hm) = (field_str(h, "status"), field_str(h, "method"));
    chk(
        &mut c,
        "b_to_a host_drops unknown, or known only from the host-wide counter (macOS receiver)",
        "unknown | known by hostdrop.host-fullsock/1",
        format!("{hs} by {hm}"),
        hs == "unknown" || (hs == "known" && hm == "hostdrop.host-fullsock/1"),
    );
    let o = t.path.get("overlay");
    let os = field_str(o, "status");
    let ov = o.and_then(|o| o.get("overlay")).and_then(Value::as_bool);
    chk(
        &mut c,
        "overlay recorded (PATH.overlay)",
        "known, overlay true",
        format!("{os}, overlay {ov:?}"),
        os == "known" && ov == Some(true),
    );
    c
}

/// One step's results.
#[derive(Debug)]
pub struct StepResult {
    pub dir: String,
    pub spec: String,
    pub checks: Vec<Check>,
}

fn missing(what: &str, e: &anyhow::Error) -> Check {
    Check {
        name: what.into(),
        truth: "present".into(),
        got: e.to_string(),
        pass: false,
    }
}

/// Check a whole run directory.
pub fn check_dir(dir: &Path) -> Result<Vec<StepResult>> {
    let text = std::fs::read_to_string(dir.join("schedule"))
        .with_context(|| format!("no schedule in {}", dir.display()))?;
    let steps = parse_schedule(&text)?;
    let load = |sd: &Path| -> Result<Trace> { Trace::load(&trace_in(sd)?) };
    let base_dir = dir.join(steps[0].dir_name(0));
    let base = load(&base_dir);
    let mut out = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let name = step.dir_name(i);
        let sd = dir.join(&name);
        let read = |f: &str| std::fs::read_to_string(sd.join(f)).unwrap_or_default();
        let mut checks = Vec::new();
        match load(&sd) {
            Ok(t) => {
                checks.extend(invariants(step, &t, &read("ack.txt"), &read("probe.exit")));
                if i > 0 {
                    let truth = parse_netem(&step.spec)?;
                    match &base {
                        Ok(b) => checks.extend(step_checks(&truth, b, &t)),
                        Err(e) => checks.push(missing("baseline trace", e)),
                    }
                }
            }
            Err(e) => checks.push(missing("step trace", &e)),
        }
        out.push(StepResult {
            dir: name,
            spec: step.spec.clone(),
            checks,
        });
    }
    Ok(out)
}

fn csv_field(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "'"))
}

/// The results table (Markdown), CSV and JSON summary.
pub fn render(results: &[StepResult]) -> (String, String, String, bool) {
    let mut md = String::from(
        "| Step | netem (b→a) | Check | Truth | Recovered | Pass |\n|---|---|---|---|---|---|\n",
    );
    let mut csv = String::from("step,netem,check,truth,got,pass\n");
    let mut all = true;
    let mut steps = Vec::new();
    for r in results {
        let mut cks = Vec::new();
        for k in &r.checks {
            all &= k.pass;
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {} |",
                r.dir,
                r.spec,
                k.name,
                k.truth,
                k.got,
                if k.pass { "yes" } else { "**no**" }
            );
            let _ = writeln!(
                csv,
                "{},{},{},{},{},{}",
                r.dir,
                csv_field(&r.spec),
                csv_field(&k.name),
                csv_field(&k.truth),
                csv_field(&k.got),
                k.pass
            );
            cks.push(
                Value::map()
                    .with("check", k.name.as_str())
                    .with("truth", k.truth.as_str())
                    .with("got", k.got.as_str())
                    .with("pass", k.pass),
            );
        }
        steps.push(
            Value::map()
                .with("step", r.dir.as_str())
                .with("netem", r.spec.as_str())
                .with("pass", r.checks.iter().all(|k| k.pass))
                .with("checks", Value::Array(cks)),
        );
    }
    let summary = Value::map()
        .with("harness", "overlay-gt/1")
        .with("design", "docs/design/overlay-ground-truth.md")
        .with("verdict", if all { "pass" } else { "fail" })
        .with(
            "tolerances",
            Value::map()
                .with("delay_ms", DELAY_TOL_MS)
                .with("delay_baseline_sigmas", DELAY_TOL_SIGMAS)
                .with("jitter_rel", JITTER_TOL)
                .with("loss_z", LOSS_Z)
                .with("rate_rel", RATE_TOL)
                .with("rate_headroom", RATE_HEADROOM),
        )
        .with("steps", Value::Array(steps));
    let json = pt_format::jsonl::cbor_to_json(&summary).to_string() + "\n";
    (md, csv, json, all)
}

/// `cargo xtask overlay-gt check <dir>`: returns whether every check passed.
pub fn check(dir: &Path) -> Result<bool> {
    let results = check_dir(dir)?;
    let (md, csv, json, all) = render(&results);
    let mut outs: Vec<PathBuf> = vec![dir.to_path_buf()];
    if let Some(ev) = std::env::var_os("PT_EVIDENCE_OUT") {
        outs.push(PathBuf::from(ev));
    }
    for o in outs {
        std::fs::create_dir_all(&o)?;
        std::fs::write(o.join("results.md"), &md)?;
        std::fs::write(o.join("results.csv"), &csv)?;
        std::fs::write(o.join("summary.json"), &json)?;
    }
    print!("{md}");
    println!("verdict: {}", if all { "pass" } else { "fail" });
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pt_format::{PtfFile, Section, WriteOptions, flags};

    const MS: f64 = 1e6;

    /// Measured values of a synthetic macOS-initiator trace.
    #[derive(Clone, Copy)]
    struct M {
        base_a_ms: f64,
        base_b_ms: f64,
        p50_b_ms: f64,
        sigma_b_ms: f64,
        loss_b: f64,
        samples_b: u64,
        cap_b: f64,
    }

    const BASE: M = M {
        base_a_ms: 6.0,
        base_b_ms: 6.0,
        p50_b_ms: 1.0,
        sigma_b_ms: 1.0,
        loss_b: 0.001,
        samples_b: 10_000,
        cap_b: 200e6,
    };

    fn path(m: M) -> Value {
        let levels = [0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99];
        let q: Vec<Value> = levels
            .iter()
            .map(|l| Value::from((m.p50_b_ms + (l - 0.5) * 4.0 * m.sigma_b_ms) * MS))
            .collect();
        let jitter = |sigma_ms: f64| {
            Value::map()
                .with("status", "known")
                .with(
                    "quantile_levels",
                    Value::Array(levels.iter().map(|l| Value::from(*l)).collect()),
                )
                .with("quantiles_ns", Value::Array(q.clone()))
                .with("stddev_ns", sigma_ms * MS)
        };
        let a = Value::map()
            .with(
                "base_delay",
                Value::map().with("delay_ns", m.base_a_ms * MS),
            )
            .with(
                "timestamps",
                Value::map().with("counts", Value::map().with("user", 5000u64)),
            )
            .with(
                "local_qdisc_drops",
                Value::map()
                    .with("status", "unknown")
                    .with("reason", "no qdisc counters recorded"),
            );
        let b = Value::map()
            .with(
                "base_delay",
                Value::map().with("delay_ns", m.base_b_ms * MS),
            )
            .with("jitter", jitter(m.sigma_b_ms))
            .with(
                "loss",
                Value::map()
                    .with("rate", m.loss_b)
                    .with("samples", m.samples_b),
            )
            .with("capacity", Value::map().with("median_rate_bps", m.cap_b))
            .with(
                "host_drops",
                Value::map()
                    .with("status", "known")
                    .with("method", "hostdrop.host-fullsock/1")
                    .with("packets", 0u64),
            )
            .with(
                "timestamps",
                Value::map().with("counts", Value::map().with("snd", 5000u64)),
            );
        Value::map()
            .with(
                "directions",
                Value::map().with("a_to_b", a).with("b_to_a", b),
            )
            .with(
                "overlay",
                Value::map()
                    .with("status", "known")
                    .with("overlay", true)
                    .with("provider", "tailscale"),
            )
    }

    fn meta() -> Value {
        Value::map().with("complete", true)
    }

    fn trace(m: M) -> Trace {
        Trace {
            path: path(m),
            plcy: Value::Null,
            meta: meta(),
            events: Vec::new(),
            file: PtfFile {
                major: 1,
                minor: 2,
                sections: Vec::new(),
            },
        }
    }

    fn passes(c: &[Check]) -> bool {
        c.iter().all(|k| k.pass)
    }

    fn step(spec: &str) -> Step {
        Step {
            name: "s".into(),
            spec: spec.into(),
        }
    }

    #[test]
    fn shipped_schedule_parses_to_the_designed_truth() {
        let steps = parse_schedule(include_str!("../../tools/overlay-gt/schedule")).unwrap();
        let truths: Vec<(String, Truth)> = steps
            .iter()
            .map(|s| (s.name.clone(), parse_netem(&s.spec).unwrap()))
            .collect();
        let t = |d, j, l, r| Truth {
            delay_ms: d,
            jitter_ms: j,
            loss: l,
            rate_bps: r,
        };
        let want = [
            ("baseline", t(0.0, 0.0, 0.0, None)),
            ("delay40", t(40.0, 0.0, 0.0, None)),
            ("delay40-jitter5", t(40.0, 5.0, 0.0, None)),
            ("loss2", t(0.0, 0.0, 0.02, None)),
            ("rate20", t(0.0, 0.0, 0.0, Some(20e6))),
            ("delay30-loss1", t(30.0, 0.0, 0.01, None)),
        ];
        assert_eq!(truths.len(), want.len());
        for ((name, got), (wn, w)) in truths.iter().zip(want) {
            assert_eq!(name, wn);
            assert!((got.delay_ms - w.delay_ms).abs() < 1e-9, "{name}");
            assert!((got.jitter_ms - w.jitter_ms).abs() < 1e-9, "{name}");
            assert!((got.loss - w.loss).abs() < 1e-12, "{name}");
            assert_eq!(got.rate_bps, w.rate_bps, "{name}");
        }
        assert_eq!(steps[1].dir_name(1), "02-delay40");
    }

    #[test]
    fn netem_forms_outside_the_checks_are_refused() {
        assert!(parse_netem("delay 40ms 5ms distribution pareto").is_err());
        assert!(parse_netem("delay 40ms 5ms 25%").is_err());
        assert!(parse_netem("duplicate 1%").is_err());
        assert!(parse_netem("loss 2").is_err());
        assert!(parse_netem("rate 20").is_err());
        assert!(parse_schedule("first delay 10ms\n").is_err());
        assert!(parse_schedule("# nothing\n\n").is_err());
        assert!(parse_schedule("bad/name none\n").is_err());
        // Uniform jitter: σ = J/√3; units.
        let u = parse_netem("delay 1s 3us").unwrap();
        assert!((u.delay_ms - 1000.0).abs() < 1e-9);
        assert!((u.jitter_ms - 0.003 / 3f64.sqrt()).abs() < 1e-12);
        assert_eq!(parse_netem("loss random 1.5%").unwrap().loss, 0.015);
        assert_eq!(parse_netem("rate 512kbit").unwrap().rate_bps, Some(512e3));
    }

    #[test]
    fn delay_increase_uses_the_base_sum_and_the_median() {
        let base = trace(BASE);
        // Symmetric split: 40 ms on b→a moves each base delay by 20 ms.
        let ok = trace(M {
            base_a_ms: 26.0,
            base_b_ms: 26.0,
            ..BASE
        });
        let truth = parse_netem("delay 40ms limit 100000").unwrap();
        assert!(passes(&step_checks(&truth, &base, &ok)));
        // Tolerance is 1 ms + 2σ₀ = 3 ms: 4 ms short fails.
        let short = trace(M {
            base_a_ms: 24.0,
            base_b_ms: 24.0,
            ..BASE
        });
        assert!(!passes(&step_checks(&truth, &base, &short)));
        // A loss-only step must not move the delay.
        let loss = parse_netem("loss 2% limit 100000").unwrap();
        let moved = trace(M {
            base_a_ms: 11.0,
            base_b_ms: 11.0,
            loss_b: 0.021,
            ..BASE
        });
        let c = step_checks(&loss, &base, &moved);
        assert!(!c[0].pass && c[1].pass, "{c:?}");
    }

    #[test]
    fn jitter_is_recovered_in_quadrature() {
        let base = trace(BASE);
        let truth = parse_netem("delay 40ms 5ms distribution normal").unwrap();
        // The minimum falls about 3σ below the netem delay; the median does not.
        let sigma = (25.0f64 + 1.0).sqrt();
        let ok = trace(M {
            base_a_ms: 18.5,
            base_b_ms: 18.5,
            p50_b_ms: 1.0 + 15.0,
            sigma_b_ms: sigma,
            ..BASE
        });
        let c = step_checks(&truth, &base, &ok);
        assert!(passes(&c), "{c:?}");
        let flat = trace(M {
            sigma_b_ms: 2.0,
            ..BASE
        });
        let c = step_checks(&truth, &base, &flat);
        assert!(!c[1].pass, "{c:?}");
    }

    #[test]
    fn loss_is_judged_against_the_baseline_with_its_noise() {
        let base = trace(BASE);
        let truth = parse_netem("loss 2%").unwrap();
        let ok = trace(M {
            loss_b: 0.0205,
            ..BASE
        });
        assert!(passes(&step_checks(&truth, &base, &ok)));
        let high = trace(M {
            loss_b: 0.03,
            ..BASE
        });
        assert!(!passes(&step_checks(&truth, &base, &high)));
        // No sample count: unknown, so the check fails rather than passing on a zero.
        let mut none = trace(BASE);
        none.path = Value::map().with("directions", Value::map());
        assert!(!passes(&step_checks(&truth, &base, &none)));
    }

    #[test]
    fn rate_needs_headroom_and_matches_within_ten_percent() {
        let truth = parse_netem("rate 20mbit limit 1000").unwrap();
        let base = trace(BASE);
        let ok = trace(M {
            cap_b: 19.2e6,
            ..BASE
        });
        let c = step_checks(&truth, &base, &ok);
        assert_eq!(c.len(), 2, "rate steps skip the delay check");
        assert!(passes(&c), "{c:?}");
        let slow = trace(M {
            cap_b: 17.0e6,
            ..BASE
        });
        assert!(!step_checks(&truth, &base, &slow)[1].pass);
        // A relayed overlay below 2x the rate: netem is not the bottleneck.
        let relayed = trace(M {
            cap_b: 30e6,
            ..BASE
        });
        assert!(!step_checks(&truth, &relayed, &ok)[0].pass);
    }

    #[test]
    fn invariants_hold_for_a_macos_initiator_trace() {
        let t = trace(BASE);
        let s = step("none");
        let ack = "step 01 s\nnetem none\n";
        assert!(passes(&invariants(&s, &t, ack, "0\n")));
        // An unknown host-drop field also passes; a zero from rxq_drops does not.
        let mut u = trace(BASE);
        let set_host = |p: &mut Value, v: Value| {
            if let Some(Value::Map(d)) = p.get_mut_dir("b_to_a") {
                d.insert("host_drops".into(), v);
            }
        };
        set_host(
            &mut u.path,
            Value::map().with("status", "unknown").with("reason", "x"),
        );
        assert!(passes(&invariants(&s, &u, ack, "0")));
        set_host(
            &mut u.path,
            Value::map()
                .with("status", "known")
                .with("method", "hostdrop.rxq-gap/1")
                .with("packets", 0u64),
        );
        assert!(!passes(&invariants(&s, &u, ack, "0")));
    }

    #[test]
    fn invariants_catch_each_failure() {
        let s = step("delay 40ms");
        let t = trace(BASE);
        let ack = "netem delay 40ms\n";
        let fails = |c: Vec<Check>, name: &str| {
            let bad: Vec<&str> = c
                .iter()
                .filter(|k| !k.pass)
                .map(|k| k.name.as_str())
                .collect();
            assert_eq!(bad.len(), 1, "{bad:?}");
            assert!(bad[0].starts_with(name), "{bad:?}");
        };
        fails(invariants(&s, &t, "netem delay 30ms\n", "0"), "ack");
        fails(invariants(&s, &t, ack, "3"), "probe exit");
        let mut inc = trace(BASE);
        inc.meta = Value::map().with("complete", false);
        fails(invariants(&s, &inc, ack, "0"), "session complete");
        let mut stamped = trace(BASE);
        if let Some(Value::Map(d)) = stamped.path.get_mut_dir("a_to_b") {
            d.insert(
                "timestamps".into(),
                Value::map().with(
                    "counts",
                    Value::map().with("user", 10u64).with("snd", 4990u64),
                ),
            );
        }
        fails(invariants(&s, &stamped, ack, "0"), "a_to_b transmit");
        let mut qd = trace(BASE);
        if let Some(Value::Map(d)) = qd.path.get_mut_dir("a_to_b") {
            d.insert(
                "local_qdisc_drops".into(),
                Value::map().with("status", "known").with("drops", 0u64),
            );
        }
        fails(invariants(&s, &qd, ack, "0"), "a_to_b local_qdisc");
        let mut flat = trace(BASE);
        if let Value::Map(p) = &mut flat.path {
            p.insert(
                "overlay".into(),
                Value::map().with("status", "known").with("overlay", false),
            );
        }
        fails(invariants(&s, &flat, ack, "0"), "overlay");
    }

    trait DirMut {
        fn get_mut_dir(&mut self, d: &str) -> Option<&mut Value>;
    }

    impl DirMut for Value {
        fn get_mut_dir(&mut self, d: &str) -> Option<&mut Value> {
            let Value::Map(p) = self else { return None };
            let Value::Map(dirs) = p.get_mut(&"directions".into())? else {
                return None;
            };
            dirs.get_mut(&d.into())
        }
    }

    fn write_ptf(dir: &Path, m: M) {
        let file = PtfFile {
            major: 1,
            minor: 2,
            sections: vec![
                Section::new(b"META", 0, meta().as_map().cloned().unwrap()),
                Section::new(
                    b"PATH",
                    flags::CRITICAL | flags::DERIVED,
                    path(m).as_map().cloned().unwrap(),
                ),
            ],
        };
        let mut f = std::fs::File::create(dir.join("t.ptf")).unwrap();
        pt_format::write(&file, &WriteOptions::canonical(), &mut f).unwrap();
    }

    #[test]
    fn a_run_directory_is_checked_end_to_end() {
        let root = std::env::temp_dir().join(format!("overlay-gt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("schedule"),
            "baseline none\ndelay40 delay 40ms limit 100000\nloss2 loss 2% limit 100000\n",
        )
        .unwrap();
        let step = |name: &str, spec: &str, m: M| {
            let d = root.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("ack.txt"), format!("step x\nnetem {spec}\n")).unwrap();
            std::fs::write(d.join("probe.exit"), "0\n").unwrap();
            write_ptf(&d, m);
        };
        step("01-baseline", "none", BASE);
        step(
            "02-delay40",
            "delay 40ms limit 100000",
            M {
                base_a_ms: 26.0,
                base_b_ms: 26.0,
                ..BASE
            },
        );
        // The loss step's trace is missing: reported as a failing row, not an error.
        let results = check_dir(&root).unwrap();
        assert_eq!(results.len(), 3);
        assert!(passes(&results[0].checks) && passes(&results[1].checks));
        assert!(!passes(&results[2].checks));
        let (md, csv, json, all) = render(&results);
        assert!(!all);
        assert!(md.contains("| 02-delay40 |"));
        assert!(csv.starts_with("step,netem,check,truth,got,pass\n"));
        assert!(json.contains("\"verdict\":\"fail\""));
        assert!(json.len() < 64 * 1024);
        step(
            "03-loss2",
            "loss 2% limit 100000",
            M {
                loss_b: 0.021,
                ..BASE
            },
        );
        assert!(check(&root).unwrap());
        let json = std::fs::read_to_string(root.join("summary.json")).unwrap();
        assert!(json.contains("\"verdict\":\"pass\""));
        assert!(root.join("results.md").exists() && root.join("results.csv").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
