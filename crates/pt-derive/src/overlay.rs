//! `overlay.egress-iface/1`: whether the path ran through a tunnel at either endpoint, and the
//! `overlay_limited` qualification of the verdicts that then describe the tunnel
//! (docs/design/derivation.md, Session-wide; probe.md §9.9).

use pt_format::{Key, Value};

use crate::clock::TimeBase;
use crate::raw::Raw;

pub const METHOD: &str = "overlay.egress-iface/1";

/// Per-direction PATH fields whose verdicts describe the tunnel when there is one.
pub const LIMITED_FIELDS: [&str; 4] = ["policer", "mtu", "ecn", "dscp"];

/// One tunnel state of an endpoint's egress interface.
#[derive(Debug, Clone, PartialEq)]
struct Tunnel {
    kind: Option<String>,
    provider: Option<String>,
    mtu: Option<u64>,
}

/// The tunnel described by an `iface` map (META `endpoint.iface` or an `iface_change` detail's
/// `iface`), or `None` when it carries no `tunnel` key.
fn tunnel_of(iface: Option<&Value>) -> Option<Tunnel> {
    let iface = iface?;
    let t = iface.get("tunnel").filter(|t| t.as_map().is_some())?;
    let s = |k: &str| t.get(k).and_then(Value::as_str).map(str::to_string);
    Some(Tunnel {
        kind: s("kind"),
        provider: s("provider"),
        mtu: iface.get("mtu").and_then(Value::as_u64),
    })
}

/// An endpoint's tunnel states in trace time: the state at its start, then one per
/// `iface_change`, in time order, and the span of its clock pairs.
struct Timeline {
    states: Vec<(Option<i64>, Option<Tunnel>)>,
    span: Option<(i64, i64)>,
}

fn timeline(raw: &Raw, tb: &TimeBase, ep: &str, meta: &Value) -> Timeline {
    let mut states = vec![(None, tunnel_of(meta.get("iface")))];
    let mut changes: Vec<(Option<i64>, Option<Tunnel>)> = raw
        .events_of("iface_change")
        .filter(|e| e.get("endpoint").and_then(Value::as_str) == Some(ep))
        .map(|e| {
            let t = e
                .get("t")
                .and_then(Value::as_u64)
                .and_then(|t| tb.mono(ep, t as i64));
            (t, tunnel_of(e.get("detail").and_then(|d| d.get("iface"))))
        })
        .collect();
    changes.sort_by_key(|c| c.0);
    states.extend(changes);
    let span = raw.table(&format!("pairs[{ep}]")).and_then(|p| {
        let m: Vec<i64> = p
            .col("mono")
            .iter()
            .flatten()
            .filter_map(|m| tb.mono(ep, *m))
            .collect();
        Some((*m.iter().min()?, *m.iter().max()?))
    });
    Timeline { states, span }
}

/// Trace-time intervals during which the timeline's interface was a tunnel.
fn tunnel_intervals(tl: &Timeline) -> Vec<(i64, i64)> {
    let Some((start, end)) = tl.span else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, (t, s)) in tl.states.iter().enumerate() {
        if s.is_none() {
            continue;
        }
        let from = t.unwrap_or(start).max(start);
        let to = tl
            .states
            .get(i + 1)
            .and_then(|n| n.0)
            .unwrap_or(end)
            .min(end);
        if to > from {
            out.push((from, to));
        }
    }
    out
}

/// Total length of the union of intervals.
fn union_ns(mut iv: Vec<(i64, i64)>) -> i64 {
    iv.sort_unstable();
    let mut total = 0;
    let mut cur: Option<(i64, i64)> = None;
    for (a, b) in iv {
        match cur {
            Some((ca, cb)) if a <= cb => cur = Some((ca, cb.max(b))),
            _ => {
                if let Some((ca, cb)) = cur {
                    total += cb - ca;
                }
                cur = Some((a, b));
            }
        }
    }
    total + cur.map_or(0, |(a, b)| b - a)
}

/// `PATH.overlay`, and whether the path ran through a tunnel (true only when known).
pub fn overlay(raw: &Raw, tb: &TimeBase) -> (Value, bool) {
    let endpoints = raw.meta.get("endpoints");
    let mut tunnelled = Vec::new();
    let mut first: Option<Tunnel> = None;
    let mut mtu: Option<u64> = None;
    let mut intervals = Vec::new();
    let mut all_recorded = true;
    let mut any_endpoint = false;
    for ep in ["a", "b"] {
        let Some(meta) = endpoints
            .and_then(|e| e.get(ep))
            .filter(|m| m.as_map().is_some())
        else {
            continue;
        };
        any_endpoint = true;
        // A 1.2 writer records `os_family` and records `tunnel` whenever there is one.
        all_recorded &= meta.get("os_family").and_then(Value::as_str).is_some();
        let tl = timeline(raw, tb, ep, meta);
        let tunnels: Vec<&Tunnel> = tl.states.iter().filter_map(|s| s.1.as_ref()).collect();
        if tunnels.is_empty() {
            continue;
        }
        tunnelled.push(Value::from(ep));
        if first.is_none() {
            first = tunnels.first().map(|t| (*t).clone());
        }
        for m in tunnels.iter().filter_map(|t| t.mtu) {
            mtu = Some(mtu.map_or(m, |c| c.min(m)));
        }
        intervals.extend(tunnel_intervals(&tl));
    }
    let base = Value::map().with("method", METHOD);
    if let Some(t) = first {
        let v = base
            .with("status", "known")
            .with("confidence", 1.0)
            .with("source", sources())
            .with("overlay", true)
            .with("endpoints", Value::Array(tunnelled))
            .with("kind", t.kind)
            .with("provider", t.provider)
            .with("mtu", mtu)
            .with("overlay_ns", union_ns(intervals) as u64);
        return (v, true);
    }
    if any_endpoint && all_recorded {
        let v = base
            .with("status", "known")
            .with("confidence", 1.0)
            .with("source", sources())
            .with("overlay", false)
            .with("endpoints", Value::Array(Vec::new()))
            .with("kind", Value::Null)
            .with("provider", Value::Null)
            .with("mtu", Value::Null)
            .with("overlay_ns", 0u64);
        return (v, false);
    }
    let v = base
        .with("status", "unknown")
        .with("confidence", 0.0)
        .with("reason", "no tunnel fact recorded (PTF < 1.2)")
        .with("overlay", Value::Null);
    (v, false)
}

fn sources() -> Value {
    Value::Array(vec![Value::from("META"), Value::from("EVNT")])
}

/// Add `overlay_limited: true` to a map value (a verdict the tunnel limits).
pub fn limit(v: &mut Value) {
    if let Value::Map(m) = v {
        m.insert(Key::from("overlay_limited"), Value::from(true));
    }
}

/// Qualify the per-direction verdicts that describe the tunnel ([`LIMITED_FIELDS`]).
pub fn limit_direction(fields: &mut Value) {
    if let Value::Map(m) = fields {
        for f in LIMITED_FIELDS {
            if let Some(v) = m.get_mut(&Key::from(f)) {
                limit(v);
            }
        }
    }
}

/// Qualify every PLCY class entry.
pub fn limit_policy(plcy: &mut Value) {
    if let Value::Map(m) = plcy
        && let Some(Value::Map(classes)) = m.get_mut(&Key::from("classes"))
    {
        for v in classes.values_mut() {
            limit(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_merges_overlaps() {
        assert_eq!(union_ns(vec![]), 0);
        assert_eq!(union_ns(vec![(0, 10), (5, 15), (20, 30)]), 25);
        assert_eq!(union_ns(vec![(20, 30), (0, 10)]), 20);
    }

    #[test]
    fn tunnel_intervals_follow_changes() {
        let t = || {
            Some(Tunnel {
                kind: Some("utun".into()),
                provider: None,
                mtu: Some(1280),
            })
        };
        // Starts on a tunnel, leaves it at 40, returns at 70; span 0..100.
        let tl = Timeline {
            states: vec![(None, t()), (Some(40), None), (Some(70), t())],
            span: Some((0, 100)),
        };
        assert_eq!(tunnel_intervals(&tl), vec![(0, 40), (70, 100)]);
        // Without clock pairs the time under a tunnel is not measurable.
        let tl = Timeline {
            states: vec![(None, t())],
            span: None,
        };
        assert!(tunnel_intervals(&tl).is_empty());
    }
}
