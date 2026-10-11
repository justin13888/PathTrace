//! PLCY (policy matrix) and VALD (reference-flow results) (docs/design/derivation.md).

use std::collections::BTreeMap;

use pt_format::Value;

use crate::clock::TimeBase;
use crate::raw::Raw;

fn q(v: &mut [f64], p: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    Some(v[((v.len() - 1) as f64 * p).round() as usize])
}

/// UDP echo RTTs per flow (trace ns): echo arrival at the sender minus its transmission.
fn echo_rtts(raw: &Raw, tb: &TimeBase) -> BTreeMap<i64, Vec<f64>> {
    let mut out: BTreeMap<i64, Vec<f64>> = BTreeMap::new();
    let (Some(echo), Some(pkt)) = (raw.table("echo[a]"), raw.table("pkt[a_to_b]")) else {
        return out;
    };
    let mut tx: BTreeMap<(i64, i64), i64> = BTreeMap::new();
    for i in 0..pkt.n {
        let (Some(f), Some(s)) = (pkt.get("flow", i), pkt.get("seq", i)) else {
            continue;
        };
        let t = pkt
            .get("tx_sched", i)
            .map(|s| s + pkt.get("tx_snd_lag", i).unwrap_or(0));
        if let Some(t) = t.and_then(|t| tb.real("a", t)) {
            tx.insert((f, s), t);
        }
    }
    for i in 0..echo.n {
        let (Some(f), Some(s), Some(r)) =
            (echo.get("flow", i), echo.get("seq", i), echo.get("rx", i))
        else {
            continue;
        };
        if let (Some(t), Some(r)) = (tx.get(&(f, s)), tb.real("a", r)) {
            out.entry(f).or_default().push((r - t) as f64);
        }
    }
    out
}

/// Delivery rate (bit/s) of a flow in a direction: received bytes over the receive span.
fn flow_rate(raw: &Raw, dir: &str, flow: i64) -> Option<(f64, f64)> {
    let t = raw.table(&format!("pkt[{dir}]"))?;
    let (mut bytes, mut sent, mut recv, mut t0, mut t1) = (0i64, 0u64, 0u64, i64::MAX, i64::MIN);
    for i in 0..t.n {
        if t.get("flow", i) != Some(flow) {
            continue;
        }
        sent += 1;
        if let Some(r) = t.get("rx", i) {
            recv += 1;
            bytes += t.get("size", i).unwrap_or(0);
            t0 = t0.min(r);
            t1 = t1.max(r);
        }
    }
    if recv < 10 || t1 <= t0 {
        return None;
    }
    Some((
        bytes as f64 * 8.0 * 1e9 / (t1 - t0) as f64,
        1.0 - recv as f64 / sent as f64,
    ))
}

pub fn plcy(raw: &Raw, tb: &TimeBase) -> Value {
    let rtts = echo_rtts(raw, tb);
    let mut udp_min_rtt = f64::MAX;
    let mut classes = Value::map();
    let ref_rate = flow_rate(raw, "a_to_b", 16);
    for (flow, sat_flow, class) in [
        (13i64, 16i64, "udp/high-port"),
        (11, 14, "udp/443"),
        (12, 15, "udp/443-quic"),
    ] {
        let r = rtts.get(&flow).cloned().unwrap_or_default();
        let mut rr = r.clone();
        let min = rr.iter().copied().fold(f64::MAX, f64::min);
        if r.is_empty() {
            classes = classes.with(
                class,
                Value::map()
                    .with("reachable", false)
                    .with("transport", "udp"),
            );
            continue;
        }
        udp_min_rtt = udp_min_rtt.min(min);
        let sat = flow_rate(raw, "a_to_b", sat_flow);
        classes = classes.with(
            class,
            Value::map()
                .with("transport", "udp")
                .with("reachable", true)
                .with("rtt_min_ns", min)
                .with("rtt_median_ns", q(&mut rr, 0.5))
                .with("echoes", r.len())
                .with("rate_bps", sat.map(|s| s.0))
                .with("loss", sat.map(|s| s.1))
                .with(
                    "capacity_ratio",
                    sat.zip(ref_rate).map(|(s, r)| s.0 / r.0.max(1.0)),
                )
                .with(
                    "loss_differential",
                    sat.zip(ref_rate).map(|(s, r)| s.1 - r.1),
                ),
        );
    }
    // TCP classes from tcp_probe events.
    let mut syn_ttl: BTreeMap<u64, u64> = BTreeMap::new();
    for e in raw.events_of("saved_syn") {
        let d = e.get("detail");
        let port = d
            .and_then(|d| d.get("port"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if let Some(Value::Bytes(b)) = d.and_then(|d| d.get("syn")).and_then(|s| s.get("value")) {
            let ttl = if b.first().is_some_and(|v| v >> 4 == 4) {
                b.get(8)
            } else {
                b.get(7)
            };
            if let Some(t) = ttl {
                syn_ttl.insert(port, u64::from(*t));
            }
        }
    }
    let udp_ttl = raw
        .table("pkt[a_to_b]")
        .and_then(|t| (0..t.n).find_map(|i| t.get("ttl_rx", i)))
        .map(|v| v as u64);
    let mut proxy_evidence = Vec::new();
    for e in raw.events_of("tcp_probe") {
        let Some(d) = e.get("detail") else { continue };
        if d.get("primary").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let port = d.get("port").and_then(Value::as_u64).unwrap_or(0);
        let class = match port {
            443 => "tcp/443",
            80 => "tcp/80",
            _ => "tcp/high-port",
        };
        let err = d.get("error").and_then(Value::as_str);
        let connect = d.get("connect_ns").and_then(Value::as_u64).unwrap_or(0) as f64;
        if err.is_none() && udp_min_rtt < f64::MAX && connect < 0.5 * udp_min_rtt {
            proxy_evidence.push(format!(
                "{class}: TCP connect {:.1} ms < half the UDP min RTT {:.1} ms",
                connect / 1e6,
                udp_min_rtt / 1e6
            ));
        }
        if let (Some(st), Some(ut)) = (syn_ttl.get(&port), udp_ttl)
            && *st != ut
        {
            proxy_evidence.push(format!(
                "{class}: SYN TTL at responder {st} differs from UDP TTL {ut}"
            ));
        }
        classes = classes.with(
            class,
            Value::map()
                .with("transport", "tcp")
                .with("reachable", err.is_none())
                .with(
                    "connect_ns",
                    if err.is_none() {
                        Value::from(connect)
                    } else {
                        Value::Null
                    },
                )
                .with("tls_ns", d.get("tls_ns").cloned().unwrap_or(Value::Null))
                .with("error", d.get("error").cloned().unwrap_or(Value::Null))
                .with("syn_ttl_at_responder", syn_ttl.get(&port).copied()),
        );
    }
    // Secondary-family TCP reachability.
    let mut secondary = Vec::new();
    for e in raw.events_of("tcp_probe") {
        if let Some(d) = e.get("detail")
            && d.get("primary").and_then(Value::as_bool) == Some(false)
        {
            secondary.push(
                Value::map()
                    .with("family", d.get("family").cloned().unwrap_or(Value::Null))
                    .with("port", d.get("port").cloned().unwrap_or(Value::Null))
                    .with(
                        "reachable",
                        d.get("error").is_none_or(|v| matches!(v, Value::Null)),
                    ),
            );
        }
    }
    // NAT binding timeouts: flow NAT0+k echoed after T.
    let mut nat = Vec::new();
    for (id, f) in &raw.flows {
        if f.get("kind").and_then(Value::as_str) != Some("nat") {
            continue;
        }
        let t = f.get("echo_delay_ns").and_then(Value::as_u64).unwrap_or(0);
        let arrived = rtts.get(&(*id as i64)).is_some_and(|v| !v.is_empty());
        nat.push(
            Value::map()
                .with("idle_s", t / 1_000_000_000)
                .with("binding_alive", arrived),
        );
    }
    let rebinds = raw.events_of("nat_rebind").count();
    Value::map()
        .with("method", "policy.matrix/1")
        .with("confidence", 0.8)
        .with("classes", classes)
        .with("secondary_family", Value::Array(secondary))
        .with(
            "nat",
            Value::map()
                .with("timeouts", Value::Array(nat))
                .with("rebinds", rebinds),
        )
        .with(
            "proxy_suspected",
            Value::map()
                .with("suspected", !proxy_evidence.is_empty())
                .with(
                    "evidence",
                    Value::Array(proxy_evidence.into_iter().map(Value::from).collect()),
                ),
        )
        .with(
            "udp_min_rtt_ns",
            if udp_min_rtt < f64::MAX {
                Value::from(udp_min_rtt)
            } else {
                Value::Null
            },
        )
}

pub fn vald(raw: &Raw, tb: &TimeBase) -> Value {
    let mut refs = Vec::new();
    // TCP flows from app events on both endpoints.
    for ep in ["a", "b"] {
        let Some(app) = raw.table(&format!("app[{ep}]")) else {
            continue;
        };
        let mut by_flow: BTreeMap<i64, Vec<(i64, i64, i64, i64)>> = BTreeMap::new();
        for i in 0..app.n {
            if let (Some(f), Some(t), Some(e)) =
                (app.get("flow", i), app.get("t", i), app.get("event", i))
            {
                by_flow.entry(f).or_default().push((
                    t,
                    e,
                    app.get("bytes", i).unwrap_or(0),
                    app.get("value", i).unwrap_or(0),
                ));
            }
        }
        for (flow, ev) in by_flow {
            let kind = raw.flow_kind(flow);
            let name = match flow {
                43 => "tcp-bulk-a_to_b",
                44 => "tcp-bulk-b_to_a",
                45 => "tcp-reqresp",
                _ => continue,
            };
            let _ = kind;
            // events: index into APP_EVENTS: 3 first_byte, 5 done, 6 req_start, 7 resp_done
            let first = ev.iter().find(|e| e.1 == 3).map(|e| e.0);
            let done = ev.iter().find(|e| e.1 == 5);
            let mut v = Value::map()
                .with("name", name)
                .with("endpoint", ep)
                .with("flow", flow as u64);
            if flow == 45 && ep == "a" {
                let mut lat: Vec<f64> = Vec::new();
                let starts: BTreeMap<i64, i64> =
                    ev.iter().filter(|e| e.1 == 6).map(|e| (e.3, e.0)).collect();
                for e in ev.iter().filter(|e| e.1 == 7) {
                    if let Some(s) = starts.get(&e.3) {
                        lat.push((e.0 - s) as f64);
                    }
                }
                let n = lat.len();
                v = v
                    .with("requests", n)
                    .with("completion_p50_ns", q(&mut lat, 0.5))
                    .with("completion_p95_ns", q(&mut lat, 0.95))
                    .with("completion_p99_ns", q(&mut lat, 0.99));
            } else if let (Some(f0), Some(d)) = (first, done) {
                // Goodput measured at the receiving endpoint.
                let secs = (d.0 - f0) as f64 / 1e9;
                if secs > 0.0 {
                    v = v
                        .with("bytes", d.2 as u64)
                        .with("goodput_bps", d.2 as f64 * 8.0 / secs)
                        .with("duration_ns", (d.0 - f0) as u64);
                } else {
                    continue;
                }
            } else {
                continue;
            }
            refs.push(v);
        }
    }
    // UDP CBR flows (17 a→b, 18 b→a): one-way latency and loss.
    for (flow, dir) in [(17i64, "a_to_b"), (18, "b_to_a")] {
        let (pkts, _) = crate::dir::packets(raw, tb, dir);
        let ps: Vec<_> = pkts.iter().filter(|p| p.flow == flow).collect();
        if ps.is_empty() {
            continue;
        }
        let mut owd: Vec<f64> = ps
            .iter()
            .filter_map(|p| p.owd())
            .map(|o| o as f64)
            .collect();
        let loss = 1.0 - owd.len() as f64 / ps.len() as f64;
        refs.push(
            Value::map()
                .with("name", format!("udp-cbr-{dir}"))
                .with("flow", flow as u64)
                .with("rate_bps", 2_000_000u64)
                .with("loss", loss)
                .with("owd_p50_ns", q(&mut owd, 0.5))
                .with("owd_p95_ns", q(&mut owd, 0.95))
                .with("owd_p99_ns", q(&mut owd, 0.99))
                .with("split_method", "symmetric_assumed"),
        );
    }
    Value::map()
        .with("method", "vald.reference/1")
        .with("reference", Value::Array(refs))
        .with("fidelity", Value::Null)
}
