//! Derivation of macOS-shaped traces (probe.md §9, derivation.md): a macOS initiator (a, no
//! kernel TX stamps, no `rxq_drops`, no qdisc, no ICMP errors, host-wide `udp_fullsock`)
//! against a Linux responder (b), optionally through a tunnel; and the Linux behaviour these
//! rules must leave unchanged.

use pt_derive::Tool;
use pt_format::{Column, Data, Enc, Map, PtfFile, Section, Table, Value, Values, flags};

const T0: u64 = 1_000_000_000_000;
const MS: u64 = 1_000_000;
const DELAY: u64 = 5 * MS;
const USER_LAG: i64 = 20_000;
const LIGHT: u64 = 200;

fn tool() -> Tool {
    Tool {
        version: "test".into(),
        git_commit: "0".into(),
        git_dirty: false,
    }
}

fn u(name: &str, v: Vec<u64>) -> Column {
    Column::new(name, Enc::Delta, Values::U64(v))
}

fn nu(name: &str, v: &[Option<u64>]) -> Column {
    Column::nullable_u64(name, Enc::Delta, v)
}

fn ni(name: &str, v: &[Option<i64>]) -> Column {
    Column {
        name: name.into(),
        data: Data::Known {
            enc: Enc::Varint,
            values: Values::I64(v.iter().flatten().copied().collect()),
        },
        validity: Some(v.iter().map(Option::is_some).collect()),
        meta: Map::new(),
    }
}

fn section(kind: &[u8; 4], head: Value) -> Section {
    Section::new(kind, 0, head.as_map().cloned().unwrap_or_default())
}

fn tables(kind: &[u8; 4], t: Table) -> Section {
    Section::new(kind, 0, Map::new()).with_table(t)
}

/// One transmitted packet: flow, seq, size, kind of transmit time, arrival.
#[derive(Clone, Copy)]
struct P {
    flow: u64,
    seq: u64,
    size: u64,
    tx: u64,
    rx: Option<u64>,
}

/// A `pkt` table. `stamped`: the sender has kernel TX stamps (Linux b); otherwise only the
/// user-space time (macOS a). `rxq`: the receiver records `rxq_drops` (Linux b).
fn pkt(dir: &str, ps: &[P], stamped: bool, rxq: bool) -> Table {
    let n = ps.len();
    let col = |f: fn(&P) -> u64| ps.iter().map(f).collect::<Vec<_>>();
    let mut t = Table::new("pkt", n)
        .with(u("flow", col(|p| p.flow)))
        .with(u("seq", col(|p| p.seq)))
        .with(u("size", col(|p| p.size)))
        .with(u("phase", vec![2; n]))
        .with(u("train", vec![0; n]))
        .with(u("train_idx", vec![0; n]))
        .with(u("tos_tx", vec![0; n]))
        .with(u("tx_sock", vec![0; n]))
        .with(u("tx_intended", col(|p| p.tx)))
        .with(ni("tx_user_lag", &vec![Some(USER_LAG); n]));
    if stamped {
        let sched: Vec<Option<u64>> = ps.iter().map(|p| Some(p.tx + 1_000)).collect();
        t = t
            .with(nu("tx_sched", &sched))
            .with(ni("tx_snd_lag", &vec![Some(2_000); n]));
    } else {
        t = t
            .with(nu("tx_sched", &vec![None; n]))
            .with(ni("tx_snd_lag", &vec![None; n]));
    }
    let rx: Vec<Option<u64>> = ps.iter().map(|p| p.rx).collect();
    t = t.with(nu("rx", &rx));
    let got = |v: u64| ps.iter().map(|p| p.rx.map(|_| v)).collect::<Vec<_>>();
    t = t.with(nu("rx_sock", &got(0)));
    if rxq {
        t = t.with(nu("rxq_drops", &got(0)));
    }
    t.with_attrs(Value::map().with("dir", dir))
}

/// A light flow (`LIGHT` packets 10 ms apart, every 20th lost), the PMTU ladder and the UDP
/// class probes of one direction.
fn direction(light: u64, pmtu: u64, user: bool) -> Vec<P> {
    let lag = if user { USER_LAG as u64 } else { 3_000 };
    let mut v: Vec<P> = (0..LIGHT)
        .map(|i| {
            let tx = T0 + i * 10 * MS;
            P {
                flow: light,
                seq: i,
                size: 128,
                tx,
                rx: (i % 20 != 19).then_some(tx + lag + DELAY),
            }
        })
        .collect();
    for (k, size) in [1200u64, 1280, 1400, 1500].iter().enumerate() {
        let tx = T0 + 50 * MS + k as u64 * MS;
        v.push(P {
            flow: pmtu,
            seq: k as u64,
            size: *size,
            tx,
            rx: (*size <= 1280).then_some(tx + lag + DELAY),
        });
    }
    v
}

/// Policer of the `policed_class` saturation: rate (bit/s) and bucket (bytes).
const POLICER_BPS: f64 = 10e6;
const POLICER_BUCKET: f64 = 30_000.0;

/// A 1 s saturation of 1200 B packets at 20 Mbit/s, from 200 ms after T0, through a full
/// `POLICER_BPS` token bucket of `POLICER_BUCKET`, which queues nothing: what passes arrives
/// after the base delay, what does not is lost.
fn policed(flow: u64, lag: u64) -> Vec<P> {
    let gap = 480_000u64;
    let mut tokens = POLICER_BUCKET;
    (0..2_083u64)
        .map(|k| {
            if k > 0 {
                tokens = (tokens + POLICER_BPS * gap as f64 / 8e9).min(POLICER_BUCKET);
            }
            let pass = tokens >= 1200.0;
            if pass {
                tokens -= 1200.0;
            }
            let tx = T0 + 200 * MS + k * gap;
            P {
                flow,
                seq: k,
                size: 1200,
                tx,
                rx: pass.then_some(tx + lag + DELAY),
            }
        })
        .collect()
}

#[derive(Clone)]
struct Fixture {
    /// Rows of `netstack[a].udp_fullsock` (macOS receiver of b → a).
    fullsock: Vec<Option<u64>>,
    /// META `endpoints.a.iface.tunnel`.
    tunnel_a: bool,
    /// `iface_change` events at a: (ms after T0, tunnel after the change).
    changes_a: Vec<(u64, bool)>,
    /// A Linux initiator instead (kernel TX stamps, rxq_drops, qdisc, ICMP errors).
    linux_a: bool,
    /// META without the PTF 1.2 keys (`os_family`, `icmp_errors`).
    pre_1_2: bool,
    /// A P7 `udp/high-port` saturation (flow 16) through a token-bucket policer.
    policed_class: bool,
}

impl Default for Fixture {
    fn default() -> Self {
        Fixture {
            fullsock: vec![Some(17), Some(17), Some(17)],
            tunnel_a: false,
            changes_a: Vec::new(),
            linux_a: false,
            pre_1_2: false,
            policed_class: false,
        }
    }
}

fn tunnel() -> Value {
    Value::map()
        .with("kind", "utun")
        .with("provider", "tailscale")
}

fn endpoint(fx: &Fixture, linux: bool, name: &str, mtu: u64, tunnel_on: bool) -> Value {
    let mut sock = Value::map()
        .with("name", "main")
        .with("kernel_rx", true)
        .with("kernel_tx", linux)
        .with("rxq_ovfl", linux)
        .with("tx_ids", if linux { "explicit" } else { "none" });
    let mut iface = Value::map().with("name", name).with("mtu", mtu);
    if tunnel_on {
        iface = iface.with("tunnel", tunnel());
    }
    let mut e = Value::map().with("iface", iface);
    if !fx.pre_1_2 {
        sock = sock.with("icmp_errors", linux);
        e = e.with("os_family", if linux { "linux" } else { "darwin" });
    }
    e.with("sockets", Value::Array(vec![sock]))
}

fn flow(id: u64, kind: &str) -> Value {
    Value::map()
        .with("id", id)
        .with("kind", kind)
        .with("sock", "main")
}

fn event(ep: &str, t: u64, kind: &str, detail: Value) -> Value {
    Value::map()
        .with("t", t)
        .with("clock", format!("{ep}.mono"))
        .with("endpoint", ep)
        .with("type", kind)
        .with("detail", detail)
}

fn trace(fx: &Fixture) -> PtfFile {
    let linux_a = fx.linux_a;
    let meta = section(
        b"META",
        Value::map()
            .with("kind", "trace")
            .with("redaction", "full")
            .with(
                "session",
                Value::map().with("a", Value::map().with("t0_mono", T0)),
            )
            .with(
                "endpoints",
                Value::map()
                    .with("a", endpoint(fx, linux_a, "utun4", 1280, fx.tunnel_a))
                    .with("b", endpoint(fx, true, "eth0", 1500, false)),
            ),
    );
    let meta = Section::new(b"META", flags::CRITICAL, meta.head().cloned().unwrap());
    let mut flow_defs = vec![
        flow(1, "light"),
        flow(2, "light"),
        flow(11, "class"),
        flow(12, "class"),
        flow(13, "class"),
        flow(30, "pmtu"),
        flow(31, "pmtu"),
    ];
    if fx.policed_class {
        flow_defs.push(flow(16, "class-sat"));
    }
    let flows = section(b"FLOW", Value::map().with("flows", Value::Array(flow_defs)));
    // a → b: the macOS sender's user-space times; the class probes 11 and 13 are sent too.
    let mut ab = direction(1, 30, !linux_a);
    for (flow, seq) in [(11u64, 0u64), (13, 0), (13, 1)] {
        let tx = T0 + 100 * MS + seq * MS;
        ab.push(P {
            flow,
            seq,
            size: 200,
            tx,
            rx: Some(tx + DELAY),
        });
    }
    if fx.policed_class {
        ab.extend(policed(16, if linux_a { 3_000 } else { USER_LAG as u64 }));
    }
    let ba = direction(2, 31, false);
    // Echoes at a: 13 twice (transmit times known), 12 once without a transmitted row (its
    // transmit time is unknown), 11 never.
    let echo_rx = |seq: u64| T0 + 100 * MS + seq * MS + 2 * DELAY + USER_LAG as u64;
    let echo = Table::new("echo", 3)
        .with(u("flow", vec![13, 13, 12]))
        .with(u("seq", vec![0, 1, 0]))
        .with(u("rx", vec![echo_rx(0), echo_rx(1), echo_rx(0)]))
        .with_attrs(Value::map().with("endpoint", "a"));
    let pairs = |ep: &str| {
        let m: Vec<u64> = (0..=4).map(|k| T0 + k * 1_000 * MS).collect();
        Table::new("pairs", m.len())
            .with(u("mono", m.clone()))
            .with(u("real", m.clone()))
            .with(u("width", vec![30; m.len()]))
            .with_attrs(Value::map().with("endpoint", ep))
    };
    // Symmetric exchanges, offset 0.
    let ex: Vec<u64> = (0..8).map(|k| T0 + k * 100 * MS).collect();
    let exchange = Table::new("exchange", ex.len())
        .with(u("t1", ex.clone()))
        .with(u("t2", ex.iter().map(|t| t + MS / 2).collect()))
        .with(u("t3", ex.iter().map(|t| t + MS * 6 / 10).collect()))
        .with(u("t4", ex.iter().map(|t| t + MS * 11 / 10).collect()))
        .with_attrs(Value::map().with("endpoint", "a"));
    let n = fx.fullsock.len();
    let st: Vec<u64> = (0..n as u64).map(|k| T0 + k * 1_000 * MS).collect();
    let netstack = |ep: &str, fullsock: &[Option<u64>], linux: bool| {
        Table::new("netstack", fullsock.len())
            .with(u("t", st[..fullsock.len()].to_vec()))
            .with(nu(
                "udp_rcvbuf_errors",
                &vec![linux.then_some(4); fullsock.len()],
            ))
            .with(nu("udp_fullsock", fullsock))
            .with_attrs(Value::map().with("endpoint", ep))
    };
    let qdisc = |ep: &str| {
        Table::new("qdisc", 2)
            .with(u("t", vec![T0, T0 + 1_000 * MS]))
            .with(nu("drops", &[Some(3), Some(5)]))
            .with_attrs(Value::map().with("endpoint", ep))
    };
    let mut events = vec![event(
        "a",
        T0,
        "phase_start",
        Value::map().with("phase", 2u64),
    )];
    for (ms, on) in &fx.changes_a {
        let mut iface = Value::map().with("mtu", if *on { 1280u64 } else { 1500 });
        if *on {
            iface = iface.with("tunnel", tunnel());
        }
        events.push(event(
            "a",
            T0 + ms * MS,
            "iface_change",
            Value::map().with("iface", iface),
        ));
    }
    let mut s = vec![
        meta,
        flows,
        tables(b"OBSV", pkt("a_to_b", &ab, linux_a, true)),
        tables(b"OBSV", pkt("b_to_a", &ba, true, linux_a)),
        tables(b"OBSV", echo),
        tables(b"CLOK", pairs("a")),
        tables(b"CLOK", pairs("b")),
        tables(b"CLOK", exchange),
        tables(b"CTXS", netstack("b", &[None, None], true)),
        tables(b"CTXS", qdisc("b")),
        section(b"EVNT", Value::map().with("events", Value::Array(events))),
    ];
    if linux_a {
        s.push(tables(b"CTXS", qdisc("a")));
        s.push(tables(b"CTXS", netstack("a", &vec![None; n.max(1)], true)));
    } else {
        s.push(tables(b"CTXS", netstack("a", &fx.fullsock, false)));
    }
    PtfFile {
        major: 1,
        minor: 2,
        sections: s,
    }
}

fn derived(fx: &Fixture) -> (Value, Value) {
    let out = pt_derive::derive(&trace(fx), &tool());
    let get = |k: &[u8; 4]| {
        Value::Map(
            out.iter()
                .find(|s| &s.kind == k)
                .and_then(Section::head)
                .cloned()
                .unwrap(),
        )
    };
    (get(b"PATH"), get(b"PLCY"))
}

fn dirf<'a>(path: &'a Value, dir: &str, field: &str) -> &'a Value {
    path.get("directions")
        .and_then(|d| d.get(dir))
        .and_then(|d| d.get(field))
        .unwrap_or_else(|| panic!("{dir}.{field}"))
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn num(v: &Value, k: &str) -> Option<f64> {
    match v.get(k)? {
        Value::Float(f) => Some(*f),
        other => other.as_u64().map(|x| x as f64),
    }
}

/// probe.md §9.2: every a → b packet's transmit time is user-space, and delay and loss are
/// derived from it; b → a keeps the responder's kernel stamps.
#[test]
fn user_transmit_times_drive_delay_and_loss() {
    let (path, _) = derived(&Fixture::default());
    let counts = dirf(&path, "a_to_b", "timestamps").get("counts").unwrap();
    let n = LIGHT + 4 + 3;
    assert_eq!(counts.get("user").and_then(Value::as_u64), Some(n));
    assert!(counts.get("snd").is_none() && counts.get("sched").is_none());
    let back = dirf(&path, "b_to_a", "timestamps").get("counts").unwrap();
    assert_eq!(back.get("snd").and_then(Value::as_u64), Some(LIGHT + 4));
    let base = dirf(&path, "a_to_b", "base_delay");
    assert_eq!(s(base, "status"), Some("known"));
    assert_eq!(num(base, "delay_ns"), Some(DELAY as f64));
    let loss = dirf(&path, "a_to_b", "loss");
    assert_eq!(s(loss, "status"), Some("known"));
    assert_eq!(num(loss, "rate"), Some(10.0 / LIGHT as f64));
}

/// probe.md §9.6: the receiver a has no `rxq_drops`; a flat `udp_fullsock` proves no drops.
#[test]
fn flat_fullsock_is_known_zero() {
    let (path, _) = derived(&Fixture::default());
    let h = dirf(&path, "b_to_a", "host_drops");
    assert_eq!(s(h, "status"), Some("known"));
    assert_eq!(s(h, "method"), Some("hostdrop.host-fullsock/1"));
    assert_eq!(h.get("packets").and_then(Value::as_u64), Some(0));
    // The Linux receiver b keeps the per-socket rule.
    let h = dirf(&path, "a_to_b", "host_drops");
    assert_eq!(s(h, "method"), Some("hostdrop.rxq-gap/1"));
    assert_eq!(s(h, "status"), Some("known"));
}

#[test]
fn rising_fullsock_is_unknown_with_context() {
    let fx = Fixture {
        fullsock: vec![Some(17), Some(17), Some(20)],
        ..Fixture::default()
    };
    let (path, _) = derived(&fx);
    let h = dirf(&path, "b_to_a", "host_drops");
    assert_eq!(s(h, "status"), Some("unknown"));
    assert_eq!(s(h, "reason"), Some("host-wide counter rose"));
    assert_eq!(h.get("host_socket_drops").and_then(Value::as_u64), Some(3));
    assert!(h.get("packets").is_none());
}

/// The host-wide counter is not segmented at an interface change: a rise across one is a rise.
#[test]
fn fullsock_rising_across_an_iface_change_is_unknown() {
    let fx = Fixture {
        fullsock: vec![Some(17), Some(17), Some(18)],
        changes_a: vec![(1_500, false)],
        ..Fixture::default()
    };
    let (path, _) = derived(&fx);
    let h = dirf(&path, "b_to_a", "host_drops");
    assert_eq!(s(h, "status"), Some("unknown"));
    assert_eq!(s(h, "reason"), Some("host-wide counter rose"));
}

#[test]
fn decreasing_fullsock_is_unknown() {
    let fx = Fixture {
        fullsock: vec![Some(17), Some(2), Some(2)],
        ..Fixture::default()
    };
    let (path, _) = derived(&fx);
    let h = dirf(&path, "b_to_a", "host_drops");
    assert_eq!(s(h, "status"), Some("unknown"));
    assert_eq!(s(h, "reason"), Some("host-wide counter decreased"));
    assert!(h.get("host_socket_drops").is_none());
}

/// No counter at all: exactly the `hostdrop.rxq-gap/1` output, reason text included.
#[test]
fn no_counter_is_the_rxq_gap_unknown() {
    let fx = Fixture {
        fullsock: vec![None, None],
        ..Fixture::default()
    };
    let (path, _) = derived(&fx);
    let h = dirf(&path, "b_to_a", "host_drops");
    assert_eq!(s(h, "status"), Some("unknown"));
    assert_eq!(s(h, "method"), Some("hostdrop.rxq-gap/1"));
    assert_eq!(s(h, "reason"), Some("no rxq_drops in this trace (PTF 1.0)"));
}

/// A macOS sender has no qdisc: unknown with a reason and no counts; the Linux sender's known.
#[test]
fn no_qdisc_table_is_unknown() {
    let (path, _) = derived(&Fixture::default());
    let q = dirf(&path, "a_to_b", "local_qdisc_drops");
    assert_eq!(s(q, "status"), Some("unknown"));
    assert_eq!(s(q, "reason"), Some("no qdisc counters recorded"));
    assert!(q.get("drops").is_none());
    let q = dirf(&path, "b_to_a", "local_qdisc_drops");
    assert_eq!(s(q, "status"), Some("known"));
    assert_eq!(q.get("drops").and_then(Value::as_u64), Some(2));
}

/// probe.md §9.5: the macOS sender cannot see ICMP errors, so the larger lost sizes are not a
/// black hole; the Linux sender's are.
#[test]
fn blackhole_unknown_without_icmp_errors() {
    let (path, _) = derived(&Fixture::default());
    let m = dirf(&path, "a_to_b", "mtu");
    assert_eq!(s(m, "method"), Some("mtu.ladder/2"));
    assert_eq!(m.get("path_mtu").and_then(Value::as_u64), Some(1280));
    assert_eq!(m.get("blackhole"), Some(&Value::Null));
    let m = dirf(&path, "b_to_a", "mtu");
    assert_eq!(m.get("blackhole").and_then(Value::as_bool), Some(true));
    // A Linux initiator keeps the verdict, as does a trace without the 1.2 key.
    for fx in [
        Fixture {
            linux_a: true,
            ..Fixture::default()
        },
        Fixture {
            pre_1_2: true,
            ..Fixture::default()
        },
    ] {
        let (path, _) = derived(&fx);
        let m = dirf(&path, "a_to_b", "mtu");
        assert_eq!(m.get("blackhole").and_then(Value::as_bool), Some(true));
    }
}

/// `policy.matrix/2`: a UDP class is reachable when an echo arrived, with user-space transmit
/// times (`/1` read only `tx_sched` and reported every class unreachable here).
#[test]
fn udp_classes_reachable_without_tx_stamps() {
    let (_, plcy) = derived(&Fixture::default());
    assert_eq!(s(&plcy, "method"), Some("policy.matrix/2"));
    let class = |c: &str| plcy.get("classes").and_then(|v| v.get(c)).unwrap();
    let hp = class("udp/high-port");
    assert_eq!(hp.get("reachable").and_then(Value::as_bool), Some(true));
    assert_eq!(hp.get("echoes").and_then(Value::as_u64), Some(2));
    let rtt = num(hp, "rtt_min_ns").unwrap();
    assert_eq!(rtt, (2 * DELAY) as f64);
    // An echo whose transmit time is unknown still proves reachability.
    let q = class("udp/443-quic");
    assert_eq!(q.get("reachable").and_then(Value::as_bool), Some(true));
    assert_eq!(q.get("rtt_min_ns"), Some(&Value::Null));
    let none = class("udp/443");
    assert_eq!(none.get("reachable").and_then(Value::as_bool), Some(false));
}

/// `policer.class-lossy-flat/1`: a policed `udp/high-port` saturation from a macOS initiator
/// (user-space transmit times) gets its own policer verdict on its PLCY entry; the classes
/// P7 did not saturate are unknown, not undetected.
#[test]
fn policed_class_has_its_own_policer_verdict() {
    let (path, plcy) = derived(&Fixture {
        policed_class: true,
        ..Fixture::default()
    });
    let class = |c: &str| {
        plcy.get("classes")
            .and_then(|v| v.get(c))
            .and_then(|v| v.get("policer"))
            .unwrap()
    };
    let hp = class("udp/high-port");
    assert_eq!(s(hp, "method"), Some("policer.class-lossy-flat/1"));
    assert_eq!(s(hp, "status"), Some("estimated"));
    assert_eq!(s(hp, "scope"), Some("class"));
    assert_eq!(hp.get("detected").and_then(Value::as_bool), Some(true));
    assert!(num(hp, "depth_time_ns").unwrap() < 2e6);
    let r = num(hp, "rate_bps").unwrap();
    assert!((r / POLICER_BPS - 1.0).abs() < 0.01, "{r}");
    let b = num(hp, "burst_bytes").unwrap();
    assert!((b - POLICER_BUCKET).abs() <= 1200.0, "{b}");
    for c in ["udp/443", "udp/443-quic"] {
        let v = class(c);
        assert_eq!(s(v, "status"), Some("unknown"), "{c}");
        assert_eq!(v.get("detected"), Some(&Value::Null), "{c}");
        assert_eq!(s(v, "reason"), Some("no class saturation"), "{c}");
    }
    let methods = path
        .get("derivation")
        .and_then(|d| d.get("methods"))
        .and_then(Value::as_array)
        .unwrap();
    assert!(methods.contains(&Value::from("policer.class-lossy-flat/1")));
}

/// probe.md §9.9: through a tunnel, the five verdict groups are flagged and no others.
#[test]
fn overlay_flags_the_tunnel_verdicts() {
    let fx = Fixture {
        tunnel_a: true,
        changes_a: vec![(1_000, false), (3_000, true)],
        ..Fixture::default()
    };
    let (path, plcy) = derived(&fx);
    let o = path.get("overlay").unwrap();
    assert_eq!(s(o, "status"), Some("known"));
    assert_eq!(s(o, "method"), Some("overlay.egress-iface/1"));
    assert_eq!(o.get("overlay").and_then(Value::as_bool), Some(true));
    assert_eq!(
        o.get("endpoints"),
        Some(&Value::Array(vec![Value::from("a")]))
    );
    assert_eq!(s(o, "kind"), Some("utun"));
    assert_eq!(s(o, "provider"), Some("tailscale"));
    assert_eq!(o.get("mtu").and_then(Value::as_u64), Some(1280));
    // a's pairs span 0..4 s: tunnelled 0..1 s and 3..4 s.
    assert_eq!(
        o.get("overlay_ns").and_then(Value::as_u64),
        Some(2_000 * MS)
    );
    for dir in ["a_to_b", "b_to_a"] {
        for f in ["policer", "mtu", "ecn", "dscp"] {
            let v = dirf(&path, dir, f);
            assert_eq!(
                v.get("overlay_limited").and_then(Value::as_bool),
                Some(true),
                "{dir}.{f}"
            );
        }
        for f in [
            "capacity",
            "base_delay",
            "jitter",
            "loss",
            "reorder",
            "queue",
            "host_drops",
        ] {
            if let Some(v) = path
                .get("directions")
                .and_then(|d| d.get(dir))
                .and_then(|d| d.get(f))
            {
                assert!(v.get("overlay_limited").is_none(), "{dir}.{f}");
            }
        }
    }
    for (c, v) in plcy.get("classes").and_then(Value::as_map).unwrap() {
        assert_eq!(
            v.get("overlay_limited").and_then(Value::as_bool),
            Some(true),
            "{}",
            c.0
        );
    }
}

#[test]
fn no_tunnel_is_known_false() {
    let (path, plcy) = derived(&Fixture::default());
    let o = path.get("overlay").unwrap();
    assert_eq!(s(o, "status"), Some("known"));
    assert_eq!(o.get("overlay").and_then(Value::as_bool), Some(false));
    assert_eq!(o.get("overlay_ns").and_then(Value::as_u64), Some(0));
    assert!(
        dirf(&path, "a_to_b", "mtu")
            .get("overlay_limited")
            .is_none()
    );
    for v in plcy
        .get("classes")
        .and_then(Value::as_map)
        .unwrap()
        .values()
    {
        assert!(v.get("overlay_limited").is_none());
    }
    // Without the 1.2 facts the absence of `tunnel` is not evidence.
    let (path, _) = derived(&Fixture {
        pre_1_2: true,
        ..Fixture::default()
    });
    let o = path.get("overlay").unwrap();
    assert_eq!(s(o, "status"), Some("unknown"));
    assert_eq!(o.get("overlay"), Some(&Value::Null));
}

/// The redacted real Linux trace of the conformance corpus derives with the same values: only
/// method versions, the qdisc reason and the overlay field are new.
#[test]
fn linux_golden_trace_keeps_its_values() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/v1.0-real/smoke-ipv6-netns-anonymous.ptf"
    ))
    .unwrap();
    let (f, _) = pt_format::read(&bytes, pt_format::ReadOptions::default()).unwrap();
    let out = pt_derive::derive(&f, &tool());
    let head = |k: &[u8; 4]| {
        Value::Map(
            out.iter()
                .find(|s| &s.kind == k)
                .unwrap()
                .head()
                .cloned()
                .unwrap(),
        )
    };
    let (path, plcy) = (head(b"PATH"), head(b"PLCY"));
    for dir in ["a_to_b", "b_to_a"] {
        let m = dirf(&path, dir, "mtu");
        assert!(
            m.get("blackhole").and_then(Value::as_bool).is_some(),
            "{dir}"
        );
        assert!(m.get("overlay_limited").is_none());
        let h = dirf(&path, dir, "host_drops");
        assert_eq!(s(h, "reason"), Some("no rxq_drops in this trace (PTF 1.0)"));
    }
    for (c, v) in plcy.get("classes").and_then(Value::as_map).unwrap() {
        if s(v, "transport") == Some("udp") {
            assert_eq!(
                v.get("reachable").and_then(Value::as_bool),
                Some(true),
                "{}",
                c.0
            );
        }
    }
}
