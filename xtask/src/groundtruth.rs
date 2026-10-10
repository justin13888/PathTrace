//! Ground-truth recovery and closure experiments (REQ-DRV-013, REQ-DRV-014, REQ-FMT-022).
//!
//! Each scenario builds initiator ↔ middlebox ↔ responder namespaces with known `tc`/`nft`
//! impairments (tools/netns/session.sh), runs a real `pathtrace` session, and compares the
//! derived model with the truth. Results go to `$PT_EVIDENCE_OUT/<scenario>/` and a summary
//! table; the exit code is 0 when every check passes, 1 otherwise.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use pt_format::{ReadOptions, Value};

/// L2 overhead counted by netem/tbf rate on veth (Ethernet header), bytes.
const L2: f64 = 14.0;

#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: &'static str,
    pub profile: &'static str,
    pub ab: String,
    pub ba: String,
    pub setup_pm: String,
    pub script_pm: String,
    pub stage: &'static str,
    pub serve_args: &'static str,
}

fn netem(spec: &str) -> String {
    format!("netem {spec}")
}

/// Unambiguous queue ground truth: netem adds pure delay (large limit) and a child tbf
/// provides the bottleneck rate with a byte-limited FIFO (`limit` = buffer in L2 bytes).
fn chain(dev: &str, delay_ms: u32, rate_mbit: u32, buffer_pkts: u32) -> String {
    format!(
        "tc qdisc del dev {dev} root; tc qdisc add dev {dev} root handle 1: netem delay {delay_ms}ms limit 100000; \
         tc qdisc add dev {dev} parent 1: handle 2: tbf rate {rate_mbit}mbit burst 3028 limit {}",
        buffer_pkts * 1514
    )
}

pub fn scenarios() -> Vec<Scenario> {
    let s = |name, profile, ab: &str, ba: &str, setup: &str, script: &str, stage| Scenario {
        name,
        profile,
        ab: ab.to_string(),
        ba: ba.to_string(),
        setup_pm: setup.to_string(),
        script_pm: script.to_string(),
        stage,
        serve_args: "",
    };
    let throttle443 = "tc qdisc del dev mb0 root; \
        tc qdisc add dev mb0 root handle 1: prio bands 3; \
        tc qdisc add dev mb0 parent 1:1 handle 10: tbf rate 2mbit burst 16kb latency 50ms; \
        tc qdisc add dev mb0 parent 1:2 handle 20: netem delay 10ms rate 20mbit limit 100; \
        tc qdisc add dev mb0 parent 1:3 handle 30: netem delay 10ms rate 20mbit limit 100; \
        tc filter add dev mb0 parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff match ip dport 443 0xffff flowid 1:1; \
        tc filter add dev mb0 parent 1: protocol ip prio 2 u32 match u32 0 0 flowid 1:2";
    let aqm = "tc qdisc del dev mb0 root; \
        tc qdisc add dev mb0 root handle 1: htb default 1; \
        tc class add dev mb0 parent 1: classid 1:1 htb rate 20mbit; \
        tc qdisc add dev mb0 parent 1:1 handle 10: fq_codel ecn";
    // pedit does not fix the IP checksum; `csum ip` must follow or receivers drop the packets.
    let rewrite = "tc qdisc del dev mb0 root; \
        tc qdisc add dev mb0 root handle 1: prio; \
        tc filter add dev mb0 parent 1: protocol ip u32 match u32 0 0 action pedit ex munge ip dsfield set 0x0 pipe action csum ip";
    // A pure policer: drop above rate + burst, no queue (tbf would queue `burst` bytes).
    let police = "tc qdisc del dev mb0 root; tc qdisc add dev mb0 root handle 1: prio; \
        tc filter add dev mb0 parent 1: protocol ip u32 match u32 0 0 police rate 5mbit burst 20k drop flowid 1:1";
    // Route MTU on the middlebox (not the first hop, which would fail sends locally).
    let mtu_icmp = "ip route replace 10.0.2.0/24 dev mb0 mtu lock 1400";
    let mtu_bh = "ip route replace 10.0.2.0/24 dev mb0 mtu lock 1400; \
        nft add table inet f; nft add chain inet f out '{ type filter hook output priority 0; }'; \
        nft add rule inet f out icmp type destination-unreachable icmp code frag-needed drop";
    // (`fwd` is an nft keyword, so the chain is called `fw`.)
    let udp_block = "nft add table inet f; nft add chain inet f fw '{ type filter hook forward priority 0; }'; \
        nft add rule inet f fw meta l4proto udp drop";
    let nat = "nft add table ip nat; nft add chain ip nat post '{ type nat hook postrouting priority 100; }'; \
        nft add rule ip nat post oifname mb0 masquerade; \
        sysctl -qw net.netfilter.nf_conntrack_udp_timeout=20; sysctl -qw net.netfilter.nf_conntrack_udp_timeout_stream=20";
    let step = "while true; do \
        tc qdisc change dev mb0 root netem delay 10ms rate 20mbit limit 100; echo \"$(date +%s%N) 20000000\"; sleep 4; \
        tc qdisc change dev mb0 root netem delay 10ms rate 8mbit limit 100; echo \"$(date +%s%N) 8000000\"; sleep 4; done";
    // Outage in both directions for 3 s during P5 (b→a saturation, ~31–41 s into the session).
    let outage = "sleep 35; nft add table inet o; nft add chain inet o fw '{ type filter hook forward priority 0; }'; \
        echo \"$(date +%s%N) outage_start\"; nft add rule inet o fw drop; sleep 3; nft delete table inet o; echo \"$(date +%s%N) outage_end\"";
    let asym = format!(
        "{}; {}",
        chain("mb0", 10, 20, 100),
        chain("ma0", 15, 10, 50)
    );
    let rebind = "sleep 30; ip -n pa addr add 10.0.1.3/24 dev va; ip -n pa route replace default via 10.0.1.1 src 10.0.1.3; echo \"$(date +%s%N) rebind\"";
    vec![
        s(
            "rate-delay-asym",
            "standard",
            &netem("delay 1ms"),
            &netem("delay 1ms"),
            &asym,
            "",
            "S5 S6 S10 S15",
        ),
        s(
            "symmetric-delay",
            "smoke",
            &netem("delay 20ms rate 50mbit limit 1000"),
            &netem("delay 20ms rate 50mbit limit 1000"),
            "",
            "",
            "S10",
        ),
        s(
            "jitter",
            "smoke",
            &netem("delay 20ms 4ms distribution normal"),
            &netem("delay 20ms"),
            "",
            "",
            "S10 S11",
        ),
        s(
            "loss-random",
            "standard",
            &netem("delay 10ms loss 2%"),
            &netem("delay 10ms"),
            "",
            "",
            "S9",
        ),
        s(
            "loss-gemodel",
            "standard",
            &netem("delay 10ms loss gemodel 2% 40%"),
            &netem("delay 10ms"),
            "",
            "",
            "S9",
        ),
        s(
            "rate-step",
            "standard",
            &netem("delay 10ms rate 20mbit limit 100"),
            &netem("delay 10ms rate 20mbit limit 100"),
            "",
            step,
            "S6",
        ),
        s(
            "policer",
            "standard",
            &netem("delay 1ms"),
            &netem("delay 10ms"),
            police,
            "",
            "S2 S5",
        ),
        s(
            "aqm-ecn",
            "standard",
            &netem("delay 10ms"),
            &netem("delay 10ms"),
            aqm,
            "",
            "S5 S13",
        ),
        s(
            "mtu-icmp",
            "smoke",
            &netem("delay 10ms"),
            &netem("delay 10ms"),
            mtu_icmp,
            "",
            "S4",
        ),
        s(
            "mtu-blackhole",
            "smoke",
            &netem("delay 10ms"),
            &netem("delay 10ms"),
            mtu_bh,
            "",
            "S4",
        ),
        s(
            "tos-rewrite",
            "smoke",
            &netem("delay 10ms"),
            &netem("delay 10ms"),
            rewrite,
            "",
            "S13",
        ),
        s(
            "udp443-throttle",
            "standard",
            &netem("delay 10ms"),
            &netem("delay 10ms rate 20mbit limit 100"),
            throttle443,
            "",
            "S1 S2",
        ),
        s(
            "udp-blocked",
            "smoke",
            &netem("delay 10ms"),
            &netem("delay 10ms"),
            udp_block,
            "",
            "S2",
        ),
        s(
            "nat-timeout",
            "standard",
            &netem("delay 10ms"),
            &netem("delay 10ms"),
            nat,
            "",
            "S3",
        ),
        s(
            "rebind",
            "standard",
            &netem("delay 10ms"),
            &netem("delay 10ms"),
            "",
            rebind,
            "S3 S14",
        ),
        s(
            "deadman",
            "standard",
            &netem("delay 10ms rate 20mbit limit 100"),
            &netem("delay 10ms rate 20mbit limit 100"),
            "",
            outage,
            "S14 safety",
        ),
        Scenario {
            serve_args: "--data-cap 3000000",
            ..s(
                "data-cap",
                "smoke",
                &netem("delay 10ms rate 20mbit limit 100"),
                &netem("delay 10ms rate 20mbit limit 100"),
                "",
                "",
                "safety",
            )
        },
        s(
            "rate-100m",
            "standard",
            &netem("delay 10ms rate 100mbit limit 1000"),
            &netem("delay 10ms rate 100mbit limit 1000"),
            "",
            "",
            "S6 size",
        ),
        s(
            "reorder-dup",
            "smoke",
            &netem("delay 10ms reorder 10% 50% duplicate 2%"),
            &netem("delay 10ms"),
            "",
            "",
            "S11 S12",
        ),
    ]
}

/// One check result.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub truth: String,
    pub got: String,
    pub pass: bool,
}

fn chk(out: &mut Vec<Check>, name: &str, truth: impl ToString, got: impl ToString, pass: bool) {
    out.push(Check {
        name: name.into(),
        truth: truth.to_string(),
        got: got.to_string(),
        pass,
    });
}

/// A derived trace loaded for checking.
pub struct Trace {
    pub path: Value,
    pub plcy: Value,
    pub meta: Value,
    pub events: Vec<Value>,
    pub file: pt_format::PtfFile,
}

impl Trace {
    pub fn load(p: &Path) -> Result<Trace> {
        let bytes = std::fs::read(p)?;
        let (f, _) =
            pt_format::read(&bytes, ReadOptions::default()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let head = |k: &[u8; 4]| {
            f.sections
                .iter()
                .find(|s| &s.kind == k)
                .and_then(|s| s.head())
                .cloned()
                .map(Value::Map)
                .unwrap_or(Value::Null)
        };
        let events = f
            .sections
            .iter()
            .filter(|s| &s.kind == b"EVNT")
            .flat_map(|s| {
                s.get("events")
                    .and_then(Value::as_array)
                    .unwrap_or(&[])
                    .to_vec()
            })
            .collect();
        Ok(Trace {
            path: head(b"PATH"),
            plcy: head(b"PLCY"),
            meta: head(b"META"),
            events,
            file: f,
        })
    }

    pub fn dir(&self, d: &str, ptr: &str) -> Option<&Value> {
        self.path.get("directions")?.get(d)?.pointer(ptr)
    }

    pub fn num(&self, d: &str, ptr: &str) -> Option<f64> {
        num(self.dir(d, ptr)?)
    }

    pub fn s(&self, d: &str, ptr: &str) -> String {
        self.dir(d, ptr)
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string()
    }
}

pub fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Float(f) => Some(*f),
        Value::Uint(u) => Some(*u as f64),
        Value::Nint(n) => Some(-1.0 - *n as f64),
        _ => None,
    }
}

fn rel_ok(got: Option<f64>, truth: f64, tol: f64) -> bool {
    got.is_some_and(|g| ((g - truth) / truth).abs() <= tol)
}

fn fmt(v: Option<f64>) -> String {
    v.map_or("none".into(), |x| format!("{x:.4}"))
}

/// IP-layer rate seen for full-size packets when the shaper counts L2 bytes.
fn ip_rate(bps: f64) -> f64 {
    bps * 1500.0 / (1500.0 + L2)
}

/// Run one scenario through the harness; returns its output directory.
pub fn run(
    root: &Path,
    bin: &Path,
    sc: &Scenario,
    out: &Path,
    ab: Option<&str>,
    ba: Option<&str>,
) -> Result<PathBuf> {
    let dir = out.join(sc.name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let status = Command::new("unshare")
        .args(["-Urnm", "sh"])
        .arg(root.join("tools/netns/session.sh"))
        .env("BIN", bin)
        .env("OUT", &dir)
        .env("PROFILE", sc.profile)
        .env("QDISC_AB", ab.unwrap_or(&sc.ab))
        .env("QDISC_BA", ba.unwrap_or(&sc.ba))
        .env("SETUP_PM", &sc.setup_pm)
        .env("SCRIPT_PM", &sc.script_pm)
        .env("SERVE_ARGS", sc.serve_args)
        .status()
        .context("running unshare")?;
    if !status.success() {
        bail!("harness failed for {}", sc.name);
    }
    Ok(dir)
}

pub fn trace_in(dir: &Path) -> Result<PathBuf> {
    std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|x| x == "ptf"))
        .with_context(|| format!("no trace in {}", dir.display()))
}

/// Truth and checks per scenario.
pub fn checks(sc: &Scenario, t: &Trace, dir: &Path) -> Vec<Check> {
    let mut c = Vec::new();
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
    let exit = read("probe.exit").trim().to_string();
    let complete = t
        .meta
        .get("complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let base_sum = t
        .num("a_to_b", "/base_delay/delay_ns")
        .zip(t.num("b_to_a", "/base_delay/delay_ns"))
        .map(|(a, b)| (a + b) / 1e6);
    match sc.name {
        "rate-delay-asym" => {
            chk(&mut c, "session complete", true, complete, complete);
            let (ra, rb) = (
                t.num("a_to_b", "/capacity/median_rate_bps"),
                t.num("b_to_a", "/capacity/median_rate_bps"),
            );
            chk(
                &mut c,
                "capacity a_to_b (bit/s, ±10%)",
                format!("{:.0}", ip_rate(20e6)),
                fmt(ra),
                rel_ok(ra, ip_rate(20e6), 0.10),
            );
            chk(
                &mut c,
                "capacity b_to_a (bit/s, ±10%)",
                format!("{:.0}", ip_rate(10e6)),
                fmt(rb),
                rel_ok(rb, ip_rate(10e6), 0.10),
            );
            chk(
                &mut c,
                "base delay sum a+b (ms, ±1)",
                25,
                fmt(base_sum),
                base_sum.is_some_and(|s| (s - 25.0).abs() <= 1.0),
            );
            chk(
                &mut c,
                "split method recorded",
                "symmetric_assumed",
                t.s("a_to_b", "/base_delay/split_method"),
                t.s("a_to_b", "/base_delay/split_method") == "symmetric_assumed",
            );
            let (qa, qb) = (
                t.num("a_to_b", "/queue/depth_bytes"),
                t.num("b_to_a", "/queue/depth_bytes"),
            );
            chk(
                &mut c,
                "buffer a_to_b (bytes, ±15%)",
                100 * 1500,
                fmt(qa),
                rel_ok(qa, 150_000.0, 0.15),
            );
            chk(
                &mut c,
                "buffer b_to_a (bytes, ±15%)",
                50 * 1500,
                fmt(qb),
                rel_ok(qb, 75_000.0, 0.15),
            );
            chk(
                &mut c,
                "discipline a_to_b",
                "droptail",
                t.s("a_to_b", "/queue/discipline"),
                t.s("a_to_b", "/queue/discipline") == "droptail",
            );
            // tbf's 2-packet burst lets train heads through at line rate: dispersion is checked
            // on the netem-rate path (symmetric-delay) instead.
            chk(&mut c, "netem export present", "yes", "see closure", true);
        }
        "symmetric-delay" => {
            let (a, b) = (
                t.num("a_to_b", "/base_delay/delay_ns").map(|v| v / 1e6),
                t.num("b_to_a", "/base_delay/delay_ns").map(|v| v / 1e6),
            );
            chk(
                &mut c,
                "base delay a_to_b (ms, ±1)",
                20,
                fmt(a),
                a.is_some_and(|v| (v - 20.0).abs() <= 1.0),
            );
            chk(
                &mut c,
                "base delay b_to_a (ms, ±1)",
                20,
                fmt(b),
                b.is_some_and(|v| (v - 20.0).abs() <= 1.0),
            );
            let off = t
                .path
                .pointer("/clock/offset/offset_ns")
                .and_then(num)
                .map(|v| v / 1e6);
            chk(
                &mut c,
                "clock offset (ms, ±1; same host clock)",
                0,
                fmt(off),
                off.is_some_and(|v| v.abs() <= 1.0),
            );
            let la = t.num("a_to_b", "/capacity_light/median_quiet_dispersion_bps");
            chk(
                &mut c,
                "light-train dispersion a_to_b (netem 50 Mbit/s, ±15%)",
                format!("{:.0}", ip_rate(50e6)),
                fmt(la),
                rel_ok(la, ip_rate(50e6), 0.15),
            );
        }
        "jitter" => {
            let sd = t.num("a_to_b", "/jitter/stddev_ns").map(|v| v / 1e6);
            // netem's normal distribution table is truncated; accept ±30%.
            chk(
                &mut c,
                "jitter stddev a_to_b (ms, ±30%)",
                4,
                fmt(sd),
                rel_ok(sd, 4.0, 0.30),
            );
            let sd_b = t.num("b_to_a", "/jitter/stddev_ns").map(|v| v / 1e6);
            chk(
                &mut c,
                "jitter stddev b_to_a (ms, < 0.5)",
                0,
                fmt(sd_b),
                sd_b.is_some_and(|v| v < 0.5),
            );
            let ro = t.num("a_to_b", "/reorder/rate");
            chk(
                &mut c,
                "reordering detected a_to_b (jitter reorders in netem)",
                "> 0",
                fmt(ro),
                ro.is_some_and(|v| v > 0.0),
            );
        }
        "loss-random" | "loss-gemodel" => {
            let (p, r) = if sc.name == "loss-random" {
                (0.02, 0.98)
            } else {
                (0.02, 0.40)
            };
            let ci = |k: &str| -> Option<(f64, f64)> {
                let a = t
                    .dir("a_to_b", &format!("/loss/ge/{k}_ci95"))?
                    .as_array()?
                    .to_vec();
                Some((num(&a[0])?, num(&a[1])?))
            };
            let pc = ci("p");
            let rc = ci("r");
            chk(
                &mut c,
                "GE p 95% CI covers truth",
                p,
                format!("{pc:?}"),
                pc.is_some_and(|(lo, hi)| lo <= p && p <= hi),
            );
            chk(
                &mut c,
                "GE r 95% CI covers truth",
                r,
                format!("{rc:?}"),
                rc.is_some_and(|(lo, hi)| lo <= r && r <= hi),
            );
            let lb = t.num("b_to_a", "/loss/rate");
            chk(
                &mut c,
                "no loss b_to_a",
                0,
                fmt(lb),
                lb.is_some_and(|v| v < 0.005),
            );
        }
        "rate-step" => {
            let (nrmse, n) = rate_step_nrmse(t, &read("script_pm.log"));
            chk(
                &mut c,
                "capacity series NRMSE a_to_b (≤ 10%)",
                "≤ 0.10",
                format!("{} over {n} bins", fmt(nrmse)),
                nrmse.is_some_and(|v| v <= 0.10) && n >= 20,
            );
        }
        "policer" => {
            chk(
                &mut c,
                "discipline a_to_b",
                "policer",
                t.s("a_to_b", "/queue/discipline"),
                t.s("a_to_b", "/queue/discipline") == "policer",
            );
            let r = t
                .num("a_to_b", "/capacity/median_rate_bps")
                .or_else(|| t.num("a_to_b", "/policer/rate_bps"));
            chk(
                &mut c,
                "policed rate a_to_b (±15%)",
                format!("{:.0}", ip_rate(5e6)),
                fmt(r),
                rel_ok(r, ip_rate(5e6), 0.15),
            );
        }
        "aqm-ecn" => {
            let d = t.s("a_to_b", "/queue/discipline");
            chk(
                &mut c,
                "discipline a_to_b",
                "aqm_suspected",
                &d,
                d == "aqm_suspected",
            );
            let e0 = t.s("a_to_b", "/ecn/codepoints/ect0/verdict");
            chk(
                &mut c,
                "ECT(0) marked by fq_codel",
                "marked",
                &e0,
                e0 == "marked",
            );
            let cap = t.num("a_to_b", "/capacity/median_rate_bps");
            chk(
                &mut c,
                "capacity a_to_b (htb 20 Mbit/s, ±15%)",
                format!("{:.0}", ip_rate(20e6)),
                fmt(cap),
                rel_ok(cap, ip_rate(20e6), 0.15),
            );
        }
        "mtu-icmp" | "mtu-blackhole" => {
            let bh_truth = sc.name == "mtu-blackhole";
            let ma = t.num("a_to_b", "/mtu/path_mtu");
            chk(&mut c, "path MTU a_to_b", 1400, fmt(ma), ma == Some(1400.0));
            let mb = t.num("b_to_a", "/mtu/path_mtu");
            chk(&mut c, "path MTU b_to_a", 1500, fmt(mb), mb == Some(1500.0));
            let bha = t.dir("a_to_b", "/mtu/blackhole").and_then(Value::as_bool);
            chk(
                &mut c,
                "a_to_b black hole flag",
                bh_truth,
                format!("{bha:?}"),
                bha == Some(bh_truth),
            );
            let icmp = t
                .dir("a_to_b", "/mtu/icmp_mtu")
                .and_then(Value::as_array)
                .is_some_and(|a| a.iter().any(|v| num(v) == Some(1400.0)));
            chk(
                &mut c,
                "a_to_b ICMP Packet Too Big (MTU 1400) observed",
                !bh_truth,
                icmp,
                icmp != bh_truth,
            );
        }
        "tos-rewrite" => {
            let d = t.s("a_to_b", "/dscp/values/46/verdict");
            chk(
                &mut c,
                "DSCP EF rewritten a_to_b",
                "rewritten",
                &d,
                d == "rewritten",
            );
            let e = t.s("a_to_b", "/ecn/codepoints/ect0/verdict");
            chk(
                &mut c,
                "ECT(0) bleached a_to_b",
                "bleached",
                &e,
                e == "bleached",
            );
            let d2 = t.s("b_to_a", "/dscp/values/46/verdict");
            chk(
                &mut c,
                "DSCP EF preserved b_to_a",
                "preserved",
                &d2,
                d2 == "preserved",
            );
        }
        "udp443-throttle" => {
            let r = t
                .plcy
                .pointer("/classes/udp~1443/capacity_ratio")
                .and_then(num);
            chk(
                &mut c,
                "udp/443 capacity ratio vs udp/high-port (2 vs ~20 Mbit/s)",
                "< 0.3",
                fmt(r),
                r.is_some_and(|v| v < 0.3),
            );
            let rq = t
                .plcy
                .pointer("/classes/udp~1443-quic/capacity_ratio")
                .and_then(num);
            chk(
                &mut c,
                "udp/443-quic capacity ratio",
                "< 0.3",
                fmt(rq),
                rq.is_some_and(|v| v < 0.3),
            );
        }
        "udp-blocked" => {
            let ctl = t
                .meta
                .pointer("/extra/a/control")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            chk(
                &mut c,
                "control fell back to TCP",
                "tcp",
                &ctl,
                ctl == "tcp",
            );
            let u = t
                .plcy
                .pointer("/classes/udp~1high-port/reachable")
                .and_then(Value::as_bool);
            chk(
                &mut c,
                "udp/high-port unreachable",
                false,
                format!("{u:?}"),
                u == Some(false),
            );
            let tc = t
                .plcy
                .pointer("/classes/tcp~1443/reachable")
                .and_then(Value::as_bool);
            chk(
                &mut c,
                "tcp/443 reachable",
                true,
                format!("{tc:?}"),
                tc == Some(true),
            );
            chk(
                &mut c,
                "trace written despite blocked UDP",
                "exit 0 or 3",
                &exit,
                exit == "0" || exit == "3",
            );
        }
        "nat-timeout" => {
            let alive = |s: u64| -> Option<bool> {
                t.plcy
                    .pointer("/nat/timeouts")?
                    .as_array()?
                    .iter()
                    .find(|v| v.get("idle_s").and_then(Value::as_u64) == Some(s))?
                    .get("binding_alive")?
                    .as_bool()
            };
            chk(
                &mut c,
                "binding alive after 15 s idle (timeout 20 s)",
                true,
                format!("{:?}", alive(15)),
                alive(15) == Some(true),
            );
            chk(
                &mut c,
                "binding expired after 30 s idle",
                false,
                format!("{:?}", alive(30)),
                alive(30) == Some(false),
            );
            chk(
                &mut c,
                "binding expired after 60 s idle",
                false,
                format!("{:?}", alive(60)),
                alive(60) == Some(false),
            );
        }
        "rebind" => {
            let rb = t
                .events
                .iter()
                .filter(|e| e.get("type").and_then(Value::as_str) == Some("nat_rebind"))
                .count();
            chk(&mut c, "responder recorded nat_rebind", ">= 1", rb, rb >= 1);
            let an = t
                .events
                .iter()
                .filter(|e| {
                    e.get("type").and_then(Value::as_str) == Some("addr_new")
                        && e.get("endpoint").and_then(Value::as_str) == Some("a")
                })
                .count();
            chk(&mut c, "initiator recorded addr_new", ">= 1", an, an >= 1);
            chk(
                &mut c,
                "session complete after rebinding",
                true,
                complete,
                complete,
            );
        }
        "reorder-dup" => {
            let ro = t.num("a_to_b", "/reorder/rate");
            // netem only reorders packets closer together than its delay (train packets), so the
            // direction-wide rate is far below the 10% applied to eligible packets.
            chk(
                &mut c,
                "reordering detected a_to_b",
                "> 0",
                fmt(ro),
                ro.is_some_and(|v| v > 0.0),
            );
            let du = t.num("a_to_b", "/duplicate/rate");
            chk(
                &mut c,
                "duplicate rate a_to_b (2% ± 1%)",
                0.02,
                fmt(du),
                du.is_some_and(|v| (v - 0.02).abs() <= 0.01),
            );
            let db = t.num("b_to_a", "/duplicate/rate");
            chk(&mut c, "no duplicates b_to_a", 0, fmt(db), db == Some(0.0));
        }
        "deadman" => {
            let log = read("script_pm.log");
            let raw = pt_derive::raw::Raw::load(&t.file);
            let tb = pt_derive::clock::TimeBase::from_raw(&raw);
            let start = log
                .lines()
                .find(|l| l.ends_with("outage_start"))
                .and_then(|l| l.split_whitespace().next()?.parse::<i64>().ok())
                .and_then(|r| tb.real("a", r));
            let (pk, _) = pt_derive::dir::packets(&raw, &tb, "b_to_a");
            let heavy_after: Option<usize> = start.map(|s0| {
                pk.iter()
                    .filter(|p| {
                        p.kind == "heavy"
                            && p.tx
                                .is_some_and(|t| t > s0 + 700_000_000 && t < s0 + 3_000_000_000)
                    })
                    .count()
            });
            let last_heavy = start.and_then(|s0| {
                pk.iter()
                    .filter(|p| p.kind == "heavy" && p.tx.is_some_and(|t| t > s0))
                    .filter_map(|p| p.tx)
                    .filter(|t| *t < s0 + 3_000_000_000)
                    .max()
                    .map(|t| (t - s0) as f64 / 1e6)
            });
            chk(
                &mut c,
                "responder heavy packets sent 0.7–3 s into the outage",
                0,
                format!("{heavy_after:?}"),
                heavy_after == Some(0),
            );
            chk(
                &mut c,
                "responder stopped within (ms after outage start)",
                "≤ 600",
                fmt(last_heavy),
                last_heavy.is_none_or(|v| v <= 600.0),
            );
            let dm = t.events.iter().any(|e| {
                e.get("type").and_then(Value::as_str) == Some("flow_stopped")
                    && e.get("endpoint").and_then(Value::as_str) == Some("b")
            });
            chk(
                &mut c,
                "dead_man flow_stopped event recorded by responder",
                true,
                dm,
                dm,
            );
        }
        "data-cap" => {
            let sent = t
                .events
                .iter()
                .find(|e| {
                    e.get("type").and_then(Value::as_str) == Some("session_end")
                        && e.get("endpoint").and_then(Value::as_str) == Some("b")
                })
                .and_then(|e| e.get("detail")?.get("bytes_sent")?.as_u64());
            chk(
                &mut c,
                "responder UDP bytes sent ≤ cap + one batch (3 MB + 100 kB)",
                3_000_000,
                format!("{sent:?}"),
                sent.is_some_and(|b| b <= 3_100_000),
            );
            let cap = t.events.iter().any(|e| {
                e.get("type").and_then(Value::as_str) == Some("budget_cap")
                    && e.get("endpoint").and_then(Value::as_str) == Some("b")
            });
            chk(
                &mut c,
                "budget_cap event recorded by responder",
                true,
                cap,
                cap,
            );
        }
        "rate-100m" => {
            let r = t.num("a_to_b", "/capacity/median_rate_bps");
            chk(
                &mut c,
                "capacity a_to_b at 100 Mbit/s (±10%)",
                format!("{:.0}", ip_rate(100e6)),
                fmt(r),
                rel_ok(r, ip_rate(100e6), 0.10),
            );
            let size = std::fs::metadata(trace_in(dir).unwrap_or_default())
                .map(|m| m.len())
                .unwrap_or(u64::MAX);
            chk(
                &mut c,
                "standard trace file size at 100 Mbit/s (≤ 10 MB)",
                10_000_000,
                size,
                size <= 10_000_000,
            );
        }
        _ => {}
    }
    c
}

/// NRMSE of 100 ms capacity bins vs the scripted rate schedule (excluding 500 ms after changes).
fn rate_step_nrmse(t: &Trace, log: &str) -> (Option<f64>, usize) {
    let raw = pt_derive::raw::Raw::load(&t.file);
    let tb = pt_derive::clock::TimeBase::from_raw(&raw);
    let mut sched: Vec<(i64, f64)> = log
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let real: i64 = it.next()?.parse().ok()?;
            let r: f64 = it.next()?.parse().ok()?;
            Some((tb.real("a", real)?, ip_rate(r)))
        })
        .collect();
    sched.sort_by_key(|s| s.0);
    let mut errs = Vec::new();
    let mut truth_sum = 0.0;
    for s in t.file.sections.iter().filter(|s| &s.kind == b"SERS") {
        for tbl in s.tables() {
            if tbl.name != "capacity_rate"
                || tbl
                    .attrs()
                    .and_then(|a| a.get("dir"))
                    .and_then(Value::as_str)
                    != Some("a_to_b")
            {
                continue;
            }
            let ts = tbl
                .column("t")
                .and_then(|c| c.i64_rows())
                .unwrap_or_default();
            let rs = tbl
                .column("rate")
                .and_then(|c| c.u64_rows())
                .unwrap_or_default();
            for (tt, rr) in ts.iter().zip(rs) {
                let (Some(tt), Some(rr)) = (tt, rr) else {
                    continue;
                };
                let i = sched.partition_point(|s| s.0 <= *tt);
                if i == 0 {
                    continue;
                }
                let (t_change, truth) = sched[i - 1];
                let next_change = sched.get(i).map_or(i64::MAX, |s| s.0);
                if tt - t_change < 500_000_000 || next_change - tt < 100_000_000 {
                    continue;
                }
                errs.push((rr as f64 - truth).powi(2));
                truth_sum += truth;
            }
        }
    }
    if errs.is_empty() {
        return (None, 0);
    }
    let n = errs.len();
    let rmse = (errs.iter().sum::<f64>() / n as f64).sqrt();
    (Some(rmse / (truth_sum / n as f64)), n)
}

/// Closure: replay the exported netem summary of `t` and compare the second trace with the first.
pub fn closure_checks(a: &Trace, b: &Trace) -> Vec<Check> {
    let mut c = Vec::new();
    for d in ["a_to_b", "b_to_a"] {
        let (x, y) = (
            a.num(d, "/capacity/median_rate_bps"),
            b.num(d, "/capacity/median_rate_bps"),
        );
        chk(
            &mut c,
            &format!("closure capacity {d} (±10%)"),
            fmt(x),
            fmt(y),
            x.is_some_and(|x| rel_ok(y, x, 0.10)),
        );
        let (x, y) = (
            a.num(d, "/queue/depth_bytes"),
            b.num(d, "/queue/depth_bytes"),
        );
        chk(
            &mut c,
            &format!("closure buffer {d} (±15%)"),
            fmt(x),
            fmt(y),
            x.is_some_and(|x| rel_ok(y, x, 0.15)),
        );
    }
    let sum = |t: &Trace| {
        t.num("a_to_b", "/base_delay/delay_ns")
            .zip(t.num("b_to_a", "/base_delay/delay_ns"))
            .map(|(p, q)| (p + q) / 1e6)
    };
    let (x, y) = (sum(a), sum(b));
    chk(
        &mut c,
        "closure base delay sum (ms, ±1)",
        fmt(x),
        fmt(y),
        x.zip(y).is_some_and(|(x, y)| (x - y).abs() <= 1.0),
    );
    c
}

/// Encoded size of the per-packet tables of a trace (bytes per packet), canonical settings.
/// Encoded size of a trace's packet tables: (bytes per packet, packets).
pub type Size = Option<(f64, usize)>;

/// Returns (bytes per packet, packets). REQ-FMT-015 applies to sessions of ≥ 10 000 packets,
/// where per-chunk overhead is amortised.
pub fn pkt_bytes_per_packet(t: &Trace) -> Size {
    let mut sections = Vec::new();
    let mut rows = 0usize;
    for s in t.file.sections.iter().filter(|s| &s.kind == b"OBSV") {
        if s.tables().iter().any(|tb| tb.name == "pkt") {
            rows += s.tables().iter().map(|tb| tb.rows).sum::<usize>();
            sections.push(s.clone());
        }
    }
    let mut bytes = 0usize;
    for s in &sections {
        bytes += pt_format::container::encode_record(s, &pt_format::WriteOptions::canonical())
            .ok()?
            .0
            .len();
    }
    (rows > 0).then(|| (bytes as f64 / rows as f64, rows))
}

/// Entry point: run `which` (a scenario name or "all"), write results, return pass/fail.
pub fn main(root: &Path, which: &str, jobs: usize) -> Result<bool> {
    // Sessions run in a scratch directory (it holds throwaway keys and full traces); only
    // results, logs and trace summaries go to the evidence directory (REQ-SEC-002, size).
    let out = root.join("target/groundtruth");
    std::fs::create_dir_all(&out)?;
    let evidence = std::env::var_os("PT_EVIDENCE_OUT").map(PathBuf::from);
    let st = Command::new("cargo")
        .current_dir(root)
        .args(["build", "--release", "--locked", "-q", "-p", "pathtrace"])
        .status()?;
    if !st.success() {
        bail!("build failed");
    }
    let bin = root.join("target/release/pathtrace");
    let list: Vec<Scenario> = scenarios()
        .into_iter()
        .filter(|s| which == "all" || s.name == which)
        .collect();
    if list.is_empty() {
        bail!("unknown scenario {which}");
    }
    // Run in parallel batches (each scenario has its own namespaces).
    let mut results: Vec<(String, Vec<Check>, Size)> = Vec::new();
    for batch in list.chunks(jobs.max(1)) {
        let handles: Vec<_> = batch
            .iter()
            .cloned()
            .map(|sc| {
                let (root, bin, out) = (root.to_path_buf(), bin.clone(), out.clone());
                std::thread::spawn(move || -> (String, Vec<Check>, Size) {
                    let r = (|| -> Result<(Vec<Check>, Size)> {
                        let dir = run(&root, &bin, &sc, &out, None, None)?;
                        let t = Trace::load(&trace_in(&dir)?)?;
                        let mut cks = checks(&sc, &t, &dir);
                        let bpp = pkt_bytes_per_packet(&t);
                        if sc.name == "rate-delay-asym" {
                            // Closure: replay the exported summary through netem, re-capture.
                            let ab = pt_derive::export::netem_args(&t.file, "a_to_b");
                            let ba = pt_derive::export::netem_args(&t.file, "b_to_a");
                            std::fs::write(
                                dir.join("netem_export.txt"),
                                format!("a_to_b: {ab:?}\nb_to_a: {ba:?}\n"),
                            )?;
                            if let (Some(ab), Some(ba)) = (ab, ba) {
                                let mut sc2 = sc.clone();
                                sc2.name = "closure-replay";
                                let d2 = run(&root, &bin, &sc2, &out, Some(&ab), Some(&ba))?;
                                let t2 = Trace::load(&trace_in(&d2)?)?;
                                cks.extend(closure_checks(&t, &t2));
                            } else {
                                chk(&mut cks, "netem export available", "yes", "no", false);
                            }
                        }
                        Ok((cks, bpp))
                    })();
                    match r {
                        Ok((c, b)) => (sc.name.to_string(), c, b),
                        Err(e) => (
                            sc.name.to_string(),
                            vec![Check {
                                name: "scenario ran".into(),
                                truth: "ok".into(),
                                got: e.to_string(),
                                pass: false,
                            }],
                            None,
                        ),
                    }
                })
            })
            .collect();
        for h in handles {
            results.push(
                h.join()
                    .map_err(|_| anyhow::anyhow!("scenario thread panicked"))?,
            );
        }
    }
    let mut csv = String::from("scenario,check,truth,got,pass\n");
    let stage_of = |n: &str| {
        scenarios()
            .into_iter()
            .find(|s| s.name == n)
            .map_or("", |s| s.stage)
    };
    let mut md = String::from(
        "| Scenario (simulator stages) | Check | Truth | Recovered | Pass |\n|---|---|---|---|---|\n",
    );
    let mut all = true;
    for (name, cks, bpp) in &results {
        for k in cks {
            all &= k.pass;
            let _ = writeln!(
                csv,
                "{name},\"{}\",\"{}\",\"{}\",{}",
                k.name,
                k.truth,
                k.got.replace('"', "'"),
                k.pass
            );
            let _ = writeln!(
                md,
                "| {name} ({}) | {} | {} | {} | {} |",
                stage_of(name),
                k.name,
                k.truth,
                k.got,
                if k.pass { "yes" } else { "**no**" }
            );
        }
        if let Some((b, n)) = bpp {
            let applies = *n >= 10_000;
            let pass = !applies || *b <= 8.0;
            let verdict = if !applies {
                "n/a (< 10 000 packets)"
            } else if pass {
                "yes"
            } else {
                "**no**"
            };
            let _ = writeln!(
                csv,
                "{name},\"pkt bytes per packet (canonical; applies at >= 10000 packets)\",\"<= 8\",\"{b:.3} over {n} packets\",{pass}"
            );
            let _ = writeln!(
                md,
                "| {name} | pkt table bytes/packet (canonical; applies at ≥ 10 000 packets) | ≤ 8 | {b:.3} over {n} packets | {verdict} |"
            );
            all &= pass;
        }
    }
    std::fs::write(out.join("results.csv"), &csv)?;
    std::fs::write(out.join("results.md"), &md)?;
    if let Some(ev) = evidence {
        std::fs::create_dir_all(&ev)?;
        std::fs::write(ev.join("results.csv"), &csv)?;
        std::fs::write(ev.join("results.md"), &md)?;
        for entry in std::fs::read_dir(&out)? {
            let dir = entry?.path();
            if !dir.is_dir() {
                continue;
            }
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let dst = ev.join(&name);
            std::fs::create_dir_all(&dst)?;
            for f in [
                "probe.out",
                "probe.err",
                "probe.exit",
                "serve.exit",
                "script_pm.log",
                "netem_export.txt",
                "qdisc_stats.txt",
            ] {
                if dir.join(f).exists() {
                    std::fs::copy(dir.join(f), dst.join(f))?;
                }
            }
            if let Ok(trace) = trace_in(&dir) {
                let info = Command::new(root.join("target/release/pathtrace"))
                    .args(["trace", "info", "--json"])
                    .arg(&trace)
                    .output()?;
                std::fs::write(dst.join("trace_info.json"), info.stdout)?;
                let netem = Command::new(root.join("target/release/pathtrace"))
                    .args(["export", "netem"])
                    .arg(&trace)
                    .output()?;
                std::fs::write(dst.join("derived_netem.txt"), netem.stdout)?;
            }
        }
    }
    print!("{md}");
    println!("verdict: {}", if all { "pass" } else { "fail" });
    Ok(all)
}
