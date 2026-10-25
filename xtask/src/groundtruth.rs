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
    pub resp_addr: &'static str,
    pub probe_args: &'static str,
    /// Shell commands in the initiator namespace (e.g. a qdisc on its egress).
    pub setup_pa: String,
    /// Environment for `serve` / `probe` (test hooks, session.sh SERVE_ENV / PROBE_ENV).
    pub serve_env: &'static str,
    pub probe_env: &'static str,
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
        resp_addr: "10.0.2.2",
        probe_args: "",
        setup_pa: String::new(),
        serve_env: "",
        probe_env: "",
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
    // 1.5 s buffers at 20 Mbit/s in both directions (bufferbloat): feedback crossing the
    // saturated direction arrives late, which must pause, not kill, the session-long observers.
    let bloat = format!(
        "{}; {}",
        chain("mb0", 10, 20, 2500),
        chain("ma0", 10, 20, 2500)
    );
    // The initiator's own egress is the bottleneck: a 10-packet tbf returns ENOBUFS.
    let local_qdisc = "tc qdisc add dev va root tbf rate 20mbit burst 3028 limit 15140";
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
        // The hard cap must still be reached to test it. With byte allowances (probe.md §6)
        // the smoke profile plans its saturations inside a 3 MB cap, so 1.1 uses 1 MB, about
        // what a smoke session's background traffic alone sends. EXP-0002-r8 checked the 3 MB cap with 1.0;
        // EXP-0002-r9 (#38) supersedes it for 1.1.
        Scenario {
            serve_args: "--data-cap 1000000",
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
        Scenario {
            resp_addr: "fd00:2::2",
            ..s(
                "ipv6",
                "smoke",
                &netem("delay 10ms rate 20mbit limit 100"),
                &netem("delay 10ms rate 20mbit limit 100"),
                "",
                "",
                "IPv6",
            )
        },
        s(
            "light",
            "light",
            &netem("delay 10ms rate 20mbit limit 100"),
            &netem("delay 10ms rate 20mbit limit 100"),
            "",
            "",
            "profile",
        ),
        Scenario {
            probe_args: "--track-secs 120",
            ..s(
                "deep",
                "deep",
                &netem("delay 10ms rate 20mbit limit 100"),
                &netem("delay 10ms rate 20mbit limit 100"),
                "",
                "",
                "profile S6",
            )
        },
        Scenario {
            probe_args: "--rate-cap 5000000",
            ..s(
                "rate-cap",
                "smoke",
                &netem("delay 10ms rate 20mbit limit 100"),
                &netem("delay 10ms rate 20mbit limit 100"),
                "",
                "",
                "safety",
            )
        },
        // `probe --data-cap` on a fast path (cli.md): standard's saturations shrink to fit
        // 30 MB per sender instead of 200 MB, every saturation phase still runs.
        Scenario {
            probe_args: "--data-cap 30000000",
            ..s(
                "probe-data-cap",
                "standard",
                &netem("delay 10ms rate 100mbit limit 1000"),
                &netem("delay 10ms rate 100mbit limit 1000"),
                "",
                "",
                "safety budget",
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
            "geo",
            "standard",
            &netem("delay 300ms rate 20mbit limit 2000"),
            &netem("delay 300ms rate 20mbit limit 2000"),
            "",
            "",
            "robustness S4 S7",
        ),
        s(
            "geo-100m",
            "standard",
            &netem("delay 300ms rate 100mbit limit 10000"),
            &netem("delay 300ms rate 100mbit limit 10000"),
            "",
            "",
            "S6",
        ),
        s(
            "bufferbloat",
            "standard",
            &netem("delay 1ms"),
            &netem("delay 1ms"),
            &bloat,
            "",
            "robustness S4 S7",
        ),
        s(
            "fast",
            "standard",
            &netem("delay 5ms rate 300mbit limit 5000"),
            &netem("delay 5ms rate 300mbit limit 5000"),
            "",
            "",
            "safety budget",
        ),
        // An 8 KiB buffer drops only while the responder is descheduled (none on a quiet
        // host, EXP-0002-r13); 20 ms slots deliver a→b in bursts that overflow it anyway.
        Scenario {
            serve_env: "PATHTRACE_RECV_BUF=8192",
            ..s(
                "rcvbuf",
                "smoke",
                &netem("delay 10ms rate 100mbit limit 1000 slot 20ms 20ms"),
                &netem("delay 10ms rate 100mbit limit 1000"),
                "",
                "",
                "host drops S5 S9",
            )
        },
        Scenario {
            setup_pa: local_qdisc.to_string(),
            ..s(
                "local-qdisc",
                "smoke",
                &netem("delay 10ms"),
                &netem("delay 10ms"),
                "",
                "",
                "host drops tx ids",
            )
        },
        Scenario {
            setup_pa: local_qdisc.to_string(),
            probe_env: "PATHTRACE_TX_IDS=predicted",
            ..s(
                "local-qdisc-predicted",
                "smoke",
                &netem("delay 10ms"),
                &netem("delay 10ms"),
                "",
                "",
                "host drops tx ids",
            )
        },
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
        .env("RESP_ADDR", sc.resp_addr)
        .env("PROBE_ARGS", sc.probe_args)
        .env("SETUP_PA", &sc.setup_pa)
        .env("SERVE_ENV", sc.serve_env)
        .env("PROBE_ENV", sc.probe_env)
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
            // Four intervals (p and r, in two scenarios) are judged per run, so each is taken at
            // the Bonferroni level 1 - 0.05/4 = 98.75% (z = 2.498) for a family-wise 95%
            // (EXP-0002-r6). Computed from the transition counts the trace records.
            const Z_FAMILY: f64 = 2.498;
            let ci = |k: &str, n: &str| -> Option<(f64, f64)> {
                let k = t.num("a_to_b", &format!("/loss/ge/{k}"))?;
                let n = t.num("a_to_b", &format!("/loss/ge/{n}"))?;
                Some(pt_derive::dir::wilson_z(k, n, Z_FAMILY))
            };
            let pc = ci("good_to_bad", "good_n");
            let rc = ci("bad_to_good", "bad_n");
            chk(
                &mut c,
                "GE p 98.75% CI covers truth (family-wise 95% over 4)",
                p,
                format!("{pc:?}"),
                pc.is_some_and(|(lo, hi)| lo <= p && p <= hi),
            );
            chk(
                &mut c,
                "GE r 98.75% CI covers truth (family-wise 95% over 4)",
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
            // fq_codel `ecn` marks ECT(0) and ECT(1) alike, and its marks on the light flow are
            // few (4-13 per session), so a mark on either ECT codepoint is the truth (EXP-0002-r7).
            let e0 = t.s("a_to_b", "/ecn/codepoints/ect0/verdict");
            let e1 = t.s("a_to_b", "/ecn/codepoints/ect1/verdict");
            chk(
                &mut c,
                "ECT marked by fq_codel (ECT(0) or ECT(1))",
                "marked",
                format!("ect0 {e0}, ect1 {e1}"),
                e0 == "marked" || e1 == "marked",
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
                "responder UDP bytes sent ≤ cap + one batch (1 MB + 100 kB)",
                1_000_000,
                format!("{sent:?}"),
                sent.is_some_and(|b| b <= 1_100_000),
            );
            let skipped = event_count(t, "phase_skipped", "a");
            chk(
                &mut c,
                "responder saturation skipped for lack of budget (phase_skipped)",
                ">= 1",
                skipped,
                skipped >= 1,
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
        "light" => {
            chk(&mut c, "session complete", true, complete, complete);
            let sent = |ep: &str| {
                t.events
                    .iter()
                    .find(|e| {
                        e.get("type").and_then(Value::as_str) == Some("session_end")
                            && e.get("endpoint").and_then(Value::as_str) == Some(ep)
                    })
                    .and_then(|e| e.get("detail")?.get("bytes_sent")?.as_u64())
            };
            let (a, b) = (sent("a"), sent("b"));
            chk(
                &mut c,
                "light profile UDP bytes sent per endpoint (≤ 2 MB)",
                2_000_000,
                format!("a={a:?} b={b:?}"),
                a.is_some_and(|x| x <= 2_000_000) && b.is_some_and(|x| x <= 2_000_000),
            );
            let size = std::fs::metadata(trace_in(dir).unwrap_or_default())
                .map(|m| m.len())
                .unwrap_or(u64::MAX);
            chk(
                &mut c,
                "light trace file size (≤ 200 kB)",
                200_000,
                size,
                size <= 200_000,
            );
        }
        "deep" => {
            chk(&mut c, "session complete", true, complete, complete);
            let tracking = t
                .file
                .sections
                .iter()
                .filter(|s| &s.kind == b"FLOW")
                .flat_map(|s| {
                    s.get("flows")
                        .and_then(Value::as_array)
                        .unwrap_or(&[])
                        .to_vec()
                })
                .filter(|f| {
                    f.get("id")
                        .and_then(Value::as_u64)
                        .is_some_and(|id| (100..250).contains(&id))
                })
                .count();
            chk(
                &mut c,
                "periodic tracking saturations (120 s → 2)",
                2,
                tracking,
                tracking >= 2,
            );
            let alive300 = t
                .plcy
                .pointer("/nat/timeouts")
                .and_then(Value::as_array)
                .is_some_and(|a| {
                    a.iter()
                        .any(|v| v.get("idle_s").and_then(Value::as_u64) == Some(300))
                });
            chk(
                &mut c,
                "deep NAT probes include 300 s idle",
                true,
                alive300,
                alive300,
            );
        }
        "rate-cap" => {
            let raw = pt_derive::raw::Raw::load(&t.file);
            let tb = pt_derive::clock::TimeBase::from_raw(&raw);
            let (pk, _) = pt_derive::dir::packets(&raw, &tb, "a_to_b");
            let heavy: Vec<_> = pk
                .iter()
                .filter(|p| p.kind == "heavy")
                .filter_map(|p| Some((p.tx?, p.size)))
                .collect();
            let rate = match (
                heavy.iter().map(|h| h.0).min(),
                heavy.iter().map(|h| h.0).max(),
            ) {
                (Some(t0), Some(t1)) if t1 > t0 => Some(
                    heavy.iter().map(|h| h.1).sum::<i64>() as f64 * 8.0 * 1e9 / (t1 - t0) as f64,
                ),
                _ => None,
            };
            chk(
                &mut c,
                "initiator heavy send rate under --rate-cap 5 Mbit/s (≤ 5.5 Mbit/s)",
                5_000_000,
                fmt(rate),
                rate.is_some_and(|r| r <= 5_500_000.0),
            );
        }
        "ipv6" => {
            chk(
                &mut c,
                "session complete over IPv6",
                true,
                complete,
                complete,
            );
            let peer = t
                .meta
                .pointer("/endpoints/a/peer_addr")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            chk(
                &mut c,
                "initiator used the IPv6 responder address",
                "[fd00:2::2]:4433",
                &peer,
                peer == "[fd00:2::2]:4433",
            );
            let ra = t.num("a_to_b", "/capacity/median_rate_bps");
            chk(
                &mut c,
                "capacity a_to_b over IPv6 (±10%)",
                format!("{:.0}", ip_rate(20e6)),
                fmt(ra),
                rel_ok(ra, ip_rate(20e6), 0.10),
            );
            let u = t
                .plcy
                .pointer("/classes/udp~1443/reachable")
                .and_then(Value::as_bool);
            chk(
                &mut c,
                "udp/443 reachable over IPv6",
                true,
                format!("{u:?}"),
                u == Some(true),
            );
        }
        "geo-100m" => {
            // 300 ms one way at 100 Mbit/s: slow start must not exit on lagged delivery
            // feedback, or the ramp outlasts the saturation (issue #30).
            chk(&mut c, "session complete", true, complete, complete);
            for dir in ["a_to_b", "b_to_a"] {
                let r = t.num(dir, "/capacity/median_rate_bps");
                chk(
                    &mut c,
                    &format!("capacity {dir} at 300 ms one way, 100 Mbit/s (±10%)"),
                    format!("{:.0}", ip_rate(100e6)),
                    fmt(r),
                    rel_ok(r, ip_rate(100e6), 0.10),
                );
                // Seconds the bottleneck held a queue under the heavy flows (P4–P7). The
                // budget-shortened saturations' overdrives alone give about 2 s; the slow
                // ramp gave 1.9–2.7 s here, the lag-gated one 3.9–6.1 s. b→a, whose
                // saturations the budget shortens least, also needs hold to keep its queue
                // (issue #40): hold on the RTT-old queue gave 5.8–6.1 s there, hold on the
                // predicted queue 7.7–8.1 s alone and 6.56 s beside two other scenarios on a
                // loaded host (EXP-0002-r11), so the floor sits between the two laws at 6.5 s.
                // a→b stays at about 4.1 s either way. Only `saturated` segments count: the
                // chirp's `estimated` segment would otherwise lift a slow ramp over the floor.
                let min_s = if dir == "b_to_a" { 6.5 } else { 3.0 };
                let sat_s = t
                    .dir(dir, "/capacity/segments")
                    .and_then(Value::as_array)
                    .map(|s| {
                        s.iter()
                            .filter(|w| {
                                w.get("quality").and_then(Value::as_str) == Some("saturated")
                            })
                            .filter_map(|w| Some(num(w.get("t1")?)? - num(w.get("t0")?)?))
                            .sum::<f64>()
                            / 1e9
                    });
                chk(
                    &mut c,
                    &format!("saturated time {dir} (s, ≥ {min_s})"),
                    format!("≥ {min_s}"),
                    fmt(sat_s),
                    sat_s.is_some_and(|s| s >= min_s),
                );
            }
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
        "geo" | "bufferbloat" => {
            chk(&mut c, "session complete", true, complete, complete);
            if sc.name == "geo" {
                // 300 ms one way: the saturations must still reach and hold capacity (issue #30).
                for dir in ["a_to_b", "b_to_a"] {
                    let r = t.num(dir, "/capacity/median_rate_bps");
                    chk(
                        &mut c,
                        &format!("capacity {dir} at 300 ms one way (bit/s, ±10%)"),
                        format!("{:.0}", ip_rate(20e6)),
                        fmt(r),
                        rel_ok(r, ip_rate(20e6), 0.10),
                    );
                }
            }
            // Trains (3, 4) and PMTU ladders (9, 10) may pause but must never be stopped.
            let killed = t
                .events
                .iter()
                .filter(|e| e.get("type").and_then(Value::as_str) == Some("flow_stopped"))
                .filter(|e| {
                    e.get("detail")
                        .and_then(|d| d.get("flow"))
                        .and_then(Value::as_u64)
                        .is_some_and(|f| matches!(f, 3 | 4 | 9 | 10))
                })
                .count();
            chk(
                &mut c,
                "train and PMTU flows never stopped by the dead-man",
                0,
                killed,
                killed == 0,
            );
            let raw = pt_derive::raw::Raw::load(&t.file);
            let tb = pt_derive::clock::TimeBase::from_raw(&raw);
            // Start of P8 (reference flows), after every saturation phase.
            let p8 = t
                .events
                .iter()
                .find(|e| {
                    e.get("type").and_then(Value::as_str) == Some("phase_start")
                        && e.get("endpoint").and_then(Value::as_str) == Some("a")
                        && e.get("detail")
                            .and_then(|d| d.get("phase"))
                            .and_then(Value::as_u64)
                            == Some(8)
                })
                .and_then(|e| e.get("t")?.as_u64())
                .and_then(|m| tb.mono("a", m as i64));
            for (dir, flow) in [("a_to_b", 3), ("b_to_a", 4)] {
                let (pk, _) = pt_derive::dir::packets(&raw, &tb, dir);
                let late = p8.map(|t0| {
                    pk.iter()
                        .filter(|p| {
                            p.flow == flow && p.rx.is_some() && p.tx.is_some_and(|x| x > t0)
                        })
                        .count()
                });
                chk(
                    &mut c,
                    &format!("light trains {dir} still delivered after the saturations"),
                    "> 0",
                    format!("{late:?}"),
                    late.is_some_and(|n| n > 0),
                );
                let m = t.num(dir, "/mtu/path_mtu");
                chk(
                    &mut c,
                    &format!("PMTU ladder {dir} completed (path MTU 1500)"),
                    1500,
                    fmt(m),
                    m == Some(1500.0),
                );
            }
        }
        "fast" => {
            chk(&mut c, "session complete", true, complete, complete);
            for ep in ["a", "b"] {
                let cap = event_count(t, "budget_cap", ep);
                chk(
                    &mut c,
                    &format!("hard data cap not reached by {ep} (allowances planned the budget)"),
                    0,
                    cap,
                    cap == 0,
                );
                let sent = t
                    .events
                    .iter()
                    .find(|e| {
                        e.get("type").and_then(Value::as_str) == Some("session_end")
                            && e.get("endpoint").and_then(Value::as_str) == Some(ep)
                    })
                    .and_then(|e| e.get("detail")?.get("bytes_sent")?.as_u64());
                chk(
                    &mut c,
                    &format!("{ep} UDP bytes sent within the standard cap (200 MB)"),
                    200_000_000,
                    format!("{sent:?}"),
                    sent.is_some_and(|b| b <= 200_000_000),
                );
            }
            let phases: Vec<u64> = t
                .events
                .iter()
                .filter(|e| {
                    e.get("type").and_then(Value::as_str) == Some("phase_start")
                        && e.get("endpoint").and_then(Value::as_str) == Some("a")
                })
                .filter_map(|e| e.get("detail")?.get("phase")?.as_u64())
                .collect();
            let all = [4, 5, 6, 7, 8].iter().all(|p| phases.contains(p));
            chk(
                &mut c,
                "every phase P4-P8 ran",
                "4 5 6 7 8",
                format!("{phases:?}"),
                all,
            );
            let allow = t
                .events
                .iter()
                .filter(|e| {
                    e.get("type").and_then(Value::as_str) == Some("flow_stopped")
                        && e.get("detail")
                            .and_then(|d| d.get("reason"))
                            .and_then(Value::as_str)
                            == Some("allowance")
                })
                .count();
            chk(
                &mut c,
                "saturations ended by their allowances (flow_stopped)",
                ">= 2",
                allow,
                allow >= 2,
            );
        }
        "probe-data-cap" => {
            chk(&mut c, "session complete", true, complete, complete);
            for ep in ["a", "b"] {
                let sent = t
                    .events
                    .iter()
                    .find(|e| {
                        e.get("type").and_then(Value::as_str) == Some("session_end")
                            && e.get("endpoint").and_then(Value::as_str) == Some(ep)
                    })
                    .and_then(|e| e.get("detail")?.get("bytes_sent")?.as_u64());
                chk(
                    &mut c,
                    &format!("{ep} UDP bytes sent within --data-cap (30 MB)"),
                    30_000_000,
                    format!("{sent:?}"),
                    sent.is_some_and(|b| b <= 30_000_000),
                );
                let cap = event_count(t, "budget_cap", ep);
                chk(
                    &mut c,
                    &format!("hard data cap not reached by {ep} (allowances planned the budget)"),
                    0,
                    cap,
                    cap == 0,
                );
            }
            let phases: Vec<u64> = t
                .events
                .iter()
                .filter(|e| {
                    e.get("type").and_then(Value::as_str) == Some("phase_start")
                        && e.get("endpoint").and_then(Value::as_str) == Some("a")
                })
                .filter_map(|e| e.get("detail")?.get("phase")?.as_u64())
                .collect();
            chk(
                &mut c,
                "saturations P4 and P5 ran",
                "4 5",
                format!("{phases:?}"),
                phases.contains(&4) && phases.contains(&5),
            );
            let user = t
                .meta
                .pointer("/extra/a/data_cap_user")
                .and_then(Value::as_u64);
            chk(
                &mut c,
                "META records the requested cap",
                30_000_000,
                format!("{user:?}"),
                user == Some(30_000_000),
            );
        }
        "rcvbuf" => {
            chk(&mut c, "session complete", true, complete, complete);
            let hd = t.num("a_to_b", "/host_drops/socket_drops");
            chk(
                &mut c,
                "responder socket drops recorded (rxq_drops)",
                "> 0",
                fmt(hd),
                hd.is_some_and(|v| v > 0.0),
            );
            let hp = t.num("a_to_b", "/host_drops/packets");
            chk(
                &mut c,
                "lost packets attributed to the receiving host",
                "> 0",
                fmt(hp),
                hp.is_some_and(|v| v > 0.0),
            );
            let errs = counter_increase(t, "netstack", "b", "udp_rcvbuf_errors");
            chk(
                &mut c,
                "responder UDP RcvbufErrors increased (netstack)",
                "> 0",
                format!("{errs:?}"),
                errs.is_some_and(|v| v > 0),
            );
            let d = t.s("a_to_b", "/queue/discipline");
            chk(
                &mut c,
                "host drops not mistaken for a policer",
                "not policer",
                &d,
                d != "policer",
            );
        }
        "local-qdisc" | "local-qdisc-predicted" => {
            chk(&mut c, "session complete", true, complete, complete);
            let mode = if sc.name == "local-qdisc" {
                "explicit"
            } else {
                "predicted"
            };
            let got = t
                .meta
                .pointer("/endpoints/a/sockets/0/tx_ids")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            chk(
                &mut c,
                "initiator transmit id mode",
                mode,
                &got,
                got == mode,
            );
            let enobufs = t
                .events
                .iter()
                .filter(|e| {
                    matches!(
                        e.get("type").and_then(Value::as_str),
                        Some("send_error" | "send_partial")
                    ) && e.get("endpoint").and_then(Value::as_str) == Some("a")
                })
                .count();
            chk(
                &mut c,
                "initiator send failures recorded (local qdisc full)",
                "> 0",
                enobufs,
                enobufs > 0,
            );
            let q = t.num("a_to_b", "/local_qdisc_drops/drops");
            chk(
                &mut c,
                "local qdisc drops a_to_b recorded",
                "> 0",
                fmt(q),
                q.is_some_and(|v| v > 0.0),
            );
            let bad = t
                .meta
                .pointer("/merge_checks/a_to_b/txts_implausible")
                .and_then(Value::as_u64);
            let joined = t
                .meta
                .pointer("/merge_checks/a_to_b/txts_joined")
                .and_then(Value::as_u64);
            chk(
                &mut c,
                "TX stamps aligned after send failures (implausible joins)",
                0,
                format!("{bad:?} of {joined:?}"),
                bad == Some(0) && joined.is_some_and(|j| j > 1000),
            );
        }
        _ => {}
    }
    c
}

/// Events of `kind` recorded by endpoint `ep`.
fn event_count(t: &Trace, kind: &str, ep: &str) -> usize {
    t.events
        .iter()
        .filter(|e| {
            e.get("type").and_then(Value::as_str) == Some(kind)
                && e.get("endpoint").and_then(Value::as_str) == Some(ep)
        })
        .count()
}

/// Last minus first value of a cumulative counter column of a raw table of endpoint `ep`.
fn counter_increase(t: &Trace, table: &str, ep: &str, col: &str) -> Option<i64> {
    let raw = pt_derive::raw::Raw::load(&t.file);
    let v: Vec<i64> = raw
        .table(&format!("{table}[{ep}]"))?
        .col(col)
        .iter()
        .flatten()
        .copied()
        .collect();
    Some(v.last()? - v.first()?)
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

/// Returns (bytes per packet, packets). REQ-FMT-015's per-packet figure applies to standard and
/// deep sessions, where the volume is.
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
    if which == "all" {
        // Fresh scratch space so no directory from an earlier run is reported.
        let _ = std::fs::remove_dir_all(&out);
    }
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
    let profile_of = |n: &str| {
        scenarios()
            .into_iter()
            .find(|s| s.name == n)
            .map_or("", |s| s.profile)
    };
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
            let applies = matches!(profile_of(name), "standard" | "deep");
            let pass = !applies || *b <= 8.0;
            let verdict = if !applies {
                "n/a (smoke/light: fixed overhead dominates)"
            } else if pass {
                "yes"
            } else {
                "**no**"
            };
            let _ = writeln!(
                csv,
                "{name},\"pkt bytes per packet (canonical; applies to standard/deep sessions)\",\"<= 8\",\"{b:.3} over {n} packets\",{pass}"
            );
            let _ = writeln!(
                md,
                "| {name} | pkt table bytes/packet (canonical; applies to standard/deep sessions) | ≤ 8 | {b:.3} over {n} packets | {verdict} |"
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
