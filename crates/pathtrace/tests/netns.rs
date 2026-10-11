//! End-to-end session through unprivileged network namespaces with known impairments
//! (tools/netns/session.sh). Ignored by default; `mise run test-netns` runs it, and CI treats a
//! failure to create namespaces as a failure, never a skip.

use std::path::{Path, PathBuf};
use std::process::Command;

fn run_session(profile: &str, ab: &str, ba: &str) -> (PathBuf, serde_json::Value) {
    run_session_with(profile, ab, ba, &[], "0", "plain")
}

/// Run the harness with extra environment, expecting the probe to exit with `probe_exit`.
fn run_session_with(
    profile: &str,
    ab: &str,
    ba: &str,
    env: &[(&str, &str)],
    probe_exit: &str,
    tag: &str,
) -> (PathBuf, serde_json::Value) {
    let bin = env!("CARGO_BIN_EXE_pathtrace");
    let out = std::env::temp_dir().join(format!("pt-netns-{profile}-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/netns/session.sh");
    let status = Command::new("unshare")
        .args(["-Urnm", "sh"])
        .arg(&script)
        .env("BIN", bin)
        .env("OUT", &out)
        .env("PROFILE", profile)
        .env("QDISC_AB", ab)
        .env("QDISC_BA", ba)
        .envs(env.iter().copied())
        .status()
        .expect("unshare must be available");
    assert!(
        status.success(),
        "namespace harness failed (are unprivileged user namespaces enabled?)"
    );
    let read = |f: &str| std::fs::read_to_string(out.join(f)).unwrap_or_default();
    assert_eq!(
        read("probe.exit").trim(),
        probe_exit,
        "probe failed:\n{}\n{}",
        read("probe.err"),
        read("serve.log")
    );
    assert_eq!(
        read("serve.exit").trim(),
        "0",
        "serve failed:\n{}",
        read("serve.log")
    );
    let trace = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|x| x == "ptf"))
        .expect("trace written");
    let check = Command::new(bin)
        .args(["trace", "check"])
        .arg(&trace)
        .status()
        .unwrap();
    assert!(check.success(), "trace check failed");
    let info = Command::new(bin)
        .args(["trace", "info", "--json"])
        .arg(&trace)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    (trace, v)
}

#[test]
#[ignore = "needs unprivileged user+net namespaces: run via `mise run test-netns`"]
fn smoke_session_through_netem() {
    let (_, info) = run_session(
        "smoke",
        "netem delay 10ms rate 20mbit limit 100",
        "netem delay 15ms rate 10mbit limit 100",
    );
    assert_eq!(info["complete"], true, "{info}");
    for dir in ["pkt[a_to_b]", "pkt[b_to_a]"] {
        let rows = info["tables"][dir]["rows"].as_u64().unwrap_or(0);
        assert!(rows > 1000, "{dir}: {rows} rows");
    }
    assert_eq!(info["ptf_version"], "1.1", "{info}");
    // Every TX stamp joins its own transmission (probe.md §4.1).
    for dir in ["a_to_b", "b_to_a"] {
        let c = &info["merge_checks"][dir];
        assert!(c["txts_joined"].as_u64().unwrap_or(0) > 1000, "{dir}: {c}");
        assert_eq!(c["txts_implausible"], 0, "{dir}: {c}");
    }
    for t in [
        "tcpinfo[a]",
        "tcpinfo[b]",
        "app[a]",
        "pairs[a]",
        "pairs[b]",
        "exchange[a]",
        "ifstats[a]",
        "echo[a]",
        // Host-drop accounting on both endpoints (probe.md §4.2).
        "netstack[a]",
        "netstack[b]",
        "qdisc[a]",
        "qdisc[b]",
    ] {
        assert!(
            info["tables"][t]["rows"].as_u64().unwrap_or(0) > 0,
            "{t} missing: {info}"
        );
    }
}

/// All event types recorded in a trace.
fn event_types(trace: &Path) -> Vec<String> {
    let bin = env!("CARGO_BIN_EXE_pathtrace");
    let dump = Command::new(bin)
        .args(["trace", "dump"])
        .arg(trace)
        .output()
        .unwrap();
    String::from_utf8_lossy(&dump.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["type"] == "EVNT")
        .flat_map(|v| {
            v["head"]["events"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|e| e["type"].as_str().unwrap_or("").to_string())
        })
        .collect()
}

#[test]
#[ignore = "needs unprivileged user+net namespaces: run via `mise run test-netns`"]
fn interrupted_session_ends_gracefully_and_stays_fetchable() {
    // SIGINT during the saturation phases: the probe ends the session with the responder,
    // fetches its log and merges (exit 3), and the session file still fetches it over TLS.
    let (trace, info) = run_session_with(
        "smoke",
        "netem delay 10ms rate 20mbit limit 100",
        "netem delay 10ms rate 20mbit limit 100",
        &[
            ("PROBE_SIGNAL_AFTER", "14"),
            (
                "POST_PA",
                r#""$BIN" --config-dir "$CFG" fetch --resume "$(ls "$OUT"/*.session)" --out "$OUT/refetch.b.ptflog""#,
            ),
        ],
        "3",
        "sigint",
    );
    let out = trace.parent().unwrap();
    let read = |f: &str| std::fs::read_to_string(out.join(f)).unwrap_or_default();
    assert_eq!(info["complete"], true, "{info}");
    assert!(
        read("probe.err").contains("interrupted by SIGINT"),
        "{}",
        read("probe.err")
    );
    assert!(event_types(&trace).iter().any(|t| t == "interrupted"));
    assert_eq!(read("post_pa.exit").trim(), "0", "{}", read("post_pa.log"));
    assert!(
        std::fs::metadata(out.join("refetch.b.ptflog"))
            .unwrap()
            .len()
            > 1000
    );
}

#[test]
#[ignore = "needs unprivileged user+net namespaces: run via `mise run test-netns`"]
fn lost_handshake_reply_is_resent() {
    // The middlebox drops the responder's first datagram (the handshake reply).
    let (trace, info) = run_session_with(
        "smoke",
        "netem delay 10ms rate 20mbit limit 100",
        "netem delay 10ms rate 20mbit limit 100",
        &[(
            "SETUP_PM",
            "nft add table inet hs && nft add set inet hs seen '{ type ipv4_addr; flags dynamic; }' && nft add chain inet hs f '{ type filter hook forward priority 0; }' && nft add rule inet hs f ip saddr 10.0.2.2 udp sport 4433 ip daddr != @seen add @seen '{ ip daddr }' drop",
        )],
        "0",
        "handshake",
    );
    assert_eq!(info["complete"], true, "{info}");
    assert!(event_types(&trace).iter().any(|t| t == "handshake_resent"));
}
