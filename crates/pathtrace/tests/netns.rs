//! End-to-end session through unprivileged network namespaces with known impairments
//! (tools/netns/session.sh). Ignored by default; `mise run test-netns` runs it, and CI treats a
//! failure to create namespaces as a failure, never a skip.

use std::path::{Path, PathBuf};
use std::process::Command;

fn run_session(profile: &str, ab: &str, ba: &str) -> (PathBuf, serde_json::Value) {
    let bin = env!("CARGO_BIN_EXE_pathtrace");
    let out = std::env::temp_dir().join(format!("pt-netns-{profile}-{}", std::process::id()));
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
        .status()
        .expect("unshare must be available");
    assert!(
        status.success(),
        "namespace harness failed (are unprivileged user namespaces enabled?)"
    );
    let read = |f: &str| std::fs::read_to_string(out.join(f)).unwrap_or_default();
    assert_eq!(
        read("probe.exit").trim(),
        "0",
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
