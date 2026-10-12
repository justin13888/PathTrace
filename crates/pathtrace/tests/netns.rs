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
    run_session_full(profile, ab, ba, env, probe_exit, "0", tag)
}

/// As [`run_session_with`], also expecting the (first) responder to exit with `serve_exit`.
fn run_session_full(
    profile: &str,
    ab: &str,
    ba: &str,
    env: &[(&str, &str)],
    probe_exit: &str,
    serve_exit: &str,
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
        serve_exit,
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
    // ... and at the id level: no stamp id is left unexplained.
    for ep in ["a", "b"] {
        let c = &info["merge_checks"];
        assert_eq!(c[format!("txts_unexplained_{ep}")], 0, "{c}");
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

/// All events recorded in a trace, as dumped (`trace dump`).
fn events(trace: &Path) -> Vec<serde_json::Value> {
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
        .flat_map(|v| v["head"]["events"].as_array().cloned().unwrap_or_default())
        .collect()
}

/// All event types recorded in a trace.
fn event_types(trace: &Path) -> Vec<String> {
    events(trace)
        .iter()
        .map(|e| e["type"].as_str().unwrap_or("").to_string())
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

#[test]
#[ignore = "needs unprivileged user+net namespaces: run via `mise run test-netns`"]
fn responder_signal_ends_the_session_for_both() {
    // SIGTERM to `serve` during the saturation phases (probe.md §8): the responder records
    // `interrupted`, sends `abort`, and keeps serving the fetch; the initiator skips the
    // remaining phases, says bye, fetches and merges (exit 3).
    let (trace, info) = run_session_with(
        "smoke",
        "netem delay 10ms rate 20mbit limit 100",
        "netem delay 10ms rate 20mbit limit 100",
        &[("SERVE_SIGNAL_AFTER", "14")],
        "3",
        "servesig",
    );
    let out = trace.parent().unwrap();
    let read = |f: &str| std::fs::read_to_string(out.join(f)).unwrap_or_default();
    assert_eq!(info["complete"], true, "{info}");
    assert!(
        read("probe.err").contains("responder stopped by SIGTERM"),
        "{}",
        read("probe.err")
    );
    let ev = events(&trace);
    let interrupted: Vec<_> = ev.iter().filter(|e| e["type"] == "interrupted").collect();
    // One from each endpoint: the responder's own, and the initiator's from `abort`.
    assert_eq!(interrupted.len(), 2, "{interrupted:?}");
    assert!(
        interrupted
            .iter()
            .all(|e| e.to_string().contains("SIGTERM")),
        "{interrupted:?}"
    );
    assert!(
        interrupted
            .iter()
            .any(|e| e.to_string().contains("responder")),
        "{interrupted:?}"
    );
    // The responder ended its half because of the signal, not a bye or a lost peer.
    let ends: Vec<_> = ev.iter().filter(|e| e["type"] == "session_end").collect();
    assert!(
        ends.iter().any(|e| e.to_string().contains("signal")),
        "{ends:?}"
    );
}

#[test]
#[ignore = "needs unprivileged user+net namespaces: run via `mise run test-netns`"]
fn fetch_resume_uses_pinned_tls_and_falls_back_to_443() {
    // probe.md §8: `fetch --resume` fetches over TLS with the pinned certificate, on the main
    // port and then on 443. A wrong pinned certificate must fail (so TLS really is used), and
    // with tcp/4433 blocked the fetch must still succeed over tcp/443.
    let post = r#"set -e
S=$(ls "$OUT"/*.session)
sed 's/^cert .*/cert 308201ff/' "$S" >"$OUT/wrongcert.session"
chmod 600 "$OUT/wrongcert.session"
if "$BIN" --config-dir "$CFG" fetch --resume "$OUT/wrongcert.session" --out "$OUT/wrong.b.ptflog"; then
  echo "UNEXPECTED: fetch with a wrong pinned certificate succeeded"; exit 1
fi
nft add table inet f
nft add chain inet f o '{ type filter hook output priority 0; }'
nft add rule inet f o tcp dport 4433 drop
"$BIN" --config-dir "$CFG" fetch --resume "$S" --out "$OUT/via443.b.ptflog""#;
    let (trace, _) = run_session_with(
        "smoke",
        "netem delay 10ms rate 20mbit limit 100",
        "netem delay 10ms rate 20mbit limit 100",
        &[
            ("PROBE_SIGNAL_AFTER", "14"),
            ("SERVE_RESTART", "1"),
            ("POST_PA", post),
        ],
        "3",
        "fetchtls",
    );
    let out = trace.parent().unwrap();
    let read = |f: &str| std::fs::read_to_string(out.join(f)).unwrap_or_default();
    let log = read("post_pa.log");
    assert_eq!(read("post_pa.exit").trim(), "0", "{log}");
    assert!(
        log.contains("fetched the responder log over TLS on tcp/443"),
        "{log}"
    );
    assert!(!log.contains("plain TCP"), "{log}");
    assert!(
        std::fs::metadata(out.join("via443.b.ptflog"))
            .unwrap()
            .len()
            > 1000
    );
    assert!(!out.join("wrong.b.ptflog").exists());
}

#[test]
#[ignore = "needs unprivileged user+net namespaces: run via `mise run test-netns`"]
fn responder_log_fetchable_after_responder_killed_mid_session() {
    // REQ-PRB-031: the responder persists the fetch token when the session starts, so a
    // responder killed mid-session (SIGKILL: no end-of-session code runs) and restarted still
    // serves the log to `fetch --resume`.
    let (trace, _) = run_session_full(
        "smoke",
        "netem delay 10ms rate 20mbit limit 100",
        "netem delay 10ms rate 20mbit limit 100",
        &[
            ("SERVE_SIGNAL", "KILL"),
            ("SERVE_SIGNAL_AFTER", "12"),
            ("PROBE_SIGNAL_AFTER", "15"),
            ("SERVE_RESTART", "1"),
            (
                "POST_PA",
                r#""$BIN" --config-dir "$CFG" fetch --resume "$(ls "$OUT"/*.session)" --out "$OUT/afterkill.b.ptflog""#,
            ),
        ],
        "3",
        "137",
        "killrestart",
    );
    let out = trace.parent().unwrap();
    let read = |f: &str| std::fs::read_to_string(out.join(f)).unwrap_or_default();
    assert_eq!(read("post_pa.exit").trim(), "0", "{}", read("post_pa.log"));
    assert_eq!(read("serve2.exit").trim(), "0", "{}", read("serve2.log"));
    assert!(
        std::fs::metadata(out.join("afterkill.b.ptflog"))
            .unwrap()
            .len()
            > 1000
    );
}
