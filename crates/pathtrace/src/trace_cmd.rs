//! `pathtrace trace …`: validate, summarise and convert PTF files (REQ-FMT-014, REQ-FMT-018).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use pt_format::{ReadOptions, Value, WriteOptions};

#[derive(Debug, Subcommand)]
pub enum TraceCmd {
    /// Strictly validate a file (exit 1 if invalid).
    Check {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Summarise a file.
    Info {
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Write the lossless JSON Lines twin.
    Dump {
        file: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Write a redacted copy (`shareable` removes identifying data; `anonymous` also removes
    /// quasi-identifiers and shifts wall-clock times to start at 0).
    Redact {
        file: PathBuf,
        #[arg(long, value_parser = ["shareable", "anonymous"])]
        level: String,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Read a JSON Lines twin back into canonical PTF.
    Load {
        file: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
    },
}

fn read(
    path: &PathBuf,
    recover: bool,
) -> Result<(pt_format::PtfFile, pt_format::ReadReport), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    pt_format::read(
        &bytes,
        ReadOptions {
            recover,
            ..Default::default()
        },
    )
    .map_err(|e| format!("{} [{}]", e, e.kind()))
}

/// What `trace info` shows from PATH (cli.md): per direction `host_drops`, `local_qdisc_drops`
/// and `tx_timestamps` (the counts of `PATH.<dir>.timestamps`: how many transmit times are
/// `snd`, `sched` or `user`), and `overlay`. A field derivation could not establish is shown
/// whole, with its `unknown` status and `reason` and no counts (probe.md §9.6).
fn path_facts(f: &pt_format::PtfFile) -> serde_json::Value {
    let head = f.sections.iter().find(|s| &s.kind == b"PATH");
    let dirs = head.and_then(|s| s.get("directions"));
    let per_dir = |get: &dyn Fn(&Value) -> Option<&Value>| {
        dirs.map(|d| {
            ["a_to_b", "b_to_a"]
                .iter()
                .filter_map(|dir| {
                    let v = get(d.get(dir)?)?;
                    Some((dir.to_string(), pt_format::jsonl::cbor_to_json(v)))
                })
                .collect::<serde_json::Map<_, _>>()
        })
    };
    serde_json::json!({
        "host_drops": per_dir(&|d: &Value| d.get("host_drops")),
        "local_qdisc_drops": per_dir(&|d: &Value| d.get("local_qdisc_drops")),
        "tx_timestamps": per_dir(&|d: &Value| d.get("timestamps").and_then(|t| t.get("counts"))),
        "overlay": head.and_then(|s| s.get("overlay")).map(pt_format::jsonl::cbor_to_json),
    })
}

/// What `trace info` shows of each endpoint's host (cli.md): `host_suspend {events,
/// suspended_ns}` from the EVNT `stall {cause: "suspend"}` events (probe.md §4.3), and
/// `host_state` from META `clock_sync`, `power` and `pacing` (PTF 1.3, probe.md §4.5) with the
/// number of `host_state` events, null where META has none of them. An observation log has one
/// endpoint, its `role`.
fn host_facts(f: &pt_format::PtfFile, meta: &Value) -> (serde_json::Value, serde_json::Value) {
    let role = meta.get("role").and_then(Value::as_str);
    let eps: Vec<&str> = match role {
        Some(r) => vec![r],
        None => vec!["a", "b"],
    };
    let events: Vec<&Value> = f
        .sections
        .iter()
        .filter(|s| &s.kind == b"EVNT")
        .filter_map(|s| s.get("events").and_then(Value::as_array))
        .flatten()
        .collect();
    let of = |e: &Value, ep: &str| e.get("endpoint").and_then(Value::as_str).or(role) == Some(ep);
    let mut suspend = serde_json::Map::new();
    let mut state = serde_json::Map::new();
    for ep in eps {
        let (n, ns) = events
            .iter()
            .filter(|e| of(e, ep) && e.get("type").and_then(Value::as_str) == Some("stall"))
            .filter_map(|e| e.get("detail"))
            .filter(|d| d.get("cause").and_then(Value::as_str) == Some("suspend"))
            .fold((0u64, 0u64), |(n, ns), d| {
                (
                    n + 1,
                    ns + d.get("suspended_ns").and_then(Value::as_u64).unwrap_or(0),
                )
            });
        suspend.insert(
            ep.to_string(),
            serde_json::json!({"events": n, "suspended_ns": ns}),
        );
        let facts = match role {
            Some(_) => meta.get("endpoint"),
            None => meta.get("endpoints").and_then(|e| e.get(ep)),
        };
        let get = |k: &str| {
            facts
                .and_then(|f| f.get(k))
                .map(pt_format::jsonl::cbor_to_json)
        };
        let (cs, pw, pc) = (get("clock_sync"), get("power"), get("pacing"));
        let v = if cs.is_none() && pw.is_none() && pc.is_none() {
            serde_json::Value::Null
        } else {
            let changes = events
                .iter()
                .filter(|e| {
                    of(e, ep) && e.get("type").and_then(Value::as_str) == Some("host_state")
                })
                .count();
            serde_json::json!({"clock_sync": cs, "power": pw, "pacing": pc, "changes": changes})
        };
        state.insert(ep.to_string(), v);
    }
    (suspend.into(), state.into())
}

pub fn run(cmd: TraceCmd) -> Result<ExitCode, String> {
    match cmd {
        TraceCmd::Check { file, json } => {
            let r = read(&file, false);
            let ok = r.is_ok();
            if json {
                let v = match &r {
                    Ok((f, rep)) => {
                        serde_json::json!({"valid": true, "sections": f.sections.len(), "index_verified": rep.index_verified, "content_digest": rep.content_digest, "unknown_sections": rep.unknown_sections})
                    }
                    Err(e) => serde_json::json!({"valid": false, "error": e}),
                };
                println!("{v}");
            } else {
                match &r {
                    Ok((f, rep)) => println!(
                        "valid: {} sections, index {}, content_digest {}",
                        f.sections.len(),
                        if rep.index_verified {
                            "verified"
                        } else {
                            "absent"
                        },
                        rep.content_digest
                    ),
                    Err(e) => println!("invalid: {e}"),
                }
            }
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        TraceCmd::Info { file, json } => {
            let (f, rep) = read(&file, true)?;
            let meta = f
                .sections
                .first()
                .and_then(|s| s.head())
                .cloned()
                .unwrap_or_default();
            let meta = Value::Map(meta);
            let mut tables: std::collections::BTreeMap<String, (usize, usize)> =
                std::collections::BTreeMap::new();
            let mut kinds: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            for s in &f.sections {
                *kinds.entry(s.kind_str()).or_default() += 1;
                for t in s.tables() {
                    let attrs = t
                        .attrs()
                        .and_then(|a| a.get("dir").or(a.get("endpoint")))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let e = tables
                        .entry(if attrs.is_empty() {
                            t.name.clone()
                        } else {
                            format!("{}[{attrs}]", t.name)
                        })
                        .or_default();
                    e.0 += 1;
                    e.1 += t.rows;
                }
            }
            let events = f
                .sections
                .iter()
                .filter(|s| &s.kind == b"EVNT")
                .map(|s| {
                    s.get("events")
                        .and_then(Value::as_array)
                        .map_or(0, <[Value]>::len)
                })
                .sum::<usize>();
            let flows = f
                .sections
                .iter()
                .filter(|s| &s.kind == b"FLOW")
                .map(|s| {
                    s.get("flows")
                        .and_then(Value::as_array)
                        .map_or(0, <[Value]>::len)
                })
                .sum::<usize>();
            let p = path_facts(&f);
            let (host_suspend, host_state) = host_facts(&f, &meta);
            let summary = serde_json::json!({
                "file": file.display().to_string(),
                "ptf_version": format!("{}.{}", f.major, f.minor),
                "kind": meta.get("kind").and_then(Value::as_str),
                "trace_id": meta.get("trace_id").and_then(Value::as_str),
                "profile": meta.get("profile").or(meta.get("session").and_then(|s| s.get("profile"))).and_then(Value::as_str),
                "network_class": meta.get("network").and_then(|n| n.get("class")).and_then(Value::as_str),
                "complete": meta.get("complete").and_then(Value::as_bool),
                "merge_checks": meta.get("merge_checks").map(pt_format::jsonl::cbor_to_json),
                "host_drops": p["host_drops"],
                "local_qdisc_drops": p["local_qdisc_drops"],
                "tx_timestamps": p["tx_timestamps"],
                "overlay": p["overlay"],
                "host_suspend": host_suspend,
                "host_state": host_state,
                "redaction": meta.get("redaction").and_then(Value::as_str),
                "tool_commit": meta.get("tool").and_then(|t| t.get("git_commit")).and_then(Value::as_str),
                "sections": kinds,
                "tables": tables.iter().map(|(k, (c, r))| (k.clone(), serde_json::json!({"chunks": c, "rows": r}))).collect::<serde_json::Map<_, _>>(),
                "flows": flows,
                "events": events,
                "content_digest": rep.content_digest,
                "index_verified": rep.index_verified,
                "stopped": rep.stopped.map(|(o, r)| format!("at byte {o}: {r}")),
            });
            if json {
                println!("{summary}");
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_default()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        TraceCmd::Dump { file, out } => {
            let (f, _) = read(&file, false)?;
            let text = pt_format::jsonl::dump(&f);
            match out {
                Some(p) => std::fs::write(&p, text).map_err(|e| e.to_string())?,
                None => print!("{text}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        TraceCmd::Redact { file, level, out } => {
            let (f, _) = read(&file, false)?;
            let lvl = pt_format::redact::Level::parse(&level).ok_or("bad level")?;
            let (red, rep) = pt_format::redact::redact(&f, lvl).map_err(|e| e.to_string())?;
            // Raw data changed: regenerate the derived layer (spec P14).
            let red = pt_derive::apply(&red, &crate::derive_tool());
            let mut buf = Vec::new();
            let d = pt_format::write(&red, &WriteOptions::canonical(), &mut buf)
                .map_err(|e| e.to_string())?;
            std::fs::write(&out, buf).map_err(|e| e.to_string())?;
            println!(
                "{} level={level} removed_pointers={} removed_columns={} shifted_columns={} content_digest={d}",
                out.display(),
                rep.pointers,
                rep.columns,
                rep.shifted_columns
            );
            Ok(ExitCode::SUCCESS)
        }
        TraceCmd::Load { file, out } => {
            let text = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
            let f = pt_format::jsonl::load(&text).map_err(|e| e.to_string())?;
            let mut buf = Vec::new();
            let d = pt_format::write(&f, &WriteOptions::canonical(), &mut buf)
                .map_err(|e| e.to_string())?;
            std::fs::write(&out, buf).map_err(|e| e.to_string())?;
            println!("{} content_digest={d}", out.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(rel: &str) -> pt_format::PtfFile {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance")
            .join(rel);
        read(&p, false).unwrap().0
    }

    /// `trace info` shows the overlay fact of a 1.2 trace (cli.md).
    #[test]
    fn info_shows_the_overlay() {
        let p = path_facts(&corpus("v1.2/valid-1-2-additions.ptf"));
        assert_eq!(p["overlay"]["overlay"], true);
        assert_eq!(p["overlay"]["provider"], "tailscale");
    }

    /// `trace info` shows each endpoint's host state and suspended time (cli.md, PTF 1.3).
    #[test]
    fn info_shows_host_state_and_suspend() {
        let f = corpus("v1.3/valid-1-3-additions.ptf");
        let meta = Value::Map(f.sections[0].head().cloned().unwrap_or_default());
        let (suspend, state) = host_facts(&f, &meta);
        assert_eq!(suspend["a"]["events"], 0);
        assert_eq!(state["a"]["clock_sync"]["status"], "unknown");
        assert_eq!(state["a"]["changes"], 1);
        assert_eq!(state["b"]["clock_sync"]["status"], "synced");
        assert_eq!(state["b"]["power"]["source"], "none");
        assert_eq!(state["b"]["changes"], 0);
        // A trace captured before 1.3 has no host state.
        let f = corpus("v1.2/valid-1-2-additions.ptf");
        let meta = Value::Map(f.sections[0].head().cloned().unwrap_or_default());
        assert!(host_facts(&f, &meta).1["a"].is_null());
    }

    /// An unknown field shows its status and reason and no counts, never 0; the transmit
    /// time sources are counted per direction.
    #[test]
    fn info_shows_unknown_counters_and_tx_sources() {
        let f = corpus("v1.0-real/smoke-ipv6-netns-anonymous.ptf");
        let f = pt_derive::apply(&f, &crate::derive_tool());
        let p = path_facts(&f);
        let q = &p["local_qdisc_drops"]["a_to_b"];
        assert_eq!(q["status"], "unknown");
        assert_eq!(q["reason"], "no qdisc counters recorded");
        assert!(q.get("drops").is_none());
        let h = &p["host_drops"]["b_to_a"];
        assert_eq!(h["status"], "unknown");
        assert!(h.get("packets").is_none());
        assert!(p["tx_timestamps"]["a_to_b"]["snd"].as_u64().unwrap() > 0);
        assert_eq!(p["overlay"]["status"], "unknown");
    }
}
