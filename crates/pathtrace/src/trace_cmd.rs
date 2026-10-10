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
            let summary = serde_json::json!({
                "file": file.display().to_string(),
                "ptf_version": format!("{}.{}", f.major, f.minor),
                "kind": meta.get("kind").and_then(Value::as_str),
                "trace_id": meta.get("trace_id").and_then(Value::as_str),
                "profile": meta.get("profile").or(meta.get("session").and_then(|s| s.get("profile"))).and_then(Value::as_str),
                "network_class": meta.get("network").and_then(|n| n.get("class")).and_then(Value::as_str),
                "complete": meta.get("complete").and_then(Value::as_bool),
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
