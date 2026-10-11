//! `pathtrace`: record what a network path does to packets, into PTF traces.
//!
//! Command reference: docs/design/cli.md. Exit codes (REQ-CLI-004): 0 success, 1 failure or
//! invalid input, 2 usage error, 3 partial result.

mod doctor;
mod trace_cmd;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use pt_probe::config;
use pt_probe::plan::Profile;
use pt_probe::session::{self, NetTags, ProbeOpts, ServeOpts, ToolInfo};

pub const NETWORK_CLASSES: &[&str] = &[
    "home",
    "office",
    "hotel-wifi",
    "cafe",
    "airport",
    "cellular-4g",
    "cellular-5g",
    "train",
    "in-flight",
    "tether",
    "satellite",
    "lab",
    "other",
];

#[derive(Debug, Parser)]
#[command(
    name = "pathtrace",
    version,
    about = "Record what a network path does to packets, into PTF traces"
)]
struct Cli {
    /// Configuration directory (keys, authorized initiators, responders).
    #[arg(long, global = true, env = "PATHTRACE_CONFIG_DIR")]
    config_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Create this machine's key pair (idempotent) and print the public key.
    Keygen {
        /// Replace an existing key (invalidates existing pairings).
        #[arg(long)]
        force: bool,
    },
    /// Responder: authorise an initiator public key; prints the pairing string for it.
    Authorize {
        /// Initiator public key (64 hex characters, from `pathtrace keygen` on the initiator).
        pubkey: String,
        /// Label for this initiator (no spaces).
        #[arg(long)]
        name: String,
    },
    /// Initiator: manage known responders.
    Responder {
        #[command(subcommand)]
        cmd: ResponderCmd,
    },
    /// Run the responder (public VM side).
    Serve(ServeArgs),
    /// Run a measurement session against a responder and write a trace.
    Probe(ProbeArgs),
    /// Merge observation logs into a trace (offline).
    Merge {
        /// Initiator log (`*.a.ptflog`).
        log_a: PathBuf,
        /// Responder log (`*.b.ptflog`), if available.
        log_b: Option<PathBuf>,
        #[arg(short, long)]
        out: PathBuf,
    },
    /// Re-derive the path model (PATH, SERS, PLCY, VALD) from a trace's raw layer.
    Derive {
        trace: PathBuf,
        /// Output file (default: rewrite the input in place, atomically).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Export a trace to another tool's format.
    Export {
        #[command(subcommand)]
        cmd: ExportCmd,
    },
    /// Import another tool's trace as PTF.
    Import {
        #[command(subcommand)]
        cmd: ImportCmd,
    },
    /// Download a responder log for a finished session.
    Fetch {
        #[arg(long)]
        responder: String,
        /// Session id (hex, from the probe output).
        #[arg(long)]
        session: String,
        /// Fetch token (hex, from the probe output).
        #[arg(long)]
        token: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Inspect, validate and convert PTF files.
    Trace {
        #[command(subcommand)]
        cmd: trace_cmd::TraceCmd,
    },
    /// Check local prerequisites and responder reachability before a field session.
    Doctor {
        /// Responder name to test reachability against.
        responder: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ExportCmd {
    /// Print netem qdisc arguments reproducing each direction's static summary.
    Netem { trace: PathBuf },
    /// Write Mahimahi up/down traces (1504-byte opportunities, ms timestamps).
    Mahimahi {
        trace: PathBuf,
        /// Output prefix: writes <prefix>.up (a->b) and <prefix>.down (b->a).
        #[arg(short, long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ImportCmd {
    /// Import Mahimahi traces (capacity only; everything else unknown).
    Mahimahi {
        /// Uplink trace (a->b).
        up: PathBuf,
        /// Downlink trace (b->a).
        down: Option<PathBuf>,
        #[arg(short, long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ResponderCmd {
    /// Add a responder: name, host[:port] (default port 4433) and the pairing string.
    Add {
        name: String,
        addr: String,
        pairing: String,
    },
    /// List known responders.
    List,
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// UDP/TCP port for control, probe flows and log fetch.
    #[arg(long, default_value_t = 4433)]
    port: u16,
    /// Do not listen on UDP/TCP 443 and TCP 80 (class probes then report them unreachable).
    #[arg(long)]
    no_class_ports: bool,
    /// Directory for session logs and the TLS certificate.
    #[arg(long, env = "PATHTRACE_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Hard per-session data cap for traffic this responder sends, bytes.
    #[arg(long, default_value_t = 1_000_000_000)]
    data_cap: u64,
    /// Hard sending-rate cap, bit/s.
    #[arg(long, default_value_t = 500_000_000)]
    rate_cap: u64,
    /// Delete session logs older than this.
    #[arg(long, default_value_t = 14)]
    retention_days: u64,
    /// Exit after this many sessions (0 = run forever).
    #[arg(long, default_value_t = 0)]
    max_sessions: u64,
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Debug, Args)]
struct ProbeArgs {
    /// Responder name (see `pathtrace responder list`).
    responder: String,
    /// Network class of the access network you are on.
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(NETWORK_CLASSES))]
    class: String,
    /// Free-text label (e.g. "Hotel Foo lobby"); identifying, removed by redaction.
    #[arg(long, default_value = "")]
    label: String,
    /// Mobility during the session.
    #[arg(long, default_value = "static", value_parser = ["static", "walking", "vehicle", "train", "flight"])]
    mobility: String,
    /// Extra tags (repeatable).
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Profile; `auto` picks `light` on metered connections, else `standard`.
    #[arg(long, default_value = "auto", value_parser = ["auto", "smoke", "light", "standard", "deep"])]
    profile: String,
    /// Tracking duration for the deep profile, seconds.
    #[arg(long)]
    track_secs: Option<u64>,
    /// Output directory for logs and the trace.
    #[arg(long, default_value = ".")]
    out: PathBuf,
    /// Prefer IPv6 if the responder has both families.
    #[arg(long)]
    ipv6: bool,
    /// Hard sending-rate cap, bit/s.
    #[arg(long, default_value_t = 500_000_000)]
    rate_cap: u64,
    #[arg(short, long)]
    quiet: bool,
}

pub fn derive_tool() -> pt_derive::Tool {
    let t = tool_info();
    pt_derive::Tool {
        version: t.version,
        git_commit: t.git_commit,
        git_dirty: t.git_dirty,
    }
}

pub fn tool_info() -> ToolInfo {
    ToolInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_commit: env!("PATHTRACE_GIT_COMMIT").to_string(),
        git_dirty: env!("PATHTRACE_GIT_DIRTY") == "true",
    }
}

fn find_responder(dir: &std::path::Path, name: &str) -> Result<config::Responder, String> {
    let all = config::load_responders(dir).map_err(|e| e.to_string())?;
    all.into_iter()
        .find(|r| r.name == name)
        .ok_or_else(|| format!("unknown responder {name:?}; add it with `pathtrace responder add`"))
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let cfg = cli
        .config_dir
        .clone()
        .unwrap_or_else(config::default_config_dir);
    match cli.cmd {
        Cmd::Keygen { force } => {
            let (kp, new) = config::keygen(&cfg, force).map_err(|e| e.to_string())?;
            if new {
                eprintln!("created {}", cfg.join("key").display());
            }
            println!("{}", config::hex(&kp.public));
        }
        Cmd::Authorize { pubkey, name } => {
            let pk = config::unhex32(pubkey.trim()).map_err(|e| e.to_string())?;
            let pairing = config::authorize(&cfg, &pk, &name).map_err(|e| e.to_string())?;
            eprintln!(
                "authorised {name}; on the initiator run:\n  pathtrace responder add <name> <this-host> {pairing}"
            );
            println!("{pairing}");
        }
        Cmd::Responder { cmd } => match cmd {
            ResponderCmd::Add {
                name,
                addr,
                pairing,
            } => {
                config::add_responder(&cfg, &name, &addr, &pairing).map_err(|e| e.to_string())?;
                eprintln!("added responder {name} ({addr})");
            }
            ResponderCmd::List => {
                for r in config::load_responders(&cfg).map_err(|e| e.to_string())? {
                    println!("{} {}", r.name, r.addr);
                }
            }
        },
        Cmd::Serve(a) => {
            let opts = ServeOpts {
                config_dir: cfg,
                state_dir: a.state_dir.unwrap_or_else(config::default_state_dir),
                main_port: a.port,
                class_ports: !a.no_class_ports,
                data_cap: a.data_cap,
                rate_cap_bps: a.rate_cap,
                tool: tool_info(),
                retention_days: a.retention_days,
                max_sessions: a.max_sessions,
                verbose: !a.quiet,
            };
            session::serve(&opts).map_err(|e| e.to_string())?;
        }
        Cmd::Probe(a) => return probe(cfg, a),
        Cmd::Merge { log_a, log_b, out } => {
            let (file, r) = pt_probe::merge::merge_file(&log_a, log_b.as_deref(), &tool_info())
                .map_err(|e| e.to_string())?;
            let file = pt_derive::apply(&file, &derive_tool());
            let digest = pt_probe::merge::write_trace(&file, &out).map_err(|e| e.to_string())?;
            println!("{} content_digest={digest}", out.display());
            if log_b.is_none() || r.logs.iter().any(|l| l.stopped.is_some()) {
                return Ok(ExitCode::from(3));
            }
        }
        Cmd::Fetch {
            responder,
            session,
            token,
            out,
        } => {
            let r = find_responder(&cfg, &responder)?;
            let (dst, _) = session::resolve(&r.addr, false).map_err(|e| e.to_string())?;
            let sid = u32::from_str_radix(session.trim_start_matches("0x"), 16)
                .map_err(|e| e.to_string())?;
            let tok = config::unhex32(&token).map_err(|e| e.to_string())?;
            // The TLS certificate is unknown offline; fetch over the plain main port.
            let n = session::fetch_with_retry(dst.ip(), &[], sid, &tok, &out, true)
                .map_err(|e| e.to_string())?;
            println!("{} ({n} bytes)", out.display());
        }
        Cmd::Trace { cmd } => return trace_cmd::run(cmd),
        Cmd::Derive { trace, out } => {
            let f = pt_probe::merge::read_trace(&trace).map_err(|e| e.to_string())?;
            let f = pt_derive::apply(&f, &derive_tool());
            let out = out.unwrap_or(trace);
            let d = pt_probe::merge::write_trace(&f, &out).map_err(|e| e.to_string())?;
            println!("{} content_digest={d}", out.display());
        }
        Cmd::Export { cmd } => match cmd {
            ExportCmd::Netem { trace } => {
                let f = pt_probe::merge::read_trace(&trace).map_err(|e| e.to_string())?;
                for dir in ["a_to_b", "b_to_a"] {
                    match pt_derive::export::netem_args(&f, dir) {
                        Some(a) => println!("{dir}: tc qdisc add dev <dev> root {a}"),
                        None => println!("{dir}: (no summary; run `pathtrace derive` first)"),
                    }
                }
            }
            ExportCmd::Mahimahi { trace, out } => {
                let f = pt_probe::merge::read_trace(&trace).map_err(|e| e.to_string())?;
                for (dir, ext) in [("a_to_b", "up"), ("b_to_a", "down")] {
                    let (lines, notes) = pt_derive::export::mahimahi_lines(&f, dir);
                    for n in notes {
                        eprintln!("note: {n}");
                    }
                    if lines.is_empty() {
                        continue;
                    }
                    let p = out.with_extension(ext);
                    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
                    std::fs::write(&p, text).map_err(|e| e.to_string())?;
                    println!("{}", p.display());
                }
            }
        },
        Cmd::Import { cmd } => match cmd {
            ImportCmd::Mahimahi { up, down, out } => {
                let u = std::fs::read_to_string(&up).map_err(|e| e.to_string())?;
                let d = down
                    .as_ref()
                    .map(std::fs::read_to_string)
                    .transpose()
                    .map_err(|e| e.to_string())?;
                let label = up
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let f = pt_derive::export::import_mahimahi(&u, d.as_deref(), &label)?;
                let digest = pt_probe::merge::write_trace(&f, &out).map_err(|e| e.to_string())?;
                println!("{} content_digest={digest}", out.display());
            }
        },
        Cmd::Doctor { responder, json } => {
            let r = responder.map(|n| find_responder(&cfg, &n)).transpose()?;
            return Ok(doctor::run(&cfg, r.as_ref(), json));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn probe(cfg: PathBuf, a: ProbeArgs) -> Result<ExitCode, String> {
    let responder = find_responder(&cfg, &a.responder)?;
    let profile_name = if a.profile == "auto" {
        let (dst, _) = session::resolve(&responder.addr, a.ipv6).map_err(|e| e.to_string())?;
        let ip = pt_sys::netif::local_addr_for(dst).map_err(|e| e.to_string())?;
        let iface = pt_sys::netif::iface_with_addr(ip)
            .ok()
            .flatten()
            .unwrap_or_default();
        let m = pt_probe::context::metered(&iface);
        let chosen = pt_probe::plan::auto_profile(&m);
        if chosen == "light" {
            eprintln!(
                "[pathtrace] {iface} is metered ({m}); using the light profile (override with --profile)"
            );
            chosen.to_string()
        } else {
            chosen.to_string()
        }
    } else {
        a.profile.clone()
    };
    let profile = Profile::by_name(&profile_name).ok_or("unknown profile")?;
    let opts = ProbeOpts {
        config_dir: cfg,
        out_dir: a.out.clone(),
        responder,
        profile,
        net: NetTags {
            class: a.class,
            label: a.label,
            mobility: a.mobility,
            tags: a.tags,
        },
        tool: tool_info(),
        prefer_v6: a.ipv6,
        rate_cap_bps: a.rate_cap,
        track_s: a.track_secs,
        verbose: !a.quiet,
    };
    let outcome = session::run_probe(&opts).map_err(|e| e.to_string())?;
    let trace = a.out.join(format!("{}.ptf", outcome.trace_id));
    let mut partial = outcome.log_b.is_none() || !outcome.notes.is_empty();
    let merged =
        pt_probe::merge::merge_file(&outcome.log_a, outcome.log_b.as_deref(), &tool_info())
            .and_then(|(f, r)| {
                let f = pt_derive::apply(&f, &derive_tool());
                let d = pt_probe::merge::write_trace(&f, &trace)?;
                Ok((d, r))
            });
    match merged {
        Ok((digest, r)) => {
            println!("trace: {}", trace.display());
            println!("content_digest: {digest}");
            for (dir, n) in &r.pkt_rows {
                println!("packets {dir}: {n}");
            }
            for (dir, c) in &r.stamps {
                if c.implausible > 0 {
                    eprintln!(
                        "warning: {dir}: {} of {} TX stamp joins are implausible in time (see probe.md §4.1)",
                        c.implausible, c.joined
                    );
                }
            }
            if r.logs.iter().any(|l| l.stopped.is_some()) {
                partial = true;
            }
        }
        Err(e) => {
            eprintln!("merge failed: {e}; logs kept: {}", outcome.log_a.display());
            partial = true;
        }
    }
    println!("session: {:08x}", outcome.session);
    for n in &outcome.notes {
        eprintln!("note: {n}");
    }
    Ok(if partial {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    })
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
