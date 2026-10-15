//! Repository automation for PathTrace.
//!
//! - `evidence new <slug>`: scaffold the next `docs/evidence/EXP-NNNN-<slug>/` from the template.
//! - `evidence run <EXP-NNNN>`: run an experiment on a clean tree and pin it to `HEAD`.
//! - `audit [--release]`: verify the requirement → design → ADR → evidence chain.
//! - `groundtruth [scenario]`: ground-truth recovery experiments in network namespaces.
//!
//! The rules enforced here are documented in `docs/README.md`, `docs/spec/README.md` and
//! `docs/evidence/README.md`.

mod audit;
mod corpus;
mod evidence;
mod git;
mod groundtruth;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "xtask", about = "PathTrace repository automation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage commit-pinned experiments under docs/evidence/.
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
    /// Ground-truth recovery experiments in network namespaces (`all` or one scenario).
    Groundtruth {
        #[arg(default_value = "all")]
        which: String,
        /// Scenarios run in parallel.
        #[arg(long, default_value_t = 4)]
        jobs: usize,
    },
    /// Regenerate the PTF conformance corpus (conformance/v1.0, v1.1 and v1.2).
    Corpus,
    /// Check the requirement → design → ADR → evidence chain.
    Audit {
        /// Treat stale evidence as an error (used for release tags).
        #[arg(long)]
        release: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    /// Scaffold the next experiment directory from docs/evidence/TEMPLATE.
    New { slug: String },
    /// Run an experiment on a clean tree and write its manifest.
    Run { id: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = repo_root()?;
    match cli.command {
        Command::Evidence { command } => match command {
            EvidenceCommand::New { slug } => evidence::new(&root, &slug),
            EvidenceCommand::Run { id } => evidence::run(&root, &id),
        },
        Command::Groundtruth { which, jobs } => {
            if !groundtruth::main(&root, &which, jobs)? {
                std::process::exit(1);
            }
            Ok(())
        }
        Command::Corpus => corpus::generate(&root),
        Command::Audit { release } => {
            let report = audit::audit(&root)?;
            report.print(release);
            if report.failed(release) {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

fn repo_root() -> Result<PathBuf> {
    let out = git::output(&std::env::current_dir()?, &["rev-parse", "--show-toplevel"])
        .context("xtask must run inside the PathTrace git repository")?;
    Ok(PathBuf::from(out.trim()))
}
