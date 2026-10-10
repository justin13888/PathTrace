//! Repository automation for PathTrace.
//!
//! - `evidence new <slug>`: scaffold the next `docs/evidence/EXP-NNNN-<slug>/` from the template.
//! - `evidence run <EXP-NNNN>`: run an experiment on a clean tree and pin it to `HEAD`.
//! - `audit [--release]`: verify the requirement → design → ADR → evidence chain.
//!
//! The rules enforced here are documented in `docs/README.md`, `docs/spec/README.md` and
//! `docs/evidence/README.md`.

mod audit;
mod evidence;
mod git;

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
        Command::Audit { release } => {
            let report = audit::audit(&root)?;
            report.print();
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
