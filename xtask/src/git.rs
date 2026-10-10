//! Thin wrappers over the `git` CLI.

use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};

/// Run `git <args>` in `dir` and return stdout. Fails on non-zero exit.
pub fn output(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").current_dir(dir).args(args).output()?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// Run `git <args>` in `dir` and return whether it exited successfully.
pub fn succeeds(dir: &Path, args: &[&str]) -> Result<bool> {
    Ok(Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()?
        .status
        .success())
}

/// Paths reported by `git status --porcelain` (tracked changes and untracked, non-ignored files).
pub fn dirty_paths(dir: &Path) -> Result<Vec<String>> {
    Ok(
        output(dir, &["status", "--porcelain", "--untracked-files=all"])?
            .lines()
            .filter(|l| l.len() > 3)
            .map(|l| l[3..].to_string())
            .collect(),
    )
}

pub fn head(dir: &Path) -> Result<String> {
    Ok(output(dir, &["rev-parse", "HEAD"])?.trim().to_string())
}
