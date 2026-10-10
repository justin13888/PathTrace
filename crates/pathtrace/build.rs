//! Embed the git commit and dirty flag so traces record exactly which code produced them
//! (REQ-FMT-008). Falls back to "unknown" outside a git checkout (e.g. crates.io tarballs).

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let commit = std::env::var("PATHTRACE_GIT_COMMIT")
        .ok()
        .or_else(|| git(&["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());
    let dirty = std::env::var("PATHTRACE_GIT_DIRTY")
        .ok()
        .unwrap_or_else(|| {
            git(&["status", "--porcelain", "--untracked-files=no"])
                .map_or("unknown".into(), |s| (!s.is_empty()).to_string())
        });
    println!("cargo:rustc-env=PATHTRACE_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=PATHTRACE_GIT_DIRTY={dirty}");
    println!("cargo:rerun-if-env-changed=PATHTRACE_GIT_COMMIT");
    println!("cargo:rerun-if-env-changed=PATHTRACE_GIT_DIRTY");
    if let Some(dir) = git(&["rev-parse", "--git-dir"]) {
        println!("cargo:rerun-if-changed={dir}/HEAD");
        println!("cargo:rerun-if-changed={dir}/index");
    }
}
