//! Commit-pinned experiments (`docs/evidence/`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::git;

pub const EVIDENCE_DIR: &str = "docs/evidence";

/// `experiment.toml`: written by hand before the run.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Experiment {
    pub id: String,
    pub title: String,
    pub hypothesis: String,
    pub command: String,
    #[serde(default)]
    pub covers: Vec<String>,
    #[serde(default)]
    pub requirements: Vec<String>,
    #[serde(default)]
    pub supersedes: Vec<String>,
}

/// `manifest.toml`: written by `evidence run`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    pub verdict: String,
    pub pinned_commit: String,
    pub tree_clean: bool,
    pub command: String,
    pub exit_code: i32,
    pub started_utc: String,
    pub duration_s: f64,
    pub host: Host,
    /// Relative path (from the experiment directory) → BLAKE3 hex.
    pub artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub os: String,
    pub kernel: String,
    pub cpu: String,
    pub cpus: usize,
    pub rustc: String,
}

/// A loaded experiment directory.
#[derive(Debug)]
pub struct Entry {
    pub dir: PathBuf,
    pub experiment: Experiment,
    pub manifest: Option<Manifest>,
}

pub fn load_all(root: &Path) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    let base = root.join(EVIDENCE_DIR);
    if !base.exists() {
        return Ok(out);
    }
    let mut dirs: Vec<_> = fs::read_dir(&base)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && dir_name(p).starts_with("EXP-"))
        .collect();
    dirs.sort();
    for dir in dirs {
        let exp_path = dir.join("experiment.toml");
        let experiment: Experiment = toml::from_str(
            &fs::read_to_string(&exp_path)
                .with_context(|| format!("reading {}", exp_path.display()))?,
        )
        .with_context(|| format!("parsing {}", exp_path.display()))?;
        let man_path = dir.join("manifest.toml");
        let manifest = if man_path.exists() {
            Some(
                toml::from_str(&fs::read_to_string(&man_path)?)
                    .with_context(|| format!("parsing {}", man_path.display()))?,
            )
        } else {
            None
        };
        out.push(Entry {
            dir,
            experiment,
            manifest,
        });
    }
    Ok(out)
}

pub fn dir_name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The `EXP-NNNN` (or `EXP-NNNN-rK`) id prefix of a directory name.
pub fn id_of_dir(name: &str) -> &str {
    // EXP-0001-slug or EXP-0001-r2-slug
    let mut end = "EXP-0000".len().min(name.len());
    if name[end..].starts_with("-r")
        && name[end + 2..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit())
    {
        end += 2;
        end += name[end..].chars().take_while(char::is_ascii_digit).count();
    }
    &name[..end]
}

pub fn new(root: &Path, slug: &str) -> Result<()> {
    if slug.is_empty()
        || !slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("slug must be kebab-case ascii: {slug:?}");
    }
    let base = root.join(EVIDENCE_DIR);
    let next = load_all(root)?
        .iter()
        .filter_map(|e| e.experiment.id.get(4..8)?.parse::<u32>().ok())
        .max()
        .unwrap_or(0)
        + 1;
    let id = format!("EXP-{next:04}");
    let dir = base.join(format!("{id}-{slug}"));
    fs::create_dir_all(&dir)?;
    let template = base.join("TEMPLATE");
    for name in ["experiment.toml", "README.md"] {
        let text = fs::read_to_string(template.join(name))?.replace("EXP-NNNN", &id);
        fs::write(dir.join(name), text)?;
    }
    println!("{}", dir.display());
    Ok(())
}

pub fn run(root: &Path, id: &str) -> Result<()> {
    let entry = load_all(root)?
        .into_iter()
        .find(|e| e.experiment.id == id)
        .with_context(|| format!("no experiment with id {id} under {EVIDENCE_DIR}"))?;
    if entry.manifest.is_some() {
        bail!(
            "{id} already has a manifest; completed experiments are immutable. \
             Create a superseding experiment instead (see docs/evidence/README.md)"
        );
    }
    let dirty = git::dirty_paths(root)?;
    if !dirty.is_empty() {
        bail!(
            "working tree is dirty; commit first so the experiment can be pinned:\n  {}",
            dirty.join("\n  ")
        );
    }
    let commit = git::head(root)?;
    let artifacts = entry.dir.join("artifacts");
    if artifacts.exists() {
        bail!(
            "{} exists on a clean tree; remove it from git history? refusing",
            artifacts.display()
        );
    }
    fs::create_dir_all(&artifacts)?;

    eprintln!(
        "[xtask] running {id} ({}) at {commit}\n[xtask] hypothesis: {}\n[xtask] $ {}",
        entry.experiment.title, entry.experiment.hypothesis, entry.experiment.command
    );
    let started_utc = utc_now();
    let t0 = Instant::now();
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&entry.experiment.command)
        .current_dir(root)
        .env("PT_EVIDENCE_OUT", &artifacts)
        .env("PT_EVIDENCE_ID", id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = tee(
        child.stdout.take().expect("piped"),
        artifacts.join("stdout.log"),
        false,
    );
    let stderr = tee(
        child.stderr.take().expect("piped"),
        artifacts.join("stderr.log"),
        true,
    );
    let status = child.wait()?;
    stdout.join().expect("tee thread")?;
    stderr.join().expect("tee thread")?;
    let duration_s = t0.elapsed().as_secs_f64();
    let exit_code = status.code().unwrap_or(-1);

    let mut verdict = match exit_code {
        0 => "pass",
        1 => "fail",
        3 => "partial",
        _ => {
            bail!(
                "experiment command errored (exit {exit_code}); no manifest written. \
                 Inspect {} and delete it before retrying",
                artifacts.display()
            )
        }
    }
    .to_string();
    let verdict_file = artifacts.join("verdict.txt");
    if verdict_file.exists() {
        let v = fs::read_to_string(&verdict_file)?.trim().to_string();
        if !["pass", "fail", "partial"].contains(&v.as_str()) {
            bail!("verdict.txt must be pass|fail|partial, got {v:?}");
        }
        if verdict == "pass" || v != "pass" {
            verdict = v;
        }
    }

    // The experiment must not modify tracked or untracked files outside its own directory.
    let rel_dir = entry.dir.strip_prefix(root)?.to_string_lossy().into_owned();
    let stray: Vec<_> = git::dirty_paths(root)?
        .into_iter()
        .filter(|p| !p.starts_with(&rel_dir))
        .collect();
    if !stray.is_empty() {
        bail!(
            "experiment modified files outside {rel_dir}:\n  {}",
            stray.join("\n  ")
        );
    }

    let manifest = Manifest {
        id: id.to_string(),
        verdict: verdict.clone(),
        pinned_commit: commit,
        tree_clean: true,
        command: entry.experiment.command.clone(),
        exit_code,
        started_utc,
        duration_s: (duration_s * 1000.0).round() / 1000.0,
        host: host_info(),
        artifacts: hash_tree(&entry.dir, &artifacts)?,
    };
    let text = format!(
        "# Generated by `cargo xtask evidence run {id}`. Do not edit.\n{}",
        toml::to_string(&manifest)?
    );
    fs::write(entry.dir.join("manifest.toml"), text)?;
    eprintln!(
        "[xtask] {id}: verdict = {verdict}; write README.md, then commit `docs(evidence): {id} ...`"
    );
    Ok(())
}

fn tee(
    mut src: impl Read + Send + 'static,
    path: PathBuf,
    to_stderr: bool,
) -> std::thread::JoinHandle<Result<()>> {
    std::thread::spawn(move || {
        let mut file = fs::File::create(path)?;
        let mut buf = [0u8; 8192];
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            if to_stderr {
                std::io::stderr().write_all(&buf[..n])?;
            } else {
                std::io::stdout().write_all(&buf[..n])?;
            }
        }
        Ok(())
    })
}

/// BLAKE3 of every file under `dir`, keyed by path relative to `base`, sorted.
pub fn hash_tree(base: &Path, dir: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d)? {
            let p = e?.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(base)?.to_string_lossy().into_owned();
                out.insert(rel, blake3::hash(&fs::read(&p)?).to_hex().to_string());
            }
        }
    }
    Ok(out)
}

fn host_info() -> Host {
    let os = fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into());
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("model name")
                    .map(|v| v.trim_start_matches([' ', '\t', ':']).to_string())
            })
        })
        .unwrap_or_else(|| "unknown".into());
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let rustc = Command::new("rustc")
        .arg("-V")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    Host {
        os,
        kernel,
        cpu,
        cpus,
        rustc,
    }
}

/// Current UTC time as RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_736), (2026, 10, 10));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    }

    #[test]
    fn ids_from_dir_names() {
        assert_eq!(id_of_dir("EXP-0001-format-bakeoff"), "EXP-0001");
        assert_eq!(id_of_dir("EXP-0012-r2-roundtrip"), "EXP-0012-r2");
        assert_eq!(id_of_dir("EXP-0003-rate-step"), "EXP-0003");
    }
}
