//! Mechanical audit of the requirement → design → ADR → evidence chain.
//!
//! Rules are specified in `docs/spec/README.md` and `docs/evidence/README.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::evidence::{self, Entry};
use crate::git;

const STATUSES: &[&str] = &["planned", "met", "deferred", "user-acceptance", "dropped"];

#[derive(Debug, Default)]
pub struct Requirement {
    pub id: String,
    pub file: String,
    pub fields: BTreeMap<String, String>,
}

impl Requirement {
    fn list(&self, key: &str) -> Vec<String> {
        self.fields
            .get(key)
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && s != "—" && s != "-")
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub requirements: usize,
    pub by_status: BTreeMap<String, usize>,
    pub experiments: usize,
    pub errors: Vec<String>,
    pub stale: Vec<String>,
    pub pending: Vec<String>,
}

impl Report {
    pub fn failed(&self, release: bool) -> bool {
        !self.errors.is_empty() || (release && !(self.stale.is_empty() && self.pending.is_empty()))
    }

    pub fn print(&self, release: bool) {
        println!(
            "audit: {} requirements {:?}, {} experiments",
            self.requirements, self.by_status, self.experiments
        );
        for s in &self.stale {
            println!("STALE   {s}");
        }
        for p in &self.pending {
            println!("PENDING {p}");
        }
        for e in &self.errors {
            println!("ERROR   {e}");
        }
        if self.errors.is_empty() {
            println!("audit: chain intact");
        }
        if release && self.failed(true) {
            println!("audit: release blocked by stale or pending evidence");
        }
    }
}

pub fn parse_requirements(root: &Path) -> Result<Vec<Requirement>> {
    let dir = root.join("docs/spec");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let n = evidence::dir_name(p);
            n.starts_with("REQ-") && n.ends_with(".md")
        })
        .collect();
    files.sort();
    let mut out = Vec::new();
    for path in files {
        let file = path.strip_prefix(root)?.to_string_lossy().into_owned();
        let mut current: Option<Requirement> = None;
        for line in fs::read_to_string(&path)?.lines() {
            if let Some(rest) = line.strip_prefix("### ") {
                out.extend(current.take());
                if rest.starts_with("REQ-") {
                    let id = rest.split(':').next().unwrap_or(rest).trim().to_string();
                    current = Some(Requirement {
                        id,
                        file: file.clone(),
                        ..Default::default()
                    });
                }
            } else if line.starts_with("## ") || line.starts_with("# ") {
                out.extend(current.take());
            } else if let Some(req) = current.as_mut()
                && let Some(kv) = line.strip_prefix("- ")
                && let Some((k, v)) = kv.split_once(':')
                && k.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            {
                req.fields
                    .entry(k.to_string())
                    .or_insert_with(|| v.trim().to_string());
            }
        }
        out.extend(current);
    }
    Ok(out)
}

fn valid_req_id(id: &str) -> bool {
    let parts: Vec<_> = id.split('-').collect();
    parts.len() == 3
        && parts[0] == "REQ"
        && !parts[1].is_empty()
        && parts[1].chars().all(|c| c.is_ascii_uppercase())
        && parts[2].len() == 3
        && parts[2].chars().all(|c| c.is_ascii_digit())
}

pub fn audit(root: &Path) -> Result<Report> {
    let mut r = Report::default();
    let reqs = parse_requirements(root)?;
    let exps = evidence::load_all(root)?;
    r.requirements = reqs.len();
    r.experiments = exps.len();

    let exp_by_id: BTreeMap<&str, &Entry> =
        exps.iter().map(|e| (e.experiment.id.as_str(), e)).collect();
    let superseded = superseded_ids(&exps);
    let adrs = adr_numbers(root)?;

    let mut seen = BTreeSet::new();
    for req in &reqs {
        let at = format!("{} ({})", req.id, req.file);
        if !valid_req_id(&req.id) {
            r.errors
                .push(format!("{at}: malformed id, expected REQ-<AREA>-NNN"));
        }
        if !seen.insert(req.id.clone()) {
            r.errors.push(format!("{at}: duplicate id"));
        }
        let status = req.fields.get("status").map(String::as_str).unwrap_or("");
        *r.by_status.entry(status.to_string()).or_default() += 1;
        if !STATUSES.contains(&status) {
            r.errors
                .push(format!("{at}: status {status:?} not in {STATUSES:?}"));
        }
        if !req.fields.contains_key("spec") {
            r.errors
                .push(format!("{at}: missing `spec:` (draft section or `new`)"));
        }
        for d in req.list("design") {
            let path = d.split('#').next().unwrap_or(&d);
            if !root.join(path).exists() {
                r.errors
                    .push(format!("{at}: design reference {d} does not exist"));
            }
        }
        for a in req.list("adr") {
            if !adrs.contains(a.as_str()) {
                r.errors
                    .push(format!("{at}: ADR {a} not found in docs/adr/"));
            }
        }
        let evidence_ids = req.list("evidence");
        for id in &evidence_ids {
            if !exp_by_id.contains_key(id.as_str()) {
                r.errors
                    .push(format!("{at}: evidence {id} not found in docs/evidence/"));
            }
        }
        match status {
            "met" => {
                let passing = evidence_ids.iter().any(|id| {
                    exp_by_id.get(id.as_str()).is_some_and(|e| {
                        !superseded.contains(id.as_str())
                            && e.manifest.as_ref().is_some_and(|m| m.verdict == "pass")
                    })
                });
                if !passing {
                    r.errors.push(format!(
                        "{at}: status met but no listed evidence has a current `pass` verdict"
                    ));
                }
            }
            "deferred" | "user-acceptance" if req.list("issue").is_empty() => {
                r.errors
                    .push(format!("{at}: status {status} requires `issue:`"));
            }
            "dropped" if req.list("adr").is_empty() => {
                r.errors
                    .push(format!("{at}: status dropped requires `adr:`"));
            }
            _ => {}
        }
    }

    for e in &exps {
        let name = evidence::dir_name(&e.dir);
        let id = e.experiment.id.as_str();
        if evidence::id_of_dir(&name) != id {
            r.errors
                .push(format!("{name}: directory prefix does not match id {id}"));
        }
        for req in &e.experiment.requirements {
            if !seen.contains(req) {
                r.errors
                    .push(format!("{id}: requirement {req} not defined in docs/spec/"));
            }
        }
        for s in &e.experiment.supersedes {
            if !exp_by_id.contains_key(s.as_str()) {
                r.errors
                    .push(format!("{id}: supersedes unknown experiment {s}"));
            }
        }
        let Some(m) = &e.manifest else {
            r.pending.extend(pending(e, &superseded));
            continue;
        };
        if m.id != id {
            r.errors
                .push(format!("{id}: manifest id {} mismatch", m.id));
        }
        if !m.tree_clean {
            r.errors
                .push(format!("{id}: manifest records a dirty tree"));
        }
        if !["pass", "fail", "partial"].contains(&m.verdict.as_str()) {
            r.errors
                .push(format!("{id}: invalid verdict {:?}", m.verdict));
        }
        let commit = m.pinned_commit.as_str();
        if !git::succeeds(root, &["cat-file", "-e", &format!("{commit}^{{commit}}")])? {
            r.errors
                .push(format!("{id}: pinned commit {commit} does not exist"));
            continue;
        }
        if !git::succeeds(root, &["merge-base", "--is-ancestor", commit, "HEAD"])? {
            r.errors.push(format!(
                "{id}: pinned commit {commit} is not an ancestor of HEAD"
            ));
        }
        let artifacts = e.dir.join("artifacts");
        let actual = if artifacts.exists() {
            evidence::hash_tree(&e.dir, &artifacts)?
        } else {
            BTreeMap::new()
        };
        if actual != m.artifacts {
            let keys: BTreeSet<_> = actual.keys().chain(m.artifacts.keys()).collect();
            for k in keys {
                if actual.get(k) != m.artifacts.get(k) {
                    r.errors.push(format!(
                        "{id}: artifact {k} missing, unlisted or hash mismatch"
                    ));
                }
            }
        }
        if !superseded.contains(id) && !e.experiment.covers.is_empty() {
            let mut args = vec!["diff", "--quiet", commit, "HEAD", "--"];
            args.extend(e.experiment.covers.iter().map(String::as_str));
            if !git::succeeds(root, &args)? {
                r.stale.push(format!(
                    "{id}: covered paths changed since {}",
                    &commit[..12.min(commit.len())]
                ));
            }
        }
    }
    Ok(r)
}

/// Experiments superseded by an experiment that has actually run (has a manifest).
fn superseded_ids(exps: &[Entry]) -> BTreeSet<&str> {
    exps.iter()
        .filter(|e| e.manifest.is_some())
        .flat_map(|e| e.experiment.supersedes.iter().map(String::as_str))
        .collect()
}

/// The pending entry for an experiment that has not run, if it is still pending.
/// An unrun experiment that a run experiment supersedes was withdrawn: it is
/// historical, like a superseded run, and never pending.
fn pending(e: &Entry, superseded: &BTreeSet<&str>) -> Option<String> {
    let id = e.experiment.id.as_str();
    (e.manifest.is_none() && !superseded.contains(id))
        .then(|| format!("{id}: defined but not yet run ({})", e.experiment.title))
}

fn adr_numbers(root: &Path) -> Result<BTreeSet<String>> {
    let dir = root.join("docs/adr");
    let mut out = BTreeSet::new();
    if dir.exists() {
        for e in fs::read_dir(dir)? {
            let name = e?.file_name().to_string_lossy().into_owned();
            if name.len() > 5
                && name.as_bytes()[4] == b'-'
                && name[..4].chars().all(|c| c.is_ascii_digit())
            {
                out.insert(name[..4].to_string());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_ids() {
        assert!(valid_req_id("REQ-FMT-001"));
        assert!(valid_req_id("REQ-SCOPE-010"));
        assert!(!valid_req_id("REQ-fmt-001"));
        assert!(!valid_req_id("REQ-FMT-1"));
        assert!(!valid_req_id("FMT-001"));
    }

    fn entry(id: &str, supersedes: &[&str], run: bool) -> Entry {
        Entry {
            dir: std::path::PathBuf::from(format!("docs/evidence/{id}-x")),
            experiment: evidence::Experiment {
                id: id.to_string(),
                title: format!("title {id}"),
                hypothesis: String::new(),
                command: String::new(),
                covers: Vec::new(),
                requirements: Vec::new(),
                supersedes: supersedes.iter().map(|s| s.to_string()).collect(),
            },
            manifest: run.then(|| evidence::Manifest {
                id: id.to_string(),
                verdict: "pass".to_string(),
                pinned_commit: String::new(),
                tree_clean: true,
                command: String::new(),
                exit_code: 0,
                started_utc: String::new(),
                duration_s: 0.0,
                host: evidence::Host {
                    os: String::new(),
                    kernel: String::new(),
                    cpu: String::new(),
                    cpus: 1,
                    rustc: String::new(),
                },
                artifacts: BTreeMap::new(),
            }),
        }
    }

    fn pending_ids(exps: &[Entry]) -> Vec<String> {
        let superseded = superseded_ids(exps);
        exps.iter()
            .filter_map(|e| pending(e, &superseded))
            .map(|p| p.split(':').next().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn unrun_experiment_superseded_by_a_run_is_not_pending() {
        // r1 ran; r2 was defined and withdrawn; r3 supersedes both and ran.
        let exps = [
            entry("EXP-0001", &[], true),
            entry("EXP-0001-r2", &["EXP-0001"], false),
            entry("EXP-0001-r3", &["EXP-0001", "EXP-0001-r2"], true),
        ];
        assert!(pending_ids(&exps).is_empty());
    }

    #[test]
    fn unrun_superseder_keeps_unrun_predecessor_pending() {
        // r3 has not run yet, so it supersedes nothing: both unrun ones are pending.
        let exps = [
            entry("EXP-0001", &[], true),
            entry("EXP-0001-r2", &["EXP-0001"], false),
            entry("EXP-0001-r3", &["EXP-0001", "EXP-0001-r2"], false),
        ];
        assert_eq!(pending_ids(&exps), ["EXP-0001-r2", "EXP-0001-r3"]);
    }
}
