//! CI deployment + consumer hook integrity gate.
//!
//! Git skips absent or non-executable hook files with no error, so a fresh
//! clone (or a hook deleted out from under a repo) commits with zero
//! quality gates. This module fails commit/push closed before the
//! contract script runs:
//!   1. Consumer side: the repo being committed to has pre-commit,
//!      commit-msg and pre-push hooks that exist, are executable, and
//!      carry the generate-hooks AUTO-GENERATED marker.
//!   2. Deployment side: the projects/CI checkout the hooks source
//!      live is root-owned, has exec bits matching the git index, and
//!      is not ahead of the last-seen origin/main (behind only warns:
//!      run deploy-ci to catch up).
//!
//! All checks are implemented natively here rather than by shelling
//! into the CI repo: a tampered verifier cannot be trusted to report
//! its own tampering.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{GuardError, CHILD_PATH};

#[cfg(not(test))]
const GIT_BIN: &str = crate::GIT_ORIGINAL_PATH;
#[cfg(test)]
const GIT_BIN: &str = "git";

const REQUIRED_HOOKS: [&str; 3] = ["pre-commit", "commit-msg", "pre-push"];
const HOOK_MARKER_NEEDLES: [&str; 2] = ["AUTO-GENERATED", "generate-hooks"];
const MAX_LISTED_VIOLATIONS: usize = 10;
const CI_DEPLOY_REL: &str = "projects/CI";
const UNTRACKED_ALLOWLIST: [&str; 5] = [
    ".venv/",
    "node_modules/",
    "__pycache__/",
    "target/",
    ".pytest_cache/",
];

fn git_output(dir: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(GIT_BIN);
    cmd.env_clear()
        .env("PATH", CHILD_PATH)
        .env("HOME", "/")
        .arg("-C")
        .arg(dir)
        .args(args);
    crate::apply_safe_directory(&mut cmd);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn is_executable(meta: &fs::Metadata) -> bool {
    meta.permissions().mode() & 0o111 != 0
}

fn hook_violation_reason(path: &Path) -> Option<String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Some(format!("{}: hook missing", path.display())),
    };
    if !meta.is_file() {
        return Some(format!("{}: not a regular file", path.display()));
    }
    if !is_executable(&meta) {
        return Some(format!(
            "{}: not executable (git skips it without error)",
            path.display()
        ));
    }
    let mut head = [0u8; 512];
    let read = {
        use std::io::Read;
        match fs::File::open(path) {
            Ok(mut f) => f.read(&mut head).unwrap_or(0),
            Err(_) => 0,
        }
    };
    let text = String::from_utf8_lossy(&head[..read]);
    for needle in HOOK_MARKER_NEEDLES {
        if !text.contains(needle) {
            return Some(format!(
                "{}: missing '{}' marker (not generate-hooks output)",
                path.display(),
                needle
            ));
        }
    }
    None
}

fn check_consumer_hooks(toplevel: &str) -> Result<(), GuardError> {
    let hooks_dir = match git_output(Path::new(toplevel), &["rev-parse", "--git-path", "hooks"]) {
        Some(p) => {
            let pb = PathBuf::from(&p);
            if pb.is_absolute() {
                pb
            } else {
                Path::new(toplevel).join(pb)
            }
        }
        None => {
            return Err(GuardError::ContractFailed(format!(
                "CI integrity: cannot resolve hooks dir for {}",
                toplevel
            )))
        }
    };

    let mut violations: Vec<String> = Vec::new();
    for hook in REQUIRED_HOOKS {
        if let Some(reason) = hook_violation_reason(&hooks_dir.join(hook)) {
            violations.push(reason);
        }
    }
    if violations.is_empty() {
        return Ok(());
    }
    Err(GuardError::ContractFailed(format!(
        "CI integrity: hooks unusable in {} (git would skip them without error):\n  {}\n\
         Fix: sudo bash /tmp/opencode/install-hooks.sh (or: sudo make install-hooks)",
        toplevel,
        violations.join("\n  ")
    )))
}

fn parse_ls_files(blob: &str) -> Vec<(String, String, String)> {
    blob.split('\0')
        .filter_map(|rec| {
            let (meta, path) = rec.split_once('\t')?;
            let mut fields = meta.split_whitespace();
            let mode = fields.next()?.to_string();
            let hash = fields.next()?.to_string();
            Some((mode, hash, path.to_string()))
        })
        .collect()
}

fn blob_hash_of(path: &Path) -> Option<String> {
    let mut cmd = Command::new(GIT_BIN);
    cmd.env_clear()
        .env("PATH", CHILD_PATH)
        .env("HOME", "/")
        .arg("hash-object")
        .arg("--")
        .arg(path);
    crate::apply_safe_directory(&mut cmd);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn untracked_violations(ci_path: &Path) -> Vec<String> {
    let Some(blob) = git_output(
        ci_path,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    ) else {
        return Vec::new();
    };
    blob.split('\0')
        .filter(|rel| !rel.is_empty())
        .filter(|rel| {
            !rel.split('/').any(|component| {
                UNTRACKED_ALLOWLIST
                    .iter()
                    .any(|a| component == a.trim_end_matches('/'))
            })
        })
        .map(|rel| {
            format!(
                "{}: untracked file in deployment",
                ci_path.join(rel).display()
            )
        })
        .collect()
}

fn divergence_violation(ci_path: &Path, head: &str, upstream: &str, ahead: u64) -> Option<String> {
    if head == upstream {
        return None;
    }
    if ahead > 0 {
        return Some(format!(
            "{}: HEAD is {} commit(s) ahead of origin/main (unpushed provenance)",
            ci_path.display(),
            ahead
        ));
    }
    eprintln!(
        "[workspace-guard] WARN: {} is behind origin/main; run: sudo make deploy-ci",
        ci_path.display()
    );
    None
}

fn deployment_violations(
    ci_path: &Path,
    git_uid: u32,
    file_uid: u32,
    check_upstream: bool,
) -> Vec<String> {
    let mut violations: Vec<String> = Vec::new();

    let git_dir = ci_path.join(".git");
    match fs::symlink_metadata(&git_dir) {
        Ok(m) if m.uid() != git_uid => violations.push(format!(
            "{}: .git owned by uid {} (expected {})",
            git_dir.display(),
            m.uid(),
            git_uid
        )),
        Ok(_) => {}
        Err(_) => violations.push(format!("{}: .git missing", git_dir.display())),
    }

    if check_upstream {
        let head = git_output(ci_path, &["rev-parse", "HEAD"]);
        let upstream = git_output(ci_path, &["rev-parse", "refs/remotes/origin/main"]);
        match (head, upstream) {
            (Some(head), Some(upstream)) => {
                let ahead = if head == upstream {
                    0
                } else {
                    git_output(ci_path, &["rev-list", "--count", "origin/main..HEAD"])
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0)
                };
                if let Some(v) = divergence_violation(ci_path, &head, &upstream, ahead) {
                    violations.push(v);
                }
            }
            _ => violations.push(format!(
                "{}: cannot resolve HEAD/origin refs",
                ci_path.display()
            )),
        }
    }

    if let Some(blob) = git_output(ci_path, &["ls-files", "-s", "-z"]) {
        for (mode, hash, rel) in parse_ls_files(&blob) {
            if violations.len() >= MAX_LISTED_VIOLATIONS {
                break;
            }
            let path = ci_path.join(&rel);
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => {
                    violations.push(format!("{}: tracked file missing", path.display()));
                    continue;
                }
            };
            if meta.file_type().is_symlink() {
                if mode != "120000" {
                    violations.push(format!(
                        "{}: tracked entry is a symlink but index mode is {}",
                        path.display(),
                        mode
                    ));
                }
                continue;
            }
            if meta.uid() != file_uid {
                violations.push(format!(
                    "{}: owned by uid {} (expected {})",
                    path.display(),
                    meta.uid(),
                    file_uid
                ));
                continue;
            }
            if mode == "100755" && !is_executable(&meta) {
                violations.push(format!(
                    "{}: index mode 100755 but not executable on disk",
                    path.display()
                ));
            }
            if meta.is_file() && blob_hash_of(&path).as_deref() != Some(hash.as_str()) {
                violations.push(format!(
                    "{}: content hash differs from git index (modified on disk)",
                    path.display()
                ));
            }
        }
    }
    for v in untracked_violations(ci_path) {
        if violations.len() >= MAX_LISTED_VIOLATIONS {
            break;
        }
        violations.push(v);
    }
    violations
}

pub fn check_ci_integrity(toplevel: &str, wsroot: &str) -> Result<(), GuardError> {
    check_consumer_hooks(toplevel)?;
    let ci_path = Path::new(wsroot).join(CI_DEPLOY_REL);
    let violations = deployment_violations(&ci_path, 0, 0, true);
    if violations.is_empty() {
        return Ok(());
    }
    Err(GuardError::ContractFailed(format!(
        "CI integrity: deployment {} failed verification:\n  {}\n\
         Fix: sudo --preserve-env=HOME,SSH_AUTH_SOCK make -C projects/WORKSPACE-CI deploy-ci",
        ci_path.display(),
        violations.join("\n  ")
    )))
}

#[cfg(test)]
#[path = "ci_integrity_tests.rs"]
mod tests;
