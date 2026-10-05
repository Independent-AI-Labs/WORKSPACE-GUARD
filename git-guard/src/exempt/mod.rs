//! Operator-owned exempt-project registry (REQ-GGUARD-179/180/181,
//! SPEC-GIT-GUARD section 6.5).
//!
//! A repository inside a registered workspace normally must carry the
//! three AUTO-GENERATED WORKSPACE-CI hooks or its `commit`/`push` fails
//! closed (ci_integrity.rs). An operator may instead authorise an
//! exception for a named path by registering it in the root-owned
//! registry `/etc/workspace-guard/exempt-projects.yaml`. This module is
//! the sole reader of that registry.
//!
//! The registry is a privileged policy input, so it is accepted only
//! while every trust invariant holds: a no-follow regular file owned
//! `root:root` with exact mode `0644`, carrying the filesystem
//! immutable flag, under a root-owned parent chain with no group/other
//! write bit. Missing, malformed, or drifted state grants nothing; the
//! caller continues on the normal contract path. An agent-owned or
//! forged copy is therefore inert.
//!
//! The guard parses no YAML at runtime (REQ-GGUARD-122): this reader
//! scans only `path:` scalars between the `exemptions:` key and the
//! next top-level key. Matching is component-wise against the
//! canonical effective repository root, never a lexical string prefix.
//!
//! The registry path is a fixed absolute constant, mirroring
//! `CI_DEPLOY_PATH` in ci_integrity.rs and `WORKSPACE_ROOT_RECORD` in
//! wsroot.rs.

use std::fs;
use std::os::unix::fs::MetadataExt;
#[cfg(feature = "capability-mode")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Fixed absolute path of the operator-owned registry (REQ-GGUARD-179).
pub const EXEMPT_REGISTRY: &str = "/etc/workspace-guard/exempt-projects.yaml";

/// Linux inode flag: immutable (chattr +i). Stable ABI constant from
/// linux/fs.h; the libc crate does not expose the FL flag values.
#[cfg(feature = "capability-mode")]
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;

/// A directory trusted to contain the registry: root-owned and with no
/// group/other write bit. A symlinked ancestor is followed (metadata),
/// matching the shell guard's parent-chain trust rule; the terminal
/// registry file itself is never followed.
fn dir_root_locked(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(m) => m.is_dir() && m.uid() == 0 && (m.mode() & 0o022) == 0,
        Err(_) => false,
    }
}

/// True when every ancestor of `path` is root-locked up to and
/// including `/`. The terminal `/` satisfies the root-owned,
/// non-writable test on any Linux host.
fn parents_root_locked(path: &Path) -> bool {
    let mut cur = path.parent();
    while let Some(p) = cur {
        if !dir_root_locked(p) {
            return false;
        }
        if p == Path::new("/") {
            return true;
        }
        cur = p.parent();
    }
    false
}

/// True when the registry carries the immutable flag. Root-only builds
/// carry no caps and are a documented soft barrier, so the flag check is
/// compiled out there.
#[cfg(feature = "capability-mode")]
fn immutable_ok(path: &Path) -> bool {
    use std::os::fd::AsFd;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return false,
    };
    match crate::linux_ffi::immutable_flags(file.as_fd()) {
        Ok(flags) => flags & FS_IMMUTABLE_FL != 0,
        Err(_) => false,
    }
}

#[cfg(not(feature = "capability-mode"))]
fn immutable_ok(_path: &Path) -> bool {
    true
}

/// Test seam: the ownership/mode/parent checks are real in production.
fn registry_trusted(path: &Path) -> bool {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return false;
    }
    if meta.uid() != 0 || meta.gid() != 0 {
        return false;
    }
    if meta.mode() & 0o777 != 0o644 {
        return false;
    }
    if !parents_root_locked(path) {
        return false;
    }
    immutable_ok(path)
}

/// Strip surrounding quotes and any trailing full-line comment from a
/// scalar; a path value never contains these.
fn clean_scalar(raw: &str) -> String {
    let v = raw.trim();
    let v = v.split(" #").next().unwrap_or(v).trim();
    v.trim_matches('"').trim_matches('\'').to_string()
}

/// Collect the `path` scalars of the `exemptions:` list. A line with
/// leading indentation belongs to the list; the first non-indented,
/// non-dash line ends it.
fn parse_paths(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_list = false;
    for line in content.lines() {
        let no_eol = line.trim_end();
        if no_eol.is_empty() {
            continue;
        }
        let trimmed = no_eol.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "exemptions:" {
            in_list = true;
            continue;
        }
        if !in_list {
            continue;
        }
        let indented = no_eol.len() != trimmed.len();
        if !indented && !trimmed.starts_with('-') {
            in_list = false;
            continue;
        }
        let entry = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if let Some(v) = entry.strip_prefix("path:") {
            let v = clean_scalar(v);
            if !v.is_empty() {
                out.push(v);
            }
        }
    }
    out
}

/// Component-wise containment: equality or a true descendant path.
fn path_matches(top: &Path, candidate: &Path) -> bool {
    top == candidate || top.starts_with(candidate)
}

/// Return the matched registry path when `toplevel` is exempt.
///
/// Fails closed: an untrusted, absent, or malformed registry, a
/// non-canonicalizable entry, or a non-canonicalizable repository
/// yields `None`, so the caller applies the normal contract.
pub fn exempt_match(toplevel: &str) -> Option<String> {
    let registry = PathBuf::from(EXEMPT_REGISTRY);
    if !registry_trusted(&registry) {
        return None;
    }
    let content = fs::read_to_string(&registry).ok()?;
    let top = fs::canonicalize(toplevel).ok()?;
    for entry in parse_paths(&content) {
        let Ok(candidate) = fs::canonicalize(Path::new(&entry)) else {
            continue;
        };
        if path_matches(&top, &candidate) {
            return Some(entry);
        }
    }
    None
}

/// Evaluate the exemption for `toplevel` (REQ-GGUARD-180). On a match the
/// mandatory audit record is appended before real Git (REQ-GGUARD-181):
/// a sink failure fails closed as guard-unavailable. Returns true when the
/// caller must skip the CI hook/contract layer.
pub fn honor(toplevel: &str) -> Result<bool, crate::GuardError> {
    let Some(entry) = exempt_match(toplevel) else {
        return Ok(false);
    };
    crate::log::audit_exempt(toplevel, &entry)
        .map_err(|e| crate::GuardError::GuardUnavailable(format!("exempt audit: {e}")))?;
    Ok(true)
}

#[cfg(test)]
mod tests;
