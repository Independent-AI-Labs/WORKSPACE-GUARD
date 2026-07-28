//! Post-exec policy reconcile (REQ-GGUARD-176, REQ-GGUARD-178;
//! SPEC-GIT-GUARD section 8).
//!
//! Git operations and tampering are the same syscalls; only the actor
//! differs. When git.original exits after a mutating porcelain, every
//! worktree path it recreated (unlink+create on pull, merge, checkout,
//! switch, restore, rebase, cherry-pick, revert, apply, am, submodule
//! update, plus the root-only reset/clean paths) is owned by the
//! CALLING USER, not root: the ownership invariant the guard asserts
//! pre-exec (gitdir.rs) no longer holds. This module is the
//! post-flight that restores it in the SAME guard invocation, using
//! the guard's own cap_chown/cap_fowner (never loaned onward; the
//! ambient loan to git.original carries only CAP_DAC_OVERRIDE).
//!
//! Two enforcement classes:
//!
//!   STRICT (drift -> caller exits EX_IOERR 74):
//!     - `<repo>/config/` directory (root:root 0o755) and its direct
//!       `*.yaml` children (root:root 0o644): the repo policy set.
//!     - files matching the compiled LOCKED_GLOB_PATTERNS
//!       (e.g. `*_exceptions.yaml`, `exemption_files.yaml`) and
//!       LOCKED_INDIVIDUAL_FILE_PATHS (e.g. `.gitmodules`) anywhere in
//!       the worktree, with the same prune set as gitdir.rs.
//!
//!   WARN-ONLY (stderr, never alters the exit code; REQ-GGUARD-178):
//!     - `.git/hooks/*` missing root ownership or the immutable flag.
//!     - the tier registries (`ci/config/project_enforcement.yaml`,
//!       `workspace/config/project_enforcement.yaml` under the
//!       workspace root) missing root ownership or the immutable flag.
//!     Re-applying `+i` remains a root-run repair action
//!     (`install-hooks-recursive`), not a guard duty: the guard does
//!     not carry CAP_LINUX_IMMUTABLE.
//!
//! Symlinks are never followed (lstat first, matching gitdir.rs);
//! symlink entries in the strict set are skipped with a warning.
//!
//! The module is compiled only in capability mode (`#[cfg(feature =
//! "capability-mode")]`): root-only builds pass no resolved git dir to
//! the exec path, so reconcile stays inert there (the operator is
//! root; the invariant is theirs to keep, SPEC-GIT-GUARD section 8.7).

use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use nix::unistd::{chown, Gid, Uid};

/// Porcelains that mutate worktree files (REQ-GGUARD-175). Resolved
/// canonical names only: args.rs expands abbreviations before this is
/// consulted. `stash` is absent: it is blocked outright
/// (REQ-GGUARD-050). `commit` is absent: it writes only under `.git/`
/// (reclaimed by gitdir::lock), never the worktree policy set.
pub const MUTATING_SUBCOMMANDS: &[&str] = &[
    "am",
    "apply",
    "cherry-pick",
    "checkout",
    "clean",
    "merge",
    "pull",
    "rebase",
    "reset",
    "restore",
    "revert",
    "submodule",
    "switch",
];

/// Mode for policy directories and regular policy files.
const DIR_MODE: u32 = 0o755;
const FILE_MODE: u32 = 0o644;

/// Linux inode flag: immutable (chattr +i). Stable ABI constant from
/// linux/fs.h; the libc crate does not expose the FL flag values.
const FS_IMMUTABLE_FL: i32 = 0x0000_0010;

/// Tier registries that never change via `git pull` and keep `chattr
/// +i` (REQ-GGUARD-178), relative to the workspace root.
const TIER_REGISTRIES: [&str; 2] = [
    "ci/config/project_enforcement.yaml",
    "workspace/config/project_enforcement.yaml",
];

pub fn is_mutating(subcommand: &str) -> bool {
    MUTATING_SUBCOMMANDS.contains(&subcommand)
}

/// Reconcile the policy manifest for the repo whose git dir is
/// `git_dir`. Returns the drift list: one entry per path whose
/// ownership/mode could not be re-asserted. An empty list means the
/// invariant holds. Warnings (hooks, registries, symlinks) go to
/// stderr and never appear in the drift list.
pub fn run(git_dir: &Path) -> Vec<String> {
    let mut drift = Vec::new();
    let toplevel = match git_dir.parent() {
        Some(p) => p.to_path_buf(),
        None => return drift,
    };
    if !in_scope(&toplevel) {
        return drift;
    }
    reconcile_config_policy(&toplevel, &mut drift);
    reconcile_locked_paths(&toplevel, &mut drift);
    warn_hooks_drift(git_dir);
    warn_registry_drift(&toplevel);
    drift
}

/// Same scope rule as gitdir::lock: workspace repos (full or partial
/// marker match) and clones of provisioned remotes. Anything else is
/// left alone.
fn in_scope(toplevel: &Path) -> bool {
    let s = toplevel.to_string_lossy().to_string();
    crate::wsroot::find_partial_workspace_root(&s).is_some()
        || crate::remote::repo_targets_provisioned_host(&s)
}

/// `<repo>/config/` and its direct `*.yaml` children (non-recursive;
/// SPEC-GIT-GUARD section 8.4).
fn reconcile_config_policy(toplevel: &Path, drift: &mut Vec<String>) {
    let dir = toplevel.join("config");
    let meta = match fs::symlink_metadata(&dir) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.is_symlink() {
        warn(&format!("{}: symlink, skipped", dir.display()));
        return;
    }
    if !meta.is_dir() {
        return;
    }
    assert_owner_mode(&dir, &meta, DIR_MODE, drift);
    if let Ok(entries) = fs::read_dir(&dir) {
        for ent in entries.flatten() {
            let path = ent.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_owned(),
                None => continue,
            };
            if !name.ends_with(".yaml") {
                continue;
            }
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_symlink() => {
                    warn(&format!("{}: symlink, skipped", path.display()));
                }
                Ok(m) if m.is_file() => {
                    assert_owner_mode(&path, &m, FILE_MODE, drift);
                }
                _ => {}
            }
        }
    }
}

/// Files matching the compiled LOCKED_GLOB_PATTERNS plus
/// LOCKED_INDIVIDUAL_FILE_PATHS, in one recursive worktree walk with
/// the same prune set as gitdir.rs (`.git` always pruned).
fn reconcile_locked_paths(toplevel: &Path, drift: &mut Vec<String>) {
    for &(file_path, mode) in crate::LOCKED_INDIVIDUAL_FILE_PATHS {
        let path = toplevel.join(file_path);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.is_symlink() => {
                warn(&format!("{}: symlink, skipped", path.display()));
            }
            Ok(m) if m.is_file() => assert_owner_mode(&path, &m, mode, drift),
            _ => {}
        }
    }
    walk_globs(toplevel, drift);
}

fn walk_globs(dir: &Path, drift: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let path = ent.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_owned(),
            None => continue,
        };
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if name != ".git" && !crate::LOCK_PRUNE_DIR_NAMES.contains(&name.as_str()) {
                walk_globs(&path, drift);
            }
        } else if meta.is_file() {
            for &(pattern, mode) in crate::LOCKED_GLOB_PATTERNS {
                if glob_match(pattern, &name) {
                    assert_owner_mode(&path, &meta, mode, drift);
                    break;
                }
            }
        }
    }
}

/// Filename-only glob matcher (`*` wildcard), identical semantics to
/// gitdir.rs. Duplicated because gitdir.rs is compiled only in
/// capability mode while this module builds in both modes.
fn glob_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == name;
    }
    let segments: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue;
        }
        match name[pos..].find(seg) {
            Some(idx) => pos += idx + seg.len(),
            None => return false,
        }
        if i == 0 && !name.starts_with(seg) {
            return false;
        }
    }
    let last = segments.last().unwrap_or(&"");
    if !pattern.ends_with('*') && !last.is_empty() && !name.ends_with(last) {
        return false;
    }
    true
}

/// Re-assert root:root and `mode` on one path. Failures are appended
/// to the drift list, never dropped without a diagnostic
/// (REQ-GGUARD-176: a missed reconcile halts the pipeline via the
/// caller's EX_IOERR).
fn assert_owner_mode(path: &Path, meta: &fs::Metadata, mode: u32, drift: &mut Vec<String>) {
    if meta.st_uid() != 0 || meta.st_gid() != 0 {
        if let Err(e) = chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))) {
            drift.push(format!("{}: chown root:root failed: {}", path.display(), e));
            return;
        }
    }
    if (meta.st_mode() & 0o777) != mode || meta.st_uid() != 0 {
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
            drift.push(format!(
                "{}: chmod 0{:o} failed: {}",
                path.display(),
                mode,
                e
            ));
        }
    }
}

/// Warn when any `.git/hooks/` entry is not root-owned or lacks the
/// immutable flag (REQ-GGUARD-178). Non-blocking by design.
fn warn_hooks_drift(git_dir: &Path) {
    let hooks = git_dir.join("hooks");
    warn_if_unlocked(&hooks);
    if let Ok(entries) = fs::read_dir(&hooks) {
        for ent in entries.flatten() {
            warn_if_unlocked(&ent.path());
        }
    }
}

/// Warn when a tier registry (workspace level) is not root-owned or
/// lacks the immutable flag (REQ-GGUARD-178). Absent registries are
/// skipped: not every checkout carries both trees.
fn warn_registry_drift(toplevel: &Path) {
    let ws = match crate::wsroot::find_partial_workspace_root(&toplevel.to_string_lossy()) {
        Some(w) => w,
        None => return,
    };
    for rel in TIER_REGISTRIES {
        let path = PathBuf::from(&ws).join(rel);
        if path.exists() {
            warn_if_unlocked(&path);
        }
    }
}

fn warn_if_unlocked(path: &Path) {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if meta.is_symlink() {
        warn(&format!(
            "{}: symlink where a locked path was expected",
            path.display()
        ));
        return;
    }
    if meta.st_uid() != 0 || meta.st_gid() != 0 {
        warn(&format!(
            "{}: not root-owned; repair: sudo make install-hooks-recursive",
            path.display()
        ));
    }
    if immutable_flag(path) == Some(false) {
        warn(&format!(
            "{}: immutable flag missing; repair: sudo make install-hooks-recursive",
            path.display()
        ));
    }
}

/// Read the inode immutable flag via FS_IOC_GETFLAGS. Returns None
/// when the flag state cannot be determined (unreadable path,
/// unsupported filesystem): callers treat None as "unknown", never as
/// "immutable".
fn immutable_flag(path: &Path) -> Option<bool> {
    let fd = fs::File::open(path).ok()?;
    let mut flags: libc::c_int = 0;
    // SAFETY: ioctl(2) with FS_IOC_GETFLAGS takes an int* as its third
    // argument. `flags` is a live, properly aligned c_int whose address
    // is passed by mutable reference; the kernel writes sizeof(c_int)
    // bytes to it. The fd is open for the duration of the call. This is
    // an irreducible FFI site (REQ-GGUARD-121): nix exposes no safe
    // wrapper for inode-flag reads.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
    if rc != 0 {
        return None;
    }
    Some(flags & FS_IMMUTABLE_FL != 0)
}

fn warn(msg: &str) {
    eprintln!("guard reconcile WARNING: {}", msg);
}

#[cfg(test)]
#[path = "reconcile_tests.rs"]
mod tests;
