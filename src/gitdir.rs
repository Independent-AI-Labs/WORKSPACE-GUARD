//! Capability-mode ownership lock for all paths declared in
//! `config/shared_locked_paths.yaml`.
//!
//! Before delegating to the real git binary, the guard claims ownership
//! of every path declared in the config: the `.git/` tree MINUS its
//! object stores (see GITDIR_PRUNE_DIR_NAMES), recursive directory
//! trees matching glob patterns (e.g. `.boot*`), individual files
//! (e.g. `.gitmodules`), and files matching filename glob patterns
//! (e.g. `*_exceptions.yaml`).  Every matched path is `chown`'d to
//! `root:root` at the mode specified in the config.  Files that
//! already are `root:root` with the correct mode are skipped
//! (idempotent, metadata stat only).
//!
//! The object stores (`.git/objects`, `.git/lfs`) are pruned from the
//! recursive walk: they hold content-addressed data, not policy input,
//! and they account for ~99% of the files under `.git/`.  The pruned
//! directories themselves are still locked `root:root` 0o755, so the
//! agent cannot add, remove, or rename entries directly; object
//! content written by git stays hash-verified on read.  All
//! policy-bearing paths (`HEAD`, `config`, `index`, `refs/`, `logs/`,
//! `hooks/`, `info/`, `packed-refs`, `modules/`, `worktrees/`, and the
//! transient state files at the git-dir root) remain fully locked.
//!
//! For `.git/` specifically:
//!   - Directories → 0o755 (world-traversable, root-writable)
//!   - Regular files → 0o644 (world-readable, root-writable)
//!   - Hook files under `.git/hooks/` → 0o755 (executable so git
//!     invokes them; non-executable hooks are skipped by git)
//!   - The hook directory itself prevents `core.hooksPath` / `core.fsmonitor`
//!     RCE and `.git/hooks/` trojaning (CVE-2025-48384).
//!   - `.git/config` is root-owned read-only, preventing `include.path`
//!     and other injection vectors.
//!
//! Locking `*_exceptions.yaml` prevents tampering with quality-gate
//! exemptions (`quality_exceptions.yaml`), banned-word overrides
//! (`banned_words_exceptions.yaml`), sensitive-file exceptions
//! (`sensitive_files_exceptions.yaml`), or any other exception policy
//! files that could be used to bypass CI enforcement.
//!
//! Once locked, the user cannot directly write to any locked path.
//! They can still operate the repository normally because the guard
//! grants `CAP_DAC_OVERRIDE` to `git.original` via the Ambient
//! capability set for the duration of the authorized subcommand only.
//!
//! The lock runs TWICE per invocation:
//!   1. Before the policy engine (`main.rs`): closes the window
//!      where a planted `.git/config` payload could fire during
//!      policy-check sub-calls, and locks exception files before any
//!      git operation can read them.
//!   2. After `git.original` exits (`exec.rs`): reclaims files
//!      that git.original created or modified back to `root:root`,
//!      closing the backdoor window between git operations.
//!
//! Both passes share a single `rev-parse` git-dir resolution performed
//! once in `main.rs`, and all worktree glob patterns are evaluated in
//! ONE recursive walk (previously one walk per pattern).
//!
//! The guard's own `rev-parse` resolution uses a hardened environment
//! (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`,
//! `GIT_CONFIG_SYSTEM=/dev/null`, plus `core.fsmonitor=` via
//! `GIT_CONFIG_*` overrides) so the resolution call itself cannot be
//! weaponised by a fsmonitor payload planted in `.git/config`. Agent
//! commit/push exec does not null `core.hooksPath`; locked `.git/hooks/`
//! runs normally (see SPEC-GIT-IDENTITY §5.1).
//!
//! This module is compiled only in capability mode (`#[cfg(feature =
//! "capability-mode")]`).  In root-only mode the user IS root, so the
//! ownership lock would just impede them and they can chown it back
//! trivially (see docs/ROOT-ONLY-MODE.md).
//!
//! All locked paths are defined in `config/shared_locked_paths.yaml` --
//! NOT hardcoded in Rust.  Edit the YAML and rebuild; no code changes
//! needed to add or remove a locked path.

#![cfg(feature = "capability-mode")]

use std::ffi::{CString, OsString};
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::unistd::{chown, Gid, Uid};

use crate::{CHILD_PATH, GIT_ORIGINAL_PATH};

/// Mode for regular files: world-readable, root-writable only.
const FILE_MODE: u32 = 0o644;
/// Mode for hook files: executable so git actually invokes them
/// (non-executable hooks are skipped by git, resulting in no enforcement).
const HOOK_FILE_MODE: u32 = 0o755;
/// Mode for directories: traversable by all, root can create entries.
const DIR_MODE: u32 = 0o755;

/// Directory names under `.git/` that hold content-addressed object
/// data. The recursive git-dir walk locks these directories themselves
/// (root:root 0o755, so the agent cannot add/remove/rename entries)
/// but does NOT descend into them: they contain ~99% of the files
/// under `.git/` and none of them are policy input.
const GITDIR_PRUNE_DIR_NAMES: [&str; 2] = ["objects", "lfs"];

/// Lock all paths declared in `config/shared_locked_paths.yaml` for the
/// repo whose git dir is `git_dir` (already resolved by the caller, so
/// both the pre-exec and post-exec passes share one `rev-parse`
/// resolution).
pub fn lock(git_dir: &Path) {
    // Skip only for a real root operator (root can chown anything back, so
    // the lock would just impede them). is_sudo()/AT_SECURE is the wrong
    // gate here: file-capability host-exec sets AT_SECURE for every agent
    // git invocation, which disabled the lock in exactly the deployment it
    // protects (observed: .git/index left agent-owned and agent-writable).
    if nix::unistd::geteuid().as_raw() == 0 {
        return;
    }
    let toplevel = match git_dir.parent() {
        Some(p) => p.to_path_buf(),
        None => return,
    };

    // Scope: the lock protects repositories the guard is responsible for
    // (see lock_in_scope). Any other repo is left alone.
    if !lock_in_scope(&toplevel) {
        return;
    }

    // 1. Recursive tree paths (e.g. .git/ minus its object stores)
    for entry in crate::LOCKED_RECURSIVE_TREE_PATHS {
        if *entry == ".git" {
            lock_tree(git_dir, git_dir);
        } else {
            let path = toplevel.join(entry);
            if path.exists() {
                lock_tree(&path, &path);
            }
        }
    }

    // 2. Individual files (e.g. .gitmodules)
    for &(file_path, mode) in crate::LOCKED_INDIVIDUAL_FILE_PATHS {
        let path = toplevel.join(file_path);
        if path.exists() && !path.is_symlink() {
            lock_file(&path, mode);
        }
    }

    // 3+4. Tree glob patterns (e.g. .boot*) and filename glob patterns
    // (e.g. *_exceptions.yaml) in ONE recursive worktree walk. The lock
    // is unconditional: edits to locked policy files go through the
    // root-gated workspace-yaml-edit binary (SPEC-YAML-EDIT); there is
    // no unseal skip list.
    lock_worktree_globs(&toplevel);
}

/// True when the ownership lock applies to the repo at `toplevel`: repos
/// inside the workspace (full or partial marker match; a partial match is
/// a workspace with missing pieces and must stay locked, matching the
/// fail-closed contract in exec.rs) and clones of provisioned remotes
/// outside the workspace (H4). Any other repo (scratch clones, test
/// sandboxes under /tmp, upstream checkouts) is out of scope: locking it
/// would break ordinary agent workflows without protecting anything the
/// guard enforces on.
fn lock_in_scope(toplevel: &Path) -> bool {
    let s = toplevel.to_string_lossy().to_string();
    crate::wsroot::find_partial_workspace_root(&s).is_some()
        || crate::remote::repo_targets_provisioned_host(&s)
}

/// Directory names the unified worktree glob walk never descends into.
/// `.git` is always pruned (locked separately via lock_tree); the rest
/// come from `config/shared_locked_paths.yaml` prune_dir_names.
fn is_pruned_dir(name: &str) -> bool {
    name == ".git" || crate::LOCK_PRUNE_DIR_NAMES.contains(&name)
}

/// Single recursive worktree walk that evaluates BOTH glob pattern
/// classes in one pass:
///   - directory names matching LOCKED_RECURSIVE_TREE_GLOB_PATTERNS
///     (e.g. `.boot*`) have their whole tree locked via lock_tree()
///   - file names matching LOCKED_GLOB_PATTERNS (e.g.
///     `*_exceptions.yaml`) are locked with the pattern's mode
///
/// Previously each pattern triggered its own full worktree walk (7+
/// traversals per lock pass); now every entry is visited once and
/// matched against all patterns.
fn lock_worktree_globs(root: &Path) {
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.is_symlink() => {
            let _ = lchown_root(root);
        }
        Ok(meta) if meta.is_dir() => {
            if let Some(name) = root.file_name().and_then(|n| n.to_str()) {
                if name != ".git"
                    && crate::LOCKED_RECURSIVE_TREE_GLOB_PATTERNS
                        .iter()
                        .any(|p| glob_match(p, name))
                {
                    lock_tree(root, root);
                    return;
                }
            }
            if let Ok(entries) = fs::read_dir(root) {
                for ent in entries.flatten() {
                    let path = ent.path();
                    let file_name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n.to_owned(),
                        None => continue,
                    };
                    if path.is_dir() && !is_pruned_dir(&file_name) {
                        lock_worktree_globs(&path);
                    } else if path.is_file() {
                        for &(pattern, mode) in crate::LOCKED_GLOB_PATTERNS {
                            if glob_match(pattern, &file_name) {
                                lock_file(&path, mode);
                                break;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// Simple filename-only glob matching. Supports `*` as a wildcard that
/// matches any sequence of characters (including empty).
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

/// Check if `file` is inside the `hooks` subdirectory of `git_dir`.
fn is_hook_file(path: &Path, git_dir: &Path) -> bool {
    let hooks_dir = git_dir.join("hooks");
    path.starts_with(&hooks_dir)
}

/// Compute the mode to apply to a non-hook file: preserve any existing
/// user/group/other execute bits while enforcing the base `FILE_MODE`.
fn file_lock_mode(st_mode: u32) -> u32 {
    (st_mode & 0o111) | FILE_MODE
}

/// Recursively lock an entire directory tree to root:root.
/// Object-store directories (see GITDIR_PRUNE_DIR_NAMES) are locked
/// themselves but not descended into: they hold content-addressed
/// data, not policy input, and skipping them keeps the per-invocation
/// cost proportional to the policy surface rather than the repo size.
fn lock_tree(path: &Path, git_dir: &Path) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_symlink() => {
            let _ = lchown_root(path);
        }
        Ok(meta) if meta.is_dir() => {
            lock_dir(path, DIR_MODE);
            let pruned = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| GITDIR_PRUNE_DIR_NAMES.contains(&n))
                .unwrap_or(false);
            if pruned {
                return;
            }
            if let Ok(entries) = fs::read_dir(path) {
                for ent in entries.flatten() {
                    lock_tree(&ent.path(), git_dir);
                }
            }
        }
        Ok(meta) if meta.is_file() && is_hook_file(path, git_dir) && !meta.is_symlink() => {
            lock_file(path, HOOK_FILE_MODE);
        }
        Ok(meta) => {
            lock_file(path, file_lock_mode(meta.st_mode()));
        }
        Err(_) => {}
    }
}

/// Resolve the absolute git dir for this invocation. Called ONCE per
/// guard invocation from main.rs; both lock passes reuse the result.
pub fn resolve_git_dir(argv_os: &[OsString]) -> Option<PathBuf> {
    let mut cmd = Command::new(GIT_ORIGINAL_PATH);
    cmd.env_clear().env("PATH", CHILD_PATH).env("HOME", "/");
    crate::agent_identity::apply_agent_hardened_git_env(&mut cmd, false);
    // Preserve repo-location env overrides; env_clear would drop them and
    // the lock would resolve the cwd repo instead of the intended one.
    for var in ["GIT_DIR", "GIT_WORK_TREE"] {
        if let Some(v) = std::env::var_os(var) {
            cmd.env(var, v);
        }
    }
    let out = cmd
        .args(crate::args::repo_location_args(argv_os))
        .args(["rev-parse", "--absolute-git-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return None;
    }
    Some(PathBuf::from(s))
}

fn lock_dir(path: &Path, mode: u32) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_symlink() => {
            let _ = lchown_root(path);
        }
        Ok(meta) => {
            if needs_lock(meta.st_uid(), meta.st_gid()) {
                let chown_res = chown_root(path);
                let chmod_res = if chown_res.is_ok() {
                    chmod(path, mode)
                } else {
                    Ok(())
                };
                let _ = (chown_res, chmod_res);
            } else if meta.st_uid() == 0 && meta.st_gid() == 0 && (meta.st_mode() & 0o777) != mode {
                let _ = chmod(path, mode);
            }
        }
        Err(_) => {}
    }
}

fn lock_file(path: &Path, mode: u32) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_symlink() => {
            let _ = lchown_root(path);
        }
        Ok(meta) => {
            let cur_mode = meta.st_mode() & 0o777;
            if needs_lock(meta.st_uid(), meta.st_gid()) {
                let chown_res = chown_root(path);
                let _ = if chown_res.is_ok() {
                    chmod(path, mode)
                } else {
                    Ok(())
                };
            } else if meta.st_uid() == 0 && meta.st_gid() == 0 && cur_mode != mode {
                let _ = chmod(path, mode);
            }
        }
        Err(_) => {}
    }
}

fn needs_lock(uid: u32, gid: u32) -> bool {
    uid != 0 || gid != 0
}

fn cpath(path: &Path) -> std::io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "nul byte in path"))
}

/// chown(2) following symlinks, used only on paths already verified
/// non-symlink by the caller (lock_dir/lock_file check `meta.is_symlink()`
/// first and divert symlinks to lchown_root). Uses nix::unistd::chown,
/// which is safe: no pointer juggling, no raw errno.
fn chown_root(path: &Path) -> std::io::Result<()> {
    chown(path, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
}

/// lchown(2) does not follow symlinks: required for symlinks so we chown
/// the link itself rather than the target. nix has no lchown wrapper as of
/// 0.29 (nix::unistd::chown follows symlinks, which would chown the wrong
/// file unnoticed), so this is an irreducible unsafe FFI block.
// SAFETY: libc::lchown(3) takes a NUL-terminated path string and two
// numeric ids (0, 0 for root:root). `c` is a valid CString produced from
// the OsStr bytes of `path`, so c.as_ptr() is a valid NUL-terminated
// pointer for the duration of the call. lchown does not follow symlinks,
// so there is no dereference hazard. The return value is the libc errno
// convention (-1 on error, errno set).
fn lchown_root(path: &Path) -> std::io::Result<()> {
    let c = cpath(path)?;
    let rc = unsafe { libc::lchown(c.as_ptr(), 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// chmod(2) using std::fs::set_permissions, which is safe and
/// symlink-following (matches the prior libc::chmod behaviour). Callers
/// check `meta.is_symlink()` before calling, so this never operates on a
/// symlink.
fn chmod(path: &Path, mode: u32) -> std::io::Result<()> {
    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)
}

#[cfg(test)]
#[path = "gitdir_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "gitdir_glob_tests.rs"]
mod glob_tests;
