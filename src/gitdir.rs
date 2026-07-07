//! Capability-mode ownership lock for all paths declared in
//! `config/guard_locked_paths.yaml`.
//!
//! Before delegating to the real git binary, the guard claims ownership
//! of every path declared in the config: recursive directory trees
//! (e.g. `.git/`), directory trees matching glob patterns (e.g.
//! `.boot*`), individual files (e.g. `.gitmodules`), and files
//! matching filename glob patterns (e.g. `*_exceptions.yaml`).  Every
//! matched path is `chown`'d to `root:root` at the mode specified in
//! the config.  Files that already are `root:root` with the correct
//! mode are skipped (idempotent, metadata stat only).
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
//!   1. Before the policy engine (`main.rs:156-163`): closes the window
//!      where a planted `.git/config` payload could fire during
//!      policy-check sub-calls, and locks exception files before any
//!      git operation can read them.
//!   2. After `git.original` exits (`exec.rs:245-248`): reclaims files
//!      that git.original created or modified back to `root:root`,
//!      closing the backdoor window between git operations.
//!
//! The guard's own `rev-parse` resolution uses a hardened environment
//! (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`,
//! `GIT_CONFIG_SYSTEM=/dev/null`, plus `core.fsmonitor=`,
//! `core.hooksPath=` via `GIT_CONFIG_*` overrides) so the resolution
//! call itself cannot be weaponised by a payload already planted in
//! `.git/config`.
//!
//! This module is compiled only in capability mode (`#[cfg(feature =
//! "capability-mode")]`).  In root-only mode the user IS root, so the
//! ownership lock would just impede them and they can chown it back
//! trivially (see docs/ROOT-ONLY-MODE.md).
//!
//! All locked paths are defined in `config/guard_locked_paths.yaml` --
//! NOT hardcoded in Rust.  Edit the YAML and rebuild; no code changes
//! needed to add or remove a locked path.

#![cfg(feature = "capability-mode")]

use std::ffi::CString;
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{is_sudo, CHILD_PATH, GIT_ORIGINAL_PATH};

/// Mode for regular files: world-readable, root-writable only.
const FILE_MODE: u32 = 0o644;
/// Mode for hook files: executable so git actually invokes them
/// (non-executable hooks are skipped by git, resulting in no enforcement).
const HOOK_FILE_MODE: u32 = 0o755;
/// Mode for directories: traversable by all, root can create entries.
const DIR_MODE: u32 = 0o755;

pub fn lock() {
    if is_sudo() {
        return;
    }
    let git_dir = match resolve_git_dir() {
        Some(p) => p,
        None => return,
    };
    let toplevel = match git_dir.parent() {
        Some(p) => p.to_path_buf(),
        None => return,
    };

    // 1. Recursive tree paths (e.g. .git/)
    for entry in crate::LOCKED_RECURSIVE_TREE_PATHS {
        if *entry == ".git" {
            lock_tree(&git_dir, &git_dir);
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

    // 3. Recursive tree glob patterns (e.g. .boot*)
    for entry in crate::LOCKED_RECURSIVE_TREE_GLOB_PATTERNS {
        lock_glob_trees(&toplevel, entry);
    }

    // 4. Glob patterns (e.g. *_exceptions.yaml): recursive scan from toplevel
    for &(pattern, mode) in crate::LOCKED_GLOB_PATTERNS {
        lock_glob_files(&toplevel, pattern, mode);
    }
}

/// Recursively scan `root` for files whose name matches `pattern` and
/// lock each with `mode`.
///
/// Supported glob forms:
///   - `*suffix`       → match files ending with `suffix`
///   - `prefix*`       → match files starting with `prefix`
///   - `*middle*`      → match files containing `middle`
///   - `exact` (no *)  → match files with exactly that name
///
/// Skips `.git/` to avoid re-walking the already-locked git directory.
fn lock_glob_files(root: &Path, pattern: &str, mode: u32) {
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.is_symlink() => {
            let _ = lchown_root(root);
        }
        Ok(meta) if meta.is_dir() => {
            if let Ok(entries) = fs::read_dir(root) {
                for ent in entries.flatten() {
                    let path = ent.path();
                    let file_name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n.to_owned(),
                        None => continue,
                    };
                    if path.is_dir() && file_name != ".git" {
                        lock_glob_files(&path, pattern, mode);
                    } else if path.is_file() && glob_match(pattern, &file_name) {
                        lock_file(&path, mode);
                    }
                }
            }
        }
        Ok(meta) if meta.is_file() => {
            if let Some(name) = root.file_name().and_then(|n| n.to_str()) {
                if glob_match(pattern, name) {
                    lock_file(root, mode);
                }
            }
        }
        _ => {}
    }
}

/// Recursively scan `root` for directories whose name matches `pattern`
/// and lock each matching directory tree with `lock_tree()`.
///
/// Skips `.git/` to avoid re-walking the already-locked git directory.
fn lock_glob_trees(root: &Path, pattern: &str) {
    match fs::symlink_metadata(root) {
        Ok(meta) if meta.is_symlink() => {
            let _ = lchown_root(root);
        }
        Ok(meta) if meta.is_dir() => {
            if let Some(name) = root.file_name().and_then(|n| n.to_str()) {
                if name != ".git" && glob_match(pattern, name) {
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
                    if path.is_dir() && file_name != ".git" {
                        lock_glob_trees(&path, pattern);
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
fn lock_tree(path: &Path, git_dir: &Path) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_symlink() => {
            let _ = lchown_root(path);
        }
        Ok(meta) if meta.is_dir() => {
            lock_dir(path, DIR_MODE);
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

fn resolve_git_dir() -> Option<PathBuf> {
    let mut cmd = Command::new(GIT_ORIGINAL_PATH);
    cmd.env_clear()
        .env("PATH", CHILD_PATH)
        .env("HOME", "/")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_COUNT", "3")
        .env("GIT_CONFIG_KEY_0", "safe.directory")
        .env("GIT_CONFIG_VALUE_0", "*")
        .env("GIT_CONFIG_KEY_1", "core.fsmonitor")
        .env("GIT_CONFIG_VALUE_1", "")
        .env("GIT_CONFIG_KEY_2", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_2", "");
    let out = cmd
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

fn chown_root(path: &Path) -> std::io::Result<()> {
    let c = cpath(path)?;
    let rc = unsafe { libc::chown(c.as_ptr(), 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn lchown_root(path: &Path) -> std::io::Result<()> {
    let c = cpath(path)?;
    let rc = unsafe { libc::lchown(c.as_ptr(), 0, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn chmod(path: &Path, mode: u32) -> std::io::Result<()> {
    let c = cpath(path)?;
    let rc = unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Return the hardened env overrides that neutralise `.git/config` payloads
/// for the duration of a policy-check git.original sub-call. Used by
/// `block.rs git_cmd()` to inject these into its subprocess.
pub fn hardened_git_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_SYSTEM", "/dev/null"),
        ("GIT_CONFIG_COUNT", "3"),
        ("GIT_CONFIG_KEY_0", "safe.directory"),
        ("GIT_CONFIG_VALUE_0", "*"),
        ("GIT_CONFIG_KEY_1", "core.fsmonitor"),
        ("GIT_CONFIG_VALUE_1", ""),
        ("GIT_CONFIG_KEY_2", "core.hooksPath"),
        ("GIT_CONFIG_VALUE_2", ""),
    ]
}

#[cfg(test)]
#[path = "gitdir_tests.rs"]
mod tests;
