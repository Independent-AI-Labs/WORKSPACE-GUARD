//! Capability-mode `.git` ownership lock.
//!
//! Before delegating to the real git binary, the guard claims ownership
//! of the ENTIRE `.git/` directory tree and the repo-root `.gitmodules`.
//! Every file and directory inside `.git/` is `chown`'d to `root:root`
//! and given a mode that allows all users to READ/TRAVERSE but only root
//! to WRITE. Hook files under `.git/hooks/` are kept at 0o755 (executable)
//! so git actually invokes them (non-executable hooks are skipped by git
//! by git, which would bypass all enforcement.
//!
//! This closes the local RCE vector surfaced by the CVE history of
//! `.git/config` injection (`core.fsmonitor`, `core.hooksPath`,
//! `include.path`), `.git/hooks/` trojaning (CVE-2025-48384), and attacks
//! on `.git/index`, `.git/HEAD`, `.git/refs/`, `.git/objects/`,
//! `.git/logs/`, etc. Once locked, the user cannot directly write to
//! ANY part of `.git/`. They can still operate the repository normally
//! because the guard grants `CAP_DAC_OVERRIDE` to `git.original` via
//! the Ambient capability set for the duration of the authorized
//! subcommand only.
//!
//! The lock runs TWICE per invocation:
//!   1. Before the policy engine: closes the window where a planted
//!      `.git/config` payload could fire during policy-check sub-calls.
//!   2. After `git.original` exits: reclaims any files that git.original
//!      created or modified (which will be owned by the real user's uid)
//!      back to `root:root`. This closes the "backdoor" window where the
//!      user could write to agent-owned .git/ files between git operations.
//!
//! The guard's own `rev-parse` resolution uses a hardened environment
//! (`GIT_CONFIG_NOSYSTEM`, `core.fsmonitor=`, `core.hooksPath=`, etc.)
//! so the resolution call itself cannot be weaponised by a payload
//! already planted in `.git/config`.
//!
//! This module is compiled only in capability mode: in root-only mode
//! the user IS root, so a `.git` ownership lock would just impede them
//! and they can chown it back trivially (the soft-barrier threat model
//! already accepts root bypasses (see docs/ROOT-ONLY-MODE.md).
//!
//! The lock is idempotent: if a path is already `root:root` with the
//! target mode, no syscall is issued, so the per-invocation overhead
//! after the first lock is a metadata stat only.

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

    lock_tree(&git_dir, &git_dir);

    let toplevel = match git_dir.parent() {
        Some(p) => p.to_path_buf(),
        None => return,
    };
    let modules = toplevel.join(".gitmodules");
    if modules.exists() && !modules.is_symlink() {
        lock_file(&modules, FILE_MODE);
    }
}

/// Check if `file` is inside the `-hooks` subdirectory of `git_dir`.
fn is_hook_file(path: &Path, git_dir: &Path) -> bool {
    let hooks_dir = git_dir.join("hooks");
    path.starts_with(&hooks_dir)
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
        Ok(_) => {
            lock_file(path, FILE_MODE);
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
/// block.rs `git_cmd()` to inject these into its subprocess.
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
mod tests {
    use super::*;

    #[test]
    fn needs_lock_flags_non_root_owned() {
        assert!(needs_lock(1000, 1000));
        assert!(needs_lock(1000, 0));
        assert!(!needs_lock(0, 0));
    }

    #[test]
    fn lock_does_not_panic_without_git() {
        lock();
    }

    #[test]
    fn cpath_rejects_nul_byte() {
        use std::os::unix::ffi::OsStringExt;
        let bad = std::ffi::OsString::from_vec(vec![b'a', 0, b'b']);
        let p = PathBuf::from(bad);
        let res = cpath(&p);
        assert!(res.is_err());
    }

    #[test]
    fn hardened_git_env_contains_key_overrides() {
        let env = hardened_git_env();
        assert!(env.iter().any(|(k, _)| *k == "GIT_CONFIG_NOSYSTEM"));
        assert!(env.iter().any(|(k, _)| *k == "GIT_CONFIG_KEY_1"));
        assert!(env
            .iter()
            .any(|(k, v)| *k == "GIT_CONFIG_VALUE_1" && v.is_empty()));
    }

    #[test]
    fn is_hook_file_detects_hooks() {
        let git_dir = PathBuf::from("/repo/.git");
        assert!(is_hook_file(
            &PathBuf::from("/repo/.git/hooks/pre-commit"),
            &git_dir
        ));
        assert!(is_hook_file(
            &PathBuf::from("/repo/.git/hooks/commit-msg"),
            &git_dir
        ));
        assert!(!is_hook_file(&PathBuf::from("/repo/.git/config"), &git_dir));
        assert!(!is_hook_file(&PathBuf::from("/repo/.git/HEAD"), &git_dir));
        assert!(!is_hook_file(&PathBuf::from("/repo/.git/index"), &git_dir));
    }
}
