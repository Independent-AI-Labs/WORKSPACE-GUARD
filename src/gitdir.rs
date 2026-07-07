//! Capability-mode ownership lock for paths declared in
//! `config/guard_locked_paths.yaml`: recursive trees (`.git/`),
//! individual files (`.gitmodules`), and glob patterns (`*_exceptions.yaml`).
//! Every matched path is `chown`'d to `root:root`.  The lock runs twice
//! per invocation (pre-policy and post-git.original), is idempotent, and
//! best-effort.  All locked paths are defined in the YAML, not hardcoded.

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
            // .git is resolved via rev-parse (handles submodules, .git files)
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

    // 3. Glob patterns (e.g. *_exceptions.yaml): recursive scan from toplevel
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // --- lock_glob_files tests ---

    #[test]
    fn glob_files_does_not_panic_on_nonexistent_path() {
        let p = PathBuf::from("/tmp/this-path-does-not-exist-1234567890");
        lock_glob_files(&p, "*_exceptions.yaml", 0o644);
    }

    #[test]
    fn glob_files_does_not_panic_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        lock_glob_files(dir.path(), "*_exceptions.yaml", 0o644);
    }

    #[test]
    fn glob_files_finds_nested_exceptions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::write(root.join("quality_exceptions.yaml"), b"x").unwrap();
        fs::write(root.join("other.txt"), b"x").unwrap();

        let config_dir = root.join("config");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(config_dir.join("guard_x_exceptions.yaml"), b"x").unwrap();
        fs::write(config_dir.join("normal.yaml"), b"x").unwrap();

        let sub = root.join("vendor").join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("deep_exceptions.yaml"), b"x").unwrap();

        lock_glob_files(root, "*_exceptions.yaml", 0o644);

        // Every file we created must still exist after the scan
        assert!(root.join("quality_exceptions.yaml").exists());
        assert!(root.join("other.txt").exists());
        assert!(config_dir.join("guard_x_exceptions.yaml").exists());
        assert!(config_dir.join("normal.yaml").exists());
        assert!(sub.join("deep_exceptions.yaml").exists());
    }

    #[test]
    fn glob_files_skips_dotgit() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let git_dir = root.join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(git_dir.join("config"), b"[core]").unwrap();
        fs::write(git_dir.join("pre_exceptions.yaml"), b"x").unwrap();
        let exc = root.join("quality_exceptions.yaml");
        fs::write(&exc, b"x").unwrap();

        lock_glob_files(root, "*_exceptions.yaml", 0o644);
        assert!(exc.exists());
    }

    #[test]
    fn glob_files_handles_symlink_exceptions_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let real_file = root.join("actual.txt");
        fs::write(&real_file, b"hello").unwrap();
        let link = root.join("link_exceptions.yaml");
        std::os::unix::fs::symlink(&real_file, &link).unwrap();

        // Should not panic (symlinks are lchown'd, not followed)
        lock_glob_files(root, "*_exceptions.yaml", 0o644);

        assert!(real_file.exists());
        assert!(link.exists());
    }

    #[test]
    fn glob_files_handles_broken_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let link = root.join("broken_exceptions.yaml");
        std::os::unix::fs::symlink("/nonexistent", &link).unwrap();

        // Should not panic on broken symlink
        lock_glob_files(root, "*_exceptions.yaml", 0o644);
    }

    #[test]
    fn glob_files_multiple_patterns_independent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::write(root.join("foo_exceptions.yaml"), b"x").unwrap();
        fs::write(root.join("bar_exceptions.yaml"), b"x").unwrap();
        fs::write(root.join("other.txt"), b"x").unwrap();

        lock_glob_files(root, "*_exceptions.yaml", 0o644);

        assert!(root.join("foo_exceptions.yaml").exists());
        assert!(root.join("bar_exceptions.yaml").exists());
        assert!(root.join("other.txt").exists());
    }

    #[test]
    fn glob_files_deeply_nested() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let mut cur = root.to_path_buf();
        for i in 0..32 {
            cur = cur.join(format!("depth{}", i));
            fs::create_dir_all(&cur).unwrap();
        }
        let deep_file = cur.join("deep_exceptions.yaml");
        fs::write(&deep_file, b"x").unwrap();

        lock_glob_files(root, "*_exceptions.yaml", 0o644);
        assert!(deep_file.exists());
    }

    // --- glob_match tests ---

    #[test]
    fn glob_match_various_forms() {
        // exact
        assert!(glob_match("foo.yaml", "foo.yaml"));
        assert!(!glob_match("foo.yaml", "bar.yaml"));
        // suffix wildcard
        assert!(glob_match("*_exceptions.yaml", "foo_exceptions.yaml"));
        assert!(!glob_match("*_exceptions.yaml", "exceptions.yaml"));
        // prefix wildcard
        assert!(glob_match("guard_*", "guard_paths.yaml"));
        assert!(!glob_match("guard_*", "myguard_foo"));
        // middle wildcard
        assert!(glob_match("a*c", "abc"));
        assert!(!glob_match("a*c", "ab"));
        // multiple wildcards
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("a*b*c", "aXbY"));
        // wildcard only
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        // empty
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }
}
