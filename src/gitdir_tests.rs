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
fn glob_files_no_crash_on_various_inputs() {
    lock_glob_files(
        Path::new("/nonexistent-path-1234"),
        "*_exceptions.yaml",
        0o644,
    );
    lock_glob_files(
        tempfile::tempdir().unwrap().path(),
        "*_exceptions.yaml",
        0o644,
    );
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
fn glob_match_exact() {
    assert!(glob_match("foo.yaml", "foo.yaml"));
    assert!(!glob_match("foo.yaml", "bar.yaml"));
}

#[test]
fn glob_match_suffix_wildcard() {
    assert!(glob_match("*_exceptions.yaml", "foo_exceptions.yaml"));
    assert!(glob_match("*_exceptions.yaml", "x_exceptions.yaml"));
    assert!(!glob_match("*_exceptions.yaml", "exceptions.yaml"));
    assert!(!glob_match("*_exceptions.yaml", "foo_exceptions.txt"));
}

#[test]
fn glob_match_prefix_wildcard() {
    assert!(glob_match("guard_*", "guard_paths.yaml"));
    assert!(glob_match("guard_*", "guard_"));
    assert!(!glob_match("guard_*", "myguard_foo"));
    assert!(!glob_match("guard_*", "guard"));
}

#[test]
fn glob_match_middle_wildcard() {
    assert!(glob_match("a*c", "abc"));
    assert!(glob_match("a*c", "abbc"));
    assert!(glob_match("a*c", "ac"));
    assert!(!glob_match("a*c", "ab"));
    assert!(!glob_match("a*c", "bc"));
}

#[test]
fn glob_match_multiple_wildcards() {
    assert!(glob_match("a*b*c", "abc"));
    assert!(glob_match("a*b*c", "aXbYc"));
    assert!(glob_match("a*b*c", "aXbYcZc"));
    assert!(!glob_match("a*b*c", "aXbY"));
}

#[test]
fn glob_match_wildcard_only() {
    assert!(glob_match("*", "anything"));
    assert!(glob_match("*", ""));
}

#[test]
fn glob_match_empty_pattern() {
    assert!(glob_match("", ""));
    assert!(!glob_match("", "x"));
}
