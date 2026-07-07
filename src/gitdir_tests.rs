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

// --- lock_glob_trees tests ---

#[test]
fn glob_trees_no_crash_on_nonexistent() {
    lock_glob_trees(Path::new("/nonexistent-path-1234"), ".boot*");
    lock_glob_trees(tempfile::tempdir().unwrap().path(), ".boot*");
}

#[test]
fn glob_trees_finds_boot_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let boot_dir = root.join(".boot");
    fs::create_dir_all(&boot_dir).unwrap();
    fs::write(boot_dir.join("vmlinuz"), b"x").unwrap();

    let bootloader_dir = root.join(".bootloader");
    fs::create_dir_all(&bootloader_dir).unwrap();
    fs::write(bootloader_dir.join("stage1.bin"), b"x").unwrap();

    let other = root.join("other");
    fs::create_dir_all(&other).unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(boot_dir.join("vmlinuz").exists());
    assert!(bootloader_dir.join("stage1.bin").exists());
    assert!(other.exists());
}

#[test]
fn glob_trees_finds_nested_boot_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let nested = root.join("vendor").join(".boot-artifacts");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("kernel.img"), b"x").unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(nested.join("kernel.img").exists());
}

#[test]
fn glob_trees_skips_dotgit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let git_dir = root.join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join("config"), b"[core]").unwrap();

    let boot_dir = root.join(".boot");
    fs::create_dir_all(&boot_dir).unwrap();
    fs::write(boot_dir.join("initrd"), b"x").unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(boot_dir.join("initrd").exists());
    assert!(git_dir.join("config").exists());
}

#[test]
fn glob_trees_does_not_lock_plain_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let normal = root.join("src");
    fs::create_dir_all(&normal).unwrap();
    fs::write(normal.join("main.rs"), b"fn main() {}").unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(normal.join("main.rs").exists());
}

#[test]
fn glob_trees_handles_symlink_dir() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let real = root.join("real_boot");
    fs::create_dir_all(&real).unwrap();
    fs::write(real.join("file"), b"x").unwrap();

    let link = root.join(".boot-link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(real.join("file").exists());
    assert!(link.exists());
}

#[test]
fn glob_trees_handles_broken_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let link = root.join(".boot-broken");
    std::os::unix::fs::symlink("/nonexistent", &link).unwrap();

    lock_glob_trees(root, ".boot*");
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

// --- file_lock_mode tests ---

#[test]
fn file_lock_mode_preserves_user_exec() {
    assert_eq!(file_lock_mode(0o744), 0o744);
}

#[test]
fn file_lock_mode_preserves_group_exec() {
    assert_eq!(file_lock_mode(0o654), 0o654);
}

#[test]
fn file_lock_mode_preserves_other_exec() {
    assert_eq!(file_lock_mode(0o647), 0o645);
}

#[test]
fn file_lock_mode_preserves_all_exec() {
    assert_eq!(file_lock_mode(0o755), 0o755);
}

#[test]
fn file_lock_mode_strips_write_bits_from_group_other() {
    let mode = file_lock_mode(0o777);
    assert_eq!(mode & 0o022, 0);
    assert_eq!(mode & 0o111, 0o111);
    assert_eq!(mode & 0o644, 0o644);
}

#[test]
fn file_lock_mode_no_exec_stays_644() {
    assert_eq!(file_lock_mode(0o644), 0o644);
    assert_eq!(file_lock_mode(0o600), 0o644);
}

#[test]
fn file_lock_mode_zero_mode_becomes_644() {
    assert_eq!(file_lock_mode(0o000), 0o644);
}

#[test]
fn file_lock_mode_preserves_only_exec_ignores_setuid_setgid_sticky() {
    let mode = file_lock_mode(0o4755);
    assert_eq!(mode, 0o755);
    let mode = file_lock_mode(0o2755);
    assert_eq!(mode, 0o755);
    let mode = file_lock_mode(0o1755);
    assert_eq!(mode, 0o755);
}

#[test]
fn file_lock_mode_user_exec_only() {
    assert_eq!(file_lock_mode(0o700), 0o744);
}

#[test]
fn file_lock_mode_group_exec_only() {
    assert_eq!(file_lock_mode(0o070), 0o654);
}

#[test]
fn file_lock_mode_other_exec_only() {
    assert_eq!(file_lock_mode(0o007), 0o645);
}

// --- lock_glob_trees exec-bit structure tests ---

#[test]
fn glob_trees_does_not_crash_on_large_dir_hierarchy() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    for i in 0..10 {
        let sub = root.join(format!("depth{}", i));
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("file.txt"), b"x").unwrap();
    }

    lock_glob_trees(root, ".boot*");
}

#[test]
fn glob_trees_multiple_matching_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let b1 = root.join(".boot-one");
    fs::create_dir_all(&b1).unwrap();
    fs::write(b1.join("a.bin"), b"x").unwrap();

    let b2 = root.join(".boot-two");
    fs::create_dir_all(&b2).unwrap();
    fs::write(b2.join("b.bin"), b"x").unwrap();

    let nested = root.join("sub").join(".boot-three");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("c.bin"), b"x").unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(b1.join("a.bin").exists());
    assert!(b2.join("b.bin").exists());
    assert!(nested.join("c.bin").exists());
}

#[test]
fn glob_trees_does_not_match_non_dot_boot_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let normal = root.join("boot");
    fs::create_dir_all(&normal).unwrap();
    fs::write(normal.join("x.txt"), b"x").unwrap();

    let partial = root.join("myboot-extra");
    fs::create_dir_all(&partial).unwrap();
    fs::write(partial.join("y.txt"), b"x").unwrap();

    lock_glob_trees(root, ".boot*");

    assert!(normal.join("x.txt").exists());
    assert!(partial.join("y.txt").exists());
}

#[test]
fn glob_trees_handles_empty_root() {
    let dir = tempfile::tempdir().unwrap();
    lock_glob_trees(dir.path(), ".boot*");
}

#[test]
fn glob_trees_handles_root_is_file() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("not_a_dir");
    fs::write(&f, b"x").unwrap();
    lock_glob_trees(&f, ".boot*");
}

#[test]
fn glob_trees_exec_bits_preserved_on_binary_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let boot_dir = root.join(".boot-test");
    fs::create_dir_all(&boot_dir).unwrap();
    fs::write(boot_dir.join("node"), b"x").unwrap();
    fs::write(boot_dir.join("script.sh"), b"#!/bin/sh\necho hi\n").unwrap();

    std::process::Command::new("chmod")
        .args(["+x", &boot_dir.join("node").to_string_lossy()])
        .output()
        .unwrap();
    std::process::Command::new("chmod")
        .args(["+x", &boot_dir.join("script.sh").to_string_lossy()])
        .output()
        .unwrap();

    lock_glob_trees(root, ".boot*");

    let node_mode = fs::symlink_metadata(boot_dir.join("node"))
        .unwrap()
        .st_mode()
        & 0o111;
    let script_mode = fs::symlink_metadata(boot_dir.join("script.sh"))
        .unwrap()
        .st_mode()
        & 0o111;

    assert!(node_mode != 0, "node lost all execute bits");
    assert!(script_mode != 0, "script.sh lost all execute bits");
}
