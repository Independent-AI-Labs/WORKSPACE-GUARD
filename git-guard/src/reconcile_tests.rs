use super::*;

#[test]
fn mutating_subcommands_are_classified() {
    for sub in [
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
    ] {
        assert!(is_mutating(sub), "{sub} must be classified mutating");
    }
}

#[test]
fn non_mutating_subcommands_are_classified() {
    for sub in [
        "commit", "status", "log", "diff", "fetch", "push", "show", "stash", "branch", "tag",
    ] {
        assert!(!is_mutating(sub), "{sub} must not be classified mutating");
    }
}

#[test]
fn immutable_flag_unknown_for_missing_path() {
    assert_eq!(
        immutable_flag(Path::new("/nonexistent-guard-test-path")),
        None
    );
}

#[test]
fn immutable_flag_reads_real_file() {
    let dir = std::env::temp_dir().join(format!("guard-reconcile-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let f = dir.join("plain.txt");
    fs::write(&f, b"x").unwrap();
    // A freshly created temp file is never immutable; the ioctl must
    // succeed and report Some(false) on any filesystem that supports
    // inode flags, and None where unsupported. Both are acceptable,
    // but Some(true) is impossible here.
    assert_ne!(immutable_flag(&f), Some(true));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn run_out_of_scope_repo_yields_no_drift() {
    let dir = std::env::temp_dir().join(format!("guard-reconcile-scope-{}", std::process::id()));
    let git_dir = dir.join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::create_dir_all(dir.join("config")).unwrap();
    fs::write(dir.join("config/policy.yaml"), b"k: v\n").unwrap();
    // /tmp is outside the workspace and not a provisioned remote:
    // reconcile must not touch it and must report no drift.
    let drift = run(&git_dir);
    assert!(drift.is_empty(), "unexpected drift: {:?}", drift);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn glob_match_semantics() {
    assert!(glob_match("*_exceptions.yaml", "quality_exceptions.yaml"));
    assert!(glob_match("*_exceptions.yaml", "_exceptions.yaml"));
    assert!(!glob_match("*_exceptions.yaml", "exceptions.yaml"));
    assert!(!glob_match("*_exceptions.yaml", "quality_exceptions.yml"));
    assert!(glob_match("exemption_files.yaml", "exemption_files.yaml"));
    assert!(!glob_match("exemption_files.yaml", "other.yaml"));
    assert!(glob_match("*", "anything"));
}

#[test]
fn missing_git_dir_parent_yields_no_drift() {
    let drift = run(Path::new("/"));
    assert!(drift.is_empty());
}
