//! Protected-branch policy tests using a real git repository fixture.

use super::*;
use crate::args;
use std::path::Path;
use std::process::Command;

fn find_git() -> Option<String> {
    for candidate in ["/usr/bin/git", "/usr/local/bin/git"] {
        if Path::new(candidate).is_file() {
            return Some(candidate.to_string());
        }
    }
    Command::new("git")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| "git".to_string())
}

fn init_main_repo(dir: &Path, git: &str) -> bool {
    let run = |args: &[&str]| -> bool {
        Command::new(git)
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    run(&["init", "-q"])
        && run(&["config", "user.email", "protected@test.local"])
        && run(&["config", "user.name", "Protected Branch Test"])
        && std::fs::write(dir.join("file.txt"), b"x").is_ok()
        && run(&["add", "file.txt"])
        && run(&["commit", "-q", "-m", "init"])
        && run(&["branch", "-M", "main"])
}

fn evaluate(argv: &[&str], git: &str, cwd: &str) -> Result<(), GuardError> {
    let bytes: Vec<&[u8]> = argv.iter().map(|s| s.as_bytes()).collect();
    args::check_null_bytes(&bytes)?;
    let state = args::parse_args(&bytes)?;
    let sub = state.subcommand.as_deref().unwrap_or("");
    let os: Vec<OsString> = argv.iter().map(OsString::from).collect();
    check_blocked(&state, sub, &os, git, Some(cwd))
}

#[test]
fn protected_branch_pull_without_safe_flag_blocked() {
    let Some(git) = find_git() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    if !init_main_repo(dir.path(), &git) {
        return;
    }
    let cwd = dir.path().to_string_lossy().to_string();
    let result = evaluate(&["git", "pull"], &git, &cwd);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "pull on main without --ff-only/--rebase should block: {:?}",
        result
    );
}

#[test]
fn protected_branch_pull_ff_only_allowed() {
    let Some(git) = find_git() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    if !init_main_repo(dir.path(), &git) {
        return;
    }
    let cwd = dir.path().to_string_lossy().to_string();
    let result = evaluate(&["git", "pull", "--ff-only"], &git, &cwd);
    assert!(result.is_ok(), "pull --ff-only on main should be allowed: {:?}", result);
}

#[test]
fn protected_branch_merge_without_ff_only_blocked_for_non_root() {
    if crate::is_sudo() {
        return;
    }
    let Some(git) = find_git() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    if !init_main_repo(dir.path(), &git) {
        return;
    }
    let cwd = dir.path().to_string_lossy().to_string();
    let result = evaluate(&["git", "merge", "feature"], &git, &cwd);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "merge on main without --ff-only should block for non-root: {:?}",
        result
    );
}

#[test]
fn protected_branch_merge_ff_only_allowed() {
    let Some(git) = find_git() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    if !init_main_repo(dir.path(), &git) {
        return;
    }
    let cwd = dir.path().to_string_lossy().to_string();
    let result = evaluate(&["git", "merge", "--ff-only", "feature"], &git, &cwd);
    assert!(
        result.is_ok(),
        "merge --ff-only on main should be allowed: {:?}",
        result
    );
}

#[test]
fn protected_branch_release_prefix_pull_blocked() {
    let Some(git) = find_git() else {
        return;
    };
    let dir = tempfile::tempdir().expect("tempdir");
    if !init_main_repo(dir.path(), &git) {
        return;
    }
    let git_cmd = |args: &[&str]| -> bool {
        Command::new(&git)
            .args(args)
            .current_dir(dir.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !git_cmd(&["checkout", "-q", "-b", "release/1.0"]) {
        return;
    }
    let cwd = dir.path().to_string_lossy().to_string();
    let result = evaluate(&["git", "pull"], &git, &cwd);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "pull on release/* without safe flags should block: {:?}",
        result
    );
}