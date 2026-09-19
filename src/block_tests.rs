use super::*;
use crate::args::ArgState;

fn empty_state(subcommand: &str) -> ArgState {
    ArgState {
        subcommand: Some(subcommand.to_string()),
        subcommand_raw: Some(subcommand.to_string()),
        has_amend: false,
        has_force_flag: false,
        has_force_with_lease_flag: false,
        has_branch_d: false,
        has_branch_force_rename: false,
        has_stash_drop: false,
        has_stash_clear: false,
        safe_pull_flag: false,
        has_rebase_safe_flag: false,
        has_ff_only: false,
        has_merge_abort: false,
        has_cached: false,
        has_delete_flag: false,
        dangerous_config_keys: Vec::new(),
        config_spans: Vec::new(),
        no_verify_short_idxs: Vec::new(),
    }
}

fn argv(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn clear_blocked_bypass_env_vars() {
    for &var in crate::BLOCKED_BYPASS_VARS {
        std::env::remove_var(var);
    }
}

#[test]
fn blocked_subcommands_in_config() {
    for sub in [
        "reset",
        "clean",
        "update-ref",
        "read-tree",
        "symbolic-ref",
        "checkout-index",
        "update-index",
        "merge-file",
        "merge-index",
    ] {
        assert!(
            BLOCKED_SUBCOMMANDS.contains(&sub),
            "{sub} should be unconditionally blocked"
        );
    }
}

#[test]
fn switch_is_sudo_gated_not_blocked() {
    assert!(!BLOCKED_SUBCOMMANDS.contains(&"switch"));
    assert!(SUDO_GATED_SUBCOMMANDS.contains(&"switch"));
}

#[test]
fn plumbing_subcommands_blocked_for_root() {
    for sub in [
        "update-ref",
        "read-tree",
        "symbolic-ref",
        "write-tree",
        "commit-tree",
        "checkout-index",
        "update-index",
        "merge-file",
        "merge-index",
    ] {
        let state = empty_state(sub);
        let argv_os = argv(&["git", sub]);
        let result = check_blocked(&state, sub, &argv_os, "/nonexistent-git", None);
        assert!(
            matches!(result, Err(GuardError::Blocked { .. })),
            "{sub} should be blocked even for root: {:?}",
            result
        );
    }
}

#[test]
fn sudo_gated_submodule_allowed_for_root() {
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
    let state = empty_state("submodule");
    let argv_os = argv(&["git", "submodule", "update", "--init"]);
    let root = crate::is_config_privileged();
    let result = check_blocked(&state, "submodule", &argv_os, "/nonexistent-git", None);
    if root {
        assert!(result.is_ok(), "root should be allowed: {:?}", result);
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
}

#[test]
fn submodule_not_in_blocked_list() {
    assert!(!BLOCKED_SUBCOMMANDS.contains(&"submodule"));
    assert!(SUDO_GATED_SUBCOMMANDS.contains(&"submodule"));
}

#[test]
fn blocked_still_blocked_for_root() {
    let state = empty_state("reset");
    let argv_os = argv(&["git", "reset", "--hard"]);
    let result = check_blocked(&state, "reset", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn push_force_blocked() {
    let mut state = empty_state("push");
    state.has_force_flag = true;
    let argv_os = argv(&["git", "push", "--force", "origin", "main"]);
    let result = check_blocked(&state, "push", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn commit_amend_blocked() {
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
    let mut state = empty_state("commit");
    state.has_amend = true;
    let argv_os = argv(&["git", "commit", "--amend"]);
    let result = check_blocked(&state, "commit", &argv_os, "/nonexistent-git", None);
    if crate::is_config_privileged() {
        assert!(result.is_ok(), "root should be allowed: {:?}", result);
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
}

#[test]
fn rm_without_cached_blocked() {
    let state = empty_state("rm");
    let argv_os = argv(&["git", "rm", "file.txt"]);
    let result = check_blocked(&state, "rm", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn rm_cached_allowed() {
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
    let mut state = empty_state("rm");
    state.has_cached = true;
    let argv_os = argv(&["git", "rm", "--cached", "file.txt"]);
    let result = check_blocked(&state, "rm", &argv_os, "/nonexistent-git", None);
    assert!(
        result.is_ok(),
        "rm --cached should be allowed: {:?}",
        result
    );
}

#[test]
fn rebase_without_safe_flag_blocked() {
    let state = empty_state("rebase");
    let argv_os = argv(&["git", "rebase", "main"]);
    let result = check_blocked(&state, "rebase", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn rebase_continue_allowed() {
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
    let mut state = empty_state("rebase");
    state.has_rebase_safe_flag = true;
    let argv_os = argv(&["git", "rebase", "--continue"]);
    let result = check_blocked(&state, "rebase", &argv_os, "/nonexistent-git", None);
    assert!(
        result.is_ok(),
        "rebase --continue should be allowed: {:?}",
        result
    );
}

#[test]
fn stash_drop_blocked_even_for_root() {
    let mut state = empty_state("stash");
    state.has_stash_drop = true;
    let argv_os = argv(&["git", "stash", "drop"]);
    let result = check_blocked(&state, "stash", &argv_os, "/nonexistent-git", None);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "stash drop is blocked for all users (REQ-GGUARD-050): {:?}",
        result
    );
}

#[test]
fn stash_clear_blocked_even_for_root() {
    let mut state = empty_state("stash");
    state.has_stash_clear = true;
    let argv_os = argv(&["git", "stash", "clear"]);
    let result = check_blocked(&state, "stash", &argv_os, "/nonexistent-git", None);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "stash clear is blocked for all users (REQ-GGUARD-050): {:?}",
        result
    );
}

#[test]
fn destructive_checkout_or_switch_detects_pathspec_dot() {
    let os = argv(&["git", "checkout", "--", "."]);
    assert_eq!(
        destructive_checkout_or_switch("checkout", &os),
        Some("pathspec discard")
    );
}

#[test]
fn destructive_checkout_or_switch_detects_head_file() {
    let os = argv(&["git", "checkout", "HEAD", "--", "README.md"]);
    assert_eq!(
        destructive_checkout_or_switch("checkout", &os),
        Some("pathspec discard")
    );
}

#[test]
fn destructive_checkout_or_switch_detects_head_file_no_sep() {
    let os = argv(&["git", "checkout", "HEAD", "README.md"]);
    assert_eq!(
        destructive_checkout_or_switch("checkout", &os),
        Some("tree-ish path restore")
    );
}

#[test]
fn destructive_checkout_or_switch_detects_single_file() {
    let os = argv(&["git", "checkout", "README.md"]);
    assert_eq!(
        destructive_checkout_or_switch("checkout", &os),
        Some("pathspec discard")
    );
}

#[test]
fn destructive_checkout_or_switch_allows_branch_switch() {
    let os = argv(&["git", "checkout", "main"]);
    assert_eq!(destructive_checkout_or_switch("checkout", &os), None);
}

#[test]
fn destructive_checkout_or_switch_allows_slash_branch() {
    let os = argv(&["git", "checkout", "feature/foo"]);
    assert_eq!(destructive_checkout_or_switch("checkout", &os), None);
}

#[test]
fn destructive_checkout_or_switch_detects_patch() {
    let os = argv(&["git", "checkout", "-p", "README.md"]);
    assert_eq!(
        destructive_checkout_or_switch("checkout", &os),
        Some("patch discard")
    );
}

#[test]
fn destructive_checkout_or_switch_detects_force() {
    let os = argv(&["git", "checkout", "-f", "main"]);
    assert_eq!(
        destructive_checkout_or_switch("checkout", &os),
        Some("force discard")
    );
}

#[test]
fn destructive_checkout_or_switch_detects_force_create() {
    let os = argv(&["git", "checkout", "-B", "newbranch"]);
    assert_eq!(
        destructive_checkout_or_switch("checkout", &os),
        Some("force branch switch")
    );
}

#[test]
fn destructive_checkout_or_switch_detects_switch_force_recreate() {
    let os = argv(&["git", "switch", "-B", "newbranch"]);
    assert_eq!(
        destructive_checkout_or_switch("switch", &os),
        Some("discard-changes / force-create")
    );
}

#[test]
fn branch_force_rename_blocked() {
    let mut state = empty_state("branch");
    state.has_branch_force_rename = true;
    let argv_os = argv(&["git", "branch", "-M", "old", "new"]);
    let result = check_blocked(&state, "branch", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn push_force_with_lease_blocked() {
    let mut state = empty_state("push");
    state.has_force_with_lease_flag = true;
    let argv_os = argv(&["git", "push", "--force-with-lease", "origin", "main"]);
    let result = check_blocked(&state, "push", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn tag_delete_uppercase_blocked() {
    let mut state = empty_state("tag");
    state.has_branch_d = true;
    let argv_os = argv(&["git", "tag", "-D", "v1"]);
    let result = check_blocked(&state, "tag", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn config_dangerous_key_blocked() {
    let mut state = empty_state("config");
    state
        .dangerous_config_keys
        .push("core.hooksPath".to_string());
    let argv_os = argv(&["git", "config", "core.hooksPath", "/evil"]);
    let result = check_blocked(&state, "config", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn config_read_shape_allows_key_display() {
    // Reads display a value and persist nothing: sudo-gated identity
    // keys and dangerous keys must pass as single positionals or under
    // get forms (Claude Code probes these constantly).
    for args in [
        vec!["git", "config", "user.name"],
        vec!["git", "config", "--get", "user.email"],
        vec!["git", "config", "core.hooksPath"],
        vec!["git", "config", "--file", "/tmp/x", "user.name"],
    ] {
        let state = empty_state("config");
        let argv_os = argv(&args);
        let result = check_blocked(&state, "config", &argv_os, "/nonexistent-git", None);
        assert!(result.is_ok(), "read should pass: {:?}", args);
    }
}

#[test]
fn config_write_shape_blocks_keys() {
    for args in [
        vec!["git", "config", "user.email", "x@y"],
        vec!["git", "config", "core.hooksPath", "/evil"],
        vec!["git", "config", "--unset", "user.email"],
        vec!["git", "config", "--add", "core.hooksPath", "/evil"],
        vec![
            "git",
            "config",
            "--file",
            "/tmp/x",
            "core.hooksPath",
            "/evil",
        ],
    ] {
        let state = empty_state("config");
        let argv_os = argv(&args);
        let result = check_blocked(&state, "config", &argv_os, "/nonexistent-git", None);
        assert!(
            matches!(result, Err(GuardError::Blocked { .. })),
            "write should block: {:?}",
            args
        );
    }
}

#[path = "block_protected_branch_tests.rs"]
mod protected_branch_tests;

#[cfg(test)]
#[path = "block_checkout_tests.rs"]
mod checkout_tests;

#[cfg(test)]
#[path = "block_bypass_env_tests.rs"]
mod bypass_env_tests;
