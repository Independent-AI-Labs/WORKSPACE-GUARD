use super::*;
use crate::args::ArgState;

fn empty_state(subcommand: &str) -> ArgState {
    ArgState {
        subcommand: Some(subcommand.to_string()),
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
fn sudo_gated_checkout_allowed_for_root() {
    let state = empty_state("checkout");
    let argv_os = argv(&["git", "checkout", "main"]);
    let root = crate::is_config_privileged();
    let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
    if root {
        assert!(result.is_ok(), "root should be allowed: {:?}", result);
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
}

#[test]
fn checkout_head_file_blocked_even_for_root() {
    let state = empty_state("checkout");
    let argv_os = argv(&["git", "checkout", "HEAD", "--", "README.md"]);
    let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "checkout HEAD path restore must be blocked for all users: {:?}",
        result
    );
}

#[test]
fn checkout_head_file_no_sep_blocked() {
    let state = empty_state("checkout");
    let argv_os = argv(&["git", "checkout", "HEAD", "README.md"]);
    let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "checkout HEAD file without separator must be blocked: {:?}",
        result
    );
}

#[test]
fn checkout_single_file_blocked() {
    let state = empty_state("checkout");
    let argv_os = argv(&["git", "checkout", "README.md"]);
    let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "checkout <file> must be blocked: {:?}",
        result
    );
}

#[test]
fn plumbing_checkout_index_blocked() {
    let state = empty_state("checkout-index");
    let argv_os = argv(&["git", "checkout-index", "-f", "-a"]);
    let result = check_blocked(&state, "checkout-index", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn plumbing_update_index_blocked() {
    let state = empty_state("update-index");
    let argv_os = argv(&["git", "update-index", "--force-remove", "x.txt"]);
    let result = check_blocked(&state, "update-index", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn sudo_gated_uses_euid_not_at_secure() {
    // File-cap host-exec sets AT_SECURE for every git invocation; sudo-gated
    // must key off euid==0, not is_sudo()/AT_SECURE.
    if crate::is_sudo() && !crate::is_config_privileged() {
        let state = empty_state("checkout");
        let argv_os = argv(&["git", "checkout", "main"]);
        let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
        assert!(
            matches!(result, Err(GuardError::Blocked { .. })),
            "AT_SECURE without euid 0 must still block checkout: {:?}",
            result
        );
    }
}

#[test]
fn checkout_discard_blocked_even_for_root() {
    let state = empty_state("checkout");
    let argv_os = argv(&["git", "checkout", "--", "."]);
    let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "destructive checkout should be blocked for all users: {:?}",
        result
    );
}

#[test]
fn switch_discard_changes_blocked() {
    let state = empty_state("switch");
    let argv_os = argv(&["git", "switch", "--discard-changes"]);
    let result = check_blocked(&state, "switch", &argv_os, "/nonexistent-git", None);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "switch --discard-changes should be blocked: {:?}",
        result
    );
}

#[test]
fn checkout_not_in_blocked_list() {
    assert!(!BLOCKED_SUBCOMMANDS.contains(&"checkout"));
    assert!(SUDO_GATED_SUBCOMMANDS.contains(&"checkout"));
}

#[test]
fn restore_is_sudo_gated_not_blocked() {
    assert!(!BLOCKED_SUBCOMMANDS.contains(&"restore"));
    assert!(SUDO_GATED_SUBCOMMANDS.contains(&"restore"));
}

#[test]
fn sudo_gated_restore_allowed_for_root() {
    let state = empty_state("restore");
    let argv_os = argv(&["git", "restore", "README.md"]);
    let root = crate::is_config_privileged();
    let result = check_blocked(&state, "restore", &argv_os, "/nonexistent-git", None);
    if root {
        assert!(result.is_ok(), "root should be allowed: {:?}", result);
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
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
    let mut state = empty_state("commit");
    state.has_amend = true;
    let argv_os = argv(&["git", "commit", "--amend"]);
    let result = check_blocked(&state, "commit", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
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
fn sudo_gated_stash_drop() {
    let mut state = empty_state("stash");
    state.has_stash_drop = true;
    let argv_os = argv(&["git", "stash", "drop"]);
    let root = crate::is_config_privileged();
    let result = check_blocked(&state, "stash", &argv_os, "/nonexistent-git", None);
    if root {
        assert!(result.is_ok(), "root should be allowed: {:?}", result);
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
}

#[test]
fn sudo_gated_stash_clear() {
    let mut state = empty_state("stash");
    state.has_stash_clear = true;
    let argv_os = argv(&["git", "stash", "clear"]);
    let root = crate::is_config_privileged();
    let result = check_blocked(&state, "stash", &argv_os, "/nonexistent-git", None);
    if root {
        assert!(result.is_ok(), "root should be allowed: {:?}", result);
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
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
fn bypass_env_skip_blocked() {
    std::env::set_var("SKIP", "1");
    let result = {
        let state = empty_state("status");
        let argv_os = argv(&["git", "status"]);
        check_blocked(&state, "status", &argv_os, "/nonexistent-git", None)
    };
    clear_blocked_bypass_env_vars();
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn bypass_env_pre_commit_allow_no_config_blocked() {
    std::env::set_var("PRE_COMMIT_ALLOW_NO_CONFIG", "1");
    let result = {
        let state = empty_state("commit");
        let argv_os = argv(&["git", "commit", "-m", "x"]);
        check_blocked(&state, "commit", &argv_os, "/nonexistent-git", None)
    };
    clear_blocked_bypass_env_vars();
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[path = "block_protected_branch_tests.rs"]
mod protected_branch_tests;

#[test]
fn checkout_dotless_existing_file_blocked() {
    // Item 20: ambiguous single pathspec that exists on disk is treated as
    // a path (git resolves the ambiguity as a pathspec too). Absolute path
    // keeps the test cwd-independent.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("LICENSE");
    std::fs::write(&file, b"x").unwrap();
    let state = empty_state("checkout");
    let argv_os = argv(&["git", "checkout", file.to_str().unwrap()]);
    let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
    assert!(
        matches!(result, Err(GuardError::Blocked { .. })),
        "checkout of existing dotless file must be blocked: {:?}",
        result
    );
}
#[test]
fn checkout_dotless_nonexistent_name_allowed() {
    // No dot, no leading dot, no colon, and nothing on disk: parsed as a
    // branch name and allowed (sudo-gated, not universally blocked).
    let state = empty_state("checkout");
    let argv_os = argv(&["git", "checkout", "no-such-branch-or-file-xyz"]);
    let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
    // checkout itself is sudo-gated for non-root; what must not happen is a
    // "pathspec discard" classification for a name absent from disk.
    if let Err(GuardError::Blocked { reason, .. }) = &result {
        assert!(
            !reason.contains("pathspec"),
            "branch-looking name absent from disk must not be path-blocked: {:?}",
            result
        );
    }
}
