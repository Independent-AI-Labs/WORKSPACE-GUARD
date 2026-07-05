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

#[test]
fn sudo_gated_submodule_allowed_for_root() {
    let state = empty_state("submodule");
    let argv_os = argv(&["git", "submodule", "update", "--init"]);
    let sudo = crate::is_sudo();
    let result = check_blocked(&state, "submodule", &argv_os, "/nonexistent-git", None);
    if sudo {
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
    let argv_os = argv(&["git", "checkout", "--", "."]);
    let sudo = crate::is_sudo();
    let result = check_blocked(&state, "checkout", &argv_os, "/nonexistent-git", None);
    if sudo {
        assert!(result.is_ok(), "root should be allowed: {:?}", result);
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
}

#[test]
fn checkout_not_in_blocked_list() {
    assert!(!BLOCKED_SUBCOMMANDS.contains(&"checkout"));
    assert!(SUDO_GATED_SUBCOMMANDS.contains(&"checkout"));
}

#[test]
fn sudo_gated_stash_drop() {
    let mut state = empty_state("stash");
    state.has_stash_drop = true;
    let argv_os = argv(&["git", "stash", "drop"]);
    let sudo = crate::is_sudo();
    let result = check_blocked(&state, "stash", &argv_os, "/nonexistent-git", None);
    if sudo {
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
    let sudo = crate::is_sudo();
    let result = check_blocked(&state, "stash", &argv_os, "/nonexistent-git", None);
    if sudo {
        assert!(result.is_ok(), "root should be allowed: {:?}", result);
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
}
