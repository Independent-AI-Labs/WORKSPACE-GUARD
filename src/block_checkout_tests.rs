use super::*;

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
