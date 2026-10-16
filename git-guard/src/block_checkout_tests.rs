use super::*;
use crate::child::{parent_argv_subcommand_in, stash_verb};

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
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
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
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
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
fn rebase_without_safe_flag_blocked() {
    let state = empty_state("rebase");
    let argv_os = argv(&["git", "rebase", "main"]);
    let result = check_blocked(&state, "rebase", &argv_os, "/nonexistent-git", None);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn rebase_onto_direct_blocked() {
    // REQ-GGUARD-064: the pull-generated `--onto` shape alone is not enough;
    // a direct rebase's parent is not a running `pull --rebase`, so it stays
    // blocked even when the caller forges the old session env vars.
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
    std::env::set_var(crate::SESSION_ENV, "1");
    let state = empty_state("rebase");
    let argv_os = argv(&["git", "rebase", "--onto", "aaaa", "bbbb"]);
    let result = check_blocked(&state, "rebase", &argv_os, "/nonexistent-git", None);
    std::env::remove_var(crate::SESSION_ENV);
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn rebase_approval_requires_onto_and_pull_parent() {
    assert!(rebase_approval(true, true));
    assert!(!rebase_approval(false, true), "no --onto");
    assert!(!rebase_approval(true, false), "parent is not pull --rebase");
    assert!(!rebase_approval(false, false));
}

#[test]
fn parent_argv_pull_detection() {
    // REQ-GGUARD-064: a `pull` parent authorizes the forked rebase (the
    // rebase child's own `--onto` signature is checked separately). Plain
    // pulls qualify because repo config `pull.rebase=true` can make any pull
    // fork the rebase.
    let pull = &["pull"];
    assert!(parent_argv_subcommand_in(
        &[b"git", b"pull", b"--rebase", b"origin", b"main"],
        pull
    ));
    assert!(parent_argv_subcommand_in(&[b"git", b"pull", b"-r"], pull));
    assert!(parent_argv_subcommand_in(
        &[b"git", b"pull", b"--rebase=merges"],
        pull
    ));
    assert!(parent_argv_subcommand_in(
        &[b"git", b"pull", b"--ff-only"],
        pull
    ));
    assert!(parent_argv_subcommand_in(
        &[b"git", b"pull", b"origin", b"main"],
        pull
    ));
    assert!(!parent_argv_subcommand_in(
        &[b"git", b"rebase", b"--onto", b"a", b"b"],
        pull
    ));
    assert!(!parent_argv_subcommand_in(
        &[b"git", b"merge", b"--ff-only", b"origin"],
        pull
    ));
    assert!(!parent_argv_subcommand_in(
        &[b"git", b"fetch", b"origin"],
        pull
    ));
}

#[test]
fn parent_argv_internal_stash_parents() {
    // REQ-GGUARD-183: the porcelains whose internal snapshot forks
    // `git stash create` are the accepted parents; unrelated subcommands are
    // not. The `-c merge.autostash=false` shape is the real merge argv.
    let ops = &["merge", "rebase", "am", "pull"];
    assert!(parent_argv_subcommand_in(
        &[
            b"git",
            b"-c",
            b"merge.autostash=false",
            b"merge",
            b"--no-autostash",
            b"upstream/main"
        ],
        ops
    ));
    assert!(parent_argv_subcommand_in(
        &[b"git", b"rebase", b"--continue"],
        ops
    ));
    assert!(parent_argv_subcommand_in(
        &[b"git", b"am", b"--autostash"],
        ops
    ));
    assert!(parent_argv_subcommand_in(
        &[b"git", b"pull", b"--rebase"],
        ops
    ));
    assert!(!parent_argv_subcommand_in(
        &[b"git", b"stash", b"create"],
        ops
    ));
    assert!(!parent_argv_subcommand_in(
        &[b"git", b"commit", b"-m", b"x"],
        ops
    ));
}

#[test]
fn stash_verb_extraction() {
    assert_eq!(
        stash_verb(&argv(&["git", "stash", "create"])).as_deref(),
        Some("create")
    );
    assert_eq!(
        stash_verb(&argv(&[
            "git", "stash", "apply", "--index", "--quiet", "abc"
        ]))
        .as_deref(),
        Some("apply")
    );
    assert_eq!(stash_verb(&argv(&["git", "stash"])), None);
    assert_eq!(
        stash_verb(&argv(&["git", "-c", "x=y", "stash", "create"])).as_deref(),
        Some("create")
    );
}

#[test]
fn internal_stash_approved_requires_snapshot_verb_and_sealed_parent() {
    // REQ-GGUARD-183: the verb gate excludes ordinary stash operations even
    // before the parent check, and the parent check denies under the test
    // harness (the parent is cargo, not sealed Git).
    for verb in ["push", "pop", "save", "drop", "clear", "list", "show"] {
        assert!(
            !internal_stash_approved("stash", &argv(&["git", "stash", verb])),
            "git stash {verb} must not be authorized as an internal snapshot"
        );
    }
    assert!(!internal_stash_approved("stash", &argv(&["git", "stash"])));
    assert!(!internal_stash_approved(
        "stash",
        &argv(&["git", "stash", "create"])
    ));
    assert!(!internal_stash_approved(
        "commit",
        &argv(&["git", "commit", "create"])
    ));
}

#[test]
fn stash_create_blocked_for_non_root_without_sealed_parent() {
    // REQ-GGUARD-183: create/apply are authorized ONLY when the parent is the
    // sealed real Git running an approved porcelain. Under the test harness
    // the parent is cargo, so non-root stays denied for the non-fast-forward
    // merge's internal snapshot.
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
    if crate::is_config_privileged() {
        return;
    }
    for case in [["git", "stash", "create"], ["git", "stash", "apply"]] {
        let state = empty_state("stash");
        let argv_os = argv(&case);
        let result = check_blocked(&state, "stash", &argv_os, "/nonexistent-git", None);
        assert!(
            matches!(result, Err(GuardError::Blocked { .. })),
            "git {} must stay blocked without a sealed-git parent",
            case.join(" ")
        );
    }
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
fn stash_is_sudo_gated_not_blocked() {
    // REQ-GGUARD-050: stash moved from the unconditional block to the
    // sudo-gated category, matching checkout/restore/switch.
    assert!(!BLOCKED_SUBCOMMANDS.contains(&"stash"));
    assert!(SUDO_GATED_SUBCOMMANDS.contains(&"stash"));
}

#[test]
fn stash_denied_for_non_root_allowed_for_root() {
    // REQ-GGUARD-050: non-root agents are denied every verb before any
    // operation parsing; root (operator) may run the whole subcommand.
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_blocked_bypass_env_vars();
    let cases: &[&[&str]] = &[
        &["git", "stash"],
        &["git", "stash", "create"],
        &["git", "stash", "push"],
        &["git", "stash", "save"],
        &["git", "stash", "pop"],
        &["git", "stash", "apply"],
        &["git", "stash", "list"],
        &["git", "stash", "show"],
        &["git", "stash", "drop"],
        &["git", "stash", "clear"],
        &["git", "stash", "future-op"],
        &["git", "stash", "--", "drop"],
    ];
    let root = crate::is_config_privileged();
    for case in cases {
        let state = empty_state("stash");
        let argv_os = argv(case);
        let result = check_blocked(&state, "stash", &argv_os, "/nonexistent-git", None);
        if root {
            assert!(
                result.is_ok(),
                "{case:?} must be allowed for root: {result:?}"
            );
        } else {
            match result {
                Err(GuardError::Blocked { hint, .. }) => {
                    assert!(
                        hint.contains("sudo"),
                        "non-root hint must name sudo: {hint}"
                    );
                }
                other => panic!("{case:?} must be blocked for non-root: {other:?}"),
            }
        }
    }
}
