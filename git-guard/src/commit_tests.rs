use super::{check_commit_attribution, scan_commit_args};
use crate::args::{parse_args, ArgState};
use crate::GuardError;

fn empty_state() -> ArgState {
    ArgState {
        subcommand: Some("commit".to_string()),
        subcommand_raw: Some("commit".to_string()),
        has_amend: false,
        has_author_override: false,
        has_author_date_override: false,
        has_force_flag: false,
        has_force_with_lease_flag: false,
        has_branch_d: false,
        has_branch_force_rename: false,
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

fn scan(tokens: &[&str]) -> ArgState {
    let bytes: Vec<&[u8]> = tokens.iter().map(|s| s.as_bytes()).collect();
    let mut state = empty_state();
    scan_commit_args(&bytes, &mut state);
    state
}

fn parse(args: &[&str]) -> ArgState {
    let bytes: Vec<&[u8]> = args.iter().map(|s| s.as_bytes()).collect();
    parse_args(&bytes).unwrap()
}

#[test]
fn scan_flags_every_author_override_form() {
    for tokens in [
        &["--author", "X <x@y>"][..],
        &["--author=X <x@y>"],
        &["--reset-author"],
        &["-C", "HEAD"],
        &["-c", "HEAD"],
        &["--reuse-message=HEAD"],
        &["--reedit-message", "HEAD"],
    ] {
        assert!(scan(tokens).has_author_override, "not flagged: {tokens:?}");
    }
}

#[test]
fn scan_flags_author_date_forms_without_author_override() {
    for tokens in [
        &["--date=2000-01-01T00:00:00Z"][..],
        &["--date", "2000-01-01T00:00:00Z"],
    ] {
        let state = scan(tokens);
        assert!(state.has_author_date_override, "not flagged: {tokens:?}");
        assert!(!state.has_author_override, "date set author: {tokens:?}");
    }
}

#[test]
fn scan_ignores_plain_and_post_separator_tokens() {
    assert!(!scan(&["-m", "x", "--", "-C", "HEAD"]).has_author_override);
    assert!(!scan(&["-m", "x"]).has_author_override);
    assert!(!scan(&["-m", "x"]).has_author_date_override);
}

#[test]
fn parse_args_flags_commit_author_override_but_not_global_dash_c() {
    assert!(parse(&["git", "commit", "--author=X <x@y>"]).has_author_override);
    assert!(parse(&["git", "commit", "-C", "HEAD"]).has_author_override);
    // A global `-c key=value` precedes the subcommand and is not a commit
    // authorship reuse.
    assert!(!parse(&["git", "-c", "core.pager=cat", "commit", "-m", "x"]).has_author_override);
}

#[test]
fn check_blocks_non_root_and_allows_root() {
    for (label, state) in [
        ("amend", {
            let mut s = empty_state();
            s.has_amend = true;
            s
        }),
        ("author", {
            let mut s = empty_state();
            s.has_author_override = true;
            s
        }),
        ("date", {
            let mut s = empty_state();
            s.has_author_date_override = true;
            s
        }),
    ] {
        let non_root = check_commit_attribution(&state, false);
        assert!(
            matches!(non_root, Err(GuardError::Blocked { .. })),
            "{label} must block non-root"
        );
        assert!(
            check_commit_attribution(&state, true).is_ok(),
            "{label} must allow root"
        );
    }
    assert!(check_commit_attribution(&empty_state(), false).is_ok());
}

#[test]
fn block_engine_wires_commit_attribution_rules() {
    use crate::block::check_blocked;
    use std::ffi::OsString;
    let argv: Vec<OsString> = ["git", "commit", "--author=X <x@y>"]
        .iter()
        .map(OsString::from)
        .collect();
    let mut state = empty_state();
    state.has_author_override = true;
    let result = check_blocked(&state, "commit", &argv, "/nonexistent-git", None);
    if crate::is_config_privileged() {
        assert!(result.is_ok(), "root allowed: {result:?}");
    } else {
        assert!(matches!(result, Err(GuardError::Blocked { .. })));
    }
}
