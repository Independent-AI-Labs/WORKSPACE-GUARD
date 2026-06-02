use super::*;

fn bytes<'a>(args: &[&'a str]) -> Vec<&'a [u8]> {
    args.iter().map(|s| s.as_bytes()).collect()
}

#[test]
fn resolve_abbrev_exact_match() {
    assert_eq!(resolve_subcommand_abbreviation("commit"), "commit");
    assert_eq!(resolve_subcommand_abbreviation("reset"), "reset");
    assert_eq!(resolve_subcommand_abbreviation("config"), "config");
}

#[test]
fn resolve_abbrev_unambiguous_prefix() {
    assert_eq!(resolve_subcommand_abbreviation("com"), "commit");
    assert_eq!(resolve_subcommand_abbreviation("cl"), "clean");
    assert_eq!(resolve_subcommand_abbreviation("pus"), "push");
    assert_eq!(resolve_subcommand_abbreviation("br"), "branch");
    assert_eq!(resolve_subcommand_abbreviation("reba"), "rebase");
    assert_eq!(resolve_subcommand_abbreviation("chec"), "checkout");
    assert_eq!(resolve_subcommand_abbreviation("sub"), "submodule");
    assert_eq!(resolve_subcommand_abbreviation("da"), "daemon");
    assert_eq!(resolve_subcommand_abbreviation("refl"), "reflog");
    assert_eq!(resolve_subcommand_abbreviation("wor"), "worktree");
}

#[test]
fn resolve_abbrev_ambiguous_returns_raw() {
    let result = resolve_subcommand_abbreviation("ch");
    assert_eq!(result, "ch");
    let result2 = resolve_subcommand_abbreviation("re");
    assert_eq!(result2, "re");
}

#[test]
fn resolve_abbrev_unknown_returns_raw() {
    assert_eq!(resolve_subcommand_abbreviation("unknownxyz"), "unknownxyz");
}

#[test]
fn resolve_abbrev_case_insensitive() {
    assert_eq!(resolve_subcommand_abbreviation("COM"), "commit");
    assert_eq!(resolve_subcommand_abbreviation("DA"), "daemon");
    assert_eq!(resolve_subcommand_abbreviation("REBA"), "rebase");
}

#[test]
fn null_bytes_no_null() {
    let args = bytes(&["git", "status", "--short"]);
    assert!(check_null_bytes(&args).is_ok());
}

#[test]
fn null_bytes_contains_null() {
    let arg = b"stat\0us".to_vec();
    let args: Vec<&[u8]> = vec![b"git", &arg];
    assert!(check_null_bytes(&args).is_err());
}

#[test]
fn parse_args_no_verify_long_blocked() {
    let args = bytes(&["git", "commit", "--no-verify", "-m", "msg"]);
    let result = parse_args(&args);
    assert!(result.is_err());
}

#[test]
fn parse_args_n_short_blocked() {
    let args = bytes(&["git", "commit", "-n", "-m", "msg"]);
    let result = parse_args(&args);
    assert!(result.is_err());
}

#[test]
fn parse_args_n_upper_blocked() {
    let args = bytes(&["git", "commit", "-N", "-m", "msg"]);
    let result = parse_args(&args);
    assert!(result.is_err());
}

#[test]
fn parse_args_n_combined_blocked() {
    let args = bytes(&["git", "-fn", "commit"]);
    let result = parse_args(&args);
    assert!(result.is_err());
}

#[test]
fn parse_args_c_attached_dangerous_config() {
    let args = bytes(&["git", "-ccore.hooksPath=/evil", "commit"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
    assert!(state
        .dangerous_config_keys
        .iter()
        .any(|k| k.contains("core.hooksPath")));
}

#[test]
fn parse_args_c_standalone_dangerous_config() {
    let args = bytes(&["git", "-c", "core.hooksPath=/evil", "commit"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_c_attached_dangerous_fsmonitor() {
    let args = bytes(&["git", "-Ccore.fsmonitor=/evil", "status"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_alias_blocked() {
    let args = bytes(&["git", "-c", "alias.x=!rm -rf /", "status"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_wildcard_filter_clean() {
    let args = bytes(&["git", "-c", "filter.lfs.clean=rm -rf /", "status"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_wildcard_protocol_allow() {
    let args = bytes(&["git", "-c", "protocol.file.allow=always", "fetch"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_wildcard_url_insteadof() {
    let args = bytes(&[
        "git",
        "-c",
        "url.https://evil.com.insteadof=https://github.com",
        "status",
    ]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_config_long_form() {
    let args = bytes(&["git", "--config", "core.hooksPath=/evil", "commit"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_config_equals_form() {
    let args = bytes(&["git", "--config=core.hooksPath=/evil", "commit"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_config_env_long_form() {
    let args = bytes(&["git", "--config-env", "core.hooksPath=HOME", "commit"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_push_delete_short_flag() {
    let args = bytes(&["git", "push", "-d", "origin", "main"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_delete_flag);
}

#[test]
fn parse_args_push_delete_long_flag() {
    let args = bytes(&["git", "push", "--delete", "origin", "main"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_delete_flag);
}

#[test]
fn parse_args_upload_pack_blocked() {
    let args = bytes(&["git", "--upload-pack", "/bin/sh", "clone", "url"]);
    assert!(parse_args(&args).is_err());
}

#[test]
fn parse_args_upload_pack_equals_blocked() {
    let args = bytes(&["git", "--upload-pack=/bin/sh", "clone", "url"]);
    assert!(parse_args(&args).is_err());
}

#[test]
fn parse_args_receive_pack_equals_blocked() {
    let args = bytes(&["git", "--receive-pack=/bin/sh", "push"]);
    assert!(parse_args(&args).is_err());
}

#[test]
fn parse_args_exec_blocked() {
    let args = bytes(&["git", "--exec", "/tmp/evil", "fetch"]);
    assert!(parse_args(&args).is_err());
}

#[test]
fn parse_args_exec_equals_blocked() {
    let args = bytes(&["git", "--exec=/tmp/evil", "fetch"]);
    assert!(parse_args(&args).is_err());
}

#[test]
fn parse_args_separator_stash_drop_is_pathspec() {
    let args = bytes(&["git", "stash", "--", "drop"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.has_stash_drop);
}

#[test]
fn parse_args_separator_push_force_is_pathspec() {
    let args = bytes(&["git", "push", "origin", "main", "--", "--force"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.has_force_flag);
}

#[test]
fn parse_args_tag_force_flag() {
    let args = bytes(&["git", "tag", "-f", "v1.0"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_force_flag);
}

#[test]
fn parse_args_branch_force_rename() {
    let args = bytes(&["git", "branch", "-M", "old", "new"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_branch_force_rename);
}

#[test]
fn parse_args_config_key_with_spaces() {
    let args = bytes(&["git", "-c", " core.hooksPath = /tmp/evil ", "commit"]);
    let state = parse_args(&args).unwrap();
    assert!(!state.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_hard_flag_blocked() {
    let args = bytes(&["git", "--hard", "reset"]);
    assert!(parse_args(&args).is_err());
}

#[test]
fn parse_args_commit_amend() {
    let args = bytes(&["git", "commit", "--amend"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_amend);
}

#[test]
fn parse_args_commit_amend_no_edit() {
    let args = bytes(&["git", "commit", "--amend", "--no-edit"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_amend);
}

#[test]
fn parse_args_push_force_flag() {
    let args = bytes(&["git", "push", "-f"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_force_flag);
}

#[test]
fn parse_args_push_force_with_lease_flag() {
    let args = bytes(&["git", "push", "--force-with-lease"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_force_with_lease_flag);
}

#[test]
fn parse_args_branch_d_flag() {
    let args = bytes(&["git", "branch", "-D", "foo"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_branch_d);
}

#[test]
fn parse_args_stash_drop() {
    let args = bytes(&["git", "stash", "drop"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_stash_drop);
}

#[test]
fn parse_args_stash_clear() {
    let args = bytes(&["git", "stash", "clear"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_stash_clear);
}

#[test]
fn parse_args_safe_pull_ff_only() {
    let args = bytes(&["git", "pull", "--ff-only"]);
    let state = parse_args(&args).unwrap();
    assert!(state.safe_pull_flag);
}

#[test]
fn parse_args_safe_pull_rebase() {
    let args = bytes(&["git", "pull", "--rebase"]);
    let state = parse_args(&args).unwrap();
    assert!(state.safe_pull_flag);
}

#[test]
fn parse_args_rm_cached() {
    let args = bytes(&["git", "rm", "--cached", "file.rs"]);
    let state = parse_args(&args).unwrap();
    assert!(state.has_cached);
}

#[test]
fn parse_args_config_key_trim_newline() {
    let key = "core.hooksPath\n";
    assert!(is_dangerous_config_key(key));
}

#[test]
fn parse_args_no_args_passes() {
    let args = bytes(&["git"]);
    let state = parse_args(&args).unwrap();
    assert!(state.subcommand.is_none());
}

#[test]
fn parse_args_git_status_passes() {
    let args = bytes(&["git", "status"]);
    let state = parse_args(&args).unwrap();
    assert_eq!(state.subcommand.as_deref(), Some("status"));
}
