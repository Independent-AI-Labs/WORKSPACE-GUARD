//! Config-key, operand-arity, and leading-global parser tests
//! (REQ-GGUARD-011, REQ-GGUARD-030, REQ-GGUARD-031, REQ-GGUARD-041).

use super::*;

fn bytes<'a>(args: &[&'a str]) -> Vec<&'a [u8]> {
    args.iter().map(|s| s.as_bytes()).collect()
}

fn sub(args: &[&str]) -> Option<String> {
    parse_args(&bytes(args)).unwrap().subcommand
}

#[test]
fn parse_args_config_implicit_true_forms_are_checked() {
    // REQ-GGUARD-041: no `=` means implicit boolean true; both the separate
    // and attached no-value forms must still be matched against policy.
    let separate = parse_args(&bytes(&["git", "-c", "core.hooksPath", "commit"])).unwrap();
    assert!(!separate.dangerous_config_keys.is_empty());
    let attached = parse_args(&bytes(&["git", "-ccore.hooksPath", "commit"])).unwrap();
    assert!(!attached.dangerous_config_keys.is_empty());
}

#[test]
fn parse_args_config_malformed_key_is_exit_2() {
    // REQ-GGUARD-041: empty, non-ASCII, or non-UTF-8 keys are malformed
    // invocations, never lossily collapsed to an empty string.
    for args in [
        bytes(&["git", "-c", "=evil", "commit"]),
        bytes(&["git", "-c", "", "commit"]),
        bytes(&["git", "-c", "caf\u{e9}=evil", "commit"]),
    ] {
        assert!(matches!(
            parse_args(&args),
            Err(GuardError::InvalidInvocation(_))
        ));
    }
    let raw: Vec<Vec<u8>> = vec![b"git".to_vec(), b"-c".to_vec(), vec![0xff, 0xfe]];
    let refs: Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
    assert!(matches!(
        parse_args(&refs),
        Err(GuardError::InvalidInvocation(_))
    ));
}

#[test]
fn parse_args_config_key_case_folded_only_for_matching() {
    // Stored key is byte-exact (audit evidence); the matcher folds ASCII case.
    let state = parse_args(&bytes(&["git", "-c", "CORE.HOOKSPATH=/evil", "commit"])).unwrap();
    assert_eq!(
        state.dangerous_config_keys,
        vec!["CORE.HOOKSPATH".to_string()]
    );
}

#[test]
fn tag_message_operand_is_not_a_force_flag() {
    // REQ-GGUARD-030: `-m`/`--message` take the message, even when the
    // message text begins with `-`.
    let state = parse_args(&bytes(&["git", "tag", "-m", "--force", "v1"])).unwrap();
    assert!(!state.has_force_flag);
}

#[test]
fn branch_move_and_copy_operands_are_not_flags() {
    let moved = parse_args(&bytes(&["git", "branch", "-m", "--force"])).unwrap();
    assert!(!moved.has_force_flag);
    let copied = parse_args(&bytes(&["git", "branch", "--copy", "-D", "old", "new"])).unwrap();
    assert!(!copied.has_branch_d);
}

#[test]
fn real_force_flags_are_still_recorded() {
    assert!(
        parse_args(&bytes(&["git", "branch", "--force", "main"]))
            .unwrap()
            .has_force_flag
    );
    assert!(
        parse_args(&bytes(&["git", "tag", "-f", "v1"]))
            .unwrap()
            .has_force_flag
    );
    assert!(
        parse_args(&bytes(&["git", "branch", "-D", "main"]))
            .unwrap()
            .has_branch_d
    );
}

#[test]
fn value_taking_globals_do_not_swallow_the_subcommand() {
    // REQ-GGUARD-011: `--git-dir <path> reset` must still identify `reset`.
    assert_eq!(
        sub(&["git", "--git-dir", "/r", "reset"]).as_deref(),
        Some("reset")
    );
    assert_eq!(
        sub(&["git", "--work-tree", "/r", "reset"]).as_deref(),
        Some("reset")
    );
    assert_eq!(
        sub(&["git", "--namespace", "ns", "reset"]).as_deref(),
        Some("reset")
    );
    assert_eq!(
        sub(&["git", "--git-dir=/r", "reset"]).as_deref(),
        Some("reset")
    );
    assert_eq!(
        sub(&["git", "--work-tree=/r", "reset"]).as_deref(),
        Some("reset")
    );
    assert_eq!(
        sub(&["git", "--namespace=ns", "reset"]).as_deref(),
        Some("reset")
    );
}

#[test]
fn shallow_file_leading_global_identifies_index_pack() {
    // Git's fetch-pack runs `git --shallow-file <file> index-pack ...` for a
    // shallow fetch. `--shallow-file` takes the following token as its
    // operand, so `index-pack` must still be discovered (no false
    // "unknown leading option" rejection that breaks every shallow clone).
    assert_eq!(
        sub(&[
            "git",
            "--shallow-file",
            "/tmp/s.lock",
            "index-pack",
            "--stdin",
            "--fix-thin",
        ])
        .as_deref(),
        Some("index-pack")
    );
    assert_eq!(
        sub(&["git", "--shallow-file=/tmp/s.lock", "index-pack", "--stdin"]).as_deref(),
        Some("index-pack")
    );
}

#[test]
fn shallow_file_operand_is_not_misread_as_subcommand() {
    // The consumed operand must never itself become the subcommand, and an
    // unknown option after it still fails closed.
    assert!(matches!(
        parse_args(&bytes(&["git", "--shallow-file", "reset", "--hard"])),
        Err(GuardError::InvalidInvocation(_))
    ));
}

#[test]
fn repeated_and_attached_c_identify_the_subcommand() {
    assert_eq!(
        sub(&["git", "-C", "/a", "-C", "/b", "status"]).as_deref(),
        Some("status")
    );
    assert_eq!(sub(&["git", "-C/a", "status"]).as_deref(), Some("status"));
    assert_eq!(
        sub(&["git", "-C", "/a", "status"]).as_deref(),
        Some("status")
    );
}

#[test]
fn known_modifier_globals_pass_through() {
    assert_eq!(
        sub(&["git", "--paginate", "status"]).as_deref(),
        Some("status")
    );
    assert_eq!(sub(&["git", "-p", "status"]).as_deref(), Some("status"));
    assert_eq!(
        sub(&["git", "--no-pager", "status"]).as_deref(),
        Some("status")
    );
    assert_eq!(sub(&["git", "--bare", "status"]).as_deref(), Some("status"));
}

#[test]
fn terminal_query_options_leave_no_subcommand() {
    for args in [
        bytes(&["git", "--version"]),
        bytes(&["git", "--help"]),
        bytes(&["git", "-h"]),
        bytes(&["git", "-v"]),
        bytes(&["git", "--exec-path"]),
        bytes(&["git", "--html-path"]),
        bytes(&["git", "--man-path"]),
        bytes(&["git", "--info-path"]),
    ] {
        assert!(parse_args(&args).unwrap().subcommand.is_none());
    }
}

#[test]
fn unknown_leading_option_fails_closed_with_exit_2() {
    for args in [
        bytes(&["git", "--bogus", "status"]),
        bytes(&["git", "--exec-path=/x", "status"]),
        bytes(&["git", "-Z", "status"]),
        bytes(&["git", "--hard", "reset"]),
    ] {
        assert!(matches!(
            parse_args(&args),
            Err(GuardError::InvalidInvocation(_))
        ));
    }
}
