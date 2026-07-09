use super::binary_policy_types::{BinaryPolicy, RejectKind, RejectRule};
use super::*;
use std::ffi::OsString;

// --- static test policies -------------------------------------------------
// BinaryPolicy fields require &'static str, so test policies are declared as
// static items with string-literal fields. These are never installed; they
// exist only for unit-testing decide/check_arg_validate/build_sanitized_env
// in isolation from the compiled-in BINARY_POLICIES table.

static POLICY_DENY_NON_ROOT: BinaryPolicy = BinaryPolicy {
    name: "test-deny-non-root",
    policy: PolicyKind::DenyNonRoot,
    allow_subcommands: &[],
    allow_self_username: false,
    reject_patterns: &[],
    env_sanitise: &["BG_TEST_STRIP"],
};

static POLICY_DENY_ALL_NON_ROOT: BinaryPolicy = BinaryPolicy {
    name: "test-deny-all-non-root",
    policy: PolicyKind::DenyAllNonRoot,
    allow_subcommands: &[],
    allow_self_username: false,
    reject_patterns: &[],
    env_sanitise: &[],
};

static POLICY_ARG_VALIDATE_FLAG: BinaryPolicy = BinaryPolicy {
    name: "test-arg-flag",
    policy: PolicyKind::ArgValidate,
    allow_subcommands: &[],
    allow_self_username: false,
    reject_patterns: &[RejectRule {
        kind: RejectKind::Flag,
        flag: Some("-R"),
        pattern: None,
        subcommand: None,
        requires_flags: &[],
        reason: "test flag reject -R",
    }],
    env_sanitise: &[],
};

static POLICY_ARG_VALIDATE_REGEX: BinaryPolicy = BinaryPolicy {
    name: "test-arg-regex",
    policy: PolicyKind::ArgValidate,
    allow_subcommands: &["test-arg-regex", "testsub"],
    allow_self_username: false,
    reject_patterns: &[RejectRule {
        kind: RejectKind::Regex,
        flag: None,
        pattern: Some("\\\\$"),
        subcommand: Some("testsub"),
        requires_flags: &["-s"],
        reason: "test regex reject trailing backslash",
    }],
    env_sanitise: &[],
};

static POLICY_PASSTHROUGH: BinaryPolicy = BinaryPolicy {
    name: "test-passthrough",
    policy: PolicyKind::PassThrough,
    allow_subcommands: &[],
    allow_self_username: false,
    reject_patterns: &[],
    env_sanitise: &[],
};

fn argv(args: &[&str]) -> Vec<OsString> {
    args.iter().map(|s| OsString::from(*s)).collect()
}

fn env_has(env: &[(OsString, OsString)], key: &str) -> bool {
    env.iter().any(|(k, _)| k.to_string_lossy() == key)
}

// === decide() =============================================================

#[test]
fn decide_deny_non_root_rejects_non_root() {
    let d = decide(
        &POLICY_DENY_NON_ROOT,
        "test-deny-non-root",
        &argv(&["arg1"]),
        false,
    );
    assert!(matches!(d, Decision::Reject(_)));
}

#[test]
fn decide_deny_non_root_allows_root() {
    let d = decide(
        &POLICY_DENY_NON_ROOT,
        "test-deny-non-root",
        &argv(&["arg1"]),
        true,
    );
    assert!(matches!(d, Decision::Allow { .. }));
}

#[test]
fn decide_deny_all_non_root_rejects_non_root() {
    let d = decide(
        &POLICY_DENY_ALL_NON_ROOT,
        "test-deny-all-non-root",
        &[],
        false,
    );
    assert!(matches!(d, Decision::Reject(_)));
}

#[test]
fn decide_deny_all_non_root_allows_root() {
    let d = decide(
        &POLICY_DENY_ALL_NON_ROOT,
        "test-deny-all-non-root",
        &[],
        true,
    );
    assert!(matches!(d, Decision::Allow { .. }));
}

#[test]
fn decide_arg_validate_rejects_non_root() {
    let d = decide(
        &POLICY_ARG_VALIDATE_FLAG,
        "test-arg-flag",
        &argv(&["-R"]),
        false,
    );
    assert!(matches!(d, Decision::Reject(_)));
}

#[test]
fn decide_arg_validate_allows_root_clean_args() {
    let d = decide(
        &POLICY_ARG_VALIDATE_FLAG,
        "test-arg-flag",
        &argv(&["-l"]),
        true,
    );
    assert!(matches!(d, Decision::Allow { .. }));
}

#[test]
fn decide_arg_validate_rejects_root_with_blocked_flag() {
    let d = decide(
        &POLICY_ARG_VALIDATE_FLAG,
        "test-arg-flag",
        &argv(&["-R"]),
        true,
    );
    match d {
        Decision::Reject(reason) => assert!(reason.contains("test flag reject")),
        other => panic!("expected Reject, got {:?}", other),
    }
}

#[test]
fn decide_pass_through_allows_root() {
    let d = decide(
        &POLICY_PASSTHROUGH,
        "test-passthrough",
        &argv(&["anything"]),
        true,
    );
    assert!(matches!(d, Decision::Allow { .. }));
}

#[test]
fn decide_pass_through_allows_non_root() {
    let d = decide(
        &POLICY_PASSTHROUGH,
        "test-passthrough",
        &argv(&["anything"]),
        false,
    );
    assert!(matches!(d, Decision::Allow { .. }));
}

// === check_arg_validate() =================================================

#[test]
fn check_arg_validate_non_root_always_rejected() {
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_FLAG,
        "test-arg-flag",
        &argv(&["-l"]),
        false,
    );
    assert!(r.is_some());
}

#[test]
fn check_arg_validate_root_clean_args_passes() {
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_FLAG,
        "test-arg-flag",
        &argv(&["-l"]),
        true,
    );
    assert!(r.is_none());
}

#[test]
fn check_arg_validate_flag_rejected() {
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_FLAG,
        "test-arg-flag",
        &argv(&["-R"]),
        true,
    );
    assert!(r.is_some());
    assert!(r.unwrap().contains("test flag reject"));
}

#[test]
fn check_arg_validate_flag_not_rejected_when_absent() {
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_FLAG,
        "test-arg-flag",
        &argv(&["-l", "-s"]),
        true,
    );
    assert!(r.is_none());
}

#[test]
fn check_arg_validate_regex_rejected_with_subcommand_and_flags() {
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_REGEX,
        "test-arg-regex",
        &argv(&["testsub", "-s", "foo\\"]),
        true,
    );
    assert!(r.is_some());
    assert!(r.unwrap().contains("test regex reject"));
}

#[test]
fn check_arg_validate_regex_not_rejected_wrong_subcommand() {
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_REGEX,
        "test-arg-regex",
        &argv(&["othersub", "-s", "foo\\"]),
        true,
    );
    assert!(r.is_none());
}

#[test]
fn check_arg_validate_regex_not_rejected_missing_required_flag() {
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_REGEX,
        "test-arg-regex",
        &argv(&["testsub", "foo\\"]),
        true,
    );
    assert!(r.is_none());
}

#[test]
fn check_arg_validate_regex_not_rejected_no_pattern_match() {
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_REGEX,
        "test-arg-regex",
        &argv(&["testsub", "-s", "foo"]),
        true,
    );
    assert!(r.is_none());
}

#[test]
fn check_arg_validate_regex_rejected_when_invoked_name_matches_subcommand() {
    // subcommand check also matches invoked_name, so calling the binary
    // directly (argv_rest[0] is not "testsub" but invoked_name is "testsub")
    // should still gate on the subcommand field.
    let r = check_arg_validate(
        &POLICY_ARG_VALIDATE_REGEX,
        "testsub",
        &argv(&["testsub", "-s", "foo\\"]),
        true,
    );
    assert!(r.is_some());
}

// === build_sanitized_env() ================================================
// These tests set/remove env vars. Env var mutation is process-global; to
// avoid cross-test races we use uniquely named vars and accept that cargo's
// default parallelism could theoretically interleave. The vars are prefixed
// BG_TEST_ and are not used by any other test.

#[test]
fn build_sanitized_env_strips_listed_vars() {
    std::env::set_var("BG_TEST_STRIP", "secret");
    std::env::set_var("BG_TEST_KEEP", "safe");
    let env = build_sanitized_env(&POLICY_DENY_NON_ROOT, true);
    std::env::remove_var("BG_TEST_STRIP");
    std::env::remove_var("BG_TEST_KEEP");

    assert!(
        !env_has(&env, "BG_TEST_STRIP"),
        "listed var should be stripped"
    );
    assert!(env_has(&env, "BG_TEST_KEEP"), "unlisted var should survive");
}

#[test]
fn build_sanitized_env_empty_strip_set_preserves_all() {
    std::env::set_var("BG_TEST_KEEP2", "safe");
    let env = build_sanitized_env(&POLICY_DENY_ALL_NON_ROOT, true);
    std::env::remove_var("BG_TEST_KEEP2");

    assert!(
        env_has(&env, "BG_TEST_KEEP2"),
        "empty strip set preserves all"
    );
}

// === join_argv() ==========================================================

#[test]
fn join_argv_empty() {
    assert_eq!(join_argv(&[]), "");
}

#[test]
fn join_argv_single() {
    assert_eq!(join_argv(&argv(&["hello"])), "hello");
}

#[test]
fn join_argv_multiple() {
    assert_eq!(join_argv(&argv(&["a", "b", "c"])), "a b c");
}

// === find_policy() against compiled table =================================

#[test]
fn find_policy_known_name_returns_some() {
    // "aa-exec" is the first entry in res/binary-lock.yaml.
    let p = find_policy("aa-exec");
    assert!(p.is_some());
    assert_eq!(p.unwrap().name, "aa-exec");
}

#[test]
fn find_policy_unknown_name_returns_none() {
    let p = find_policy("this-binary-does-not-exist-anywhere-xyz");
    assert!(p.is_none());
}

#[test]
fn find_policy_symlink_alias_via_allow_subcommands() {
    // sudo entry has allow_subcommands: ["sudo", "sudoedit"].
    // "sudoedit" should resolve to the sudo policy via the alias path.
    let p = find_policy("sudoedit");
    assert!(p.is_some());
    assert_eq!(p.unwrap().name, "sudo");
}

#[test]
fn find_policy_exact_name_wins_over_alias() {
    // If a binary has its own entry AND is listed in another's
    // allow_subcommands, the exact-name match should win (first .find()).
    // "sudo" has its own entry; it should return the sudo entry, not
    // whatever might alias it.
    let p = find_policy("sudo");
    assert!(p.is_some());
    assert_eq!(p.unwrap().name, "sudo");
}
