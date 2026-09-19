use super::*;
use crate::args::parse_args;
use std::ffi::OsString;

const LIST: &[&str] = &["log", "status", "diff", "config", "remote", "show"];

fn os(argv: &[&str]) -> Vec<OsString> {
    argv.iter().map(OsString::from).collect()
}

fn plan_argv(read_only: &[&str], argv: &[&str]) -> Result<Option<Plan>, GuardError> {
    let bytes: Vec<&[u8]> = argv.iter().map(|s| s.as_bytes()).collect();
    let state = parse_args(&bytes).map_err(|e| match e {
        GuardError::Blocked { reason, hint } => {
            panic!(
                "unexpected parse block for {:?}: {} ({})",
                argv, reason, hint
            )
        }
        other => other,
    })?;
    plan(read_only, &state, &os(argv))
}

#[test]
fn strips_flag_and_operand_on_read_only_subcommand() {
    let p = plan_argv(LIST, &["git", "-c", "core.hooksPath=/evil", "log", "-1"])
        .expect("plan ok")
        .expect("stripped");
    assert_eq!(p.argv, os(&["git", "log", "-1"]));
    assert_eq!(
        p.dropped,
        vec![b"-c".to_vec(), b"core.hooksPath=/evil".to_vec()]
    );
}

#[test]
fn config_read_shape_get_qualifies() {
    let p = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "config",
            "--get",
            "core.bare",
        ],
    )
    .expect("plan ok")
    .expect("stripped");
    assert_eq!(p.argv, os(&["git", "config", "--get", "core.bare"]));
}

#[test]
fn config_type_and_file_value_forms_qualify() {
    let p = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "config",
            "--type=bool",
            "--get",
            "core.bare",
        ],
    )
    .expect("plan ok")
    .expect("stripped");
    assert_eq!(
        p.argv,
        os(&["git", "config", "--type=bool", "--get", "core.bare"])
    );
    let p = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "config",
            "-f",
            "/tmp/x.cfg",
            "--list",
        ],
    )
    .expect("plan ok")
    .expect("stripped");
    assert_eq!(p.argv, os(&["git", "config", "-f", "/tmp/x.cfg", "--list"]));
}

#[test]
fn config_get_urlmatch_two_positionals_qualify() {
    plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "config",
            "--get-urlmatch",
            "http",
            "https://x",
        ],
    )
    .expect("plan ok")
    .expect("stripped");
}

#[test]
fn config_unknown_option_blocks() {
    let err = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "config",
            "--int-to-bool",
            "--list",
        ],
    )
    .unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
}

#[test]
fn remote_verbose_listing_qualifies() {
    plan_argv(LIST, &["git", "-c", "core.hooksPath=/e", "remote", "-v"])
        .expect("plan ok")
        .expect("stripped");
    let err = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "remote",
            "rename",
            "a",
            "b",
        ],
    )
    .unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
}

#[test]
fn mixed_benign_and_dangerous_strips_only_dangerous() {
    let p = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "color.ui=auto",
            "-c",
            "core.hooksPath=/evil",
            "log",
        ],
    )
    .expect("plan ok")
    .expect("stripped");
    assert_eq!(p.argv, os(&["git", "-c", "color.ui=auto", "log"]));
    assert_eq!(
        p.dropped,
        vec![b"-c".to_vec(), b"core.hooksPath=/evil".to_vec()]
    );
}

#[test]
fn strips_repeated_occurrences() {
    let p = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/a",
            "-c",
            "core.fsmonitor=/b",
            "diff",
            "HEAD",
        ],
    )
    .expect("plan ok")
    .expect("stripped");
    assert_eq!(p.argv, os(&["git", "diff", "HEAD"]));
    assert_eq!(p.dropped.len(), 4);
}

#[test]
fn benign_only_config_is_untouched() {
    let r = plan_argv(LIST, &["git", "-c", "color.ui=auto", "log"]).expect("plan ok");
    assert!(r.is_none());
}

#[test]
fn non_read_only_subcommand_blocks() {
    let err = plan_argv(LIST, &["git", "-c", "core.hooksPath=/evil", "push"]).unwrap_err();
    match err {
        GuardError::Blocked { reason, .. } => {
            assert!(reason.contains("dangerous -c config key: core.hooksPath"))
        }
        other => panic!("expected Blocked, got {:?}", other),
    }
}

#[test]
fn abbreviation_never_sanitizes() {
    // "log" abbreviated to "lo" resolves for category checks but must
    // not qualify for stripping: byte-exact match only (REQ-GGUARD-043).
    let err = plan_argv(LIST, &["git", "-c", "core.hooksPath=/evil", "lo"]).unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
}

#[test]
fn post_subcommand_option_never_stripped() {
    let err = plan_argv(LIST, &["git", "log", "-c", "core.hooksPath=/evil"]).unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
}

#[test]
fn sudo_gated_key_is_not_strippable() {
    // user.email is sudo-gated for non-root (test uid): keeps the
    // REQ-GGUARD-068 block, never a strip.
    let err = plan_argv(LIST, &["git", "-c", "user.email=x@y", "log"]).unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
}

#[test]
fn no_subcommand_blocks() {
    let err = plan_argv(LIST, &["git", "-c", "core.hooksPath=/evil"]).unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
}

#[test]
fn config_list_qualifies() {
    let p = plan_argv(
        LIST,
        &["git", "-c", "core.hooksPath=/e", "config", "--list"],
    )
    .expect("plan ok")
    .expect("stripped");
    assert_eq!(p.argv, os(&["git", "config", "--list"]));
}

#[test]
fn config_write_shape_blocks() {
    let err = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "config",
            "core.hooksPath",
            "/evil",
        ],
    )
    .unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
    let err = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "config",
            "--unset",
            "core.bare",
        ],
    )
    .unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
    let err = plan_argv(
        LIST,
        &["git", "-c", "core.hooksPath=/e", "config", "--edit"],
    )
    .unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
}

#[test]
fn remote_get_url_qualifies_add_blocks() {
    let p = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "remote",
            "get-url",
            "origin",
        ],
    )
    .expect("plan ok")
    .expect("stripped");
    assert_eq!(p.argv, os(&["git", "remote", "get-url", "origin"]));
    let err = plan_argv(
        LIST,
        &[
            "git",
            "-c",
            "core.hooksPath=/e",
            "remote",
            "add",
            "evil",
            "url",
        ],
    )
    .unwrap_err();
    assert!(matches!(err, GuardError::Blocked { .. }));
}

#[test]
fn report_grammar_exact() {
    let argv = os(&["git", "-c", "core.hooksPath=/evil", "log"]);
    let report = build_report(
        "2026-09-19T06:00:00Z",
        "log",
        &[b"-c".to_vec(), b"core.hooksPath=/evil".to_vec()],
        &argv,
    );
    assert_eq!(
        report,
        "SANITIZED: ts=2026-09-19T06:00:00Z|subcommand=log|drops=2|drop0=-c|\
         drop1=core.hooksPath=/evil|argc=4|arg0=git|arg1=-c|\
         arg2=core.hooksPath=/evil|arg3=log"
    );
}

#[test]
fn report_encodes_dynamic_values() {
    let argv = os(&["git", "log"]);
    let report = build_report("t", "a b", &[b"|x%".to_vec()], &argv);
    assert!(report.contains("subcommand=a%20b"));
    assert!(report.contains("drop0=%7Cx%25"));
}

#[test]
fn no_verify_short_scope_constant() {
    assert_eq!(NO_VERIFY_SHORT_SUBCOMMANDS, &["am", "commit"]);
}
