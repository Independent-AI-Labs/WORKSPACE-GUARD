//! Table-driven policy tests from config/guard_policy_matrix.yaml.

use std::ffi::OsString;
use std::fs;

use serde::Deserialize;

use crate::args;
use crate::block::check_blocked;
use crate::GuardError;

#[derive(Deserialize)]
struct PolicyMatrixCase {
    id: String,
    argv: Vec<String>,
    expect: String,
    reason_contains: Option<String>,
    #[serde(default)]
    sudo_only: bool,
}

#[derive(Deserialize)]
struct PolicyMatrixConfig {
    cases: Vec<PolicyMatrixCase>,
}

fn load_matrix() -> PolicyMatrixConfig {
    let path = format!(
        "{}/config/guard_policy_matrix.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn argv_bytes(argv: &[String]) -> Vec<&[u8]> {
    argv.iter().map(|s| s.as_bytes()).collect()
}

fn argv_os(argv: &[String]) -> Vec<OsString> {
    argv.iter().map(OsString::from).collect()
}

fn evaluate_case(case: &PolicyMatrixCase) -> Result<(), String> {
    if case.sudo_only && !crate::is_sudo() {
        return Ok(());
    }
    if !case.sudo_only && case.expect == "allowed" && crate::is_sudo() {
        // allowed-for-non-root cases (e.g. checkout main) are not asserted as root.
        if case.id.contains("non-root") || case.argv.len() > 2 {
            let sub = case.argv.get(1).map(String::as_str).unwrap_or("");
            if crate::SUDO_GATED_SUBCOMMANDS.contains(&sub) && case.expect == "allowed" {
                return Ok(());
            }
        }
    }

    let bytes = argv_bytes(&case.argv);
    args::check_null_bytes(&bytes).map_err(|e| format!("null-byte check: {e:?}"))?;

    let state = match args::parse_args(&bytes) {
        Ok(s) => s,
        Err(GuardError::Blocked { reason, .. }) => {
            if case.expect == "blocked" {
                if let Some(needle) = &case.reason_contains {
                    if !reason.to_lowercase().contains(&needle.to_lowercase()) {
                        return Err(format!(
                            "case {}: expected reason containing {:?}, got {:?}",
                            case.id, needle, reason
                        ));
                    }
                }
                return Ok(());
            }
            return Err(format!(
                "case {}: parse_args blocked unexpectedly: {}",
                case.id, reason
            ));
        }
        Err(e) => return Err(format!("case {}: parse_args error: {e:?}", case.id)),
    };

    let sub = state
        .subcommand
        .as_deref()
        .or_else(|| case.argv.get(1).map(String::as_str))
        .unwrap_or("");
    let os = argv_os(&case.argv);
    let block_result = check_blocked(&state, sub, &os, "/nonexistent-git", None);

    match block_result {
        Err(GuardError::Blocked { reason, .. }) => {
            if case.expect != "blocked" {
                return Err(format!(
                    "case {}: expected allowed, blocked: {}",
                    case.id, reason
                ));
            }
            if let Some(needle) = &case.reason_contains {
                if !reason.to_lowercase().contains(&needle.to_lowercase()) {
                    return Err(format!(
                        "case {}: expected reason containing {:?}, got {:?}",
                        case.id, needle, reason
                    ));
                }
            }
            Ok(())
        }
        Ok(()) => {
            if case.expect == "allowed" {
                Ok(())
            } else {
                Err(format!(
                    "case {}: expected blocked, command was allowed",
                    case.id
                ))
            }
        }
        Err(e) => Err(format!("case {}: unexpected error: {e:?}", case.id)),
    }
}

#[test]
fn policy_matrix_all_cases() {
    let matrix = load_matrix();
    assert!(
        matrix.cases.len() >= 70,
        "policy matrix too small: {}",
        matrix.cases.len()
    );
    let mut failures = Vec::new();
    for case in &matrix.cases {
        if let Err(msg) = evaluate_case(case) {
            failures.push(msg);
        }
    }
    if !failures.is_empty() {
        panic!(
            "policy matrix failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn policy_matrix_subcommands_have_cases() {
    let matrix = load_matrix();
    let covered: std::collections::HashSet<String> = matrix
        .cases
        .iter()
        .filter_map(|c| c.argv.get(1).cloned())
        .filter(|s| !s.starts_with('-'))
        .collect();
    for sub in crate::BLOCKED_SUBCOMMANDS
        .iter()
        .chain(crate::SUDO_GATED_SUBCOMMANDS.iter())
        .chain(crate::SUBCOMMANDS_WITH_PARTIAL_BLOCKS.iter())
    {
        assert!(
            covered.contains(*sub),
            "policy matrix missing case for subcommand {sub}"
        );
    }
}
