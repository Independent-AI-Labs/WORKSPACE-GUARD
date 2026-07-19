//! Table-driven attack-surface tests from config/guard_attack_surface_matrix.yaml.
//! Covers destructive paths catalogued from git.git source (checkout.c, restore.c,
//! plumbing builtins, command-list.txt).

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;

use serde::Deserialize;

use crate::args;
use crate::block::check_blocked;
use crate::GuardError;

#[derive(Deserialize)]
struct AttackSurfaceCase {
    id: String,
    argv: Vec<String>,
    expect: String,
    reason_contains: Option<String>,
    #[serde(default)]
    sudo_only: bool,
    #[serde(default)]
    env: HashMap<String, String>,
}

#[derive(Deserialize)]
struct AttackSurfaceConfig {
    cases: Vec<AttackSurfaceCase>,
}

fn load_matrix() -> AttackSurfaceConfig {
    let path = format!(
        "{}/config/guard_attack_surface_matrix.yaml",
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

fn clear_env(case: &AttackSurfaceCase) {
    for key in case.env.keys() {
        std::env::remove_var(key);
    }
    for &var in crate::BLOCKED_BYPASS_VARS {
        std::env::remove_var(var);
    }
}

fn set_env(case: &AttackSurfaceCase) {
    for (k, v) in &case.env {
        std::env::set_var(k, v);
    }
}

fn evaluate_case(case: &AttackSurfaceCase) -> Result<(), String> {
    if case.sudo_only && !crate::is_config_privileged() {
        return Ok(());
    }
    if !case.sudo_only && case.expect == "allowed" && crate::is_config_privileged() {
        let sub = case.argv.get(1).map(String::as_str).unwrap_or("");
        if crate::SUDO_GATED_SUBCOMMANDS.contains(&sub) {
            return Ok(());
        }
    }

    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    set_env(case);
    let result = evaluate_case_inner(case);
    clear_env(case);
    result
}

fn evaluate_case_inner(case: &AttackSurfaceCase) -> Result<(), String> {
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
fn attack_surface_all_cases() {
    let matrix = load_matrix();
    assert!(
        matrix.cases.len() >= 90,
        "attack surface matrix too small: {}",
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
            "attack surface failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[test]
fn attack_surface_checkout_restore_vectors_blocked() {
    let matrix = load_matrix();
    let checkout_restore: Vec<_> = matrix
        .cases
        .iter()
        .filter(|c| {
            c.id.starts_with("atk-checkout-")
                || c.id.starts_with("atk-restore-")
                || c.id.starts_with("atk-read-tree")
        })
        .collect();
    assert!(
        checkout_restore.len() >= 20,
        "expected >=20 checkout/restore vectors, got {}",
        checkout_restore.len()
    );
    for case in checkout_restore {
        if case.expect != "blocked" {
            continue;
        }
        if let Err(msg) = evaluate_case(case) {
            panic!("checkout/restore vector failed: {msg}");
        }
    }
}

#[test]
fn attack_surface_plumbing_vectors_blocked() {
    let matrix = load_matrix();
    let plumbing_prefixes = [
        "atk-checkout-index",
        "atk-update-index",
        "atk-merge-file",
        "atk-merge-index",
        "atk-read-tree",
        "atk-update-ref",
        "atk-symbolic-ref",
        "atk-write-tree",
        "atk-commit-tree",
    ];
    for prefix in plumbing_prefixes {
        let cases: Vec<_> = matrix
            .cases
            .iter()
            .filter(|c| c.id.starts_with(prefix))
            .collect();
        assert!(
            !cases.is_empty(),
            "missing attack cases for prefix {prefix}"
        );
        for case in cases {
            assert_eq!(
                case.expect, "blocked",
                "plumbing case {} must be blocked",
                case.id
            );
            if let Err(msg) = evaluate_case(case) {
                panic!("plumbing vector failed: {msg}");
            }
        }
    }
}
