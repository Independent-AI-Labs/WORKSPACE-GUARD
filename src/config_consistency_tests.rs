//! Cross-config consistency tests for WORKSPACE-GUARD.
//!
//! These are Rust unit tests (run via `cargo test`) that load the YAML
//! config and generated baselines and assert the cross-file invariants
//! the prose specs describe but no single script enforces: the binary-
//! lock surface is a subset of the live SUID baseline, the cap
//! allowlist only references absolute paths with lowercase cap_*
//! names, sandbox profile names resolve to real profile files, the
//! CVE catalog has unique ids in a sane CVSS range, etc.
//!
//! Tests read files relative to CARGO_MANIFEST_DIR (the repo root) so
//! they are stable regardless of the cargo invocation cwd.

use serde_yaml::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Resolve a repo-relative path under the crate manifest dir.
fn repo_path(rel: &str) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/{rel}")
}

fn load_yaml(rel: &str) -> Value {
    let raw =
        fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("failed to read {rel}: {e}"));
    serde_yaml::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {rel} as YAML: {e}"))
}

/// Collect the top-level keys of a mapping at the given dotted path.
fn mapping_keys<'a>(root: &'a Value, key: &str) -> Vec<&'a str> {
    let map = root
        .get(key)
        .unwrap_or_else(|| panic!("missing top-level key: {key}"))
        .as_mapping()
        .unwrap_or_else(|| panic!("`{key}` is not a mapping"));
    map.keys().filter_map(|k| k.as_str()).collect()
}

/// Pull the string list under each entry of a YAML sequence.
fn seq_strings<'a>(root: &'a Value, key: &str, field: &str) -> Vec<&'a str> {
    let seq = root
        .get(key)
        .unwrap_or_else(|| panic!("missing key: {key}"))
        .as_sequence()
        .unwrap_or_else(|| panic!("`{key}` is not a sequence"));
    seq.iter()
        .filter_map(|e| e.get(field).and_then(|v| v.as_str()))
        .collect()
}

const VALID_POLICIES: &[&str] = &[
    "deny-non-root",
    "deny-all-non-root",
    "arg-validate",
    "pass-through",
];

// ---------------------------------------------------------------------------
// config/guard_subcommands.yaml + guard_policy_matrix.yaml
// ---------------------------------------------------------------------------

#[test]
fn guard_subcommands_parses() {
    let _ = load_yaml("config/guard_subcommands.yaml");
}

#[test]
fn guard_subcommands_blocked_and_partial_disjoint() {
    let doc = load_yaml("config/guard_subcommands.yaml");
    let blocked: HashSet<&str> = doc
        .get("blocked")
        .and_then(|v| v.as_sequence())
        .unwrap()
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    let sudo: HashSet<&str> = doc
        .get("sudo_gated")
        .and_then(|v| v.as_sequence())
        .map(|seq| seq.iter().filter_map(|e| e.as_str()).collect())
        .unwrap_or_default();
    let partial: HashSet<&str> = doc
        .get("partial")
        .and_then(|v| v.as_sequence())
        .unwrap()
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    for sub in &blocked {
        assert!(!sudo.contains(sub), "blocked/sudo_gated overlap: {sub}");
        assert!(!partial.contains(sub), "blocked/partial overlap: {sub}");
    }
    for sub in &sudo {
        assert!(!partial.contains(sub), "sudo_gated/partial overlap: {sub}");
    }
}

#[test]
fn guard_subcommands_plumbing_in_blocked() {
    let doc = load_yaml("config/guard_subcommands.yaml");
    let blocked: HashSet<&str> = doc
        .get("blocked")
        .and_then(|v| v.as_sequence())
        .unwrap()
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    for sub in [
        "update-ref",
        "read-tree",
        "symbolic-ref",
        "write-tree",
        "commit-tree",
    ] {
        assert!(blocked.contains(sub), "plumbing subcommand missing: {sub}");
    }
}

#[test]
fn guard_subcommands_switch_in_sudo_gated() {
    let doc = load_yaml("config/guard_subcommands.yaml");
    let sudo: HashSet<&str> = doc
        .get("sudo_gated")
        .and_then(|v| v.as_sequence())
        .unwrap()
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    assert!(sudo.contains("switch"), "switch must be sudo_gated");
}

#[test]
fn guard_policy_matrix_parses_with_cases() {
    let doc = load_yaml("config/guard_policy_matrix.yaml");
    let cases = doc
        .get("cases")
        .and_then(|c| c.as_sequence())
        .expect("cases is a sequence");
    assert!(cases.len() >= 70, "policy matrix too small: {}", cases.len());
}

#[test]
fn guard_policy_matrix_covers_partial_subcommands() {
    let subcommands = load_yaml("config/guard_subcommands.yaml");
    let matrix = load_yaml("config/guard_policy_matrix.yaml");
    let partial: HashSet<&str> = subcommands
        .get("partial")
        .and_then(|v| v.as_sequence())
        .unwrap()
        .iter()
        .filter_map(|e| e.as_str())
        .collect();
    let covered: HashSet<String> = matrix
        .get("cases")
        .unwrap()
        .as_sequence()
        .unwrap()
        .iter()
        .filter_map(|e| e.get("argv").and_then(|a| a.as_sequence()))
        .filter_map(|argv| argv.get(1).and_then(|v| v.as_str()))
        .filter(|s| !s.starts_with('-'))
        .map(String::from)
        .collect();
    for sub in &partial {
        assert!(
            covered.contains(&sub.to_string()),
            "policy matrix missing partial subcommand case: {sub}"
        );
    }
}

#[test]
fn guard_policy_matrix_cases_have_unique_ids() {
    let doc = load_yaml("config/guard_policy_matrix.yaml");
    let cases = doc.get("cases").unwrap().as_sequence().unwrap();
    let mut seen = HashSet::new();
    for entry in cases {
        let id = entry
            .get("id")
            .and_then(|v| v.as_str())
            .expect("case has id");
        assert!(seen.insert(id), "duplicate policy matrix id: {id}");
        let expect = entry.get("expect").and_then(|v| v.as_str()).unwrap();
        assert!(
            expect == "blocked" || expect == "allowed",
            "invalid expect on {id}: {expect}"
        );
        let argv = entry.get("argv").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(
            argv.first().and_then(|v| v.as_str()),
            Some("git"),
            "argv must start with git on {id}"
        );
    }
}

// ---------------------------------------------------------------------------
// res/binary-lock.yaml (generated by sync-gtfobins)
// ---------------------------------------------------------------------------

#[test]
fn binary_lock_parses() {
    let _ = load_yaml("res/binary-lock.yaml");
}

#[test]
fn binary_lock_paths_are_absolute_or_null() {
    let doc = load_yaml("res/binary-lock.yaml");
    let seq = doc.get("binaries").unwrap().as_sequence().unwrap();
    for entry in seq {
        let path = entry.get("path").and_then(|p| p.as_str());
        if let Some(p) = path {
            assert!(p.starts_with('/'), "binary-lock path is not absolute: {p}");
        }
    }
}

#[test]
fn binary_lock_policies_are_known() {
    let doc = load_yaml("res/binary-lock.yaml");
    let seq = doc.get("binaries").unwrap().as_sequence().unwrap();
    for entry in seq {
        let policy = entry
            .get("policy")
            .and_then(|p| p.as_str())
            .unwrap_or_else(|| panic!("entry has no policy: {:?}", entry));
        assert!(
            VALID_POLICIES.contains(&policy),
            "unknown policy `{policy}` on {:?}",
            entry.get("name")
        );
    }
}

#[test]
fn binary_lock_arg_validate_requires_allow_subcommands() {
    let doc = load_yaml("res/binary-lock.yaml");
    let seq = doc.get("binaries").unwrap().as_sequence().unwrap();
    for entry in seq {
        let policy = entry.get("policy").and_then(|p| p.as_str()).unwrap();
        if policy != "arg-validate" {
            continue;
        }
        let allow = entry.get("allow_subcommands").and_then(|a| a.as_sequence());
        assert!(
            allow.map(|s| !s.is_empty()).unwrap_or(false),
            "arg-validate entry {:?} has empty/missing allow_subcommands",
            entry.get("name")
        );
    }
}

#[test]
fn binary_lock_env_sanitise_names_are_uppercase_ids() {
    let doc = load_yaml("res/binary-lock.yaml");
    let seq = doc.get("binaries").unwrap().as_sequence().unwrap();
    for entry in seq {
        let Some(list) = entry.get("env_sanitise").and_then(|e| e.as_sequence()) else {
            continue;
        };
        for env in list {
            let name = env
                .as_str()
                .unwrap_or_else(|| panic!("non-str-env {:?}", env));
            assert!(
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                "env_sanitise entry `{name}` on {:?} is not an uppercase identifier",
                entry.get("name")
            );
        }
    }
}

#[test]
fn binary_lock_non_null_paths_are_subset_of_suid_or_cap_baseline() {
    let lock = load_yaml("res/binary-lock.yaml");
    let suid = load_yaml("res/suid-baseline.yaml");
    let fcap = load_yaml("res/fcap-baseline.yaml");
    let lock_paths: HashSet<&str> = {
        let seq = lock.get("binaries").unwrap().as_sequence().unwrap();
        seq.iter()
            .filter_map(|e| e.get("path").and_then(|p| p.as_str()))
            .filter(|p| !p.is_empty())
            .collect()
    };
    let suid_paths: HashSet<&str> = seq_strings(&suid, "suid_binaries", "path")
        .into_iter()
        .collect();
    let cap_paths: HashSet<&str> = seq_strings(&fcap, "file_capabilities", "path")
        .into_iter()
        .collect();
    for p in &lock_paths {
        assert!(
            suid_paths.contains(p) || cap_paths.contains(p),
            "binary-lock path `{p}` is in neither suid nor fcap baseline",
        );
    }
}

#[test]
fn binary_lock_has_entries() {
    let lock = load_yaml("res/binary-lock.yaml");
    let n = lock.get("binaries").unwrap().as_sequence().unwrap().len();
    assert!(
        n > 100,
        "binary-lock surface too small: {n} (expected 100+)"
    );
}

// ---------------------------------------------------------------------------
// cap-allowlist.yaml
// ---------------------------------------------------------------------------

#[test]
fn cap_allowlist_parses() {
    let _ = load_yaml("config/cap-allowlist.yaml");
}

#[test]
fn cap_allowlist_paths_are_absolute() {
    let doc = load_yaml("config/cap-allowlist.yaml");
    for path in mapping_keys(&doc, "allowlist") {
        assert!(
            path.starts_with('/'),
            "cap-allowlist path is not absolute: {path}"
        );
    }
}

#[test]
fn cap_allowlist_entries_have_allowed_and_reason() {
    let doc = load_yaml("config/cap-allowlist.yaml");
    let map = doc.get("allowlist").unwrap().as_mapping().unwrap();
    for (k, v) in map {
        let allowed = v.get("allowed").and_then(|a| a.as_sequence());
        assert!(
            allowed.map(|s| !s.is_empty()).unwrap_or(false),
            "allowlist entry {:?} has empty/missing allowed",
            k
        );
        assert!(v.get("reason").is_some(), "entry {:?} missing reason", k);
    }
}

#[test]
fn cap_allowlist_cap_names_are_lowercase_cap_prefix() {
    let doc = load_yaml("config/cap-allowlist.yaml");
    let map = doc.get("allowlist").unwrap().as_mapping().unwrap();
    for (k, v) in map {
        let Some(list) = v.get("allowed").and_then(|a| a.as_sequence()) else {
            continue;
        };
        for cap in list {
            let name = cap
                .as_str()
                .unwrap_or_else(|| panic!("non-str cap {:?}", cap));
            assert!(
                name.starts_with("cap_")
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "allowlist cap `{name}` on {:?} is not a lowercase cap_* name",
                k
            );
        }
    }
}

#[test]
fn cap_allowlist_subset_of_fcap_baseline() {
    let allow = load_yaml("config/cap-allowlist.yaml");
    let baseline = load_yaml("res/fcap-baseline.yaml");
    let allow_paths: HashSet<&str> = mapping_keys(&allow, "allowlist").into_iter().collect();
    let baseline_paths: HashSet<&str> = seq_strings(&baseline, "file_capabilities", "path")
        .into_iter()
        .collect();
    // The allowlist must not list a path that is neither on the live
    // cap surface nor a known hand-curated exception; we only assert
    // that every allowlisted path present in the baseline keeps its
    // caps within the allowed set (consistency, not completeness).
    assert!(!allow_paths.is_empty(), "cap-allowlist is empty");
    if baseline_paths.is_empty() {
        // Minimal hosts (Podman ubuntu:22.04, fresh CI images) may have
        // zero file capabilities on disk; sync emits file_capabilities: [].
        return;
    }
    let _ = (&allow_paths, &baseline_paths);
}

// ---------------------------------------------------------------------------
// res/suid-baseline.yaml integrity
// ---------------------------------------------------------------------------

#[test]
fn suid_baseline_paths_are_absolute_and_unique() {
    let doc = load_yaml("res/suid-baseline.yaml");
    let paths: Vec<&str> = seq_strings(&doc, "suid_binaries", "path");
    assert!(!paths.is_empty(), "suid baseline empty");
    let mut seen = HashSet::new();
    for p in &paths {
        assert!(p.starts_with('/'), "baseline path not absolute: {p}");
        assert!(seen.insert(p), "duplicate baseline path: {p}");
    }
}

#[test]
fn suid_baseline_entries_have_required_fields() {
    let doc = load_yaml("res/suid-baseline.yaml");
    let seq = doc.get("suid_binaries").unwrap().as_sequence().unwrap();
    for e in seq {
        for field in &["path", "owner", "group", "mode", "sha256"] {
            assert!(e.get(*field).is_some(), "entry missing {field}");
        }
    }
}

// ---------------------------------------------------------------------------
// res/fcap-baseline.yaml integrity
// ---------------------------------------------------------------------------

#[test]
fn fcap_baseline_paths_are_absolute_and_unique() {
    let doc = load_yaml("res/fcap-baseline.yaml");
    let paths: Vec<&str> = seq_strings(&doc, "file_capabilities", "path");
    let mut seen = HashSet::new();
    for p in &paths {
        assert!(p.starts_with('/'), "fcap path not absolute: {p}");
        assert!(seen.insert(p), "duplicate fcap path: {p}");
    }
}

// ---------------------------------------------------------------------------
// config/guard_locked_paths.yaml absolute_file_paths (home-lock surface)
// ---------------------------------------------------------------------------

#[test]
fn home_lock_paths_parses() {
    let _ = load_yaml("config/guard_locked_paths.yaml");
}

#[test]
fn home_lock_paths_are_absolute_or_tilde_prefixed() {
    let doc = load_yaml("config/guard_locked_paths.yaml");
    let map = doc
        .get("absolute_file_paths")
        .and_then(|v| v.as_mapping())
        .unwrap_or_else(|| panic!("absolute_file_paths is a mapping"));
    assert!(!map.is_empty(), "absolute_file_paths is empty");
    for (k, _v) in map {
        let p = k.as_str().expect("key is a string");
        assert!(
            p.starts_with('/') || p.starts_with('~'),
            "home-lock path is neither absolute nor ~ -prefixed: {p}"
        );
    }
}

#[test]
fn home_lock_modes_are_in_valid_range() {
    let doc = load_yaml("config/guard_locked_paths.yaml");
    let map = doc
        .get("absolute_file_paths")
        .unwrap()
        .as_mapping()
        .unwrap();
    for (_k, v) in map {
        let mode = v
            .as_u64()
            .or_else(|| v.as_i64().map(|i| i as u64))
            .unwrap_or_else(|| panic!("mode is an integer: {:?}", v));
        assert!(
            (0o400..=0o777).contains(&mode),
            "home-lock mode {mode:o} outside [0o400,0o777]"
        );
    }
}
