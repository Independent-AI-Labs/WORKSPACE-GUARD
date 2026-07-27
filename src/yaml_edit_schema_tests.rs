// Unit tests for yaml_edit_schema.rs: the registry must fail closed
// on the exact shapes the audit found in the fleet (string paths,
// short reasons, missing fields) and stay open for unknown basenames
// so the tool remains generic.

use super::yaml_edit_schema as schema;
use serde_yaml::Value;
use std::io::Write;

fn doc(yaml: &str) -> Value {
    serde_yaml::from_str(yaml).expect("test yaml must parse")
}

fn validate(basename: &str, yaml: &str) -> Result<(), String> {
    schema::validate_document(basename, &doc(yaml), &schema::builtins())
}

#[test]
fn quality_exceptions_accepts_a_valid_entry() {
    let yaml = "exceptions:\n  - hook: quality\n    added_by: alice\n    reason: tracked upstream, remove after release\n    paths: [src/a.py]\n";
    assert!(validate("quality_exceptions.yaml", yaml).is_ok());
}

#[test]
fn quality_exceptions_rejects_string_paths() {
    // Audit 1: CI iterated a string as characters, exempting the
    // whole repository. A string paths field must never validate.
    let yaml = "exceptions:\n  - hook: quality\n    added_by: alice\n    reason: tracked upstream, remove after release\n    paths: src/a.py\n";
    assert!(validate("quality_exceptions.yaml", yaml).is_err());
}

#[test]
fn quality_exceptions_rejects_missing_and_short_fields() {
    let missing = "exceptions:\n  - added_by: alice\n    reason: tracked upstream, remove after release\n    paths: [a]\n";
    assert!(validate("quality_exceptions.yaml", missing).is_err());
    let short =
        "exceptions:\n  - hook: quality\n    added_by: a\n    reason: too short\n    paths: [a]\n";
    assert!(validate("quality_exceptions.yaml", short).is_err());
    let empty_paths = "exceptions:\n  - hook: quality\n    added_by: alice\n    reason: tracked upstream, remove after release\n    paths: []\n";
    assert!(validate("quality_exceptions.yaml", empty_paths).is_err());
}

#[test]
fn scalar_list_rejects_empty_and_structured_items() {
    assert!(validate(
        "sensitive_files_exceptions.yaml",
        "safe_exceptions: [README.md, .gitignore]\n"
    )
    .is_ok());
    assert!(validate(
        "sensitive_files_exceptions.yaml",
        "safe_exceptions:\n  - ''\n"
    )
    .is_err());
    assert!(validate(
        "sensitive_files_exceptions.yaml",
        "safe_exceptions:\n  - {nested: true}\n"
    )
    .is_err());
}

#[test]
fn numeric_schemas_reject_string_values() {
    assert!(validate(
        "coverage_thresholds.yaml",
        "coverage_thresholds:\n  version: 2\n  min_coverage: 95\n  timeout: 300\n"
    )
    .is_ok());
    assert!(validate(
        "coverage_thresholds.yaml",
        "coverage_thresholds:\n  min_coverage: '95'\n"
    )
    .is_err());
    assert!(validate("file_length_limits.yaml", "max_lines: lots\n").is_err());
}

#[test]
fn unknown_basename_passes_with_structural_checks_only() {
    assert!(validate("brand_new_policy.yaml", "anything:\n  - goes\n").is_ok());
}

#[test]
fn missing_list_key_fails_for_known_basename() {
    assert!(validate("quality_exceptions.yaml", "other: 1\n").is_err());
}

#[test]
fn override_file_merges_and_wins_per_basename() {
    let dir = std::env::temp_dir().join(format!("ye-schema-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let target = dir.join("custom_policy.yaml");
    std::fs::write(&target, "rules: []\n").expect("write target");
    let mut f = std::fs::File::create(dir.join("yaml_edit_schemas.yaml")).expect("create");
    writeln!(
        f,
        "version: 1\nschemas:\n  - basename: custom_policy.yaml\n    key: rules\n    kind: scalar-list\n"
    )
    .expect("write");
    let reg = schema::registry_for(&target).expect("registry");
    let bad = doc("rules:\n  - {not: scalar}\n");
    assert!(schema::validate_document("custom_policy.yaml", &bad, &reg).is_err());
    let good = doc("rules: [a, b]\n");
    assert!(schema::validate_document("custom_policy.yaml", &good, &reg).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_override_fails_closed() {
    let dir = std::env::temp_dir().join(format!("ye-schema-bad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let target = dir.join("anything.yaml");
    std::fs::write(&target, "k: 1\n").expect("write target");
    std::fs::write(dir.join("yaml_edit_schemas.yaml"), "schemas: [").expect("write");
    assert!(schema::registry_for(&target).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn builtins_cover_the_fleet_policy_files() {
    let builtins = schema::builtins();
    let names: Vec<&str> = builtins.iter().map(|s| s.basename.as_str()).collect();
    for want in [
        "quality_exceptions.yaml",
        "banned_words_exceptions.yaml",
        "silent_swallow_exceptions.yaml",
        "sensitive_files_exceptions.yaml",
        "coverage_thresholds.yaml",
        "file_length_limits.yaml",
    ] {
        assert!(names.contains(&want), "missing builtin schema for {want}");
    }
}
