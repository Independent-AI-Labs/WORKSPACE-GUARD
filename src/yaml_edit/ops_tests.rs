use super::ops::{self, Intent};
use super::target::is_deployed_ci_path;
use std::path::Path;

#[test]
fn map_add_parses_map_key_and_entry_key_literally() {
    let args: Vec<String> = [
        "map-add",
        "f.yaml",
        "files",
        "config/shell_guard_policy_matrix.yaml",
        "class=policy-definition",
        "owner=workspace-guard",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let cli = ops::parse_cli(&args).expect("map-add parses");
    assert_eq!(cli.intent, Intent::MapAdd);
    assert_eq!(cli.key.as_deref(), Some("files"));
    assert_eq!(
        cli.new_key.as_deref(),
        Some("config/shell_guard_policy_matrix.yaml")
    );
    assert_eq!(cli.specs.len(), 2);
}

#[test]
fn map_add_requires_an_entry_key() {
    let args: Vec<String> = ["map-add", "f.yaml", "files", "class=x"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(ops::parse_cli(&args).is_err());
}

#[test]
fn deployed_ci_paths_are_rejected() {
    assert!(is_deployed_ci_path(Path::new(
        "/opt/workspace-ci/res/dependency-pins.yaml"
    )));
    assert!(is_deployed_ci_path(Path::new(
        "/opt/workspace-ci/sha256-abcd"
    )));
}

#[test]
fn source_and_similar_paths_are_not_deployed_ci() {
    assert!(!is_deployed_ci_path(Path::new(
        "/workspace/projects/WORKSPACE-CI/res/dependency-pins.yaml"
    )));
    assert!(!is_deployed_ci_path(Path::new(
        "/workspace/projects/similar-name/res/dependency-pins.yaml"
    )));
}
