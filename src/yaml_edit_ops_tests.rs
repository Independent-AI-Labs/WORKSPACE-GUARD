use super::is_deployed_ci_path;
use std::path::Path;

#[test]
fn deployed_ci_paths_are_rejected() {
    assert!(is_deployed_ci_path(Path::new(
        "/workspace/projects/CI/res/dependency-pins.yaml"
    )));
    assert!(is_deployed_ci_path(Path::new(
        "/workspace/projects/CI.releases/sha256-abcd"
    )));
}

#[test]
fn source_and_similar_paths_are_not_deployed_ci() {
    assert!(!is_deployed_ci_path(Path::new(
        "/workspace/projects/WORKSPACE-CI/res/dependency-pins.yaml"
    )));
    assert!(!is_deployed_ci_path(Path::new(
        "/workspace/projects/CI-quarantine/res/dependency-pins.yaml"
    )));
}
