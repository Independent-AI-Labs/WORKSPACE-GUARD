use super::yaml_edit_target::is_deployed_ci_path;
use std::path::Path;

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
