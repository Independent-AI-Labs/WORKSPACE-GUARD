use super::*;

#[test]
fn remote_url_host_parses_scp_and_scheme_forms() {
    assert_eq!(
        remote_url_host("git@github.com:Independent-AI-Labs/WORKSPACE-GUARD.git"),
        Some("github.com".to_string())
    );
    assert_eq!(
        remote_url_host("ssh://git@github.com:22/org/repo.git"),
        Some("github.com".to_string())
    );
    assert_eq!(
        remote_url_host("https://github.com/org/repo.git"),
        Some("github.com".to_string())
    );
    assert_eq!(remote_url_host("/local/path/repo"), None);
    assert_eq!(remote_url_host("file:///srv/repo.git"), None);
}

#[test]
fn repo_with_provisioned_remote_is_flagged() {
    let dir = tempfile::tempdir().unwrap();
    let top = dir.path().to_string_lossy().to_string();
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&top)
            .args(args)
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "safe.directory")
            .env("GIT_CONFIG_VALUE_0", "*")
            .output()
            .unwrap()
    };
    assert!(run(&["init", "-q"]).status.success());
    assert!(!repo_targets_provisioned_host(&top));
    assert!(run(&[
        "remote",
        "add",
        "origin",
        "git@github.com:Independent-AI-Labs/WORKSPACE-GUARD.git"
    ])
    .status
    .success());
    assert!(repo_targets_provisioned_host(&top));
    assert!(
        run(&["remote", "set-url", "origin", "https://example.com/x/y.git"])
            .status
            .success()
    );
    assert!(!repo_targets_provisioned_host(&top));
}
