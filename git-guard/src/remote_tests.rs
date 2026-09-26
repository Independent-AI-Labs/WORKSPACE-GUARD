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
            // Hook contexts (pre-push) export repo env that overrides -C
            // and would redirect these calls at the enclosing repository.
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .unwrap()
    };
    let run_ok = |args: &[&str]| {
        let out = run(args);
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let write_remote = |url: &str| {
        std::fs::write(
            format!("{top}/.git/config"),
            format!("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = {url}\n"),
        )
        .unwrap();
    };
    run_ok(&["init", "-q"]);
    assert!(!repo_targets_provisioned_host(&top));
    write_remote("https://example.com/x/y.git");
    assert!(!repo_targets_provisioned_host(&top));
    // Mutate the config via fs, not `git remote`: once the remote points
    // at a provisioned host the guard treats the repo as a workspace
    // clone and root-locks its .git, so capability-scrubbed contexts
    // (pre-push hooks) can no longer write it via git. The lock also
    // means the tempdir may survive cleanup in such contexts.
    write_remote("git@github.com:Independent-AI-Labs/WORKSPACE-GUARD.git");
    assert!(repo_targets_provisioned_host(&top));
    let _ = std::fs::remove_dir_all(dir.path());
    std::mem::forget(dir);
}
