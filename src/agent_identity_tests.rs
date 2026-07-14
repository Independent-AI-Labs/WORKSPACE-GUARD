use super::*;
use std::ffi::CString;

#[test]
fn parse_agent_git_identity_accepts_allowed_keys() {
    let content = r#"
# comment
user.email=agent@test.local
user.name=Test Agent
core.editor=vim
"#;
    let id = parse_agent_git_identity(content);
    assert_eq!(
        id,
        AgentGitIdentity {
            email: Some("agent@test.local".into()),
            name: Some("Test Agent".into()),
        }
    );
}

#[test]
fn parse_gitconfig_user_section_reads_ini_block() {
    let content = r#"
[core]
    editor = vim
[user]
    name = Ini Agent
    email = ini@test.local
"#;
    let id = parse_gitconfig_user_section(content);
    assert_eq!(
        id,
        AgentGitIdentity {
            email: Some("ini@test.local".into()),
            name: Some("Ini Agent".into()),
        }
    );
}

#[test]
fn parse_agent_git_identity_ignores_empty_values() {
    let id = parse_agent_git_identity("user.email=\nuser.name=  \n");
    assert_eq!(id, AgentGitIdentity::default());
}

#[test]
fn base_hardened_entries_includes_identity_when_present() {
    let id = AgentGitIdentity {
        email: Some("a@b.c".into()),
        name: Some("N".into()),
    };
    let entries = base_hardened_entries(&id);
    assert!(entries
        .iter()
        .any(|(k, v)| k == "user.email" && v == "a@b.c"));
    assert!(entries.iter().any(|(k, v)| k == "user.name" && v == "N"));
    assert!(entries
        .iter()
        .any(|(k, v)| k == "safe.directory" && v == "*"));
    assert_eq!(entries.len(), 5);
}

#[test]
fn hardened_git_env_pairs_non_privileged_nulls_global_and_injects_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("identity");
    std::fs::write(&path, "user.email=e@test.local\nuser.name=E Test\n").expect("write");
    std::env::set_var(
        "WORKSPACE_GUARD_AGENT_IDENTITY_FILE",
        path.to_string_lossy().as_ref(),
    );

    let pairs = hardened_git_env_pairs(false);
    std::env::remove_var("WORKSPACE_GUARD_AGENT_IDENTITY_FILE");

    assert!(pairs
        .iter()
        .any(|(k, v)| k == "GIT_CONFIG_GLOBAL" && v == "/dev/null"));
    assert!(pairs
        .iter()
        .any(|(k, v)| k == "GIT_CONFIG_NOSYSTEM" && v == "1"));
    assert!(pairs
        .iter()
        .any(|(k, v)| k == "GIT_CONFIG_KEY_3" && v == "user.email"));
    assert!(pairs
        .iter()
        .any(|(k, v)| k == "GIT_CONFIG_VALUE_3" && v == "e@test.local"));
    assert!(pairs
        .iter()
        .any(|(k, v)| k == "GIT_CONFIG_COUNT" && v == "5"));
}

#[test]
fn hardened_git_env_pairs_privileged_only_safe_directory() {
    let pairs = hardened_git_env_pairs(true);
    assert_eq!(pairs.len(), 3);
    assert!(pairs
        .iter()
        .any(|(k, v)| k == "GIT_CONFIG_KEY_0" && v == "safe.directory"));
    assert!(!pairs.iter().any(|(k, _)| k == "GIT_CONFIG_GLOBAL"));
}

#[test]
fn push_agent_hardened_git_env_non_privileged_builds_cstrings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("identity");
    std::fs::write(&path, "user.email=x@y.z\n").expect("write");
    std::env::set_var(
        "WORKSPACE_GUARD_AGENT_IDENTITY_FILE",
        path.to_string_lossy().as_ref(),
    );

    let mut envp: Vec<CString> = Vec::new();
    push_agent_hardened_git_env(&mut envp, false);
    std::env::remove_var("WORKSPACE_GUARD_AGENT_IDENTITY_FILE");

    let flat: Vec<String> = envp
        .iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect();
    assert!(flat.iter().any(|e| e == "GIT_CONFIG_GLOBAL=/dev/null"));
    assert!(flat.iter().any(|e| e.starts_with("GIT_CONFIG_COUNT=")));
    assert!(flat.iter().any(|e| e == "GIT_CONFIG_KEY_3=user.email"));
}

#[test]
fn load_identity_from_home_gitconfig_requires_root_owned_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let gitconfig = dir.path().join(".gitconfig");
    std::fs::write(
        &gitconfig,
        "[user]\nname = Local\nemail = local@test.local\n",
    )
    .expect("write");
    let id = load_identity_from_home_gitconfig(dir.path());
    assert_eq!(id, AgentGitIdentity::default());
}
