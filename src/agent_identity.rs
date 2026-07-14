//! Root-provisioned per-user git identity for non-privileged guard exec.
//!
//! Agents never run `git config` for `user.*`. Identity is read from
//! root-owned `$HOME/.gitconfig` (preferred), then fleet fallbacks, and
//! injected into `git.original` via `GIT_CONFIG_*` overrides. SSH transport
//! uses guard-injected `GIT_SSH_COMMAND` → `git-ssh-wrapper`.

use std::ffi::CString;
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::unistd::{getuid, User};

pub const DEFAULT_IDENTITY_PATH: &str = "/usr/lib/workspace-guard/agent-git-identity";
pub const IDENTITIES_DIR: &str = "/usr/lib/workspace-guard/identities";
pub const GIT_SSH_WRAPPER_PATH: &str = "/usr/lib/workspace-guard/git-ssh-wrapper";

const ALLOWED_KEYS: &[&str] = &["user.email", "user.name"];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct AgentGitIdentity {
    pub email: Option<String>,
    pub name: Option<String>,
}

pub fn identity_path() -> PathBuf {
    if let Ok(p) = std::env::var("WORKSPACE_GUARD_AGENT_IDENTITY_FILE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(DEFAULT_IDENTITY_PATH)
}

/// Parse `key=value` lines (`user.email`, `user.name` only).
pub fn parse_agent_git_identity(content: &str) -> AgentGitIdentity {
    let mut identity = AgentGitIdentity::default();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if !ALLOWED_KEYS.contains(&key) {
            continue;
        }
        if value.is_empty() {
            continue;
        }
        match key {
            "user.email" => identity.email = Some(value.to_string()),
            "user.name" => identity.name = Some(value.to_string()),
            _ => {}
        }
    }
    identity
}

/// Parse `[user]` section of a gitconfig ini file (`name` / `email` keys).
pub fn parse_gitconfig_user_section(content: &str) -> AgentGitIdentity {
    let mut identity = AgentGitIdentity::default();
    let mut in_user = false;
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            in_user = section.eq_ignore_ascii_case("user");
            continue;
        }
        if !in_user {
            continue;
        }
        let Some((key, value)) = parse_ini_kv(line) else {
            continue;
        };
        match key.as_str() {
            "email" => identity.email = Some(value),
            "name" => identity.name = Some(value),
            _ => {}
        }
    }
    identity
}

fn parse_ini_kv(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim().to_lowercase();
    let mut value = value.trim().to_string();
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
        {
            value = value[1..value.len() - 1].to_string();
        }
    }
    if value.is_empty() {
        return None;
    }
    Some((key, value))
}

fn is_root_owned(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.st_uid() == 0).unwrap_or(false)
}

pub fn load_agent_git_identity_from(path: &Path) -> AgentGitIdentity {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return AgentGitIdentity::default(),
    };
    if path.extension().is_none() && path.file_name().is_some_and(|n| n == ".gitconfig") {
        return parse_gitconfig_user_section(&content);
    }
    let ini = parse_gitconfig_user_section(&content);
    if ini.email.is_some() || ini.name.is_some() {
        return ini;
    }
    parse_agent_git_identity(&content)
}

pub fn load_identity_from_home_gitconfig(home: &Path) -> AgentGitIdentity {
    let path = home.join(".gitconfig");
    if !path.is_file() || !is_root_owned(&path) {
        return AgentGitIdentity::default();
    }
    load_agent_git_identity_from(&path)
}

pub fn load_identity_from_fleet_file(username: &str) -> AgentGitIdentity {
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return AgentGitIdentity::default();
    }
    let path = PathBuf::from(IDENTITIES_DIR).join(username);
    if !path.is_file() || !is_root_owned(&path) {
        return AgentGitIdentity::default();
    }
    load_agent_git_identity_from(&path)
}

pub fn resolve_unix_user() -> Option<(String, PathBuf)> {
    let uid = getuid();
    let user = User::from_uid(uid).ok().flatten()?;
    let name = user.name;
    if name.is_empty() {
        return None;
    }
    Some((name, user.dir))
}

pub fn load_identity_for_current_user() -> AgentGitIdentity {
    if let Ok(p) = std::env::var("WORKSPACE_GUARD_AGENT_IDENTITY_FILE") {
        if !p.is_empty() {
            return load_agent_git_identity_from(Path::new(&p));
        }
    }
    if let Some((username, home)) = resolve_unix_user() {
        let from_home = load_identity_from_home_gitconfig(&home);
        if from_home.email.is_some() || from_home.name.is_some() {
            return from_home;
        }
        let from_fleet = load_identity_from_fleet_file(&username);
        if from_fleet.email.is_some() || from_fleet.name.is_some() {
            return from_fleet;
        }
    }
    load_agent_git_identity_from(&identity_path())
}

pub fn base_hardened_entries(identity: &AgentGitIdentity) -> Vec<(String, String)> {
    let mut entries = vec![
        ("safe.directory".to_string(), "*".to_string()),
        ("core.fsmonitor".to_string(), String::new()),
        ("core.hooksPath".to_string(), String::new()),
    ];
    if let Some(ref email) = identity.email {
        entries.push(("user.email".to_string(), email.clone()));
    }
    if let Some(ref name) = identity.name {
        entries.push(("user.name".to_string(), name.clone()));
    }
    entries
}

fn push_git_config_count_env(envp: &mut Vec<CString>, entries: &[(String, String)]) {
    envp.push(
        CString::new(format!("GIT_CONFIG_COUNT={}", entries.len())).expect("GIT_CONFIG_COUNT"),
    );
    for (i, (key, val)) in entries.iter().enumerate() {
        envp.push(CString::new(format!("GIT_CONFIG_KEY_{}={}", i, key)).expect("GIT_CONFIG_KEY"));
        envp.push(
            CString::new(format!("GIT_CONFIG_VALUE_{}={}", i, val)).expect("GIT_CONFIG_VALUE"),
        );
    }
}

fn push_ssh_wrapper_env(envp: &mut Vec<CString>) {
    if !Path::new(GIT_SSH_WRAPPER_PATH).is_file() {
        return;
    }
    envp.push(
        CString::new(format!("GIT_SSH_COMMAND={}", GIT_SSH_WRAPPER_PATH)).expect("GIT_SSH_COMMAND"),
    );
    envp.push(CString::new(format!("GIT_SSH={}", GIT_SSH_WRAPPER_PATH)).expect("GIT_SSH"));
}

fn ssh_wrapper_env_pairs() -> Vec<(String, String)> {
    if !Path::new(GIT_SSH_WRAPPER_PATH).is_file() {
        return Vec::new();
    }
    vec![
        (
            "GIT_SSH_COMMAND".to_string(),
            GIT_SSH_WRAPPER_PATH.to_string(),
        ),
        ("GIT_SSH".to_string(), GIT_SSH_WRAPPER_PATH.to_string()),
    ]
}

/// Push git env overrides for `git.original` child exec.
///
/// Privileged (`euid == 0`) callers keep normal global/system config so
/// operators may use `sudo git config`. Non-privileged agents get nulled
/// global/system config plus per-user injected identity and SSH wrapper.
pub fn push_agent_hardened_git_env(envp: &mut Vec<CString>, privileged: bool) {
    if privileged {
        crate::push_safe_directory_env(envp);
        return;
    }
    envp.push(CString::new("GIT_CONFIG_NOSYSTEM=1").expect("GIT_CONFIG_NOSYSTEM"));
    envp.push(CString::new("GIT_CONFIG_GLOBAL=/dev/null").expect("GIT_CONFIG_GLOBAL"));
    envp.push(CString::new("GIT_CONFIG_SYSTEM=/dev/null").expect("GIT_CONFIG_SYSTEM"));
    let identity = load_identity_for_current_user();
    let entries = base_hardened_entries(&identity);
    push_git_config_count_env(envp, &entries);
    push_ssh_wrapper_env(envp);
}

/// Flat key/value pairs for `std::process::Command::env` (policy subcalls).
pub fn hardened_git_env_pairs(privileged: bool) -> Vec<(String, String)> {
    if privileged {
        return vec![
            ("GIT_CONFIG_COUNT".to_string(), "1".to_string()),
            ("GIT_CONFIG_KEY_0".to_string(), "safe.directory".to_string()),
            ("GIT_CONFIG_VALUE_0".to_string(), "*".to_string()),
        ];
    }
    let mut pairs = vec![
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
        ("GIT_CONFIG_SYSTEM".to_string(), "/dev/null".to_string()),
    ];
    let identity = load_identity_for_current_user();
    let entries = base_hardened_entries(&identity);
    pairs.push(("GIT_CONFIG_COUNT".to_string(), entries.len().to_string()));
    for (i, (key, val)) in entries.iter().enumerate() {
        pairs.push((format!("GIT_CONFIG_KEY_{}", i), key.clone()));
        pairs.push((format!("GIT_CONFIG_VALUE_{}", i), val.clone()));
    }
    pairs.extend(ssh_wrapper_env_pairs());
    pairs
}

pub fn apply_agent_hardened_git_env(cmd: &mut std::process::Command, privileged: bool) {
    for (k, v) in hardened_git_env_pairs(privileged) {
        cmd.env(k, v);
    }
}

#[cfg(test)]
#[path = "agent_identity_tests.rs"]
mod tests;
