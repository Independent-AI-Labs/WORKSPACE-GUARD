//! Git SSH wrapper: exec ssh authenticated by a root-provisioned per-user
//! ed25519 key, without ever writing key material to agent-readable disk.
//! Installed as /usr/lib/workspace-guard/git-ssh-wrapper with cap_dac_override.
//!
//! Two controls (H3):
//!   1. Key isolation: the wrapper reads the root-owned key via its file
//!      capability and pipes it straight into an ssh-agent it owns
//!      (`ssh-add -` on stdin). ssh then authenticates through the agent
//!      socket (`-o IdentityAgent=`), so no `-i` staging copy exists for
//!      the agent to read and reuse with a plain ssh client.
//!   2. Argv allowlist: the wrapper refuses any invocation that is not
//!      exactly git's transport form
//!      `ssh [-p port] [-o SendEnv=GIT_PROTOCOL] [-4|-6] user@host <cmd>`
//!      with user/host inside config/git_ssh_allowlist.yaml and <cmd> a
//!      quoted `git-upload-pack`/`git-receive-pack` with a safe path
//!      charset. No port forwards, no interactive sessions, no other
//!      hosts.
//!
//! Residual: the agent can point its own ssh at the wrapper-managed agent
//! socket and authenticate as itself to any host that accepts the
//! provisioned key, but it can never extract the private key (ssh-agent
//! does not export key material). Server-side receive hooks (H4) are the
//! enforcement layer for where pushes may land.

use std::ffi::{CString, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{self, Command, Stdio};

use nix::unistd::{chown, execv, getuid, Uid, User};

const SSH_BIN: &str = "/usr/bin/ssh";
const SSH_AGENT_BIN: &str = "/usr/bin/ssh-agent";
const SSH_ADD_BIN: &str = "/usr/bin/ssh-add";
const KEY_ROOT: &str = "/usr/lib/workspace-guard/ssh-keys";
const STAGE_DIR_NAME: &str = "workspace-guard";
const AGENT_SOCK_NAME: &str = "agent.sock";
const CHILD_PATH_ENV: &str = "/usr/bin:/bin";

include!(concat!(env!("OUT_DIR"), "/git_ssh_config.rs"));

#[derive(Debug, PartialEq)]
enum AgentState {
    HasKeys,
    Empty,
    Dead,
}

fn valid_username(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn provisioned_key_path(username: &str) -> Option<PathBuf> {
    if !valid_username(username) {
        return None;
    }
    let key = PathBuf::from(KEY_ROOT).join(username).join("id_ed25519");
    let parent = key.parent()?;
    let parent = fs_canonicalize(parent).ok()?;
    let key = parent.join("id_ed25519");
    if !key.is_file() {
        return None;
    }
    let key_str = key.to_string_lossy();
    if !key_str.starts_with(&format!("{}/", KEY_ROOT)) {
        return None;
    }
    Some(key)
}

fn fs_canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::RootDir | Component::Prefix(_) => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(c) => out.push(c),
        }
    }
    if out.is_absolute() && out.is_dir() {
        Ok(out)
    } else {
        std::fs::canonicalize(path)
    }
}

fn runtime_base(uid: Uid) -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", uid.as_raw())))
}

fn runtime_dir(uid: Uid) -> Result<PathBuf, std::io::Error> {
    let dir = runtime_base(uid).join(STAGE_DIR_NAME);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let _ = chown(&dir, Some(uid), None);
    Ok(dir)
}

fn ssh_add_probe(sock: &Path) -> AgentState {
    let out = Command::new(SSH_ADD_BIN)
        .arg("-l")
        .env_clear()
        .env("PATH", CHILD_PATH_ENV)
        .env("SSH_AUTH_SOCK", sock)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match out {
        Ok(s) if s.success() => AgentState::HasKeys,
        Ok(s) if s.code() == Some(1) => AgentState::Empty,
        _ => AgentState::Dead,
    }
}

fn spawn_agent(sock: &Path) -> Result<(), std::io::Error> {
    let _ = std::fs::remove_file(sock);
    let status = Command::new(SSH_AGENT_BIN)
        .arg("-a")
        .arg(sock)
        .env_clear()
        .env("PATH", CHILD_PATH_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("ssh-agent exited non-zero"))
    }
}

fn load_key_into_agent(sock: &Path, material: &[u8]) -> Result<(), std::io::Error> {
    let mut child = Command::new(SSH_ADD_BIN)
        .arg("-")
        .env_clear()
        .env("PATH", CHILD_PATH_ENV)
        .env("SSH_AUTH_SOCK", sock)
        .env("SSH_ASKPASS", "/bin/false")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        let write_result = stdin.write_all(material);
        drop(stdin);
        write_result?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("ssh-add exited non-zero"))
    }
}

fn ensure_agent_with_key(uid: Uid, key: &Path) -> Result<PathBuf, String> {
    let material = std::fs::read(key).map_err(|e| format!("cannot read provisioned key: {e}"))?;
    let dir = runtime_dir(uid).map_err(|e| format!("cannot prepare runtime dir: {e}"))?;
    let sock = dir.join(AGENT_SOCK_NAME);
    if ssh_add_probe(&sock) == AgentState::Dead {
        spawn_agent(&sock).map_err(|e| format!("cannot spawn ssh-agent: {e}"))?;
    }
    if ssh_add_probe(&sock) == AgentState::Dead {
        return Err("ssh-agent socket not responsive after spawn".into());
    }
    if load_key_into_agent(&sock, &material).is_err() && ssh_add_probe(&sock) != AgentState::HasKeys
    {
        return Err("cannot load provisioned key into ssh-agent".into());
    }
    Ok(sock)
}

fn is_safe_repo_path(inner: &str) -> bool {
    !inner.is_empty()
        && inner.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || c == '.'
                || c == '_'
                || c == '/'
                || c == '-'
                || c == '~'
                || c == '+'
        })
}

fn valid_git_command(cmd: &str) -> bool {
    for prefix in ["git-upload-pack '", "git-receive-pack '"] {
        if let Some(rest) = cmd.strip_prefix(prefix) {
            if let Some(inner) = rest.strip_suffix('\'') {
                return is_safe_repo_path(inner);
            }
        }
    }
    false
}

fn valid_host_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn validate_ssh_args(args: &[OsString]) -> Result<(), String> {
    let mut positionals: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let s = args[i].to_string_lossy().to_string();
        match s.as_str() {
            "-p" => {
                let port = args
                    .get(i + 1)
                    .map(|p| p.to_string_lossy().to_string())
                    .ok_or("missing port after -p")?;
                if port.is_empty() || port.len() > 5 || !port.chars().all(|c| c.is_ascii_digit()) {
                    return Err(format!("bad -p port: {port}"));
                }
                i += 2;
            }
            "-o" => {
                let opt = args
                    .get(i + 1)
                    .map(|o| o.to_string_lossy().to_string())
                    .ok_or("missing value after -o")?;
                if opt != "SendEnv=GIT_PROTOCOL" {
                    return Err(format!("-o option not allowed: {opt}"));
                }
                i += 2;
            }
            "-4" | "-6" => i += 1,
            _ if s.starts_with('-') => return Err(format!("ssh option not allowed: {s}")),
            _ => {
                positionals.push(s);
                i += 1;
            }
        }
    }
    if positionals.len() != 2 {
        return Err(format!(
            "expected user@host and command, got {} positional(s)",
            positionals.len()
        ));
    }
    let dest = &positionals[0];
    let (user, host) = dest
        .split_once('@')
        .ok_or_else(|| format!("destination not user@host: {dest}"))?;
    if !valid_host_token(user) || !valid_host_token(host) {
        return Err(format!("bad destination charset: {dest}"));
    }
    if !GIT_SSH_ALLOWED_USERS.contains(&user) {
        return Err(format!("ssh user not allowed: {user}"));
    }
    if !GIT_SSH_ALLOWED_HOSTS.contains(&host) {
        return Err(format!("ssh host not allowed: {host}"));
    }
    let cmd = &positionals[1];
    if !valid_git_command(cmd) {
        return Err(format!("remote command not allowed: {cmd}"));
    }
    Ok(())
}

fn cstring_arg(arg: &OsString) -> CString {
    CString::new(arg.as_bytes()).unwrap_or_else(|_| CString::new("ssh").unwrap())
}

/// Build the ssh argv. IdentityFile is required even though the key
/// comes from the agent: with IdentitiesOnly=yes and no configured
/// identity file, ssh offers zero keys and the server rejects with
/// publickey-denied (observed 2026-07-22: pushes failed despite the
/// agent holding the provisioned key). Pointing IdentityFile at the
/// provisioned .pub makes ssh offer exactly that key from our agent;
/// the private half stays root-only.
fn build_ssh_argv(sock: &Path, pubkey: &Path, incoming: &[OsString]) -> Vec<CString> {
    let mut argv: Vec<CString> = vec![
        CString::new("ssh").expect("argv0"),
        CString::new("-F").expect("-F"),
        CString::new("/dev/null").expect("ssh config"),
        CString::new("-o").expect("-o flag"),
        CString::new("IdentitiesOnly=yes").expect("IdentitiesOnly"),
        CString::new("-o").expect("-o flag"),
        CString::new(format!("IdentityFile={}", pubkey.to_string_lossy())).expect("IdentityFile"),
        CString::new("-o").expect("-o flag"),
        CString::new(format!("IdentityAgent={}", sock.to_string_lossy())).expect("IdentityAgent"),
        CString::new("-o").expect("-o flag"),
        CString::new("StrictHostKeyChecking=accept-new").expect("StrictHostKeyChecking"),
    ];
    for arg in incoming {
        argv.push(cstring_arg(arg));
    }
    argv
}

fn main() {
    let user = match User::from_uid(getuid()) {
        Ok(Some(u)) => u,
        _ => {
            eprintln!("git-ssh-wrapper: cannot resolve user");
            process::exit(2);
        }
    };
    let username = &user.name;
    let source_key = match provisioned_key_path(username) {
        Some(k) => k,
        None => {
            eprintln!("git-ssh-wrapper: no provisioned key for user {}", username);
            process::exit(2);
        }
    };

    let incoming: Vec<OsString> = std::env::args_os().skip(1).collect();
    if let Err(e) = validate_ssh_args(&incoming) {
        eprintln!("git-ssh-wrapper: refused: {e}");
        process::exit(2);
    }

    let sock = match ensure_agent_with_key(user.uid, &source_key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("git-ssh-wrapper: {e}");
            process::exit(2);
        }
    };

    let ssh = CString::new(SSH_BIN).expect("ssh path");
    let mut pubkey = source_key.clone().into_os_string();
    pubkey.push(".pub");
    let argv = build_ssh_argv(&sock, Path::new(&pubkey), &incoming);

    if execv(&ssh, &argv).is_err() {
        eprintln!("git-ssh-wrapper: execv {} failed", SSH_BIN);
        process::exit(3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn valid_username_accepts_agent() {
        assert!(valid_username("agent"));
        assert!(valid_username("builder-1"));
    }

    #[test]
    fn valid_username_rejects_empty_and_slash() {
        assert!(!valid_username(""));
        assert!(!valid_username("../root"));
        assert!(!valid_username("a/b"));
    }

    #[test]
    fn provisioned_key_path_rejects_bad_username() {
        assert!(provisioned_key_path("").is_none());
        assert!(provisioned_key_path("bad/name").is_none());
    }

    #[test]
    fn runtime_base_prefers_xdg_runtime_dir() {
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        assert_eq!(
            runtime_base(Uid::from_raw(1000)),
            PathBuf::from("/run/user/1000")
        );
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    #[test]
    fn validate_accepts_git_upload_pack() {
        let args = os(&[
            "git@github.com",
            "git-upload-pack '/Independent-AI-Labs/WORKSPACE-GUARD.git'",
        ]);
        assert!(validate_ssh_args(&args).is_ok());
    }

    #[test]
    fn validate_accepts_git_protocol_and_port() {
        let args = os(&[
            "-p",
            "22",
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "-4",
            "git@github.com",
            "git-receive-pack '/org/repo.git'",
        ]);
        assert!(validate_ssh_args(&args).is_ok());
    }

    #[test]
    fn validate_rejects_unknown_host() {
        let args = os(&["git@evil.example.com", "git-upload-pack '/org/repo.git'"]);
        let err = validate_ssh_args(&args).unwrap_err();
        assert!(err.contains("host not allowed"), "unexpected: {err}");
    }

    #[test]
    fn validate_rejects_unknown_user() {
        let args = os(&["root@github.com", "git-upload-pack '/org/repo.git'"]);
        let err = validate_ssh_args(&args).unwrap_err();
        assert!(err.contains("user not allowed"), "unexpected: {err}");
    }

    #[test]
    fn validate_rejects_interactive_session() {
        let args = os(&["git@github.com"]);
        assert!(validate_ssh_args(&args).is_err());
    }

    #[test]
    fn validate_rejects_port_forward() {
        let args = os(&[
            "-L",
            "8080:localhost:80",
            "git@github.com",
            "git-upload-pack '/org/repo.git'",
        ]);
        assert!(validate_ssh_args(&args).is_err());
    }

    #[test]
    fn validate_rejects_option_injection() {
        let args = os(&[
            "-o",
            "ProxyCommand=/tmp/x",
            "git@github.com",
            "git-upload-pack '/org/repo.git'",
        ]);
        assert!(validate_ssh_args(&args).is_err());
    }

    #[test]
    fn validate_rejects_shell_injection_in_command() {
        let args = os(&[
            "git@github.com",
            "git-upload-pack '/org/repo.git'; rm -rf /; '",
        ]);
        assert!(validate_ssh_args(&args).is_err());
        let args2 = os(&["git@github.com", "git-upload-pack '/org/repo.git' extra"]);
        assert!(validate_ssh_args(&args2).is_err());
    }

    #[test]
    fn argv_pins_identity_file_when_identities_only() {
        let args = os(&["git@github.com", "git-upload-pack '/org/repo.git'"]);
        let argv = build_ssh_argv(
            Path::new("/run/user/1000/workspace-guard/agent.sock"),
            Path::new("/usr/lib/workspace-guard/ssh-keys/agent/id_ed25519.pub"),
            &args,
        );
        let joined: Vec<String> = argv
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect();
        assert!(joined.iter().any(|a| a == "IdentitiesOnly=yes"));
        assert!(
            joined
                .iter()
                .any(|a| a == "IdentityFile=/usr/lib/workspace-guard/ssh-keys/agent/id_ed25519.pub"),
            "IdentityFile missing: {joined:?}"
        );
        assert!(
            joined
                .iter()
                .any(|a| a == "IdentityAgent=/run/user/1000/workspace-guard/agent.sock"),
            "IdentityAgent missing: {joined:?}"
        );
        assert_eq!(
            joined.last().map(String::as_str),
            Some("git-upload-pack '/org/repo.git'")
        );
    }

    #[test]
    fn validate_rejects_bad_port() {
        let args = os(&[
            "-p",
            "22;id",
            "git@github.com",
            "git-upload-pack '/org/repo.git'",
        ]);
        assert!(validate_ssh_args(&args).is_err());
    }
}
