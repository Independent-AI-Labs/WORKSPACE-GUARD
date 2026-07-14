//! Git SSH wrapper: exec ssh with root-provisioned per-user ed25519 key only.
//! Installed as /usr/lib/workspace-guard/git-ssh-wrapper with cap_dac_override.
//!
//! OpenSSH requires the connecting user to own the private key file. Provision
//! stores keys root:root under `/usr/lib/workspace-guard/ssh-keys/`. This
//! wrapper reads them (via file cap), stages a 0600 copy under the user's
//! runtime dir, then execs ssh against that path.

use std::ffi::{CString, OsString};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process;

use nix::unistd::{chown, execv, getuid, User, Uid};

const SSH_BIN: &str = "/usr/bin/ssh";
const KEY_ROOT: &str = "/usr/lib/workspace-guard/ssh-keys";
const STAGE_DIR_NAME: &str = "workspace-guard";

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

fn stage_key_for_user(uid: Uid, source: &Path) -> Result<PathBuf, std::io::Error> {
    let material = std::fs::read(source)?;
    let stage_dir = runtime_base(uid).join(STAGE_DIR_NAME);
    std::fs::create_dir_all(&stage_dir)?;
    std::fs::set_permissions(&stage_dir, std::fs::Permissions::from_mode(0o700))?;
    let _ = chown(&stage_dir, Some(uid), None);

    let stage_key = stage_dir.join("id_ed25519");
    std::fs::write(&stage_key, &material)?;
    std::fs::set_permissions(&stage_key, std::fs::Permissions::from_mode(0o600))?;
    chown(&stage_key, Some(uid), None)?;
    Ok(stage_key)
}

fn cstring_arg(arg: &OsString) -> CString {
    CString::new(arg.as_bytes()).unwrap_or_else(|_| CString::new("ssh").unwrap())
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

    let staged_key = match stage_key_for_user(user.uid, &source_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("git-ssh-wrapper: cannot stage SSH key: {e}");
            process::exit(2);
        }
    };

    let ssh = CString::new(SSH_BIN).expect("ssh path");
    let mut argv: Vec<CString> = vec![
        CString::new("ssh").expect("argv0"),
        CString::new("-i").expect("-i"),
        CString::new(staged_key.to_string_lossy().as_bytes()).expect("identity file"),
        CString::new("-F").expect("-F"),
        CString::new("/dev/null").expect("ssh config"),
        CString::new("-o").expect("-o flag"),
        CString::new("IdentitiesOnly=yes").expect("IdentitiesOnly"),
        CString::new("-o").expect("-o flag"),
        CString::new("StrictHostKeyChecking=accept-new").expect("StrictHostKeyChecking"),
    ];
    for arg in std::env::args_os().skip(1) {
        argv.push(cstring_arg(&arg));
    }

    if execv(&ssh, &argv).is_err() {
        eprintln!("git-ssh-wrapper: execv {} failed", SSH_BIN);
        process::exit(3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(runtime_base(Uid::from_raw(1000)), PathBuf::from("/run/user/1000"));
        std::env::remove_var("XDG_RUNTIME_DIR");
    }
}