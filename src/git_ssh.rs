//! Git SSH wrapper: exec ssh with root-provisioned per-user ed25519 key only.
//! Installed as /usr/lib/workspace-guard/git-ssh-wrapper with cap_dac_override.

use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process;

use nix::unistd::{execv, getuid, User};

const SSH_BIN: &str = "/usr/bin/ssh";
const KEY_ROOT: &str = "/usr/lib/workspace-guard/ssh-keys";

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
    let key = match provisioned_key_path(username) {
        Some(k) => k,
        None => {
            eprintln!("git-ssh-wrapper: no provisioned key for user {}", username);
            process::exit(2);
        }
    };

    let ssh_config = user.dir.join(".ssh/config");
    let ssh = CString::new(SSH_BIN).expect("ssh path");
    let mut argv: Vec<CString> = vec![
        CString::new("ssh").expect("argv0"),
        CString::new("-i").expect("-i"),
        CString::new(key.to_string_lossy().as_bytes()).expect("identity file"),
        CString::new("-F").expect("-F"),
        CString::new(ssh_config.to_string_lossy().as_bytes()).expect("ssh config"),
        CString::new("-o").expect("-o flag"),
        CString::new("IdentitiesOnly=yes").expect("IdentitiesOnly"),
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
}
