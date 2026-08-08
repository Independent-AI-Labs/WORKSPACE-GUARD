//! Remote-URL inspection for the H4 fail-closed check: a repo that has
//! no workspace markers but points at a provisioned host is a workspace
//! clone living outside the gated tree and must not commit or push.

use crate::GIT_SSH_ALLOWED_HOSTS;

#[cfg(not(test))]
const REMOTE_GIT_BIN: &str = crate::GIT_ORIGINAL_PATH;
#[cfg(test)]
const REMOTE_GIT_BIN: &str = "git";

/// Host part of a git remote URL: scp-like `user@host:path` or
/// `scheme://[user@]host[:port]/path`.
pub fn remote_url_host(url: &str) -> Option<String> {
    let rest = match url.split_once("://") {
        Some((_, after)) => after,
        None => url,
    };
    let rest = rest.rsplit('@').next()?;
    if rest.is_empty() || rest.starts_with('/') {
        return None;
    }
    let host: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    Some(host)
}

fn remote_urls(toplevel: &str) -> Vec<String> {
    let mut cmd = std::process::Command::new(REMOTE_GIT_BIN);
    cmd.args([
        "-C",
        toplevel,
        "config",
        "--get-regexp",
        "^remote\\..*\\.url$",
    ]);
    crate::apply_safe_directory(&mut cmd);
    let out = match cmd.output() {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1).map(str::to_string))
        .collect()
}

/// True when any remote of the repo points at a provisioned SSH host
/// (config/git_ssh_allowlist.yaml): a workspace clone living outside the
/// workspace, which must not commit/push without the contract (H4).
///
/// Production builds cache the verdict per toplevel for the process
/// lifetime: the guard is a short-lived per-invocation process and this
/// check fires twice on the commit/push path (gitdir lock scope and the
/// exec contract check), each spawning `git config --get-regexp`.
/// Test builds bypass the cache because tests mutate repo config.
#[cfg(not(test))]
pub fn repo_targets_provisioned_host(toplevel: &str) -> bool {
    use std::cell::RefCell;
    use std::collections::HashMap;
    thread_local! {
        static CACHE: RefCell<HashMap<String, bool>> = RefCell::new(HashMap::new());
    }
    CACHE.with(|c| {
        if let Some(v) = c.borrow().get(toplevel) {
            return *v;
        }
        let v = repo_targets_provisioned_host_uncached(toplevel);
        c.borrow_mut().insert(toplevel.to_string(), v);
        v
    })
}

#[cfg(test)]
pub fn repo_targets_provisioned_host(toplevel: &str) -> bool {
    repo_targets_provisioned_host_uncached(toplevel)
}

fn repo_targets_provisioned_host_uncached(toplevel: &str) -> bool {
    remote_urls(toplevel)
        .iter()
        .filter_map(|u| remote_url_host(u))
        .any(|h| GIT_SSH_ALLOWED_HOSTS.contains(&h.as_str()))
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
