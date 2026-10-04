use std::collections::HashMap;
use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use nix::fcntl::OFlag;
use nix::sys::resource::{setrlimit, Resource};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use crate::child_status::{
    read_child_status, ChildStatus, CHILD_SETUP_CAP_FAIL, CHILD_SETUP_EXEC_FAIL, CHILD_SETUP_EXIT,
};
use crate::{
    args::ArgState,
    remote::repo_targets_provisioned_host,
    wsroot::{classify_workspace_root, WorkspaceRoot},
    GuardError, CONTRACT_POLL_MS, CONTRACT_SCRIPT, CONTRACT_TIMEOUT_MS, CORE_LIMIT, GIT_ORIGINAL,
    NOFILE_LIMIT,
};

#[cfg(test)]
use crate::ALLOWED_VARS;

// Re-exported so callers keep one import site for the real-Git
// verification contract (REQ-GGUARD-006); the inode probe is test-only.
#[cfg(test)]
pub(crate) use crate::git_binary::is_guard_binary;
pub(crate) use crate::git_binary::verify_git_original;
#[cfg(feature = "capability-mode")]
pub fn raise_ambient_caps() -> Result<(), GuardError> {
    // Raise all guard caps into the Inheritable set so forked children
    // can promote them into Ambient before exec. We do NOT raise
    // anything into Ambient here: the parent already has Effective caps
    // from the file's +ep flags and does not need Ambient. Keeping
    // Ambient empty ensures policy-check sub-calls (block.rs git_cmd)
    // that fork+exec git.original from the parent get NO caps.
    const INHERITABLE_CAPS: [caps::Capability; 4] = [
        caps::Capability::CAP_SETPCAP,
        caps::Capability::CAP_CHOWN,
        caps::Capability::CAP_DAC_OVERRIDE,
        caps::Capability::CAP_FOWNER,
    ];
    for cap in INHERITABLE_CAPS.iter().copied() {
        caps::raise(None, caps::CapSet::Inheritable, cap).map_err(|_| GuardError::MissingCap)?;
    }
    Ok(())
}

/// Called in the child process after fork, just before execve(git.original).
/// Raises CAP_DAC_OVERRIDE into the child's Ambient set so that
/// git.original (a non-privileged binary with no file caps) inherits it
/// across exec and can write to root-owned .git/ files.
///
/// Requires CAP_SETPCAP in Effective (inherited from parent via fork)
/// and CAP_DAC_OVERRIDE in Inheritable+Permitted (also inherited).
#[cfg(feature = "capability-mode")]
fn raise_child_dac_override() -> Result<(), GuardError> {
    caps::clear(None, caps::CapSet::Ambient).map_err(|_| GuardError::MissingCap)?;
    caps::raise(
        None,
        caps::CapSet::Ambient,
        caps::Capability::CAP_DAC_OVERRIDE,
    )
    .map_err(|_| GuardError::MissingCap)
}

#[cfg(not(feature = "capability-mode"))]
#[allow(dead_code)]
pub fn raise_ambient_caps() -> Result<(), GuardError> {
    Ok(())
}

#[cfg(not(feature = "capability-mode"))]
fn raise_child_dac_override() -> Result<(), GuardError> {
    Ok(())
}

/// Post-exec policy reconcile (REQ-GGUARD-176, SPEC-GIT-GUARD section
/// 8). Runs only for mutating porcelains and only when a git dir was
/// resolved. Drift is fatal to the guard invocation (EX_IOERR 74):
/// the git result stands, the invariant does not. Root-only builds
/// pass no git dir, so reconcile stays inert there.
#[cfg(feature = "capability-mode")]
fn post_exec_reconcile(git_dir: Option<&Path>, mutating: bool, git_code: i32) {
    if !mutating {
        return;
    }
    let gd = match git_dir {
        Some(g) => g,
        None => return,
    };
    let drift = crate::reconcile::run(gd);
    if !drift.is_empty() {
        eprintln!(
            "FATAL: guard policy reconcile failed after git exited {}; \
             the git operation stands but the policy-file invariant is broken. \
             Repair via the operator relock path (see AGENTS.md):",
            git_code
        );
        for d in &drift {
            eprintln!("  {}", d);
        }
        std::process::exit(74);
    }
}

pub fn set_resource_limits() {
    let _ = setrlimit(Resource::RLIMIT_NOFILE, NOFILE_LIMIT, NOFILE_LIMIT);
    let _ = setrlimit(Resource::RLIMIT_CORE, CORE_LIMIT, CORE_LIMIT);
}

fn collect_sudo_gated_env_warnings(privileged: bool) -> Vec<String> {
    let mut warnings = Vec::new();
    if privileged {
        return warnings;
    }
    for &var in crate::SUDO_GATED_IDENTITY_ENV_VARS {
        if let Some(val) = std::env::var_os(var) {
            if !val.is_empty() {
                warnings.push(format!(
                    "[{}] NON-ROOT USER HAS SET CUSTOM GIT CONFIG COMMITTER DATA - IGNORING.",
                    var
                ));
            }
        }
    }
    for &var in crate::SUDO_GATED_EDITOR_ENV_VARS {
        if let Some(val) = std::env::var_os(var) {
            if !val.is_empty() {
                warnings.push(format!(
                    "[{}] NON-ROOT USER HAS SET CUSTOM GIT EDITOR - IGNORING.",
                    var
                ));
            }
        }
    }
    warnings
}

/// True when a caller-provided environment variable must not reach real Git.
/// Hook-bypass names are always dropped. For non-root callers the cataloged
/// identity and editor names are dropped too: the "IGNORING" warning in
/// `collect_sudo_gated_env_warnings` is only truthful if this filter actually
/// removes the variable, otherwise `GIT_AUTHOR_*`/`GIT_COMMITTER_*` override
/// the guard-injected identity and forge commit authorship.
fn should_drop_child_env(key: &str, privileged: bool) -> bool {
    // Caller-supplied guard-owned names are discarded before the one
    // canonical guard value is injected (REQ-GGUARD-070).
    key == crate::SESSION_ENV
        || crate::BLOCKED_BYPASS_VARS.contains(&key)
        || (!privileged
            && (crate::SUDO_GATED_IDENTITY_ENV_VARS.contains(&key)
                || crate::SUDO_GATED_EDITOR_ENV_VARS.contains(&key)))
}

/// True when this guard invocation is nested inside a guard-managed git
/// operation. Git exports `GIT_AUTHOR_*`/`GIT_EDITOR` into its own hooks, so a
/// nested call sees the guard's canonical identity, not a caller override.
/// Its evidence is written to the audit sink without echoing to stderr and
/// `/dev/tty`, which keeps one commit from flooding the caller on every
/// nested `git` invocation. Stripping and the evidence record are unchanged.
pub(crate) fn is_nested_session() -> bool {
    std::env::var_os(crate::SESSION_ENV).is_some_and(|v| v == "1")
}

/// Convert caller arguments into NUL-terminated C strings, preserving every
/// byte (including non-UTF-8) and the argument order.
///
/// An embedded NUL cannot cross `execve` at all, so it is a typed caller
/// error (exit 2) rather than a substituted or truncated argument. This is
/// the single owner of the argv-conversion invariant (REQ-GGUARD-014).
pub(crate) fn argv_to_cstrings(argv_os: &[OsString]) -> Result<Vec<CString>, GuardError> {
    argv_os
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            CString::new(arg.as_bytes()).map_err(|_| {
                GuardError::InvalidInvocation(format!(
                    "argv[{i}] contains an embedded NUL byte; refusing to invoke real git"
                ))
            })
        })
        .collect()
}

pub fn execve_real_git(
    argv_os: &[OsString],
    state: Option<&ArgState>,
    git_dir: Option<&Path>,
) -> Result<(), GuardError> {
    #[cfg(not(feature = "capability-mode"))]
    let _ = git_dir;
    #[cfg(not(feature = "capability-mode"))]
    let _ = state;
    // Dangerous `-c` config decisions happen in the engine (step 3,
    // sanitize::decide) before this point; argv arriving here is either
    // clean or the invocation was blocked (SPEC-GIT-GUARD section 4).
    // euid==0, not AT_SECURE: the kernel also sets AT_SECURE for
    // file-capability binaries run by non-root, so is_sudo() is true for
    // every agent git invocation. Gating the drop on AT_SECURE would keep
    // GIT_AUTHOR_*/GIT_COMMITTER_* and forge authorship (REQ-GGUARD-073).
    let privileged = crate::is_config_privileged();
    let nested = is_nested_session();

    verify_git_original()?;

    // REQ-GGUARD-021a: record every allowed root-privileged sudo-gated
    // operation before real git runs. Fail closed: a privileged destructive
    // operation must not proceed without its evidence.
    if let Some(sub) = state.and_then(|s| s.subcommand.as_deref()) {
        if crate::block::should_audit_allowed(sub, privileged) {
            let fields = crate::log::audit_argv_fields(sub, argv_os);
            crate::log::audit_allowed(&fields)
                .map_err(|e| GuardError::GuardUnavailable(format!("allow audit: {}", e)))?;
        }
    }

    for msg in collect_sudo_gated_env_warnings(privileged) {
        if nested {
            crate::log::warn_audit_only(&msg);
        } else {
            crate::log::warn(&msg);
        }
    }

    let git_path = CStr::from_bytes_with_nul(GIT_ORIGINAL.as_bytes())
        .map_err(|_| GuardError::GitOriginalMissing)?;

    // Real Git is invoked via the fixed pathname; argv[0] is replaced but
    // every other argument is forwarded byte-for-byte.
    let mut argv_c = argv_to_cstrings(argv_os)?;
    let fixed_argv0 = CString::new("/usr/bin/git.original").expect("static path has no NUL");
    match argv_c.first_mut() {
        Some(slot) => *slot = fixed_argv0,
        None => argv_c.push(fixed_argv0),
    }

    let mut env_map: HashMap<OsString, OsString> = std::env::vars_os()
        .filter(|(key, _)| !should_drop_child_env(&key.to_string_lossy(), privileged))
        .collect();

    let hardened = crate::agent_identity::hardened_git_env_pairs(privileged);
    for (key, value) in hardened {
        env_map.insert(OsString::from(key), OsString::from(value));
    }

    if privileged {
        for &var in crate::SUDO_GATED_IDENTITY_ENV_VARS
            .iter()
            .chain(crate::SUDO_GATED_EDITOR_ENV_VARS.iter())
        {
            if let Some(val) = std::env::var_os(var) {
                env_map.insert(OsString::from(var), val);
            }
        }
    }

    // One canonical guard-owned session value, after the caller's copy (if
    // any) was dropped above, so nested guard calls are distinguishable.
    env_map.insert(OsString::from(crate::SESSION_ENV), OsString::from("1"));

    let envp: Vec<CString> = env_map
        .into_iter()
        .filter_map(|(key, value)| {
            let mut entry = key.into_vec();
            entry.push(b'=');
            entry.extend_from_slice(&value.into_vec());
            CString::new(entry).ok()
        })
        .collect();

    #[cfg(feature = "capability-mode")]
    let mutating = state
        .and_then(|s| s.subcommand.as_deref())
        .map(crate::reconcile::is_mutating)
        .unwrap_or(false);
    // The child reports setup/exec failure over a close-on-exec pipe
    // (REQ-GGUARD-121): one fixed status byte on failure, EOF once execve
    // succeeds and the kernel closes the CLOEXEC write end. The child writes
    // no diagnostic text and picks no public exit code; the parent owns all
    // visible diagnostics and maps the typed status to a GuardError.
    let (status_read, status_write) = nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|_| {
        GuardError::GuardUnavailable("failed to create the child status pipe".to_string())
    })?;
    // Post-fork child work uses only async-signal-safe primitives: fork and
    // _exit come from linux_ffi; the fixed status write and execve go through
    // nix's safe API. Nothing in the child allocates, formats, locks, or
    // unwinds.
    match crate::linux_ffi::fork() {
        Err(_) => Err(GuardError::GitOriginalMissing),
        Ok(None) => {
            drop(status_read);
            if raise_child_dac_override().is_err() {
                let _ = nix::unistd::write(&status_write, &[CHILD_SETUP_CAP_FAIL]);
                crate::linux_ffi::exit_now(CHILD_SETUP_EXIT);
            }
            let _ = nix::unistd::execve(git_path, &argv_c, &envp);
            let _ = nix::unistd::write(&status_write, &[CHILD_SETUP_EXEC_FAIL]);
            crate::linux_ffi::exit_now(CHILD_SETUP_EXIT);
        }
        Ok(Some(pid)) => {
            drop(status_write);
            let child_pid = Pid::from_raw(pid);
            match read_child_status(&status_read) {
                ChildStatus::CapFailed => {
                    let _ = waitpid(child_pid, None);
                    return Err(GuardError::MissingCap);
                }
                ChildStatus::ExecFailed => {
                    let _ = waitpid(child_pid, None);
                    return Err(GuardError::GitOriginalMissing);
                }
                ChildStatus::Executed => {}
            }
            // Post-exec relock: reclaim files git.original created back to
            // root:root. Reuses the git dir resolved once in main.rs; when
            // no git dir was resolved (no subcommand, or not a repo) the
            // relock is skipped entirely instead of spawning a rev-parse.
            #[cfg(feature = "capability-mode")]
            let relock = |git_dir: Option<&Path>| {
                if let Some(gd) = git_dir {
                    crate::gitdir::lock(gd);
                }
            };
            let t = crate::trace_start("git.original exec+wait");
            let waited = waitpid(child_pid, None);
            crate::trace_end(t, "git.original exec+wait");
            match waited {
                Ok(WaitStatus::Exited(_, code)) => {
                    #[cfg(feature = "capability-mode")]
                    {
                        relock(git_dir);
                        post_exec_reconcile(git_dir, mutating, code);
                    }
                    std::process::exit(code);
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    #[cfg(feature = "capability-mode")]
                    {
                        relock(git_dir);
                        post_exec_reconcile(git_dir, mutating, 128 + sig as i32);
                    }
                    std::process::exit(128 + sig as i32);
                }
                _ => {
                    #[cfg(feature = "capability-mode")]
                    {
                        relock(git_dir);
                        post_exec_reconcile(git_dir, mutating, 1);
                    }
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Resolve the toplevel of the repo this invocation actually targets.
/// Mirrors exactly what the exec'd git.original will see: -C,
/// --git-dir/--work-tree argv pass through to it verbatim, so they are
/// honored here; GIT_DIR/GIT_WORK_TREE are NOT in ALLOWED_VARS and are
/// stripped by execve_real_git, so they must NOT be honored here (doing
/// so would re-open a dodge: env points the check at an innocent repo
/// while the real commit lands in the workspace repo).
/// The guard's own cwd is intentionally irrelevant, so running from a
/// directory outside any repo cannot dodge the contract check.
/// Bounded by a timeout so a wedged resolver can never stall a commit.
pub fn resolve_toplevel(location: &[OsString], git_bin: &str) -> Option<String> {
    let mut cmd = std::process::Command::new(git_bin);
    cmd.args(location);
    crate::apply_safe_directory(&mut cmd);
    cmd.args(["rev-parse", "--show-toplevel"]);
    match crate::child::run_with_timeout(&mut cmd, None, std::time::Duration::from_secs(20)) {
        Ok(o) if o.success() => {
            let t = o.stdout_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        }
        _ => None,
    }
}

pub fn check_workspace_ci_contract(
    subcommand: &str,
    location: &[OsString],
) -> Result<(), GuardError> {
    // Fail closed: if the target repo cannot be resolved we cannot know
    // whether this commit/push is subject to the workspace contract, so
    // the safe default is to block. (git would reject the operation
    // outside a work tree anyway.)
    let toplevel = match resolve_toplevel(location, "/usr/bin/git.original") {
        Some(t) => t,
        None => {
            return Err(GuardError::ContractFailed(format!(
                "could not resolve the target repository for '{subcommand}'; \
                 failing closed (cannot verify the workspace CI contract). \
                 Run inside a valid work tree."
            )))
        }
    };

    let wsroot = match classify_workspace_root(&toplevel) {
        WorkspaceRoot::Full(w) => w,
        WorkspaceRoot::None => {
            if repo_targets_provisioned_host(&toplevel) {
                return Err(GuardError::ContractFailed(format!(
                    "{} is a clone of a provisioned remote but sits outside the workspace: \
                     committing or pushing here bypasses every quality gate (H4). \
                     Work inside the workspace tree instead.",
                    toplevel
                )));
            }
            return Ok(());
        }
    };

    if crate::vendored::check_vendored_tier_bypass(&wsroot, &toplevel) {
        return Err(GuardError::ContractFailed(
            "Project tier is set to 'vendored' in project_enforcement.yaml: \
             quality gates are disabled. Restore 'strict' tier before committing."
                .into(),
        ));
    }

    crate::ci_integrity::check_ci_integrity(&toplevel, &wsroot)?;

    let ci_script = CONTRACT_SCRIPT;
    if !Path::new(ci_script).exists() {
        return Err(GuardError::ContractFailed(format!(
            "WORKSPACE-CI contract check script not found at {}: \
             failing closed (contract cannot be verified)",
            ci_script
        )));
    }

    let child = std::process::Command::new("/bin/bash")
        .arg(ci_script)
        .env("WORKSPACE_GGUARD_CMD", subcommand)
        .env("WORKSPACE_GGUARD_REPO_ROOT", &toplevel)
        .env("WORKSPACE_GGUARD_WORKSPACE_ROOT", &wsroot)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| GuardError::ContractFailed(format!("Failed to run contract check: {}", e)))?;

    let pid = Pid::from_raw(child.id() as i32);
    let mut stderr_pipe = child.stderr;

    let mut final_status: WaitStatus = WaitStatus::StillAlive;
    let timeout_ms = CONTRACT_TIMEOUT_MS;
    {
        let mut elapsed: u64 = 0;
        loop {
            match waitpid(Some(pid), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {}
                Ok(s) => {
                    final_status = s;
                    break;
                }
                Err(_) => break,
            }
            if elapsed >= timeout_ms {
                let _ = kill(pid, Some(Signal::SIGKILL));
                let _ = waitpid(Some(pid), None);
                return Err(GuardError::ContractFailed(format!(
                    "WORKSPACE-CI contract check timed out after {}ms: \
                     failing closed (contract cannot be verified)",
                    timeout_ms
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(CONTRACT_POLL_MS));
            elapsed += CONTRACT_POLL_MS;
        }
    }

    if let WaitStatus::Exited(_, 0) = final_status {
        return Ok(());
    }

    let stderr_msg = if let Some(mut pipe) = stderr_pipe.take() {
        use std::io::Read;
        let mut buf = String::new();
        let _ = pipe.read_to_string(&mut buf);
        buf
    } else {
        String::new()
    };

    Err(GuardError::ContractFailed(format!(
        "WORKSPACE-CI contract violation:\n{}",
        stderr_msg
    )))
}

/// True when `path` is a regular, non-symlink file owned by uid 0.
/// Runtime trust gate for files the guard honors but an agent could
/// otherwise rewrite (mirrors verify_git_original's ownership rule).
// Raw libc::fork/_exit test fixtures are confined to this one module and
// carry the same async-signal-safe contract as production (REQ-GGUARD-121).
#[cfg(test)]
#[allow(unsafe_code)]
#[path = "exec_tests.rs"]
mod tests;
