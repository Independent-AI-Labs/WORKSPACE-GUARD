use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use nix::sys::resource::{setrlimit, Resource};
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{getuid, Pid, User};

use crate::{
    args::ArgState,
    remote::repo_targets_provisioned_host,
    wsroot::{classify_workspace_root, WorkspaceRoot},
    GuardError, ALLOWED_VARS, CHILD_PATH, CONTRACT_POLL_MS, CONTRACT_SCRIPT, CONTRACT_TIMEOUT_MS,
    CORE_LIMIT, GIT_ORIGINAL, NOFILE_LIMIT, WORKSPACE_MARKERS,
};

#[cfg(feature = "capability-mode")]
pub fn raise_ambient_caps() -> Result<(), GuardError> {
    // Raise all guard caps into the Inheritable set so forked children
    // can promote them into Ambient before exec. We do NOT raise
    // anything into Ambient here: the parent already has Effective caps
    // from the file's +ep flags and does not need Ambient. Keeping
    // Ambient empty ensures policy-check sub-calls (block.rs git_cmd)
    // that fork+exec git.original from the parent get NO caps.
    const INHERITABLE_CAPS: [caps::Capability; 5] = [
        caps::Capability::CAP_SETPCAP,
        caps::Capability::CAP_CHOWN,
        caps::Capability::CAP_DAC_OVERRIDE,
        caps::Capability::CAP_FOWNER,
        caps::Capability::CAP_FSETID,
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

fn resolve_safe_home() -> String {
    let uid = getuid();
    match User::from_uid(uid) {
        Ok(Some(user)) => {
            let s = user.dir.to_string_lossy().to_string();
            if !s.is_empty() {
                s
            } else {
                "/".to_string()
            }
        }
        _ => "/".to_string(),
    }
}

fn verify_git_original() -> Result<(), GuardError> {
    let path = Path::new("/usr/bin/git.original");
    match fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(GuardError::GitOriginalMissing);
            }
            if meta.st_uid() != 0 {
                return Err(GuardError::GitOriginalBadPerms);
            }
            if meta.st_mode() & 0o777 != 0o700 {
                return Err(GuardError::GitOriginalBadPerms);
            }
            if is_guard_binary(path) {
                eprintln!(
                    "FATAL: /usr/bin/git.original is the guard itself, not real git. \
                     Restore: apt install --reinstall git"
                );
                return Err(GuardError::GitOriginalMissing);
            }
            Ok(())
        }
        Err(_) => Err(GuardError::GitOriginalMissing),
    }
}

/// True when `path` IS the running guard binary itself: same device and
/// inode as /proc/self/exe. O(1) metadata comparison; the previous
/// implementation read the entire git.original binary into memory and
/// window-scanned it for a sentinel string on every git invocation.
fn is_guard_binary(path: &Path) -> bool {
    let target = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let self_meta = match fs::metadata("/proc/self/exe") {
        Ok(m) => m,
        Err(_) => return false,
    };
    target.st_dev() == self_meta.st_dev() && target.st_ino() == self_meta.st_ino()
}

fn collect_sudo_gated_env_warnings(sudo: bool) -> Vec<String> {
    let mut warnings = Vec::new();
    if sudo {
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

pub fn execve_real_git(
    argv_os: &[OsString],
    state: Option<&ArgState>,
    git_dir: Option<&Path>,
) -> Result<(), GuardError> {
    #[cfg(not(feature = "capability-mode"))]
    let _ = git_dir;
    let sudo = crate::is_sudo();
    if let Some(s) = state {
        if !s.dangerous_config_keys.is_empty() {
            return Err(GuardError::Blocked {
                reason: format!("dangerous -c config key: {}", s.dangerous_config_keys[0]),
                hint: "Remove the -c flag with the dangerous config key".into(),
            });
        }
    }

    verify_git_original()?;

    for msg in collect_sudo_gated_env_warnings(sudo) {
        crate::log::warn(&msg);
    }

    let git_path = CStr::from_bytes_with_nul(GIT_ORIGINAL.as_bytes())
        .map_err(|_| GuardError::GitOriginalMissing)?;

    let mut argv_c: Vec<CString> = Vec::new();
    argv_c.push(CString::new("/usr/bin/git.original").unwrap());

    for arg in argv_os.iter().skip(1) {
        let mut bytes = arg.as_bytes().to_vec();
        bytes.push(0);
        match CStr::from_bytes_with_nul(&bytes) {
            Ok(c) => argv_c.push(c.to_owned()),
            Err(_) => argv_c.push(CString::new("<binary-arg>").unwrap()),
        }
    }

    let mut envp: Vec<CString> = Vec::new();
    for &key in ALLOWED_VARS {
        if key == "HOME" {
            continue;
        }
        if let Some(val) = std::env::var_os(key) {
            let entry = format!("{}={}", key, val.to_string_lossy());
            if let Ok(c) = CString::new(entry) {
                envp.push(c);
            }
        }
    }

    let safe_home = resolve_safe_home();
    envp.push(CString::new(format!("HOME={}", safe_home)).unwrap());

    envp.push(CString::new(format!("PATH={}", CHILD_PATH)).unwrap());

    crate::agent_identity::push_agent_hardened_git_env(&mut envp, crate::is_config_privileged());

    if sudo {
        for &var in crate::SUDO_GATED_IDENTITY_ENV_VARS
            .iter()
            .chain(crate::SUDO_GATED_EDITOR_ENV_VARS.iter())
        {
            if let Some(val) = std::env::var_os(var) {
                let entry = format!("{}={}", var, val.to_string_lossy());
                if let Ok(c) = CString::new(entry) {
                    envp.push(c);
                }
            }
        }
    }

    let pid;
    #[cfg(feature = "capability-mode")]
    let mutating = state
        .and_then(|s| s.subcommand.as_deref())
        .map(crate::reconcile::is_mutating)
        .unwrap_or(false);
    // SAFETY: libc::fork is an irreducible async-signal-safe primitive with no
    // safe nix substitute that preserves the exact fork-without-atfork-handler
    // semantics the guard depends on. Any allocation or lock acquisition between
    // fork and exec would be a defect; the only calls in the child below are
    // raise_child_dac_override() (caps syscalls), nix::execve (execve(2)), and
    // libc::_exit, all async-signal-safe.
    unsafe {
        pid = libc::fork();
    }
    match pid {
        -1 => Err(GuardError::GitOriginalMissing),
        0 => {
            if raise_child_dac_override().is_err() {
                const MSG: &[u8] =
                    b"FATAL: failed to loan CAP_DAC_OVERRIDE to git.original; reinstall guard\n";
                // SAFETY: write(2) is async-signal-safe; used only in the post-fork
                // child before execve.
                unsafe {
                    libc::write(libc::STDERR_FILENO, MSG.as_ptr().cast(), MSG.len());
                    libc::_exit(2);
                }
            }
            let _ = nix::unistd::execve(git_path, &argv_c, &envp);
            // SAFETY: libc::_exit is the only async-signal-safe exit path;
            // std::process::exit and Drop runtimes are forbidden in the
            // post-fork child. nix has no _exit wrapper.
            unsafe {
                libc::_exit(3);
            }
        }
        _ => {
            let child_pid = Pid::from_raw(pid);
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
pub fn resolve_toplevel(argv_os: &[OsString], git_bin: &str) -> Option<String> {
    let mut cmd = std::process::Command::new(git_bin);
    cmd.env_clear().env("PATH", CHILD_PATH).env("HOME", "/");
    cmd.args(crate::args::repo_location_args(argv_os));
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
    argv_os: &[OsString],
) -> Result<(), GuardError> {
    // Fail closed: if the target repo cannot be resolved we cannot know
    // whether this commit/push is subject to the workspace contract, so
    // the safe default is to block. (git would reject the operation
    // outside a work tree anyway.)
    let toplevel = match resolve_toplevel(argv_os, "/usr/bin/git.original") {
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
        WorkspaceRoot::Partial(partial) => {
            return Err(GuardError::ContractFailed(format!(
                "workspace markers incomplete at {}: expected all of {:?}; \
                 failing closed (possible marker tampering)",
                partial, WORKSPACE_MARKERS
            )));
        }
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

    let ci_script = format!("{}/{}", wsroot, CONTRACT_SCRIPT);
    if !Path::new(&ci_script).exists() {
        return Err(GuardError::ContractFailed(format!(
            "WORKSPACE-CI contract check script not found at {}: \
             failing closed (contract cannot be verified)",
            ci_script
        )));
    }

    let child = std::process::Command::new("/bin/bash")
        .env_clear()
        .env("PATH", CHILD_PATH)
        .env("HOME", "/")
        .arg(&ci_script)
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
#[cfg(test)]
#[path = "exec_tests.rs"]
mod tests;
