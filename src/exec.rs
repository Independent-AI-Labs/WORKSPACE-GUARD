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
    args::ArgState, GuardError, ALLOWED_VARS, CHILD_PATH, CONTRACT_POLL_MS, CONTRACT_SCRIPT,
    CONTRACT_TIMEOUT_MS, CORE_LIMIT, ENFORCEMENT_CONFIG, GIT_ORIGINAL, NOFILE_LIMIT,
    WORKSPACE_MARKERS,
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

fn is_guard_binary(path: &Path) -> bool {
    let sentinel = b"workspace-guard";
    match fs::read(path) {
        Ok(bytes) => bytes.windows(sentinel.len()).any(|w| w == sentinel),
        Err(_) => false,
    }
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

pub fn execve_real_git(argv_os: &[OsString], state: Option<&ArgState>) -> Result<(), GuardError> {
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
            match waitpid(child_pid, None) {
                Ok(WaitStatus::Exited(_, code)) => {
                    #[cfg(feature = "capability-mode")]
                    {
                        crate::gitdir::lock();
                    }
                    std::process::exit(code);
                }
                Ok(WaitStatus::Signaled(_, sig, _)) => {
                    #[cfg(feature = "capability-mode")]
                    {
                        crate::gitdir::lock();
                    }
                    std::process::exit(128 + sig as i32);
                }
                _ => {
                    #[cfg(feature = "capability-mode")]
                    {
                        crate::gitdir::lock();
                    }
                    std::process::exit(1);
                }
            }
        }
    }
}

pub fn check_workspace_ci_contract(subcommand: &str) -> Result<(), GuardError> {
    let mut toplevel_cmd = std::process::Command::new("/usr/bin/git.original");
    toplevel_cmd
        .env_clear()
        .env("PATH", CHILD_PATH)
        .env("HOME", "/");
    crate::apply_safe_directory(&mut toplevel_cmd);
    let toplevel = match toplevel_cmd.args(["rev-parse", "--show-toplevel"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => return Ok(()),
    };

    let wsroot = find_workspace_root(&toplevel);
    let wsroot = match wsroot {
        Some(w) => w,
        None => return Ok(()),
    };

    if check_vendored_tier_bypass(&wsroot, &toplevel) {
        return Err(GuardError::ContractFailed(
            "Project tier is set to 'vendored' in project_enforcement.yaml: \
             quality gates are disabled. Restore 'strict' tier before committing."
                .into(),
        ));
    }

    let ci_script = format!("{}/{}", wsroot, CONTRACT_SCRIPT);
    if !Path::new(&ci_script).exists() {
        eprintln!(
            "WARNING: WORKSPACE-CI contract check script not found at {}",
            ci_script
        );
        return Ok(());
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
                eprintln!(
                    "WARNING: WORKSPACE-CI contract check timed out after {}ms: skipping",
                    timeout_ms
                );
                return Ok(());
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

fn check_vendored_tier_bypass(wsroot: &str, toplevel: &str) -> bool {
    let enforce_path = Path::new(wsroot).join(ENFORCEMENT_CONFIG);
    if !enforce_path.exists() {
        return false;
    }
    let content = match fs::read_to_string(&enforce_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let rel_path = match toplevel.strip_prefix(wsroot) {
        Some(stripped) => stripped.trim_start_matches('/'),
        None => toplevel,
    };

    let mut in_exemptions = false;
    let mut current_path: Option<String> = None;
    let mut current_tier: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "exemptions:" {
            in_exemptions = true;
            current_path = None;
            current_tier = None;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if in_exemptions && !trimmed.starts_with('-') && !trimmed.contains(':') {
            continue;
        }
        if in_exemptions
            && !trimmed.starts_with('-')
            && !trimmed.starts_with("path:")
            && !trimmed.starts_with("tier:")
            && !trimmed.starts_with("reason:")
        {
            in_exemptions = false;
            current_path = None;
            current_tier = None;
            continue;
        }
        if !in_exemptions {
            continue;
        }

        let entry_line = match trimmed.strip_prefix("- ") {
            Some(s) => s,
            None => trimmed,
        };

        if let Some(stripped) = entry_line.strip_prefix("tier:") {
            let val = stripped.trim();
            let val = val.trim_matches(|c| c == '"' || c == '\'');
            let val = val.split('#').next().unwrap_or(val).trim();
            current_tier = Some(val.to_lowercase());
        }
        if let Some(stripped) = entry_line.strip_prefix("path:") {
            current_path = Some(stripped.trim().to_string());
        }

        if current_path.is_some() && current_tier.is_some() {
            let path_val = current_path.as_deref().unwrap();
            if (rel_path.starts_with(path_val.trim_end_matches('/')) || path_val == rel_path)
                && current_tier.as_deref() == Some("vendored")
            {
                return true;
            }
            current_path = None;
            current_tier = None;
        }
    }

    if let (Some(path_val), Some(tier)) = (current_path.as_deref(), current_tier.as_deref()) {
        if (rel_path.starts_with(path_val.trim_end_matches('/')) || path_val == rel_path)
            && tier == "vendored"
        {
            return true;
        }
    }

    false
}

fn find_workspace_root(toplevel: &str) -> Option<String> {
    let mut cur = std::path::PathBuf::from(toplevel);
    loop {
        if WORKSPACE_MARKERS.iter().all(|m| cur.join(m).exists()) {
            return Some(cur.to_string_lossy().to_string());
        }
        if !cur.pop() {
            return None;
        }
    }
}

#[cfg(test)]
#[path = "exec_tests.rs"]
mod tests;
