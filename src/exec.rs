use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::{args::ArgState, GuardError, ALLOWED_VARS, GIT_ORIGINAL};

#[cfg(feature = "capability-mode")]
pub fn raise_ambient_caps() -> Result<(), GuardError> {
    caps::raise(
        None,
        caps::CapSet::Inheritable,
        caps::Capability::CAP_DAC_OVERRIDE,
    )
    .map_err(|_| GuardError::MissingCap)?;
    caps::raise(
        None,
        caps::CapSet::Ambient,
        caps::Capability::CAP_DAC_OVERRIDE,
    )
    .map_err(|_| GuardError::MissingCap)?;
    Ok(())
}

#[cfg(feature = "capability-mode")]
fn clear_child_caps() -> Result<(), GuardError> {
    caps::clear(None, caps::CapSet::Ambient).map_err(|_| GuardError::MissingCap)?;
    Ok(())
}

#[cfg(not(feature = "capability-mode"))]
#[allow(dead_code)]
pub fn raise_ambient_caps() -> Result<(), GuardError> {
    Ok(())
}

#[cfg(not(feature = "capability-mode"))]
fn clear_child_caps() -> Result<(), GuardError> {
    Ok(())
}

pub fn set_resource_limits() {
    unsafe {
        libc::setrlimit(
            libc::RLIMIT_NOFILE,
            &libc::rlimit {
                rlim_cur: 256,
                rlim_max: 256,
            },
        );
        libc::setrlimit(
            libc::RLIMIT_CORE,
            &libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            },
        );
    }
}

fn resolve_safe_home() -> String {
    let uid = unsafe { libc::getuid() };
    unsafe {
        let pwd = libc::getpwuid(uid);
        if !pwd.is_null() {
            let dir = (*pwd).pw_dir;
            if !dir.is_null() {
                if let Ok(s) = CStr::from_ptr(dir).to_str() {
                    if !s.is_empty() {
                        return s.to_string();
                    }
                }
            }
        }
    }
    "/".to_string()
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

    envp.push(CString::new("PATH=/usr/local/bin:/usr/bin:/bin").unwrap());

    envp.push(CString::new("GIT_CONFIG_COUNT=1").unwrap());
    envp.push(CString::new("GIT_CONFIG_KEY_0=safe.directory").unwrap());
    envp.push(CString::new("GIT_CONFIG_VALUE_0=*").unwrap());

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

    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(GuardError::GitOriginalMissing),
        0 => {
            let _ = clear_child_caps();
            unsafe {
                libc::execve(git_path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
                libc::_exit(3);
            }
        }
        _ => {
            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
            if libc::WIFEXITED(status) {
                std::process::exit(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                std::process::exit(128 + libc::WTERMSIG(status));
            }
            std::process::exit(1);
        }
    }
}

pub fn check_workspace_ci_contract(subcommand: &str) -> Result<(), GuardError> {
    let toplevel = match std::process::Command::new("/usr/bin/git.original")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "safe.directory")
        .env("GIT_CONFIG_VALUE_0", "*")
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
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

    let ci_script = format!("{}/projects/CI/lib/checks_quality.sh", wsroot);
    if !Path::new(&ci_script).exists() {
        eprintln!(
            "WARNING: WORKSPACE-CI contract check script not found at {}",
            ci_script
        );
        return Ok(());
    }

    let child = std::process::Command::new("/bin/bash")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/")
        .arg(&ci_script)
        .env("WORKSPACE_GGUARD_CMD", subcommand)
        .env("WORKSPACE_GGUARD_REPO_ROOT", &toplevel)
        .env("WORKSPACE_GGUARD_WORKSPACE_ROOT", &wsroot)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| GuardError::ContractFailed(format!("Failed to run contract check: {}", e)))?;

    let pid = child.id() as libc::pid_t;
    let mut stderr_pipe = child.stderr;

    let mut status: libc::c_int = 0;
    let timeout_ms = 2000;
    unsafe {
        let mut elapsed = 0;
        loop {
            let ret = libc::waitpid(pid, &mut status, libc::WNOHANG);
            if ret == pid {
                break;
            }
            if ret < 0 {
                break;
            }
            if elapsed >= timeout_ms {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
                eprintln!(
                    "WARNING: WORKSPACE-CI contract check timed out after {}ms: skipping",
                    timeout_ms
                );
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            elapsed += 50;
        }
    }

    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
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
    let enforce_path = Path::new(wsroot).join("workspace/config/project_enforcement.yaml");
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
        let boot = cur.join(".boot-linux");
        let ci = cur.join("projects/CI");
        let guard = cur.join("workspace/scripts/utils/git-guard");
        if boot.is_dir() && ci.is_dir() && guard.is_file() {
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
