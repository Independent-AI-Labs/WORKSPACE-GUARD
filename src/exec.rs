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
            Ok(())
        }
        Err(_) => Err(GuardError::GitOriginalMissing),
    }
}

pub fn execve_real_git(argv_os: &[OsString], state: Option<&ArgState>) -> Result<(), GuardError> {
    if let Some(s) = state {
        if !s.dangerous_config_keys.is_empty() {
            return Err(GuardError::Blocked {
                reason: format!("dangerous -c config key: {}", s.dangerous_config_keys[0]),
                hint: "Remove the -c flag with the dangerous config key".into(),
            });
        }
    }

    verify_git_original()?;

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
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_enforcement(dir: &std::path::Path, content: &str) {
        let ws_config = dir.join("workspace").join("config");
        std::fs::create_dir_all(&ws_config).unwrap();
        let mut f = std::fs::File::create(ws_config.join("project_enforcement.yaml")).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    #[test]
    fn vendored_tier_not_bypassed_for_safe_tier() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
version: 1
defaults:
  tier: strict
exemptions:
  - path: projects/WORKSPACE-GUARD/
    tier: strict
    reason: "test"
"#;
        write_temp_enforcement(dir.path(), content);
        let wsroot = dir.path().to_string_lossy().to_string();
        let toplevel = format!("{}/projects/WORKSPACE-GUARD", wsroot);
        assert!(!check_vendored_tier_bypass(&wsroot, &toplevel));
    }

    #[test]
    fn vendored_tier_bypass_detected() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
version: 1
defaults:
  tier: strict
exemptions:
  - path: projects/WORKSPACE-GUARD/
    tier: vendored
    reason: "test vendored bypass"
"#;
        write_temp_enforcement(dir.path(), content);
        let wsroot = dir.path().to_string_lossy().to_string();
        let toplevel = format!("{}/projects/WORKSPACE-GUARD", wsroot);
        assert!(check_vendored_tier_bypass(&wsroot, &toplevel));
    }

    #[test]
    fn vendored_tier_no_exemptions() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
version: 1
defaults:
  tier: strict
"#;
        write_temp_enforcement(dir.path(), content);
        let wsroot = dir.path().to_string_lossy().to_string();
        let toplevel = format!("{}/projects/other", wsroot);
        assert!(!check_vendored_tier_bypass(&wsroot, &toplevel));
    }

    #[test]
    fn vendored_tier_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let wsroot = dir.path().to_string_lossy().to_string();
        let toplevel = format!("{}/projects/WORKSPACE-GUARD", wsroot);
        assert!(!check_vendored_tier_bypass(&wsroot, &toplevel));
    }

    #[test]
    fn vendored_tier_path_prefix_match() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
version: 1
defaults:
  tier: strict
exemptions:
  - path: projects/WORKSPACE-GUARD/
    tier: vendored
    reason: "test"
"#;
        write_temp_enforcement(dir.path(), content);
        let wsroot = dir.path().to_string_lossy().to_string();
        let toplevel = format!("{}/projects/WORKSPACE-GUARD/subdir", wsroot);
        assert!(check_vendored_tier_bypass(&wsroot, &toplevel));
    }

    #[test]
    fn clear_child_caps_succeeds() {
        assert!(clear_child_caps().is_ok());
    }

    #[cfg(feature = "capability-mode")]
    #[test]
    fn raise_ambient_caps_returns_error_without_file_caps() {
        let result = raise_ambient_caps();
        assert!(result.is_err());
    }

    #[test]
    fn verify_git_original_returns_error_when_missing() {
        if std::path::Path::new("/usr/bin/git.original").exists() {
            return;
        }
        assert!(verify_git_original().is_err());
    }

    #[test]
    fn fork_child_clears_and_exits() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork should succeed");
        if pid == 0 {
            let _ = clear_child_caps();
            std::process::exit(0);
        } else {
            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}
