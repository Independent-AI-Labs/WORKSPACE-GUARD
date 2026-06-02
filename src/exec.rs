use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::{args::ArgState, GuardError, ALLOWED_VARS, GIT_ORIGINAL};

pub fn check_at_secure() -> Result<(), GuardError> {
    let at_secure = unsafe { libc::getauxval(libc::AT_SECURE) };
    if at_secure == 0 {
        return Err(GuardError::NotSuid);
    }
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

fn verify_git_original() -> Result<(), GuardError> {
    let path = Path::new("/usr/bin/git.original");
    if !path.exists() {
        return Err(GuardError::GitOriginalMissing);
    }

    match fs::metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(GuardError::GitOriginalBadPerms);
            }
            if meta.st_uid() != 0 {
                return Err(GuardError::GitOriginalBadPerms);
            }
            if meta.st_mode() & 0o777 != 0o700 {
                return Err(GuardError::GitOriginalBadPerms);
            }
            Ok(())
        }
        Err(_) => Err(GuardError::GitOriginalBadPerms),
    }
}

pub fn execve_real_git(argv_os: &[OsString], state: Option<&ArgState>) -> Result<(), GuardError> {
    verify_git_original()?;

    if let Some(s) = state {
        if !s.dangerous_config_keys.is_empty() {
            return Err(GuardError::Blocked {
                reason: format!("dangerous -c config key: {}", s.dangerous_config_keys[0]),
                hint: "Remove the -c flag with the dangerous config key".into(),
            });
        }
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
        if let Some(val) = std::env::var_os(key) {
            let entry = format!("{}={}", key, val.to_string_lossy());
            if let Ok(c) = CString::new(entry) {
                envp.push(c);
            }
        }
    }
    envp.push(CString::new("PATH=/usr/local/bin:/usr/bin:/bin").unwrap());

    envp.push(CString::new("GIT_CONFIG_COUNT=1").unwrap());
    envp.push(CString::new("GIT_CONFIG_KEY_0=safe.directory").unwrap());
    envp.push(CString::new("GIT_CONFIG_VALUE_0=*").unwrap());

    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    unsafe {
        libc::execve(git_path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
        libc::_exit(3);
    }
}

pub fn check_ami_ci_contract(subcommand: &str) -> Result<(), GuardError> {
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
            "Project tier is set to 'vendored' in project_enforcement.yaml — \
             quality gates are disabled. Restore 'strict' tier before committing."
                .into(),
        ));
    }

    let ci_script = format!("{}/projects/AMI-CI/lib/checks_quality.sh", wsroot);
    if !Path::new(&ci_script).exists() {
        eprintln!(
            "WARNING: AMI-CI contract check script not found at {}",
            ci_script
        );
        return Ok(());
    }

    let output = std::process::Command::new("bash")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/")
        .arg(&ci_script)
        .env("AMI_GGUARD_CMD", subcommand)
        .env("AMI_GGUARD_REPO_ROOT", &toplevel)
        .env("AMI_GGUARD_WORKSPACE_ROOT", &wsroot)
        .output()
        .map_err(|e| GuardError::ContractFailed(format!("Failed to run contract check: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GuardError::ContractFailed(format!(
            "AMI-CI contract violation:\n{}",
            stderr
        )));
    }

    Ok(())
}

fn check_vendored_tier_bypass(wsroot: &str, toplevel: &str) -> bool {
    let enforce_path = Path::new(wsroot).join("ami/config/project_enforcement.yaml");
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
            current_tier = Some(stripped.trim().to_lowercase());
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
        let ci = cur.join("projects/AMI-CI");
        let guard = cur.join("ami/scripts/utils/git-guard");
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
        let ami_config = dir.join("ami").join("config");
        std::fs::create_dir_all(&ami_config).unwrap();
        let mut f = std::fs::File::create(ami_config.join("project_enforcement.yaml")).unwrap();
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
  - path: projects/RUST-GUARD/
    tier: strict
    reason: "test"
"#;
        write_temp_enforcement(dir.path(), content);
        let wsroot = dir.path().to_string_lossy().to_string();
        let toplevel = format!("{}/projects/RUST-GUARD", wsroot);
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
  - path: projects/RUST-GUARD/
    tier: vendored
    reason: "test vendored bypass"
"#;
        write_temp_enforcement(dir.path(), content);
        let wsroot = dir.path().to_string_lossy().to_string();
        let toplevel = format!("{}/projects/RUST-GUARD", wsroot);
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
        let toplevel = format!("{}/projects/RUST-GUARD", wsroot);
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
  - path: projects/RUST-GUARD/
    tier: vendored
    reason: "test"
"#;
        write_temp_enforcement(dir.path(), content);
        let wsroot = dir.path().to_string_lossy().to_string();
        let toplevel = format!("{}/projects/RUST-GUARD/subdir", wsroot);
        assert!(check_vendored_tier_bypass(&wsroot, &toplevel));
    }
}
