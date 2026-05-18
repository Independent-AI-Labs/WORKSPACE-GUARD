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
        let nofile = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 256,
        };
        libc::setrlimit(libc::RLIMIT_NOFILE, &nofile);

        let core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &core);
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

    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    // Drop privileges back to real user before execve so git.original runs
    // as the invoking user, not root. Prevents git's "dubious ownership"
    // fatal error when root accesses repos owned by other users.
    unsafe {
        let real_uid = libc::getuid();
        let real_gid = libc::getgid();
        libc::setgid(real_gid);
        libc::setuid(real_uid);
        libc::execve(git_path.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
        libc::_exit(3);
    }
}

pub fn check_ami_ci_contract(subcommand: &str) -> Result<(), GuardError> {
    let toplevel = match std::process::Command::new("git")
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

    let ci_script = format!("{}/projects/AMI-CI/lib/checks_quality.sh", wsroot);
    if !Path::new(&ci_script).exists() {
        eprintln!(
            "WARNING: AMI-CI contract check script not found at {}",
            ci_script
        );
        return Ok(());
    }

    let output = std::process::Command::new("bash")
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
