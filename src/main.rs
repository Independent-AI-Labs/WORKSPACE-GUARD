use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::process;

mod args;
mod block;
mod config_keys;
mod exec;
#[cfg(feature = "capability-mode")]
mod gitdir;

#[cfg(not(feature = "capability-mode"))]
mod gitdir {
    #[allow(dead_code)]
    pub fn lock() {}
    pub fn hardened_git_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_SYSTEM", "/dev/null"),
            ("GIT_CONFIG_COUNT", "3"),
            ("GIT_CONFIG_KEY_0", "safe.directory"),
            ("GIT_CONFIG_VALUE_0", "*"),
            ("GIT_CONFIG_KEY_1", "core.fsmonitor"),
            ("GIT_CONFIG_VALUE_1", ""),
            ("GIT_CONFIG_KEY_2", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_2", ""),
        ]
    }
}
mod log;

pub use config_keys::{is_config_key_blocked, is_dangerous_config_key};

use log::block;

#[derive(Debug)]
pub enum GuardError {
    MissingCap,
    GitOriginalMissing,
    GitOriginalBadPerms,
    NullByteInArg,
    Blocked { reason: String, hint: String },
    ContractFailed(String),
}

mod guard_config {
    include!(concat!(env!("OUT_DIR"), "/guard_config.rs"));
}

pub use guard_config::*;

pub fn is_sudo() -> bool {
    unsafe { libc::getuid() == 0 }
}

pub const GIT_ORIGINAL: &str = "/usr/bin/git.original\0";
pub const GIT_ORIGINAL_PATH: &str = "/usr/bin/git.original";

pub fn apply_safe_directory(cmd: &mut std::process::Command) {
    cmd.env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "safe.directory")
        .env("GIT_CONFIG_VALUE_0", "*");
}

pub fn push_safe_directory_env(envp: &mut Vec<std::ffi::CString>) {
    envp.push(std::ffi::CString::new("GIT_CONFIG_COUNT=1").unwrap());
    envp.push(std::ffi::CString::new("GIT_CONFIG_KEY_0=safe.directory").unwrap());
    envp.push(std::ffi::CString::new("GIT_CONFIG_VALUE_0=*").unwrap());
}

fn main() {
    let argv_os: Vec<OsString> = std::env::args_os().collect();
    let cmd_str: String = argv_os
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");

    let result = run(&argv_os);

    match result {
        Ok(()) => {}
        Err(GuardError::Blocked { reason, hint }) => block(&reason, &hint, &cmd_str),
        Err(GuardError::ContractFailed(msg)) => {
            eprintln!("{}", msg);
            process::exit(4);
        }
        Err(GuardError::MissingCap) => {
            eprintln!(
                "FATAL: missing file capabilities (needs \
                 cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid+ep): \
                 reinstall guard"
            );
            process::exit(2);
        }
        Err(e) => {
            eprintln!("FATAL: {:?}", e);
            process::exit(2);
        }
    }
}

#[cfg(feature = "root-only")]
fn check_privileges() -> Result<(), GuardError> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!(
            "FATAL: root-only mode requires euid 0 (got {}). \
             Build without --features root-only for capability-based mode.",
            euid
        );
        process::exit(2);
    }
    eprintln!(
        "[workspace-guard] running in root-only mode (soft barrier). \
         See docs/ROOT-ONLY-MODE.md for threat model and limitations."
    );
    Ok(())
}

#[cfg(not(feature = "root-only"))]
fn check_privileges() -> Result<(), GuardError> {
    const REQUIRED_CAPS: [caps::Capability; 5] = [
        caps::Capability::CAP_SETPCAP,
        caps::Capability::CAP_CHOWN,
        caps::Capability::CAP_DAC_OVERRIDE,
        caps::Capability::CAP_FOWNER,
        caps::Capability::CAP_FSETID,
    ];
    for cap in REQUIRED_CAPS.iter().copied() {
        if !caps::has_cap(None, caps::CapSet::Effective, cap).unwrap_or(false) {
            return Err(GuardError::MissingCap);
        }
    }
    exec::raise_ambient_caps()?;
    Ok(())
}

fn run(argv_os: &[OsString]) -> Result<(), GuardError> {
    check_privileges()?;
    exec::set_resource_limits();

    if argv_os.len() <= 1 {
        return exec::execve_real_git(argv_os, None);
    }

    let argv: Vec<&[u8]> = argv_os.iter().map(|a| a.as_bytes()).collect();
    args::check_null_bytes(&argv)?;

    let state = args::parse_args(&argv)?;

    if let Some(ref sub) = state.subcommand {
        block::check_blocked(&state, sub, argv_os, crate::GIT_ORIGINAL_PATH, None)?;

        // Capability-mode ownership lock: claim all paths declared in
        // config/guard_locked_paths.yaml (e.g. .git/, .gitmodules,
        // *_exceptions.yaml) as root:root before any further git.original
        // subprocess can fire a payload planted inside them.
        // Best-effort; never blocks a pass.
        // Root-only builds are no-ops (user is already root).
        #[cfg(feature = "capability-mode")]
        gitdir::lock();

        if CONTRACT_CHECK_SUBCOMMANDS.contains(&sub.as_str()) {
            exec::check_workspace_ci_contract(sub)?;
        }
    }

    exec::execve_real_git(argv_os, Some(&state))
}
