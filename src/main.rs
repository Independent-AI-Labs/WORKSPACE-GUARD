use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::process;

mod args;
mod block;
mod exec;
mod log;

use log::block;

#[derive(Debug)]
pub enum GuardError {
    NotSuid,
    GitOriginalMissing,
    GitOriginalBadPerms,
    NullByteInArg,
    Blocked { reason: String, hint: String },
    ContractFailed(String),
}

const BLOCKED_SUBCOMMANDS: &[&str] = &[
    "reset", "checkout", "clean", "restore", "rm", "rebase", "gc", "prune",
];

pub const ALLOWED_VARS: &[&str] = &[
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "TERM",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "SSH_AUTH_SOCK",
    "GPG_TTY",
    "PINENTRY_USER_DATA",
    "GIT_PAGER",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "EMAIL",
    "EDITOR",
    "VISUAL",
    "SHELL",
    "PWD",
];

pub const DANGEROUS_CONFIG_KEYS: &[&str] = &[
    "core.hookspath",
    "core.sshcommand",
    "core.editor",
    "core.excludesfile",
    "protocol.allow",
    "protocol.ext.allow",
    "safe.directory",
    "core.gitproxy",
    "url.insteadof",
    "credential.helper",
    "http.proxy",
    "https.proxy",
];

pub const GIT_ORIGINAL: &str = "/usr/bin/git.original\0";
pub const LOG_FILE: &str = ".rust-guard.log";

fn main() {
    let result = run();

    match result {
        Ok(()) => {}
        Err(GuardError::Blocked { reason, hint }) => block(&reason, &hint),
        Err(GuardError::ContractFailed(msg)) => {
            eprintln!("{}", msg);
            process::exit(4);
        }
        Err(e) => {
            eprintln!("FATAL: {:?}", e);
            process::exit(2);
        }
    }
}

fn run() -> Result<(), GuardError> {
    exec::check_at_secure()?;
    exec::set_resource_limits();

    let argv_os: Vec<OsString> = std::env::args_os().collect();

    if argv_os.len() <= 1 {
        return exec::execve_real_git(&argv_os, None);
    }

    let argv: Vec<&[u8]> = argv_os.iter().map(|a| a.as_bytes()).collect();
    args::check_null_bytes(&argv)?;

    let state = args::parse_args(&argv)?;

    if let Some(ref sub) = state.subcommand {
        block::check_blocked(&state, sub, &argv_os)?;

        if sub == "commit" || sub == "push" {
            exec::check_ami_ci_contract(sub)?;
        }
    }

    exec::execve_real_git(&argv_os, Some(&state))
}
