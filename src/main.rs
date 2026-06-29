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
    MissingCap,
    GitOriginalMissing,
    GitOriginalBadPerms,
    NullByteInArg,
    Blocked { reason: String, hint: String },
    ContractFailed(String),
}

const BLOCKED_SUBCOMMANDS: &[&str] = &[
    "reset",
    "checkout",
    "clean",
    "restore",
    "rebase",
    "gc",
    "prune",
    "bisect",
    "filter-branch",
    "filter-repo",
    "submodule",
    "worktree",
    "reflog",
    "replace",
    "lfs",
    "daemon",
    "fast-import",
];

const SUBCOMMANDS_WITH_PARTIAL_BLOCKS: &[&str] = &[
    "rm",
    "stash",
    "branch",
    "push",
    "commit",
    "revert",
    "pull",
    "merge",
    "tag",
    "cherry-pick",
    "apply",
    "am",
];

pub const ALLOWED_VARS: &[&str] = &[
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_COLLATE",
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
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "EMAIL",
    "SHELL",
    "PWD",
];

pub const DANGEROUS_CONFIG_KEYS: &[&str] = &[
    "core.hookspath",
    "core.sshcommand",
    "core.editor",
    "core.excludesfile",
    "core.pager",
    "core.askpass",
    "core.fsmonitor",
    "core.alternaterefscommand",
    "core.gitproxy",
    "diff.external",
    "gpg.program",
    "gpg.*.program",
    "protocol.allow",
    "protocol.*.allow",
    "safe.directory",
    "include.path",
    "includeif.**.path",
    "alias.*",
    "url.**.insteadof",
    "credential.helper",
    "credential.**.helper",
    "http.proxy",
    "https.proxy",
    "http.sslverify",
    "http.sslcainfo",
    "http.sslcert",
    "http.sslkey",
    "http.sslcertpasswordprotected",
    "http.extraheader",
    "http.cookiefile",
    "filter.*.clean",
    "filter.*.smudge",
    "diff.*.textconv",
    "diff.*.cachetextconv",
    "difftool.*.cmd",
    "mergetool.*.cmd",
    "mergetool.*.trustexitcode",
    "browser.*.cmd",
    "remote.*.proxy",
    "remote.*.promisor",
    "remote.*.uploadpack",
    "remote.*.receivepack",
    "submodule.*.url",
    "submodule.*.update",
    "submodule.recurse",
    "commit.gpgsign",
    "commit.template",
    "commit.cleanup",
    "rebase.autosquash",
    "rebase.autostash",
    "rebase.instructionFormat",
    "receive.denyCurrentBranch",
    "receive.denyNonFastForwards",
    "receive.denyDeletes",
    "receive.hideRefs",
    "uploadpack.hideRefs",
    "uploadpack.allowReachableSHA1InWant",
    "uploadpack.allowAnySHA1InWant",
    "fetch.fsckObjects",
    "transfer.fsckObjects",
    "receive.fsckObjects",
    "fetch.prune",
    "clone.rejectShallow",
    "push.default",
    "push.followTags",
    "push.gpgSign",
    "merge.ff",
    "merge.verifySignatures",
    "pull.ff",
    "pull.rebase",
    "user.email",
    "user.name",
    "user.signingkey",
    "format.signoff",
    "sequence.editor",
    "sendemail.smtpserver",
    "help.autocorrect",
];

pub fn is_dangerous_config_key(key: &str) -> bool {
    let key_lower = key.trim().to_lowercase();
    let segments: Vec<&str> = key_lower.split('.').collect();

    for &pattern in DANGEROUS_CONFIG_KEYS {
        let pat_segs: Vec<&str> = pattern.split('.').collect();
        if glob_match_segments(&segments, &pat_segs) {
            return true;
        }
    }

    false
}

fn glob_match_segments(segs: &[&str], pats: &[&str]) -> bool {
    let n = segs.len();
    let m = pats.len();
    let mut dp = vec![vec![false; m + 1]; n + 1];
    dp[0][0] = true;

    for j in 0..m {
        if pats[j] == "**" && dp[0][j] {
            dp[0][j + 1] = true;
        }
    }

    for i in 0..n {
        for j in 0..m {
            if pats[j] == "**" {
                dp[i + 1][j + 1] = dp[i + 1][j] || dp[i][j + 1];
            } else if pats[j] == "*" || segs[i] == pats[j].to_lowercase().as_str() {
                dp[i + 1][j + 1] = dp[i][j];
            }
        }
    }

    dp[n][m]
}

pub const GIT_ORIGINAL: &str = "/usr/bin/git.original\0";
pub const GIT_ORIGINAL_PATH: &str = "/usr/bin/git.original";
pub const LOG_FILE: &str = ".workspace-guard.log";

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
                "FATAL: missing CAP_DAC_OVERRIDE — guard must be installed with file capabilities"
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
        "[workspace-guard] WARNING: running in root-only mode (soft barrier). \
         Direct execution of /usr/bin/git.original bypasses this guard. \
         See docs/ROOT-ONLY-MODE.md for threat model and limitations."
    );
    Ok(())
}

#[cfg(not(feature = "root-only"))]
fn check_privileges() -> Result<(), GuardError> {
    if !caps::has_cap(
        None,
        caps::CapSet::Effective,
        caps::Capability::CAP_DAC_OVERRIDE,
    )
    .unwrap_or(false)
    {
        return Err(GuardError::MissingCap);
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

        if sub == "commit" || sub == "push" || sub == "cherry-pick" || sub == "apply" || sub == "am"
        {
            exec::check_workspace_ci_contract(sub)?;
        }
    }

    exec::execve_real_git(argv_os, Some(&state))
}

#[cfg(test)]
mod tests {
    use super::is_dangerous_config_key;

    #[test]
    fn exact_match_lowercase() {
        assert!(is_dangerous_config_key("core.hookspath"));
    }

    #[test]
    fn exact_match_case_insensitive() {
        assert!(is_dangerous_config_key("core.HooksPath"));
        assert!(is_dangerous_config_key("CORE.HOOKSPATH"));
    }

    #[test]
    fn exact_match_not_dangerous() {
        assert!(!is_dangerous_config_key("core.safepath"));
        assert!(!is_dangerous_config_key("user.signingkey2"));
    }

    #[test]
    fn wildcard_single_segment_filter_clean() {
        assert!(is_dangerous_config_key("filter.lfs.clean"));
        assert!(is_dangerous_config_key("filter.myfilter.clean"));
    }

    #[test]
    fn wildcard_single_segment_filter_smudge() {
        assert!(is_dangerous_config_key("filter.lfs.smudge"));
        assert!(is_dangerous_config_key("filter.anyname.smudge"));
    }

    #[test]
    fn wildcard_single_segment_alias() {
        assert!(is_dangerous_config_key("alias.push"));
        assert!(is_dangerous_config_key("alias.commit"));
        assert!(is_dangerous_config_key("alias.x"));
    }

    #[test]
    fn wildcard_single_segment_protocol_allow() {
        assert!(is_dangerous_config_key("protocol.file.allow"));
        assert!(is_dangerous_config_key("protocol.git.allow"));
        assert!(is_dangerous_config_key("protocol.ext.allow"));
    }

    #[test]
    fn wildcard_single_segment_url_insteadof() {
        assert!(is_dangerous_config_key("url.https://evil.com.insteadof"));
        assert!(is_dangerous_config_key("url.ssh://evil.insteadof"));
    }

    #[test]
    fn wildcard_single_segment_credential_helper() {
        assert!(is_dangerous_config_key("credential.helper"));
        assert!(is_dangerous_config_key(
            "credential.https://evil.com.helper"
        ));
    }

    #[test]
    fn wildcard_single_segment_gpg_program() {
        assert!(is_dangerous_config_key("gpg.program"));
        assert!(is_dangerous_config_key("gpg.ssh.program"));
        assert!(is_dangerous_config_key("gpg.openpgp.program"));
    }

    #[test]
    fn wildcard_segment_count_mismatch() {
        assert!(!is_dangerous_config_key("filter.clean"));
        assert!(!is_dangerous_config_key("alias"));
        assert!(!is_dangerous_config_key("protocol.allow.extra"));
    }

    #[test]
    fn trim_whitespace() {
        assert!(is_dangerous_config_key(" core.hookspath "));
        assert!(is_dangerous_config_key("\tcore.editor\t"));
    }

    #[test]
    fn exact_match_without_wildcard_differing_segment() {
        assert!(!is_dangerous_config_key("filter.xyz.other"));
    }

    #[test]
    fn all_dangerous_keys_covered() {
        let test_keys = &[
            ("core.hookspath", true),
            ("core.sshcommand", true),
            ("core.editor", true),
            ("core.excludesfile", true),
            ("core.pager", true),
            ("core.askpass", true),
            ("core.fsmonitor", true),
            ("core.alternaterefscommand", true),
            ("core.gitproxy", true),
            ("diff.external", true),
            ("gpg.program", true),
            ("gpg.ssh.program", true),
            ("protocol.allow", true),
            ("protocol.ext.allow", true),
            ("protocol.file.allow", true),
            ("safe.directory", true),
            ("include.path", true),
            ("includeif.gitdir.path", true),
            ("alias.st", true),
            ("url.https://evil.insteadof", true),
            ("credential.helper", true),
            ("credential.https://foo.helper", true),
            ("http.proxy", true),
            ("https.proxy", true),
            ("http.sslverify", true),
            ("http.sslcainfo", true),
            ("http.sslcert", true),
            ("http.sslkey", true),
            ("http.sslcertpasswordprotected", true),
            ("http.extraheader", true),
            ("http.cookiefile", true),
            ("filter.lfs.clean", true),
            ("filter.lfs.smudge", true),
            ("diff.binary.textconv", true),
            ("diff.binary.cachetextconv", true),
            ("difftool.vimdiff.cmd", true),
            ("mergetool.vimdiff.cmd", true),
            ("mergetool.vimdiff.trustexitcode", true),
            ("browser.firefox.cmd", true),
            ("remote.origin.proxy", true),
            ("remote.origin.promisor", true),
            ("remote.origin.uploadpack", true),
            ("remote.origin.receivepack", true),
            ("submodule.mylib.url", true),
            ("submodule.mylib.update", true),
            ("submodule.recurse", true),
            ("commit.gpgsign", true),
            ("commit.template", true),
            ("commit.cleanup", true),
            ("rebase.autosquash", true),
            ("rebase.autostash", true),
            ("rebase.instructionformat", true),
            ("receive.denycurrentbranch", true),
            ("receive.denynonfastforwards", true),
            ("receive.denydeletes", true),
            ("receive.hiderefs", true),
            ("uploadpack.hiderefs", true),
            ("uploadpack.allowreachablesha1inwant", true),
            ("uploadpack.allowanysha1inwant", true),
            ("fetch.fsckobjects", true),
            ("transfer.fsckobjects", true),
            ("receive.fsckobjects", true),
            ("fetch.prune", true),
            ("clone.rejectshallow", true),
            ("push.default", true),
            ("push.followtags", true),
            ("push.gpgsign", true),
            ("merge.ff", true),
            ("merge.verifysignatures", true),
            ("pull.ff", true),
            ("pull.rebase", true),
            ("user.email", true),
            ("user.name", true),
            ("user.signingkey", true),
            ("format.signoff", true),
            ("sequence.editor", true),
            ("sendemail.smtpserver", true),
            ("help.autocorrect", true),
            ("safe.config", false),
        ];

        for (key, expected) in test_keys {
            assert_eq!(
                is_dangerous_config_key(key),
                *expected,
                "key='{}' expected={}",
                key,
                expected
            );
        }
    }
}
