// workspace-binary-guard: generic SUID/capability guard binary.
//
// One binary is built and copied to every contained path. At runtime the
// invoked basename (basename(argv[0])) selects a policy from the
// compile-time-baked BINARY_POLICIES table (see binary_policy_types.rs).
// The guard either rejects the invocation, sanitises the environment and
// execs the diverted real binary, or passes through.
//
// Build: cargo build --release --features binary-guard --bin workspace-binary-guard
// Install: see scripts/install-lock-runtime (copies this binary to <path>
// BEFORE dpkg-divert; the <path>.real target holds the original).

use std::env;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process;

use nix::unistd::{execve, getuid};

#[path = "binary_policy_types.rs"]
mod binary_policy_types;

use binary_policy_types::{find_policy, PolicyKind};

/// Exit codes. 126 = "found but not executable" (matches sh); we use it for
/// "blocked by policy". 127 = "not found" (matches sh); we use it for "no
/// policy for this basename" (fail-closed for binaries not in the catalog).
const EXIT_BLOCKED: i32 = 126;
const EXIT_NO_POLICY: i32 = 127;
const EXIT_INTERNAL: i32 = 70;

fn main() {
    let argv: Vec<OsString> = env::args_os().collect();
    let invoked_name = match argv.first() {
        Some(a) => Path::new(a)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        None => {
            log_block("?", "<no-argv0>", "no argv[0]");
            process::exit(EXIT_INTERNAL);
        }
    };

    let policy = match find_policy(&invoked_name) {
        Some(p) => p,
        None => {
            log_block(
                &invoked_name,
                "-",
                &format!("no policy for basename {:?}", invoked_name),
            );
            process::exit(EXIT_NO_POLICY);
        }
    };

    let argv_rest: Vec<OsString> = argv.iter().skip(1).cloned().collect();
    let is_root = getuid().is_root();
    let decision = decide(policy, &invoked_name, &argv_rest, is_root);

    match decision {
        Decision::Reject(reason) => {
            log_block(&invoked_name, "-", &reason);
            process::exit(EXIT_BLOCKED);
        }
        Decision::Allow {
            real_path,
            sanitized_env,
        } => {
            execve_real(&real_path, &argv, &sanitized_env);
        }
    }
}

#[derive(Debug)]
enum Decision {
    Reject(String),
    Allow {
        real_path: String,
        sanitized_env: Vec<(OsString, OsString)>,
    },
}

fn decide(
    policy: &binary_policy_types::BinaryPolicy,
    invoked_name: &str,
    argv_rest: &[OsString],
    is_root: bool,
) -> Decision {
    match policy.policy {
        PolicyKind::DenyAllNonRoot => {
            if is_root {
                let real = real_binary_path(invoked_name);
                let env = build_sanitized_env(policy, is_root);
                Decision::Allow {
                    real_path: real,
                    sanitized_env: env,
                }
            } else {
                Decision::Reject("deny-all-non-root: invocation blocked (not root)".into())
            }
        }
        PolicyKind::DenyNonRoot => {
            if is_root {
                let real = real_binary_path(invoked_name);
                let env = build_sanitized_env(policy, is_root);
                Decision::Allow {
                    real_path: real,
                    sanitized_env: env,
                }
            } else {
                Decision::Reject("deny-non-root: invocation blocked (not root)".into())
            }
        }
        PolicyKind::ArgValidate => {
            if let Some(reason) = check_arg_validate(policy, invoked_name, argv_rest, is_root) {
                return Decision::Reject(reason);
            }
            let real = real_binary_path(invoked_name);
            let env = build_sanitized_env(policy, is_root);
            Decision::Allow {
                real_path: real,
                sanitized_env: env,
            }
        }
        PolicyKind::PassThrough => {
            let real = real_binary_path(invoked_name);
            let env = build_sanitized_env(policy, is_root);
            Decision::Allow {
                real_path: real,
                sanitized_env: env,
            }
        }
    }
}

fn check_arg_validate(
    policy: &binary_policy_types::BinaryPolicy,
    invoked_name: &str,
    argv_rest: &[OsString],
    is_root: bool,
) -> Option<String> {
    if !is_root {
        return Some("arg-validate: invocation blocked (not root)".into());
    }
    let joined = join_argv(argv_rest);
    let subcommand = argv_rest
        .first()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();

    for rp in policy.reject_patterns {
        match rp.kind {
            binary_policy_types::RejectKind::Flag => {
                if let Some(flag) = rp.flag {
                    for a in argv_rest {
                        if a.to_string_lossy() == flag {
                            return Some(format!("reject flag {}: {}", flag, rp.reason));
                        }
                    }
                }
            }
            binary_policy_types::RejectKind::Regex => {
                if let Some(pat) = rp.pattern {
                    let subcommand_ok = rp
                        .subcommand
                        .map(|s| s == subcommand || s == invoked_name)
                        .unwrap_or(true);
                    if !subcommand_ok {
                        continue;
                    }
                    let flags_ok = if rp.requires_flags.is_empty() {
                        true
                    } else {
                        rp.requires_flags
                            .iter()
                            .all(|rf| argv_rest.iter().any(|a| a.to_string_lossy() == *rf))
                    };
                    if !flags_ok {
                        continue;
                    }
                    if let Ok(re) = regex::Regex::new(pat) {
                        if re.is_match(&joined) {
                            return Some(format!("reject regex {:?}: {}", pat, rp.reason));
                        }
                    }
                }
            }
        }
    }
    None
}

fn join_argv(argv_rest: &[OsString]) -> String {
    let mut s = String::new();
    for (i, a) in argv_rest.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&a.to_string_lossy());
    }
    s
}

fn real_binary_path(invoked_name: &str) -> String {
    let exe = env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| format!("/usr/bin/{}", invoked_name));
    let candidate = format!("{}.real", exe);
    if Path::new(&candidate).exists() {
        return candidate;
    }
    for dir in ["/usr/bin", "/usr/sbin", "/bin", "/sbin"] {
        let p = format!("{}/{}", dir, invoked_name);
        let real = format!("{}.real", p);
        if Path::new(&real).exists() {
            return real;
        }
        if Path::new(&p).exists() {
            return p;
        }
    }
    exe
}

fn build_sanitized_env(
    policy: &binary_policy_types::BinaryPolicy,
    _is_root: bool,
) -> Vec<(OsString, OsString)> {
    let mut out: Vec<(OsString, OsString)> = Vec::new();
    let strip_set: Vec<&'static str> = policy.env_sanitise.to_vec();
    for (k, v) in env::vars_os() {
        let key_str = k.to_string_lossy();
        if strip_set.iter().any(|s| *s == key_str) {
            continue;
        }
        out.push((k, v));
    }
    out
}

fn execve_real(real_path: &str, argv: &[OsString], env: &[(OsString, OsString)]) -> ! {
    let prog = match CString::new(real_path) {
        Ok(c) => c,
        Err(_) => {
            log_block("?", real_path, "CString::new failed on real_path");
            process::exit(EXIT_INTERNAL);
        }
    };
    let argv_c: Vec<CString> = argv
        .iter()
        .map(|a| CString::new(a.as_bytes()).unwrap_or_else(|_| CString::new("").unwrap()))
        .collect();
    let env_c: Vec<CString> = env
        .iter()
        .map(|(k, v)| {
            let mut buf = k.as_bytes().to_vec();
            buf.push(b'=');
            buf.extend_from_slice(v.as_bytes());
            CString::new(buf).unwrap_or_else(|_| CString::new("").unwrap())
        })
        .collect();
    match execve(&prog, &argv_c, &env_c) {
        Ok(inf) => match inf {},
        Err(errno) => {
            let err = std::io::Error::from_raw_os_error(errno as i32);
            log_block("?", real_path, &format!("execve failed: {}", err));
        }
    }
    process::exit(EXIT_INTERNAL);
}

fn log_block(invoked_name: &str, target: &str, reason: &str) {
    let line = format!(
        "BINARY-GUARD BLOCK name={:?} target={:?} reason={:?}\n",
        invoked_name, target, reason
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/workspace-guard.log")
    {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
    } else {
        eprint!("{}", line);
    }
}

#[cfg(test)]
#[path = "binary_guard_tests.rs"]
mod tests;
