use std::ffi::OsString;
#[cfg(all(target_os = "linux", not(feature = "root-only")))]
use std::os::linux::fs::MetadataExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process;

use nix::unistd::geteuid;

mod agent_identity;
mod args;
mod block;
mod child;
mod ci_integrity;
mod config_keys;
mod exec;
mod fetch;
#[cfg(feature = "capability-mode")]
mod gitdir;
#[cfg(feature = "capability-mode")]
mod reconcile;
mod remote;
mod sanitize;
#[cfg(feature = "capability-mode")]
mod sealed_repo;
mod vendored;
mod wsroot;

#[cfg(not(feature = "capability-mode"))]
mod gitdir {
    #[allow(dead_code)]
    pub fn lock() {}
}
mod log;

pub use config_keys::{is_config_key_blocked, is_dangerous_config_key};

use log::block;

#[derive(Debug)]
pub enum GuardError {
    MissingCap,
    MissingCapabilities(String),
    GitOriginalMissing,
    GitOriginalBadPerms,
    NullByteInArg,
    Blocked {
        reason: String,
        hint: String,
    },
    ContractFailed(String),
    /// The guard cannot deliver a sanitize report or persist its audit
    /// record; real git must not run (REQ-GGUARD-045, exit 3).
    GuardUnavailable(String),
}

mod guard_config {
    include!(concat!(env!("OUT_DIR"), "/guard_config.rs"));
}

pub use guard_config::*;

/// Returns true when the guard is executing in secure-execution mode, i.e. the
/// kernel set the AT_SECURE auxv flag at exec time. This is the correct SUID
/// detection primitive: AT_SECURE is non-zero whenever euid != ruid OR
/// egid != rgid at exec (set-user-ID or set-group-ID binary), and zero
/// otherwise (plain non-SUID exec, whether elevated or not). The prior
/// `getuid() == 0` heuristic was incorrect: it conflated "running as root"
/// with "running in SUID context", and returned the wrong answer whenever
/// root invoked the guard directly or a non-root user ran a non-SUID guard.
///
/// The application code uses `is_sudo()` to gate behaviour that must only
/// fire in the SUID scenario (e.g. removing real-euid disparities, denying
/// sudo-only config keys). It MUST NOT fire just because euid==0.
pub fn is_sudo() -> bool {
    aux_secure() != 0
}

/// Whether sudo-gated git config keys (`user.email`, `user.name`, …) may be
/// set. Requires effective root (`sudo git config`); file-capability
/// AT_SECURE alone is not sufficient in capability mode.
pub fn is_config_privileged() -> bool {
    geteuid().as_raw() == 0
}

/// Read the AT_SECURE auxv flag set by the kernel at exec(2). No `nix`
/// wrapper exists for `getauxval` as of nix 0.29, so this is an irreducible
/// unsafe FFI call.
// SAFETY: getauxval(3) is a libc function that reads the process auxiliary
// vector, a kernel-populated in-memory array available at process start.
// The argument AT_SECURE is a libc integer constant naming a well-known
// key. The kernel guarantees the auxv is initialised before user code runs
// and never mutated thereafter. The function returns an unsigned long with
// no nullability pitfalls. This is the only correct secure-execution
// detection primitive; the dynamic linker uses the same call internally.
fn aux_secure() -> usize {
    unsafe { libc::getauxval(libc::AT_SECURE) as usize }
}

pub const GIT_ORIGINAL: &str = "/usr/bin/git.original\0";
pub const GIT_ORIGINAL_PATH: &str = "/usr/bin/git.original";

pub fn apply_safe_directory(cmd: &mut std::process::Command) {
    agent_identity::apply_agent_hardened_git_env(cmd, false);
}

pub fn push_safe_directory_env(envp: &mut Vec<std::ffi::CString>) {
    envp.push(std::ffi::CString::new("GIT_CONFIG_COUNT=1").unwrap());
    envp.push(std::ffi::CString::new("GIT_CONFIG_KEY_0=safe.directory").unwrap());
    envp.push(std::ffi::CString::new("GIT_CONFIG_VALUE_0=*").unwrap());
}

fn main() {
    let argv_os: Vec<OsString> = std::env::args_os().collect();
    // cmd_str is built lazily: it is only used on the block/error paths,
    // so the join must not run on every allowed git invocation.
    let cmd_str = || {
        argv_os
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    };

    let result = run(&argv_os);

    match result {
        Ok(()) => {}
        Err(GuardError::Blocked { reason, hint }) => block(&reason, &hint, &cmd_str()),
        Err(GuardError::ContractFailed(msg)) => {
            eprintln!("{}", msg);
            process::exit(4);
        }
        Err(GuardError::GuardUnavailable(msg)) => {
            eprintln!("FATAL: {}", msg);
            process::exit(3);
        }
        Err(GuardError::MissingCap) => {
            eprintln!(
                "FATAL: missing workload capabilities (needs \
                 cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid); \
                 run make install-guard-host-exec"
            );
            process::exit(2);
        }
        Err(GuardError::MissingCapabilities(msg)) => {
            eprintln!("{msg}");
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
    let euid = geteuid();
    if euid != nix::unistd::Uid::from_raw(0) {
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
const REQUIRED_WORKLOAD_CAPS: [caps::Capability; 5] = [
    caps::Capability::CAP_SETPCAP,
    caps::Capability::CAP_CHOWN,
    caps::Capability::CAP_DAC_OVERRIDE,
    caps::Capability::CAP_FOWNER,
    caps::Capability::CAP_FSETID,
];

#[cfg(not(feature = "root-only"))]
fn no_new_privs_enabled() -> bool {
    const PR_GET_NO_NEW_PRIVS: libc::c_int = 39;
    unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 }
}

#[cfg(not(feature = "root-only"))]
const DEPLOYMENT_CLASS_FILE: &str = "/usr/lib/workspace-guard/deployment-class";

#[cfg(not(feature = "root-only"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentClass {
    HostExec,
    SandboxService,
    Unknown,
}

#[cfg(not(feature = "root-only"))]
fn read_deployment_class() -> DeploymentClass {
    // Fail closed unless the file is a regular root-owned file: an
    // agent-writable deployment-class would let the workload pick its
    // own class.
    let trusted = std::fs::symlink_metadata(DEPLOYMENT_CLASS_FILE)
        .map(|m| m.is_file() && m.st_uid() == 0)
        .unwrap_or(false);
    if !trusted {
        return DeploymentClass::Unknown;
    }
    let raw = std::fs::read_to_string(DEPLOYMENT_CLASS_FILE)
        .unwrap_or_default()
        .trim()
        .to_string();
    match raw.as_str() {
        "host-exec" => DeploymentClass::HostExec,
        "sandbox-service" => DeploymentClass::SandboxService,
        _ => DeploymentClass::Unknown,
    }
}

#[cfg(not(feature = "root-only"))]
fn workload_has_cap_ambient(cap: caps::Capability) -> bool {
    caps::has_cap(None, caps::CapSet::Ambient, cap).unwrap_or(false)
        && caps::has_cap(None, caps::CapSet::Permitted, cap).unwrap_or(false)
}

#[cfg(not(feature = "root-only"))]
fn workload_has_cap_file_exec(cap: caps::Capability) -> bool {
    caps::has_cap(None, caps::CapSet::Effective, cap).unwrap_or(false)
        && caps::has_cap(None, caps::CapSet::Permitted, cap).unwrap_or(false)
}

#[cfg(not(feature = "root-only"))]
fn workload_has_cap_for_class(class: DeploymentClass, cap: caps::Capability) -> bool {
    match class {
        DeploymentClass::HostExec => !no_new_privs_enabled() && workload_has_cap_file_exec(cap),
        DeploymentClass::SandboxService => workload_has_cap_ambient(cap),
        DeploymentClass::Unknown => false,
    }
}

#[cfg(not(feature = "root-only"))]
fn promote_ambient_to_effective(class: DeploymentClass) -> Result<(), GuardError> {
    if class != DeploymentClass::SandboxService {
        return Ok(());
    }
    for cap in REQUIRED_WORKLOAD_CAPS.iter().copied() {
        if workload_has_cap_for_class(class, cap)
            && !caps::has_cap(None, caps::CapSet::Effective, cap).unwrap_or(false)
        {
            caps::raise(None, caps::CapSet::Effective, cap).map_err(|_| GuardError::MissingCap)?;
        }
    }
    Ok(())
}

#[cfg(not(feature = "root-only"))]
fn deployment_class_hint(class: DeploymentClass) -> &'static str {
    match class {
        DeploymentClass::HostExec => {
            "deployment-class host-exec: file capabilities on /usr/bin/git required \
             (NoNewPrivs must be 0); run make install-guard-host-exec"
        }
        DeploymentClass::SandboxService => {
            "deployment-class sandbox-service: ambient capabilities required from \
             workspace-agent@ systemd unit; run make install-sandbox"
        }
        DeploymentClass::Unknown => {
            "deployment-class missing or unknown in /usr/lib/workspace-guard/deployment-class; \
             run make install-guard-host-exec"
        }
    }
}

#[cfg(not(feature = "root-only"))]
fn check_privileges() -> Result<(), GuardError> {
    let class = read_deployment_class();
    let mut missing = Vec::new();
    for cap in REQUIRED_WORKLOAD_CAPS.iter().copied() {
        if !workload_has_cap_for_class(class, cap) {
            missing.push(format!("{cap:?}"));
        }
    }
    if !missing.is_empty() {
        let caps_list = "cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid";
        let hint = deployment_class_hint(class);
        return Err(GuardError::MissingCapabilities(format!(
            "FATAL: missing workload capabilities ({caps_list}); missing: [{}]. {hint}",
            missing.join(", ")
        )));
    }
    promote_ambient_to_effective(class)?;
    match class {
        DeploymentClass::HostExec | DeploymentClass::SandboxService => {
            exec::raise_ambient_caps()?;
        }
        DeploymentClass::Unknown => {}
    }
    Ok(())
}

/// Opt-in phase timing for debugging wrapped-git invocations:
/// `WORKSPACE_GUARD_TRACE=1 git ...` prints each guard phase and its
/// elapsed time to stderr. Off by default; zero cost when unset beyond
/// one env lookup per phase.
pub(crate) struct PhaseTrace(std::time::Instant);

pub(crate) fn trace_start(phase: &str) -> Option<PhaseTrace> {
    std::env::var_os("WORKSPACE_GUARD_TRACE")?;
    eprintln!("[guard-trace] {phase}...");
    Some(PhaseTrace(std::time::Instant::now()))
}

pub(crate) fn trace_end(t: Option<PhaseTrace>, phase: &str) {
    if let Some(t) = t {
        eprintln!(
            "[guard-trace] {phase} done in {}ms",
            t.0.elapsed().as_millis()
        );
    }
}

/// Basename of an arbitrary argv byte string (no allocation).
fn basename(bytes: &[u8]) -> &[u8] {
    match bytes.iter().rposition(|&b| b == b'/') {
        Some(i) => &bytes[i + 1..],
        None => bytes,
    }
}

/// Normalise git's multi-call form (`git-foo ...`, argv[0] basename
/// `git-foo`) to the dispatcher form (`git foo ...`) so the SAME policy
/// applies whether git is reached as `/usr/bin/git` or through a
/// `/usr/lib/git-core/git-foo` symlink. /usr/lib/git-core/git is the
/// guard itself, and git prefixes its exec path to PATH when spawning
/// hooks, so hook/child `git-foo` invocations land here. Without this,
/// `git-commit --amend` would reach real git as argv[1]=`--amend` and
/// slip past the commit rule, and `git-upload-pack` would be misparsed
/// as a repo path.
fn normalize_multicall(argv: &[OsString]) -> Vec<OsString> {
    let Some(first) = argv.first() else {
        return Vec::new();
    };
    let base = basename(first.as_bytes());
    let Some(suffix) = base.strip_prefix(b"git-") else {
        return argv.to_vec();
    };
    if suffix.is_empty() || suffix.contains(&b'/') {
        return argv.to_vec();
    }
    let mut out = Vec::with_capacity(argv.len() + 1);
    out.push(first.clone());
    out.push(OsString::from_vec(suffix.to_vec()));
    out.extend_from_slice(&argv[1..]);
    out
}

fn run(argv_os: &[OsString]) -> Result<(), GuardError> {
    let t = trace_start("check_privileges");
    check_privileges()?;
    trace_end(t, "check_privileges");
    exec::set_resource_limits();

    // Multi-call normalisation must precede parsing and exec: real git is
    // invoked via a fixed pathname with argv[0] replaced, so the subcommand
    // must already be present at argv[1].
    let normalized = normalize_multicall(argv_os);
    let argv_os: &[OsString] = &normalized;

    if argv_os.len() <= 1 {
        return exec::execve_real_git(argv_os, None, None);
    }

    let argv: Vec<&[u8]> = argv_os.iter().map(|a| a.as_bytes()).collect();
    args::check_null_bytes(&argv)?;

    let t = trace_start("parse_args");
    let mut state = args::parse_args(&argv)?;
    trace_end(t, "parse_args");

    // SPEC-GIT-GUARD section 4 engine order: 1 categories, 2 destructive
    // options (parse_args), 3 dangerous -c (sanitize-or-block), then the
    // subcommand-specific rules on the possibly-rewritten argv.
    if let Some(ref sub) = state.subcommand {
        let t = trace_start("check_categories");
        block::check_categories(sub, argv_os, None)?;
        trace_end(t, "check_categories");
    }

    let t = trace_start("sanitize");
    let stripped = sanitize::decide(&mut state, argv_os)?;
    trace_end(t, "sanitize");
    let argv_effective: Vec<OsString> = match stripped {
        Some(v) => v,
        None => argv_os.to_vec(),
    };

    if let Some(ref sub) = state.subcommand {
        let t = trace_start("check_blocked");
        block::check_subcommand_rules(
            &state,
            sub,
            &argv_effective,
            crate::GIT_ORIGINAL_PATH,
            None,
        )?;
        trace_end(t, "check_blocked");

        // Capability-mode ownership lock: claim all paths declared in
        // config/shared_locked_paths.yaml (e.g. .git/ minus object
        // stores, .gitmodules, *_exceptions.yaml) as root:root before
        // any further git.original subprocess can fire a payload
        // planted inside them. Best-effort; never blocks a pass.
        // Root-only builds are no-ops (user is already root).
        // The git dir is resolved ONCE here; the post-exec relock in
        // exec.rs reuses it instead of spawning a second rev-parse.
        #[cfg(feature = "capability-mode")]
        let git_dir = {
            let t = trace_start("resolve_git_dir+lock");
            let gd = gitdir::resolve_git_dir(&argv_effective);
            if let Some(ref g) = gd {
                gitdir::lock(g);
                let t = trace_start("check_sealed_repo");
                sealed_repo::check_sealed_repo(sub, g)?;
                trace_end(t, "check_sealed_repo");
            }
            trace_end(t, "resolve_git_dir+lock");
            gd
        };

        if CONTRACT_CHECK_SUBCOMMANDS.contains(&sub.as_str()) {
            let t = trace_start("ci_contract_check");
            exec::check_workspace_ci_contract(sub, &argv_effective)?;
            trace_end(t, "ci_contract_check");
        }

        #[cfg(feature = "capability-mode")]
        return exec::execve_real_git(&argv_effective, Some(&state), git_dir.as_deref());
    }

    exec::execve_real_git(&argv_effective, Some(&state), None)
}

#[cfg(test)]
pub static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
#[path = "config_consistency_tests.rs"]
mod config_consistency;

#[cfg(test)]
#[path = "config_consistency_catalog_tests.rs"]
mod config_consistency_catalog;

#[cfg(test)]
#[path = "policy_matrix_tests.rs"]
mod policy_matrix_tests;

#[cfg(test)]
#[path = "attack_surface_tests.rs"]
mod attack_surface_tests;

#[cfg(test)]
#[path = "multicall_tests.rs"]
mod multicall_tests;
