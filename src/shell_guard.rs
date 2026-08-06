use std::ffi::{CString, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::{execve, getuid, Uid, User};
use regex::bytes::Regex;

mod shell_config {
    include!(concat!(env!("OUT_DIR"), "/shell_guard_config.rs"));
}
mod shell_guard_fd;
mod shell_guard_report;

use shell_guard_fd as shg_fd;
use shell_guard_report as report;

const REAL_SHELL: &str = "/bin/bash.real";
const MAX_TEXT: usize = 1 << 20;
const LOG_FILE_NAME: &str = ".workspace-guard.log";
const RESET_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

const PRESERVE_EXACT: &[&str] = &[
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "TERM",
    "COLORTERM",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "SSH_AUTH_SOCK",
    "GPG_TTY",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "SHELL",
    "TZ",
];
const PRESERVE_PREFIX: &[&str] = &["LC_", "XDG_", "OPENCODE_", "WORKSPACE_", "AMI_", "_CI_"];

struct Rule {
    id: &'static str,
    re: Regex,
    hint: &'static str,
    scope: &'static str,
}

fn compile_rules() -> Vec<Rule> {
    shell_config::SHELL_PATTERNS
        .iter()
        .map(|(id, pat, hint, scope)| Rule {
            id,
            re: Regex::new(pat).unwrap_or_else(|e| {
                panic!("shell guard: pattern {:?} does not compile: {}", id, e)
            }),
            hint,
            scope,
        })
        .collect()
}

enum Invocation {
    PassThrough,
    Command(Vec<u8>),
    Script(OsString, usize),
}

fn classify(args: &[OsString]) -> Invocation {
    let mut i = 1;
    let mut options = true;
    while i < args.len() {
        let bytes = args[i].as_bytes();
        if options && bytes == b"--" {
            options = false;
            i += 1;
            continue;
        }
        if options && bytes.len() > 1 && bytes[0] == b'-' {
            if bytes == b"--help" || bytes == b"--version" {
                return Invocation::PassThrough;
            }
            if bytes.starts_with(b"--") {
                if (bytes.starts_with(b"--init-file") || bytes.starts_with(b"--rcfile"))
                    && !bytes.contains(&b'=')
                {
                    i += 1;
                }
                i += 1;
                continue;
            }
            let bundle = &bytes[1..];
            if let Some(pos) = bundle.iter().position(|&c| c == b'c') {
                if pos == bundle.len() - 1 {
                    match args.get(i + 1) {
                        Some(s) => return Invocation::Command(s.as_bytes().to_vec()),
                        None => return Invocation::PassThrough,
                    }
                }
                return Invocation::PassThrough;
            }
            if bundle.contains(&b'i') {
                return Invocation::PassThrough;
            }
            i += 1;
            continue;
        }
        return Invocation::Script(args[i].clone(), i);
    }
    Invocation::PassThrough
}

enum ScriptClass {
    Trusted(Vec<u8>),
    Untrusted(Vec<u8>),
    Unreadable,
    /// fd/pipe/device-backed source that is not our sealed staging
    /// memfd: real content the scanner cannot see. Hard block.
    ForeignFd,
}

fn dir_is_root_locked(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(m) => {
            use std::os::unix::fs::MetadataExt;
            m.uid() == 0 && (m.mode() & 0o022) == 0
        }
        Err(_) => false,
    }
}

// _IOR('f', 1, long) on 64-bit Linux; libc::FS_IOC_GETFLAGS is not
// exported by all pinned libc versions, and FS_IMMUTABLE_FL is not in
// the libc crate at all.
const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IMMUTABLE_FL: libc::c_long = 0x0000_0010;

fn dir_is_immutable(path: &Path) -> bool {
    use std::os::unix::io::AsRawFd;
    let f = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut flags: libc::c_long = 0;
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) };
    rc == 0 && (flags & FS_IMMUTABLE_FL) != 0
}

// Anchored trust: every ancestor from the script's parent upward must be
// root-locked, and the chain must either reach / or terminate at a
// directory carrying FS_IMMUTABLE_FL. The immutable anchor cannot be
// renamed or replaced by the agent-owned parent above it, which closes
// the unlink+recreate attack that plain root-ownership under an
// agent-owned ancestor leaves open.
fn parents_root_locked_or_anchored(path: &Path) -> bool {
    let abs: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(c) => c.join(path),
            Err(_) => return false,
        }
    };
    let mut cur = abs.parent().map(|p| p.to_path_buf());
    let mut top_locked: Option<PathBuf> = None;
    while let Some(p) = cur {
        if !dir_is_root_locked(&p) {
            break;
        }
        if p == Path::new("/") {
            return true;
        }
        top_locked = Some(p.clone());
        cur = p.parent().map(|x| x.to_path_buf());
    }
    match top_locked {
        Some(p) => dir_is_immutable(&p),
        None => false,
    }
}

fn classify_script(path: &OsString) -> ScriptClass {
    let spath = path.to_string_lossy();
    // fd-delivered sources are real content the regular open path
    // cannot see (O_NOFOLLOW rejects /proc/self/fd symlinks). Accept
    // only our own sealed staging memfd; block everything else.
    if shg_fd::is_fd_path(&spath) {
        return match shg_fd::read_staged_fd(&spath) {
            Some(buf) => ScriptClass::Untrusted(buf),
            None => ScriptClass::ForeignFd,
        };
    }
    // Metadata first: opening a fifo for read would block forever.
    // Directories pass through so the real bash prints its own error;
    // every other non-file (fifo, socket, device) is a content channel
    // the scanner cannot read and is therefore blocked.
    // Resolve launcher symlinks before scanning. The resolved target is the
    // content that will execute; opening that canonical path with O_NOFOLLOW
    // prevents a later link traversal while still supporting root-owned
    // launchers such as the opencode wrapper.
    let resolved = match fs::canonicalize(Path::new(path)) {
        Ok(p) => p,
        Err(_) => return ScriptClass::Unreadable,
    };
    let meta = match fs::symlink_metadata(&resolved) {
        Ok(m) => m,
        Err(_) => return ScriptClass::Unreadable,
    };
    if !meta.is_file() {
        if meta.is_dir() {
            return ScriptClass::Unreadable;
        }
        return ScriptClass::ForeignFd;
    }
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&resolved)
    {
        Ok(f) => f,
        Err(_) => return ScriptClass::Unreadable,
    };
    let mut buf = Vec::new();
    let mut limited = file.take((MAX_TEXT + 1) as u64);
    if limited.read_to_end(&mut buf).is_err() {
        return ScriptClass::Unreadable;
    }
    if buf.len() > MAX_TEXT {
        eprintln!("shell guard: script content exceeds 1 MiB limit");
        process::exit(2);
    }
    use std::os::unix::fs::MetadataExt;
    let trusted =
        meta.uid() == 0 && (meta.mode() & 0o022) == 0 && parents_root_locked_or_anchored(&resolved);
    if trusted {
        ScriptClass::Trusted(buf)
    } else {
        ScriptClass::Untrusted(buf)
    }
}

fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (hour, minute, second) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        year, m, d, hour, minute, second
    )
}

fn audit(reason: &str, cmd: &str) {
    let uid = getuid().as_raw();
    let home = User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.dir);
    if let Some(dir) = home {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "?".to_string());
        if let Ok(mut f) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(dir.join(LOG_FILE_NAME))
        {
            let _ = writeln!(f, "{}|{}|{}|{}|uid={}", timestamp(), cwd, cmd, reason, uid);
        }
    }
}

fn block(rule: &Rule, display: &str, excerpt: &str) -> ! {
    let msg = report::block_report(rule, display, excerpt, &timestamp());
    eprintln!("{}", msg);
    if let Ok(tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(&tty, "{}", msg);
    }
    audit(
        &format!("blocked rule: {}", rule.id),
        &format!("{} excerpt={}", display, report::flatten(excerpt)),
    );
    process::exit(1);
}

fn block_unreadable(display: &str) -> ! {
    let msg = format!("BLOCKED: script-unreadable: {}", display);
    eprintln!("{}", msg);
    if let Ok(tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(&tty, "{}", msg);
    }
    audit("blocked rule: script-unreadable", display);
    process::exit(1);
}

fn build_envp(staged_script: Option<&Path>) -> Vec<CString> {
    let mut out: Vec<CString> = Vec::new();
    for (k, v) in std::env::vars_os() {
        let key = k.to_string_lossy();
        let keep = PRESERVE_EXACT.contains(&key.as_ref())
            || PRESERVE_PREFIX.iter().any(|p| key.starts_with(p))
            || (key == "TMPDIR" && tmpdir_ok(&v));
        if keep {
            let mut s = k.into_vec();
            s.push(b'=');
            s.extend_from_slice(&v.into_vec());
            if let Ok(c) = CString::new(s) {
                out.push(c);
            }
        }
    }
    out.push(CString::new(format!("PATH={}", RESET_PATH)).unwrap());
    // Memfd staging rewrites the script argument to /proc/self/fd/N, so
    // $0/BASH_SOURCE no longer name the real file and $0-relative
    // sourcing (dirname "$0"/../lib/...) breaks. Publish the canonical
    // original path so scripts can resolve their true location:
    //   _SELF="${SHG_SCRIPT_PATH:-${BASH_SOURCE[0]}}"
    // Inserted post-scrub (SHG_ is not a preserved prefix), so only the
    // guard can set it; a caller-supplied value is dropped above.
    if let Some(orig) = staged_script {
        let mut s = b"SHG_SCRIPT_PATH=".to_vec();
        s.extend_from_slice(orig.as_os_str().as_bytes());
        out.extend(CString::new(s).ok());
    }
    out
}

fn tmpdir_ok(v: &OsString) -> bool {
    use std::os::unix::fs::MetadataExt;
    let p = Path::new(v);
    p.is_absolute()
        && fs::metadata(p)
            .map(|m| m.is_dir() && m.uid() == getuid().as_raw())
            .unwrap_or(false)
}

fn set_rlimits() {
    use nix::sys::resource::{getrlimit, setrlimit, Resource};
    if let Ok((soft, hard)) = getrlimit(Resource::RLIMIT_NOFILE) {
        let _ = setrlimit(Resource::RLIMIT_NOFILE, soft.min(4096), hard.min(4096));
    }
    let _ = setrlimit(Resource::RLIMIT_CORE, 0, 0);
}

fn verify_real_shell() {
    use std::os::unix::fs::MetadataExt;
    let meta = match fs::metadata(REAL_SHELL) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("shell guard: cannot stat {}: {}", REAL_SHELL, e);
            process::exit(3);
        }
    };
    if !meta.is_file() || meta.uid() != 0 || (meta.mode() & 0o7777) != 0o700 {
        eprintln!(
            "shell guard: {} failed verification (regular file, uid 0, mode 0700)",
            REAL_SHELL
        );
        process::exit(3);
    }
}

fn exec_real(args: &[OsString], staged: Option<(usize, String, PathBuf)>) -> ! {
    verify_real_shell();
    let envp = build_envp(staged.as_ref().map(|(_, _, orig)| orig.as_path()));
    set_rlimits();
    let mut argv: Vec<CString> = Vec::with_capacity(args.len());
    for (idx, a) in args.iter().enumerate() {
        let bytes = match &staged {
            Some((at, fdpath, _)) if *at == idx => fdpath.clone().into_bytes(),
            _ => a.as_bytes().to_vec(),
        };
        match CString::new(bytes) {
            Ok(c) => argv.push(c),
            Err(_) => {
                eprintln!("shell guard: null byte in argument");
                process::exit(2);
            }
        }
    }
    let path = CString::new(REAL_SHELL).unwrap();
    match execve(&path, &argv, &envp) {
        Ok(inf) => match inf {},
        Err(errno) => {
            eprintln!(
                "FATAL: execve failed: {}",
                std::io::Error::from_raw_os_error(errno as i32)
            );
            process::exit(3);
        }
    }
}

fn at_secure() -> u64 {
    const AT_SECURE_KEY: u64 = 23;
    let raw = match fs::read("/proc/self/auxv") {
        Ok(b) => b,
        Err(_) => return 0,
    };
    let word = std::mem::size_of::<u64>();
    for pair in raw.chunks_exact(word * 2) {
        let key = u64::from_ne_bytes(pair[..word].try_into().unwrap());
        let val = u64::from_ne_bytes(pair[word..].try_into().unwrap());
        if key == AT_SECURE_KEY {
            return val;
        }
        if key == 0 {
            break;
        }
    }
    0
}

fn main() {
    // Root already has an unconditional escape hatch (/bin/bash.real),
    // so failing closed for euid 0 only breaks every root make target
    // and package-manager lifecycle script without adding any security.
    // Keep the AT_SECURE gate for everyone else.
    let euid = unsafe { libc::geteuid() };
    if at_secure() == 0 && euid != 0 {
        eprintln!("shell guard: not running in a capability context (AT_SECURE == 0)");
        process::exit(3);
    }

    let args: Vec<OsString> = std::env::args_os().collect();
    let rules = compile_rules();

    match classify(&args) {
        Invocation::PassThrough => exec_real(&args, None),
        Invocation::Command(text) => {
            if text.contains(&0) {
                eprintln!("shell guard: null byte in command string");
                process::exit(2);
            }
            if text.len() > MAX_TEXT {
                eprintln!("shell guard: command string exceeds 1 MiB limit");
                process::exit(2);
            }
            if let Some(hit) = report::find_hit(&text, &rules, "command") {
                let display = format!("bash -c '{}'", report::sanitize_cmd(&text));
                let excerpt = report::excerpt(&text, hit.start, hit.end, false);
                block(hit.rule, &display, &excerpt);
            }
            exec_real(&args, None);
        }
        Invocation::Script(path, idx) => match classify_script(&path) {
            ScriptClass::ForeignFd => {
                let msg = report::fd_block_report(&path.to_string_lossy(), &timestamp());
                eprintln!("{}", msg);
                if let Ok(tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
                    let _ = writeln!(&tty, "{}", msg);
                }
                audit("blocked fd-script-source", &path.to_string_lossy());
                process::exit(1);
            }
            ScriptClass::Unreadable => {
                let display = format!("bash {} (unreadable script)", path.to_string_lossy());
                block_unreadable(&display);
            }
            ScriptClass::Trusted(content) => {
                if let Some(hit) = report::find_hit(&content, &rules, "script") {
                    let display = format!("bash {} (trusted script body)", path.to_string_lossy());
                    let excerpt = report::excerpt(&content, hit.start, hit.end, true);
                    block(hit.rule, &display, &excerpt);
                }
                exec_real(&args, None);
            }
            ScriptClass::Untrusted(content) => {
                if let Some(hit) = report::find_hit(&content, &rules, "untrusted-script") {
                    let display = format!("bash {} (script body)", path.to_string_lossy());
                    let excerpt = report::excerpt(&content, hit.start, hit.end, true);
                    block(hit.rule, &display, &excerpt);
                }
                let fdpath = shg_fd::memfd_exec_path(&content);
                let orig =
                    fs::canonicalize(Path::new(&path)).unwrap_or_else(|_| PathBuf::from(&path));
                exec_real(&args, Some((idx, fdpath, orig)));
            }
        },
    }
}

#[cfg(test)]
#[path = "shell_guard_tests.rs"]
mod tests;
