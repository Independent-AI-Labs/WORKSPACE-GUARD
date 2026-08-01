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

fn scope_applies(scope: &str, is_script: bool) -> bool {
    scope == "both" || (is_script && scope == "script") || (!is_script && scope == "command")
}

fn scan<'r>(text: &[u8], rules: &'r [Rule], is_script: bool) -> Option<&'r Rule> {
    rules
        .iter()
        .find(|r| scope_applies(r.scope, is_script) && r.re.is_match(text))
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

fn parents_root_locked(path: &Path) -> bool {
    let abs: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(c) => c.join(path),
            Err(_) => return false,
        }
    };
    let mut cur = abs.parent().map(|p| p.to_path_buf());
    while let Some(p) = cur {
        if !dir_is_root_locked(&p) {
            return false;
        }
        if p == Path::new("/") {
            return true;
        }
        cur = p.parent().map(|x| x.to_path_buf());
    }
    true
}

fn classify_script(path: &OsString) -> ScriptClass {
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(path))
    {
        Ok(f) => f,
        Err(_) => return ScriptClass::Unreadable,
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(_) => return ScriptClass::Unreadable,
    };
    if !meta.is_file() {
        return ScriptClass::Unreadable;
    }
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
        meta.uid() == 0 && (meta.mode() & 0o022) == 0 && parents_root_locked(Path::new(path));
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

fn sanitize_cmd(text: &[u8]) -> String {
    let lossy = String::from_utf8_lossy(text);
    let mut out = String::new();
    for word in lossy.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        if let Some(eq) = word.find('=') {
            let (k, _) = word.split_at(eq);
            if !k.is_empty()
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                && k.bytes().next().is_some_and(|b| !b.is_ascii_digit())
            {
                out.push_str(k);
                out.push_str("=...");
                continue;
            }
        }
        out.push_str(word);
    }
    let out = out.replace('\'', "\u{2019}");
    if out.len() > 200 {
        out.chars().take(200).collect()
    } else {
        out
    }
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

fn block(rule: &Rule, display: &str) -> ! {
    let msg = format!(
        "BLOCKED: {} ({}) ({})\n  -> Hint: {}",
        display,
        rule.id,
        timestamp(),
        rule.hint
    );
    eprintln!("{}", msg);
    if let Ok(tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(&tty, "{}", msg);
    }
    audit(&format!("blocked rule: {}", rule.id), display);
    process::exit(1);
}

fn would_block(rule: &Rule, display: &str) {
    let msg = format!(
        "shell guard: would-block ({}) in trusted-tier script: {}",
        rule.id, display
    );
    eprintln!("{}", msg);
    audit(&format!("would-block rule: {}", rule.id), display);
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

fn memfd_exec_path(content: &[u8]) -> String {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, SealFlag};
    use rustix::fs::{memfd_create, MemfdFlags};
    use std::os::unix::io::{AsRawFd, IntoRawFd};

    // rustix safe wrapper: nix 0.29 does not expose MFD_EXEC. Flags:
    // ALLOW_SEALING is mandatory (without it the memfd is born with
    // F_SEAL_SEAL and every F_ADD_SEALS fails EPERM); EXEC keeps the
    // fd executable under vm.memfd_noexec=1 (Ubuntu 24.04).
    let fd = match memfd_create(
        c"workspace-shell-guard",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::EXEC,
    ) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("shell guard: memfd_create failed: {}", e);
            process::exit(3);
        }
    };
    if nix::unistd::write(&fd, content).is_err() {
        eprintln!("shell guard: memfd write failed");
        process::exit(3);
    }
    let seals = SealFlag::F_SEAL_SHRINK
        | SealFlag::F_SEAL_WRITE
        | SealFlag::F_SEAL_GROW
        | SealFlag::F_SEAL_SEAL;
    if let Err(e) = fcntl(fd.as_raw_fd(), FcntlArg::F_ADD_SEALS(seals)) {
        eprintln!("shell guard: memfd sealing failed: {}", e);
        process::exit(3);
    }
    if let Err(e) = fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())) {
        eprintln!("shell guard: memfd cloexec clear failed: {}", e);
        process::exit(3);
    }
    // Leak the fd on purpose: it must survive the execve into the real
    // shell. Dropping the OwnedFd here would close it before exec.
    let leaked = fd.into_raw_fd();
    format!("/proc/self/fd/{}", leaked)
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
    if at_secure() == 0 {
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
            if let Some(rule) = scan(&text, &rules, false) {
                let display = format!("bash -c '{}'", sanitize_cmd(&text));
                block(rule, &display);
            }
            exec_real(&args, None);
        }
        Invocation::Script(path, idx) => match classify_script(&path) {
            ScriptClass::Unreadable => {
                eprintln!(
                    "shell guard: warning: cannot read script {:?}; passing through",
                    path
                );
                exec_real(&args, None);
            }
            ScriptClass::Trusted(content) => {
                if let Some(rule) = scan(&content, &rules, true) {
                    would_block(rule, &path.to_string_lossy());
                }
                exec_real(&args, None);
            }
            ScriptClass::Untrusted(content) => {
                if let Some(rule) = scan(&content, &rules, true) {
                    let display = format!("bash {} (script body)", path.to_string_lossy());
                    block(rule, &display);
                }
                let fdpath = memfd_exec_path(&content);
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
