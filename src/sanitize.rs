//! Read-only invocation sanitization (REQ-GGUARD-043..046, SPEC-GIT-GUARD
//! sections 3.4 and 4 engine step 3). A read-only subcommand invoked with
//! leading dangerous `-c` config options keeps working by having those
//! options stripped before real git sees a single dangerous-config byte.
//! Anything that does not qualify blocks exactly as before: sanitization
//! only ever removes tokens, never weakens another rule.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use crate::args::ArgState;
use crate::{is_dangerous_config_key, log, GuardError, READ_ONLY_SUBCOMMANDS};

/// One flagged config-option occurrence: argv indexes of the flag token
/// and its separate operand token (attached forms have none), plus the
/// blocked keys carried by that option. Recorded by args::parse_args.
#[derive(Debug, Clone)]
pub struct ConfigSpan {
    pub flag_idx: usize,
    pub operand_idx: Option<usize>,
    pub keys: Vec<String>,
    pub post_subcommand: bool,
}

/// Subcommands whose grammar defines `-n` as the `--no-verify` short
/// alias (REQ-GGUARD-030; pinned against the deployed git help output).
/// Everywhere else `-n` has a different meaning and stays allowed.
pub const NO_VERIFY_SHORT_SUBCOMMANDS: &[&str] = &["am", "commit"];

#[derive(Debug)]
pub struct Plan {
    pub argv: Vec<OsString>,
    pub dropped: Vec<Vec<u8>>,
}

fn blocked_first(state: &ArgState) -> GuardError {
    GuardError::Blocked {
        reason: format!(
            "dangerous -c config key: {}",
            state
                .dangerous_config_keys
                .first()
                .map(String::as_str)
                .unwrap_or("?")
        ),
        hint: "Remove the -c flag with the dangerous config key".into(),
    }
}

/// Pure decision core (no I/O): strip flagged dangerous config options
/// when the invocation qualifies as a read-only query; keep every other
/// outcome a block. Qualification (REQ-GGUARD-043): byte-exact raw
/// subcommand match (no abbreviation expansion), read shapes only for
/// `config` and `remote`, and every flagged occurrence covered by a
/// pre-subcommand span whose keys are all in the dangerous class
/// (sudo-gated keys keep their REQ-GGUARD-068 treatment).
pub fn plan(
    read_only: &[&str],
    state: &ArgState,
    argv_os: &[OsString],
) -> Result<Option<Plan>, GuardError> {
    if state.dangerous_config_keys.is_empty() {
        return Ok(None);
    }
    let raw = match state.subcommand_raw.as_deref() {
        Some(r) => r,
        None => return Err(blocked_first(state)),
    };
    if !read_only.contains(&raw) {
        return Err(blocked_first(state));
    }
    if raw == "config" && !config_read_shape(argv_os) {
        return Err(blocked_first(state));
    }
    if raw == "remote" && !remote_read_shape(argv_os) {
        return Err(blocked_first(state));
    }
    for span in &state.config_spans {
        if span.post_subcommand || !span.keys.iter().all(|k| is_dangerous_config_key(k)) {
            return Err(blocked_first(state));
        }
    }
    let mut drop_idxs: Vec<usize> = Vec::new();
    for span in &state.config_spans {
        drop_idxs.push(span.flag_idx);
        if let Some(op) = span.operand_idx {
            drop_idxs.push(op);
        }
    }
    drop_idxs.sort_unstable();
    drop_idxs.dedup();
    let mut argv = Vec::with_capacity(argv_os.len() - drop_idxs.len());
    let mut dropped: Vec<Vec<u8>> = Vec::new();
    for (idx, arg) in argv_os.iter().enumerate() {
        if drop_idxs.binary_search(&idx).is_ok() {
            dropped.push(arg.as_bytes().to_vec());
        } else {
            argv.push(arg.clone());
        }
    }
    Ok(Some(Plan { argv, dropped }))
}

/// Engine step 3 wrapper: plan, then deliver the SANITIZED report
/// (stderr plus controlling terminal, REQ-GGUARD-021) and the audit
/// record. Report or persistence failure is a typed GuardUnavailable
/// (exit 3) and real git never runs (REQ-GGUARD-045).
pub fn decide(
    state: &mut ArgState,
    argv_os: &[OsString],
) -> Result<Option<Vec<OsString>>, GuardError> {
    let planned = plan(READ_ONLY_SUBCOMMANDS, state, argv_os)?;
    match planned {
        None => Ok(None),
        Some(p) => {
            let raw = state.subcommand_raw.clone().unwrap_or_default();
            let report = build_report(&log::timestamp_utc_z(), &raw, &p.dropped, argv_os);
            deliver_report(&report)?;
            log::audit_sanitize(&report)
                .map_err(|e| GuardError::GuardUnavailable(format!("sanitize audit: {}", e)))?;
            state.dangerous_config_keys.clear();
            state.config_spans.clear();
            Ok(Some(p.argv))
        }
    }
}

/// REQ-GGUARD-045 report grammar:
/// `SANITIZED: ts=<RFC3339-UTC-Z>|subcommand=<name>|drops=<decimal>|
///  drop0=<encoded>|...|argc=<decimal>|arg0=<encoded>|...`
/// Tokens are the original, pre-strip argv; dynamic values use the
/// REQ-GGUARD-091 uppercase %HH encoding.
pub fn build_report(ts: &str, raw_sub: &str, dropped: &[Vec<u8>], argv: &[OsString]) -> String {
    let mut s = format!(
        "SANITIZED: ts={}|subcommand={}|drops={}",
        ts,
        log::pct_encode(raw_sub.as_bytes()),
        dropped.len()
    );
    for (i, d) in dropped.iter().enumerate() {
        s.push_str(&format!("|drop{}={}", i, log::pct_encode(d)));
    }
    s.push_str(&format!("|argc={}", argv.len()));
    for (i, a) in argv.iter().enumerate() {
        s.push_str(&format!("|arg{}={}", i, log::pct_encode(a.as_bytes())));
    }
    s
}

/// Sink selector for the SANITIZED terminal report (operator flag).
/// `WORKSPACE_GUARD_SANITIZED_SINK=stderr` (default/unset) keeps the
/// stderr + /dev/tty delivery; `liveaudit` appends the report to a
/// `.liveaudit` file in the working directory instead, keeping tool
/// stderr clean. Only the terminal report moves: the home-sink audit
/// record stays mandatory in both modes (REQ-GGUARD-045). Any other
/// value fails closed as GuardUnavailable.
pub const SANITIZED_SINK_ENV: &str = "WORKSPACE_GUARD_SANITIZED_SINK";
pub const LIVEAUDIT_NAME: &str = ".liveaudit";

#[derive(Debug, PartialEq, Eq)]
enum SanitizedSink {
    Stderr,
    Liveaudit,
}

fn parse_sink(val: Option<&std::ffi::OsStr>) -> Result<SanitizedSink, String> {
    let Some(v) = val else {
        return Ok(SanitizedSink::Stderr);
    };
    let b = v.as_bytes();
    if b.eq_ignore_ascii_case(b"stderr") {
        Ok(SanitizedSink::Stderr)
    } else if b.eq_ignore_ascii_case(b"liveaudit") {
        Ok(SanitizedSink::Liveaudit)
    } else {
        Err(format!(
            "{} must be stderr or liveaudit, got {:?}",
            SANITIZED_SINK_ENV,
            String::from_utf8_lossy(b)
        ))
    }
}

fn deliver_report(report: &str) -> Result<(), GuardError> {
    let sink = parse_sink(std::env::var_os(SANITIZED_SINK_ENV).as_deref())
        .map_err(GuardError::GuardUnavailable)?;
    let io_result = match sink {
        SanitizedSink::Stderr => deliver_stderr(report),
        SanitizedSink::Liveaudit => append_liveaudit(std::path::Path::new("."), report),
    };
    io_result.map_err(|e| GuardError::GuardUnavailable(format!("sanitize report: {}", e)))
}

fn deliver_stderr(report: &str) -> std::io::Result<()> {
    let mut err = std::io::stderr();
    err.write_all(report.as_bytes())?;
    err.write_all(b"\n")?;
    err.flush()?;
    if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(tty, "{}", report);
    }
    Ok(())
}

fn append_liveaudit(dir: &std::path::Path, report: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(LIVEAUDIT_NAME))?;
    writeln!(f, "{}", report)
}

/// `git config` options that turn the invocation into a write (shared
/// with block.rs: writes keep the dangerous/sudo-gated key block; a
/// read shape like `git config user.name` or `--get user.email` only
/// displays a value and must pass).
pub const CONFIG_WRITE_OPTS: &[&str] = &[
    "--add",
    "--unset",
    "--unset-all",
    "--replace-all",
    "--rename-section",
    "--remove-section",
    "--edit",
];

/// `git config` positional-key policy (engine step 4): only a WRITE
/// shape blocks. `git config user.name` and `config --get user.email`
/// are reads (value display, nothing is persisted); a write is any
/// CONFIG_WRITE_OPTS verb or a second positional (key + value). Under a
/// write shape the first positional is the key being written and is
/// blocked retroactively; keys named under a write verb block directly.
pub fn config_write_key_check(argv_os: &[OsString], privileged: bool) -> Result<(), GuardError> {
    let block_key = |key: &str| -> Option<GuardError> {
        if crate::is_config_key_blocked(key, privileged) {
            Some(GuardError::Blocked {
                reason: format!("git config: dangerous config key: {}", key),
                hint: "Use a non-dangerous config key instead".into(),
            })
        } else {
            None
        }
    };
    let mut seen = false;
    let mut skip_next = false;
    let mut write_shape = false;
    let mut pending_read_key: Option<String> = None;
    let mut saw_positional = false;
    for arg in argv_os.iter().skip(1) {
        let s = arg.to_string_lossy();
        // Global preamble (-c key value, -C dir, ...) is not part of the
        // config invocation; positionals are counted only after the
        // subcommand marker. A literal "config" AFTER the marker is an
        // ordinary positional (a value being written).
        if s == "config" && !seen {
            seen = true;
            continue;
        }
        if !seen || skip_next {
            skip_next = false;
            continue;
        }
        if s.starts_with('-') {
            let opt = s.split('=').next().unwrap_or(&s);
            if CONFIG_WRITE_OPTS.contains(&opt) {
                write_shape = true;
            } else if crate::VALUE_TAKING_OPTS.contains(&opt) {
                skip_next = true;
            }
            continue;
        }
        if write_shape {
            if let Some(e) = block_key(&s) {
                return Err(e);
            }
            continue;
        }
        if saw_positional {
            // second positional: the first was the key of a write
            if let Some(k) = pending_read_key.take() {
                if let Some(e) = block_key(&k) {
                    return Err(e);
                }
            }
            write_shape = true;
            continue;
        }
        saw_positional = true;
        pending_read_key = Some(s.to_string());
    }
    Ok(())
}

/// Read shape for `git config` (REQ-GGUARD-043): listing and get forms
/// with display modifiers only. Any write option, unknown option, or a
/// second positional (key plus value) disqualifies.
fn config_read_shape(argv_os: &[OsString]) -> bool {
    // --fixed-value is valid with get forms but rare; failing closed
    // here only blocks sanitization.
    const WRITE_OPTS: &[&str] = &["--fixed-value"];
    const READ_OPTS: &[&str] = &[
        "--list",
        "-l",
        "--get",
        "--get-all",
        "--get-regexp",
        "--get-urlmatch",
        "--name-only",
        "--show-origin",
        "--show-scope",
        "--bool",
        "--int",
        "--bool-or-int",
        "--bool-or-str",
        "--path",
        "--null",
        "-z",
        "--includes",
        "--no-includes",
        "--type",
        "--default",
        "--global",
        "--system",
        "--local",
        "--file",
        "-f",
        "--blob",
    ];
    let mut seen = false;
    let mut skip_next = false;
    let mut positionals = 0usize;
    let mut urlmatch = false;
    for a in argv_os.iter().skip(1) {
        let s = a.to_string_lossy();
        if s == "config" {
            seen = true;
            continue;
        }
        if !seen || skip_next {
            skip_next = false;
            continue;
        }
        if s.starts_with('-') && s.len() > 1 {
            let (name, val) = match s.split_once('=') {
                Some((n, _)) => (n, true),
                None => (s.as_ref(), false),
            };
            if CONFIG_WRITE_OPTS.contains(&name) || WRITE_OPTS.contains(&name) {
                return false;
            }
            if !READ_OPTS.contains(&name) {
                return false;
            }
            if name == "--get-urlmatch" {
                urlmatch = true;
            }
            if !val && matches!(name, "--type" | "--default" | "--file" | "-f" | "--blob") {
                skip_next = true;
            }
            continue;
        }
        positionals += 1;
    }
    if urlmatch {
        positionals <= 2
    } else {
        positionals <= 1
    }
}

/// Read shape for `git remote` (REQ-GGUARD-043): bare listing, `list`,
/// or `get-url <name>` with verbose flags only.
fn remote_read_shape(argv_os: &[OsString]) -> bool {
    let mut seen = false;
    let mut verb: Option<String> = None;
    let mut extra_positionals = 0usize;
    for a in argv_os.iter().skip(1) {
        let s = a.to_string_lossy();
        if s == "remote" {
            seen = true;
            continue;
        }
        if !seen {
            continue;
        }
        if s == "--" {
            break;
        }
        if s.starts_with('-') {
            if s != "-v" && s != "--verbose" {
                return false;
            }
            continue;
        }
        if verb.is_none() {
            verb = Some(s.to_string());
        } else {
            extra_positionals += 1;
        }
    }
    match verb.as_deref() {
        None | Some("list") => extra_positionals == 0,
        Some("get-url") => extra_positionals <= 1,
        _ => false,
    }
}

#[cfg(test)]
#[path = "sanitize_tests.rs"]
mod tests;
