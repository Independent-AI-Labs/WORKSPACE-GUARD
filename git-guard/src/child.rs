//! Bounded child-process execution. Every subprocess the guard (or its
//! tests) spawns gets a hard timeout so a blocked child becomes a named,
//! diagnosable failure instead of hanging the caller forever (observed:
//! `hash-object --stdin-paths` deadlocked against a >64KiB path list when
//! the caller wrote all of stdin before draining stdout, stalling every
//! workspace commit for minutes).
//!
//! Stdin is always fed from a dedicated writer thread and stdout/stderr
//! are drained by reader threads, so pipe-buffer sizes can never
//! deadlock the parent regardless of payload size.

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Default ceiling for one child process. Generous for cold-cache
/// `hash-object` over a large deployment tree; far below any human
/// noticing threshold.
pub const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

const POLL_INTERVAL: Duration = Duration::from_millis(5);

pub struct ChildOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    /// Diagnostics surface for callers that fail with context (used by
    /// the test helpers; production callers fail closed without it).
    #[allow(dead_code)]
    pub stderr: Vec<u8>,
}

impl ChildOutput {
    pub fn success(&self) -> bool {
        self.status.success()
    }

    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_string()
    }

    #[allow(dead_code)]
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

#[derive(Debug)]
pub enum RunError {
    Spawn(std::io::Error),
    Timeout { elapsed_ms: u128 },
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Spawn(e) => write!(f, "spawn failed: {e}"),
            RunError::Timeout { elapsed_ms } => {
                write!(f, "child timed out after {elapsed_ms}ms (killed)")
            }
        }
    }
}

/// Spawn `cmd` with piped stdout/stderr, optionally feed `stdin_payload`,
/// and wait at most `timeout`. On timeout the child is killed and reaped;
/// the error carries the elapsed time so callers can fail with context.
pub fn run_with_timeout(
    cmd: &mut Command,
    stdin_payload: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<ChildOutput, RunError> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().map_err(RunError::Spawn)?;

    let writer = match (child.stdin.take(), stdin_payload) {
        (Some(mut stdin), Some(payload)) => Some(std::thread::spawn(move || {
            let _ = stdin.write_all(&payload);
        })),
        (stdin, _) => {
            drop(stdin);
            None
        }
    };

    let stdout_reader = child.stdout.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });
    let stderr_reader = child.stderr.take().map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            buf
        })
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    join(writer);
                    join(stdout_reader);
                    join(stderr_reader);
                    return Err(RunError::Timeout {
                        elapsed_ms: start.elapsed().as_millis(),
                    });
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                join(writer);
                join(stdout_reader);
                join(stderr_reader);
                return Err(RunError::Spawn(e));
            }
        }
    };

    join(writer);
    let stdout = join(stdout_reader).unwrap_or_default();
    let stderr = join(stderr_reader).unwrap_or_default();
    Ok(ChildOutput {
        status,
        stdout,
        stderr,
    })
}

fn join<T>(handle: Option<std::thread::JoinHandle<T>>) -> Option<T> {
    handle.and_then(|h| h.join().ok())
}

// --- Process-lineage introspection for destructive-subcommand rules ---
//
// REQ-GGUARD-053 backgrounded-push detection plus REQ-GGUARD-064 / -183
// structural parent authorization (porcelain-forks `rebase` / `stash`).
// Extracted from `block.rs` to keep it within the file-length limit.
/// REQ-GGUARD-064: true only for the rebase child Git forks from a `pull`.
/// Pure decision (no process access) so it is testable and the evidence
/// requirements are explicit:
///   - `has_onto`: argv carries the `--onto` signature Git always generates;
///   - `parent_is_pull_rebase`: the parent process is the sealed real Git
///     running a `pull` (see `parent_is_pull_rebase`).
///
/// An agent-issued `git rebase` has a shell or the guard as its parent, not a
/// running `sealed/git pull`, so it can never satisfy this.
pub(crate) fn rebase_approval(has_onto: bool, parent_is_pull_rebase: bool) -> bool {
    has_onto && parent_is_pull_rebase
}

/// Git's `pull` always generates `rebase ... --onto <newbase> <upstream>` for
/// the child it forks (`run_rebase` in builtin/pull.c). Requiring the `--onto`
/// signature keeps any other nested rebase from reusing the pull authorization.
pub(crate) fn rebase_has_onto(argv_os: &[OsString]) -> bool {
    argv_os
        .iter()
        .any(|a| a.as_bytes() == b"--onto" || a.as_bytes().starts_with(b"--onto="))
}

/// REQ-GGUARD-064: authorize the rebase child only when its parent process is
/// the sealed real Git running a `pull`. Any pull may fork the rebase (an
/// explicit `--rebase`, or repo config `pull.rebase=true`), so the subcommand
/// alone is the gate; the `--onto` signature the caller separately requires
/// confines it to Git's own pull-generated rebase.
pub(crate) fn parent_is_pull_rebase() -> bool {
    parent_is_sealed_git_running(&["pull"])
}

/// REQ-GGUARD-183: true only for the `stash create`/`stash apply` child that an
/// approved porcelain (`merge`, `rebase`, `am`, or `pull`) forks to snapshot
/// and restore the working tree.
///
/// Real Git runs `git stash create` *unconditionally* for a real
/// (non-fast-forward) merge (`save_state` in `builtin/merge.c`), independent
/// of `--autostash` and `merge.autostash`, so `--no-autostash` does not avoid
/// it; `restore_state`/`apply_autostash` may later run `git stash apply`.
/// Because the guard owns the exec-path frontend, that child re-enters the
/// guard and would otherwise be blocked, deadlocking any non-fast-forward
/// merge. The child is authorized structurally, exactly like the
/// REQ-GGUARD-064 pull rebase: its parent must be the sealed real Git
/// (`root:root 0700`, which only the guard can launch) running an approved
/// porcelain, and its own verb must be Git's internal snapshot (`create`) or
/// restore (`apply`). No environment variable is consulted, so a caller cannot
/// forge it, and a caller-issued `git stash` (whose parent is a shell, not a
/// running porcelain) stays blocked.
pub(crate) fn internal_stash_approved(subcommand: &str, argv_os: &[OsString]) -> bool {
    subcommand == "stash"
        && matches!(
            stash_verb(argv_os).as_deref(),
            Some("create") | Some("apply")
        )
        && parent_is_sealed_git_running(&["merge", "rebase", "am", "pull"])
}

/// Positional operand immediately after the `stash` subcommand (its verb),
/// skipping any option tokens. `None` for a bare `git stash`.
pub(crate) fn stash_verb(argv_os: &[OsString]) -> Option<String> {
    let mut seen_stash = false;
    for arg in argv_os.iter().skip(1) {
        let s = arg.to_string_lossy();
        if !seen_stash {
            if s == "stash" {
                seen_stash = true;
            }
            continue;
        }
        if !s.starts_with('-') {
            return Some(s.into_owned());
        }
    }
    None
}

/// True only when this process's parent is the sealed real Git running one of
/// `ops`. `sealed/git` is `root:root 0700`, so only the guard (which loans
/// itself `CAP_DAC_OVERRIDE` for the exec) can launch it; the argv it is
/// launched with is the caller's already-validated command. Together those are
/// unforgeable by an agent: environment variables and argv are
/// caller-controlled, but the parent's executable is not. The check is a
/// read-only `/proc` probe; any missing or malformed file simply denies.
pub(crate) fn parent_is_sealed_git_running(ops: &[&str]) -> bool {
    let Some(ppid) = read_ppid() else {
        return false;
    };
    let Ok(exe) = fs::read_link(format!("/proc/{ppid}/exe")) else {
        return false;
    };
    if exe.as_path() != std::path::Path::new(crate::GIT_ORIGINAL_PATH) {
        return false;
    }
    let Ok(cmdline) = fs::read(format!("/proc/{ppid}/cmdline")) else {
        return false;
    };
    let args: Vec<&[u8]> = cmdline
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .collect();
    parent_argv_subcommand_in(&args, ops)
}

/// Parse a parent argv (argv[0] = program, argv[1..] = git words) and report
/// whether its subcommand is one of `ops`. Any parse failure denies.
pub(crate) fn parent_argv_subcommand_in(args: &[&[u8]], ops: &[&str]) -> bool {
    matches!(
        crate::args::parse_args(args),
        Ok(state) if state.subcommand.as_deref().is_some_and(|s| ops.contains(&s))
    )
}

/// Read this process's `PPid` from `/proc/self/status`.
pub(crate) fn read_ppid() -> Option<i32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("PPid:").and_then(|v| v.trim().parse().ok()))
}

/// Decode the process-group fields the background-push check needs from a
/// `/proc/<pid>/stat` line (REQ-GGUARD-053). `comm` (field 2) is wrapped in
/// parentheses and may itself contain spaces or `)`, so the fields are read
/// relative to the final `)`: relative index 2 is `pgrp` and relative index 5
/// is `tpgid`. Any missing delimiter, short field list, non-integer, or
/// out-of-range value is a typed failure; the caller turns it into a block.
pub(crate) fn parse_stat_process_groups(stat: &str) -> Result<(i32, i32), &'static str> {
    let close = stat.rfind(')').ok_or("missing comm delimiter")?;
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    if fields.len() <= 5 {
        return Err("too few fields after comm");
    }
    let pgrp = fields[2]
        .parse::<i32>()
        .map_err(|_| "pgrp is not an integer")?;
    let tpgid = fields[5]
        .parse::<i32>()
        .map_err(|_| "tpgid is not an integer")?;
    Ok((pgrp, tpgid))
}

/// REQ-GGUARD-053: a push is backgrounded when it has a controlling terminal
/// (`tpgid > 0`) whose foreground process group differs from the push's own.
/// `tpgid <= 0` (no controlling terminal) is treated as foreground, and the
/// decision is the same for root and non-root.
pub(crate) fn push_is_backgrounded(pgrp: i32, tpgid: i32) -> bool {
    tpgid > 0 && tpgid != pgrp
}
