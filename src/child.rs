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

use std::io::Read;
use std::io::Write;
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
