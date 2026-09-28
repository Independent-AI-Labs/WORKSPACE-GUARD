//! Typed child setup/exec status channel (REQ-GGUARD-121).
//!
//! The exec child reports setup or exec failure to the parent as a single
//! fixed byte over a close-on-exec pipe. A successful `execve` closes the
//! write end (the kernel applies `O_CLOEXEC`), so the parent observes EOF.
//! The child never writes diagnostic text and never chooses a public exit
//! code; the parent owns all visible diagnostics.

use std::os::fd::{AsRawFd, OwnedFd};

use nix::errno::Errno;

/// Child could not loan `CAP_DAC_OVERRIDE` to git.original.
pub const CHILD_SETUP_CAP_FAIL: u8 = 1;
/// `execve(git.original)` failed.
pub const CHILD_SETUP_EXEC_FAIL: u8 = 2;

/// Child exit code after a reported setup failure. The parent ignores it and
/// uses the typed pipe status instead; 127 keeps the bare observation sane.
pub const CHILD_SETUP_EXIT: i32 = 127;

/// Typed parent-side view of the child setup channel.
pub enum ChildStatus {
    /// EOF: git.original executed and the kernel closed the close-on-exec pipe.
    Executed,
    /// CAP_DAC_OVERRIDE could not be loaned to the child.
    CapFailed,
    /// `execve(git.original)` failed.
    ExecFailed,
}

/// Read the one-shot child setup status. Retries on `EINTR`; any unreadable
/// status is treated as an exec failure so the guard still fails closed.
pub fn read_child_status(fd: &OwnedFd) -> ChildStatus {
    let mut buf = [0u8; 1];
    loop {
        match nix::unistd::read(fd.as_raw_fd(), &mut buf) {
            Ok(0) => return ChildStatus::Executed,
            Ok(_) => {
                return match buf[0] {
                    CHILD_SETUP_CAP_FAIL => ChildStatus::CapFailed,
                    _ => ChildStatus::ExecFailed,
                }
            }
            Err(Errno::EINTR) => continue,
            Err(_) => return ChildStatus::ExecFailed,
        }
    }
}
