//! The single reviewed unsafe boundary for the guard (REQ-GGUARD-121).
//!
//! Every production `unsafe` block in `workspace-guard` lives here. The crate
//! root carries `#![deny(unsafe_code)]`; only this module is exempted, via a
//! module-local `#[allow(unsafe_code)]` on its `mod` declaration, and only for
//! the approved operations below. Nothing else in the crate may call `libc`
//! directly. Each block documents its own `// SAFETY:` contract: pointer
//! validity, alignment, lifetime, accepted values, return/error
//! interpretation, and post-fork restrictions.

use std::io;
#[cfg(feature = "capability-mode")]
use std::os::fd::{AsRawFd, BorrowedFd};

/// Linux `FS_IOC_GETFLAGS` reads the inode flags word as an `int` (`fs.h`).
/// Only the capability build reconciles inode flags.
#[cfg(feature = "capability-mode")]
pub fn immutable_flags(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut flags: libc::c_int = 0;
    // SAFETY: FS_IOC_GETFLAGS requires an `int *` as its third argument.
    // `flags` is a live, properly aligned `c_int` whose address is passed by
    // mutable reference for the duration of the call; the kernel writes
    // exactly `sizeof(c_int)` bytes. `fd` is borrowed for the call and is only
    // read, never closed or transferred. No arbitrary ioctl command is
    // accepted by this wrapper.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags as u32)
}

/// Read the AT_SECURE auxv flag set by the kernel at `exec(2)`.
///
/// Returns the raw value: non-zero means secure-execution mode (setuid or
/// setgid at exec). `nix 0.29` exposes no `getauxval` wrapper.
pub fn at_secure() -> usize {
    // SAFETY: getauxval(3) reads the process auxiliary vector, a
    // kernel-populated in-memory array that exists for the life of the process
    // and is never mutated by user code. `AT_SECURE` is a libc integer
    // constant naming a well-known key. No pointer is passed in or out; the
    // return is an unsigned long with no nullability or lifetime concern.
    unsafe { libc::getauxval(libc::AT_SECURE) as usize }
}

/// Fork the process, returning `Ok(None)` in the child and `Ok(Some(pid))` in
/// the parent. `Err` carries the OS error (e.g. `EAGAIN`).
///
/// The guard is single-threaded by construction. The child must obey the
/// post-fork contract: only async-signal-safe work before `execve`, and no
/// allocation, locks, formatting, unwinding, or destructors. The child path in
/// `exec.rs` calls only `raise_child_dac_override`, `nix::unistd::write`,
/// `nix::unistd::execve`, and [`exit_now`], all of which satisfy that rule.
pub fn fork() -> io::Result<Option<i32>> {
    // SAFETY: libc::fork has no safe nix substitute that preserves the exact
    // fork-without-atfork-handler semantics the guard depends on. The process
    // is single-threaded, so the child sees a consistent address space. The
    // child branch performs only the async-signal-safe calls listed above;
    // this is the contract the whole module exists to localise.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        Err(io::Error::last_os_error())
    } else if pid == 0 {
        Ok(None)
    } else {
        Ok(Some(pid))
    }
}

/// Terminate the calling process immediately, without running destructors,
/// `atexit` handlers, or buffered I/O. Only valid in a freshly forked child.
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit(2) is async-signal-safe and never returns. It deliberately
    // skips Rust's exit machinery; std::process::exit and Drop are forbidden
    // after fork, so this is the only correct child exit path. nix exposes no
    // _exit wrapper.
    unsafe { libc::_exit(code) }
}
