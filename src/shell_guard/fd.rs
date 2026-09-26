//! fd-backed script sources and memfd staging.
//!
//! bash can be handed a script through a /proc/self/fd/N (or /dev/fd/N)
//! symlink instead of a regular path. That channel carries real,
//! scannable content (pipes, process substitution, inherited fds), so
//! it must never fall through unscanned. The only fd source accepted
//! here is this guard's own sealed staging memfd (created by
//! memfd_exec_path below); anything else returns None and the caller
//! hard-blocks the invocation.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::path::Path;
use std::process;

use nix::fcntl::{fcntl, FcntlArg, FdFlag, SealFlag};

use crate::MAX_TEXT;

pub const MEMFD_NAME: &str = "workspace-shell-guard";

/// True for script arguments that name an fd instead of a regular file.
pub fn is_fd_path(path: &str) -> bool {
    path.starts_with("/proc/self/fd/") || path.starts_with("/dev/fd/") || path == "/dev/stdin"
}

fn parse_fd(path: &str) -> Option<i32> {
    path.rsplit('/').next()?.parse().ok()
}

/// Read the body behind our own sealed staging memfd. Every
/// verification step is mandatory: readlink must name our memfd, all
/// four seals must be present, the dup must be a regular file. Any
/// failure returns None and the caller blocks the invocation.
pub fn read_staged_fd(path: &str) -> Option<Vec<u8>> {
    let target = fs::read_link(path).ok()?;
    let expected = format!("/memfd:{} (deleted)", MEMFD_NAME);
    if target != Path::new(&expected) {
        return None;
    }
    let fd = parse_fd(path)?;
    let seals = fcntl(fd, FcntlArg::F_GET_SEALS).ok()?;
    let required = SealFlag::F_SEAL_SHRINK
        | SealFlag::F_SEAL_WRITE
        | SealFlag::F_SEAL_GROW
        | SealFlag::F_SEAL_SEAL;
    if !SealFlag::from_bits_truncate(seals).contains(required) {
        return None;
    }
    // Verified: reopen through the proc-fd symlink. The kernel hands
    // us a fresh open file description for the same sealed memfd
    // (offset 0), with no unsafe fd juggling.
    let mut file = fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut buf = Vec::new();
    let mut limited = file.take((MAX_TEXT + 1) as u64);
    limited.read_to_end(&mut buf).ok()?;
    if buf.len() > MAX_TEXT {
        eprintln!("shell guard: staged script content exceeds 1 MiB limit");
        process::exit(2);
    }
    Some(buf)
}

/// Stage a scanned script body in a sealed memfd and return the
/// /proc/self/fd/N path to exec. Seals make the content immutable; the
/// fd is intentionally leaked so it survives the execve into the real
/// shell (dropping the OwnedFd would close it before exec).
pub fn memfd_exec_path(content: &[u8]) -> String {
    use rustix::fs::{memfd_create, MemfdFlags};

    // rustix safe wrapper: nix 0.29 does not expose MFD_EXEC. Flags:
    // ALLOW_SEALING is mandatory (without it the memfd is born with
    // F_SEAL_SEAL and every F_ADD_SEALS fails EPERM); EXEC keeps the
    // fd executable under vm.memfd_noexec=1 (Ubuntu 24.04).
    let name = std::ffi::CString::new(MEMFD_NAME).expect("memfd name");
    let fd = match memfd_create(
        &name,
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
    let leaked = fd.into_raw_fd();
    format!("/proc/self/fd/{}", leaked)
}
