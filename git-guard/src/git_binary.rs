//! Real-Git binary verification (REQ-GGUARD-006, REQ-GGUARD-103).
//!
//! `/usr/bin/git.original` is the trusted real Git the guard execs after a
//! policy pass. It must be inspected without following symlinks and must be
//! exactly `root:root` mode `0700` with no special bits, and must not be the
//! running guard itself. Any failure is a guard-unavailable condition (the
//! caller maps `GitOriginalMissing` / `GitOriginalBadPerms` to exit 3).

use std::fs;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use crate::GuardError;

const GIT_ORIGINAL_MODE: u32 = 0o700;

/// Outcome of classifying candidate real-Git metadata. Pure so every
/// ownership/mode combination is testable without a privileged fixture.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GitOriginalCheck {
    Ok,
    Missing,
    BadPerms,
}

/// Classify a candidate real-Git file from its no-follow metadata.
///
/// `file_type_ok` is false for anything but a regular file (missing,
/// symlink, directory, device). Ownership must be exactly uid 0 and gid 0,
/// and the full permission word (including setuid/setgid/sticky) must be
/// exactly `0700`.
pub(crate) fn classify_git_original(
    file_type_ok: bool,
    uid: u32,
    gid: u32,
    mode: u32,
) -> GitOriginalCheck {
    if !file_type_ok {
        return GitOriginalCheck::Missing;
    }
    if uid != 0 || gid != 0 {
        return GitOriginalCheck::BadPerms;
    }
    if mode & 0o7777 != GIT_ORIGINAL_MODE {
        return GitOriginalCheck::BadPerms;
    }
    GitOriginalCheck::Ok
}

/// Verify the installed real Git at the fixed path.
pub(crate) fn verify_git_original() -> Result<(), GuardError> {
    verify_git_original_at(Path::new(crate::GIT_ORIGINAL_PATH))
}

/// Verify a candidate real-Git path without following symlinks.
pub(crate) fn verify_git_original_at(path: &Path) -> Result<(), GuardError> {
    let meta = fs::symlink_metadata(path).map_err(|_| GuardError::GitOriginalMissing)?;
    match classify_git_original(meta.is_file(), meta.st_uid(), meta.st_gid(), meta.st_mode()) {
        GitOriginalCheck::Ok => {
            if is_guard_binary(path) {
                eprintln!(
                    "FATAL: /usr/bin/git.original is the guard itself, not real git. \
                     Restore: apt install --reinstall git"
                );
                return Err(GuardError::GitOriginalMissing);
            }
            Ok(())
        }
        GitOriginalCheck::Missing => Err(GuardError::GitOriginalMissing),
        GitOriginalCheck::BadPerms => Err(GuardError::GitOriginalBadPerms),
    }
}

/// True when `path` IS the running guard binary itself: same device and
/// inode as `/proc/self/exe`. Uses no-follow metadata for the candidate so
/// a symlink cannot masquerade as the guard (or as real Git).
pub(crate) fn is_guard_binary(path: &Path) -> bool {
    let target = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    // /proc/self/exe is itself a magic symlink, so its metadata must be
    // followed to identify the running executable's inode.
    let self_meta = match fs::metadata("/proc/self/exe") {
        Ok(m) => m,
        Err(_) => return false,
    };
    target.st_dev() == self_meta.st_dev() && target.st_ino() == self_meta.st_ino()
}

#[cfg(test)]
mod tests {
    use super::{classify_git_original, verify_git_original_at, GitOriginalCheck};
    use std::fs;

    #[test]
    fn valid_root_owned_regular_0700_is_ok() {
        assert_eq!(
            classify_git_original(true, 0, 0, 0o100_700),
            GitOriginalCheck::Ok
        );
    }

    #[test]
    fn non_regular_file_is_missing() {
        assert_eq!(
            classify_git_original(false, 0, 0, 0o100_700),
            GitOriginalCheck::Missing
        );
    }

    #[test]
    fn wrong_uid_or_gid_is_bad_perms() {
        assert_eq!(
            classify_git_original(true, 1000, 0, 0o100_700),
            GitOriginalCheck::BadPerms
        );
        assert_eq!(
            classify_git_original(true, 0, 1000, 0o100_700),
            GitOriginalCheck::BadPerms
        );
    }

    #[test]
    fn every_relaxed_permission_class_and_special_bit_is_rejected() {
        for mode in [
            0o100_777, // group/other rwx
            0o100_770, // group rwx
            0o100_704, // other read
            0o100_740, // group read
            0o104_700, // setuid
            0o102_700, // setgid
            0o101_700, // sticky
            0o100_600, // owner loses exec
        ] {
            assert_eq!(
                classify_git_original(true, 0, 0, mode),
                GitOriginalCheck::BadPerms,
                "mode {mode:o} must be rejected"
            );
        }
    }

    #[test]
    fn missing_path_is_git_original_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(verify_git_original_at(&dir.path().join("nope")).is_err());
    }

    #[test]
    fn symlink_and_directory_are_rejected_no_follow() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(verify_git_original_at(dir.path()).is_err());

        let real = dir.path().join("real");
        fs::write(&real, b"x").expect("write");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(verify_git_original_at(&link).is_err());
    }
}
