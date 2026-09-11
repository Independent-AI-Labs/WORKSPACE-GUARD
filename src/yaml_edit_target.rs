use rustix::fs::{AtFlags, Mode, OFlags};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy)]
pub struct Identity {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub len: u64,
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub ctime: i64,
    pub ctime_nsec: i64,
}

impl Identity {
    fn from_meta(md: &std::fs::Metadata) -> Self {
        Self {
            dev: md.dev(),
            ino: md.ino(),
            uid: md.uid(),
            gid: md.gid(),
            mode: md.mode() & 0o7777,
            len: md.len(),
            mtime: md.mtime(),
            mtime_nsec: md.mtime_nsec(),
            ctime: md.ctime(),
            ctime_nsec: md.ctime_nsec(),
        }
    }

    fn stable_eq(self, other: Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.len == other.len
            && self.mtime == other.mtime
            && self.mtime_nsec == other.mtime_nsec
            && self.ctime == other.ctime
            && self.ctime_nsec == other.ctime_nsec
    }
}

pub struct Target {
    pub path: PathBuf,
    pub parent: File,
    pub file: File,
    pub name: OsString,
    pub identity: Identity,
}

fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(format!(
            "refusing parent-directory traversal: {}",
            path.display()
        ));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|p| p.join(path))
            .map_err(|e| format!("cannot read current directory: {e}"))
    }
}

pub fn is_deployed_ci_path(path: &Path) -> bool {
    path.starts_with("/opt")
}

impl Target {
    pub fn open(path: &Path, mutation: bool) -> Result<Self, String> {
        let abs = absolute(path)?;
        let md = std::fs::symlink_metadata(&abs)
            .map_err(|_| format!("file not found: {}", path.display()))?;
        if md.file_type().is_symlink() {
            return Err(format!("refusing symlink: {}", path.display()));
        }
        if !md.is_file() {
            return Err(format!("not a regular file: {}", path.display()));
        }
        let canonical = std::fs::canonicalize(&abs)
            .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
        if canonical != abs {
            return Err(format!("refusing symlinked path: {}", path.display()));
        }
        if mutation && canonical.starts_with("/opt") {
            return Err(format!("refusing mutation under /opt: {}", path.display()));
        }
        if mutation && is_deployed_ci_path(&canonical) {
            return Err(format!(
                "refusing deployed CI artifact path: {}; use the release control plane",
                path.display()
            ));
        }
        if mutation && (md.uid() != 0 || md.gid() != 0) {
            return Err(format!(
                "refusing non-root-owned file ({}:{}): {}",
                md.uid(),
                md.gid(),
                path.display()
            ));
        }
        let parent_path = canonical
            .parent()
            .ok_or_else(|| "target has no parent".to_string())?;
        let name = canonical
            .file_name()
            .ok_or_else(|| "target has no basename".to_string())?
            .to_os_string();
        let parent = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent_path)
            .map_err(|e| format!("cannot open parent {}: {e}", parent_path.display()))?;
        let fd = rustix::fs::openat(
            &parent,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            format!(
                "cannot open {} without following symlinks: {e}",
                path.display()
            )
        })?;
        let file = File::from(fd);
        let identity = Identity::from_meta(
            &file
                .metadata()
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?,
        );
        if identity.dev != md.dev() || identity.ino != md.ino() {
            return Err(format!("target changed during open: {}", path.display()));
        }
        Ok(Self {
            path: canonical,
            parent,
            file,
            name,
            identity,
        })
    }

    pub fn read_string(&self) -> Result<String, String> {
        let mut file = self
            .file
            .try_clone()
            .map_err(|e| format!("cannot clone {}: {e}", self.path.display()))?;
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .map_err(|e| format!("cannot read {}: {e}", self.path.display()))?;
        Ok(raw)
    }

    pub fn check_stable(&self) -> Result<(), String> {
        let current = Identity::from_meta(
            &self
                .file
                .metadata()
                .map_err(|e| format!("cannot restat {}: {e}", self.path.display()))?,
        );
        if !self.identity.stable_eq(current) {
            return Err(format!(
                "file changed during operation: {}",
                self.path.display()
            ));
        }
        self.check_identity()
    }

    pub fn check_identity(&self) -> Result<(), String> {
        let at = rustix::fs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("cannot restat path {}: {e}", self.path.display()))?;
        if at.st_dev as u64 != self.identity.dev || at.st_ino as u64 != self.identity.ino {
            return Err(format!(
                "path changed during operation: {}",
                self.path.display()
            ));
        }
        Ok(())
    }

    pub fn refresh_identity(&mut self) -> Result<(), String> {
        self.check_identity()?;
        self.identity = Identity::from_meta(
            &self
                .file
                .metadata()
                .map_err(|e| format!("cannot restat {}: {e}", self.path.display()))?,
        );
        Ok(())
    }

    pub fn rename_from(&self, temp_name: &OsStr) -> Result<(), String> {
        self.check_identity()?;
        rustix::fs::renameat(&self.parent, temp_name, &self.parent, &self.name)
            .map_err(|e| format!("rename failed: {e}"))?;
        self.parent
            .sync_all()
            .map_err(|e| format!("parent fsync failed: {e}"))
    }

    pub fn unlink(&self) -> Result<(), String> {
        self.check_stable()?;
        rustix::fs::unlinkat(&self.parent, &self.name, AtFlags::empty())
            .map_err(|e| format!("delete failed: {e}"))?;
        self.parent
            .sync_all()
            .map_err(|e| format!("parent fsync failed: {e}"))
    }
}

pub fn normalize_terminal(content: &str) -> String {
    let trimmed = content.trim_end_matches(['\n', '\r', ' ', '\t']);
    format!("{trimmed}\n")
}

#[cfg(test)]
mod tests {
    use super::{normalize_terminal, Target};
    use std::io::Write;

    #[test]
    fn terminal_normalization_emits_one_newline() {
        for raw in ["a: 1", "a: 1\n", "a: 1\n\n", "a: 1\n \t\n"] {
            assert_eq!(normalize_terminal(raw), "a: 1\n");
        }
    }

    #[test]
    fn concurrent_path_replacement_cannot_be_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "value: 1\n").expect("write");
        let target = Target::open(&path, false).expect("open target");
        let replacement = dir.path().join("replacement.yaml");
        let mut file = std::fs::File::create(&replacement).expect("replacement");
        file.write_all(b"value: 2\n").expect("write replacement");
        std::fs::rename(&replacement, &path).expect("replace");
        assert!(target.unlink().is_err());
        assert_eq!(
            std::fs::read_to_string(&path).expect("replacement remains"),
            "value: 2\n"
        );
    }
}
