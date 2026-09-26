// src/yaml_edit_install.rs
//
// Atomic install layer of workspace-yaml-edit (SPEC-YAML-EDIT
// section 6): immutable-flag detection via lsattr, transient
// chattr -i inside the flock, temp file in the target directory
// (0600), chown root:root, chmod 0644, rename, chattr +i restore.
// chattr/lsattr go through the e2fsprogs binaries so this crate
// needs no unsafe ioctl FFI.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process;

use crate::ops::fail;
use crate::target::Target;

const LSATTR: &str = "/usr/bin/lsattr";
const CHATTR: &str = "/usr/bin/chattr";

pub fn is_immutable(path: &Path) -> bool {
    let out = process::Command::new(LSATTR)
        .arg("-d")
        .arg("--")
        .arg(path)
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .next()
            .is_some_and(|flags| flags.contains('i')),
        _ => fail(
            1,
            &format!("cannot establish immutable state for {}", path.display()),
        ),
    }
}

pub fn set_immutable(path: &Path, on: bool) -> Result<(), String> {
    let flag = if on { "+i" } else { "-i" };
    let st = process::Command::new(CHATTR)
        .arg(flag)
        .arg("--")
        .arg(path)
        .status()
        .map_err(|e| format!("cannot run chattr: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("chattr {flag} failed: {}", path.display()))
    }
}

pub fn install(target: &Target, content: &str) {
    let path = &target.path;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_name = OsString::from(format!(".yaml-edit.{}.tmp", process::id()));
    let tmp = dir.join(&tmp_name);
    let was_immutable = is_immutable(path);
    if was_immutable {
        set_immutable(path, false).unwrap_or_else(|e| fail(1, &e));
    }
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .unwrap_or_else(|e| {
            let _ = set_immutable_quiet(path, was_immutable);
            fail(1, &format!("temp create failed: {e}"))
        });
    f.write_all(content.as_bytes()).unwrap_or_else(|e| {
        cleanup(&tmp, path, was_immutable);
        fail(1, &format!("temp write failed: {e}"))
    });
    rustix::fs::fchown(
        &f,
        Some(rustix::fs::Uid::from_raw(target.identity.uid)),
        Some(rustix::fs::Gid::from_raw(target.identity.gid)),
    )
    .unwrap_or_else(|e| {
        cleanup(&tmp, path, was_immutable);
        fail(1, &format!("temp chown failed: {e}"))
    });
    rustix::fs::fchmod(&f, rustix::fs::Mode::from_raw_mode(target.identity.mode)).unwrap_or_else(
        |e| {
            cleanup(&tmp, path, was_immutable);
            fail(1, &format!("temp chmod failed: {e}"))
        },
    );
    f.sync_all().unwrap_or_else(|e| {
        cleanup(&tmp, path, was_immutable);
        fail(1, &format!("temp fsync failed: {e}"))
    });
    drop(f);
    target.rename_from(&tmp_name).unwrap_or_else(|e| {
        cleanup(&tmp, path, was_immutable);
        fail(1, &e)
    });
    if was_immutable {
        set_immutable(path, true).unwrap_or_else(|e| {
            fail(
                1,
                &format!(
                    "CRITICAL: {e}; edit installed but the immutable flag is LOST on {}",
                    path.display()
                ),
            )
        });
    }
}

fn set_immutable_quiet(path: &Path, on: bool) -> Result<(), String> {
    if on {
        set_immutable(path, true)
    } else {
        Ok(())
    }
}

fn cleanup(tmp: &Path, path: &Path, was_immutable: bool) {
    let _ = std::fs::remove_file(tmp);
    let _ = set_immutable_quiet(path, was_immutable);
}
