// src/yaml_edit_install.rs
//
// Atomic install layer of workspace-yaml-edit (SPEC-YAML-EDIT
// section 6): immutable-flag detection via lsattr, transient
// chattr -i inside the flock, temp file in the target directory
// (0600), chown root:root, chmod 0644, rename, chattr +i restore.
// chattr/lsattr go through the e2fsprogs binaries so this crate
// needs no unsafe ioctl FFI.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process;

use crate::yaml_edit_ops::fail;

pub fn is_immutable(path: &Path) -> bool {
    let out = process::Command::new("lsattr")
        .arg("-d")
        .arg("--")
        .arg(path)
        .output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .next()
            .is_some_and(|flags| flags.contains('i')),
        _ => {
            eprintln!(
                "yaml-edit: NOTICE: cannot read attributes of {}; treating as non-immutable",
                path.display()
            );
            false
        }
    }
}

pub fn set_immutable(path: &Path, on: bool) -> Result<(), String> {
    let flag = if on { "+i" } else { "-i" };
    let st = process::Command::new("chattr")
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

pub fn install(path: &Path, content: &str) {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(".yaml-edit.{}.tmp", process::id()));
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
    drop(f);
    nix::unistd::chown(
        &tmp,
        Some(nix::unistd::Uid::from_raw(0)),
        Some(nix::unistd::Gid::from_raw(0)),
    )
    .unwrap_or_else(|e| {
        cleanup(&tmp, path, was_immutable);
        fail(1, &format!("temp chown failed: {e}"))
    });
    let mut perms = std::fs::metadata(&tmp)
        .unwrap_or_else(|e| {
            cleanup(&tmp, path, was_immutable);
            fail(1, &format!("temp stat failed: {e}"))
        })
        .permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o644);
    std::fs::set_permissions(&tmp, perms).unwrap_or_else(|e| {
        cleanup(&tmp, path, was_immutable);
        fail(1, &format!("temp chmod failed: {e}"))
    });
    std::fs::rename(&tmp, path).unwrap_or_else(|e| {
        cleanup(&tmp, path, was_immutable);
        fail(1, &format!("rename failed: {e}"))
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
