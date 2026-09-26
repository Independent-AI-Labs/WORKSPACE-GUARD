use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::GuardError;

use super::{git_output, REQUIRED_HOOKS};

pub(super) fn check_consumer_hook_identity(toplevel: &str) -> Result<(), GuardError> {
    let hooks_dir = git_output(Path::new(toplevel), &["rev-parse", "--git-path", "hooks"])
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                Path::new(toplevel).join(path)
            }
        })
        .ok_or_else(|| {
            GuardError::ContractFailed("CI integrity: cannot resolve hooks directory".into())
        })?;
    for hook in REQUIRED_HOOKS {
        let path = hooks_dir.join(hook);
        let text = fs::read_to_string(&path).map_err(|error| {
            GuardError::ContractFailed(format!(
                "CI integrity: cannot read hook {}: {error}",
                path.display()
            ))
        })?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            GuardError::ContractFailed(format!(
                "CI integrity: cannot stat hook {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(GuardError::ContractFailed(format!(
                "CI integrity: hook {} is not root-owned and protected",
                path.display()
            )));
        }
        let output = Command::new("/usr/bin/lsattr")
            .args(["-d"])
            .arg(&path)
            .output()
            .map_err(|error| {
                GuardError::ContractFailed(format!(
                    "CI integrity: cannot inspect hook flags: {error}"
                ))
            })?;
        if !output.status.success()
            || !String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .contains('i')
        {
            return Err(GuardError::ContractFailed(format!(
                "CI integrity: hook {} is not immutable",
                path.display()
            )));
        }
        if !text.contains("source /opt/workspace-ci/lib/ci.sh") {
            return Err(GuardError::ContractFailed(format!(
                "CI integrity: hook {} does not source deployed WORKSPACE-CI",
                path.display()
            )));
        }
    }
    Ok(())
}
