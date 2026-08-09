use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::GuardError;

use super::{git_output, REQUIRED_HOOKS};

pub(super) fn check_consumer_hook_identity(
    toplevel: &str,
    wsroot: &Path,
) -> Result<(), GuardError> {
    let active = fs::canonicalize(wsroot.join("projects/CI")).map_err(|error| {
        GuardError::ContractFailed(format!("CI integrity: cannot resolve active CI: {error}"))
    })?;
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(active.join("generation.json")).map_err(|error| {
            GuardError::ContractFailed(format!(
                "CI integrity: cannot read active manifest: {error}"
            ))
        })?,
    )
    .map_err(|error| {
        GuardError::ContractFailed(format!("CI integrity: invalid active manifest: {error}"))
    })?;
    let expected = [
        (
            "CI_DEPLOY_GENERATION",
            manifest
                .get("generation_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        ),
        (
            "CI_DEPLOY_MANIFEST_SHA256",
            manifest
                .get("manifest_digest")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        ),
        (
            "CI_REQUIRED_HOOKS_SHA256",
            manifest
                .get("required_hooks_digest")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        ),
        (
            "CI_HOOK_ABI",
            manifest
                .get("hook_abi")
                .and_then(|v| v.as_u64())
                .map(|v| v.to_string()),
        ),
    ];
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
        if text.contains("WORKSPACE-CI/lib/") {
            return Err(GuardError::ContractFailed(format!(
                "CI integrity: hook {} sources agent-writable WORKSPACE-CI",
                path.display()
            )));
        }
        for (name, value) in &expected {
            let Some(value) = value else {
                return Err(GuardError::ContractFailed(
                    "CI integrity: active manifest lacks hook identity".into(),
                ));
            };
            if !text.contains(&format!("{name}: {value}"))
                && !text.contains(&format!("{name}={value}"))
            {
                return Err(GuardError::ContractFailed(format!(
                    "CI integrity: hook {} has mismatched {name}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}
