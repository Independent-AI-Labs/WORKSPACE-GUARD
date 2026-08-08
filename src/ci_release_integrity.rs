use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn active_release_violations(wsroot: &Path) -> Vec<String> {
    let mut violations = Vec::new();
    let active = wsroot.join("projects/CI");
    let releases = wsroot.join("projects/CI.releases");
    let active_meta = match fs::symlink_metadata(&active) {
        Ok(meta) => meta,
        Err(_) => {
            violations.push(format!(
                "{}: active CI selector is missing",
                active.display()
            ));
            return violations;
        }
    };
    if !active_meta.file_type().is_symlink() {
        violations.push(format!(
            "{}: active CI path is not an atomic release selector",
            active.display()
        ));
        return violations;
    }
    if active_meta.uid() != 0 {
        violations.push(format!(
            "{}: active selector owned by uid {} (expected 0)",
            active.display(),
            active_meta.uid()
        ));
    }
    let release = match fs::canonicalize(&active) {
        Ok(path) => path,
        Err(error) => {
            violations.push(format!(
                "{}: selector target is invalid: {error}",
                active.display()
            ));
            return violations;
        }
    };
    let releases_root = match fs::canonicalize(&releases) {
        Ok(path) => path,
        Err(error) => {
            violations.push(format!(
                "{}: release root is invalid: {error}",
                releases.display()
            ));
            return violations;
        }
    };
    if !release.starts_with(&releases_root) {
        violations.push(format!(
            "{}: selector escapes {}",
            active.display(),
            releases.display()
        ));
        return violations;
    }
    let release_meta = match fs::symlink_metadata(&release) {
        Ok(meta) => meta,
        Err(error) => {
            violations.push(format!(
                "{}: selected release is unavailable: {error}",
                release.display()
            ));
            return violations;
        }
    };
    if release_meta.uid() != 0 || release_meta.gid() != 0 {
        violations.push(format!(
            "{}: selected release is not root-owned",
            release.display()
        ));
    }
    if release_meta.permissions().mode() & 0o022 != 0 {
        violations.push(format!(
            "{}: selected release is group/world writable",
            release.display()
        ));
    }
    let id = release
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !id.starts_with("sha256-")
        || id.len() != 71
        || !id[7..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        violations.push(format!(
            "{}: selected release has invalid identity",
            release.display()
        ));
    }
    let manifest_path = release.join("generation.json");
    let manifest = match fs::read_to_string(&manifest_path) {
        Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(value) => value,
            Err(error) => {
                violations.push(format!(
                    "{}: invalid generation manifest: {error}",
                    manifest_path.display()
                ));
                return violations;
            }
        },
        Err(error) => {
            violations.push(format!(
                "{}: generation manifest missing: {error}",
                manifest_path.display()
            ));
            return violations;
        }
    };
    if manifest.get("generation_id").and_then(|v| v.as_str()) != Some(id) {
        violations.push(format!(
            "{}: manifest identity mismatch",
            manifest_path.display()
        ));
    }
    if manifest
        .get("tree_digest")
        .and_then(|v| v.as_str())
        .is_none()
        && manifest
            .get("generation_digest")
            .and_then(|v| v.as_str())
            .is_none()
    {
        violations.push(format!(
            "{}: manifest has no release digest",
            manifest_path.display()
        ));
    } else if let Some(expected) = manifest
        .get("tree_digest")
        .or_else(|| manifest.get("generation_digest"))
        .and_then(|v| v.as_str())
    {
        match release_tree_digest(&release) {
            Ok(actual) if actual == expected => {}
            Ok(actual) => violations.push(format!(
                "{}: release digest mismatch (expected {}, got {})",
                release.display(),
                expected,
                actual
            )),
            Err(error) => violations.push(format!(
                "{}: cannot verify release digest: {error}",
                release.display()
            )),
        }
    }
    if let Some(expected) = manifest
        .get("required_hooks_digest")
        .and_then(|v| v.as_str())
    {
        let hooks = release.join("config/required_hooks.yaml");
        match fs::read(&hooks) {
            Ok(bytes) => {
                let actual = format!("{:x}", Sha256::digest(bytes));
                if actual != expected {
                    violations.push(format!(
                        "{}: required hook manifest digest mismatch",
                        hooks.display()
                    ));
                }
            }
            Err(error) => violations.push(format!(
                "{}: required hook manifest unavailable: {error}",
                hooks.display()
            )),
        }
    }
    violations
}

fn release_tree_digest(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_release_files(root, root, &mut files)?;
    files.sort();
    let mut digest = Sha256::new();
    for relative in files {
        let path = root.join(&relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        digest.update(relative.as_os_str().as_encoded_bytes());
        digest.update([0]);
        digest.update(metadata.permissions().mode().to_le_bytes());
        digest.update([0]);
        digest.update(fs::read(&path).map_err(|error| error.to_string())?);
        digest.update([0]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn collect_release_files(root: &Path, path: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let mut entries = fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!("symlink in release: {}", entry_path.display()));
        }
        if metadata.is_dir() {
            collect_release_files(root, &entry_path, files)?;
        } else if metadata.is_file() && entry.file_name() != "generation.json" {
            files.push(
                entry_path
                    .strip_prefix(root)
                    .map_err(|error| error.to_string())?
                    .to_path_buf(),
            );
        } else if !metadata.is_file() {
            return Err(format!(
                "unsupported file in release: {}",
                entry_path.display()
            ));
        }
    }
    Ok(())
}
