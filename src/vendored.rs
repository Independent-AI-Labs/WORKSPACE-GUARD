use std::fs;
use std::os::linux::fs::MetadataExt;
use std::path::Path;

use crate::ENFORCEMENT_CONFIG;

fn root_owned_regular(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(meta) => meta.is_file() && meta.st_uid() == 0,
        Err(_) => false,
    }
}

/// Test seam: unit tests write enforcement fixtures as the test user, so
/// the ownership gate is compiled out under cfg(test). Production builds
/// always enforce it.
fn enforcement_file_trusted(path: &Path) -> bool {
    #[cfg(test)]
    {
        let _ = path;
        true
    }
    #[cfg(not(test))]
    {
        root_owned_regular(path)
    }
}

pub fn check_vendored_tier_bypass(wsroot: &str, toplevel: &str) -> bool {
    let enforce_path = Path::new(wsroot).join(ENFORCEMENT_CONFIG);
    if !enforce_path.exists() {
        return false;
    }
    if !enforcement_file_trusted(&enforce_path) {
        return false;
    }
    let content = match fs::read_to_string(&enforce_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let rel_path = match toplevel.strip_prefix(wsroot) {
        Some(stripped) => stripped.trim_start_matches('/'),
        None => toplevel,
    };

    let mut in_exemptions = false;
    let mut current_path: Option<String> = None;
    let mut current_tier: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "exemptions:" {
            in_exemptions = true;
            current_path = None;
            current_tier = None;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if in_exemptions && !trimmed.starts_with('-') && !trimmed.contains(':') {
            continue;
        }
        if in_exemptions
            && !trimmed.starts_with('-')
            && !trimmed.starts_with("path:")
            && !trimmed.starts_with("tier:")
            && !trimmed.starts_with("reason:")
        {
            in_exemptions = false;
            current_path = None;
            current_tier = None;
            continue;
        }
        if !in_exemptions {
            continue;
        }

        let entry_line = match trimmed.strip_prefix("- ") {
            Some(s) => s,
            None => trimmed,
        };

        if let Some(stripped) = entry_line.strip_prefix("tier:") {
            let val = stripped.trim();
            let val = val.trim_matches(|c| c == '"' || c == '\'');
            let val = val.split('#').next().unwrap_or(val).trim();
            current_tier = Some(val.to_lowercase());
        }
        if let Some(stripped) = entry_line.strip_prefix("path:") {
            current_path = Some(stripped.trim().to_string());
        }

        if current_path.is_some() && current_tier.is_some() {
            let path_val = current_path.as_deref().unwrap();
            if (rel_path.starts_with(path_val.trim_end_matches('/')) || path_val == rel_path)
                && current_tier.as_deref() == Some("vendored")
            {
                return true;
            }
            current_path = None;
            current_tier = None;
        }
    }

    if let (Some(path_val), Some(tier)) = (current_path.as_deref(), current_tier.as_deref()) {
        if (rel_path.starts_with(path_val.trim_end_matches('/')) || path_val == rel_path)
            && tier == "vendored"
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
#[path = "vendored_tests.rs"]
mod tests;
