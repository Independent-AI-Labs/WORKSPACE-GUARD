// Build-time validation for config/git_guard_protected_branches.yaml
// (REQ-GGUARD-060). Kept out of build.rs to hold that file under the
// 512-line limit; pulled in as `mod protected_branches`.

use super::ProtectedBranchesConfig;

/// Conservative `git check-ref-format` subset for a single branch name,
/// reimplemented here so the build never shells out to Git.
fn valid_branch_name(name: &str) -> bool {
    if name.is_empty() || !name.is_ascii() || name == "@" {
        return false;
    }
    if name.starts_with('/') || name.ends_with('/') || name.ends_with('.') {
        return false;
    }
    if name.contains("..") || name.contains("@{") || name.ends_with(".lock") {
        return false;
    }
    let forbidden = [' ', '~', '^', ':', '?', '*', '[', '\\'];
    if name
        .chars()
        .any(|c| c.is_ascii_control() || forbidden.contains(&c))
    {
        return false;
    }
    name.split('/')
        .all(|component| !component.is_empty() && !component.starts_with('.'))
}

/// Reject empty, non-ASCII, non-canonical-lowercase, invalid ref-name, or
/// case-insensitive duplicate exact/prefix entries at build time.
pub fn validate(cfg: &ProtectedBranchesConfig) {
    assert!(
        !cfg.branches.is_empty() && !cfg.prefixes.is_empty(),
        "build.rs: git_guard_protected_branches.yaml needs non-empty branches and prefixes"
    );
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for name in &cfg.branches {
        assert!(
            name.is_ascii(),
            "build.rs: protected branch {:?} must be ASCII",
            name
        );
        assert!(
            name == &name.to_ascii_lowercase(),
            "build.rs: protected branch {:?} must be canonical lowercase",
            name
        );
        assert!(
            valid_branch_name(name),
            "build.rs: protected branch {:?} is not a valid branch name",
            name
        );
        assert!(
            seen.insert(name.as_str()),
            "build.rs: protected branch {:?} is a duplicate",
            name
        );
    }
    let mut seen_prefixes: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for prefix in &cfg.prefixes {
        assert!(
            prefix.is_ascii() && prefix.ends_with('/'),
            "build.rs: protected prefix {:?} must be ASCII and end with '/'",
            prefix
        );
        assert!(
            prefix == &prefix.to_ascii_lowercase(),
            "build.rs: protected prefix {:?} must be canonical lowercase",
            prefix
        );
        let stem = prefix.trim_end_matches('/');
        assert!(
            valid_branch_name(stem),
            "build.rs: protected prefix {:?} does not name a valid branch namespace",
            prefix
        );
        assert!(
            seen_prefixes.insert(prefix.as_str()),
            "build.rs: protected prefix {:?} is a duplicate",
            prefix
        );
    }
}
