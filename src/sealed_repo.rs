//! Sealed-repository gate: refuse git write subcommands for non-root
//! callers in any repo whose .git carries the immutable flag.

use std::path::Path;

use crate::GuardError;

/// Subcommands permitted against a sealed (chattr +i) repository for
/// non-root callers: pure read operations only. Everything else mutates
/// refs, index, worktree, or config and must not run while the
/// deployment mirror is sealed.
#[cfg(feature = "capability-mode")]
pub const SEALED_REPO_READONLY: &[&str] = &[
    "blame",
    "cat-file",
    "count-objects",
    "describe",
    "diff",
    "grep",
    "log",
    "ls-files",
    "ls-tree",
    "name-rev",
    "rev-list",
    "rev-parse",
    "shortlog",
    "show",
    "show-branch",
    "status",
    "var",
];

/// Pure decision for the sealed-repo gate: Some(error) when a non-root
/// caller attempts a write subcommand against an immutable repository.
#[cfg(feature = "capability-mode")]
pub fn sealed_repo_violation(
    subcommand: &str,
    operator_root: bool,
    sealed: bool,
) -> Option<GuardError> {
    if operator_root || !sealed || SEALED_REPO_READONLY.contains(&subcommand) {
        return None;
    }
    Some(GuardError::Blocked {
        reason: format!("sealed repository (immutable): git {}", subcommand),
        hint: "Repository is sealed (chattr +i). Operator: unseal via 'lock-repo --unseal' or run deploy-ci".into(),
    })
}

/// Block non-root git write operations against a sealed repository
/// (immutable .git, e.g. the projects/CI deployment mirror). Root-owned
/// alone is not the discriminator: capability-mode locking root-owns
/// .git metadata in every repo. The immutable flag is set only by
/// lock-repo sealing, so it precisely marks no-agent-write repos.
#[cfg(feature = "capability-mode")]
pub fn check_sealed_repo(subcommand: &str, git_dir: &Path) -> Result<(), GuardError> {
    let sealed = crate::reconcile::immutable_flag(git_dir) == Some(true);
    match sealed_repo_violation(subcommand, crate::is_config_privileged(), sealed) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
#[path = "sealed_repo_tests.rs"]
mod tests;
