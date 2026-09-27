//! Workspace-root detection.
//!
//! Identity comes from a root-owned record written at install time under
//! `/usr/lib/workspace-guard`. The guard does not infer the workspace root
//! from markers in the agent-writable tree: a marker can be forged or
//! deleted by the agent, and requiring one made the guard's own identity
//! test depend on a file that exists only to be bypassed. The record
//! cannot be forged or removed by the agent, and an absent or empty
//! record means "not a workspace".

use std::path::Path;

const WORKSPACE_ROOT_RECORD: &str = "/usr/lib/workspace-guard/workspace-root";

pub enum WorkspaceRoot {
    /// The recorded root, which contains the queried path.
    Full(String),
    /// No record, or the queried path is outside the recorded root.
    None,
}

pub fn classify_workspace_root(candidate: &str) -> WorkspaceRoot {
    classify_against(recorded_workspace_root().as_deref(), candidate)
}

/// Pure classifier against an explicit root, so tests need no filesystem
/// and no real installation.
pub fn classify_against(root: Option<&str>, candidate: &str) -> WorkspaceRoot {
    match root {
        Some(root) if is_within(root, candidate) => WorkspaceRoot::Full(root.to_string()),
        _ => WorkspaceRoot::None,
    }
}

/// True when `candidate` sits at or under the recorded workspace root.
#[cfg(feature = "capability-mode")]
pub fn is_workspace_path(candidate: &str) -> bool {
    matches!(classify_workspace_root(candidate), WorkspaceRoot::Full(_))
}

fn recorded_workspace_root() -> Option<String> {
    let raw = std::fs::read_to_string(WORKSPACE_ROOT_RECORD).ok()?;
    let root = raw.trim();
    if root.is_empty() {
        None
    } else {
        Some(root.to_string())
    }
}

fn is_within(root: &str, candidate: &str) -> bool {
    let root = Path::new(root);
    let candidate = Path::new(candidate);
    candidate == root || candidate.starts_with(root)
}
