use crate::WORKSPACE_MARKERS;

/// Single ancestor walk that classifies `toplevel` in ONE pass.
/// Previously callers ran find_workspace_root (up to N levels x 3
/// marker stats) and, on failure, find_partial_workspace_root (the
/// same walk again). Both results come out of one traversal here.
pub enum WorkspaceRoot {
    /// All markers present at this level.
    Full(String),
    /// Some but not all markers present (possible marker tampering).
    Partial(String),
    None,
}

pub fn classify_workspace_root(toplevel: &str) -> WorkspaceRoot {
    let mut cur = std::path::PathBuf::from(toplevel);
    let mut first_partial: Option<String> = None;
    loop {
        let mut hits = 0usize;
        for m in WORKSPACE_MARKERS {
            if cur.join(m).exists() {
                hits += 1;
            }
        }
        if hits == WORKSPACE_MARKERS.len() {
            // A full match anywhere up the tree takes precedence over a
            // partial seen at a lower level (matches the original
            // find-then-find-partial call order in exec.rs).
            return WorkspaceRoot::Full(cur.to_string_lossy().to_string());
        }
        if hits > 0 && first_partial.is_none() {
            first_partial = Some(cur.to_string_lossy().to_string());
        }
        if !cur.pop() {
            return match first_partial {
                Some(p) => WorkspaceRoot::Partial(p),
                None => WorkspaceRoot::None,
            };
        }
    }
}

/// Thin wrapper kept for callers that only want the full-marker case.
/// Currently used only by tests; exec.rs uses classify_workspace_root.
#[allow(dead_code)]
pub fn find_workspace_root(toplevel: &str) -> Option<String> {
    match classify_workspace_root(toplevel) {
        WorkspaceRoot::Full(p) => Some(p),
        _ => None,
    }
}

// Audit C6: a directory matching SOME but not all markers is a workspace
// root with missing pieces (e.g. an agent-deletable marker removed to
// stop the contract checks). Callers must fail closed on partials.
// Used by gitdir.rs (capability-mode only) and by tests.
#[cfg(any(test, feature = "capability-mode"))]
pub fn find_partial_workspace_root(toplevel: &str) -> Option<String> {
    match classify_workspace_root(toplevel) {
        WorkspaceRoot::Partial(p) | WorkspaceRoot::Full(p) => Some(p),
        WorkspaceRoot::None => None,
    }
}
