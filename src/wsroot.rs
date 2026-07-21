use crate::WORKSPACE_MARKERS;

pub fn find_workspace_root(toplevel: &str) -> Option<String> {
    let mut cur = std::path::PathBuf::from(toplevel);
    loop {
        if WORKSPACE_MARKERS.iter().all(|m| cur.join(m).exists()) {
            return Some(cur.to_string_lossy().to_string());
        }
        if !cur.pop() {
            return None;
        }
    }
}

// Audit C6: a directory matching SOME but not all markers is a workspace
// root with missing pieces (e.g. an agent-deletable marker removed to
// silence the contract checks). Callers must fail closed on partials.
pub fn find_partial_workspace_root(toplevel: &str) -> Option<String> {
    let mut cur = std::path::PathBuf::from(toplevel);
    loop {
        if WORKSPACE_MARKERS.iter().any(|m| cur.join(m).exists()) {
            return Some(cur.to_string_lossy().to_string());
        }
        if !cur.pop() {
            return None;
        }
    }
}
