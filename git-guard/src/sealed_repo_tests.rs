use super::*;
use crate::GuardError;

#[cfg(feature = "capability-mode")]
#[test]
fn sealed_repo_blocks_write_for_non_root() {
    let err = sealed_repo_violation("pull", false, true);
    match err {
        Some(GuardError::Blocked { reason, .. }) => {
            assert!(reason.contains("sealed repository"));
            assert!(reason.contains("pull"));
        }
        other => panic!("expected Blocked, got {:?}", other.is_none()),
    }
}

#[cfg(feature = "capability-mode")]
#[test]
fn sealed_repo_allows_readonly_for_non_root() {
    for sub in ["status", "log", "diff", "show", "rev-parse", "ls-files"] {
        assert!(sealed_repo_violation(sub, false, true).is_none(), "{sub}");
    }
}

#[cfg(feature = "capability-mode")]
#[test]
fn sealed_repo_allows_everything_for_root() {
    for sub in ["pull", "fetch", "rebase", "config", "commit"] {
        assert!(sealed_repo_violation(sub, true, true).is_none(), "{sub}");
    }
}

#[cfg(feature = "capability-mode")]
#[test]
fn unsealed_repo_not_gated() {
    for sub in ["pull", "fetch", "rebase", "config", "commit"] {
        assert!(sealed_repo_violation(sub, false, false).is_none(), "{sub}");
    }
}
