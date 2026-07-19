use super::*;

#[test]
fn bypass_env_skip_blocked() {
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    std::env::set_var("SKIP", "1");
    let result = {
        let state = empty_state("status");
        let argv_os = argv(&["git", "status"]);
        check_blocked(&state, "status", &argv_os, "/nonexistent-git", None)
    };
    clear_blocked_bypass_env_vars();
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}

#[test]
fn bypass_env_pre_commit_allow_no_config_blocked() {
    let _env_guard = crate::TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    std::env::set_var("PRE_COMMIT_ALLOW_NO_CONFIG", "1");
    let result = {
        let state = empty_state("commit");
        let argv_os = argv(&["git", "commit", "-m", "x"]);
        check_blocked(&state, "commit", &argv_os, "/nonexistent-git", None)
    };
    clear_blocked_bypass_env_vars();
    assert!(matches!(result, Err(GuardError::Blocked { .. })));
}
