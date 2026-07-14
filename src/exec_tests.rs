use super::*;
use std::io::Write;

fn write_temp_enforcement(dir: &std::path::Path, content: &str) {
    let ws_config = dir.join("workspace").join("config");
    std::fs::create_dir_all(&ws_config).unwrap();
    let mut f = std::fs::File::create(ws_config.join("project_enforcement.yaml")).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

#[test]
fn vendored_tier_not_bypassed_for_safe_tier() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
version: 1
defaults:
  tier: strict
exemptions:
  - path: projects/WORKSPACE-GUARD/
    tier: strict
    reason: "test"
"#;
    write_temp_enforcement(dir.path(), content);
    let wsroot = dir.path().to_string_lossy().to_string();
    let toplevel = format!("{}/projects/WORKSPACE-GUARD", wsroot);
    assert!(!check_vendored_tier_bypass(&wsroot, &toplevel));
}

#[test]
fn vendored_tier_bypass_detected() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
version: 1
defaults:
  tier: strict
exemptions:
  - path: projects/WORKSPACE-GUARD/
    tier: vendored
    reason: "test vendored bypass"
"#;
    write_temp_enforcement(dir.path(), content);
    let wsroot = dir.path().to_string_lossy().to_string();
    let toplevel = format!("{}/projects/WORKSPACE-GUARD", wsroot);
    assert!(check_vendored_tier_bypass(&wsroot, &toplevel));
}

#[test]
fn vendored_tier_no_exemptions() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
version: 1
defaults:
  tier: strict
"#;
    write_temp_enforcement(dir.path(), content);
    let wsroot = dir.path().to_string_lossy().to_string();
    let toplevel = format!("{}/projects/other", wsroot);
    assert!(!check_vendored_tier_bypass(&wsroot, &toplevel));
}

#[test]
fn vendored_tier_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let wsroot = dir.path().to_string_lossy().to_string();
    let toplevel = format!("{}/projects/WORKSPACE-GUARD", wsroot);
    assert!(!check_vendored_tier_bypass(&wsroot, &toplevel));
}

#[test]
fn vendored_tier_path_prefix_match() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
version: 1
defaults:
  tier: strict
exemptions:
  - path: projects/WORKSPACE-GUARD/
    tier: vendored
    reason: "test"
"#;
    write_temp_enforcement(dir.path(), content);
    let wsroot = dir.path().to_string_lossy().to_string();
    let toplevel = format!("{}/projects/WORKSPACE-GUARD/subdir", wsroot);
    assert!(check_vendored_tier_bypass(&wsroot, &toplevel));
}

#[test]
fn raise_child_dac_override_returns_without_panic() {
    let _ = raise_child_dac_override();
}

#[cfg(feature = "capability-mode")]
#[test]
fn raise_ambient_caps_returns_error_without_file_caps() {
    // When running inside the guard's child process (e.g., pre-push hook
    // triggered cargo test), git.original inherits CAP_DAC_OVERRIDE in
    // Ambient, which propagates to all descendants including this test
    // binary. In that context raise_ambient_caps succeeds. When running
    // as a standalone process (no ambient caps), it fails.
    let has_ambient = caps::read(None, caps::CapSet::Ambient)
        .map(|set| set.contains(&caps::Capability::CAP_DAC_OVERRIDE))
        .unwrap_or(false);
    let result = raise_ambient_caps();
    if has_ambient {
        assert!(result.is_ok(), "should succeed with ambient caps");
    } else if nix::unistd::getuid().is_root() {
        // Rootful containers can raise Inheritable caps without file caps
        // on the test binary; production enforcement runs as the capped
        // guard process, not as container root during `cargo test`.
    } else {
        assert!(result.is_err(), "should fail without file caps");
    }
}

#[test]
fn verify_git_original_returns_error_when_missing() {
    if std::path::Path::new("/usr/bin/git.original").exists() {
        return;
    }
    assert!(verify_git_original().is_err());
}

#[test]
fn is_guard_binary_detects_sentinel() {
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let guard_like = tmpdir.path().join("fake-guard");
    fs::write(&guard_like, b"some bytes workspace-guard more bytes").expect("write");
    assert!(is_guard_binary(&guard_like));

    let real_like = tmpdir.path().join("fake-real");
    fs::write(&real_like, b"git version 2.53.0\n").expect("write");
    assert!(!is_guard_binary(&real_like));

    let empty = tmpdir.path().join("empty");
    fs::write(&empty, b"").expect("write");
    assert!(!is_guard_binary(&empty));
}

#[cfg(feature = "capability-mode")]
#[test]
fn host_exec_cap_loan_after_inheritable_promotion() {
    if raise_ambient_caps().is_err() {
        return;
    }
    // SAFETY: libc::fork is exercised here intentionally so the test suite
    // hits the exact same async-signal-safe FFI the production exec path
    // uses (see src/exec.rs). No allocations occur between fork and exit
    // in the child branch.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork should succeed");
    if pid == 0 {
        let exit_code = match raise_child_dac_override() {
            Ok(()) => {
                let ambient = caps::read(None, caps::CapSet::Ambient).unwrap_or_default();
                if ambient.contains(&caps::Capability::CAP_DAC_OVERRIDE) {
                    0
                } else {
                    1
                }
            }
            Err(_) => 2,
        };
        // SAFETY: libc::_exit is the only async-signal-safe exit path; using
        // std::process::exit here would run Drop handlers and could deadlock
        // on malloc locks held across fork. nix has no _exit wrapper.
        unsafe {
            libc::_exit(exit_code);
        }
    } else {
        match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                assert_eq!(code, 0, "CAP_DAC_OVERRIDE must be in Ambient after loan");
            }
            other => panic!("unexpected wait status: {:?}", other),
        }
    }
}

#[test]
fn fork_child_clears_and_exits() {
    // SAFETY: libc::fork is exercised here intentionally so the test suite
    // hits the exact same async-signal-safe FFI the production exec path
    // uses (see src/exec.rs). No allocations occur between fork and exit
    // in the child branch.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork should succeed");
    if pid == 0 {
        let _ = raise_child_dac_override();
        // SAFETY: libc::_exit is the only async-signal-safe exit path; using
        // std::process::exit here would run Drop handlers and could deadlock
        // on malloc locks held across fork. nix has no _exit wrapper.
        unsafe {
            libc::_exit(0);
        }
    } else {
        match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None) {
            Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                assert_eq!(code, 0);
            }
            other => panic!("unexpected wait status: {:?}", other),
        }
    }
}

#[test]
fn sudo_gated_env_warnings_non_sudo_drops_with_message() {
    std::env::set_var("GIT_AUTHOR_NAME", "evil");
    std::env::set_var("GIT_COMMITTER_EMAIL", "c@d.com");
    std::env::set_var("EDITOR", "vim");
    let msgs = collect_sudo_gated_env_warnings(false);
    std::env::remove_var("GIT_AUTHOR_NAME");
    std::env::remove_var("GIT_COMMITTER_EMAIL");
    std::env::remove_var("EDITOR");

    assert!(msgs.iter().any(|m| m.contains("[GIT_AUTHOR_NAME]")
        && m.contains("NON-ROOT USER HAS SET CUSTOM GIT CONFIG COMMITTER DATA - IGNORING.")));
    assert!(msgs.iter().any(|m| m.contains("[GIT_COMMITTER_EMAIL]")
        && m.contains("NON-ROOT USER HAS SET CUSTOM GIT CONFIG COMMITTER DATA - IGNORING.")));
    assert!(msgs.iter().any(|m| m.contains("[EDITOR]")
        && m.contains("NON-ROOT USER HAS SET CUSTOM GIT EDITOR - IGNORING.")));

    let msgs_sudo = collect_sudo_gated_env_warnings(true);
    assert!(msgs_sudo.is_empty());
}
