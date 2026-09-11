use super::*;

fn exec_test_scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "guard-exec-test-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn resolve_toplevel_honors_dash_c_over_guard_cwd() {
    // Security regression: the old resolver used only the guard's cwd,
    // so `cd /outside && git -C <workspace-repo> commit` skipped the
    // entire workspace CI contract check. The resolver must follow -C
    // to the repo the commit actually targets.
    let dir = exec_test_scratch("toplevel-dashc");
    let st = std::process::Command::new("git")
        .arg("-C")
        .arg(&dir)
        .args(["init", "-q"])
        .status()
        .unwrap();
    assert!(st.success());
    let argv = vec![
        OsString::from("git"),
        OsString::from("-C"),
        dir.clone().into_os_string(),
        OsString::from("commit"),
    ];
    let resolved = resolve_toplevel(&argv, "git").expect("must resolve scratch repo");
    // The test process cwd is the guard repo; a cwd-based resolver would
    // return it instead of the -C target.
    assert_eq!(
        std::path::Path::new(&resolved).canonicalize().unwrap(),
        dir.canonicalize().unwrap(),
        "resolver must follow -C, not the guard cwd"
    );
}

#[test]
fn resolve_toplevel_returns_none_outside_any_repo() {
    // Fail-closed contract check relies on this: an unresolvable target
    // must surface as None so the caller blocks instead of skipping.
    let dir = exec_test_scratch("toplevel-none");
    let argv = vec![
        OsString::from("git"),
        OsString::from("-C"),
        dir.into_os_string(),
        OsString::from("commit"),
    ];
    assert!(resolve_toplevel(&argv, "git").is_none());
}

#[test]
fn git_dir_env_vars_stay_out_of_allowed_vars() {
    // execve_real_git only forwards ALLOWED_VARS to git.original, and
    // resolve_toplevel spawns with env_clear: both sides agree that
    // GIT_DIR/GIT_WORK_TREE never influence which repo a commit hits.
    // If config ever re-adds them, the resolver and the exec env would
    // diverge (contract check pointed at repo A, real commit in repo
    // B), reopening a contract-check dodge. Pin the invariant.
    assert!(!ALLOWED_VARS.contains(&"GIT_DIR"));
    assert!(!ALLOWED_VARS.contains(&"GIT_WORK_TREE"));
}

#[test]
fn raise_child_dac_override_returns_without_panic() {
    let _ = raise_child_dac_override();
}

#[cfg(feature = "capability-mode")]
#[test]
fn raise_ambient_caps_returns_error_without_file_caps() {
    // caps::raise(Inheritable, cap) succeeds iff cap is in Permitted.
    // Permitted holds the guard caps in three legitimate contexts: a
    // capped guard child (pre-push hook running the suite), container
    // root, and a test binary that itself carries file caps. Expect
    // success exactly when Permitted covers the full guard set (kept in
    // sync with INHERITABLE_CAPS in src/exec.rs), failure otherwise.
    let permitted = caps::read(None, caps::CapSet::Permitted).unwrap_or_default();
    let can_raise = [
        caps::Capability::CAP_SETPCAP,
        caps::Capability::CAP_CHOWN,
        caps::Capability::CAP_DAC_OVERRIDE,
        caps::Capability::CAP_FOWNER,
        caps::Capability::CAP_FSETID,
    ]
    .iter()
    .all(|c| permitted.contains(c));
    let result = raise_ambient_caps();
    if can_raise {
        assert!(
            result.is_ok(),
            "should succeed with guard caps in Permitted"
        );
    } else {
        assert!(
            result.is_err(),
            "should fail without guard caps in Permitted"
        );
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
fn is_guard_binary_detects_self_by_inode() {
    let self_path = std::fs::read_link("/proc/self/exe").expect("read_link");
    assert!(is_guard_binary(&self_path));

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let other = tmpdir.path().join("other");
    fs::write(&other, b"git version 2.53.0\n").expect("write");
    assert!(!is_guard_binary(&other));

    let missing = tmpdir.path().join("missing");
    assert!(!is_guard_binary(&missing));
}

#[cfg(feature = "capability-mode")]
#[test]
fn host_exec_cap_loan_after_inheritable_promotion() {
    if raise_ambient_caps().is_err() {
        return;
    }
    // The fork child raises CAP_DAC_OVERRIDE into Ambient, which
    // additionally requires CAP_SETPCAP in Effective. Effective survives
    // exec only for file-cap binaries (the production guard); a plain
    // test binary exec'd from a capped ancestor loses it, so the loan
    // path is not exercisable there. Skip when the precondition is absent.
    let setpcap_effective = caps::read(None, caps::CapSet::Effective)
        .map(|set| set.contains(&caps::Capability::CAP_SETPCAP))
        .unwrap_or(false);
    if !setpcap_effective {
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

fn make_workspace_markers(dir: &std::path::Path, markers: &[&str]) {
    for m in markers {
        let p = dir.join(m);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::create_dir_all(&p).unwrap();
    }
}

#[test]
fn full_markers_find_workspace_root() {
    use crate::wsroot::find_workspace_root;
    let dir = tempfile::tempdir().unwrap();
    make_workspace_markers(dir.path(), WORKSPACE_MARKERS);
    let top = format!("{}/projects/repo", dir.path().to_string_lossy());
    assert_eq!(
        find_workspace_root(&top),
        Some(dir.path().to_string_lossy().to_string())
    );
}

#[test]
fn partial_markers_miss_full_but_hit_partial() {
    use crate::wsroot::{find_partial_workspace_root, find_workspace_root};
    let dir = tempfile::tempdir().unwrap();
    let some: Vec<&str> = WORKSPACE_MARKERS.iter().take(1).cloned().collect();
    make_workspace_markers(dir.path(), &some);
    let top = format!("{}/projects/repo", dir.path().to_string_lossy());
    assert_eq!(find_workspace_root(&top), None);
    assert_eq!(
        find_partial_workspace_root(&top),
        Some(dir.path().to_string_lossy().to_string())
    );
}

#[test]
fn no_markers_hit_neither() {
    use crate::wsroot::{find_partial_workspace_root, find_workspace_root};
    let dir = tempfile::tempdir().unwrap();
    let top = dir.path().to_string_lossy().to_string();
    assert_eq!(find_workspace_root(&top), None);
    assert_eq!(find_partial_workspace_root(&top), None);
}

#[test]
fn workspace_contract_uses_only_live_paths() {
    assert_eq!(
        WORKSPACE_MARKERS,
        &[".boot-linux", "workspace/scripts/utils/git-guard"]
    );
    assert_eq!(CONTRACT_SCRIPT, "/opt/workspace-ci/lib/checks_quality.sh");
}
