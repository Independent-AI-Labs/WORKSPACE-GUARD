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
fn raise_ambient_caps_matches_kernel_inheritable_rule() {
    // Kernel capset rule for adding to the Inheritable set: the cap must
    // already be in Inheritable or Permitted, OR CAP_SETPCAP is Effective
    // and the cap is in the Bounding set. The guard loans its caps to
    // children through Inheritable (the binary's file caps are +ep:
    // Effective only), so a capped child - e.g. the pre-push hook running
    // this suite - carries the loan in Inheritable, NOT Permitted. The
    // old P-only model mispredicted exactly that context.
    // Cap list kept in sync with INHERITABLE_CAPS in src/exec.rs.
    let permitted = caps::read(None, caps::CapSet::Permitted).unwrap_or_default();
    let inheritable = caps::read(None, caps::CapSet::Inheritable).unwrap_or_default();
    let effective = caps::read(None, caps::CapSet::Effective).unwrap_or_default();
    let bounding = caps::read(None, caps::CapSet::Bounding).unwrap_or_default();
    let setpcap_effective = effective.contains(&caps::Capability::CAP_SETPCAP);
    let can_raise = [
        caps::Capability::CAP_SETPCAP,
        caps::Capability::CAP_CHOWN,
        caps::Capability::CAP_DAC_OVERRIDE,
        caps::Capability::CAP_FOWNER,
        caps::Capability::CAP_FSETID,
    ]
    .iter()
    .all(|c| {
        permitted.contains(c)
            || inheritable.contains(c)
            || (setpcap_effective && bounding.contains(c))
    });
    let dump = format!("P={permitted:?} I={inheritable:?} E={effective:?} B={bounding:?}");
    let result = raise_ambient_caps();
    if can_raise {
        assert!(
            result.is_ok(),
            "should succeed when every guard cap is raisable (kernel I-set rule); {dump}"
        );
    } else {
        assert!(
            result.is_err(),
            "should fail when a guard cap is not raisable (kernel I-set rule); {dump}"
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

#[test]
fn child_env_filter_drops_gated_vars_for_non_root_only() {
    for &var in crate::SUDO_GATED_IDENTITY_ENV_VARS
        .iter()
        .chain(crate::SUDO_GATED_EDITOR_ENV_VARS.iter())
    {
        assert!(
            should_drop_child_env(var, false),
            "non-root must drop {var} before exec"
        );
        assert!(!should_drop_child_env(var, true), "root keeps {var}");
    }
    // The loop only covers names the catalog currently holds, so it cannot
    // catch a removal from git_guard_environment.yaml. Pin the date names:
    // without them a non-root caller can backdate a commit even though
    // GIT_AUTHOR_NAME/EMAIL are dropped.
    for var in ["GIT_AUTHOR_DATE", "GIT_COMMITTER_DATE"] {
        assert!(
            crate::SUDO_GATED_IDENTITY_ENV_VARS.contains(&var),
            "{var} must stay cataloged in git_guard_environment.yaml"
        );
    }
    // Hook-bypass vars are dropped for every caller.
    assert!(should_drop_child_env("SKIP", false));
    assert!(should_drop_child_env("SKIP", true));
    // Ordinary variables pass through untouched.
    assert!(!should_drop_child_env("PATH", false));
    assert!(!should_drop_child_env("HOME", false));
}

#[test]
fn recorded_root_matches_descendants() {
    use crate::wsroot::{classify_against, WorkspaceRoot};
    let root = "/srv/wsroot";
    assert!(matches!(
        classify_against(Some(root), "/srv/wsroot/projects/repo"),
        WorkspaceRoot::Full(r) if r == root
    ));
    assert!(matches!(
        classify_against(Some(root), root),
        WorkspaceRoot::Full(r) if r == root
    ));
}

#[test]
fn path_outside_recorded_root_is_not_workspace() {
    use crate::wsroot::{classify_against, WorkspaceRoot};
    assert!(matches!(
        classify_against(Some("/srv/wsroot"), "/tmp/repo"),
        WorkspaceRoot::None
    ));
    assert!(matches!(
        classify_against(Some("/srv/wsroot"), "/srv/wsroot2/repo"),
        WorkspaceRoot::None
    ));
}

#[test]
fn absent_record_is_not_workspace() {
    use crate::wsroot::{classify_against, WorkspaceRoot};
    assert!(matches!(
        classify_against(None, "/srv/wsroot/projects/repo"),
        WorkspaceRoot::None
    ));
}

#[test]
fn workspace_contract_uses_only_live_paths() {
    assert_eq!(CONTRACT_SCRIPT, "/opt/workspace-ci/lib/checks_quality.sh");
}
