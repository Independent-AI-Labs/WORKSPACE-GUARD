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
fn raise_child_dac_override_does_not_panic() {
    raise_child_dac_override();
}

#[cfg(feature = "capability-mode")]
#[test]
fn raise_ambient_caps_returns_error_without_file_caps() {
    let result = raise_ambient_caps();
    assert!(result.is_err());
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

#[test]
fn fork_child_clears_and_exits() {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork should succeed");
    if pid == 0 {
        raise_child_dac_override();
        std::process::exit(0);
    } else {
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
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
