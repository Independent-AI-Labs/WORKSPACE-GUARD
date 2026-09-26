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
fn root_owned_regular_accepts_system_binary() {
    let path = std::path::Path::new("/usr/bin/git");
    if path.exists() {
        assert!(root_owned_regular(path));
    }
}

#[test]
fn root_owned_regular_rejects_agent_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("owned-by-test-user");
    std::fs::write(&file, b"x").unwrap();
    assert!(!root_owned_regular(&file));
}

#[test]
fn root_owned_regular_rejects_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real");
    let link = dir.path().join("link");
    std::fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(!root_owned_regular(&link));
}
