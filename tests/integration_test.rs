// Integration tests for the guard binary.
// These tests run against the debug binary, which has no file capabilities,
// so the guard exits with FATAL: missing file capabilities. This is expected
// the guard only operates when installed with file capabilities at /usr/bin/git.
// These tests verify the binary compiles and runs without crashes.

use std::process::Command;

fn guard_cmd() -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--release", "--bin", "workspace-guard", "--"]);
    cmd
}

#[test]
fn guard_exits_missing_cap() {
    let output = guard_cmd()
        .arg("status")
        .output()
        .expect("failed to execute guard");
    assert!(
        !output.status.success(),
        "guard should exit non-zero when missing file capabilities"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing file capabilities"),
        "stderr should mention missing file capabilities: {stderr}"
    );
}

#[test]
fn guard_exits_missing_cap_on_blocked_cmd() {
    let output = guard_cmd()
        .arg("reset")
        .arg("--hard")
        .output()
        .expect("failed to execute guard");
    assert!(
        !output.status.success(),
        "guard should exit non-zero when missing file capabilities"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing file capabilities"),
        "stderr should mention missing file capabilities: {stderr}"
    );
}

#[test]
fn guard_compiles_release() {
    let output = Command::new("cargo")
        .args(["build", "--release", "--bin", "workspace-guard"])
        .output()
        .expect("failed to build guard");
    assert!(
        output.status.success(),
        "guard should compile in release mode"
    );
}
