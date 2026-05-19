// Integration tests for the guard binary.
// These tests run against the debug binary, which is never SUID,
// so the guard exits with FATAL: NotSuid. This is expected behavior
// — the guard only operates when installed as SUID root at /usr/bin/git.
// These tests verify the binary compiles and runs without crashes.

use std::process::Command;

fn guard_cmd() -> Command {
    let mut cmd = Command::new("cargo");
    cmd.args(["run", "--release", "--"]);
    cmd
}

#[test]
fn guard_exits_not_suid() {
    let output = guard_cmd()
        .arg("status")
        .output()
        .expect("failed to execute guard");
    assert!(
        !output.status.success(),
        "guard should exit non-zero when not SUID"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NotSuid"),
        "stderr should mention NotSuid: {stderr}"
    );
}

#[test]
fn guard_exits_not_suid_on_blocked_cmd() {
    let output = guard_cmd()
        .arg("reset")
        .arg("--hard")
        .output()
        .expect("failed to execute guard");
    assert!(
        !output.status.success(),
        "guard should exit non-zero when not SUID"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NotSuid"),
        "stderr should mention NotSuid: {stderr}"
    );
}

#[test]
fn guard_compiles_release() {
    let output = Command::new("cargo")
        .args(["build", "--release"])
        .output()
        .expect("failed to build guard");
    assert!(
        output.status.success(),
        "guard should compile in release mode"
    );
}
