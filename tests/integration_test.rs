// Integration tests for the workspace-guard binary.
//
// Capability-mode tests require a non-root process without file capabilities
// on the guard binary (Darwin dev host, or Tier 1 `testagent` in Podman).
//
// Root-only tests require euid 0 (Tier 1 container root, Tier 2 E2E).

use std::process::Command;

fn guard_cmd() -> Command {
    let mut cmd = Command::new("cargo");
    let mut args = vec!["run", "--release"];
    #[cfg(feature = "root-only")]
    {
        args.extend(["--no-default-features", "--features", "root-only"]);
    }
    args.extend(["--bin", "workspace-guard", "--"]);
    cmd.args(args);
    cmd
}

#[test]
fn guard_compiles_release() {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--release", "--bin", "workspace-guard"]);
    #[cfg(feature = "root-only")]
    {
        cmd.args(["--no-default-features", "--features", "root-only"]);
    }
    let output = cmd.output().expect("failed to build guard");
    assert!(
        output.status.success(),
        "guard should compile in release mode"
    );
}

#[cfg(feature = "capability-mode")]
mod capability_mode {
    use super::guard_cmd;

    /// Capability integration tests require a non-root process without file
    /// caps on the guard binary (Tier 1 `testagent` in Podman). Plain
    /// `cargo test` as root in a dev container passes the cap check but
    /// then fails with GitOriginalMissing; skip that environment.
    fn capability_integration_enabled() -> bool {
        unsafe { libc::geteuid() != 0 }
    }

    #[test]
    fn guard_exits_missing_cap() {
        if !capability_integration_enabled() {
            eprintln!("SKIP: capability integration (requires non-root euid)");
            return;
        }
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
        if !capability_integration_enabled() {
            eprintln!("SKIP: capability integration (requires non-root euid)");
            return;
        }
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
}

#[cfg(feature = "root-only")]
mod root_only {
    use super::guard_cmd;

    #[test]
    fn guard_prints_root_only_notice() {
        let output = guard_cmd()
            .arg("status")
            .output()
            .expect("failed to execute guard");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("running in root-only mode"),
            "stderr should mention root-only mode: {stderr}"
        );
    }

    #[test]
    fn guard_blocks_reset_before_exec() {
        assert_guard_blocks(&["reset", "--hard"], "reset --hard");
    }

    #[test]
    fn guard_blocks_plumbing_and_bypass_vectors() {
        let cases: &[(&[&str], &str)] = &[
            (&["update-ref", "refs/heads/main", "deadbeef"], "update-ref"),
            (&["read-tree", "-u", "--reset", "HEAD"], "read-tree --reset"),
            (&["write-tree"], "write-tree"),
            (&["switch", "--discard-changes"], "switch --discard-changes"),
            (&["checkout", "-f", "main"], "checkout -f"),
        ];
        for (argv, label) in cases {
            assert_guard_blocks(argv, label);
        }
    }

    #[test]
    fn guard_blocks_hard_after_separator() {
        assert_guard_blocks(&["--", "--hard"], "git separator hard");
    }

    fn assert_guard_blocks(argv: &[&str], label: &str) {
        let mut cmd = guard_cmd();
        for arg in argv {
            cmd.arg(arg);
        }
        let output = cmd.output().expect("failed to execute guard");
        assert!(
            !output.status.success(),
            "guard should block {label}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("BLOCKED"),
            "stderr should report blocked {label}: {stderr}"
        );
        assert!(
            !stderr.contains("missing file capabilities"),
            "root-only guard should not fail cap check as root for {label}: {stderr}"
        );
    }
}
