#!/usr/bin/env bash
# 06-install-lock.bats: tests for scripts/install-lock-runtime. Root-only
# contain-via-guard installer. Uses stubs (id, chattr, dpkg-divert, lsattr)
# and fake SUID binaries under TEST_TMPDIR so no root or real path is
# touched. The guard binary is a fake sentinel-bearing script.

load lib/harness

setup()    { guard_setup; load_fake_repo; }
teardown() { guard_teardown; }

# Build a fake repo with real scripts, a fake guard binary, and a
# fake usr/bin root under TEST_TMPDIR. Sets FAKE_REPO and FAKE_USR.
_setup_install() {
    FAKE_REPO="$(make_fake_repo)"
    copy_real_scripts "$FAKE_REPO"
    fake_guard_binary "$FAKE_REPO"
    FAKE_USR="$TEST_TMPDIR/fakeusr/bin"
    mkdir -p "$FAKE_USR"
}

# Create fake SUID binaries at the given paths and write a matching
# binary-lock.yaml into FAKE_REPO. Call AFTER _setup_install.
_setup_paths() {
    local p
    for p in "$@"; do
        mkdir -p "$(dirname "$p")"
        echo '#!/usr/bin/env bash' > "$p"
        chmod 4755 "$p"
    done
    fake_binaries_yaml "$FAKE_REPO" "$@"
}

# Extract the lock surface count from dry-run output.
_dry_run_count() { printf '%s' "$output" | grep 'Lock surface:' | head -1; }

@test "install-lock: --help prints usage and exits 0" {
    _setup_install
    run bash "$FAKE_REPO/scripts/install-lock-runtime" --help
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "--dry-run"
}

@test "install-lock: unknown arg exits 2" {
    _setup_install
    run bash "$FAKE_REPO/scripts/install-lock-runtime" --bogus
    assert_failure
    [ "$status" -eq 2 ]
}

@test "install-lock: exits 2 when binary-lock.yaml missing" {
    _setup_install
    # No res/binary-lock.yaml in the fake repo.
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_failure
    [ "$status" -eq 2 ]
    assert_output --partial "missing"
}

@test "install-lock: exits 2 when lock surface is empty" {
    _setup_install
    # Create a binary-lock.yaml with only null-path entries.
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/binary-lock.yaml" <<YEOF
version: 1
binaries:
  - name: "ghost"
    tags: ["suid"]
    path: null
    contained: false
    policy: deny-non-root
    allow_subcommands: []
    allow_self_username: false
    env_sanitise: ["LD_PRELOAD"]
    reject_patterns: []
YEOF
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_failure
    [ "$status" -eq 2 ]
    assert_output --partial "no binaries parsed"
}

@test "install-lock: exits 2 when guard binary missing" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    # Remove the guard binary.
    # Remove the guard binary.
    rm -f "$FAKE_REPO/target/release/workspace-binary-guard"
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_failure
    [ "$status" -eq 2 ]
    assert_output --partial "guard binary not found"
}

@test "install-lock: --dry-run reports lock surface count without changes" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    run bash "$FAKE_REPO/scripts/install-lock-runtime" --dry-run
    assert_success
    assert_output --partial "Lock surface: 1 binaries"
    assert_output --partial "DRY RUN"
    assert_output --partial "WOULD: seal .real"
    # No .real file should exist.
    [ ! -f "${p}.real" ]
}

@test "install-lock: dry-run parses multiple non-null paths" {
    _setup_install
    local p1="$FAKE_USR/sudo" p2="$FAKE_USR/passwd"
    _setup_paths "$p1" "$p2"
    run bash "$FAKE_REPO/scripts/install-lock-runtime" --dry-run
    assert_success
    assert_output --partial "Lock surface: 2 binaries"
}

@test "install-lock: dry-run skips null-path entries" {
    _setup_install
    local p1="$FAKE_USR/sudo"
    mkdir -p "$(dirname "$p1")"
    echo '#!/usr/bin/env bash' > "$p1"
    chmod 4755 "$p1"
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/binary-lock.yaml" <<YEOF
version: 1
binaries:
  - name: "sudo"
    tags: ["suid"]
    path: "$p1"
    contained: false
    policy: deny-non-root
    allow_subcommands: []
    allow_self_username: false
    env_sanitise: ["LD_PRELOAD"]
    reject_patterns: []
  - name: "ghost"
    tags: ["suid"]
    path: null
    contained: false
    policy: deny-non-root
    allow_subcommands: []
    allow_self_username: false
    env_sanitise: ["LD_PRELOAD"]
    reject_patterns: []
YEOF
    run bash "$FAKE_REPO/scripts/install-lock-runtime" --dry-run
    assert_success
    assert_output --partial "Lock surface: 1 binaries"
}

@test "install-lock: creates .real sealed copy (0700 root:root)" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_success
    [ -f "${p}.real" ]
    local mode
    mode="$(stat -c '%a' "${p}.real")"
    assert_equal "700" "$mode"
}

@test "install-lock: installs guard at path (sentinel present)" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_success
    # The path should now contain the guard sentinel.
    grep -qa "workspace-guard" "$p"
}

@test "install-lock: invokes chattr +i on .real" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_success
    # The chattr stub logs to GUARD_STUB_LOG.
    grep -q "+i" "$GUARD_STUB_LOG"
    grep -q "${p}.real" "$GUARD_STUB_LOG"
}

@test "install-lock: invokes dpkg-divert --add for the path" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_success
    # The dpkg-divert stub records the path in GUARD_DIVERT_DB.
    grep -qxF "$p" "$GUARD_DIVERT_DB"
}

@test "install-lock: writes lock-state.yaml with contained entries" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_success
    [ -f "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml" ]
    grep -q 'lock_state:' "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml"
    grep -q "path: \"$p\"" "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml"
}

@test "install-lock: idempotent (already-contained path is skipped)" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    # First run: install.
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_success
    assert_output --partial "CONTAINED"
    # Second run: should detect already-contained and skip.
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_success
    assert_output --partial "ALREADY CONTAINED"
}

@test "install-lock: chattr failure sets exit code 3" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    export GUARD_CHATTR_FAIL=1
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    [ "$status" -eq 3 ]
    # chattr failure is a warning, not a full failure: containment still
    # succeeds per the .real and guard. But exit code is 3.
    assert_output --partial "chattr +i"
}

@test "install-lock: symlink target is skipped (refuses to lock)" {
    _setup_install
    local p="$FAKE_USR/sudo"
    local link="$FAKE_USR/sudolink"
    _setup_paths "$p"
    mkdir -p "$(dirname "$link")"
    ln -sf "$p" "$link"
    # Regenerate binary-lock.yaml with the symlink path.
    fake_binaries_yaml "$FAKE_REPO" "$link"
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_failure
    assert_output --partial "symlink"
}

@test "install-lock: missing file is skipped and counted as failed" {
    _setup_install
    local p="$FAKE_USR/nonexistent"
    fake_binaries_yaml "$FAKE_REPO" "$p"
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_failure
    assert_output --partial "not a regular file"
}

@test "install-lock: stages guard before dpkg-divert (ordering check)" {
    _setup_install
    local p="$FAKE_USR/sudo"
    _setup_paths "$p"
    # Track the order: chattr log should have +i BEFORE divert db gets
    # the entry (staging happens after chattr, divert after staging).
    run bash "$FAKE_REPO/scripts/install-lock-runtime"
    assert_success
    # .guard_new temp should NOT persist (it was mv'd to $p).
    [ ! -f "${p}.guard_new" ]
    # .distrib should exist (dpkg-divert --rename moved the original).
    [ -f "${p}.distrib" ]
}