#!/usr/bin/env bash
# 07-uninstall-lock.bats: tests for scripts/uninstall-lock-runtime.
# Reverses contain-via-guard: removes chattr +i, deletes .real, drops
# dpkg-divert. Uses stubs for id/chattr/dpkg-divert and state fixtures.

load lib/harness

setup()    { guard_setup; load_fake_repo; }
teardown() { guard_teardown; }

_setup_uninstall() {
    FAKE_REPO="$(make_fake_repo)"
    copy_real_scripts "$FAKE_REPO"
    FAKE_USR="$TEST_TMPDIR/fakeusr/bin"
    mkdir -p "$FAKE_USR"
}

@test "uninstall-lock: --help prints usage and exits 0" {
    _setup_uninstall
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime" --help
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "--dry-run"
}

@test "uninstall-lock: unknown arg exits 2" {
    _setup_uninstall
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime" --bogus
    assert_failure
    [ "$status" -eq 2 ]
}

@test "uninstall-lock: exits 0 when state file missing (nothing to roll back)" {
    _setup_uninstall
    # No lock-state.yaml in the runtime state dir.
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime"
    assert_success
    assert_output --partial "nothing to roll back"
}

@test "uninstall-lock: exits 0 when state file is empty" {
    _setup_uninstall
    mkdir -p "$FAKE_REPO/res"
    cat > "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml" <<EOF
lock_state: []
EOF
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime"
    assert_success
    assert_output --partial "no recorded entries"
}

@test "uninstall-lock: --dry-run reports planned actions without changes" {
    _setup_uninstall
    local p="$FAKE_USR/sudo"
    mkdir -p "$(dirname "$p")"
    touch "$p" "${p}.real"
    mkdir -p "$FAKE_REPO/res"
    cat > "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml" <<EOF
lock_state:
  - path: "$p"
    real_sha256: "abc"
    original_path_mode: "4755"
    immutable: true
    dpkg_diverted: true
    contained_at: "2026-01-01T00:00:00Z"
EOF
    echo "$p" >> "$GUARD_DIVERT_DB"
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime" --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "chattr -i"
    assert_output --partial "rm -f"
    assert_output --partial "dpkg-divert --remove"
    # .real should still exist (dry-run does not change).
    [ -f "${p}.real" ]
}

@test "uninstall-lock: removes .real file on rollback" {
    _setup_uninstall
    local p="$FAKE_USR/sudo"
    mkdir -p "$(dirname "$p")"
    touch "$p" "${p}.real"
    mkdir -p "$FAKE_REPO/res"
    cat > "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml" <<EOF
lock_state:
  - path: "$p"
    real_sha256: "abc"
    original_path_mode: "4755"
    immutable: true
    dpkg_diverted: true
    contained_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime"
    assert_success
    assert_output --partial "ROLLED BACK"
    [ ! -f "${p}.real" ]
}

@test "uninstall-lock: invokes chattr -i on .real" {
    _setup_uninstall
    local p="$FAKE_USR/sudo"
    mkdir -p "$(dirname "$p")"
    touch "$p" "${p}.real"
    mkdir -p "$FAKE_REPO/res"
    cat > "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml" <<EOF
lock_state:
  - path: "$p"
    real_sha256: "abc"
    original_path_mode: "4755"
    immutable: true
    dpkg_diverted: true
    contained_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime"
    assert_success
    grep -q '\-i' "$GUARD_STUB_LOG"
    grep -q "${p}.real" "$GUARD_STUB_LOG"
}

@test "uninstall-lock: invokes dpkg-divert --remove for diverted path" {
    _setup_uninstall
    local p="$FAKE_USR/sudo"
    mkdir -p "$(dirname "$p")"
    touch "$p" "${p}.real"
    # Record the divert so --list shows it's diverted.
    echo "$p" >> "$GUARD_DIVERT_DB"
    mkdir -p "$FAKE_REPO/res"
    cat > "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml" <<EOF
lock_state:
  - path: "$p"
    real_sha256: "abc"
    original_path_mode: "4755"
    immutable: true
    dpkg_diverted: true
    contained_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime"
    assert_success
    assert_output --partial "ROLLED BACK"
    # dpkg-divert stub should have removed the entry from GUARD_DIVERT_DB.
    ! grep -qxF "$p" "$GUARD_DIVERT_DB"
}

@test "uninstall-lock: clears state file after rollback" {
    _setup_uninstall
    local p="$FAKE_USR/sudo"
    mkdir -p "$(dirname "$p")"
    touch "$p" "${p}.real"
    mkdir -p "$FAKE_REPO/res"
    cat > "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml" <<EOF
lock_state:
  - path: "$p"
    real_sha256: "abc"
    original_path_mode: "4755"
    immutable: true
    dpkg_diverted: true
    contained_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime"
    assert_success
    # State file should be cleared.
    grep -q 'lock_state: \[\]' "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml"
}

@test "uninstall-lock: multiple entries all rolled back" {
    _setup_uninstall
    local p1="$FAKE_USR/sudo" p2="$FAKE_USR/passwd"
    mkdir -p "$(dirname "$p1")"
    touch "$p1" "${p1}.real" "$p2" "${p2}.real"
    mkdir -p "$FAKE_REPO/res"
    cat > "$WORKSPACE_BINARY_GUARD_STATE_DIR/lock-state.yaml" <<EOF
lock_state:
  - path: "$p1"
    real_sha256: "abc"
    original_path_mode: "4755"
    immutable: true
    dpkg_diverted: false
    contained_at: "2026-01-01T00:00:00Z"
  - path: "$p2"
    real_sha256: "def"
    original_path_mode: "4755"
    immutable: false
    dpkg_diverted: false
    contained_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-lock-runtime"
    assert_success
    [ ! -f "${p1}.real" ]
    [ ! -f "${p2}.real" ]
    # Two entries rolled back.
    assert_output --partial "2 entries"
}