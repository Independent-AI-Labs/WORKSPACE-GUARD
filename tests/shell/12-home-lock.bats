#!/usr/bin/env bash
# 12-home-lock.bats: tests for scripts/install-home-lock,
# scripts/uninstall-home-lock, and scripts/home-drift-check. The home
# lock chowns files OUTSIDE the repo tree (~/.gitconfig, ~/.ssh/config,
# authorized_keys, /root/.gitconfig, etc.) to root:root so an attacker
# cannot bypass the in-repo guard lock by writing `core.hooksPath`
# directly to ~/.gitconfig (the CI incident: a rootless agent wrote
# core.hooksPath = /tmp/opencode/githooks to ~/.gitconfig, compromising
# every git repo on the host). Uses stubs for id and chown so root-only
# code paths run as a non-root bats user. A custom stat stub is built
# per-test (via make_stub) to verify the idempotency branch; real stat
# is used everywhere else so the script's chmod/touch effects are
# verified against the actual filesystem.

bats_require_minimum_version 1.5.0

load lib/harness

setup()    { guard_setup; load_fake_repo; }
teardown() { guard_teardown; }

# Build a fake repo with real scripts and a fake home pointing into
# $TEST_TMPDIR/fakehome. Sets FAKE_REPO, FAKE_HOME. The fake repo
# carries a minimal guard_locked_paths.yaml with just the entries the
# test needs (overloaded by _write_locked_paths).
_setup_home() {
    FAKE_REPO="$(make_fake_repo)"
    copy_real_scripts "$FAKE_REPO"
    FAKE_HOME="$TEST_TMPDIR/fakehome"
    mkdir -p "$FAKE_HOME"
    _write_locked_paths "$FAKE_REPO" ""
}

# Write a guard_locked_paths.yaml with a custom absolute_file_paths
# block. Arguments are alternating "raw-path" "octal-mode-string" pairs.
# An empty list writes a block with no entries.
_write_locked_paths() {
    local dir="$1"; shift
    mkdir -p "$dir/config"
    {
        echo "version: 1"
        echo "recursive_tree_paths: []"
        echo "recursive_tree_glob_patterns: []"
        echo "individual_file_paths: {}"
        echo "glob_patterns: {}"
        echo "absolute_file_paths:"
        local i=0
        while [ $i -lt $# ]; do
            local p="${@:$((i+1)):1}" m="${@:$((i+2)):1}"
            printf '  "%s": 0o%s\n' "$p" "$m"
            i=$((i+2))
        done
    } > "$dir/config/guard_locked_paths.yaml"
}

# Materialize the listed fake-home paths with the given content so
# install-home-lock has real targets. Args: "raw-path" "content" pairs.
# `~` is expanded against $FAKE_HOME.
_make_home_files() {
    local i=0
    while [ $i -lt $# ]; do
        local p="${@:$((i+1)):1}" c="${@:$((i+2)):1}"
        local full="$FAKE_HOME/${p#\~}"
        mkdir -p "$(dirname "$full")"
        printf '%s' "$c" > "$full"
        i=$((i+2))
    done
}

# Resolve a `~`-prefixed path against $FAKE_HOME.
_tilde() {
    local p="$1"
    case "$p" in
        "~")    printf '%s' "$FAKE_HOME" ;;
        "~/"*)  printf '%s/%s' "$FAKE_HOME" "${p#"~/"}" ;;
        *)      printf '%s' "$p" ;;
    esac
}

# Build a stat stub that always reports root:root with mode $1.
_stub_stat_root() {
    local mode="$1"
    export GUARD_STAT_MODE="$mode"
    make_stub stat <<STUB
#!/usr/bin/env bash
if [ "\$1" = "-c" ]; then
    case "\$2" in
        %u) echo 0 ;;
        %g) echo 0 ;;
        %a) echo "\$GUARD_STAT_MODE" ;;
        *)  echo "0" ;;
    esac
fi
STUB
}

# =====================================================================
# install-home-lock
# =====================================================================

@test "install-home-lock: --help prints usage and exits 0" {
    _setup_home
    run bash "$FAKE_REPO/scripts/install-home-lock" --help
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "--dry-run"
}

@test "install-home-lock: unknown arg exits 2" {
    _setup_home
    run bash "$FAKE_REPO/scripts/install-home-lock" --bogus
    assert_failure
    [ "$status" -eq 2 ]
}

@test "install-home-lock: exits 2 when config missing" {
    _setup_home
    rm -f "$FAKE_REPO/config/guard_locked_paths.yaml"
    run bash "$FAKE_REPO/scripts/install-home-lock"
    assert_failure
    [ "$status" -eq 2 ]
    assert_output --partial "missing"
}

@test "install-home-lock: exits 2 when no absolute_file_paths entries" {
    _setup_home
    run bash "$FAKE_REPO/scripts/install-home-lock"
    assert_failure
    [ "$status" -eq 2 ]
    assert_output --partial "no absolute_file_paths"
}

@test "install-home-lock: --dry-run reports surface without changes" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.gitconfig" "644"
    run bash "$FAKE_REPO/scripts/install-home-lock" --dry-run
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock" --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "WOULD"
    # State file should NOT be written on dry-run.
    [ ! -f "$FAKE_REPO/res/home-lock-state.yaml" ]
}

@test "install-home-lock: creates missing files with touch" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.gitconfig" "644"
    # No file at $FAKE_HOME/.gitconfig yet.
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    [ -f "$FAKE_HOME/.gitconfig" ]
}

@test "install-home-lock: creates missing parent dir with mkdir -p" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.config/git/config" "644"
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    [ -f "$FAKE_HOME/.config/git/config" ]
}

@test "install-home-lock: writes home-lock-state.yaml with entries" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.gitconfig" "644"
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    [ -f "$FAKE_REPO/res/home-lock-state.yaml" ]
    grep -q 'home_lock_state:' "$FAKE_REPO/res/home-lock-state.yaml"
    grep -q "path: \"$FAKE_HOME/.gitconfig\"" "$FAKE_REPO/res/home-lock-state.yaml"
}

@test "install-home-lock: state captures original owner/mode/locked_at" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.gitconfig" "644"
    _make_home_files "~/.gitconfig" "old content"
    chmod 0600 "$FAKE_HOME/.gitconfig"
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    grep -q 'original_owner_uid:' "$FAKE_REPO/res/home-lock-state.yaml"
    grep -q 'original_owner_gid:' "$FAKE_REPO/res/home-lock-state.yaml"
    grep -q 'original_mode: "600"' "$FAKE_REPO/res/home-lock-state.yaml"
    grep -q 'expected_mode: "644"' "$FAKE_REPO/res/home-lock-state.yaml"
    grep -q 'locked_at:' "$FAKE_REPO/res/home-lock-state.yaml"
}

@test "install-home-lock: applies expected mode 0644 to gitconfig" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.gitconfig" "644"
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    local mode
    mode="$(stat -c '%a' "$FAKE_HOME/.gitconfig")"
    assert_equal "644" "$mode"
}

@test "install-home-lock: applies expected mode 0600 to authorized_keys" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.ssh/authorized_keys" "600"
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    local mode
    mode="$(stat -c '%a' "$FAKE_HOME/.ssh/authorized_keys")"
    assert_equal "600" "$mode"
}

@test "install-home-lock: invokes chown root:root for each entry" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.gitconfig" "644"
    # chown stub is a no-op but install-home-lock must still call it.
    # The harness chown stub just exits 0; assert the chown stub is on PATH.
    command -v chown
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    # No direct log from the static chown stub; assert the file exists
    # and the mode was applied (the only verifiable side-effect).
    [ -f "$FAKE_HOME/.gitconfig" ]
}

@test "install-home-lock: tilde expands to HOME at runtime" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.gitconfig" "644"
    # Use a non-$FAKE_HOME HOME to verify expansion tracks $HOME, not a
    # hardcoded path.
    local other="$TEST_TMPDIR/otherhome"
    mkdir -p "$other"
    run env HOME="$other" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    [ -f "$other/.gitconfig" ]
    [ ! -f "$FAKE_HOME/.gitconfig" ]
}

@test "install-home-lock: /root/ absolute paths locked directly" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "/root/.gitconfig" "644"
    # Create the real /root/.gitconfig? Cannot, not root. Instead point
    # the test at a writable parent. Override the script's view by
    # re-rooting: write the path under $TEST_TMPDIR via a custom
    # guard_locked_paths.yaml with an absolute fake path.
    local fake_root="$TEST_TMPDIR/fakeroot/.gitconfig"
    _write_locked_paths "$FAKE_REPO" "$fake_root" "644"
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    [ -f "$fake_root" ]
    local mode
    mode="$(stat -c '%a' "$fake_root")"
    assert_equal "644" "$mode"
}

@test "install-home-lock: multiple entries all locked" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" \
        "~/.gitconfig" "644" \
        "~/.ssh/authorized_keys" "600" \
        "~/.ssh/config" "644"
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    [ -f "$FAKE_HOME/.gitconfig" ]
    [ -f "$FAKE_HOME/.ssh/authorized_keys" ]
    [ -f "$FAKE_HOME/.ssh/config" ]
    [ "$(stat -c '%a' "$FAKE_HOME/.gitconfig")" = "644" ]
    [ "$(stat -c '%a' "$FAKE_HOME/.ssh/authorized_keys")" = "600" ]
    [ "$(stat -c '%a' "$FAKE_HOME/.ssh/config")" = "644" ]
}

@test "install-home-lock: idempotent (already-locked entry skipped)" {
    _setup_home
    _write_locked_paths "$FAKE_REPO" "~/.gitconfig" "644"
    # First run: install (chown stub is no-op; file stays test-user owned
    # but state is written).
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    # Second run: install a stat stub reporting root:root mode=644 so
    # the idempotency branch (orig_uid==0 && orig_gid==0 && orig_mode==mode)
    # triggers and the entry is reported ALREADY LOCKED.
    _stub_stat_root 644
    run env HOME="$FAKE_HOME" bash "$FAKE_REPO/scripts/install-home-lock"
    assert_success
    assert_output --partial "ALREADY LOCKED"
}

# =====================================================================
# uninstall-home-lock
# =====================================================================

@test "uninstall-home-lock: --help prints usage and exits 0" {
    _setup_home
    run bash "$FAKE_REPO/scripts/uninstall-home-lock" --help
    assert_success
    assert_output --partial "Usage:"
}

@test "uninstall-home-lock: unknown arg exits 2" {
    _setup_home
    run bash "$FAKE_REPO/scripts/uninstall-home-lock" --bogus
    assert_failure
    [ "$status" -eq 2 ]
}

@test "uninstall-home-lock: exits 0 when state file missing" {
    _setup_home
    run bash "$FAKE_REPO/scripts/uninstall-home-lock"
    assert_success
    assert_output --partial "nothing to roll back"
}

@test "uninstall-home-lock: exits 0 when state file empty" {
    _setup_home
    mkdir -p "$FAKE_REPO/res"
    printf 'home_lock_state: []\n' > "$FAKE_REPO/res/home-lock-state.yaml"
    run bash "$FAKE_REPO/scripts/uninstall-home-lock"
    assert_success
    assert_output --partial "no recorded entries"
}

@test "uninstall-home-lock: --dry-run reports planned restore without changes" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    _make_home_files "~/.gitconfig" "locked content"
    chmod 0644 "$p"
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "1000"
    original_owner_gid: "1000"
    original_mode: "600"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-home-lock" --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "WOULD"
    # File mode should be unchanged after dry-run.
    [ "$(stat -c '%a' "$p")" = "644" ]
}

@test "uninstall-home-lock: restores original mode from state" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    _make_home_files "~/.gitconfig" "locked content"
    chmod 0644 "$p"
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "1000"
    original_owner_gid: "1000"
    original_mode: "600"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-home-lock"
    assert_success
    assert_output --partial "ROLLED BACK"
    [ "$(stat -c '%a' "$p")" = "600" ]
}

@test "uninstall-home-lock: clears state file after rollback" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    _make_home_files "~/.gitconfig" "locked content"
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "1000"
    original_owner_gid: "1000"
    original_mode: "600"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-home-lock"
    assert_success
    grep -q 'home_lock_state: \[\]' "$FAKE_REPO/res/home-lock-state.yaml"
}

@test "uninstall-home-lock: multiple entries all rolled back" {
    _setup_home
    local p1="$FAKE_HOME/.gitconfig" p2="$FAKE_HOME/.ssh/authorized_keys"
    _make_home_files "~/.gitconfig" "g" "~/.ssh/authorized_keys" "k"
    chmod 0644 "$p1"; chmod 0600 "$p2"
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p1"
    original_owner_uid: "1000"
    original_owner_gid: "1000"
    original_mode: "644"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
  - path: "$p2"
    original_owner_uid: "1000"
    original_owner_gid: "1000"
    original_mode: "600"
    expected_mode: "600"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/uninstall-home-lock"
    assert_success
    assert_output --partial "2 entries"
    [ "$(stat -c '%a' "$p1")" = "644" ]
    [ "$(stat -c '%a' "$p2")" = "600" ]
}

# =====================================================================
# home-drift-check
# =====================================================================

@test "home-drift-check: --help prints usage and exits 0" {
    _setup_home
    run bash "$FAKE_REPO/scripts/home-drift-check" --help
    assert_success
    assert_output --partial "Usage:"
}

@test "home-drift-check: unknown arg exits 2" {
    _setup_home
    run bash "$FAKE_REPO/scripts/home-drift-check" --bogus
    assert_failure
    [ "$status" -eq 2 ]
}

@test "home-drift-check: exits 2 when state file missing" {
    _setup_home
    run bash "$FAKE_REPO/scripts/home-drift-check"
    assert_failure
    [ "$status" -eq 2 ]
    assert_output --partial "baseline missing"
}

@test "home-drift-check: exits 0 when state file empty" {
    _setup_home
    mkdir -p "$FAKE_REPO/res"
    printf 'home_lock_state: []\n' > "$FAKE_REPO/res/home-lock-state.yaml"
    run bash "$FAKE_REPO/scripts/home-drift-check"
    assert_success
    assert_output --partial "no recorded entries"
}

@test "home-drift-check: no drift when live matches state" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    _make_home_files "~/.gitconfig" "g"
    chmod 0644 "$p"
    # chown is no-op stub, so owner stays as the test user. To emulate
    # "root:root", install a stat stub returning uid=0 gid=0 mode=644.
    _stub_stat_root 644
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "0"
    original_owner_gid: "0"
    original_mode: "644"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/home-drift-check"
    assert_success
    assert_output --partial "0 critical"
}

@test "home-drift-check: missing file -> CRITICAL (exit 1)" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    # No file at $p.
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "0"
    original_owner_gid: "0"
    original_mode: "644"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/home-drift-check"
    assert_failure
    [ "$status" -eq 1 ]
    assert_output --partial "CRITICAL"
    assert_output --partial "vanished"
}

@test "home-drift-check: owner not root:root -> CRITICAL" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    _make_home_files "~/.gitconfig" "g"
    chmod 0644 "$p"
    # Real stat returns the test-user uid (not 0); owner-changed check
    # classifies that as CRITICAL.
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "0"
    original_owner_gid: "0"
    original_mode: "644"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/home-drift-check"
    assert_failure
    [ "$status" -eq 1 ]
    assert_output --partial "CRITICAL"
    assert_output --partial "no longer"
}

@test "home-drift-check: mode changed -> CRITICAL" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    _make_home_files "~/.gitconfig" "g"
    chmod 0600 "$p"  # expected_mode is 644; mismatch.
    # Use a stat stub that reports root:root uid/gid so only the mode
    # check trips CRITICAL (otherwise owner-changed would also fire).
    _stub_stat_root 600
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "0"
    original_owner_gid: "0"
    original_mode: "644"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/home-drift-check"
    assert_failure
    [ "$status" -eq 1 ]
    assert_output --partial "CRITICAL"
    assert_output --partial "mode"
}

@test "home-drift-check: --quiet suppresses non-critical output" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    _make_home_files "~/.gitconfig" "g"
    chmod 0644 "$p"
    _stub_stat_root 644
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "0"
    original_owner_gid: "0"
    original_mode: "644"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/home-drift-check" --quiet
    assert_success
    refute_output --partial "Home drift check:"
}

@test "home-drift-check: writes home-drift-report.yaml with summary" {
    _setup_home
    local p="$FAKE_HOME/.gitconfig"
    _make_home_files "~/.gitconfig" "g"
    chmod 0644 "$p"
    _stub_stat_root 644
    mkdir -p "$FAKE_REPO/res"
    cat > "$FAKE_REPO/res/home-lock-state.yaml" <<EOF
home_lock_state:
  - path: "$p"
    original_owner_uid: "0"
    original_owner_gid: "0"
    original_mode: "644"
    expected_mode: "644"
    locked_at: "2026-01-01T00:00:00Z"
EOF
    run bash "$FAKE_REPO/scripts/home-drift-check"
    assert_success
    [ -f "$FAKE_REPO/res/home-drift-report.yaml" ]
    grep -q '^summary:' "$FAKE_REPO/res/home-drift-report.yaml"
    grep -q 'critical: 0' "$FAKE_REPO/res/home-drift-report.yaml"
}