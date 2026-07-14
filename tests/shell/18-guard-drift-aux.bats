#!/usr/bin/env bash
# 18-guard-drift-aux.bats: git-ssh-wrapper / agent-git-identity drift and
# uninstall artifact preservation helpers.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "guard-drift-aux: stale git-ssh-wrapper detected" {
    local ci_root tmp_state ref_ssh
    ci_root="$(cd "$GUARD_ROOT/../CI" && pwd)"
    tmp_state="$TEST_TMPDIR/guard-state"
    mkdir -p "$tmp_state"
    printf 'stale-wrapper\n' > "$tmp_state/git-ssh-wrapper"
    ref_ssh="$TEST_TMPDIR/workspace-git-ssh"
    printf 'fresh-binary\n' > "$ref_ssh"
    chmod 0755 "$ref_ssh"

    run bash -c "
        export WORKSPACE_GUARD_STATE_DIR='$tmp_state'
        _guard_dir='$GUARD_ROOT'
        GUARD_GIT_SSH_BIN='$ref_ssh'
        source \"$ci_root/lib/guard-drift.sh\"
        guard_host_exec_aux_drift_reasons
    "
    assert_success
    assert_output --partial "git-ssh-wrapper stale"
}

@test "guard-drift-aux: missing agent-git-identity detected" {
    local ci_root tmp_state ref_ssh
    ci_root="$(cd "$GUARD_ROOT/../CI" && pwd)"
    tmp_state="$TEST_TMPDIR/guard-state"
    mkdir -p "$tmp_state"
    ref_ssh="$TEST_TMPDIR/workspace-git-ssh"
    cp "$GUARD_ROOT/target/release/workspace-git-ssh" "$ref_ssh" 2>/dev/null \
        || printf 'bin\n' > "$ref_ssh"
    install -m 0755 "$ref_ssh" "$tmp_state/git-ssh-wrapper"

    run bash -c "
        export WORKSPACE_GUARD_STATE_DIR='$tmp_state'
        _guard_dir='$GUARD_ROOT'
        GUARD_GIT_SSH_BIN='$ref_ssh'
        source \"$ci_root/lib/guard-drift.sh\"
        guard_host_exec_aux_drift_reasons
    "
    assert_success
    assert_output --partial "agent-git-identity missing"
}

@test "guard-host-exec: remove git install artifacts preserves host-provision.ok" {
    local ci_root tmp_state
    ci_root="$(cd "$GUARD_ROOT/../CI" && pwd)"
    tmp_state="$TEST_TMPDIR/guard-state"
    mkdir -p "$tmp_state/ssh-keys"
    printf 'admin=breakglass\n' > "$tmp_state/host-provision.ok"
    printf 'host-exec\n' > "$tmp_state/deployment-class"
    printf 'wrapper\n' > "$tmp_state/git-ssh-wrapper"

    run bash -c "
        export WORKSPACE_GUARD_STATE_DIR='$tmp_state'
        _guard_dir='$GUARD_ROOT'
        source \"$ci_root/lib/guard-drift.sh\"
        source \"$ci_root/lib/guard-host-exec.sh\"
        guard_remove_git_install_artifacts
        [[ -f '$tmp_state/host-provision.ok' ]]
        [[ -d '$tmp_state/ssh-keys' ]]
        [[ ! -f '$tmp_state/deployment-class' ]]
        [[ ! -f '$tmp_state/git-ssh-wrapper' ]]
    "
    assert_success
}

@test "guard-host-exec: purge refuses without GUARD_PURGE_CONFIRM" {
    local ci_root tmp_state
    ci_root="$(cd "$GUARD_ROOT/../CI" && pwd)"
    tmp_state="$TEST_TMPDIR/guard-state"
    mkdir -p "$tmp_state"
    printf 'admin=breakglass\n' > "$tmp_state/host-provision.ok"

    run bash -c "
        export WORKSPACE_GUARD_STATE_DIR='$tmp_state'
        _guard_dir='$GUARD_ROOT'
        log_error() { printf 'ERR:%s\n' \"\$*\"; }
        log_warn() { :; }
        log_info() { :; }
        source \"$ci_root/lib/guard-host-exec.sh\"
        purge_guard_state
    "
    assert_failure
    assert_output --partial "GUARD_PURGE_CONFIRM=1"
    [ -f "$tmp_state/host-provision.ok" ]
}