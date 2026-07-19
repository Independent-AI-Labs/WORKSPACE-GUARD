#!/usr/bin/env bash
# 17-host-provision-sudo.bats: fleet RED/YELLOW audit; no demotion.

bats_require_minimum_version 1.5.0

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

_hp_sudo_test_env() {
    HP_SUDOERS_DIR="$TEST_TMPDIR/sudoers.d"
    HP_SUDO_TICKET_DIR="$TEST_TMPDIR/sudo-ts"
    mkdir -p "$HP_SUDOERS_DIR" "$HP_SUDO_TICKET_DIR"
    export HP_SUDOERS_DIR WORKSPACE_SUDOERS_DIR="$HP_SUDOERS_DIR" HP_SUDO_TICKET_DIR HP_REPO_ROOT="$GUARD_ROOT"
    # shellcheck source=scripts/lib/host-provision-parse.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-parse.sh"
    # shellcheck source=scripts/lib/host-provision-users.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-users.sh"
    # shellcheck source=scripts/lib/host-provision-operator.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-operator.sh"
    # shellcheck source=scripts/lib/host-provision-sudo.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
}

@test "hp_sudo_privilege_state privileged when user in sudoers drop-in" {
    _hp_sudo_test_env
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run hp_sudo_privilege_state agent
    assert_success
    assert_equal "privileged" "$output"
}

@test "hp_sudo_privilege_state none without sudoers ref" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required for sudo -l -U"
    fi
    _hp_sudo_test_env
    local _user="hp-none-$$"
    useradd -m -s /bin/bash "$_user" 2>/dev/null || skip "cannot create test user"
    trap "userdel -r $_user 2>/dev/null || userdel $_user 2>/dev/null || true" EXIT
    run hp_sudo_privilege_state "$_user"
    assert_equal "none" "$output"
}

@test "hp_operator_audit_fleet_user RED when privileged" {
    _hp_sudo_test_env
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_REPO_ROOT='$GUARD_ROOT'
        source '$GUARD_ROOT/scripts/lib/host-provision-parse.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_operator_audit_fleet_user agent 2>&1
    "
    assert_output --partial "CRITICAL"
    assert_output --partial "HAS SUDO"
    assert_output --partial "DANGER (GAP-C06)"
    assert_output --partial "bypasses the guard stack"
}

@test "hp_operator_audit_fleet_user YELLOW when none" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required"
    fi
    _hp_sudo_test_env
    local _user="hp-yellow-$$"
    useradd -m -s /bin/bash "$_user" 2>/dev/null || skip "cannot create test user"
    trap "userdel -r $_user 2>/dev/null || userdel $_user 2>/dev/null || true" EXIT
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_REPO_ROOT='$GUARD_ROOT'
        source '$GUARD_ROOT/scripts/lib/host-provision-parse.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_operator_audit_fleet_user '$_user' 2>&1
    "
    assert_output --partial "WARN:"
    assert_output --partial "NO sudo"
}

@test "hp_operator_mandatory_fleet_report prints RED for sudoers grant" {
    _hp_sudo_test_env
    cat > "$TEST_TMPDIR/fleet.yaml" <<'EOF'
version: 1
users:
  - name: agent
EOF
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_REPO_ROOT='$GUARD_ROOT'
        source '$GUARD_ROOT/scripts/lib/host-provision-parse.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_operator_mandatory_fleet_report '$TEST_TMPDIR/fleet.yaml' admin 2>&1
    "
    assert_output --partial "CRITICAL"
    assert_output --partial "HAS SUDO"
    assert_output --partial "DANGER (GAP-C06)"
}

@test "hp_operator_print_completion_banner lists RED and YELLOW" {
    _hp_sudo_test_env
    cat > "$TEST_TMPDIR/fleet.yaml" <<'EOF'
version: 1
users:
  - name: agent
EOF
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_REPO_ROOT='$GUARD_ROOT'
        source '$GUARD_ROOT/scripts/lib/host-provision-parse.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_operator_print_completion_banner '$TEST_TMPDIR/fleet.yaml' admin 2>&1
    "
    assert_output --partial "HAS sudo (CRITICAL)"
    assert_output --partial "DANGER (GAP-C06)"
    assert_output --partial "no changes made"
}

@test "provision-host rejects --demote-fleet-sudo" {
    run bash "$GUARD_ROOT/scripts/provision-host" --demote-fleet-sudo --help
    assert_failure
    assert_output --partial "removed"
}

@test "phase5 Makefile always builds (no skip-if-fresh)" {
    ! grep -q 'skipping cargo build' "$GUARD_ROOT/Makefile"
    ! grep -q '_skip=1' "$GUARD_ROOT/Makefile"
}

@test "Makefile REPO_ROOT does not depend on git rev-parse" {
    ! grep -q 'git rev-parse --show-toplevel' "$GUARD_ROOT/Makefile"
    grep -q '_WORKSPACE_GUARD_MK' "$GUARD_ROOT/Makefile"
}

@test "phase5 install forces guard reconcile" {
    grep -q 'GUARD_FORCE_RECONCILE=1' "$GUARD_ROOT/Makefile"
}

@test "provision-host writes marker after phase 5 install" {
    local script phase5_line marker_line
    script="$GUARD_ROOT/scripts/provision-host"
    phase5_line="$(grep -n 'install-guard-stack' "$script" | head -1 | cut -d: -f1)"
    marker_line="$(grep -n 'hp_write_marker' "$script" | awk -F: -v p="$phase5_line" '$1 > p {print $1}' | head -1)"
    [[ -n "$marker_line" && "$marker_line" -gt "$phase5_line" ]]
}

@test "hp_sudo_live_runuser_probe uses non-interactive sudo -n" {
    grep -q 'sudo -n -l' "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    grep -q 'sudo -n -v' "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    ! grep -qE 'runuser -u [^ ]+ sudo -l([^-]|$)' "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
}

@test "hp_sudo_strip_user_from_dropin still works for unit tests" {
    _hp_sudo_test_env
    printf '%s\n' 'agent ALL=(ALL:ALL) ALL' > "$HP_SUDOERS_DIR/90-cloud-init-users"
    hp_sudo_strip_user_from_dropin agent "$HP_SUDOERS_DIR/90-cloud-init-users"
    [[ ! -f "$HP_SUDOERS_DIR/90-cloud-init-users" ]]
}