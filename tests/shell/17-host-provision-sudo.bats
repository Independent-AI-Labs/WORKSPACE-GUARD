#!/usr/bin/env bash
# 17-host-provision-sudo.bats: fleet sudo privilege_state, tickets, warn/demote paths.

bats_require_minimum_version 1.5.0

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

_hp_sudo_test_env() {
    HP_SUDOERS_DIR="$TEST_TMPDIR/sudoers.d"
    HP_SUDO_TICKET_DIR="$TEST_TMPDIR/sudo-ts"
    mkdir -p "$HP_SUDOERS_DIR" "$HP_SUDO_TICKET_DIR"
    export HP_SUDOERS_DIR WORKSPACE_SUDOERS_DIR="$HP_SUDOERS_DIR" HP_SUDO_TICKET_DIR
    # shellcheck source=scripts/lib/host-provision-users.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-users.sh"
    # shellcheck source=scripts/lib/host-provision-operator.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-operator.sh"
    # shellcheck source=scripts/lib/host-provision-sudo.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
}

@test "hp_sudo_ticket_path finds ticket in HP_SUDO_TICKET_DIR" {
    _hp_sudo_test_env
    touch "$HP_SUDO_TICKET_DIR/fleetuser"
    run hp_sudo_ticket_path fleetuser
    assert_success
    assert_equal "$HP_SUDO_TICKET_DIR/fleetuser" "$output"
}

@test "hp_sudo_ticket_path returns failure when no ticket" {
    _hp_sudo_test_env
    run hp_sudo_ticket_path nobody-here
    assert_failure
}

@test "hp_sudo_has_cached_ticket true when ticket file exists" {
    _hp_sudo_test_env
    touch "$HP_SUDO_TICKET_DIR/agent"
    run hp_sudo_has_cached_ticket agent
    assert_success
}

@test "hp_sudo_privilege_state privileged when user in sudoers drop-in" {
    _hp_sudo_test_env
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run hp_sudo_privilege_state agent
    assert_success
    assert_equal "privileged" "$output"
}

@test "hp_sudo_privilege_state privileged beats ticket file" {
    _hp_sudo_test_env
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    touch "$HP_SUDO_TICKET_DIR/agent"
    run hp_sudo_privilege_state agent
    assert_success
    assert_equal "privileged" "$output"
}

@test "hp_sudo_privilege_state ticket_active when ticket file and no sudoers ref" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required for sudo -l -U policy check"
    fi
    _hp_sudo_test_env
    local _user="hp-ticket-$$"
    useradd -m -s /bin/bash "$_user" 2>/dev/null || skip "cannot create test user"
    trap "userdel -r $_user 2>/dev/null || userdel $_user 2>/dev/null || true" EXIT
    touch "$HP_SUDO_TICKET_DIR/$_user"
    run hp_sudo_privilege_state "$_user"
    assert_success
    assert_equal "ticket_active" "$output"
}

@test "hp_sudo_privilege_state none when no grant and no ticket" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required for sudo -l -U policy check"
    fi
    _hp_sudo_test_env
    local _user="hp-none-$$"
    useradd -m -s /bin/bash "$_user" 2>/dev/null || skip "cannot create test user"
    trap "userdel -r $_user 2>/dev/null || userdel $_user 2>/dev/null || true" EXIT
    run hp_sudo_privilege_state "$_user"
    assert_success
    assert_equal "none" "$output"
}

@test "hp_sudo_privilege_state verify_failed for missing user" {
    _hp_sudo_test_env
    run hp_sudo_privilege_state definitely-missing-user-xyz-999
    assert_success
    assert_equal "verify_failed" "$output"
}

@test "hp_sudo_state_is_elevated distinguishes persistent and ticket" {
    _hp_sudo_test_env
    run hp_sudo_state_is_elevated privileged
    assert_success
    run hp_sudo_state_is_elevated ticket_active
    assert_success
    run hp_sudo_state_is_elevated none
    assert_failure
}

@test "hp_sudo_user_has_effective_sudo true for ticket_active state" {
    _hp_sudo_test_env
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run hp_sudo_user_has_effective_sudo agent
    assert_success
}

@test "hp_sudo_live_runuser_probe uses non-interactive sudo -n" {
    _hp_sudo_test_env
    grep -q 'sudo -n -l' "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    grep -q 'sudo -n -v' "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    ! grep -qE 'runuser -u .* -- sudo -l[^-]' "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
}

@test "hp_sudo_print_privilege_sources labels persistent vs session" {
    _hp_sudo_test_env
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    local _out=""
    _out="$(hp_sudo_print_privilege_sources agent 2>&1)"
    [[ "$_out" == *"persistent:"* ]]
    [[ "$_out" == *"session:"* ]]
}

@test "hp_sudo_warn_only_fleet_user prints CRITICAL for privileged user" {
    _hp_sudo_test_env
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_SUDO_TICKET_DIR='$HP_SUDO_TICKET_DIR'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_sudo_warn_only_fleet_user agent 2>&1
    "
    assert_success
    assert_output --partial "CRITICAL"
    assert_output --partial "retains persistent sudo"
    assert_output --partial "demotion skipped"
}

@test "hp_sudo_warn_only_fleet_user OK for none state" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required"
    fi
    _hp_sudo_test_env
    local _user="hp-warn-none-$$"
    useradd -m -s /bin/bash "$_user" 2>/dev/null || skip "cannot create test user"
    trap "userdel -r $_user 2>/dev/null || userdel $_user 2>/dev/null || true" EXIT
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_SUDO_TICKET_DIR='$HP_SUDO_TICKET_DIR'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_sudo_warn_only_fleet_user '$_user' 2>&1
    "
    assert_success
    assert_output --partial "no effective sudo"
}

@test "hp_sudo_demote_fleet_user strips sudoers drop-in when demoting" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required for visudo/strip"
    fi
    if ! command -v visudo >/dev/null 2>&1; then
        skip "visudo required"
    fi
    _hp_sudo_test_env
    local _user="hp-demote-$$"
    useradd -m -s /bin/bash "$_user" 2>/dev/null || skip "cannot create test user"
    trap "userdel -r $_user 2>/dev/null || userdel $_user 2>/dev/null || true" EXIT
    printf '%s\n' "# test" "${_user} ALL=(ALL:ALL) ALL" > "$HP_SUDOERS_DIR/90-cloud-init-users"
    chmod 0440 "$HP_SUDOERS_DIR/90-cloud-init-users"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_SUDO_TICKET_DIR='$HP_SUDO_TICKET_DIR'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_sudo_demote_fleet_user '$_user' 2>&1
    "
    assert_success
    assert_output --partial "demoting now"
    run hp_sudo_privilege_state "$_user"
    assert_equal "none" "$output"
}

@test "hp_sudo_revoke_cached_ticket removes ticket file" {
    _hp_sudo_test_env
    touch "$HP_SUDO_TICKET_DIR/revoke-me"
    hp_sudo_revoke_cached_ticket revoke-me
    [[ ! -f "$HP_SUDO_TICKET_DIR/revoke-me" ]]
}

@test "hp_sudo_require_no_effective_sudo fails on ticket_active" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required for ticket_active without sudoers"
    fi
    _hp_sudo_test_env
    local _user="hp-req-none-$$"
    useradd -m -s /bin/bash "$_user" 2>/dev/null || skip "cannot create test user"
    trap "userdel -r $_user 2>/dev/null || userdel $_user 2>/dev/null || true" EXIT
    touch "$HP_SUDO_TICKET_DIR/$_user"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_SUDO_TICKET_DIR='$HP_SUDO_TICKET_DIR'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_sudo_require_no_effective_sudo '$_user' 2>&1
    "
    assert_failure
    assert_output --partial "ticket_active"
}

@test "provision-host accepts --demote-fleet-sudo in usage" {
    run bash "$GUARD_ROOT/scripts/provision-host" --help
    assert_success
    assert_output --partial "--demote-fleet-sudo"
    assert_output --partial "warn"
}

@test "hp_operator_mandatory_fleet_report prints CRITICAL for sudoers grant" {
    _hp_sudo_test_env
    cat > "$TEST_TMPDIR/fleet.yaml" <<'EOF'
version: 1
users:
  - name: agent
EOF
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_SUDO_TICKET_DIR='$HP_SUDO_TICKET_DIR'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_operator_mandatory_fleet_report '$TEST_TMPDIR/fleet.yaml' admin 2>&1
    "
    assert_success
    assert_output --partial "Fleet sudo audit"
    assert_output --partial "CRITICAL"
    assert_output --partial "PERSISTENT SUDO"
}

@test "hp_operator_print_completion_banner warn-only mentions retain" {
    _hp_sudo_test_env
    cat > "$TEST_TMPDIR/fleet.yaml" <<'EOF'
version: 1
users:
  - name: agent
EOF
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/50-test"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_SUDO_TICKET_DIR='$HP_SUDO_TICKET_DIR'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_operator_print_completion_banner '$TEST_TMPDIR/fleet.yaml' 0 2>&1
    "
    assert_output --partial "warn-only"
    assert_output --partial "retains sudo"
}

@test "hp_operator_print_completion_banner demote mode mentions demotion" {
    _hp_sudo_test_env
    cat > "$TEST_TMPDIR/fleet.yaml" <<'EOF'
version: 1
users:
  - name: agent
EOF
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_SUDO_TICKET_DIR='$HP_SUDO_TICKET_DIR'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_operator_print_completion_banner '$TEST_TMPDIR/fleet.yaml' 1 2>&1
    "
    assert_output --partial "demotion was requested"
}

@test "hp_sudo_listing_shows_privilege false for not allowed" {
    _hp_sudo_test_env
    run hp_sudo_listing_shows_privilege $'User agent is not allowed to run sudo on host.\n'
    assert_failure
}

@test "hp_sudo_listing_shows_privilege true for ALL grant" {
    _hp_sudo_test_env
    run hp_sudo_listing_shows_privilege $'User agent may run the following commands:\n    (ALL : ALL) ALL\n'
    assert_success
}

@test "hp_sudo_managed_strip allowlist includes cloud-init files" {
    _hp_sudo_test_env
    run hp_sudo_managed_strip_is_allowlisted 90-cloud-init-users
    assert_success
    run hp_sudo_managed_strip_is_allowlisted 99-foreign-file
    assert_failure
}

@test "hp_sudo_preflight_fleet_user reports ticket_active" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required"
    fi
    _hp_sudo_test_env
    local _user="hp-preflight-$$"
    useradd -m -s /bin/bash "$_user" 2>/dev/null || skip "cannot create test user"
    trap "userdel -r $_user 2>/dev/null || userdel $_user 2>/dev/null || true" EXIT
    touch "$HP_SUDO_TICKET_DIR/$_user"
    run bash -c "
        export HP_SUDOERS_DIR='$HP_SUDOERS_DIR' WORKSPACE_SUDOERS_DIR='$HP_SUDOERS_DIR' HP_SUDO_TICKET_DIR='$HP_SUDO_TICKET_DIR'
        source '$GUARD_ROOT/scripts/lib/host-provision-users.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-operator.sh'
        source '$GUARD_ROOT/scripts/lib/host-provision-sudo.sh'
        hp_sudo_preflight_fleet_user '$_user'
    "
    assert_output --partial "TICKET ACTIVE"
}