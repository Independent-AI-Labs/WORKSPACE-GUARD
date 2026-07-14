#!/usr/bin/env bash
# 16-host-provision.bats: unit helpers (parse, sudo drop-in). Full integration: make test-podman-provision.

bats_require_minimum_version 1.5.0

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

_write_host_config() {
    local dir="$1"
    mkdir -p "$dir/config"
    cat > "$dir/config/host-provision.yaml" <<'EOF'
version: 1
user_management:
  enabled: true
admin:
  name: testadmin
  shell: /bin/bash
  create_home: true
  git_name: Test Admin
  git_email: admin@test.local
fleet_users_file: config/home-lock-users.yaml
guard_stack:
  install_lock: false
  install_auditd: false
EOF
    cat > "$dir/config/home-lock-users.yaml" <<'EOF'
version: 1
users:
  - name: agent
    git_name: Test Agent
    git_email: agent@test.local
EOF
}

@test "hp_user_mgmt_enabled parses true from config" {
    _write_host_config "$TEST_TMPDIR"
    export HP_CONFIG="$TEST_TMPDIR/config/host-provision.yaml" HP_REPO_ROOT="$TEST_TMPDIR"
    # shellcheck source=scripts/lib/host-provision-parse.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-parse.sh"
    run hp_user_mgmt_enabled
    assert_success
}

@test "hp_admin_name reads configured admin" {
    _write_host_config "$TEST_TMPDIR"
    export HP_CONFIG="$TEST_TMPDIR/config/host-provision.yaml" HP_REPO_ROOT="$TEST_TMPDIR"
    # shellcheck source=scripts/lib/host-provision-parse.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-parse.sh"
    run hp_admin_name
    assert_success
    assert_equal "testadmin" "$output"
}

@test "provision-host refuses non-root invocation" {
    if [[ "$(id -u)" -eq 0 ]]; then
        skip "non-root test requires unprivileged user"
    fi
    _write_host_config "$TEST_TMPDIR"
    export WORKSPACE_HOST_PROVISION_FILE="$TEST_TMPDIR/config/host-provision.yaml"
    run bash "$GUARD_ROOT/scripts/provision-host" --preflight
    assert_failure
    assert_output --partial "needs root"
}

@test "hp_admin_break_glass_ready false when admin missing" {
    HP_SUDOERS_ADMIN="$TEST_TMPDIR/90-workspace-guard-admin"
    HP_STATE_DIR="$TEST_TMPDIR/state"
    export HP_SUDOERS_ADMIN HP_STATE_DIR
    # shellcheck source=scripts/lib/host-provision-admin.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-admin.sh"
    run hp_admin_break_glass_ready nonexistent-admin-user-xyz
    assert_failure
}

@test "hp_phase2_token gates phase 3 without write" {
    HP_STATE_DIR="$TEST_TMPDIR/state"
    mkdir -p "$HP_STATE_DIR"
    export HP_STATE_DIR
    # shellcheck source=scripts/lib/host-provision-admin.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-admin.sh"
    run hp_phase2_token_valid_for testadmin
    assert_failure
}

@test "provision-host dry-run phase 1 as root or skip" {
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required for provision-host integration"
    fi
    _write_host_config "$TEST_TMPDIR"
    cp "$GUARD_ROOT/scripts/provision-host" "$TEST_TMPDIR/provision-host"
    cp -r "$GUARD_ROOT/scripts/lib" "$TEST_TMPDIR/scripts/"
    mkdir -p "$TEST_TMPDIR/scripts"
    cp -r "$GUARD_ROOT/scripts/lib" "$TEST_TMPDIR/scripts/lib"
    export WORKSPACE_HOST_PROVISION_FILE="$TEST_TMPDIR/config/host-provision.yaml"
    run bash "$GUARD_ROOT/scripts/provision-host" --dry-run --phase 1
    assert_success
    assert_output --partial "Phase 1"
}

@test "hp_sudo detects NOPASSWD direct root grant in sudoers text" {
    HP_SUDOERS_DIR="$TEST_TMPDIR/sudoers.d"
    export HP_SUDOERS_DIR WORKSPACE_SUDOERS_DIR="$HP_SUDOERS_DIR"
    # shellcheck source=scripts/lib/host-provision-users.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-users.sh"
    # shellcheck source=scripts/lib/host-provision-sudo.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    run hp_sudo_user_has_direct_root_grant_in_text agent $'agent ALL=(ALL) NOPASSWD:ALL\n'
    assert_success
}

@test "hp_sudo user in sudoers file counts as effective sudo" {
    HP_SUDOERS_DIR="$TEST_TMPDIR/sudoers.d"
    mkdir -p "$HP_SUDOERS_DIR"
    echo 'agent ALL=(ALL) NOPASSWD:ALL' > "$HP_SUDOERS_DIR/99-test-grant"
    export HP_SUDOERS_DIR WORKSPACE_SUDOERS_DIR="$HP_SUDOERS_DIR"
    # shellcheck source=scripts/lib/host-provision-users.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-users.sh"
    # shellcheck source=scripts/lib/host-provision-sudo.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    run hp_sudo_user_has_effective_sudo agent
    assert_success
}

@test "hp_sudo detects direct root grant in sudoers text" {
    HP_SUDOERS_DIR="$TEST_TMPDIR/sudoers.d"
    mkdir -p "$HP_SUDOERS_DIR"
    export HP_SUDOERS_DIR WORKSPACE_SUDOERS_DIR="$HP_SUDOERS_DIR"
    # shellcheck source=scripts/lib/host-provision-users.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-users.sh"
    # shellcheck source=scripts/lib/host-provision-sudo.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    run hp_sudo_user_has_direct_root_grant_in_text agent $'agent ALL=(ALL:ALL) ALL\n'
    assert_success
    run hp_sudo_user_has_direct_root_grant_in_text agent $'# agent ALL=(ALL) ALL\n'
    assert_failure
}

@test "hp_sudo foreign direct root detected outside managed allowlist" {
    HP_SUDOERS_DIR="$TEST_TMPDIR/sudoers.d"
    mkdir -p "$HP_SUDOERS_DIR"
    echo 'agent ALL=(ALL:ALL) ALL' > "$HP_SUDOERS_DIR/99-foreign-operator"
    chmod 0444 "$HP_SUDOERS_DIR/99-foreign-operator"
    export HP_SUDOERS_DIR WORKSPACE_SUDOERS_DIR="$HP_SUDOERS_DIR"
    # shellcheck source=scripts/lib/host-provision-users.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-users.sh"
    # shellcheck source=scripts/lib/host-provision-sudo.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    run hp_sudo_user_has_foreign_direct_root agent
    assert_success
}

@test "hp_sudo managed cloud-init direct root is not foreign" {
    HP_SUDOERS_DIR="$TEST_TMPDIR/sudoers.d"
    mkdir -p "$HP_SUDOERS_DIR"
    echo 'agent ALL=(ALL:ALL) ALL' > "$HP_SUDOERS_DIR/90-cloud-init-users"
    export HP_SUDOERS_DIR WORKSPACE_SUDOERS_DIR="$HP_SUDOERS_DIR"
    # shellcheck source=scripts/lib/host-provision-users.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-users.sh"
    # shellcheck source=scripts/lib/host-provision-sudo.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    run hp_sudo_user_has_foreign_direct_root agent
    assert_failure
    run hp_sudo_user_has_direct_root_grant_in_file agent "$HP_SUDOERS_DIR/90-cloud-init-users"
    assert_success
}

@test "hp_sudo_strip_user_from_dropin removes fleet line" {
    HP_SUDOERS_DIR="$TEST_TMPDIR/sudoers.d"
    mkdir -p "$HP_SUDOERS_DIR"
    printf '%s\n' 'agent ALL=(ALL:ALL) ALL' > "$HP_SUDOERS_DIR/90-cloud-init-users"
    export HP_SUDOERS_DIR WORKSPACE_SUDOERS_DIR="$HP_SUDOERS_DIR"
    # shellcheck source=scripts/lib/host-provision-users.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-users.sh"
    # shellcheck source=scripts/lib/host-provision-sudo.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-sudo.sh"
    hp_sudo_strip_user_from_dropin agent "$HP_SUDOERS_DIR/90-cloud-init-users"
    [[ ! -f "$HP_SUDOERS_DIR/90-cloud-init-users" ]]
}

@test "hp_config_error_missing_host_provision prints remediation" {
    export HP_REPO_ROOT="$GUARD_ROOT"
    # shellcheck source=scripts/lib/host-provision-parse.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-parse.sh"
    run bash -c "
        export HP_REPO_ROOT='$GUARD_ROOT'
        source '$GUARD_ROOT/scripts/lib/host-provision-parse.sh'
        hp_config_error_missing_host_provision '$TEST_TMPDIR/missing-host-provision.yaml' 2>&1
    "
    assert_failure
    assert_output --partial "host provision config missing"
    assert_output --partial "cp config/host-provision.yaml.example config/host-provision.yaml"
    assert_output --partial "SPEC-HOST-PROVISION.md"
}

@test "hp_config_error_missing_fleet_file prints remediation" {
    run bash -c "
        export HP_REPO_ROOT='$GUARD_ROOT'
        source '$GUARD_ROOT/scripts/lib/host-provision-parse.sh'
        hp_config_error_missing_fleet_file '$TEST_TMPDIR/missing-fleet.yaml' 'unit test' 2>&1
    "
    assert_failure
    assert_output --partial "fleet users file missing"
    assert_output --partial "user_management.enabled is true"
    assert_output --partial "home-lock-users.yaml.example"
    assert_output --partial "SPEC-GIT-IDENTITY.md"
}

@test "hp_config_require_fleet_file skips when user_management disabled" {
    run bash -c "
        export HP_REPO_ROOT='$GUARD_ROOT'
        source '$GUARD_ROOT/scripts/lib/host-provision-parse.sh'
        hp_config_require_fleet_file '$TEST_TMPDIR/nope.yaml' 0
    "
    assert_success
}

@test "admin sudoers drop-in contains managed markers" {
    _write_host_config "$TEST_TMPDIR"
    HP_SUDOERS_ADMIN="$TEST_TMPDIR/90-workspace-guard-admin"
    export HP_SUDOERS_ADMIN
    # shellcheck source=scripts/lib/host-provision-admin.sh
    source "$GUARD_ROOT/scripts/lib/host-provision-admin.sh"
    if [[ "$(id -u)" -ne 0 ]]; then
        skip "root required for visudo/install drop-in test"
    fi
    hp_admin_install_sudoers_dropin testadmin
    grep -q "BEGIN workspace-guard managed" "$HP_SUDOERS_ADMIN"
    grep -q "testadmin ALL=(ALL:ALL) ALL" "$HP_SUDOERS_ADMIN"
}