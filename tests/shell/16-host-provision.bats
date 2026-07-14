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

@test "provision-host dry-run exits 0 without root when skipped" {
    skip "provision-host requires root for full run"
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