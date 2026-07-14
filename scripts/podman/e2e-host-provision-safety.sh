#!/usr/bin/env bash
# Anti-brick and operator-path tests for host provision (privileged container).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-host-provision-safety.sh requires root" >&2
    exit 1
fi

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/podman/lib/host-provision-e2e.sh
source "$_SCRIPT_DIR/lib/host-provision-e2e.sh" || exit 1

_GUARD_ROOT="$(hp_e2e_guard_root)"

hp_e2e_safety_reset() {
    hp_e2e_cleanup
    HP_E2E_STATE_DIR=""
    HP_E2E_STATE_DIR_OWNED=0
    hp_e2e_init_state_dir_operator_path
    export HP_STATE_DIR="$WORKSPACE_GUARD_STATE_DIR"
    hp_e2e_write_configs
    hp_e2e_setup_fleet_user
}

hp_e2e_init_state_dir_operator_path() {
    HP_E2E_STATE_DIR="$(mktemp -d)"
    HP_E2E_STATE_DIR_OWNED=1
    export WORKSPACE_GUARD_STATE_DIR="$HP_E2E_STATE_DIR/state"
    export WORKSPACE_HOST_PROVISION_FILE="$HP_E2E_STATE_DIR/host-provision.yaml"
    export WORKSPACE_HOME_LOCK_USERS_FILE="$HP_E2E_STATE_DIR/home-lock-users.yaml"
    export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
    unset GUARD_NONINTERACTIVE WORKSPACE_ADMIN_PASSWORD_VERIFY
}

echo "==> Safety: phase 3 alone must not demote fleet user"
hp_e2e_safety_reset
_agent_uid_before="$(id -u "$HP_E2E_AGENT_USER")"
_rc=0
if bash "$_GUARD_ROOT/scripts/provision-host" --phase 3 --skip-phase5; then
    _rc=0
else
    _rc=$?
fi
if [[ $_rc -eq 0 ]]; then
    echo "ERROR: phase 3 alone should have failed" >&2
    exit 1
fi
if ! hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: fleet user lost sudo after refused phase 3 alone" >&2
    exit 1
fi
if [[ "$(id -u "$HP_E2E_AGENT_USER")" != "$_agent_uid_before" ]]; then
    echo "ERROR: fleet user uid changed unexpectedly" >&2
    exit 1
fi
echo "PASS: phase 3 alone blocked; fleet user still in sudo"

echo "==> Safety: bad admin password must abort before demotion"
hp_e2e_safety_reset
export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
bash "$_GUARD_ROOT/scripts/provision-host" --phase 1
export WORKSPACE_ADMIN_PASSWORD='definitely-wrong-password-99'
_rc=0
if bash "$_GUARD_ROOT/scripts/provision-host" --skip-phase5; then
    _rc=0
else
    _rc=$?
fi
if [[ $_rc -eq 0 ]]; then
    echo "ERROR: provision should fail on bad admin password" >&2
    exit 1
fi
if ! id "$HP_E2E_ADMIN_NAME" >/dev/null 2>&1; then
    echo "ERROR: admin should exist after failed run (phase 1)" >&2
    exit 1
fi
if ! hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: fleet user demoted despite failed password gate" >&2
    exit 1
fi
echo "PASS: bad password aborted; fleet user still in sudo; admin exists"

echo "==> Safety: phase 3 refused when phase-2 token deleted"
hp_e2e_safety_reset
export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
bash "$_GUARD_ROOT/scripts/provision-host" --phase 1
bash "$_GUARD_ROOT/scripts/provision-host" --phase 2
rm -f "$WORKSPACE_GUARD_STATE_DIR/host-provision.phase2.ok"
_rc=0
if bash "$_GUARD_ROOT/scripts/provision-host" --phase 3 --skip-phase5; then
    _rc=0
else
    _rc=$?
fi
if [[ $_rc -eq 0 ]]; then
    echo "ERROR: phase 3 should fail without phase-2 token" >&2
    exit 1
fi
if ! hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: fleet user demoted without valid phase-2 token" >&2
    exit 1
fi
echo "PASS: missing phase-2 token blocks demotion"

echo "==> Safety: operator path warn-only retains fleet sudo"
hp_e2e_safety_reset
export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
_uid_before="$(id -u "$HP_E2E_AGENT_USER")"
_out_file="$(mktemp)"
if ! bash "$_GUARD_ROOT/scripts/provision-host" --skip-phase5 >"$_out_file" 2>&1; then
    cat "$_out_file" >&2
    rm -f "$_out_file"
    echo "ERROR: operator-path provision failed" >&2
    exit 1
fi
if ! grep -q 'CRITICAL' "$_out_file"; then
    echo "ERROR: expected CRITICAL fleet sudo warning in output" >&2
    cat "$_out_file" >&2
    rm -f "$_out_file"
    exit 1
fi
if ! grep -q 'warn-only' "$_out_file"; then
    echo "ERROR: expected warn-only mode in output" >&2
    cat "$_out_file" >&2
    rm -f "$_out_file"
    exit 1
fi
rm -f "$_out_file"
if ! id "$HP_E2E_ADMIN_NAME" >/dev/null 2>&1; then
    echo "ERROR: admin missing after operator-path provision" >&2
    exit 1
fi
if ! hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: fleet user should retain group sudo (warn-only default)" >&2
    exit 1
fi
if ! hp_e2e_agent_has_effective_sudo; then
    echo "ERROR: fleet user should retain effective sudo (warn-only default)" >&2
    exit 1
fi
if [[ "$(id -u "$HP_E2E_AGENT_USER")" != "$_uid_before" ]]; then
    echo "ERROR: pre-existing fleet user uid changed" >&2
    exit 1
fi
_admin_sudo_rc=0
if runuser -u "$HP_E2E_ADMIN_NAME" -- sudo -n true 2>"$DEVNULL"; then
    _admin_sudo_rc=0
else
    _admin_sudo_rc=$?
fi
if [[ $_admin_sudo_rc -eq 0 ]]; then
    echo "ERROR: admin sudo must require a password (not NOPASSWD)" >&2
    exit 1
fi
echo "PASS: operator-path warn-only retained fleet sudo"

echo "==> Safety: --demote-fleet-sudo strips group sudo"
hp_e2e_safety_reset
export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
bash "$_GUARD_ROOT/scripts/provision-host" --skip-phase5 --demote-fleet-sudo
if hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: fleet user still in group sudo after --demote-fleet-sudo" >&2
    exit 1
fi
if hp_e2e_agent_has_effective_sudo; then
    echo "ERROR: fleet user still has effective sudo after --demote-fleet-sudo" >&2
    exit 1
fi
echo "PASS: --demote-fleet-sudo removed fleet sudo"

echo "==> Safety: direct-root cloud-init retained on warn-only; stripped on demote"
hp_e2e_safety_reset
hp_e2e_seed_direct_root_cloud_init
export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
bash "$_GUARD_ROOT/scripts/provision-host" --skip-phase5
if ! hp_e2e_agent_has_effective_sudo; then
    echo "ERROR: warn-only should retain cloud-init direct-root grant" >&2
    exit 1
fi
echo "PASS: warn-only retained cloud-init direct-root grant"

hp_e2e_safety_reset
hp_e2e_seed_direct_root_cloud_init
export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
bash "$_GUARD_ROOT/scripts/provision-host" --skip-phase5 --demote-fleet-sudo
if hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: fleet user still in group sudo after demote + cloud-init" >&2
    exit 1
fi
if hp_e2e_agent_has_effective_sudo; then
    echo "ERROR: fleet user still has effective sudo after demote + cloud-init" >&2
    exit 1
fi
if [[ -f /etc/sudoers.d/90-cloud-init-users ]]; then
    echo "ERROR: managed cloud-init sudoers drop-in should be removed or stripped" >&2
    exit 1
fi
echo "PASS: --demote-fleet-sudo stripped cloud-init direct-root grant"

echo "==> Safety: unmanaged direct-root grant blocks phase 3"
hp_e2e_safety_reset
cat > /etc/sudoers.d/99-e2e-direct-root-block <<EOF
${HP_E2E_AGENT_USER} ALL=(ALL:ALL) ALL
EOF
chmod 0440 /etc/sudoers.d/99-e2e-direct-root-block
export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
bash "$_GUARD_ROOT/scripts/provision-host" --phase 1
bash "$_GUARD_ROOT/scripts/provision-host" --phase 2
_rc=0
if bash "$_GUARD_ROOT/scripts/provision-host" --phase 3 --skip-phase5; then
    _rc=0
else
    _rc=$?
fi
if [[ $_rc -eq 0 ]]; then
    echo "ERROR: phase 3 should fail on unmanaged direct-root grant" >&2
    exit 1
fi
if ! hp_e2e_agent_has_effective_sudo; then
    echo "ERROR: fleet user should retain sudo when phase 3 is blocked" >&2
    exit 1
fi
echo "PASS: unmanaged direct-root grant blocked phase 3; fleet user unchanged"

echo "==> Safety: live probes use sudo -n (no interactive sudo -l)"
if grep -qE 'runuser -u .* -- sudo -l([^-]|$)' "$_GUARD_ROOT/scripts/lib/host-provision-sudo.sh"; then
    echo "ERROR: host-provision-sudo.sh still uses interactive sudo -l in runuser probe" >&2
    exit 1
fi
echo "PASS: runuser probes are non-interactive"

hp_e2e_cleanup
echo "==> Host provision safety E2E: ALL PASSED"