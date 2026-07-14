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

echo "==> Safety: phase 3 alone must not change fleet user"
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
echo "PASS: phase 3 alone blocked; fleet user unchanged"

echo "==> Safety: bad admin password must abort before phase 3"
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
if ! hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: fleet user should be unchanged after bad password" >&2
    exit 1
fi
echo "PASS: bad password aborted; fleet user unchanged; admin exists"

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
    echo "ERROR: fleet user should be unchanged without phase-2 token" >&2
    exit 1
fi
echo "PASS: missing phase-2 token blocks phase 3"

echo "==> Safety: full provision prints RED CRITICAL when fleet user has sudo"
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
if ! grep -q 'CRITICAL: fleet user' "$_out_file"; then
    echo "ERROR: expected RED CRITICAL for fleet user with sudo" >&2
    cat "$_out_file" >&2
    rm -f "$_out_file"
    exit 1
fi
if ! grep -q 'HAS SUDO' "$_out_file"; then
    echo "ERROR: expected HAS SUDO in CRITICAL banner" >&2
    cat "$_out_file" >&2
    rm -f "$_out_file"
    exit 1
fi
rm -f "$_out_file"
if ! hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: fleet user should still be in group sudo (no demotion)" >&2
    exit 1
fi
if [[ "$(id -u "$HP_E2E_AGENT_USER")" != "$_uid_before" ]]; then
    echo "ERROR: fleet user uid changed" >&2
    exit 1
fi
echo "PASS: RED CRITICAL printed; fleet sudo unchanged"

echo "==> Safety: --demote-fleet-sudo rejected"
hp_e2e_safety_reset
_rc=0
if bash "$_GUARD_ROOT/scripts/provision-host" --demote-fleet-sudo --skip-phase5 2>"$DEVNULL"; then
    _rc=0
else
    _rc=$?
fi
if [[ $_rc -eq 0 ]]; then
    echo "ERROR: --demote-fleet-sudo should be rejected" >&2
    exit 1
fi
echo "PASS: --demote-fleet-sudo removed"

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