#!/usr/bin/env bash
# Podman-native host provision E2E (phases 0-4; no guard stack).
# Uses container-isolated configs and WORKSPACE_GUARD_STATE_DIR ,  no host repo pollution.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-host-provision.sh requires root (container root)" >&2
    exit 1
fi

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/podman/lib/host-provision-e2e.sh
source "$_SCRIPT_DIR/lib/host-provision-e2e.sh" || exit 1

_GUARD_ROOT="$(hp_e2e_guard_root)"
if [[ ! -x "$_GUARD_ROOT/scripts/provision-host" ]]; then
    echo "ERROR: provision-host not found at $_GUARD_ROOT" >&2
    exit 1
fi

trap hp_e2e_cleanup EXIT

hp_e2e_prepare_git_safe_directory
hp_e2e_init_state_dir
hp_e2e_write_configs
hp_e2e_setup_fleet_user
hp_e2e_install_foreign_sudoers

echo "==> Host provision E2E: phase 0 (install gate before marker)"
hp_e2e_assert_install_gate_blocks

echo "==> Host provision E2E: phases 1-4 (skip guard stack)"
hp_e2e_run_phases_1_through_4

echo "==> Host provision E2E: post phase 4 assertions (warn-only default)"
hp_e2e_assert_post_phase4 0

echo "==> Host provision E2E: demote opt-in path"
hp_e2e_cleanup
hp_e2e_init_state_dir
hp_e2e_write_configs
hp_e2e_setup_fleet_user
hp_e2e_install_foreign_sudoers
hp_e2e_run_phases_1_through_4 --demote-fleet-sudo
hp_e2e_assert_post_phase4 1

echo "==> Host provision E2E: ALL PASSED"