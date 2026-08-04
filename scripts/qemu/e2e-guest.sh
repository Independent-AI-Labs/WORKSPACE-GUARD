#!/usr/bin/env bash
# Authoritative WORKSPACE-GUARD E2E inside a bare QEMU Linux guest.
# Mutates guest / only. Requires root. See WORKSPACE-VM SPEC-VM-HYPERVISOR §12.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-guest.sh requires root inside the QEMU guest" >&2
    exit 1
fi

_WORKSPACE_ROOT="${WORKSPACE_ROOT:-/opt/workspace}"
_PROJECTS="${_WORKSPACE_ROOT}/projects"
_GUARD_ROOT="${_PROJECTS}/WORKSPACE-GUARD"
_CI_ROOT="${_PROJECTS}/CI"

if [[ ! -f "${_CI_ROOT}/scripts/bootstrap-workspace-guard" ]]; then
    echo "ERROR: bootstrap-workspace-guard not found at ${_CI_ROOT}" >&2
    exit 1
fi

if [[ ! -d "${_GUARD_ROOT}/scripts/podman" ]]; then
    echo "ERROR: WORKSPACE-GUARD not found at ${_GUARD_ROOT}" >&2
    exit 1
fi

if [[ ! -e /projects ]]; then
    ln -s "${_PROJECTS}" /projects
    echo "Linked /projects -> ${_PROJECTS}"
fi

cd "${_GUARD_ROOT}"

echo "==> QEMU guest: installing shell guard prerequisite..."
make install-shell-guard

echo "==> QEMU guest: host-exec E2E (authoritative)..."
bash scripts/podman/e2e-host-exec.sh

echo "==> QEMU guest: uninstalling shell guard prerequisite..."
make uninstall-shell-guard

if [[ "${E2E_SHELL_GUARD:-0}" == "1" ]]; then
    echo "==> QEMU guest: shell-guard E2E (authoritative)..."
    bash scripts/qemu/e2e-shell-guard-guest.sh
fi

echo "==> QEMU guest E2E complete"
