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

echo "==> QEMU guest: capability-mode E2E (authoritative)..."
bash scripts/podman/e2e-capability.sh

echo "==> QEMU guest E2E complete"