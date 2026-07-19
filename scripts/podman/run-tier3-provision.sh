#!/usr/bin/env bash
# Run host-provision E2E only (privileged container).
set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/../.." && pwd)"
_PROJECTS_ROOT="$(cd "$_REPO_ROOT/.." && pwd)"
_IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

resolve_podman() {
    if _podman_probe="$(command -v real-podman 2>&1)"; then
        echo "real-podman"
        return 0
    fi
    if _podman_probe="$(command -v podman 2>&1)"; then
        echo "podman"
        return 0
    fi
    echo "ERROR: podman not found" >&2
    return 1
}

if [[ ! -d "$_PROJECTS_ROOT/CI" ]]; then
    echo "ERROR: WORKSPACE-CI not found at $_PROJECTS_ROOT/CI" >&2
    exit 1
fi

PODMAN="$(resolve_podman)"

if ! "$PODMAN" image exists "$_IMAGE"; then
    echo "==> Test image $_IMAGE missing; building from Containerfile.test..."
    "$PODMAN" build -f "$_REPO_ROOT/Containerfile.test" -t "$_IMAGE" "$_REPO_ROOT"
fi

echo "==> Host provision E2E in $_IMAGE"

"$PODMAN" run --rm --privileged \
    -v "${_PROJECTS_ROOT}:/projects:rw" \
    -w /projects/WORKSPACE-GUARD \
    "$_IMAGE" \
    bash scripts/podman/e2e-host-provision.sh

echo "==> Host provision safety E2E in $_IMAGE"

"$PODMAN" run --rm --privileged \
    -v "${_PROJECTS_ROOT}:/projects:rw" \
    -w /projects/WORKSPACE-GUARD \
    "$_IMAGE" \
    bash scripts/podman/e2e-host-provision-safety.sh

echo "==> Host provision E2E complete"