#!/usr/bin/env bash
# Tier 3: host-exec E2E in a privileged container.
set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/../.." && pwd)"
_PROJECTS_ROOT="$(cd "$_REPO_ROOT/.." && pwd)"
_IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

resolve_podman() {
    if command -v real-podman; then
        echo "real-podman"
        return 0
    fi
    if command -v podman; then
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

echo "==> Tier 3: running privileged E2E in $_IMAGE"

"$PODMAN" run --rm --privileged \
    -v "${_PROJECTS_ROOT}:/projects:rw" \
    -w /projects/WORKSPACE-GUARD \
    "$_IMAGE" \
    bash scripts/podman/e2e-host-exec.sh

echo "==> Tier 3 complete"