#!/usr/bin/env bash
# Tier 1 (quality gate) + Tier 2 (root-only E2E) in a non-privileged container.
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

echo "==> Tier 1+2: running in $_IMAGE (projects mount: $_PROJECTS_ROOT)"

"$PODMAN" run --rm \
    -v "${_PROJECTS_ROOT}:/projects:rw" \
    -w /projects/WORKSPACE-GUARD \
    "$_IMAGE" \
    bash -c 'set -euo pipefail
bash scripts/podman/tier1-test.sh
echo "==> Tier 2: root-only E2E"
bash scripts/podman/e2e-root-only.sh'

echo "==> Tier 1+2 complete"