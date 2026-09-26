#!/usr/bin/env bash
# Run host-provision E2E only (privileged container).
set -euo pipefail

_SELF="${BASH_SOURCE[0]:-$0}"
case "$_SELF" in /proc/self/fd/*) _SELF="${SHG_SCRIPT_PATH:-$_SELF}" ;; esac
_SCRIPT_DIR="$(cd "$(dirname "$_SELF")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/../.." && pwd)"
_PROJECTS_ROOT="$(cd "$_REPO_ROOT/.." && pwd)"
_IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

PODMAN="/opt/workspace-ci/.boot-linux/bin/podman"
if [[ ! -x "$PODMAN" ]]; then
    echo "ERROR: podman not found at $PODMAN" >&2
    exit 1
fi

if [[ ! -d "$_PROJECTS_ROOT/WORKSPACE-CI" ]]; then
    echo "ERROR: WORKSPACE-CI not found at $_PROJECTS_ROOT/WORKSPACE-CI" >&2
    exit 1
fi

if ! "$PODMAN" image exists "$_IMAGE"; then
    echo "==> Test image $_IMAGE missing; building from Containerfile.test..."
    "$PODMAN" build -f "$_REPO_ROOT/Containerfile.test" -t "$_IMAGE" "$_REPO_ROOT"
fi

echo "==> Host provision E2E in $_IMAGE"

"$PODMAN" run --rm --privileged \
    -v "${_PROJECTS_ROOT}:/projects:ro" \
    "$_IMAGE" \
    bash -c 'set -euo pipefail
bash /projects/WORKSPACE-GUARD/scripts/podman/lib/prepare-isolated-workspace.sh
export GUARD_ROOT=/tmp/WORKSPACE-GUARD _GUARD_ROOT=/tmp/WORKSPACE-GUARD CI_ROOT=/tmp/WORKSPACE-CI
cd "$GUARD_ROOT"
bash scripts/podman/e2e-host-provision.sh'

echo "==> Host provision safety E2E in $_IMAGE"

"$PODMAN" run --rm --privileged \
    -v "${_PROJECTS_ROOT}:/projects:ro" \
    "$_IMAGE" \
    bash -c 'set -euo pipefail
bash /projects/WORKSPACE-GUARD/scripts/podman/lib/prepare-isolated-workspace.sh
export GUARD_ROOT=/tmp/WORKSPACE-GUARD _GUARD_ROOT=/tmp/WORKSPACE-GUARD CI_ROOT=/tmp/WORKSPACE-CI
cd "$GUARD_ROOT"
bash scripts/podman/e2e-host-provision-safety.sh'

echo "==> Host provision E2E complete"
