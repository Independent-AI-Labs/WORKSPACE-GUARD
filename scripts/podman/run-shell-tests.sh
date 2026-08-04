#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECTS_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

if command -v real-podman; then
    PODMAN=real-podman
elif command -v podman; then
    PODMAN=podman
else
    echo "ERROR: podman is required for non-root shell tests" >&2
    exit 1
fi

if ! "$PODMAN" image exists "$IMAGE"; then
    "$PODMAN" build -f "$REPO_ROOT/Containerfile.test" -t "$IMAGE" "$REPO_ROOT"
fi

"$PODMAN" run --rm \
    -v "$PROJECTS_ROOT:/projects:rw" \
    -w /projects/WORKSPACE-GUARD \
    "$IMAGE" \
    bash -c 'set -euo pipefail; bats --timing tests/shell/'
