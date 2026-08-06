#!/usr/bin/env bash
set -euo pipefail

SCRIPT_SOURCE="${SHG_SCRIPT_PATH:-${BASH_SOURCE[0]}}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$SCRIPT_SOURCE")")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECTS_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

if [ -x "$PROJECTS_ROOT/CI/.boot-linux/bin/real-podman" ]; then
    PODMAN="$PROJECTS_ROOT/CI/.boot-linux/bin/real-podman"
elif [ -x "$PROJECTS_ROOT/CI/.boot-linux/bin/podman" ]; then
    PODMAN="$PROJECTS_ROOT/CI/.boot-linux/bin/podman"
elif command -v real-podman; then
    PODMAN=real-podman
elif command -v podman; then
    PODMAN=podman
else
    echo "ERROR: podman is required for non-root shell tests" >&2
    exit 1
fi

"$PODMAN" build -f "$REPO_ROOT/Containerfile.test" -t "$IMAGE" "$REPO_ROOT"

"$PODMAN" run --rm \
    -v "$PROJECTS_ROOT:/projects:ro" \
    -e BATS_TEST_FILTER="${BATS_TEST_FILTER:-}" \
    "$IMAGE" \
    bash /projects/WORKSPACE-GUARD/scripts/podman/run-shell-tests-in-container.sh
