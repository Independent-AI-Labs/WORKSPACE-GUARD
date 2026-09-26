#!/usr/bin/env bash
set -euo pipefail

SCRIPT_SOURCE="${SHG_SCRIPT_PATH:-${BASH_SOURCE[0]}}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$SCRIPT_SOURCE")")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECTS_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

PODMAN="/opt/workspace-ci/.boot-linux/bin/real-podman"
if [[ ! -x "$PODMAN" ]]; then
    echo "ERROR: podman is required for non-root shell tests" >&2
    exit 1
fi

if ! "$PODMAN" image exists "$IMAGE"; then
    "$PODMAN" build -f "$REPO_ROOT/Containerfile.test" -t "$IMAGE" "$REPO_ROOT"
fi
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-8}"
CARGO_VOLUME_PREFIX="${WORKSPACE_GUARD_CARGO_VOLUME_PREFIX:-workspace-guard}"
for volume in registry git target; do
    _volume_name="${CARGO_VOLUME_PREFIX}-cargo-${volume}"
    if ! "$PODMAN" volume exists "$_volume_name"; then
        if ! _volume_result="$($PODMAN volume create "$_volume_name" 2>&1)"; then
            echo "ERROR: could not create Cargo volume $_volume_name: ${_volume_result}" >&2
            exit 1
        fi
    fi
done

"$PODMAN" run --rm \
    -v "$PROJECTS_ROOT:/projects:ro" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-registry:/root/.cargo/registry" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-git:/root/.cargo/git" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-target:/tmp/WORKSPACE-GUARD/target" \
    -e "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
    -e BATS_TEST_FILTER="${BATS_TEST_FILTER:-}" \
    "$IMAGE" \
    bash /projects/WORKSPACE-GUARD/scripts/podman/run-shell-tests-in-container.sh
