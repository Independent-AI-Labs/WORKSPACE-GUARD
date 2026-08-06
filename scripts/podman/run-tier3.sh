#!/usr/bin/env bash
# Tier 3: host-exec E2E in a privileged container.
set -euo pipefail

_SELF="${BASH_SOURCE[0]:-$0}"
case "$_SELF" in /proc/self/fd/*) _SELF="${SHG_SCRIPT_PATH:-$_SELF}" ;; esac
_SCRIPT_DIR="$(cd "$(dirname "$_SELF")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/../.." && pwd)"
_PROJECTS_ROOT="$(cd "$_REPO_ROOT/.." && pwd)"
_IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

resolve_podman() {
    if [[ -x "$_PROJECTS_ROOT/CI/.boot-linux/bin/podman" ]]; then
        echo "$_PROJECTS_ROOT/CI/.boot-linux/bin/podman"
        return 0
    fi
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

echo "==> Tier 3: running privileged E2E in $_IMAGE"

"$PODMAN" run --rm --privileged \
    -v "${_PROJECTS_ROOT}:/projects:ro" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-registry:/root/.cargo/registry" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-git:/root/.cargo/git" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-target:/tmp/WORKSPACE-GUARD/target" \
    -e "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
    "$_IMAGE" \
    bash /projects/WORKSPACE-GUARD/scripts/podman/run-tier3-in-container.sh

echo "==> Tier 3 complete"
