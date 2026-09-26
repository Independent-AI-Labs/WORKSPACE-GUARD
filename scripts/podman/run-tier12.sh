#!/usr/bin/env bash
# Tier 1 (quality gate) + Tier 2 (root-only E2E) in a non-privileged container.
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

echo "==> Tier 1+2: running in $_IMAGE (projects mount: $_PROJECTS_ROOT)"

"$PODMAN" run --rm \
    -v "${_PROJECTS_ROOT}:/projects:rw" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-registry:/root/.cargo/registry" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-git:/root/.cargo/git" \
    -v "${CARGO_VOLUME_PREFIX}-cargo-target:/tmp/WORKSPACE-GUARD/target" \
    -e "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" \
    "$_IMAGE" \
    bash /projects/WORKSPACE-GUARD/scripts/podman/run-tier12-in-container.sh

echo "==> Tier 1+2 complete"
