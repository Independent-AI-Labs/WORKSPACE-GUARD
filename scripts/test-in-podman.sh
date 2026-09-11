#!/usr/bin/env bash
# Orchestrate WORKSPACE-GUARD Podman test tiers (see SPEC-PODMAN-TESTING.md).
set -euo pipefail

_SELF="${BASH_SOURCE[0]:-$0}"
case "$_SELF" in /proc/self/fd/*) _SELF="${SHG_SCRIPT_PATH:-$_SELF}" ;; esac
_SCRIPT_DIR="$(cd "$(dirname "$_SELF")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/.." && pwd)"
_IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

resolve_podman() {
    if [[ -x "/opt/workspace-ci/.boot-linux/bin/podman" ]]; then
        echo "/opt/workspace-ci/.boot-linux/bin/podman"
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
    echo "ERROR: podman not found. Run: make init" >&2
    return 1
}

_PROJECTS_ROOT="$(cd "$_REPO_ROOT/.." && pwd)"
if [[ ! -d "$_PROJECTS_ROOT/WORKSPACE-CI" ]]; then
    echo "ERROR: WORKSPACE-CI not found at $_PROJECTS_ROOT/WORKSPACE-CI" >&2
    echo "       Clone/sync workspace repos (make ensure-repos in CI)." >&2
    exit 1
fi

PODMAN="$(resolve_podman)"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(nproc)}"
if (( CARGO_BUILD_JOBS < 4 )); then CARGO_BUILD_JOBS=4; fi
if (( CARGO_BUILD_JOBS > 8 )); then CARGO_BUILD_JOBS=8; fi
export CARGO_BUILD_JOBS

bash "$_SCRIPT_DIR/podman/ensure-machine.sh"

echo "═══════════════════════════════════════════════════════"
echo " WORKSPACE-GUARD Podman Test Harness"
echo " Image: $_IMAGE"
echo " Projects: $_PROJECTS_ROOT"
echo " Cargo jobs: $CARGO_BUILD_JOBS"
echo "═══════════════════════════════════════════════════════"

_phase_started=$SECONDS

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo ""
    echo "==> Tier 0: host shell tests (Darwin)"
    make -C "$_REPO_ROOT" test-shell
fi

echo ""
echo "==> Building test image..."
"$PODMAN" build -f "$_REPO_ROOT/Containerfile.test" -t "$_IMAGE" "$_REPO_ROOT"
echo "==> Image phase: $((SECONDS - _phase_started))s"

echo ""
bash "$_SCRIPT_DIR/podman/run-tier12.sh"
echo "==> Tier 1+2 phase: $((SECONDS - _phase_started))s total"

if [[ "${TEST_PODMAN_QUICK:-0}" == "1" ]]; then
    echo ""
    echo "==> Skipping Tier 3 (TEST_PODMAN_QUICK=1)"
else
    echo ""
    bash "$_SCRIPT_DIR/podman/run-tier3.sh"
    echo "==> Tier 3 phase: $((SECONDS - _phase_started))s total"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo " Podman test harness: ALL TIERS PASSED"
echo "═══════════════════════════════════════════════════════"
