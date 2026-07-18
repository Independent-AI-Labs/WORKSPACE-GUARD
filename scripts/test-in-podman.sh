#!/usr/bin/env bash
# Orchestrate WORKSPACE-GUARD Podman test tiers (see SPEC-PODMAN-TESTING.md).
set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/.." && pwd)"
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
    echo "ERROR: podman not found. Run: make init" >&2
    return 1
}

_PROJECTS_ROOT="$(cd "$_REPO_ROOT/.." && pwd)"
if [[ ! -d "$_PROJECTS_ROOT/CI" ]]; then
    echo "ERROR: WORKSPACE-CI not found at $_PROJECTS_ROOT/CI" >&2
    echo "       Clone/sync workspace repos (make ensure-repos in CI)." >&2
    exit 1
fi

PODMAN="$(resolve_podman)"

bash "$_SCRIPT_DIR/podman/ensure-machine.sh"

echo "═══════════════════════════════════════════════════════"
echo " WORKSPACE-GUARD Podman Test Harness"
echo " Image: $_IMAGE"
echo " Projects: $_PROJECTS_ROOT"
echo "═══════════════════════════════════════════════════════"

if [[ "$(uname -s)" == "Darwin" ]]; then
    echo ""
    echo "==> Tier 0: host shell tests (Darwin)"
    make -C "$_REPO_ROOT" test-shell
fi

echo ""
echo "==> Building test image..."
"$PODMAN" build -f "$_REPO_ROOT/Containerfile.test" -t "$_IMAGE" "$_REPO_ROOT"

echo ""
bash "$_SCRIPT_DIR/podman/run-tier12.sh"

if [[ "${TEST_PODMAN_QUICK:-0}" == "1" ]]; then
    echo ""
    echo "==> Skipping Tier 3 (TEST_PODMAN_QUICK=1)"
else
    echo ""
    bash "$_SCRIPT_DIR/podman/run-tier3.sh"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo " Podman test harness: ALL TIERS PASSED"
echo "═══════════════════════════════════════════════════════"