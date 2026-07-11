#!/usr/bin/env bash
# Tier 2: root-only guard install sanity check test (runs inside container as root).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-root-only.sh requires root (container root)" >&2
    exit 1
fi

_CI_ROOT="/projects/CI"
_GUARD_ROOT="/projects/WORKSPACE-GUARD"

if [[ ! -f "$_CI_ROOT/scripts/bootstrap-workspace-guard" ]]; then
    echo "ERROR: bootstrap-workspace-guard not found at $_CI_ROOT" >&2
    exit 1
fi

export BUILD_MODE=root-only
export FORCE_ROOT_ONLY=1
export GUARD_NONINTERACTIVE=1

_tier2_cleanup() {
    if [[ -x "$_CI_ROOT/scripts/bootstrap-workspace-guard" ]]; then
        local _un_rc=0
        bash "$_CI_ROOT/scripts/bootstrap-workspace-guard" uninstall || _un_rc=$?
        if [[ $_un_rc -ne 0 ]]; then
            echo "WARN: Tier 2 cleanup uninstall exited $_un_rc" >&2
        fi
    fi
}
trap _tier2_cleanup EXIT

echo "==> Tier 2: installing guard (root-only mode)..."
bash "$_CI_ROOT/scripts/bootstrap-workspace-guard" install

echo "==> Tier 2: sanity check tests..."
tmpdir="$(mktemp -d)"
chmod 755 "$tmpdir"
cd "$tmpdir"
git init -q
# ALWAYS: sudo-gated identity keys require `sudo git config` (AT_SECURE).
# Never GIT_AUTHOR_* env injection or plain git config.
sudo git config user.email "podman-root-only@test.local"
sudo git config user.name "Podman Root-Only"
echo "test" > file.txt
git add file.txt
git commit -q -m "init"

if ! git status >/dev/null; then
    echo "ERROR: git status failed under root-only guard" >&2
    exit 1
fi
echo "PASS: git status succeeded"

_reset_rc=0
git reset --hard >/dev/null 2>&1 || _reset_rc=$?
if [[ $_reset_rc -eq 0 ]]; then
    echo "ERROR: git reset --hard was not blocked" >&2
    exit 1
fi
echo "PASS: git reset --hard blocked"

rm -rf "$tmpdir"

echo "==> Tier 2: uninstalling guard..."
bash "$_CI_ROOT/scripts/bootstrap-workspace-guard" uninstall

echo "==> Tier 2 complete"