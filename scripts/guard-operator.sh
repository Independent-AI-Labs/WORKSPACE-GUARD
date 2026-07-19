#!/usr/bin/env bash
# guard-operator.sh - canonical guard operator intents (safe by design).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CI_ROOT="$(cd "$REPO_ROOT/../CI" && pwd)"

MODE="${1:-}"
MARKER="${WORKSPACE_GUARD_STATE_DIR:-/usr/lib/workspace-guard}/host-provision.ok"
SYSTEM_CFG="/etc/workspace-guard/host-provision.yaml"
REPO_CFG="$REPO_ROOT/config/host-provision.yaml"

usage() {
    cat <<EOF
Usage: $0 <up|refresh|check|down|reset>
  up      Idempotent bring-up (provision + guard install as needed)
  refresh Rebuild and force reinstall git guard after code changes
  check   Read-only health check
  down    Remove git guard; preserve provision state
  reset   Purge all guard state then bring-up (requires GUARD_PURGE_CONFIRM=1)
EOF
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "ERROR: sudo make guard-$MODE" >&2
        exit 1
    fi
}

_user_mgmt_enabled() {
    local cfg=""
    if [[ -n "${WORKSPACE_HOST_PROVISION_FILE:-}" && -f "${WORKSPACE_HOST_PROVISION_FILE}" ]]; then
        cfg="${WORKSPACE_HOST_PROVISION_FILE}"
    elif [[ -f "$SYSTEM_CFG" ]]; then
        cfg="$SYSTEM_CFG"
    elif [[ -f "$REPO_CFG" ]]; then
        cfg="$REPO_CFG"
    else
        return 1
    fi
    local enabled=""
    enabled="$(awk '
        /^[[:space:]]*user_management:[[:space:]]*$/ { in_um=1; next }
        in_um && /^[[:space:]]*enabled:/ {
            v=$0; sub(/^[^:]*:[[:space:]]*/, "", v); gsub(/["'\'']/, "", v)
            print v; exit
        }
        /^[^[:space:]#]/ { in_um=0 }
    ' "$cfg")"
    [[ "${enabled:-true}" == "true" || "${enabled:-true}" == "1" || "${enabled:-true}" == "yes" ]]
}

_guard_check_status() {
    if [[ ! -x "$CI_ROOT/scripts/bootstrap-workspace-guard" ]]; then
        echo "ERROR: bootstrap-workspace-guard missing at $CI_ROOT" >&2
        return 2
    fi
    bash "$CI_ROOT/scripts/bootstrap-workspace-guard" check-host-exec 2>&1
}

_guard_needs_install() {
    local out rc=0
    out="$(_guard_check_status)" || rc=$?
    if [[ $rc -ne 0 ]]; then
        return 0
    fi
    if grep -q 'NOT INSTALLED\|DRIFTED' <<<"$out"; then
        return 0
    fi
    return 1
}

guard_up() {
    require_root
    if _user_mgmt_enabled && [[ ! -f "$MARKER" ]]; then
        echo "==> guard-up: running full host provision"
        make -C "$REPO_ROOT" provision-host
        return 0
    fi
    if _guard_needs_install; then
        if _user_mgmt_enabled && [[ -f "$MARKER" ]]; then
            echo "==> guard-up: installing guard stack (provision marker present)"
            GUARD_PROVISION_CONTEXT=1 make -C "$REPO_ROOT" install-guard-stack
        else
            echo "==> guard-up: installing git guard"
            make -C "$REPO_ROOT" install-guard-host-exec
        fi
        return 0
    fi
    echo "==> guard-up: git guard already healthy"
}

guard_refresh() {
    require_root
    echo "==> guard-refresh: rebuild + force reinstall"
    make -C "$REPO_ROOT" reconcile-guard-host-exec
}

guard_check() {
    _guard_check_status
}

guard_down() {
    require_root
    echo "==> guard-down: removing git guard (provision state preserved)"
    make -C "$REPO_ROOT" uninstall-guard
}

guard_reset() {
    require_root
    make -C "$REPO_ROOT" purge-guard-state
    guard_up
}

[[ -n "$MODE" ]] || { usage >&2; exit 2; }

case "$MODE" in
    up) guard_up ;;
    refresh) guard_refresh ;;
    check) guard_check ;;
    down) guard_down ;;
    reset) guard_reset ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown mode: $MODE" >&2; usage >&2; exit 2 ;;
esac