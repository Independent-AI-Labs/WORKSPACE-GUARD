#!/usr/bin/env bash
# guard-operator.sh - canonical guard operator intents (safe by design).
set -euo pipefail

SCRIPT_SOURCE="${BASH_SOURCE[0]}"
case "$SCRIPT_SOURCE" in /proc/self/fd/*) SCRIPT_SOURCE="${SHG_SCRIPT_PATH:-$SCRIPT_SOURCE}" ;; esac
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SOURCE")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CI_ROOT=/opt/workspace-ci

MODE="${1:-}"
MARKER="${WORKSPACE_GUARD_STATE_DIR:-/usr/lib/workspace-guard}/host-provision.ok"
SYSTEM_CFG="/etc/workspace-guard/host-provision.yaml"
REPO_CFG="$REPO_ROOT/config/host-provision.yaml"

usage() {
    printf 'Usage: %s <up|refresh|check|down>\n' "$0"
    printf '  up      Idempotent bring-up (provision + git guard + shell guard as needed)\n'
    printf '  refresh Rebuild and force reinstall git guard + shell guard after code changes\n'
    printf '  check   Read-only health check (git guard + shell guard)\n'
    printf '  down    Remove shell guard + git guard; preserve provision state\n'
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
    if [[ ! -x "$REPO_ROOT/scripts/check-guard-host-exec-readonly" ]]; then
        echo "ERROR: read-only host-exec checker missing" >&2
        return 2
    fi
    bash "$REPO_ROOT/scripts/check-guard-host-exec-readonly" 2>&1
}

_guard_needs_install() {
    local out status=0
    out="$(_guard_check_status)" || status=$?
    if [[ $status -ne 0 ]]; then
        return 0
    fi
    if grep -q 'NOT INSTALLED\|DRIFTED' <<<"$out"; then
        return 0
    fi
    return 1
}

_shell_guard_available() {
    [[ -x "$REPO_ROOT/scripts/install-shell-guard" && -x "$REPO_ROOT/scripts/shell-guard-check" ]]
}

_shell_guard_check_status() {
    bash "$REPO_ROOT/scripts/shell-guard-check" "$REPO_ROOT" 2>&1
}

_shell_guard_needs_install() {
    local out status=0
    out="$(_shell_guard_check_status)" || status=$?
    if [[ $status -ne 0 ]]; then
        return 0
    fi
    if grep -q 'NOT INSTALLED\|DRIFTED' <<<"$out"; then
        return 0
    fi
    return 1
}

_shell_guard_up() {
    if ! _shell_guard_available; then
        echo "==> guard-up: shell guard not yet implemented (skip; SPEC-SHELL-GUARD)"
        return 0
    fi
    if _shell_guard_needs_install; then
        echo "==> guard-up: installing shell guard"
        make -C "$REPO_ROOT" install-shell-guard
        return 0
    fi
    echo "==> guard-up: shell guard already healthy"
}

guard_up() {
    require_root
    if _user_mgmt_enabled && [[ ! -f "$MARKER" ]]; then
        echo "==> guard-up: running full host provision"
        make -C "$REPO_ROOT" provision-host
    fi
    if _guard_needs_install; then
        if _user_mgmt_enabled && [[ -f "$MARKER" ]]; then
            echo "==> guard-up: installing guard stack (provision marker present)"
            GUARD_PROVISION_CONTEXT=1 make -C "$REPO_ROOT" install-guard-stack
        else
            echo "==> guard-up: installing git guard"
            make -C "$REPO_ROOT" install-guard-host-exec
        fi
    else
        echo "==> guard-up: git guard already healthy"
    fi
    _shell_guard_up
}

guard_refresh() {
    require_root
    echo "==> guard-refresh: rebuild + force reinstall"
    make -C "$REPO_ROOT" reconcile-guard-host-exec
    if _shell_guard_available; then
        echo "==> guard-refresh: reconcile shell guard"
        make -C "$REPO_ROOT" install-shell-guard
    fi
}

guard_check() {
    local status=0
    _guard_check_status || status=$?
    if _shell_guard_available; then
        _shell_guard_check_status || status=$?
    fi
    return "$status"
}

guard_down() {
    require_root
    if [[ -x "$REPO_ROOT/scripts/uninstall-shell-guard" ]]; then
        echo "==> guard-down: removing shell guard"
        make -C "$REPO_ROOT" uninstall-shell-guard
    fi
    echo "==> guard-down: removing git guard (provision state preserved)"
    make -C "$REPO_ROOT" uninstall-guard
}

[[ -n "$MODE" ]] || { usage >&2; exit 2; }

case "$MODE" in
    up) guard_up ;;
    refresh) guard_refresh ;;
    check) guard_check ;;
    down) guard_down ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown mode: $MODE" >&2; usage >&2; exit 2 ;;
esac
