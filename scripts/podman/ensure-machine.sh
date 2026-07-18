#!/usr/bin/env bash
# Ensure Podman is ready and the ubuntu:22.04 base image is present.
# Darwin: start Podman Machine if needed.
set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_REPO_ROOT="$(cd "$_SCRIPT_DIR/../.." && pwd)"

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

PODMAN="$(resolve_podman)"

if [[ "$(uname -s)" == "Darwin" ]]; then
    _info_rc=0
    _info_out="$("$PODMAN" info 2>&1)" || _info_rc=$?
    if [[ $_info_rc -ne 0 ]]; then
        printf '%s\n' "$_info_out" >&2
        echo "==> Podman Machine not running: starting..."
        _has_machine=0
        _list_out="$(mktemp)"
        _list_err="$(mktemp)"
        _list_rc=0
        "$PODMAN" machine list --format '{{.Name}}' >"$_list_out" 2>"$_list_err" || _list_rc=$?
        if [[ $_list_rc -eq 0 ]]; then
            if grep -q . "$_list_out"; then
                _has_machine=1
            fi
        elif [[ -s "$_list_err" ]]; then
            cat "$_list_err" >&2
        fi
        rm -f "$_list_out" "$_list_err"
        if [[ $_has_machine -eq 0 ]]; then
            "$PODMAN" machine init
        fi
        "$PODMAN" machine start
    fi
fi

echo "==> Pulling ubuntu:22.04 base image..."
"$PODMAN" pull docker.io/library/ubuntu:22.04

echo "==> Podman ready (using $PODMAN)"