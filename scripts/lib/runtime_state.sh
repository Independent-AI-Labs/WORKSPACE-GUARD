# runtime_state.sh - canonical paths for per-host install/drift state.
#
# Runtime artifacts live under /usr/lib/workspace-guard/ and
# /usr/lib/workspace-binary-guard/, not under the git tree. Override
# the base dirs in tests via WORKSPACE_GUARD_STATE_DIR and
# WORKSPACE_BINARY_GUARD_STATE_DIR.

guard_runtime_state_dir() {
    printf '%s\n' "${WORKSPACE_GUARD_STATE_DIR:-/usr/lib/workspace-guard}"
}

binary_guard_runtime_state_dir() {
    printf '%s\n' "${WORKSPACE_BINARY_GUARD_STATE_DIR:-/usr/lib/workspace-binary-guard}"
}

home_lock_state_file() {
    printf '%s/home-lock-state.yaml\n' "$(guard_runtime_state_dir)"
}

home_drift_report_file() {
    printf '%s/home-drift-report.yaml\n' "$(guard_runtime_state_dir)"
}

binary_lock_state_file() {
    printf '%s/lock-state.yaml\n' "$(binary_guard_runtime_state_dir)"
}

binary_drift_report_file() {
    printf '%s/drift-report.yaml\n' "$(binary_guard_runtime_state_dir)"
}

_res_home_lock_state_file() {
    printf '%s/res/home-lock-state.yaml\n' "$1"
}

_res_home_drift_report_file() {
    printf '%s/res/home-drift-report.yaml\n' "$1"
}

_res_binary_lock_state_file() {
    printf '%s/res/lock-state.yaml\n' "$1"
}

_res_binary_drift_report_file() {
    printf '%s/res/drift-report.yaml\n' "$1"
}

ensure_runtime_state_dir() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        return 0
    fi
    mkdir -p "$dir"
    if [[ "$(id -u)" -eq 0 ]]; then
        chown root:root "$dir"
        chmod 0755 "$dir"
    fi
}

relocate_res_state_file() {
    local old="$1" new="$2"
    [[ -f "$old" ]] || return 0
    [[ -f "$new" ]] && return 0
    ensure_runtime_state_dir "$(dirname "$new")"
    mv "$old" "$new"
    echo "NOTICE: relocated install state $old -> $new" >&2
}

init_guard_runtime_state() {
    local repo_root="$1"
    ensure_runtime_state_dir "$(guard_runtime_state_dir)"
    relocate_res_state_file "$(_res_home_lock_state_file "$repo_root")" "$(home_lock_state_file)"
    relocate_res_state_file "$(_res_home_drift_report_file "$repo_root")" "$(home_drift_report_file)"
}

init_binary_guard_runtime_state() {
    local repo_root="$1"
    ensure_runtime_state_dir "$(binary_guard_runtime_state_dir)"
    relocate_res_state_file "$(_res_binary_lock_state_file "$repo_root")" "$(binary_lock_state_file)"
    relocate_res_state_file "$(_res_binary_drift_report_file "$repo_root")" "$(binary_drift_report_file)"
}