#!/usr/bin/env bash
# config-lock.sh - lock / timed-unseal / relock / status for consumer-repo
# config files (root-owned + chattr +i, e.g. WORKSPACE-WEB-CONTENT/config/*.yaml).
#
# Usage:
#   config-lock.sh lock    <repo>              Lock all config/*.yaml now; cancel pending timer
#   config-lock.sh unseal  <repo> [minutes]    Unseal; auto-relock after <minutes> (0 = manual relock only)
#   config-lock.sh relock  <repo>              Relock now; cancel pending timer
#   config-lock.sh status  <repo>              Show per-file state and pending timer
#
# lock/unseal/relock require root. Timed relock is scheduled via systemd-run
# (declared dependency: config/system-deps.yaml -> systemd).
set -euo pipefail

STATE_DIR="/var/lib/workspace-guard/config-unseal"
UNIT_PREFIX="workspace-guard-config-relock"

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

usage() {
    sed -n '2,14p' "$SCRIPT_PATH"
    exit 1
}

log()  { echo "config-lock: $*"; }
fail() { echo "config-lock: ERROR: $*" >&2; exit 1; }

require_root() {
    [[ "$(id -u)" -eq 0 ]] || fail "needs root: sudo make config-<intent>"
}

repo_hash() {
    printf '%s' "$1" | cksum | cut -d' ' -f1
}

unit_name() {
    echo "${UNIT_PREFIX}-$(repo_hash "$1")"
}

state_file() {
    echo "${STATE_DIR}/$(repo_hash "$1").files"
}

resolve_repo() {
    local repo="$1"
    [[ -d "$repo" ]] || fail "repo not found: $repo"
    (cd "$repo" && pwd)
}

have_cmd() { local _probe; _probe="$(command -v "$1" 2>&1)"; }

have_chattr() { have_cmd chattr; }

is_immutable() {
    have_chattr || return 1
    local _out
    _out="$(lsattr "$1" 2>&1)" || return 1
    printf '%s\n' "$_out" | awk '{print $1}' | grep -q 'i'
}

config_files() {
    local repo="$1" f
    shopt -s nullglob
    for f in "$repo"/config/*.yaml; do printf '%s\n' "$f"; done
    shopt -u nullglob
}

repo_owner() {
    stat -c '%U:%G' "$1"
}

# Resolve the real git dir (worktrees have .git as a file pointing at it).
# The guard binary reads <gitdir>/config-unseal.files to honor an active
# unseal; the file lives inside the locked .git tree so only root can
# create or remove it.
git_dir() {
    local repo="$1"
    if [[ -d "$repo/.git" ]]; then
        printf '%s\n' "$repo/.git"
    elif [[ -f "$repo/.git" ]]; then
        local target
        target="$(sed -n 's/^gitdir: //p' "$repo/.git")"
        [[ -n "$target" ]] || fail "cannot parse $repo/.git"
        [[ "$target" = /* ]] || target="$repo/$target"
        printf '%s\n' "$target"
    else
        fail "no .git in $repo"
    fi
}

unseal_state_path() {
    printf '%s/config-unseal.files\n' "$(git_dir "$1")"
}

cancel_timer() {
    local repo="$1" unit
    unit="$(unit_name "$repo")"
    if have_cmd systemctl; then
        local _out
        if ! _out="$(systemctl stop "${unit}.timer" 2>&1)"; then
            log "stop ${unit}.timer: ${_out:-not running}"
        fi
        if ! _out="$(systemctl stop "${unit}.service" 2>&1)"; then
            log "stop ${unit}.service: ${_out:-not running}"
        fi
        if ! _out="$(systemctl reset-failed "${unit}.timer" "${unit}.service" 2>&1)"; then
            log "reset-failed ${unit}: ${_out:-none failed}"
        fi
    fi
}

lock_files() {
    local repo="$1"; shift
    local f locked=0 bad=0
    for f in "$@"; do
        [[ -f "$f" ]] || { log "skip (missing): $f"; continue; }
        chown root:root "$f" || { log "ERROR: chown root:root failed: $f"; bad=1; continue; }
        if have_chattr; then
            chattr +i "$f" || { log "ERROR: chattr +i failed: $f"; bad=1; continue; }
        fi
        locked=$((locked + 1))
    done
    for f in "$@"; do
        [[ -f "$f" ]] || continue
        if [[ "$(stat -c '%U:%G' "$f")" != "root:root" ]]; then
            log "ERROR: verify failed, not root:root: $f"; bad=1
        fi
        if have_chattr && ! is_immutable "$f"; then
            log "ERROR: verify failed, not immutable: $f"; bad=1
        fi
    done
    [[ $bad -eq 0 ]] || fail "lock verification failed for $repo/config"
    log "locked $locked file(s) under $repo/config (root:root, immutable)"
}

do_lock() {
    local repo="$1" files
    require_root
    cancel_timer "$repo"
    rm -f "$(state_file "$repo")"
    rm -f "$(unseal_state_path "$repo")"
    mapfile -t files < <(config_files "$repo")
    [[ ${#files[@]} -gt 0 ]] || fail "no config/*.yaml in $repo"
    lock_files "$repo" "${files[@]}"
}

writable_by() {
    local user="$1" f="$2"
    if have_cmd sudo; then
        sudo -u "$user" test -w "$f"
    else
        su -s /bin/sh -c "test -w \"$f\"" "$user"
    fi
}

do_unseal() {
    local repo="$1" minutes="${2:-10}"
    require_root
    [[ "$minutes" =~ ^[0-9]+$ ]] || fail "minutes must be a non-negative integer, got: $minutes"
    local sf owner f
    sf="$(state_file "$repo")"
    local resumed=0
    if [[ -f "$sf" ]]; then
        log "existing unseal state found; re-applying permissions (state: $sf)"
        resumed=1
    fi
    owner="$(repo_owner "$repo")"
    local owner_user="${owner%%:*}"
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    : > "$sf"
    local count=0 bad=0 f_abs
    while IFS= read -r f; do
        f_abs="$f"
        if have_chattr && is_immutable "$f_abs"; then
            chattr -i "$f_abs" || { log "ERROR: chattr -i failed: $f_abs"; bad=1; continue; }
        fi
        chown "$owner" "$f_abs" || { log "ERROR: chown $owner failed: $f_abs"; bad=1; continue; }
        chmod u+rw "$f_abs" || { log "ERROR: chmod u+rw failed: $f_abs"; bad=1; continue; }
        printf '%s\n' "$f_abs" >> "$sf"
        count=$((count + 1))
    done < <(config_files "$repo")
    [[ $count -gt 0 ]] || fail "no config/*.yaml in $repo"
    while IFS= read -r f; do
        if is_immutable "$f"; then
            log "ERROR: verify failed, still immutable: $f"; bad=1
        fi
        if [[ "$(stat -c '%U:%G' "$f")" != "$owner" ]]; then
            log "ERROR: verify failed, owner mismatch: $f"; bad=1
        fi
        if ! writable_by "$owner_user" "$f"; then
            log "ERROR: verify failed, not writable by $owner_user: $f"; bad=1
        fi
    done < "$sf"
    [[ $bad -eq 0 ]] || fail "unseal verification failed for $repo/config; NOT scheduling relock"
    printf 'owner=%s\n' "$owner" >> "$sf"
    # Mirror the file list into the locked .git tree so the guard binary
    # skips exactly these paths on its per-invocation relock pass.
    local gsf
    gsf="$(unseal_state_path "$repo")"
    cp "$sf" "$gsf" || fail "cannot write guard-visible state: $gsf"
    chown root:root "$gsf"; chmod 0644 "$gsf"
    log "unsealed $count file(s) -> $owner (state: $sf)"
    if [[ $resumed -eq 1 ]]; then
        log "existing timer left as-is; check: make config-lock-status"
        exit 0
    fi
    if [[ "$minutes" -gt 0 ]]; then
        have_cmd systemd-run || fail "systemd-run missing (make init installs it); use 'unseal $repo 0' + manual relock"
        local unit
        unit="$(unit_name "$repo")"
        cancel_timer "$repo"
        local _sd_out
        _sd_out="$(systemd-run --unit="$unit" \
            --description="Relock $repo config after timed unseal" \
            --on-active="$((minutes * 60))" \
            "$SCRIPT_PATH" relock "$repo" 2>&1)" || fail "systemd-run failed: $_sd_out"
        log "timed relock scheduled in ${minutes} min (unit: ${unit}.timer); cancel: sudo make config-relock"
    else
        log "no timer set; relock manually: sudo make config-relock"
    fi
}

do_relock() {
    local repo="$1" sf files f
    require_root
    cancel_timer "$repo"
    sf="$(state_file "$repo")"
    files=()
    if [[ -f "$sf" ]]; then
        while IFS= read -r f; do
            [[ "$f" == owner=* ]] && continue
            files+=("$f")
        done < "$sf"
    else
        while IFS= read -r f; do files+=("$f"); done < <(config_files "$repo")
    fi
    [[ ${#files[@]} -gt 0 ]] || { log "nothing to relock"; rm -f "$sf"; rm -f "$(unseal_state_path "$repo")"; exit 0; }
    lock_files "$repo" "${files[@]}"
    rm -f "$sf"
    rm -f "$(unseal_state_path "$repo")"
}

do_status() {
    local repo="$1" f owner attr
    while IFS= read -r f; do
        owner="$(stat -c '%U:%G' "$f")"
        if have_chattr; then
            local _attr_out
            _attr_out="$(lsattr "$f" 2>&1)" || _attr_out=""
            attr="$(printf '%s\n' "$_attr_out" | awk '{print $1}')"
        else
            attr="(no chattr)"
        fi
        printf '%-55s owner=%-12s attrs=%s\n' "${f#"$repo"/}" "$owner" "$attr"
    done < <(config_files "$repo")
    if [[ -f "$(state_file "$repo")" ]]; then
        echo "state: UNSEALED (state file present: $(state_file "$repo"))"
    else
        echo "state: no active unseal"
    fi
    if have_cmd systemctl; then
        local _lt_out
        if _lt_out="$(systemctl list-timers "$(unit_name "$repo").timer" --no-pager 2>&1)"; then
            printf '%s\n' "$_lt_out"
        else
            echo "timer: none pending"
        fi
    fi
}

main() {
    local intent="${1:-}" repo minutes
    [[ -n "$intent" ]] || usage
    repo="$(resolve_repo "${2:-}")"
    case "$intent" in
        lock)    do_lock "$repo" ;;
        unseal)  minutes="${3:-10}"; do_unseal "$repo" "$minutes" ;;
        relock)  do_relock "$repo" ;;
        status)  do_status "$repo" ;;
        *)       usage ;;
    esac
}

main "$@"
