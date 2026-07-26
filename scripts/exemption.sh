#!/usr/bin/env bash
# exemption.sh - sudo-gated add/remove/list/set for guard-locked YAML
# policy files (SPEC-EXEMPTION-EDIT). Replaces the deleted config-lock.sh
# unseal dance: policy files stay root:root at all times; this tool runs
# as root and edits YAML contents directly, atomically, fail-closed.
#
# Usage:
#   exemption.sh add    <file> <list-key> <field=value>...   Append a list entry (ROOT)
#   exemption.sh remove <file> <list-key> <field=value>...   Delete entries matching ALL fields (ROOT)
#   exemption.sh set    <file> <dotted.key> <value>          Set a scalar key (ROOT)
#   exemption.sh list   <file> [list-key]                    Print file or one key's block
#
# Field specs: name=value (scalar), name=v1,v2 (list), or a bare value
# (scalar-list item, e.g. safe_exceptions). List values match set-wise.
# Exit: 0 ok (remove no-match is ok), 1 transform/validation failure,
# 2 usage/preflight/not-root.
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_PATH")")"

source "$(dirname "$SCRIPT_PATH")/lib/qc.sh" || exit 1
source "$(dirname "$SCRIPT_PATH")/lib/exemption-yaml.sh" || exit 1

usage() {
    sed -n '2,17p' "$SCRIPT_PATH"
    exit 1
}

log()  { echo "exemption: $*"; }
fail() { echo "exemption: ERROR: $*" >&2; exit 1; }
fail2() { echo "exemption: ERROR: $*" >&2; exit 2; }

require_root() {
    [[ "$(id -u)" -eq 0 ]] || fail2 "needs root: sudo make exemption-<intent>"
}

TMPFILES=()
cleanup() {
    local t
    for t in ${TMPFILES[@]+"${TMPFILES[@]}"}; do rm -f "$t"; done
}
trap cleanup EXIT

make_tmp() {
    local t
    t="$(mktemp "$(dirname "$1")/.exemption.XXXXXX")"
    TMPFILES+=("$t")
    printf '%s\n' "$t"
}

preflight_file() {
    local file="$1"
    [[ -n "$file" ]] || fail2 "missing file argument"
    [[ -e "$file" ]] || fail2 "file not found: $file"
    [[ ! -L "$file" ]] || fail2 "refusing symlink: $file"
    [[ -f "$file" ]] || fail2 "not a regular file: $file"
    local owner
    owner="$(stat -c '%U:%G' -- "$file")"
    [[ "$owner" == "root:root" ]] || fail2 "refusing non-root-owned file ($owner): $file"
}

# Build the tab-separated spec file from field=value / bare-value args.
build_specfile() {
    local spec_tmp="$1"; shift
    local arg name val
    : > "$spec_tmp"
    for arg in "$@"; do
        if [[ "$arg" == *=* ]]; then
            name="${arg%%=*}"
            val="${arg#*=}"
            [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || fail2 "bad field name: $name"
            if [[ "$val" == *,* ]]; then
                printf 'L\t%s\t%s\n' "$name" "$val" >> "$spec_tmp"
            else
                printf 'F\t%s\t%s\n' "$name" "$val" >> "$spec_tmp"
            fi
        else
            printf 'S\t\t%s\n' "$arg" >> "$spec_tmp"
        fi
    done
    [[ -s "$spec_tmp" ]] || fail2 "no field specs given"
}

# Per-basename schema validators (REQ-EX-301). Input: specfile of the
# added entry. Structural-only for unknown basenames.
validate_schema() {
    local file="$1" specfile="$2"
    case "$(basename "$file")" in
        quality_exceptions.yaml)
            # paths is a list field: a single value arrives as an F spec
            # (no comma); normalize it to L so the emitted entry keeps the
            # list shape the quality gate expects.
            awk -F '\t' 'BEGIN {OFS="\t"}
                $1=="F" && $2=="paths" {$1="L"}
                {print}' "$specfile" > "$specfile.norm" \
                && mv -f "$specfile.norm" "$specfile" \
                || rm -f "$specfile.norm"
            local hook reason added_by paths
            hook="$(awk -F '\t' '$1=="F" && $2=="hook" {print $3}' "$specfile")"
            reason="$(awk -F '\t' '$1=="F" && $2=="reason" {print $3}' "$specfile")"
            added_by="$(awk -F '\t' '$1=="F" && $2=="added_by" {print $3}' "$specfile")"
            paths="$(awk -F '\t' '$1=="L" && $2=="paths" {print $3}' "$specfile")"
            [[ -n "$hook" ]] || fail "quality_exceptions: 'hook' is required"
            [[ -n "$added_by" ]] || fail "quality_exceptions: 'added_by' is required"
            [[ -n "$paths" ]] || fail "quality_exceptions: 'paths' needs >=1 entry"
            [[ ${#reason} -ge 20 ]] || fail "quality_exceptions: 'reason' needs >=20 chars"
            ;;
    esac
}

audit_log() {
    local intent="$1" file="$2" key="$3" fields="$4"
    local log_name logf user ts
    log_name="$(awk -F': *' '/^log_file:/ {print $2; exit}' "$REPO_ROOT/config/guard_paths.yaml")"
    [[ -n "$log_name" ]] || return 0
    logf="$HOME/$log_name"
    user="${SUDO_USER:-$(qc '?' id -un)}"
    ts="$(qc '?' date -u +%Y-%m-%dT%H:%M:%SZ)"
    local line="$ts exemption $intent user=$user file=$file key=$key fields=$fields result=ok"
    if ! printf '%s\n' "$line" >> "$logf"; then
        echo "exemption: WARNING: audit write failed: $logf" >&2
    fi
}

# Structural re-verification of the transformed temp file (REQ-EX-300).
verify_add() {
    local tmp="$1" key="$2" specfile="$3"
    ey_run exists "$tmp" "$key" "$specfile" || fail "verify failed: added entry not found"
}

verify_remove() {
    local tmp="$1" key="$2" specfile="$3"
    if ey_run exists "$tmp" "$key" "$specfile"; then
        fail "verify failed: removed entry still present"
    fi
}

install_tmp() {
    local tmp="$1" file="$2"
    chmod 0644 "$tmp" || fail "chmod failed: $tmp"
    chown root:root "$tmp" || fail "chown failed: $tmp"
    mv -f -- "$tmp" "$file" || fail "install failed: $file"
}

do_add() {
    local file="$1" key="$2"; shift 2
    require_root
    preflight_file "$file"
    local spec_tmp tmp fields
    spec_tmp="$(mktemp)"; TMPFILES+=("$spec_tmp")
    build_specfile "$spec_tmp" "$@"
    validate_schema "$file" "$spec_tmp"
    tmp="$(make_tmp "$file")"
    local rc=0
    ey_run add "$file" "$key" "$spec_tmp" > "$tmp" || rc=$?
    case "$rc" in
        0) ;;
        2) fail "list key not found or not a list: $key" ;;
        4) fail "duplicate entry in $key" ;;
        *) fail "transform failed (rc=$rc)" ;;
    esac
    verify_add "$tmp" "$key" "$spec_tmp"
    install_tmp "$tmp" "$file"
    fields="$(paste -sd, "$spec_tmp")"
    audit_log add "$file" "$key" "$fields"
    log "added entry to $key in $file"
}

do_remove() {
    local file="$1" key="$2"; shift 2
    require_root
    preflight_file "$file"
    local spec_tmp tmp fields rc=0
    spec_tmp="$(mktemp)"; TMPFILES+=("$spec_tmp")
    build_specfile "$spec_tmp" "$@"
    tmp="$(make_tmp "$file")"
    ey_run remove "$file" "$key" "$spec_tmp" > "$tmp" || rc=$?
    case "$rc" in
        0) ;;
        2) fail "list key not found or not a list: $key" ;;
        3) log "no matching entry in $key; unchanged"; exit 0 ;;
        *) fail "transform failed (rc=$rc)" ;;
    esac
    verify_remove "$tmp" "$key" "$spec_tmp"
    install_tmp "$tmp" "$file"
    fields="$(paste -sd, "$spec_tmp")"
    audit_log remove "$file" "$key" "$fields"
    log "removed entry from $key in $file"
}

do_set() {
    local file="$1" dotted="$2" val="${3:-}"
    require_root
    preflight_file "$file"
    [[ -n "$dotted" && -n "$val" ]] || fail2 "set needs <dotted.key> <value>"
    local tmp rc=0
    tmp="$(make_tmp "$file")"
    ey_run set "$file" "$dotted" "" "$val" > "$tmp" || rc=$?
    case "$rc" in
        0) ;;
        2) fail "refusing set on block/list key: $dotted" ;;
        *) fail "scalar key not found: $dotted" ;;
    esac
    local got
    got="$(ey_run get "$tmp" "$dotted")" || fail "verify failed: $dotted unreadable after set"
    [[ "$got" == "$val" ]] || fail "verify failed: $dotted is '$got', want '$val'"
    install_tmp "$tmp" "$file"
    audit_log set "$file" "$dotted" "value=$val"
    log "set $dotted in $file"
}

do_list() {
    local file="$1" key="${2:-}"
    [[ -n "$file" && -f "$file" ]] || fail2 "file not found: $file"
    if [[ -z "$key" ]]; then
        cat -- "$file"
        return 0
    fi
    ey_run block "$file" "$key" || fail "list key not found or not a list: $key"
}

main() {
    local intent="${1:-}"
    [[ -n "$intent" ]] || usage
    case "$intent" in
        add)    shift; [[ $# -ge 3 ]] || usage; do_add "$@" ;;
        remove) shift; [[ $# -ge 3 ]] || usage; do_remove "$@" ;;
        set)    shift; [[ $# -ge 3 ]] || usage; do_set "$@" ;;
        list)   shift; [[ $# -ge 1 ]] || usage; do_list "$@" ;;
        -h|--help) usage ;;
        *)      usage ;;
    esac
}

main "$@"
