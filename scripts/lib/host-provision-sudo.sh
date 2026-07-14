# host-provision-sudo.sh ,  fleet sudo strip and foreign-entry scan.

: "${DEVNULL:=/dev/null}"

HP_SUDOERS_AGENTS="${HP_SUDOERS_AGENTS:-/etc/sudoers.d/90-workspace-guard-agents}"
HP_SUDOERS_DIR="${WORKSPACE_SUDOERS_DIR:-/etc/sudoers.d}"

hp_user_in_group() {
    local user="$1" group="$2" groups=""
    if ! groups="$(id -nG "$user" 2>"$DEVNULL")"; then
        return 1
    fi
    printf '%s\n' "$groups" | tr ' ' '\n' | grep -qx "$group"
}

hp_sudo_remove_managed_agent_dropin() {
    rm -f "$HP_SUDOERS_AGENTS"
}

hp_sudo_strip_fleet_from_group() {
    local user="$1"
    if ! getent passwd "$user" >/dev/null 2>&1; then
        return 0
    fi
    if ! getent group sudo >/dev/null 2>&1; then
        return 0
    fi
    if hp_user_in_group "$user" sudo; then
        echo "==> Removing $user from group sudo"
        gpasswd -d "$user" sudo
    fi
}

hp_sudo_scan_foreign_grants() {
    local fleet_file="$1"
    local user
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        local f base
        if [[ -f /etc/sudoers ]]; then
            if grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)" /etc/sudoers 2>"$DEVNULL" \
                && ! grep -qE '^[[:space:]]*#' /etc/sudoers; then
                :
            fi
            if grep -vE '^[[:space:]]*#' /etc/sudoers | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
                echo "WARN: fleet user $user referenced in /etc/sudoers (not auto-edited)" >&2
            fi
        fi
        for f in "$HP_SUDOERS_DIR"/*; do
            [[ -f "$f" ]] || continue
            base="$(basename "$f")"
            case "$base" in
                90-workspace-guard-*) continue ;;
            esac
            if grep -vE '^[[:space:]]*#' "$f" | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
                echo "WARN: fleet user $user referenced in $f (not auto-edited)" >&2
            fi
        done
    done < <(hp_users_list_fleet_names "$fleet_file")
}

hp_sudo_fleet_user_still_privileged() {
    local fleet_file="$1"
    local user
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        if hp_user_in_group "$user" sudo; then
            return 0
        fi
    done < <(hp_users_list_fleet_names "$fleet_file")
    return 1
}