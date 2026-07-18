# host-provision-sudo-probe.sh - live sudo privilege probes (sourced by host-provision-sudo.sh).

hp_sudo_live_runuser_probe() {
    local user="${1:?user}" out="" rc=0 ticket_path=""

    if ! command -v runuser; then
        echo "    live_probe: runuser unavailable" >&2
        return 0
    fi
    if ! getent passwd "$user"; then
        echo "    live_probe: user $user missing" >&2
        return 0
    fi

    out="$(runuser -u "$user" -- sudo -n -l 2>&1)" || rc=$?
    echo "    live_probe: runuser -u ${user} -- sudo -n -l (exit $rc):" >&2
    printf '%s\n' "$out" | sed 's/^/      /' >&2

    rc=0
    out="$(runuser -u "$user" -- sudo -n -v 2>&1)" || rc=$?
    echo "    live_probe: runuser -u ${user} -- sudo -n -v (exit $rc):" >&2
    if [[ -n "$out" ]]; then
        printf '%s\n' "$out" | sed 's/^/      /' >&2
    fi

    local _lt_rc=0
    ticket_path="$(hp_sudo_ticket_path "$user")" || _lt_rc=$?
    if [[ $_lt_rc -eq 0 ]]; then
        echo "    live_probe: cached ticket file: $ticket_path" >&2
    else
        echo "    live_probe: cached ticket file: none" >&2
    fi
}

hp_sudo_print_privilege_sources() {
    local user="${1:?user}" listing="" rc=0 f base state groups=""

    state="$(hp_sudo_privilege_state "$user")"
    echo "    privilege_state: $state" >&2

    groups="$(id -nG "$user" 2>&1)" || groups="(id -nG failed: $groups)"
    echo "    id -nG $user: $groups" >&2
    if getent group sudo; then
        echo "    getent group sudo: $(getent group sudo)" >&2
    fi

    if hp_sudo_user_in_sudo_group "$user"; then
        echo "    - persistent: member of group sudo" >&2
    fi
    if [[ -r /etc/sudoers ]] \
        && grep -vE '^[[:space:]]*#' /etc/sudoers \
            | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
        echo "    - persistent: /etc/sudoers" >&2
        grep -vE '^[[:space:]]*#' /etc/sudoers \
            | grep -E "(^|[[:space:]])${user}([[:space:]]|,|$)" \
            | sed 's/^/        /' >&2
    fi
    for f in "$HP_SUDOERS_DIR"/*; do
        [[ -f "$f" ]] || continue
        base="$(basename "$f")"
        if grep -vE '^[[:space:]]*#' "$f" \
            | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
            echo "    - persistent: $f" >&2
            grep -vE '^[[:space:]]*#' "$f" \
                | grep -E "(^|[[:space:]])${user}([[:space:]]|,|$)" \
                | sed 's/^/        /' >&2
        fi
    done
    if command -v sudo; then
        listing="$(sudo -l -U "$user" 2>&1)" || rc=$?
        echo "    - policy: sudo -l -U ${user} as root (exit $rc):" >&2
        printf '%s\n' "$listing" | sed 's/^/      /' >&2
    else
        echo "    - policy: sudo -l -U ${user}: ERROR (sudo binary missing)" >&2
    fi
    local _ticket=""
    if _ticket="$(hp_sudo_ticket_path "$user")" \
        || hp_sudo_has_cached_ticket "$user"; then
        echo "    - session: cached sudo ticket active" >&2
    else
        echo "    - session: no cached sudo ticket" >&2
    fi
    hp_sudo_live_runuser_probe "$user"
}