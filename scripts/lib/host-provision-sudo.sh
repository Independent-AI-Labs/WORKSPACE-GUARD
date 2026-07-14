# host-provision-sudo.sh — fleet sudo audit, optional demotion, effective-sudo checks.

HP_SUDOERS_AGENTS="${HP_SUDOERS_AGENTS:-/etc/sudoers.d/90-workspace-guard-agents}"
HP_SUDOERS_DIR="${WORKSPACE_SUDOERS_DIR:-/etc/sudoers.d}"

HP_SUDOERS_MANAGED_STRIP=(
    90-cloud-init-users
    99-cloud-init-users
    90-workspace-guard-agents
)

hp_sudo_user_in_sudo_group() {
    local user="${1:?user}" members=""

    if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
        return 0
    fi
    members="$(getent group sudo 2>/dev/null | cut -d: -f4- || true)"
    if [[ -n "$members" ]] && printf '%s\n' "$members" | tr ',' '\n' | grep -qx "$user"; then
        return 0
    fi
    return 1
}

hp_sudo_ticket_path() {
    local user="${1:?user}" dir=""

    if [[ -n "${HP_SUDO_TICKET_DIR:-}" && -f "${HP_SUDO_TICKET_DIR}/${user}" ]]; then
        printf '%s/%s\n' "$HP_SUDO_TICKET_DIR" "$user"
        return 0
    fi
    for dir in /var/lib/sudo/ts /var/run/sudo/ts; do
        if [[ -f "$dir/$user" ]]; then
            printf '%s/%s\n' "$dir" "$user"
            return 0
        fi
    done
    return 1
}

hp_sudo_has_cached_ticket() {
    local user="${1:?user}"

    if hp_sudo_ticket_path "$user" >/dev/null 2>&1; then
        return 0
    fi
    if command -v runuser >/dev/null 2>&1 && getent passwd "$user" >/dev/null 2>&1; then
        if runuser -u "$user" -- sudo -n -v 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

hp_sudo_revoke_cached_ticket() {
    local user="${1:?user}"

    if command -v runuser >/dev/null 2>&1 && getent passwd "$user" >/dev/null 2>&1; then
        runuser -u "$user" -- sudo -k 2>/dev/null || true
    fi
    local path=""
    if path="$(hp_sudo_ticket_path "$user" 2>/dev/null)"; then
        rm -f "$path"
        echo "  VERIFIED: revoked cached sudo ticket for $user"
    fi
}

# privilege_state: none | privileged | ticket_active | verify_failed
#   privileged     — persistent grant (group sudo, sudoers line, sudo -l -U policy)
#   ticket_active  — no persistent grant; cached sudo timestamp still valid
hp_sudo_privilege_state() {
    local user="${1:?user}" listing="" rc=0

    if ! getent passwd "$user" >/dev/null 2>&1; then
        printf 'verify_failed\n'
        return 0
    fi

    if hp_sudo_user_in_sudo_group "$user"; then
        printf 'privileged\n'
        return 0
    fi

    if hp_sudo_user_referenced_in_sudoers "$user"; then
        printf 'privileged\n'
        return 0
    fi

    if ! command -v sudo >/dev/null 2>&1; then
        printf 'verify_failed\n'
        return 0
    fi

    listing="$(sudo -l -U "$user" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        printf 'verify_failed\n'
        return 0
    fi

    if hp_sudo_listing_shows_privilege "$listing"; then
        printf 'privileged\n'
        return 0
    fi

    if ! printf '%s\n' "$listing" | grep -q 'is not allowed to run sudo'; then
        printf 'verify_failed\n'
        return 0
    fi

    if hp_sudo_has_cached_ticket "$user"; then
        printf 'ticket_active\n'
        return 0
    fi

    printf 'none\n'
}

hp_sudo_state_is_elevated() {
    local state="${1:?state}"
    case "$state" in
        privileged|ticket_active) return 0 ;;
        *) return 1 ;;
    esac
}

hp_user_in_group() {
    local user="$1" group="$2" groups="" rc=0

    if ! getent passwd "$user" >/dev/null 2>&1; then
        echo "ERROR: user $user not found in passwd" >&2
        return 1
    fi
    groups="$(id -nG "$user" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "ERROR: id -nG $user failed (exit $rc): $groups" >&2
        return 1
    fi
    if printf '%s\n' "$groups" | tr ' ' '\n' | grep -qx "$group"; then
        return 0
    fi
    return 1
}

hp_sudo_listing_for_user() {
    local user="${1:?user}" listing="" rc=0
    if ! command -v sudo >/dev/null 2>&1; then
        echo "ERROR: sudo binary missing" >&2
        return 1
    fi
    listing="$(sudo -l -U "$user" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "ERROR: sudo -l -U $user failed (exit $rc)" >&2
        printf '%s\n' "$listing" >&2
        return 1
    fi
    printf '%s' "$listing"
}

hp_sudo_user_referenced_in_sudoers() {
    local user="${1:?user}" f
    if [[ -r /etc/sudoers ]] \
        && grep -vE '^[[:space:]]*#' /etc/sudoers 2>/dev/null \
            | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
        return 0
    fi
    for f in "$HP_SUDOERS_DIR"/*; do
        [[ -f "$f" ]] || continue
        if grep -vE '^[[:space:]]*#' "$f" \
            | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
            return 0
        fi
    done
    return 1
}

hp_sudo_listing_shows_privilege() {
    local listing="${1:-}"
    [[ -n "$listing" ]] || return 1
    if printf '%s\n' "$listing" | grep -q 'is not allowed to run sudo'; then
        return 1
    fi
    if printf '%s\n' "$listing" | grep -qE 'may run the following|\(ALL[[:space:]]*:[[:space:]]*ALL\)|\(ALL\)[[:space:]]+ALL'; then
        return 0
    fi
    return 1
}

hp_sudo_user_has_effective_sudo() {
    local user="${1:?user}" state
    state="$(hp_sudo_privilege_state "$user")"
    case "$state" in
        privileged|ticket_active) return 0 ;;
        none) return 1 ;;
        verify_failed) return 0 ;;
    esac
    return 0
}

hp_sudo_require_no_effective_sudo() {
    local user="${1:?user}" state
    state="$(hp_sudo_privilege_state "$user")"
    case "$state" in
        none)
            echo "  VERIFIED: $user has no effective sudo"
            return 0
            ;;
        privileged|ticket_active)
            echo "ERROR: fleet user $user still has effective sudo (state=$state)" >&2
            return 1
            ;;
        verify_failed)
            echo "ERROR: could not verify sudo state for $user (fail-closed)" >&2
            return 1
            ;;
    esac
}

hp_sudo_user_has_direct_root_grant_in_text() {
    local user="${1:?user}" text="${2:-}"
    [[ -n "$text" ]] || return 1
    printf '%s\n' "$text" | grep -vE '^[[:space:]]*#' \
        | grep -qE "(^|[[:space:]])${user}[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+(ALL|NOPASSWD:[[:space:]]*ALL)"
}

hp_sudo_user_has_direct_root_grant_in_file() {
    local user="${1:?user}" file="${2:?file}"
    [[ -f "$file" ]] || return 1
    hp_sudo_user_has_direct_root_grant_in_text "$user" "$(<"$file")"
}

hp_sudo_user_has_direct_root() {
    local user="${1:?user}" listing="" rc=0 f base

    if listing="$(hp_sudo_listing_for_user "$user")"; then
        if printf '%s\n' "$listing" | grep -qE '\(ALL[[:space:]]*:[[:space:]]*ALL\)[[:space:]]+(ALL|NOPASSWD)'; then
            return 0
        fi
    fi

    if [[ -r /etc/sudoers ]] \
        && hp_sudo_user_has_direct_root_grant_in_file "$user" /etc/sudoers; then
        return 0
    fi

    for f in "$HP_SUDOERS_DIR"/*; do
        [[ -f "$f" ]] || continue
        base="$(basename "$f")"
        case "$base" in
            90-workspace-guard-admin) continue ;;
        esac
        if hp_sudo_user_has_direct_root_grant_in_file "$user" "$f"; then
            return 0
        fi
    done
    return 1
}

hp_sudo_user_has_foreign_direct_root() {
    local user="${1:?user}" f base

    if [[ -r /etc/sudoers ]] \
        && hp_sudo_user_has_direct_root_grant_in_file "$user" /etc/sudoers; then
        return 0
    fi

    for f in "$HP_SUDOERS_DIR"/*; do
        [[ -f "$f" ]] || continue
        base="$(basename "$f")"
        case "$base" in
            90-workspace-guard-admin) continue ;;
        esac
        if hp_sudo_managed_strip_is_allowlisted "$base"; then
            continue
        fi
        if hp_sudo_user_has_direct_root_grant_in_file "$user" "$f"; then
            return 0
        fi
    done
    return 1
}

hp_sudo_live_runuser_probe() {
    local user="${1:?user}" out="" rc=0 ticket_path=""

    if ! command -v runuser >/dev/null 2>&1; then
        echo "    live_probe: runuser unavailable" >&2
        return 0
    fi
    if ! getent passwd "$user" >/dev/null 2>&1; then
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

    if ticket_path="$(hp_sudo_ticket_path "$user" 2>/dev/null)"; then
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
    if getent group sudo >/dev/null 2>&1; then
        echo "    getent group sudo: $(getent group sudo)" >&2
    fi

    if hp_sudo_user_in_sudo_group "$user"; then
        echo "    - persistent: member of group sudo" >&2
    fi
    if [[ -r /etc/sudoers ]] \
        && grep -vE '^[[:space:]]*#' /etc/sudoers 2>/dev/null \
            | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
        echo "    - persistent: /etc/sudoers" >&2
        grep -vE '^[[:space:]]*#' /etc/sudoers 2>/dev/null \
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
    if command -v sudo >/dev/null 2>&1; then
        listing="$(sudo -l -U "$user" 2>&1)" || rc=$?
        echo "    - policy: sudo -l -U ${user} as root (exit $rc):" >&2
        printf '%s\n' "$listing" | sed 's/^/      /' >&2
    else
        echo "    - policy: sudo -l -U ${user}: ERROR (sudo binary missing)" >&2
    fi
    if hp_sudo_ticket_path "$user" >/dev/null 2>&1 \
        || hp_sudo_has_cached_ticket "$user"; then
        echo "    - session: cached sudo ticket active" >&2
    else
        echo "    - session: no cached sudo ticket" >&2
    fi
    hp_sudo_live_runuser_probe "$user"
}

hp_sudo_managed_strip_is_allowlisted() {
    local base="${1:?base}"
    local entry
    for entry in "${HP_SUDOERS_MANAGED_STRIP[@]}"; do
        if [[ "$base" == "$entry" ]]; then
            return 0
        fi
    done
    return 1
}

hp_sudo_validate_dropin() {
    local file="${1:?file}"
    if ! command -v visudo >/dev/null 2>&1; then
        echo "ERROR: visudo required to validate $file" >&2
        return 1
    fi
    if ! visudo -cf "$file" 2>&1; then
        echo "ERROR: visudo rejected $file" >&2
        return 1
    fi
    return 0
}

hp_sudo_strip_user_from_dropin() {
    local user="${1:?user}" file="${2:?file}"
    local tmp

    [[ -f "$file" ]] || return 0
    if ! grep -vE '^[[:space:]]*#' "$file" | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
        return 0
    fi

    tmp="$(mktemp)"
    if ! awk -v u="$user" '
        /^[[:space:]]*#/ { print; next }
        $0 ~ "(^|[[:space:]])" u "([[:space:]]|,|$)" { next }
        { print }
    ' "$file" > "$tmp"; then
        rm -f "$tmp"
        echo "ERROR: failed to edit sudoers drop-in $file" >&2
        return 1
    fi

    if ! grep -vE '^[[:space:]]*#' "$tmp" | grep -q .; then
        rm -f "$file" "$tmp"
        echo "==> Removed empty managed sudoers drop-in $(basename "$file")"
        return 0
    fi

    if ! hp_sudo_validate_dropin "$tmp"; then
        rm -f "$tmp"
        return 1
    fi

    cp "$tmp" "$file"
    chmod 0440 "$file"
    rm -f "$tmp"
    echo "==> Stripped $user from managed sudoers drop-in $(basename "$file")"
}

hp_sudo_strip_managed_dropins_for_user() {
    local user="${1:?user}" f base

    for f in "$HP_SUDOERS_DIR"/*; do
        [[ -f "$f" ]] || continue
        base="$(basename "$f")"
        if ! hp_sudo_managed_strip_is_allowlisted "$base"; then
            continue
        fi
        hp_sudo_strip_user_from_dropin "$user" "$f" || return 1
    done
}

hp_sudo_remove_managed_agent_dropin() {
    rm -f "$HP_SUDOERS_AGENTS"
}

hp_sudo_strip_fleet_from_group() {
    local user="$1" rc=0

    if ! getent passwd "$user" >/dev/null 2>&1; then
        echo "ERROR: cannot strip group sudo for missing user $user" >&2
        return 1
    fi
    if ! getent group sudo >/dev/null 2>&1; then
        echo "ERROR: group sudo does not exist on this host" >&2
        return 1
    fi
    if ! hp_user_in_group "$user" sudo; then
        echo "  OK: $user not in group sudo"
        return 0
    fi
    echo "==> Removing $user from group sudo"
    if ! gpasswd -d "$user" sudo; then
        echo "ERROR: gpasswd -d $user sudo failed (exit $?)" >&2
        return 1
    fi
    if hp_user_in_group "$user" sudo; then
        echo "ERROR: $user still in group sudo after gpasswd -d" >&2
        return 1
    fi
    echo "  VERIFIED: $user removed from group sudo"
}

hp_sudo_warn_only_fleet_user() {
    local user="${1:?user}" state

    state="$(hp_sudo_privilege_state "$user")"
    case "$state" in
        privileged)
            hp_operator_print_fleet_sudo_warning "$user" "$state"
            echo "  WARN: fleet user '$user' retains persistent sudo (demotion skipped — default warn-only policy)" >&2
            ;;
        ticket_active)
            hp_operator_print_fleet_sudo_warning "$user" "$state"
            echo "  WARN: fleet user '$user' retains cached sudo ticket (demotion skipped — default warn-only policy)" >&2
            ;;
        none)
            echo "  OK: $user has no effective sudo (see audit above)"
            ;;
        verify_failed)
            echo "ERROR: cannot verify sudo state for $user (fail-closed)" >&2
            return 1
            ;;
    esac
    return 0
}

hp_sudo_demote_fleet_user() {
    local user="${1:?user}" state

    state="$(hp_sudo_privilege_state "$user")"
    case "$state" in
        privileged|ticket_active)
            hp_operator_bold_red "ACTION: fleet user '$user' has sudo ($state) — demoting now"
            ;;
        verify_failed)
            echo "ERROR: cannot demote $user — sudo verification failed (fail-closed)" >&2
            return 1
            ;;
        none)
            echo "  OK: $user already has no effective sudo (see audit above)"
            return 0
            ;;
    esac

    hp_sudo_strip_fleet_from_group "$user" || return 1
    hp_sudo_strip_managed_dropins_for_user "$user" || return 1
    hp_sudo_remove_managed_agent_dropin
    hp_sudo_revoke_cached_ticket "$user"
    hp_sudo_require_no_effective_sudo "$user"
}

hp_sudo_assert_no_foreign_grants() {
    local fleet_file="${1:?fleet_file}"
    local user found=0

    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        local f base
        if [[ -r /etc/sudoers ]]; then
            if grep -vE '^[[:space:]]*#' /etc/sudoers 2>/dev/null | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
                echo "ERROR: fleet user $user referenced in /etc/sudoers (not auto-edited)" >&2
                grep -vE '^[[:space:]]*#' /etc/sudoers 2>/dev/null \
                    | grep -E "(^|[[:space:]])${user}([[:space:]]|,|$)" \
                    | sed 's/^/       /' >&2
                found=1
            fi
        fi
        for f in "$HP_SUDOERS_DIR"/*; do
            [[ -f "$f" ]] || continue
            base="$(basename "$f")"
            case "$base" in
                90-workspace-guard-*) continue ;;
            esac
            if hp_sudo_managed_strip_is_allowlisted "$base"; then
                continue
            fi
            if grep -vE '^[[:space:]]*#' "$f" | grep -qE "(^|[[:space:]])${user}([[:space:]]|,|$)"; then
                echo "ERROR: fleet user $user referenced in $f (not auto-edited)" >&2
                grep -vE '^[[:space:]]*#' "$f" \
                    | grep -E "(^|[[:space:]])${user}([[:space:]]|,|$)" \
                    | sed 's/^/       /' >&2
                found=1
            fi
        done
    done < <(hp_users_list_fleet_names "$fleet_file")

    if [[ "$found" -eq 1 ]]; then
        return 1
    fi
    return 0
}

hp_sudo_fleet_user_still_privileged() {
    local fleet_file="$1"
    local user state
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        state="$(hp_sudo_privilege_state "$user")"
        if hp_sudo_state_is_elevated "$state"; then
            return 0
        fi
    done < <(hp_users_list_fleet_names "$fleet_file")
    return 1
}

hp_sudo_assert_fleet_demoted() {
    local fleet_file="${1:?fleet_file}"
    local user
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        hp_sudo_require_no_effective_sudo "$user" || return 1
    done < <(hp_users_list_fleet_names "$fleet_file")
}

hp_sudo_preflight_fleet_user() {
    local user="${1:?user}" state
    state="$(hp_sudo_privilege_state "$user")"
    case "$state" in
        privileged)
            if hp_sudo_user_has_direct_root "$user"; then
                echo "    fleet user $user: PRIVILEGED (direct root sudo)"
            elif hp_user_in_group "$user" sudo; then
                echo "    fleet user $user: PRIVILEGED (group sudo)"
            else
                echo "    fleet user $user: PRIVILEGED (sudoers file or sudo -l policy)"
            fi
            ;;
        ticket_active)
            echo "    fleet user $user: TICKET ACTIVE (cached sudo; no persistent grant)"
            ;;
        verify_failed)
            echo "    fleet user $user: VERIFY FAILED (sudo -l or id check failed)"
            ;;
        none)
            echo "    fleet user $user: no effective sudo"
            ;;
    esac
}