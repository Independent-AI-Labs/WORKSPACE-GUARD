# host-provision-operator.sh - fleet account audit warnings (no demotion).

hp_operator_bold_red() {
    printf '\033[1;31m%s\033[0m\n' "$1" >&2
}

hp_operator_bold_yellow() {
    printf '\033[1;33m%s\033[0m\n' "$1" >&2
}

hp_operator_print_fleet_sudo_danger() {
    local user="${1:?user}" admin="${2:-admin}"
    echo "" >&2
    echo "  DANGER (GAP-C06): fleet user '$user' can escalate to full root via sudo." >&2
    echo "  Git Guard does not contain sudo - any allowed sudo command bypasses the guard stack." >&2
    echo "  Examples: dd/mkfs/parted to block devices, mount, su, passwd, arbitrary build scripts under sudo." >&2
    echo "  On sole-operator hosts, fleet sudo also risks lockout if sudo is stripped without break-glass." >&2
    echo "  Provision does not modify fleet sudo (audit only). Use break-glass account '$admin' for root ops." >&2
    echo "  See: docs/GAP-ANALYSIS-HARD-NUKE.md (GAP-C06)" >&2
    echo "" >&2
}

# RED if user has sudo in any list; YELLOW if user exists without sudo; RED on verify_failed.
hp_operator_audit_fleet_user() {
    local user="${1:?user}" admin="${2:-admin}" state

    if ! getent passwd "$user" >/dev/null 2>&1; then
        hp_operator_bold_yellow "WARN: fleet user '$user' is configured but UNIX account does not exist yet"
        return 0
    fi

    state="$(hp_sudo_privilege_state "$user")"
    case "$state" in
        privileged)
            hp_operator_bold_red "CRITICAL: fleet user '$user' EXISTS and HAS SUDO (group sudo, sudoers, or sudo -l policy)"
            hp_operator_print_fleet_sudo_danger "$user" "$admin"
            ;;
        none)
            hp_operator_bold_yellow "WARN: fleet user '$user' EXISTS but has NO sudo in any list"
            ;;
        verify_failed)
            hp_operator_bold_red "CRITICAL: fleet user '$user' EXISTS but sudo state VERIFY FAILED (fail-closed)"
            ;;
    esac
}

hp_operator_phase3_fleet_line() {
    local user="${1:?user}" state

    state="$(hp_sudo_privilege_state "$user")"
    case "$state" in
        privileged)
            echo "  AUDIT: $user - HAS sudo (see mandatory audit above)"
            ;;
        none)
            echo "  AUDIT: $user - exists, no sudo (see mandatory audit above)"
            ;;
        verify_failed)
            echo "  AUDIT: $user - verify failed (see mandatory audit above)" >&2
            ;;
    esac
}

hp_operator_print_direct_root_agent_warning() {
    local user="${1:?user}" admin="${2:-admin}"
    echo "" >&2
    hp_operator_bold_red "CRITICAL: fleet account '$user' has foreign direct-root sudoers grant on this machine"
    echo "" >&2
    echo "  The fleet user has a sudoers grant for full root outside managed allowlist." >&2
    echo "  Phase 3 is blocked until you remove the grant or pass --acknowledge-direct-root-agent." >&2
    echo "" >&2
    echo "  1. Inspect sudoers:" >&2
    echo "       grep -R \"${user}\" /etc/sudoers /etc/sudoers.d/ | grep -v '^#'" >&2
    echo "  2. Remove or edit the foreign grant; validate with: visudo -c" >&2
    echo "  3. Re-run: export WORKSPACE_ADMIN_PASSWORD='...' && sudo -E make install-host-stack" >&2
    echo "" >&2
}

hp_operator_mandatory_fleet_report() {
    local fleet_file="${1:?fleet_file}" admin="${2:?admin}"
    local user state

    echo "==> Fleet sudo audit (mandatory - always printed)"
    hp_config_require_fleet_file "$fleet_file" 1 "mandatory fleet sudo audit" || return 1

    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        [[ "$user" == "$admin" ]] && continue
        state="$(hp_sudo_privilege_state "$user")"
        echo "---- fleet user: $user"
        echo "    computed privilege_state: $state"
        hp_sudo_print_privilege_sources "$user"
        hp_operator_audit_fleet_user "$user" "$admin"
        echo ""
    done < <(hp_users_list_fleet_names "$fleet_file")
}

hp_operator_gate_direct_root_before_phase3() {
    local fleet_file="${1:?fleet_file}" admin="${2:?admin}" acknowledge="${3:-0}"
    local user
    local blocked=0

    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        [[ "$user" == "$admin" ]] && continue
        if ! hp_sudo_user_has_foreign_direct_root "$user"; then
            continue
        fi
        hp_operator_print_direct_root_agent_warning "$user" "$admin"
        blocked=1
    done < <(hp_users_list_fleet_names "$fleet_file")

    if [[ "$blocked" -eq 1 && "$acknowledge" -ne 1 ]]; then
        echo "ERROR: phase 3 refused: direct-root fleet user detected (use --acknowledge-direct-root-agent to override)" >&2
        return 1
    fi
    return 0
}

hp_operator_print_completion_banner() {
    local fleet_file="${1:?fleet_file}" admin="${2:-admin}"
    local user state red=0 yellow=0

    echo "" >&2
    echo "OPERATOR: fleet sudo audit summary (no changes made to sudo policy):" >&2
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        state="$(hp_sudo_privilege_state "$user")"
        case "$state" in
            privileged)
                echo "OPERATOR: $user - HAS sudo (CRITICAL)" >&2
                hp_operator_print_fleet_sudo_danger "$user" "$admin"
                red=1
                ;;
            none)
                echo "OPERATOR: $user - exists, no sudo (WARN)" >&2
                yellow=1
                ;;
            verify_failed)
                hp_operator_bold_red "OPERATOR: $user - sudo verify failed"
                red=1
                ;;
        esac
    done < <(hp_users_list_fleet_names "$fleet_file")
    if [[ "$red" -eq 0 && "$yellow" -eq 0 ]]; then
        echo "OPERATOR: no fleet users configured." >&2
    fi
    echo "" >&2
}