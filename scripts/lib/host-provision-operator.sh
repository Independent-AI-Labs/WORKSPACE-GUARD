# host-provision-operator.sh — operator-facing warnings and remediation steps.

hp_operator_bold_red() {
    printf '\033[1;31m%s\033[0m\n' "$1" >&2
}

hp_operator_print_fleet_sudo_warning() {
    local user="${1:?user}" state="${2:?state}"

    case "$state" in
        privileged)
            hp_operator_bold_red "CRITICAL: fleet user '$user' HAS PERSISTENT SUDO on this host — retaining (not demoting)"
            echo "  Source may be group sudo, sudoers drop-in, or sudo -l policy." >&2
            ;;
        ticket_active)
            hp_operator_bold_red "CRITICAL: fleet user '$user' HAS ACTIVE SUDO TICKET (no persistent grant)"
            echo "  Outer 'sudo make' may have worked via cached timestamp; persistent policy shows none." >&2
            echo "  Ticket is retained unless you pass --demote-fleet-sudo." >&2
            ;;
        *)
            hp_operator_bold_red "CRITICAL: fleet user '$user' HAS SUDO on this host — retaining (not demoting)"
            ;;
    esac
}

hp_operator_print_direct_root_agent_warning() {
    local user="${1:?user}" admin="${2:-admin}"
    echo "" >&2
    hp_operator_bold_red "CRITICAL: desired fleet account '$user' is already admin (direct root sudo) on this machine"
    echo "" >&2
    echo "  The fleet user has a sudoers grant for full root (not only group sudo)." >&2
    echo "  Automated demotion is blocked until you acknowledge the risk or remove the grant." >&2
    echo "" >&2
    echo "  Run these steps as root (console, hypervisor, or an existing root session)." >&2
    echo "  No fleet-user password is required." >&2
    echo "" >&2
    echo "  1. Inspect sudoers for direct grants:" >&2
    echo "       grep -R \"${user}\" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'" >&2
    echo "  2. Remove managed cloud-init drop-ins that grant ${user} full sudo, e.g.:" >&2
    echo "       rm -f /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/99-cloud-init-users" >&2
    echo "     Or edit the file and delete the ${user} line; validate with: visudo -c" >&2
    echo "  3. Remove ${user} from group sudo (if present):" >&2
    echo "       gpasswd -d ${user} sudo" >&2
    echo "  4. Verify effective sudo is empty:" >&2
    echo "       sudo -l -U ${user}" >&2
    echo "  5. Re-run host provision from the guard repo:" >&2
    echo "       export WORKSPACE_ADMIN_PASSWORD='...' && sudo -E make install-host-stack" >&2
    echo "" >&2
    echo "  Or pass --demote-fleet-sudo to strip managed grants on the next run." >&2
    echo "" >&2
}

hp_operator_mandatory_fleet_report() {
    local fleet_file="${1:?fleet_file}" admin="${2:?admin}"
    local user state invoker_elevated=0

    echo "==> Fleet sudo audit (mandatory — always printed)"
    [[ -f "$fleet_file" ]] || {
        echo "ERROR: fleet file missing: $fleet_file" >&2
        return 1
    }

    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "    invoker: SUDO_USER=${SUDO_USER} (this script is running as root uid=$(id -u))"
        if [[ "$SUDO_USER" != "root" && "$SUDO_USER" != "$admin" ]]; then
            hp_operator_bold_red "ALERT: root session was opened via sudo as fleet user '${SUDO_USER}'"
        fi
    else
        echo "    invoker: SUDO_USER unset (direct root / console)"
    fi

    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        [[ "$user" == "$admin" ]] && continue
        state="$(hp_sudo_privilege_state "$user")"
        echo "---- fleet user: $user"
        echo "    computed privilege_state: $state"
        hp_sudo_print_privilege_sources "$user"
        case "$state" in
            privileged)
                hp_operator_print_fleet_sudo_warning "$user" "$state"
                if [[ "${SUDO_USER:-}" == "$user" ]]; then
                    invoker_elevated=1
                fi
                ;;
            ticket_active)
                hp_operator_print_fleet_sudo_warning "$user" "$state"
                if [[ "${SUDO_USER:-}" == "$user" ]]; then
                    invoker_elevated=1
                fi
                ;;
            verify_failed)
                hp_operator_bold_red "ALERT: $user sudo state VERIFY FAILED (fail-closed)"
                ;;
            none)
                echo "    result: $user has no effective sudo per persistent policy and no cached ticket"
                ;;
        esac
        echo ""
    done < <(hp_users_list_fleet_names "$fleet_file")

    if [[ "$invoker_elevated" -eq 1 && -n "${SUDO_USER:-}" ]]; then
        hp_operator_bold_red "CRITICAL: install-host-stack continues; fleet user '${SUDO_USER}' sudo is NOT being removed (warn-only default)"
    fi
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
    local fleet_file="${1:?fleet_file}" demote="${2:-0}"
    local user state elevated=0

    echo "" >&2
    if [[ "$demote" -eq 1 ]]; then
        echo "OPERATOR: fleet sudo demotion was requested (--demote-fleet-sudo)." >&2
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            state="$(hp_sudo_privilege_state "$user")"
            if hp_sudo_state_is_elevated "$state"; then
                hp_operator_bold_red "WARNING: fleet user '$user' still elevated after demotion (state=$state)"
                elevated=1
            fi
        done < <(hp_users_list_fleet_names "$fleet_file")
        if [[ "$elevated" -eq 0 ]]; then
            echo "OPERATOR: fleet users have no effective sudo after demotion." >&2
        fi
    else
        echo "OPERATOR: fleet sudo warn-only default — no demotion performed." >&2
        while IFS= read -r user; do
            [[ -z "$user" ]] && continue
            state="$(hp_sudo_privilege_state "$user")"
            case "$state" in
                privileged|ticket_active)
                    echo "OPERATOR: fleet user '$user' retains sudo (state=$state)." >&2
                    elevated=1
                    ;;
            esac
        done < <(hp_users_list_fleet_names "$fleet_file")
        if [[ "$elevated" -eq 0 ]]; then
            echo "OPERATOR: fleet users have no effective sudo." >&2
        else
            echo "OPERATOR: pass --demote-fleet-sudo (or DEMOTE_FLEET_SUDO=1) to strip fleet sudo." >&2
        fi
    fi
    echo "" >&2
}