# host-provision-users.sh ,  fleet UNIX account helpers.

hp_users_list_fleet_names() {
    local fleet_file="${1:?fleet file}"
    [[ -f "$fleet_file" ]] || return 0
    awk '
        /^[[:space:]]*-[[:space:]]*name:[[:space:]]*/ {
            v=$0; sub(/^[^:]*:[[:space:]]*/, "", v); gsub(/["'\'']/, "", v)
            if (v) print v
        }
    ' "$fleet_file"
}

hp_users_ensure_account() {
    local user="$1" shell="${2:-/bin/bash}"
    if getent passwd "$user"; then
        echo "  OK: UNIX user $user already exists (unchanged)"
        return 0
    fi
    echo "  CREATE: UNIX user $user"
    if ! useradd -m -s "$shell" "$user"; then
        echo "ERROR: useradd failed for $user (exit $?)" >&2
        return 1
    fi
    if ! getent passwd "$user"; then
        echo "ERROR: useradd reported success but $user missing from passwd" >&2
        return 1
    fi
    echo "  VERIFIED: created UNIX user $user"
}

hp_users_ensure_fleet_accounts() {
    local fleet_file="$1"
    local user
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        hp_users_ensure_account "$user"
    done < <(hp_users_list_fleet_names "$fleet_file")
}

hp_users_fleet_sha256() {
    local fleet_file="$1"
    if [[ ! -f "$fleet_file" ]]; then
        hp_config_error_missing_fleet_file "$fleet_file" "completion marker fleet_sha256"
        return 1
    fi
    sha256sum "$fleet_file" | awk '{print $1}'
}