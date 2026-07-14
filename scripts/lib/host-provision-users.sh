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
    if getent passwd "$user" >/dev/null 2>&1; then
        echo "  SKIP: UNIX user $user exists"
        return 0
    fi
    echo "  CREATE: UNIX user $user"
    useradd -m -s "$shell" "$user"
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
        printf 'missing'
        return 0
    fi
    sha256sum "$fleet_file" | awk '{print $1}'
}