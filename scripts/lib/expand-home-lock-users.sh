# expand-home-lock-users.sh ,  append per-user home-lock paths from config.
# Sourced by install-home-lock and home-drift-check. Requires: REPO_ROOT,
# entries_tmp (writable path), register_temp optional.

_expand_home_lock_users_file() {
    if [[ -n "${WORKSPACE_HOME_LOCK_USERS_FILE:-}" ]]; then
        printf '%s\n' "$WORKSPACE_HOME_LOCK_USERS_FILE"
        return 0
    fi
    local candidate="$REPO_ROOT/config/home-lock-users.yaml"
    if [[ -f "$candidate" ]]; then
        printf '%s\n' "$candidate"
        return 0
    fi
    return 1
}

# Emit TSV: path<TAB>mode<TAB>type (file|dir) into entries_tmp.
expand_home_lock_user_entries() {
    local users_file user
    users_file="$(_expand_home_lock_users_file)" || return 0
    echo "==> Expanding fleet users from $users_file"
    while IFS= read -r user; do
        [[ -z "$user" ]] && continue
        printf '~%s/.gitconfig\t644\tfile\n' "$user" >> "$entries_tmp"
        printf '~%s/.config/git/config\t644\tfile\n' "$user" >> "$entries_tmp"
        printf '~%s/.gitconfig.local\t644\tfile\n' "$user" >> "$entries_tmp"
        printf '~%s/.ssh/config\t644\tfile\n' "$user" >> "$entries_tmp"
        printf '~%s/.ssh/authorized_keys\t600\tfile\n' "$user" >> "$entries_tmp"
        printf '~%s/.ssh/known_hosts\t644\tfile\n' "$user" >> "$entries_tmp"
        printf '~%s/.ssh\t755\tdir\n' "$user" >> "$entries_tmp"
    done < <(awk '
        /^[[:space:]]*-[[:space:]]*name:[[:space:]]*/ {
            v=$0; sub(/^[^:]*:[[:space:]]*/, "", v); gsub(/["'\'']/, "", v)
            if (v) print v
        }
    ' "$users_file")
}

list_home_lock_usernames() {
    local users_file
    users_file="$(_expand_home_lock_users_file)" || return 0
    awk '
        /^[[:space:]]*-[[:space:]]*name:[[:space:]]*/ {
            v=$0; sub(/^[^:]*:[[:space:]]*/, "", v); gsub(/["'\'']/, "", v)
            if (v) print v
        }
    ' "$users_file"
}