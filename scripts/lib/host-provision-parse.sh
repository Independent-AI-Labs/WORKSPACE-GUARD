# host-provision-parse.sh ,  YAML field extraction for host-provision.yaml.
# Sourced by provision-host and lib helpers. Requires: HP_CONFIG path set.

hp_parse_field() {
    local key="${1:?key}"
    awk -v want="$key" '
        function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
        function unquote(s) { gsub(/^["'\'']|["'\'']$/, "", s); return s }
        BEGIN { section = "" }
        /^[[:space:]]*user_management:[[:space:]]*$/ { section = "user_management"; next }
        /^[[:space:]]*admin:[[:space:]]*$/ { section = "admin"; next }
        /^[[:space:]]*guard_stack:[[:space:]]*$/ { section = "guard_stack"; next }
        /^[^[:space:]#]/ { section = "" }
        want == "user_management.enabled" && section == "user_management" && /^[[:space:]]*enabled:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
        want == "admin.name" && section == "admin" && /^[[:space:]]*name:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
        want == "admin.shell" && section == "admin" && /^[[:space:]]*shell:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
        want == "admin.create_home" && section == "admin" && /^[[:space:]]*create_home:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
        want == "admin.git_name" && section == "admin" && /^[[:space:]]*git_name:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
        want == "admin.git_email" && section == "admin" && /^[[:space:]]*git_email:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
        want == "guard_stack.install_lock" && section == "guard_stack" && /^[[:space:]]*install_lock:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
        want == "guard_stack.install_auditd" && section == "guard_stack" && /^[[:space:]]*install_auditd:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
        want == "fleet_users_file" && /^[[:space:]]*fleet_users_file:/ {
            v = $0; sub(/^[^:]*:[[:space:]]*/, "", v); print unquote(trim(v)); exit
        }
    ' "$HP_CONFIG"
}

hp_user_mgmt_enabled() {
    local v
    v="$(hp_parse_field "user_management.enabled")"
    [[ "${v:-true}" == "true" || "${v:-true}" == "1" || "${v:-true}" == "yes" ]]
}

hp_admin_name() {
    hp_parse_field "admin.name"
}

hp_fleet_users_file() {
    local rel
    rel="$(hp_parse_field "fleet_users_file")"
    [[ -z "$rel" ]] && rel="config/home-lock-users.yaml"
    if [[ "$rel" != /* ]]; then
        printf '%s/%s' "$HP_REPO_ROOT" "$rel"
    else
        printf '%s' "$rel"
    fi
}