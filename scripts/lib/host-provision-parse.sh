# host-provision-parse.sh ,  YAML field extraction for host-provision.yaml.
# Sourced by provision-host and lib helpers. Requires: HP_CONFIG path set.

hp_config_repo_example() {
    local rel="${1:?example relative path}"
    printf '%s/%s' "${HP_REPO_ROOT:?HP_REPO_ROOT}" "$rel"
}

hp_config_error_missing_host_provision() {
    local config="${1:-${HP_CONFIG:-config/host-provision.yaml}}"
    echo "ERROR: host provision config missing: $config" >&2
    echo "" >&2
    echo "  Required for make provision-host / make install-host-stack." >&2
    echo "  Defines admin break-glass, fleet_users_file, and guard_stack options." >&2
    echo "" >&2
    echo "  Fix:" >&2
    echo "    cp config/host-provision.yaml.example config/host-provision.yaml" >&2
    echo "  Then edit config/host-provision.yaml (gitignored; never commit)." >&2
    echo "  Schema: config/host-provision.schema.yaml" >&2
    echo "  Spec:   docs/specifications/SPEC-HOST-PROVISION.md" >&2
    echo "" >&2
    return 2
}

hp_config_error_missing_fleet_file() {
    local fleet_file="${1:?fleet file path}"
    local context="${2:-}"
    local example default_rel
    example="$(hp_config_repo_example "config/home-lock-users.yaml.example")"
    default_rel="config/home-lock-users.yaml"
    echo "ERROR: fleet users file missing: $fleet_file" >&2
    [[ -n "$context" ]] && echo "  Context: $context" >&2
    echo "" >&2
    echo "  Required when user_management.enabled is true." >&2
    echo "  Lists fleet UNIX accounts for sudo audit, git/SSH identity, and home-lock." >&2
    echo "  Referenced from fleet_users_file in config/host-provision.yaml" >&2
    echo "    (default: $default_rel)." >&2
    echo "" >&2
    echo "  Fix:" >&2
    if [[ "$fleet_file" == */home-lock-users.yaml ]]; then
        echo "    cp config/home-lock-users.yaml.example config/home-lock-users.yaml" >&2
    else
        echo "    cp config/home-lock-users.yaml.example \"$fleet_file\"" >&2
        echo "    or set fleet_users_file in host-provision.yaml to an existing path" >&2
    fi
    echo "  Then edit the fleet file per host (gitignored; never commit)." >&2
    echo "  Template: $example" >&2
    echo "  Schema:   config/home-lock-users.schema.yaml" >&2
    echo "  Spec:     docs/specifications/SPEC-GIT-IDENTITY.md" >&2
    echo "" >&2
    return 1
}

hp_config_require_fleet_file() {
    local fleet_file="${1:?fleet file}"
    local user_mgmt="${2:-1}"
    if [[ "$user_mgmt" -eq 0 ]]; then
        return 0
    fi
    if [[ -f "$fleet_file" ]]; then
        return 0
    fi
    hp_config_error_missing_fleet_file "$fleet_file" "${3:-}"
    return 1
}

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