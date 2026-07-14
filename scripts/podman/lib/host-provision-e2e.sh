# host-provision-e2e.sh ,  shared Podman host-provision E2E helpers.
# Sourced by e2e-host-provision.sh and e2e-host-exec.sh.

: "${DEVNULL:=/dev/null}"

HP_E2E_AGENT_USER="${HP_E2E_AGENT_USER:-agent}"
HP_E2E_AGENT_UID="${HP_E2E_AGENT_UID:-1001}"
HP_E2E_ADMIN_NAME="${HP_E2E_ADMIN_NAME:-podmanadmin}"
HP_E2E_ADMIN_PASSWORD="${HP_E2E_ADMIN_PASSWORD:-podman-e2e-admin-pass-42}"
HP_E2E_FOREIGN_SUDOERS="/etc/sudoers.d/99-e2e-foreign-preserve"

hp_e2e_guard_root() {
    if [[ -z "${_GUARD_ROOT:-}" ]]; then
        _GUARD_ROOT="/projects/WORKSPACE-GUARD"
    fi
    printf '%s\n' "$_GUARD_ROOT"
}

hp_e2e_prepare_git_safe_directory() {
    local guard_root
    guard_root="$(hp_e2e_guard_root)"
    if command -v git >/dev/null 2>&1; then
        if ! git config --global --add safe.directory "$guard_root" 2>"$DEVNULL"; then
            echo "WARN: git safe.directory not set for $guard_root" >&2
        fi
    fi
}

hp_e2e_prepare_cargo_env() {
    local ws_boot="/projects/.boot-linux"
    if [[ ! -x /root/.cargo/bin/cargo ]]; then
        return 0
    fi
    mkdir -p "$ws_boot/bin" "$ws_boot/rust"
    ln -sf /root/.cargo/bin/cargo "$ws_boot/bin/cargo"
    ln -sf /root/.cargo/bin/rustc "$ws_boot/bin/rustc"
    if [[ -x /root/.cargo/bin/rustup ]]; then
        ln -sf /root/.cargo/bin/rustup "$ws_boot/bin/rustup"
    fi
    export PATH="$ws_boot/bin:/root/.cargo/bin:${PATH}"
    export CARGO_HOME="$ws_boot/rust"
    export RUSTUP_HOME="/root/.rustup"
}

hp_e2e_init_state_dir() {
    if [[ -z "${HP_E2E_STATE_DIR:-}" ]]; then
        HP_E2E_STATE_DIR="$(mktemp -d)"
        HP_E2E_STATE_DIR_OWNED=1
    fi
    export WORKSPACE_GUARD_STATE_DIR="$HP_E2E_STATE_DIR/state"
    export WORKSPACE_HOST_PROVISION_FILE="$HP_E2E_STATE_DIR/host-provision.yaml"
    export WORKSPACE_HOME_LOCK_USERS_FILE="$HP_E2E_STATE_DIR/home-lock-users.yaml"
    export GUARD_NONINTERACTIVE=1
    export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
    unset WORKSPACE_ADMIN_PASSWORD_VERIFY
}

hp_e2e_write_configs() {
    local fleet_file="$WORKSPACE_HOME_LOCK_USERS_FILE"
    cat > "$WORKSPACE_HOST_PROVISION_FILE" <<EOF
version: 1
user_management:
  enabled: true
admin:
  name: $HP_E2E_ADMIN_NAME
  shell: /bin/bash
  create_home: true
  git_name: Podman E2E Admin
  git_email: podman-admin@test.local
fleet_users_file: $fleet_file
guard_stack:
  install_lock: false
  install_auditd: false
EOF
    cat > "$fleet_file" <<EOF
version: 1
users:
  - name: $HP_E2E_AGENT_USER
    git_name: Podman E2E Agent
    git_email: podman-agent@test.local
EOF
}

hp_e2e_setup_fleet_user() {
    if ! id "$HP_E2E_AGENT_USER" >/dev/null 2>&1; then
        useradd -m -u "$HP_E2E_AGENT_UID" -s /bin/bash "$HP_E2E_AGENT_USER"
        echo "Created user $HP_E2E_AGENT_USER (uid $HP_E2E_AGENT_UID)"
    fi
    if getent group sudo >/dev/null 2>&1; then
        if ! usermod -aG sudo "$HP_E2E_AGENT_USER" 2>"$DEVNULL"; then
            echo "WARN: usermod -aG sudo failed for $HP_E2E_AGENT_USER" >&2
        fi
    fi
}

hp_e2e_install_foreign_sudoers() {
    cat > "$HP_E2E_FOREIGN_SUDOERS" <<'EOF'
# E2E foreign operator drop-in ,  must survive provision-host
foreigntest ALL=(ALL) NOPASSWD: /bin/true
EOF
    chmod 0440 "$HP_E2E_FOREIGN_SUDOERS"
}

hp_e2e_marker_path() {
    printf '%s/host-provision.ok\n' "$WORKSPACE_GUARD_STATE_DIR"
}

hp_e2e_assert_install_gate_blocks() {
    local guard_root ci_root rc=0 out="" _out_file=""
    guard_root="$(hp_e2e_guard_root)"
    ci_root="/projects/CI"
    if [[ ! -f "$ci_root/lib/guard-host-exec.sh" ]]; then
        echo "ERROR: WORKSPACE-CI not mounted at $ci_root" >&2
        return 1
    fi
    _guard_dir="$guard_root"
    log_error() { echo "ERROR: $*" >&2; }
    # shellcheck source=/projects/CI/lib/guard-drift.sh
    source "$ci_root/lib/guard-drift.sh" || return 1
    # shellcheck source=/projects/CI/lib/guard-host-exec.sh
    source "$ci_root/lib/guard-host-exec.sh" || return 1
    _out_file="$(mktemp)"
    if guard_assert_host_provision_complete >"$_out_file" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    out="$(cat "$_out_file")"
    rm -f "$_out_file"
    if [[ $rc -eq 0 ]]; then
        echo "ERROR: install gate should fail before host provision marker" >&2
        return 1
    fi
    if [[ "$out" != *"Host provision incomplete"* ]]; then
        echo "ERROR: install gate failed for unexpected reason (rc=$rc):" >&2
        echo "$out" >&2
        return 1
    fi
    echo "PASS: install gate blocked without marker"
}

hp_e2e_run_phases_1_through_4() {
    local guard_root
    guard_root="$(hp_e2e_guard_root)"
    bash "$guard_root/scripts/provision-host" --skip-phase5
}

hp_e2e_assert_post_phase4() {
    local marker ssh_key
    marker="$(hp_e2e_marker_path)"

    if ! id "$HP_E2E_ADMIN_NAME" >/dev/null 2>&1; then
        echo "ERROR: admin user $HP_E2E_ADMIN_NAME missing after phase 1" >&2
        return 1
    fi
    echo "PASS: admin user $HP_E2E_ADMIN_NAME exists"

    if [[ ! -f /etc/sudoers.d/90-workspace-guard-admin ]] \
        || ! grep -qE "^[[:space:]]*${HP_E2E_ADMIN_NAME}[[:space:]]+ALL=" /etc/sudoers.d/90-workspace-guard-admin; then
        echo "ERROR: admin sudoers drop-in missing or wrong user" >&2
        return 1
    fi
    echo "PASS: admin sudoers drop-in installed"

    if hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
        echo "ERROR: $HP_E2E_AGENT_USER still in group sudo after phase 3" >&2
        return 1
    fi
    echo "PASS: fleet user not in group sudo"

    if [[ ! -f "$HP_E2E_FOREIGN_SUDOERS" ]] \
        || ! grep -q 'foreigntest ALL=(ALL) NOPASSWD: /bin/true' "$HP_E2E_FOREIGN_SUDOERS"; then
        echo "ERROR: foreign sudoers drop-in was removed or altered" >&2
        return 1
    fi
    echo "PASS: foreign sudoers drop-in preserved"

    ssh_key="$WORKSPACE_GUARD_STATE_DIR/ssh-keys/$HP_E2E_AGENT_USER/id_ed25519"
    if [[ ! -f "$ssh_key" ]]; then
        echo "ERROR: SSH key missing at $ssh_key after phase 4" >&2
        return 1
    fi
    echo "PASS: fleet SSH key provisioned under state dir"

    if [[ -f "$marker" ]]; then
        echo "ERROR: marker must not exist before phase 5 ($marker)" >&2
        return 1
    fi
    echo "PASS: host-provision marker absent before phase 5"

    hp_e2e_assert_install_gate_blocks
}

hp_e2e_user_in_group() {
    local user="$1" group="$2" groups=""
    if ! groups="$(id -nG "$user" 2>"$DEVNULL")"; then
        return 1
    fi
    printf '%s\n' "$groups" | tr ' ' '\n' | grep -qx "$group"
}

hp_e2e_cleanup() {
    if [[ "${HP_E2E_STATE_DIR_OWNED:-0}" == "1" && -n "${HP_E2E_STATE_DIR:-}" ]]; then
        rm -rf "$HP_E2E_STATE_DIR"
    fi
}