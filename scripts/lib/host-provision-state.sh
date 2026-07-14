# host-provision-state.sh - system provision config and completion marker helpers.

HP_SYSTEM_CONFIG_DIR="/etc/workspace-guard"
HP_SYSTEM_CONFIG="$HP_SYSTEM_CONFIG_DIR/host-provision.yaml"

hp_install_system_config() {
    local src="${1:?source config}"
    [[ -f "$src" ]] || return 1
    mkdir -p "$HP_SYSTEM_CONFIG_DIR"
    install -m 0644 "$src" "$HP_SYSTEM_CONFIG"
}