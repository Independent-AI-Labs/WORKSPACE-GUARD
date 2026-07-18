# host-provision-admin.sh ,  break-glass admin account helpers.

HP_SUDOERS_ADMIN="${HP_SUDOERS_ADMIN:-/etc/sudoers.d/90-workspace-guard-admin}"
HP_STATE_DIR="${HP_STATE_DIR:-/usr/lib/workspace-guard}"
HP_MARKER_BEGIN="# BEGIN workspace-guard managed"
HP_MARKER_END="# END workspace-guard managed"

hp_phase2_token_path() {
    printf '%s/host-provision.phase2.ok\n' "$HP_STATE_DIR"
}

hp_phase2_token_clear() {
    rm -f "$(hp_phase2_token_path)"
}

hp_phase2_token_write() {
    local name="${1:?name}"
    local token
    token="$(hp_phase2_token_path)"
    mkdir -p "$(dirname "$token")"
    {
        echo "admin=$name"
        echo "verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$token"
    chmod 0600 "$token"
}

hp_phase2_token_valid_for() {
    local name="${1:?name}"
    local token
    token="$(hp_phase2_token_path)"
    [[ -f "$token" ]] && grep -qE "^admin=${name}$" "$token"
}

hp_phase2_token_consume() {
    local name="${1:?name}"
    if ! hp_phase2_token_valid_for "$name"; then
        echo "ERROR: phase 3 refused: run phases 1-2 first or sudo make install-host-stack" >&2
        return 1
    fi
    rm -f "$(hp_phase2_token_path)"
}

hp_admin_break_glass_ready() {
    local name="${1:?name}"
    hp_admin_exists "$name" || return 1
    hp_admin_has_sudo "$name" || return 1
}

hp_admin_exists() {
    local name="${1:?name}"
    getent passwd "$name"
}

hp_admin_has_sudo() {
    local name="${1:?name}" groups="" rc=0
    if getent group sudo; then
        groups="$(id -nG "$name" 2>&1)" || rc=$?
        if [[ "$rc" -eq 0 ]] && printf '%s\n' "$groups" | tr ' ' '\n' | grep -qx sudo; then
            return 0
        fi
        if [[ "$rc" -ne 0 ]]; then
            echo "ERROR: id -nG $name failed (exit $rc): $groups" >&2
            return 1
        fi
    fi
    if [[ -f "$HP_SUDOERS_ADMIN" ]] \
        && grep -qE "^[[:space:]]*${name}[[:space:]]+ALL=" "$HP_SUDOERS_ADMIN"; then
        return 0
    fi
    return 1
}

hp_admin_generate_password() {
    if command -v openssl; then
        openssl rand -base64 24
        return 0
    fi
    if command -v perl; then
        perl -e 'print join("", map { ("A".."Z","a".."z",0..9)[rand 62] } 1..32), "\n"'
        return 0
    fi
    echo "ERROR: openssl or perl required to generate admin password" >&2
    return 1
}

hp_admin_print_password_banner() {
    local name="$1" pass="$2"
    echo ""
    echo "============================================================"
    echo " WORKSPACE-GUARD: admin account password (copy now)"
    echo "============================================================"
    echo " user:     $name"
    echo " password: $pass"
    echo ""
    echo " This password is shown once. Phase 2 will require it."
    echo "============================================================"
    echo ""
}

hp_admin_create_account() {
    local name="$1" shell="${2:-/bin/bash}" create_home="${3:-true}"
    local args=(-s "$shell")
    if [[ "$create_home" == "true" || "$create_home" == "1" || "$create_home" == "yes" ]]; then
        args+=(-m)
    fi
    if ! useradd "${args[@]}" "$name"; then
        echo "ERROR: useradd failed for admin $name (exit $?)" >&2
        return 1
    fi
    if ! hp_admin_exists "$name"; then
        echo "ERROR: useradd succeeded but $name missing from passwd" >&2
        return 1
    fi
}

hp_admin_assert_sudo_ready() {
    local name="${1:?name}"
    if ! hp_admin_break_glass_ready "$name"; then
        echo "ERROR: admin $name missing or lacks managed sudo after phase 1" >&2
        return 1
    fi
}

hp_admin_resolve_phase2_password() {
    local name="${1:?name}" prompt="${2:-Enter password for $name: }"
    if [[ -n "${ADMIN_PASSWORD:-}" ]]; then
        printf '%s' "$ADMIN_PASSWORD"
        return 0
    fi
    if [[ -n "${WORKSPACE_ADMIN_PASSWORD:-}" ]]; then
        printf '%s' "$WORKSPACE_ADMIN_PASSWORD"
        return 0
    fi
    hp_admin_prompt_password "$prompt"
}

hp_admin_set_password() {
    local name="$1" pass="$2"
    if ! printf '%s:%s\n' "$name" "$pass" | chpasswd; then
        echo "ERROR: chpasswd failed for $name (exit $?)" >&2
        return 1
    fi
}

hp_admin_install_sudoers_dropin() {
    local name="${1:?name}"
    local tmp
    tmp="$(mktemp)"
    {
        echo "$HP_MARKER_BEGIN"
        echo "$name ALL=(ALL:ALL) ALL"
        echo "$HP_MARKER_END"
    } > "$tmp"
    if ! command -v visudo; then
        rm -f "$tmp"
        echo "ERROR: visudo required to install admin sudoers drop-in" >&2
        return 1
    fi
    if ! visudo -cf "$tmp" 2>&1; then
        rm -f "$tmp"
        echo "ERROR: visudo rejected admin sudoers drop-in" >&2
        return 1
    fi
    cp "$tmp" "$HP_SUDOERS_ADMIN"
    chmod 0440 "$HP_SUDOERS_ADMIN"
    if [[ "$(id -u)" -eq 0 ]] && [[ "$HP_SUDOERS_ADMIN" == /etc/sudoers.d/* ]]; then
        if ! chown root:root "$HP_SUDOERS_ADMIN"; then
            rm -f "$tmp"
            echo "ERROR: chown root:root $HP_SUDOERS_ADMIN failed (exit $?)" >&2
            return 1
        fi
    fi
    rm -f "$tmp"
}

hp_admin_verify_password() {
    local name="${1:?name}" pass="${2:?pass}"
    if [[ "${WORKSPACE_ADMIN_PASSWORD_VERIFY:-}" == "skip" ]]; then
        echo "ERROR: WORKSPACE_ADMIN_PASSWORD_VERIFY=skip refused (password gate cannot be bypassed)" >&2
        return 1
    fi
    if command -v perl; then
        perl - "$name" "$pass" <<'PERL'
use strict;
use warnings;
my ($user, $password) = @ARGV;
getpwnam($user) or exit 1;
my $hash = "";
open my $fh, "<", "/etc/shadow" or exit 1;
while (<$fh>) {
    chomp;
    my @f = split /:/, $_, 3;
    if ($f[0] eq $user) { $hash = $f[1]; last; }
}
close $fh;
exit 1 if !$hash || $hash =~ /^[!*]+$/;
my $ok = crypt($password, $hash) eq $hash;
exit($ok ? 0 : 1);
PERL
        return $?
    fi
    echo "ERROR: perl required to verify admin password" >&2
    return 1
}

hp_admin_prompt_password() {
    local prompt="${1:-Admin password: }"
    local pass=""
    if [[ "${GUARD_NONINTERACTIVE:-}" == "1" ]]; then
        if [[ -z "${WORKSPACE_ADMIN_PASSWORD:-}" ]]; then
            echo "ERROR: GUARD_NONINTERACTIVE=1 requires WORKSPACE_ADMIN_PASSWORD" >&2
            return 1
        fi
        printf '%s' "$WORKSPACE_ADMIN_PASSWORD"
        return 0
    fi
    read -r -s -p "$prompt" pass </dev/tty
    echo "" >&2
    printf '%s' "$pass"
}