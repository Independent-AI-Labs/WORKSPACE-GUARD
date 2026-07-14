# host-provision-admin.sh ,  break-glass admin account helpers.

: "${DEVNULL:=/dev/null}"

HP_SUDOERS_ADMIN="${HP_SUDOERS_ADMIN:-/etc/sudoers.d/90-workspace-guard-admin}"
HP_MARKER_BEGIN="# BEGIN workspace-guard managed"
HP_MARKER_END="# END workspace-guard managed"

hp_admin_exists() {
    local name="${1:?name}"
    getent passwd "$name" >/dev/null 2>&1
}

hp_admin_has_sudo() {
    local name="${1:?name}" groups=""
    if getent group sudo >/dev/null 2>&1; then
        if groups="$(id -nG "$name" 2>"$DEVNULL")"; then
            if printf '%s\n' "$groups" | tr ' ' '\n' | grep -qx sudo; then
                return 0
            fi
        fi
    fi
    if [[ -f "$HP_SUDOERS_ADMIN" ]]; then
        if grep -qE "^[[:space:]]*${name}[[:space:]]+ALL=" "$HP_SUDOERS_ADMIN" 2>"$DEVNULL"; then
            return 0
        fi
    fi
    return 1
}

hp_admin_generate_password() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 24
        return 0
    fi
    if command -v perl >/dev/null 2>&1; then
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
    useradd "${args[@]}" "$name"
}

hp_admin_set_password() {
    local name="$1" pass="$2"
    printf '%s:%s\n' "$name" "$pass" | chpasswd
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
    if command -v visudo >/dev/null 2>&1; then
        if ! visudo -cf "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"
            echo "ERROR: visudo rejected admin sudoers drop-in" >&2
            return 1
        fi
    fi
    cp "$tmp" "$HP_SUDOERS_ADMIN"
    chmod 0440 "$HP_SUDOERS_ADMIN"
    if [[ "$(id -u)" -eq 0 ]] && [[ "$HP_SUDOERS_ADMIN" == /etc/sudoers.d/* ]]; then
        if ! chown root:root "$HP_SUDOERS_ADMIN" 2>"$DEVNULL"; then
            echo "WARN: chown $HP_SUDOERS_ADMIN failed (non-fatal)" >&2
        fi
    fi
    rm -f "$tmp"
}

hp_admin_verify_password() {
    local name="${1:?name}" pass="${2:?pass}"
    if [[ "${WORKSPACE_ADMIN_PASSWORD_VERIFY:-}" == "skip" ]]; then
        return 0
    fi
    if command -v perl >/dev/null 2>&1; then
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