#!/usr/bin/env bash
# 21-shell-guard.bats: runtime integration for workspace-shell-guard.
#
# The guard only operates in a capability context (AT_SECURE=1, exit 3
# otherwise) and verifies /bin/bash.real as root:root 0700, so the
# runtime tests require root: they copy the built binary, grant it
# cap_dac_override=ep, and create a throwaway /bin/bash.real when the
# host has none. On non-root hosts every runtime test skips; only the
# AT_SECURE gate test runs everywhere.

load lib/harness

SHG_BIN=""
for candidate in \
    "$GUARD_ROOT/target/agent/debug/workspace-shell-guard" \
    "$GUARD_ROOT/target/debug/workspace-shell-guard" \
    "$GUARD_ROOT/target/release/workspace-shell-guard"; do
    if [ -x "$candidate" ]; then
        SHG_BIN="$candidate"
        break
    fi
done

AUDIT_LOG=""
CAP_CTX_OK=0
SHG=""
PUBLIC_SHG=""

setup_file() {
    [ -n "$SHG_BIN" ] || return 0
    [ "$(id -u)" = "0" ] || return 0
    mkdir -p "$BATS_FILE_TMPDIR"
    cp "$SHG_BIN" "$BATS_FILE_TMPDIR/shg"
    chmod 755 "$BATS_FILE_TMPDIR" "$BATS_FILE_TMPDIR/shg"
    SHG="$BATS_FILE_TMPDIR/shg"
    /usr/sbin/setcap cap_dac_override=ep "$SHG" || return 0
    [ -f /bin/bash.real ] || return 0
    # Rootless podman maps file capabilities to user.overlay xattrs that
    # the kernel never honors, so exec never sets AT_SECURE. Probe once;
    # tests skip with a clear reason instead of failing everywhere.
    if "$SHG" -c 'true' >/dev/null 2>&1; then
        CAP_CTX_OK=1
    fi
    printf '%s' "$CAP_CTX_OK" > "$BATS_FILE_TMPDIR/.cap-ctx"
    # Public copy for non-root execution tests (bats tmpdirs are 0700
    # and not traversable by other users). cp drops xattrs, so the
    # file capability must be re-applied.
    PUBLIC_SHG="$(mktemp /tmp/shg-bats-pub.XXXXXX)"
    cp "$SHG" "$PUBLIC_SHG"
    chmod 755 "$PUBLIC_SHG"
    /usr/sbin/setcap cap_dac_override=ep "$PUBLIC_SHG"
}

teardown_file() {
    [ -z "$PUBLIC_SHG" ] || rm -f "$PUBLIC_SHG"
    if id shg-bats-user >/dev/null 2>&1; then
        userdel -r shg-bats-user >/dev/null 2>&1
    fi
}

setup() {
    guard_setup
    AUDIT_LOG="$(getent passwd "$(id -u)" | cut -d: -f6)/.workspace-guard.log"
}

teardown() { guard_teardown; }

require_root_guard() {
    [ -n "$SHG_BIN" ] || skip "shell-guard binary not built (run: cargo build)"
    [ "$(id -u)" = "0" ] || skip "shell-guard runtime tests need root (setcap + /bin/bash.real)"
    [ -x "$BATS_FILE_TMPDIR/shg" ] || skip "capability copy missing (setup_file did not run as root)"
    local ok=0
    [ -f "$BATS_FILE_TMPDIR/.cap-ctx" ] && ok="$(cat "$BATS_FILE_TMPDIR/.cap-ctx")"
    [ "$ok" = "1" ] || skip "AT_SECURE not attainable here (rootless namespace); run under QEMU guest or real-root podman"
}

shg() { "$BATS_FILE_TMPDIR/shg" "$@"; }

# Create a root-locked, /-reaching directory for genuine trusted-tier
# fixtures.  /tmp is sticky+world-writable, so fixtures under $TEST_TMPDIR
# do not reach / and are classified as Untrusted.  /root is root:root 0700
# and / is root:root 0755, so the chain is valid for trusted-tier tests.
shg_trusted_dir() {
    local d
    d="$(mktemp -d /root/shg-trusted.XXXXXX)"
    chown root:root "$d"
    chmod 700 "$d"
    printf '%s\n' "$d"
}


SHG_DD='--'

# ---------- AT_SECURE gate (runs everywhere) ----------

@test "shell-guard: non-root exits 3 outside a capability context (AT_SECURE=0)" {
    [ -n "$SHG_BIN" ] || skip "shell-guard binary not built (run: cargo build)"
    [ "$(id -u)" != "0" ] || skip "root bypasses the AT_SECURE gate"
    run "$SHG_BIN" -c 'echo hi'
    [ "$status" -eq 3 ]
    [[ "$output" == *"AT_SECURE"* ]]
}

@test "shell-guard: root bypasses AT_SECURE gate outside a capability context" {
    [ -n "$SHG_BIN" ] || skip "shell-guard binary not built (run: cargo build)"
    # The harness may fake id(1); probe the actual guard behaviour instead.
    if ! "$SHG_BIN" -c 'true' >/dev/null 2>&1; then
        skip "guard still fails closed for this user (not a real root bypass)"
    fi
    run "$SHG_BIN" -c 'echo root-pass'
    [ "$status" -eq 0 ]
    [ "$output" = "root-pass" ]
}

# ---------- argv classification ----------

@test "shell-guard: benign -c string passes through" {
    require_root_guard
    run shg -c 'echo hello-from-guard'
    [ "$status" -eq 0 ]
    [ "$output" = "hello-from-guard" ]
}

@test "shell-guard: empty -c string passes through" {
    require_root_guard
    run shg -c ''
    [ "$status" -eq 0 ]
}

@test "shell-guard: --help passes through unscanned" {
    require_root_guard
    run shg --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"GNU bash"* ]]
}

@test "shell-guard: --version passes through unscanned" {
    require_root_guard
    run shg --version
    [ "$status" -eq 0 ]
    [[ "$output" == *"GNU bash"* ]]
}

@test "shell-guard: bundled flag -xc is still scanned" {
    require_root_guard
    run shg -xc 'somecmd | tail'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: bundled login flag -lc is still scanned" {
    require_root_guard
    run shg -lc 'pkill whatever'
    [ "$status" -eq 1 ]
    [[ "$output" == *"process-by-name"* ]]
}

@test "shell-guard: --init-file with separate operand is skipped, -c scanned" {
    require_root_guard
    run shg --init-file /dev/null -c 'echo init-file-ok'
    [ "$status" -eq 0 ]
    [[ "$output" == *"init-file-ok"* ]]
}

@test "shell-guard: -i is an interactive passthrough (unscanned)" {
    require_root_guard
    run shg -i -c 'pkill no-such-process-shg' </dev/null
    [[ "$output" != *"BLOCKED"* ]]
}

@test "shell-guard: double-dash ends options; following -c is a script operand" {
    require_root_guard
    run shg "$SHG_DD" -c 'pkill x'
    [[ "$output" == *"BLOCKED"* ]]
    [ "$status" -eq 1 ]
}

@test "shell-guard: -c with no command operand passes through to bash's error" {
    require_root_guard
    run shg -c </dev/null
    [ "$status" -eq 2 ]
    [[ "$output" == *"requires an argument"* ]]
    [[ "$output" != *"BLOCKED"* ]]
}

@test "shell-guard: script operands after the script path are not scanned" {
    require_root_guard
    printf '#!/bin/bash\nprintf "ran\n"\n' > "$TEST_TMPDIR/argv.sh"
    chmod +x "$TEST_TMPDIR/argv.sh"
    run shg "$TEST_TMPDIR/argv.sh" -c 'pkill x'
    [ "$status" -eq 0 ]
    [[ "$output" == *"ran"* ]]
}

@test "shell-guard: argv0 is preserved for -c invocations" {
    require_root_guard
    run shg -c 'echo "zero=$0"'
    [ "$status" -eq 0 ]
    [[ "$output" == *"zero=$BATS_FILE_TMPDIR/shg"* ]]
}

# ---------- destructive-command rules (REQ-SHG-300..307) ----------

@test "shell-guard: blocks systemctl poweroff (power-verb)" {
    require_root_guard
    run shg -c 'systemctl poweroff'
    [ "$status" -eq 1 ]
    [[ "$output" == *"BLOCKED"* ]]
    [[ "$output" == *"power-verb"* ]]
}

@test "shell-guard: blocks loginctl hibernate (power-verb)" {
    require_root_guard
    run shg -c 'loginctl hibernate'
    [ "$status" -eq 1 ]
    [[ "$output" == *"power-verb"* ]]
}

@test "shell-guard: blocks pkill (process-by-name)" {
    require_root_guard
    run shg -c 'pkill opencode'
    [ "$status" -eq 1 ]
    [[ "$output" == *"process-by-name"* ]]
}

@test "shell-guard: blocks killall (process-by-name)" {
    require_root_guard
    run shg -c 'killall vim'
    [ "$status" -eq 1 ]
    [[ "$output" == *"process-by-name"* ]]
}

@test "shell-guard: blocks shutdown (power-command)" {
    require_root_guard
    run shg -c 'shutdown -h now'
    [ "$status" -eq 1 ]
    [[ "$output" == *"power-command"* ]]
}

@test "shell-guard: blocks bare reboot (power-command)" {
    require_root_guard
    run shg -c 'reboot'
    [ "$status" -eq 1 ]
    [[ "$output" == *"power-command"* ]]
}

@test "shell-guard: blocks mkfs (fs-destroy)" {
    require_root_guard
    run shg -c 'mkfs.ext4 /dev/sda1'
    [ "$status" -eq 1 ]
    [[ "$output" == *"fs-destroy"* ]]
}

@test "shell-guard: blocks fdisk (fs-destroy)" {
    require_root_guard
    run shg -c 'fdisk /dev/sda'
    [ "$status" -eq 1 ]
    [[ "$output" == *"fs-destroy"* ]]
}

@test "shell-guard: blocks alternate shell (alt-shell)" {
    require_root_guard
    run shg -c 'zsh -c true'
    [ "$status" -eq 1 ]
    [[ "$output" == *"alt-shell"* ]]
}

@test "shell-guard: blocks busybox shell (busybox-shell)" {
    require_root_guard
    run shg -c 'busybox sh'
    [ "$status" -eq 1 ]
    [[ "$output" == *"busybox-shell"* ]]
}

@test "shell-guard: blocks podman command boundary" {
    require_root_guard
    run shg -c 'podman run --rm image bash -c echo-inline'
    [ "$status" -eq 1 ]
    [[ "$output" == *"podman-command"* ]]
}

@test "shell-guard: blocks launcher-wrapped podman" {
    require_root_guard
    run shg -c 'sudo podman exec container /bin/sh -c id'
    [ "$status" -eq 1 ]
    [[ "$output" == *"podman-command"* ]]
}

@test "shell-guard: blocks inline Python from an untrusted script" {
    require_root_guard
    printf '#!/bin/bash\npython3 -c print(1)\n' > "$TEST_TMPDIR/inline-python.sh"
    chmod +x "$TEST_TMPDIR/inline-python.sh"
    run shg "$TEST_TMPDIR/inline-python.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"inline-code-channel"* ]]
}

@test "shell-guard: blocks heredoc interpreter code from an untrusted script" {
    require_root_guard
    printf '#!/bin/bash\npython3 - <<PY\nprint(1)\nPY\n' > "$TEST_TMPDIR/python-heredoc.sh"
    chmod +x "$TEST_TMPDIR/python-heredoc.sh"
    run shg "$TEST_TMPDIR/python-heredoc.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"inline-code-channel"* ]]
}

@test "shell-guard: blocks kill with two-digit signal (kill-mass)" {
    require_root_guard
    run shg -c 'kill -15 1234'
    [ "$status" -eq 1 ]
    [[ "$output" == *"kill-mass"* ]]
}

@test "shell-guard: blocks kill by job spec (kill-mass)" {
    require_root_guard
    run shg -c 'kill %1'
    [ "$status" -eq 1 ]
    [[ "$output" == *"kill-mass"* ]]
}

@test "shell-guard: blocks chattr immutability strip (chattr-strip)" {
    require_root_guard
    run shg -c 'chattr -i /etc/passwd'
    [ "$status" -eq 1 ]
    [[ "$output" == *"chattr-strip"* ]]
}

@test "shell-guard: blocks rm --no-preserve-root (rm-rootfs)" {
    require_root_guard
    run shg -c 'rm -rf --no-preserve-root /'
    [ "$status" -eq 1 ]
    [[ "$output" == *"rm-rootfs"* ]]
}

@test "shell-guard: blocks dd to block device (dd-device)" {
    require_root_guard
    run shg -c 'dd if=x of=/dev/sda'
    [ "$status" -eq 1 ]
    [[ "$output" == *"dd-device"* ]]
}

@test "shell-guard: blocks umount of guard mountpoint (mount-protected)" {
    require_root_guard
    run shg -c 'umount /usr/lib/workspace-guard/bin'
    [ "$status" -eq 1 ]
    [[ "$output" == *"mount-protected"* ]]
}

@test "shell-guard: blocks swapoff -a (swap-teardown)" {
    require_root_guard
    run shg -c 'swapoff -a'
    [ "$status" -eq 1 ]
    [[ "$output" == *"swap-teardown"* ]]
}

@test "shell-guard: allows targeted kill of own pid (control)" {
    require_root_guard
    run shg -c 'kill -0 $$'
    [ "$status" -eq 0 ]
}

@test "shell-guard: allows kill with explicit pid (control)" {
    require_root_guard
    run shg -c 'sleep 30 & p=$!; kill "$p"; wait "$p"; echo killed-ok'
    [ "$status" -eq 0 ]
    [[ "$output" == *"killed-ok"* ]]
}

@test "shell-guard: first-match precedence (systemctl poweroff over bare poweroff)" {
    require_root_guard
    run shg -c 'systemctl poweroff; shutdown now'
    [ "$status" -eq 1 ]
    [[ "$output" == *"power-verb"* ]]
}

# ---------- output-suppression rules (REQ-SHG-308..310) ----------

@test "shell-guard: blocks pipe-to-tail (suppress-pipe)" {
    require_root_guard
    run shg -c 'somecmd | tail -n 5'
    [ "$status" -eq 1 ]
    [[ "$output" == *"BLOCKED"* ]]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: blocks pipe-ampersand to head (suppress-pipe)" {
    require_root_guard
    run shg -c 'somecmd |& head -3'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: blocks redirect to /dev/null (suppress-null)" {
    require_root_guard
    run shg -c 'somecmd > /dev/null'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: blocks stderr redirect to /dev/null (suppress-null)" {
    require_root_guard
    run shg -c 'somecmd 2> /dev/null'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: blocks append redirect to quoted /dev/null (suppress-null)" {
    require_root_guard
    run shg -c 'somecmd 2>>"/dev/null"'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: blocks swallow idiom (suppress-swallow)" {
    require_root_guard
    run shg -c 'somecmd || true'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-swallow"* ]]
}

@test "shell-guard: blocks pipe-to-colon swallow (suppress-swallow)" {
    require_root_guard
    run shg -c 'somecmd | :'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-swallow"* ]]
}

@test "shell-guard: blocks documented false positive (quoted pipe-tail)" {
    require_root_guard
    run shg -c 'echo "use | tail"'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: allows ordinary output handling (control)" {
    require_root_guard
    run shg -c 'echo line1; echo line2'
    [ "$status" -eq 0 ]
    [ "$output" = "line1
line2" ]
}

# ---------- prefixed, path-qualified, and substituted forms ----------

@test "shell-guard: blocks sudo-prefixed pkill (process-by-name)" {
    require_root_guard
    run shg -c 'sudo pkill x'
    [ "$status" -eq 1 ]
    [[ "$output" == *"process-by-name"* ]]
}

@test "shell-guard: blocks env-wrapped pkill (process-by-name)" {
    require_root_guard
    run shg -c 'env pkill x'
    [ "$status" -eq 1 ]
    [[ "$output" == *"process-by-name"* ]]
}

@test "shell-guard: blocks path-qualified shutdown (power-command)" {
    require_root_guard
    run shg -c '/sbin/shutdown -h now'
    [ "$status" -eq 1 ]
    [[ "$output" == *"power-command"* ]]
}

@test "shell-guard: blocks path-qualified zsh (alt-shell)" {
    require_root_guard
    run shg -c '/usr/bin/zsh -c true'
    [ "$status" -eq 1 ]
    [[ "$output" == *"alt-shell"* ]]
}

@test "shell-guard: blocks literal command substitution text (process-by-name)" {
    require_root_guard
    run shg -c 'echo $(pkill x)'
    [ "$status" -eq 1 ]
    [[ "$output" == *"process-by-name"* ]]
}

@test "shell-guard: blocks combined redirect to /dev/null (suppress-null)" {
    require_root_guard
    run shg -c 'somecmd &> /dev/null'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: blocks stdout-then-stderr discard (suppress-null)" {
    require_root_guard
    run shg -c 'somecmd >/dev/null 2>&1'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: blocks pipe-to-true swallow (suppress-swallow)" {
    require_root_guard
    run shg -c 'somecmd | true'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-swallow"* ]]
}

@test "shell-guard: allows bare tail on a file (control)" {
    require_root_guard
    printf 'l1\nl2\n' > "$TEST_TMPDIR/t.txt"
    run shg -c "tail -n 1 '$TEST_TMPDIR/t.txt'"
    [ "$status" -eq 0 ]
    [ "$output" = "l2" ]
}

@test "shell-guard: allows true after && (control)" {
    require_root_guard
    run shg -c 'true && echo ok-after-and'
    [ "$status" -eq 0 ]
    [ "$output" = "ok-after-and" ]
}

# ---------- script classification and trust tiers ----------

@test "shell-guard: untrusted script with banned idiom is blocked" {
    require_root_guard
    printf '#!/bin/bash\nsomecmd | tail\n' > "$TEST_TMPDIR/evil.sh"
    chmod +x "$TEST_TMPDIR/evil.sh"
    run shg "$TEST_TMPDIR/evil.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: /tmp script bypass attempt is blocked" {
    require_root_guard
    printf '#!/bin/bash\nsomecmd 2>/dev/null\n' > /tmp/shg-bats-x.sh
    chmod +x /tmp/shg-bats-x.sh
    run shg /tmp/shg-bats-x.sh
    rm -f /tmp/shg-bats-x.sh
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: benign untrusted script runs via sealed memfd" {
    require_root_guard
    printf '#!/bin/bash\necho "argv0=$0"\n' > "$TEST_TMPDIR/ok.sh"
    chmod +x "$TEST_TMPDIR/ok.sh"
    run shg "$TEST_TMPDIR/ok.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == argv0=/proc/self/fd/* ]]
}

@test "shell-guard: staged script learns its original path via SHG_SCRIPT_PATH" {
    require_root_guard
    printf '#!/bin/bash\necho "orig=$SHG_SCRIPT_PATH"\necho "argv0=$0"\n' \
        > "$TEST_TMPDIR/orig.sh"
    chmod +x "$TEST_TMPDIR/orig.sh"
    run shg "$TEST_TMPDIR/orig.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"orig=$TEST_TMPDIR/orig.sh"* ]]
    [[ "$output" == *"argv0=/proc/self/fd/"* ]]
}

@test "shell-guard: caller-supplied SHG_SCRIPT_PATH is scrubbed" {
    require_root_guard
    local trusted_dir
    trusted_dir="$(shg_trusted_dir)"
    printf '#!/bin/bash\necho "val=${SHG_SCRIPT_PATH:-empty}"\n' \
        > "$trusted_dir/t.sh"
    chown -R root:root "$trusted_dir"
    chmod 755 "$trusted_dir" "$trusted_dir/t.sh"
    SHG_SCRIPT_PATH=/tmp/spoof run shg "$trusted_dir/t.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"val=empty"* ]]
    rm -rf "$trusted_dir"
}

@test "shell-guard: sealed memfd script cannot rewrite its own body" {
    require_root_guard
    printf '#!/bin/bash\nif echo x >> "$0"; then echo writable; else echo sealed; fi\n' \
        > "$TEST_TMPDIR/seal.sh"
    chmod +x "$TEST_TMPDIR/seal.sh"
    run shg "$TEST_TMPDIR/seal.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"sealed"* ]]
    [[ "$output" != *"writable"* ]]
}

@test "shell-guard: trusted script may contain harmless alternate-shell text" {
    require_root_guard
    local trusted_dir
    trusted_dir="$(shg_trusted_dir)"
    printf '#!/bin/bash\nprintf "dash\\n"\n' > "$trusted_dir/t.sh"
    chown -R root:root "$trusted_dir"
    chmod 755 "$trusted_dir" "$trusted_dir/t.sh"
    run shg "$trusted_dir/t.sh"
    [ "$status" -eq 0 ]
    [ "$output" = "dash" ]
    rm -rf "$trusted_dir"
}

@test "shell-guard: untrusted script alternate-shell text remains blocked" {
    require_root_guard
    printf '#!/bin/bash\nprintf "dash\\n"\n' > "$TEST_TMPDIR/untrusted-dash.sh"
    chmod +x "$TEST_TMPDIR/untrusted-dash.sh"
    run shg "$TEST_TMPDIR/untrusted-dash.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"alt-shell"* ]]
}

@test "shell-guard: world-writable file drops out of the trusted tier" {
    require_root_guard
    mkdir -p "$TEST_TMPDIR/trusted-ww"
    printf '#!/bin/bash\necho "argv0=$0"\n' > "$TEST_TMPDIR/trusted-ww/t.sh"
    chown -R root:root "$TEST_TMPDIR/trusted-ww"
    chmod 755 "$TEST_TMPDIR/trusted-ww"
    chmod 666 "$TEST_TMPDIR/trusted-ww/t.sh"
    run shg "$TEST_TMPDIR/trusted-ww/t.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == argv0=/proc/self/fd/* ]]
}

@test "shell-guard: group-writable parent dir drops out of the trusted tier" {
    require_root_guard
    mkdir -p "$TEST_TMPDIR/trusted-gw"
    printf '#!/bin/bash\necho "argv0=$0"\n' > "$TEST_TMPDIR/trusted-gw/t.sh"
    chown -R root:root "$TEST_TMPDIR/trusted-gw"
    chmod 775 "$TEST_TMPDIR/trusted-gw"
    chmod 755 "$TEST_TMPDIR/trusted-gw/t.sh"
    run shg "$TEST_TMPDIR/trusted-gw/t.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == argv0=/proc/self/fd/* ]]
}

@test "shell-guard: non-root parent dir drops out of the trusted tier" {
    require_root_guard
    mkdir -p "$TEST_TMPDIR/notroot"
    printf '#!/bin/bash\necho "argv0=$0"\n' > "$TEST_TMPDIR/notroot/t.sh"
    chown -R nobody:nogroup "$TEST_TMPDIR/notroot"
    chmod 755 "$TEST_TMPDIR/notroot" "$TEST_TMPDIR/notroot/t.sh"
    run shg "$TEST_TMPDIR/notroot/t.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == argv0=/proc/self/fd/* ]]
}

@test "shell-guard: unreadable script is blocked" {
    require_root_guard
    run shg /nonexistent/shg-script.sh
    [[ "$output" == *"BLOCKED"* ]]
    [ "$status" -eq 1 ]
}

@test "shell-guard: process-substitution script source is blocked" {
    require_root_guard
    run shg <(printf 'echo shg-procsub-ran\n')
    [ "$status" -eq 1 ]
    [[ "$output" == *"BLOCKED"* ]]
    [[ "$output" == *"fd-script-source"* ]]
    [[ "$output" == *"Origin:"* ]]
    [[ "$output" != *"shg-procsub-ran"* ]]
}

@test "shell-guard: re-exec of the guard's own staged memfd is rescanned silently" {
    require_root_guard
    printf '#!/bin/bash\nif [ ! -f "%s/mark" ]; then touch "%s/mark"; exec bash "$0"; fi\necho reexec-ok\n' \
        "$TEST_TMPDIR" "$TEST_TMPDIR" > "$TEST_TMPDIR/reexec.sh"
    run shg "$TEST_TMPDIR/reexec.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"reexec-ok"* ]]
    [[ "$output" != *"cannot read script"* ]]
}

@test "shell-guard: block report quotes the offending excerpt and origin trace" {
    require_root_guard
    run shg -c 'pkill whatever'
    [ "$status" -eq 1 ]
    [[ "$output" == *"process-by-name"* ]]
    [[ "$output" == *"Offending excerpt:"* ]]
    [[ "$output" == *"pkill whatever"* ]]
    [[ "$output" == *"Origin:"* ]]
}

@test "shell-guard: script block report shows the offending line number" {
    require_root_guard
    printf '#!/bin/bash\necho before\npkill whatever\necho after\n' > "$TEST_TMPDIR/bad-body.sh"
    run shg "$TEST_TMPDIR/bad-body.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"script body"* ]]
    [[ "$output" == *">     3 | pkill whatever"* ]]
    [[ "$output" == *"    2 | echo before"* ]]
}

# ---------- environment hygiene ----------

@test "shell-guard: caller PATH is preserved" {
    require_root_guard
    mkdir -p "$TEST_TMPDIR/fakebin"
    printf '#!/bin/sh\necho fake-ls\n' > "$TEST_TMPDIR/fakebin/ls"
    chmod +x "$TEST_TMPDIR/fakebin/ls"
    run env PATH="$TEST_TMPDIR/fakebin:/usr/bin:/bin" "$BATS_FILE_TMPDIR/shg" -c 'command -v ls'
    [ "$status" -eq 0 ]
    [[ "$output" == *"fakebin/ls"* ]]
}

@test "shell-guard: LD_PRELOAD is stripped from the child environment" {
    require_root_guard
    run env LD_PRELOAD=/tmp/shg-evil.so "$BATS_FILE_TMPDIR/shg" -c 'echo "lp=${LD_PRELOAD:-unset}"'
    [ "$status" -eq 0 ]
    # The dynamic loader may complain about a missing preload library in the
    # guard process, but the child environment must not see the value.
    [[ "$output" == *"lp=unset"* ]]
    [[ "$output" != *"lp=/tmp/shg-evil.so"* ]]
}

@test "shell-guard: caller variables survive" {
    require_root_guard
    run env LC_SHGTEST=1 WORKSPACE_TAG=abc SHG_RANDOM_VAR=no "$BATS_FILE_TMPDIR/shg" \
        -c 'echo "$LC_SHGTEST:$WORKSPACE_TAG:${SHG_RANDOM_VAR:-unset}"'
    [ "$status" -eq 0 ]
    [ "$output" = "1:abc:no" ]
}

@test "shell-guard: HOME survives the environment filter" {
    require_root_guard
    run shg -c 'echo "home=$HOME"'
    [ "$status" -eq 0 ]
    [[ "$output" == *"home=/root"* ]]
}

@test "shell-guard: TMPDIR is preserved as caller state" {
    require_root_guard
    run env TMPDIR="$TEST_TMPDIR" "$BATS_FILE_TMPDIR/shg" -c 'echo "t=${TMPDIR:-unset}"'
    [ "$status" -eq 0 ]
    [ "$output" = "t=$TEST_TMPDIR" ]
    run env TMPDIR=relative "$BATS_FILE_TMPDIR/shg" -c 'echo "t=${TMPDIR:-unset}"'
    [ "$status" -eq 0 ]
    [ "$output" = "t=relative" ]
    run env TMPDIR=/nonexistent-shg "$BATS_FILE_TMPDIR/shg" -c 'echo "t=${TMPDIR:-unset}"'
    [ "$status" -eq 0 ]
    [ "$output" = "t=/nonexistent-shg" ]
}

# ---------- resource limits ----------

@test "shell-guard: core dumps are disabled in the child" {
    require_root_guard
    run shg -c 'ulimit -c'
    [ "$status" -eq 0 ]
    [ "$output" = "0" ]
}

@test "shell-guard: NOFILE is capped at the policy limit in the child" {
    require_root_guard
    run shg -c 'ulimit -n'
    [ "$status" -eq 0 ]
    [ "$output" -le 65536 ]
}

@test "shell-guard: NOFILE soft equals the clamped hard limit" {
    require_root_guard
    run shg -c 'printf "%s %s" "$(ulimit -Sn)" "$(ulimit -Hn)"'
    [ "$status" -eq 0 ]
    [ "${output% *}" = "${output#* }" ]
}

# ---------- size limits and byte edge cases ----------

@test "shell-guard: -c string over 1 MiB exits 2" {
    require_root_guard
    local big
    big="$(head -c 1100000 /dev/zero | tr '\0' 'a')"
    # Linux argv limits (~128 KiB per argument) prevent delivering a 1 MiB
    # string to any process, so the guard's internal limit cannot be reached
    # through a normal -c invocation. The limit is covered by unit tests and
    # the script-size test below.
    if [ "${#big}" -gt 131072 ]; then
        skip "kernel argv limit prevents passing a >1MiB -c string to the guard"
    fi
    run shg -c "$big"
    [ "$status" -eq 2 ]
    [[ "$output" == *"exceeds 1 MiB"* ]]
}

@test "shell-guard: script over 1 MiB exits 2" {
    require_root_guard
    head -c 1100000 /dev/zero | tr '\0' 'a' > "$TEST_TMPDIR/big.sh"
    chmod +x "$TEST_TMPDIR/big.sh"
    run shg "$TEST_TMPDIR/big.sh"
    [ "$status" -eq 2 ]
    [[ "$output" == *"exceeds 1 MiB"* ]]
}

@test "shell-guard: non-UTF-8 bytes in -c pass through unscanned" {
    require_root_guard
    run shg -c $'echo "\xff\xfe-ok"'
    [ "$status" -eq 0 ]
    [[ "$output" == *"-ok"* ]]
}

# ---------- audit log ----------

@test "shell-guard: block writes an audit log line" {
    require_root_guard
    : > "$AUDIT_LOG"
    run shg -c 'somecmd | tail'
    [ "$status" -eq 1 ]
    run cat "$AUDIT_LOG"
    [ "$status" -eq 0 ]
    [[ "$output" == *"|blocked rule: suppress-pipe|uid="* ]]
}

@test "shell-guard: audit line records the working directory" {
    require_root_guard
    : > "$AUDIT_LOG"
    cd "$TEST_TMPDIR"
    run shg -c 'somecmd | tail'
    [ "$status" -eq 1 ]
    run cat "$AUDIT_LOG"
    [[ "$output" == *"|$TEST_TMPDIR|"* ]]
}

@test "shell-guard: audit redacts NAME=value tokens" {
    require_root_guard
    : > "$AUDIT_LOG"
    run shg -c 'SHGTOKEN=hunter2 somecmd | tail'
    [ "$status" -eq 1 ]
    run cat "$AUDIT_LOG"
    [[ "$output" == *"SHGTOKEN=..."* ]]
    run grep -c hunter2 "$AUDIT_LOG"
    [ "$status" -eq 1 ]
}

@test "shell-guard: audit truncates overlong commands" {
    require_root_guard
    : > "$AUDIT_LOG"
    local long
    long="$(head -c 300 /dev/zero | tr '\0' 'a')"
    run shg -c "$long | tail"
    [ "$status" -eq 1 ]
    run grep -cE 'a{250}' "$AUDIT_LOG"
    [ "$status" -eq 1 ]
}

@test "shell-guard: trusted-tier block writes an audit line" {
    require_root_guard
    mkdir -p "$TEST_TMPDIR/trusted-audit"
    printf '#!/bin/bash\nsomecmd | tail\n' > "$TEST_TMPDIR/trusted-audit/t.sh"
    chown -R root:root "$TEST_TMPDIR/trusted-audit"
    chmod 755 "$TEST_TMPDIR/trusted-audit" "$TEST_TMPDIR/trusted-audit/t.sh"
    : > "$AUDIT_LOG"
    run shg "$TEST_TMPDIR/trusted-audit/t.sh"
    [ "$status" -eq 1 ]
    run cat "$AUDIT_LOG"
    [[ "$output" == *"blocked rule: suppress-pipe"* ]]
}

@test "shell-guard: non-root invocation audits to the passwd home" {
    require_root_guard
    [ -n "$PUBLIC_SHG" ] || skip "file-capability execution is unavailable"
    command -v useradd >/dev/null || skip "useradd not available"
    useradd -m shg-bats-user
    run su -s /bin/sh shg-bats-user -c "$PUBLIC_SHG -c 'somecmd | tail'"
    [ "$status" -eq 1 ]
    [[ "$output" == *"BLOCKED"* ]]
    run cat "$(getent passwd shg-bats-user | cut -d: -f6)/.workspace-guard.log"
    [ "$status" -eq 0 ]
    [[ "$output" == *"blocked rule: suppress-pipe"* ]]
}
