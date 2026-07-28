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

CREATED_REAL=0
AUDIT_LOG=""
CAP_CTX_OK=0

setup_file() {
    [ -n "$SHG_BIN" ] || return 0
    [ "$(id -u)" = "0" ] || return 0
    mkdir -p "$BATS_FILE_TMPDIR"
    cp "$SHG_BIN" "$BATS_FILE_TMPDIR/shg"
    setcap cap_dac_override=ep "$BATS_FILE_TMPDIR/shg" || return 0
    if [ ! -e /bin/bash.real ]; then
        cp /bin/bash /bin/bash.real
        chown root:root /bin/bash.real
        chmod 0700 /bin/bash.real
        CREATED_REAL=1
        printf '%s' "$BATS_FILE_TMPDIR" > /tmp/.shg-bats-real-marker
    fi
    # Rootless podman maps file capabilities to user.overlay xattrs that
    # the kernel never honors, so exec never sets AT_SECURE. Probe once;
    # tests skip with a clear reason instead of failing everywhere.
    if "$BATS_FILE_TMPDIR/shg" -c 'true' >/dev/null 2>&1; then
        CAP_CTX_OK=1
    fi
    printf '%s' "$CAP_CTX_OK" > "$BATS_FILE_TMPDIR/.cap-ctx"
}

teardown_file() {
    if [ -f /tmp/.shg-bats-real-marker ]; then
        if [ "$(cat /tmp/.shg-bats-real-marker)" = "$BATS_FILE_TMPDIR" ]; then
            rm -f /bin/bash.real
        fi
        rm -f /tmp/.shg-bats-real-marker
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

@test "shell-guard: exits 3 outside a capability context (AT_SECURE=0)" {
    [ -n "$SHG_BIN" ] || skip "shell-guard binary not built (run: cargo build)"
    run "$SHG_BIN" -c 'echo hi'
    [ "$status" -eq 3 ]
    [[ "$output" == *"AT_SECURE"* ]]
}

@test "shell-guard: benign -c string passes through" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'echo hello-from-guard'
    [ "$status" -eq 0 ]
    [ "$output" = "hello-from-guard" ]
}

@test "shell-guard: --help passes through unscanned" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"GNU bash"* ]]
}

@test "shell-guard: blocks pipe-to-tail (suppress-pipe)" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'somecmd | tail -n 5'
    [ "$status" -eq 1 ]
    [[ "$output" == *"BLOCKED"* ]]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: blocks redirect to /dev/null (suppress-null)" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'somecmd > /dev/null'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: blocks stderr redirect to /dev/null (suppress-null)" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'somecmd 2> /dev/null'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: blocks swallow idiom (suppress-swallow)" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'somecmd || true'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-swallow"* ]]
}

@test "shell-guard: blocks pkill (process-by-name)" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'pkill opencode'
    [ "$status" -eq 1 ]
    [[ "$output" == *"process-by-name"* ]]
}

@test "shell-guard: blocks power verb (power-verb)" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'shutdown -h now'
    [ "$status" -eq 1 ]
    [[ "$output" == *"power-verb"* ]]
}

@test "shell-guard: allows targeted kill (control)" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'kill -0 $$'
    [ "$status" -eq 0 ]
}

@test "shell-guard: blocks documented false positive (quoted pipe-tail)" {
    require_root_guard
    run "$BATS_FILE_TMPDIR/shg" -c 'echo "use | tail"'
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: untrusted script with banned idiom is blocked" {
    require_root_guard
    printf '#!/bin/bash\nsomecmd | tail\n' > "$TEST_TMPDIR/evil.sh"
    chmod +x "$TEST_TMPDIR/evil.sh"
    run "$BATS_FILE_TMPDIR/shg" "$TEST_TMPDIR/evil.sh"
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: /tmp script bypass attempt is blocked" {
    require_root_guard
    printf '#!/bin/bash\nsomecmd 2>/dev/null\n' > /tmp/shg-bats-x.sh
    chmod +x /tmp/shg-bats-x.sh
    run "$BATS_FILE_TMPDIR/shg" /tmp/shg-bats-x.sh
    rm -f /tmp/shg-bats-x.sh
    [ "$status" -eq 1 ]
    [[ "$output" == *"suppress-null"* ]]
}

@test "shell-guard: benign untrusted script runs via sealed memfd" {
    require_root_guard
    printf '#!/bin/bash\necho "argv0=$0"\n' > "$TEST_TMPDIR/ok.sh"
    chmod +x "$TEST_TMPDIR/ok.sh"
    run "$BATS_FILE_TMPDIR/shg" "$TEST_TMPDIR/ok.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == argv0=/proc/self/fd/* ]]
}

@test "shell-guard: trusted-tier script is exempt-with-audit" {
    require_root_guard
    mkdir -p "$TEST_TMPDIR/trusted"
    printf '#!/bin/bash\necho trusted-ran\nsomecmd | tail\n' > "$TEST_TMPDIR/trusted/t.sh"
    chown -R root:root "$TEST_TMPDIR/trusted"
    chmod 755 "$TEST_TMPDIR/trusted" "$TEST_TMPDIR/trusted/t.sh"
    run "$BATS_FILE_TMPDIR/shg" "$TEST_TMPDIR/trusted/t.sh"
    [ "$status" -eq 0 ]
    [[ "$output" == *"trusted-ran"* ]]
    [[ "$output" == *"would-block"* ]]
    [[ "$output" == *"suppress-pipe"* ]]
}

@test "shell-guard: block writes an audit log line" {
    require_root_guard
    : > "$AUDIT_LOG"
    run "$BATS_FILE_TMPDIR/shg" -c 'somecmd | tail'
    [ "$status" -eq 1 ]
    run cat "$AUDIT_LOG"
    [ "$status" -eq 0 ]
    [[ "$output" == *"|blocked rule: suppress-pipe|uid="* ]]
}
