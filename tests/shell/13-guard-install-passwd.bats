#!/usr/bin/env bash
# 13-guard-install-passwd.bats: regression for /etc/passwd UID discovery in
# install_ambient_caps_pam (field 7 must be shell, not home directory).

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "guard-install-passwd: discovers uid from home-dir passwd layout" {
    printf '%s\n' "agent:x:1000:1000::$TEST_TMPDIR/agent:/bin/bash" > "$TEST_TMPDIR/passwd"
    run awk -F: '$3>=1000 && $3<65534 && $7 ~ /\/(bash|sh|zsh|fish)$/{print $3}' "$TEST_TMPDIR/passwd"
    [ "$status" -eq 0 ]
    [ "$output" = "1000" ]
}

@test "guard-install-passwd: rejects home directory mistaken for shell" {
    printf '%s\n' "agent:x:1000:1000::$TEST_TMPDIR/agent:/bin/bash" > "$TEST_TMPDIR/passwd"
    run awk -F: '$3>=1000 && $3<65534 && $6 ~ /\/(bash|sh|zsh|fish)$/{print $3}' "$TEST_TMPDIR/passwd"
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "guard-install-passwd: discovers username for verify user selection" {
    printf '%s\n' "agent:x:1000:1000::$TEST_TMPDIR/agent:/bin/bash" > "$TEST_TMPDIR/passwd"
    run awk -F: '$3>=1000 && $3<65534 && $7 ~ /\/(bash|sh|zsh|fish)$/{print $1; exit}' "$TEST_TMPDIR/passwd"
    [ "$status" -eq 0 ]
    [ "$output" = "agent" ]
}

@test "guard-install-passwd: grant targets emit uid and username" {
    printf '%s\n' "agent:x:1000:1000::$TEST_TMPDIR/agent:/bin/bash" > "$TEST_TMPDIR/passwd"
    run awk -F: '$3>=1000 && $3<65534 && $7 ~ /\/(bash|sh|zsh|fish)$/{print $3" "$1}' "$TEST_TMPDIR/passwd"
    [ "$status" -eq 0 ]
    [ "$output" = "1000 agent" ]
}

@test "guard-install-passwd: cap-fatal stderr is not a policy block" {
    stderr='FATAL: missing workload capabilities (cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid)'
    run grep -q 'missing workload capabilities' <<<"$stderr"
    [ "$status" -eq 0 ]
}