#!/usr/bin/env bash
# 24-unsafe-boundary.bats: REQ-GGUARD-121 ratchet for the reviewed unsafe
# boundary. Production unsafe Rust and direct libc usage live only in the
# allowlisted reviewed modules; any new carrier fails the gate.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "unsafe-boundary: repo passes the reviewed-boundary gate" {
    run bash "$GUARD_ROOT/scripts/check-unsafe-boundary.sh" "$GUARD_ROOT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"unsafe-boundary: OK"* ]]
}

@test "unsafe-boundary: an unlisted unsafe block fails the gate" {
    mkdir -p "$TEST_TMPDIR/tree/src"
    printf 'fn f() { unsafe %s }\n' '{ }' > "$TEST_TMPDIR/tree/src/bad.rs"
    run bash "$GUARD_ROOT/scripts/check-unsafe-boundary.sh" "$TEST_TMPDIR/tree"
    [ "$status" -eq 1 ]
    [[ "$output" == *"src/bad.rs"* ]]
}

@test "unsafe-boundary: an unlisted direct libc call fails the gate" {
    mkdir -p "$TEST_TMPDIR/tree/src"
    printf 'fn f() { libc::%s(); }\n' 'geteuid' > "$TEST_TMPDIR/tree/src/bad.rs"
    run bash "$GUARD_ROOT/scripts/check-unsafe-boundary.sh" "$TEST_TMPDIR/tree"
    [ "$status" -eq 1 ]
    [[ "$output" == *"src/bad.rs"* ]]
}
