#!/usr/bin/env bash
# 00-harness.bats: sanity tests for the test harness itself. These guard
# the contract every other suite depends on (GUARD_ROOT resolves to the
# repo under test, stubs actually shadow real tools, assertions fail on
# the right conditions). A regression here would make every other suite
# emit misleading passes.

load lib/harness

setup()      { guard_setup; }
teardown()   { guard_teardown; }

@test "harness: GUARD_ROOT points at the WORKSPACE-GUARD repo" {
    [ -n "$GUARD_ROOT" ]
    [ -d "$GUARD_ROOT/.git" ]
    [ -f "$GUARD_ROOT/Makefile" ]
    [ -f "$GUARD_ROOT/scripts/sync-gtfobins" ]
}

@test "harness: TESTS_DIR and STUBS_DIR resolve under GUARD_ROOT" {
    [ "$TESTS_DIR" = "$GUARD_ROOT/tests/shell" ]
    [ "$STUBS_DIR" = "$GUARD_ROOT/tests/shell/stubs" ]
    [ -d "$STUBS_DIR" ]
}

@test "harness: TEST_TMPDIR is a fresh writable dir per test" {
    [ -d "$TEST_TMPDIR" ]
    [ -w "$TEST_TMPDIR" ]
    echo marker > "$TEST_TMPDIR/probe"
    [ "$(cat "$TEST_TMPDIR/probe")" = "marker" ]
}

@test "harness: stubs dir is at the FRONT of PATH and shadows real tools" {
    # The first `find` on PATH must be our stub.
    command -v find
    [ "$(command -v find)" = "$STUBS_DIR/find" ]
    [ "$(command -v chattr)" = "$STUBS_DIR/chattr" ]
    [ "$(command -v id)" = "$STUBS_DIR/id" ]
}

@test "harness: id stub reports uid 0 (fake root for install suites)" {
    run id -u
    assert_success
    assert_output "0"
}

@test "harness: find stub honours GUARD_FIND_FIXTURE" {
    printf '%s\n' /usr/bin/passwd /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    run find / -xdev -perm -4000 -type f
    assert_success
    assert_line "/usr/bin/passwd"
    assert_line "/usr/bin/sudo"
}

@test "harness: find stub emits nothing with no fixture set" {
    unset GUARD_FIND_FIXTURE
    run find / -xdev -perm -4000 -type f
    assert_success
    assert_line_count 0
}

@test "harness: assert_success fails on a nonzero command" {
    run bash -c 'echo boom >&2; exit 7'
    [ "$status" -eq 7 ]
    # assert_success must itself return nonzero (failing the test).
    if assert_success 2>"$DEVNULL"; then
        echo "assert_success wrongly passed for exit 7" >&2
        return 1
    fi
}

@test "harness: assert_failure fails on an exit-0 command" {
    run bash -c 'echo ok; exit 0'
    if assert_failure 2>"$DEVNULL"; then
        echo "assert_failure wrongly passed for exit 0" >&2
        return 1
    fi
}

@test "harness: assert_output --partial matches a substring" {
    run bash -c 'echo "lock surface: 13 binaries"'
    assert_success
    assert_output --partial "lock surface"
}

@test "harness: refute_output --partial fails when the substring is present" {
    run bash -c 'echo "contained"'
    if refute_output --partial "contained" 2>"$DEVNULL"; then
        echo "refute_output wrongly passed" >&2
        return 1
    fi
}

@test "harness: load_guard_lib sources qc() into the test shell" {
    load_guard_lib qc
    type -t qc | grep -q function
}

@test "harness: guard_teardown removes TEST_TMPDIR" {
    local d="$TEST_TMPDIR"
    guard_teardown
    if [ -d "$d" ]; then
        echo "TEST_TMPDIR survived teardown" >&2
        return 1
    fi
}