#!/usr/bin/env bash
# 02-find-suid.bats: tests for scripts/lib/find-suid.sh. The function
# shares one exclusion filter between sync-gtfobins and suid-drift-
# check; these tests lock the filter so neither script can diverge and
# drop a path without an operator noticing (e.g. a /tmp-planted SUID).

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "find-suid: writes the fixture list verbatim to the out file" {
    load_guard_lib find-suid
    printf '%s\n' /usr/bin/sudo /usr/bin/passwd /opt/x/bin > "$TEST_TMPDIR/in"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_suid_live "$out"
    assert_equal "$(printf '%s\n' /opt/x/bin /usr/bin/passwd /usr/bin/sudo)" "$(cat "$out")"
}

@test "find-suid: returns 0 even when find emits nothing" {
    load_guard_lib find-suid
    unset GUARD_FIND_FIXTURE
    out="$TEST_TMPDIR/out"
    discover_suid_live "$out"
    [ $? -eq 0 ]
    [ ! -s "$out" ]
}

@test "find-suid: returns 0 when the stubbed find exits nonzero (partial result)" {
    load_guard_lib find-suid
    # Replace the static find stub with one that exits 1 but still
    # writes output, mimicking find's permission-denied exit code.
    make_stub find <<'STUB'
#!/usr/bin/env bash
if [ -n "${GUARD_FIND_FIXTURE:-}" ] && [ -r "$GUARD_FIND_FIXTURE" ]; then
    cat "$GUARD_FIND_FIXTURE"
fi
exit 1
STUB
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/in"
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/in"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_suid_live "$out"
    [ $? -eq 0 ]
    grep -qx /usr/bin/sudo "$out"
}

@test "find-suid: sorts the result (caller relies on stable diff)" {
    load_guard_lib find-suid
    printf '%s\n' /usr/bin/zebra /usr/bin/apple /usr/bin/mount > "$TEST_TMPDIR/in"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_suid_live "$out"
    [ "$(head -n1 "$out")" = "/usr/bin/apple" ]
    [ "$(tail -n1 "$out")" = "/usr/bin/zebra" ]
}

@test "find-suid: out file is created empty (truncated) even on no fixture" {
    load_guard_lib find-suid
    unset GUARD_FIND_FIXTURE
    out="$TEST_TMPDIR/out"
    : > "$out"
    echo stale > "$out"
    discover_suid_live "$out"
    [ ! -s "$out" ]
}

@test "find-suid: preserves duplicate paths only iff unsorted fixture has them" {
    load_guard_lib find-suid
    # find finds them; the function pipes through `sort` (not sort -u),
    # so dupes are retained. This documents the contract.
    printf '%s\n' /usr/bin/sudo /usr/bin/sudo /usr/bin/passwd > "$TEST_TMPDIR/in"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_suid_live "$out"
    assert_equal 3 "$(wc -l < "$out")"
}

@test "find-suid: handles paths containing spaces (no field splitting)" {
    load_guard_lib find-suid
    printf '%s\n' '/usr/bin/my tool' /usr/bin/sudo > "$TEST_TMPDIR/in"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_suid_live "$out"
    grep -qxF '/usr/bin/my tool' "$out"
}

@test "find-suid: DEVNULL default exists so stderr is swallowed not leaked" {
    unset DEVNULL
    load_guard_lib find-suid
    [ "$DEVNULL" = "/dev/null" ]
}