#!/usr/bin/env bash
# 01-qc.bats: tests for scripts/lib/qc.sh (the quiet-capture helper).
# qc is the altval-on-error primitive both sync-gtfobins and
# suid-drift-check depend on; a regression here corrupts every
# baseline field that derives from stat/sha256/getcap.
#
# NOTE: bats executes test bodies with `set -e` enabled, so any call
# whose qc-wrapped command is expected to FAIL must be guarded by
# `|| rc=$?` so the nonzero qc return does not abort the test before
# assertions can inspect it.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "qc: returns the command stdout on success" {
    load_guard_lib qc
    out="$(qc ALT printf '%s' "ok-value")"
    assert_equal "ok-value" "$out"
}

@test "qc: exit status is 0 when the wrapped command succeeds" {
    load_guard_lib qc
    qc ALT true
    [ $? -eq 0 ]
}

@test "qc: prints the altval and returns 1 when the command fails" {
    load_guard_lib qc
    local out rc
    out="$(qc MY-ALT false)" || rc=$?
    assert_equal "MY-ALT" "$out"
    [ "${rc:-0}" -eq 1 ]
}

@test "qc: suppresses the failing command's stderr" {
    load_guard_lib qc
    local sink="$TEST_TMPDIR/err" out rc
    DEVNULL="$sink" out="$(qc ALT bash -c 'echo noise >&2; exit 5')" || rc=$?
    assert_equal "ALT" "$out"
    [ "${rc:-0}" -eq 1 ]
    [ -s "$sink" ]
    grep -q noise "$sink"
}

@test "qc: caller stderr stays clean (qc's own suppression isolates it)" {
    load_guard_lib qc
    local captured rc
    captured="$(qc ALT bash -c 'echo noise >&2; exit 5' 2>&1)" || rc=$?
    # qc swallowed the inner stderr via DEVNULL; the only thing on
    # qc's combined stdout+stderr is the altval it printed.
    refute_output --partial "noise"
    assert_equal "ALT" "$captured"
}

@test "qc: preserves multi-line command stdout" {
    load_guard_lib qc
    out="$(qc ALT printf 'a\nb\nc')"
    assert_equal "a
b
c" "$out"
}

@test "qc: honours a caller-supplied DEVNULL sink" {
    load_guard_lib qc
    local sink="$TEST_TMPDIR/sink"
    DEVNULL="$sink" qc ALT bash -c 'echo to-sink >&2' >/dev/null 2>&1
    [ -s "$sink" ]
    grep -q to-sink "$sink"
}

@test "qc: defaults DEVNULL to /dev/null when unset" {
    unset DEVNULL
    load_guard_lib qc
    [ "$DEVNULL" = "/dev/null" ]
}

@test "qc: altval may contain spaces" {
    load_guard_lib qc
    local out
    out="$(qc "alt with space" false)" || rc=$?
    assert_equal "alt with space" "$out"
}

@test "qc: command may take arguments" {
    load_guard_lib qc
    out="$(qc ALT echo one two three)"
    assert_equal "one two three" "$out"
}

@test "qc: returns the altval verbatim (no trimming) on failure" {
    load_guard_lib qc
    local out
    out="$(qc "  spaced-alt  " false)" || rc=$?
    assert_equal "  spaced-alt  " "$out"
}

@test "qc: failure with || true does not abort under set -e" {
    load_guard_lib qc
    set -euo pipefail
    local out
    out="$(qc '?' false || true)"
    assert_equal "?" "$out"
}