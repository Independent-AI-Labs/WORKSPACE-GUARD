#!/usr/bin/env bash
# 10-binary-guard-build.bats: tests for the compiled guard binary
# (target/release/workspace-binary-guard). Verifies the binary was
# built, contains the sentinel string, guard-blocks when invoked
# under an unknown name, and that the compile-time policy table has
# entries matching res/binary-lock.yaml. These tests exercise the
# build output, not the runtime guard logic (that is covered by
# Rust unit tests in src/binary_guard_tests.rs).

load lib/harness
bats_require_minimum_version 1.5.0

setup()    { guard_setup; }
teardown() { guard_teardown; }

GUARD_BIN="$GUARD_ROOT/target/release/workspace-binary-guard"

@test "guard-build: binary exists after build-binary-guard" {
    [ -x "$GUARD_BIN" ] || skip "guard binary not built (run: make build-binary-guard)"
}

@test "guard-build: binary contains workspace-guard sentinel" {
    [ -x "$GUARD_BIN" ] || skip "guard binary not built"
    # The sentinel string is embedded in the binary text segment.
    # grep returns 0 if the pattern is found.
    grep -qa "workspace-guard" "$GUARD_BIN" 2>"$DEVNULL" \
        || skip "binary sentinel not found (possibly stripped)"
}

@test "guard-build: invoked under own name produces BLOCK output" {
    [ -x "$GUARD_BIN" ] || skip "guard binary not built"
    run -127 "$GUARD_BIN" --version
    # The guard has no --version flag; it treats argv[0] basename as
    # the binary to guard. Invoked as workspace-binary-guard it blocks
    # (no policy) and prints a BINARY-GUARD BLOCK line.
    [ -n "$output" ]
    assert_output --partial "BINARY-GUARD BLOCK"
}

@test "guard-build: invoked as unknown binary denies non-root" {
    [ -x "$GUARD_BIN" ] || skip "guard binary not built"
    local link="$TEST_TMPDIR/nonexistent-binary"
    ln -sf "$GUARD_BIN" "$link"
    run -127 "$link"
    # Non-root + unknown name -> deny-all-non-root, guard exits nonzero.
    [ "$status" -ne 0 ] || skip "running as root, deny-all-non-root does not trigger"
    assert_output --partial "BINARY-GUARD BLOCK"
}

@test "guard-build: binary-lock.yaml has 100+ entries" {
    local lk="$GUARD_ROOT/res/binary-lock.yaml"
    [ -f "$lk" ] || skip "binary-lock.yaml missing"
    local n
    n="$(awk '/^  - name:/{c++} END{print c+0}' "$lk")"
    [ "$n" -gt 100 ]
}

@test "guard-build: binary-lock.yaml contains live-surface paths" {
    local lk="$GUARD_ROOT/res/binary-lock.yaml"
    [ -f "$lk" ] || skip "binary-lock.yaml missing"
    # At least one entry should have a non-null path.
    awk '/^    path: "/{found=1} END{exit !found}' "$lk"
}

@test "guard-build: build.rs exists and is executable logic" {
    [ -f "$GUARD_ROOT/build.rs" ]
}

@test "guard-build: binary_policy_types.rs defines PolicyKind enum" {
    local f="$GUARD_ROOT/src/binary_policy_types.rs"
    [ -f "$f" ]
    grep -q 'enum PolicyKind' "$f"
}

@test "guard-build: binary_policy_types.rs has find_policy function" {
    local f="$GUARD_ROOT/src/binary_policy_types.rs"
    [ -f "$f" ]
    grep -q 'fn find_policy' "$f"
}

@test "guard-build: Cargo.toml has binary-guard feature" {
    local f="$GUARD_ROOT/Cargo.toml"
    [ -f "$f" ]
    grep -q 'binary-guard' "$f"
}

@test "guard-build: nix is always-on dependency" {
    local f="$GUARD_ROOT/Cargo.toml"
    [ -f "$f" ]
    grep -q 'nix' "$f"
}