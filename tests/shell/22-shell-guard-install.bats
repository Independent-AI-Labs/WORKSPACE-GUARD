#!/usr/bin/env bash
# 22-shell-guard-install.bats: fixture tests for the shell-guard
# deployment scripts (install-shell-guard, uninstall-shell-guard,
# shell-guard-check). Runs entirely under SHG_ROOT fake roots with
# the chattr/lsattr/dpkg-divert/setcap/getcap stubs; no real system
# path is touched. Stock bash and the guard build are both faked with
# /bin/true copies (real ELF, distinct content via appended byte).

load lib/harness

setup() {
    guard_setup
    FAKE="$TEST_TMPDIR/root"
    mkdir -p "$FAKE/bin" "$FAKE/etc/apt/apt.conf.d"
    cp /bin/true "$FAKE/bin/bash"
    GUARD_FIX="$TEST_TMPDIR/guard-bin"
    cp /bin/true "$GUARD_FIX"
    printf '#' >> "$GUARD_FIX"
    export SHG_ROOT="$FAKE" SHG_GUARD_BIN="$GUARD_FIX"
    export GUARD_DIVERT_DB="$TEST_TMPDIR/divert.db"
    export GUARD_SETCAP_DB="$TEST_TMPDIR/setcap.db"
    export GUARD_LSATTR_DB="$TEST_TMPDIR/lsattr.db"
    export GUARD_STUB_LOG="$TEST_TMPDIR/stub.log"
    export GUARD_LSATTR_IMMUTABLE="$GUARD_ROOT/config/*"
}

teardown() { guard_teardown; }

INSTALL="$GUARD_ROOT/scripts/install-shell-guard"
UNINSTALL="$GUARD_ROOT/scripts/uninstall-shell-guard"
CHECK="$GUARD_ROOT/scripts/shell-guard-check"

hash_of() { sha256sum "$1" | awk '{print $1}'; }

@test "shell-guard-install: --help prints usage and exits 0" {
    run bash "$INSTALL" --help
    assert_success
    assert_output --partial "install-shell-guard"
    assert_output --partial "--dry-run"
}

@test "shell-guard-install: prefers cargo-configured release binary" {
    grep -q 'target/agent/release/workspace-shell-guard' "$INSTALL"
    grep -q 'target/release/workspace-shell-guard' "$INSTALL"
    ! grep -q ' -nt ' "$INSTALL"
}

@test "shell-guard-install: unknown arg exits 2" {
    run bash "$INSTALL" --bogus
    assert_failure
    [ "$status" -eq 2 ]
}

@test "shell-guard-install: dry-run changes nothing" {
    run bash "$INSTALL" --dry-run
    assert_success
    assert_output --partial "dry-run"
    [ ! -e "$FAKE/bin/bash.real" ]
    [ ! -e "$GUARD_DIVERT_DB" ]
}

@test "shell-guard-install: applies guard to a fresh fixture" {
    run bash "$INSTALL"
    assert_success
    assert_output --partial "installed and verified"
    # /bin/sh untouched (no sh in fixture)
    assert_output --partial "left untouched"
    # guard at the bash path, matching the fixture build byte-for-byte
    [ "$(hash_of "$FAKE/bin/bash")" = "$(hash_of "$GUARD_FIX")" ]
    [ "$(stat -c %a "$FAKE/bin/bash")" = "755" ]
    # sealed original
    [ -f "$FAKE/bin/bash.real" ]
    [ "$(stat -c %a "$FAKE/bin/bash.real")" = "700" ]
    # diverted original preserved
    [ -f "$FAKE/bin/bash.distrib" ]
    [ "$(hash_of "$FAKE/bin/bash.distrib")" = "$(hash_of /bin/true)" ]
    [ "$(stat -c %a "$FAKE/bin/bash.distrib")" = "700" ]
    # capabilities recorded against the installed inode
    run getcap "$FAKE/bin/bash"
    assert_output --partial "cap_dac_override=ep"
    # immutable flag toggled via chattr stub
    grep -q "chattr +i $FAKE/bin/bash.real" "$GUARD_STUB_LOG"
    # apt hook written
    [ -f "$FAKE/etc/apt/apt.conf.d/99workspace-guard-shell" ]
    [ -x "$FAKE/usr/lib/workspace-guard/apt-shell-check" ]
    grep -qF 'DPkg::Post-Invoke { "/usr/lib/workspace-guard/apt-shell-check"; };' \
        "$FAKE/etc/apt/apt.conf.d/99workspace-guard-shell"
}

@test "shell-guard-install: second run is a reconciling no-op" {
    run bash "$INSTALL"
    assert_success
    run bash "$INSTALL"
    assert_success
    assert_output --partial "already current"
}

@test "shell-guard-install: reconcile repairs a missing apt hook" {
    run bash "$INSTALL"
    assert_success
    rm -f "$FAKE/etc/apt/apt.conf.d/99workspace-guard-shell"
    run bash "$INSTALL"
    assert_success
    [ -f "$FAKE/etc/apt/apt.conf.d/99workspace-guard-shell" ]
}

@test "shell-guard-install: reconcile repairs a missing apt hook checker" {
    run bash "$INSTALL"
    assert_success
    rm -f "$FAKE/usr/lib/workspace-guard/apt-shell-check"
    run bash "$INSTALL"
    assert_success
    [ -x "$FAKE/usr/lib/workspace-guard/apt-shell-check" ]
}

@test "shell-guard-install: covers /bin/sh when it resolves to bash" {
    ln -s bash "$FAKE/bin/sh"
    run bash "$INSTALL"
    assert_success
    [ "$(hash_of "$FAKE/bin/sh")" = "$(hash_of "$GUARD_FIX")" ]
    grep -qxF "$FAKE/bin/sh" "$GUARD_DIVERT_DB"
}

@test "shell-guard-check: reports NOT INSTALLED on an empty fixture" {
    run bash "$CHECK"
    [ "$status" -eq 2 ]
    assert_output --partial "NOT INSTALLED"
}

@test "shell-guard-check: OK after install" {
    run bash "$INSTALL"
    assert_success
    run bash "$CHECK"
    assert_success
    assert_output --partial "shell guard: OK"
}

@test "shell-guard-check: flags a missing apt hook as DRIFTED" {
    run bash "$INSTALL"
    assert_success
    rm -f "$FAKE/etc/apt/apt.conf.d/99workspace-guard-shell"
    run bash "$CHECK"
    [ "$status" -eq 1 ]
    assert_output --partial "DRIFTED"
    assert_output --partial "apt hook missing"
}

@test "shell-guard-check: flags a missing apt hook checker as DRIFTED" {
    run bash "$INSTALL"
    assert_success
    rm -f "$FAKE/usr/lib/workspace-guard/apt-shell-check"
    run bash "$CHECK"
    [ "$status" -eq 1 ]
    assert_output --partial "DRIFTED"
    assert_output --partial "apt hook checker missing"
}

@test "shell-guard-check: flags relaxed .real mode as DRIFTED" {
    run bash "$INSTALL"
    assert_success
    chmod 0755 "$FAKE/bin/bash.real"
    run bash "$CHECK"
    [ "$status" -eq 1 ]
    assert_output --partial "mode != 0700"
}

@test "shell-guard-check: flags a stale guard hash as DRIFTED" {
    run bash "$INSTALL"
    assert_success
    printf 'x' >> "$FAKE/bin/bash"
    run bash "$CHECK"
    [ "$status" -eq 1 ]
    assert_output --partial "DRIFTED"
    assert_output --partial "hash differs"
}

@test "shell-guard-check: repo root argument survives memfd-style staging" {
    run bash "$INSTALL"
    assert_success
    # Process substitution gives BASH_SOURCE=/dev/fd/N, mirroring the
    # guard's sealed-memfd staging (/proc/self/fd/N); the derivation
    # must be rejected and the explicit argument used instead.
    run bash -c 'bash <(cat "$1") "$2"' _ "$CHECK" "$GUARD_ROOT"
    assert_success
    assert_output --partial "shell guard: OK"
    refute_output --partial "policy config checks skipped"
}

@test "shell-guard-check: staged script without explicit root exits 2 with remediation" {
    run bash "$INSTALL"
    assert_success
    # No argument, no SHG_REPO_ROOT, BASH_SOURCE=/dev/fd/N: there is
    # no fallback, the script must refuse explicitly.
    run bash -c 'env -u SHG_REPO_ROOT bash <(cat "$1")' _ "$CHECK"
    [ "$status" -eq 2 ]
    assert_output --partial "repo root not determinable from script path"
    assert_output --partial "shell-guard-check <repo-root>"
}

@test "shell-guard-check: explicit root that is not a directory exits 2" {
    run bash "$INSTALL"
    assert_success
    run bash "$CHECK" /nonexistent-repo-root
    [ "$status" -eq 2 ]
    assert_output --partial "is not a directory"
    run bash -c 'SHG_REPO_ROOT=/nonexistent-repo-root bash "$1"' _ "$CHECK"
    [ "$status" -eq 2 ]
    assert_output --partial "is not a directory"
}

@test "shell-guard-check: unreadable bash.real reports OK-with-note for the +i probe" {
    [ "$(id -u)" -ne 0 ] || skip "unreadable-file premise needs a non-root caller (root reads through chmod 0000)"
    run bash "$INSTALL"
    assert_success
    chmod 0000 "$FAKE/bin/bash.real"
    export GUARD_LSATTR_FAIL="$FAKE/bin/bash.real"
    run bash "$CHECK"
    [ "$status" -eq 1 ]
    assert_output --partial "mode != 0700"
    assert_output --partial "not verifiable as non-root"
    refute_output --partial "missing +i"
}

@test "shell-guard-check: SHG_GETCAP override is honored" {
    run bash "$INSTALL"
    assert_success
    run env SHG_GETCAP=/bin/false bash "$CHECK"
    [ "$status" -eq 1 ]
    assert_output --partial "missing cap_dac_override=ep"
}

@test "shell-guard-uninstall: restores stock bash and cleans up" {
    run bash "$INSTALL"
    assert_success
    run bash "$UNINSTALL"
    assert_success
    assert_output --partial "stock bash restored"
    [ "$(hash_of "$FAKE/bin/bash")" = "$(hash_of /bin/true)" ]
    [ "$(stat -c %a "$FAKE/bin/bash")" = "755" ]
    [ ! -e "$FAKE/bin/bash.real" ]
    [ ! -e "$FAKE/bin/bash.distrib" ]
    [ ! -e "$FAKE/etc/apt/apt.conf.d/99workspace-guard-shell" ]
    [ ! -e "$FAKE/usr/lib/workspace-guard/apt-shell-check" ]
    [ ! -s "$GUARD_DIVERT_DB" ]
    grep -q "chattr -i $FAKE/bin/bash.real" "$GUARD_STUB_LOG"
}

@test "shell-guard-uninstall: no-op when not installed" {
    run bash "$UNINSTALL"
    assert_success
    assert_output --partial "nothing to do"
}

@test "shell-guard-uninstall: dry-run changes nothing" {
    run bash "$INSTALL"
    assert_success
    run bash "$UNINSTALL" --dry-run
    assert_success
    [ -e "$FAKE/bin/bash.real" ]
    [ -f "$GUARD_DIVERT_DB" ]
}
