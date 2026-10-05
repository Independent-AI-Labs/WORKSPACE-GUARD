#!/usr/bin/env bash
# 27-exempt-registry.bats: tests for scripts/install-exempt-registry.
# Root-only provisioning of the host CI-contract exemption registry
# (REQ-GGUARD-182). Uses the id/chown/lsattr/chattr stubs and a custom
# stat stub (root:root 644) so the root-only code path runs as a
# non-root bats user without touching /etc. The registry directory is
# redirected under TEST_TMPDIR via WORKSPACE_GUARD_EXEMPT_REGISTRY_DIR.

load lib/harness

setup()    { guard_setup; _setup_registry; }
teardown() { guard_teardown; }

_setup_registry() {
    export WORKSPACE_GUARD_EXEMPT_REGISTRY_DIR="$TEST_TMPDIR/etc-guard"
    export REGISTRY="$WORKSPACE_GUARD_EXEMPT_REGISTRY_DIR/exempt-projects.yaml"
    # The lsattr stub never reports the immutable flag for this path on
    # a tmpfs, so pin it. Chattr invocations are still logged.
    export GUARD_LSATTR_IMMUTABLE="$REGISTRY"
    export REAL_STAT
    REAL_STAT="$(command -v stat)"
    make_stub stat <<STUB
#!/usr/bin/env bash
if [ "\$1" = "-c" ] && [ "\$2" = "%U:%G" ]; then echo root:root; exit 0; fi
if [ "\$1" = "-c" ] && [ "\$2" = "%a" ]; then echo "\${GUARD_STAT_MODE:-644}"; exit 0; fi
exec "$REAL_STAT" "\$@"
STUB
}

@test "install-exempt-registry: creates the registry dir and empty registry" {
    run bash "$GUARD_ROOT/scripts/install-exempt-registry"
    assert_success
    [ -f "$REGISTRY" ]
    grep -q '^version: 1$' "$REGISTRY"
    grep -q '^exemptions: \[\]$' "$REGISTRY"
    assert_output --partial "created"
}

@test "install-exempt-registry: applies the immutable flag" {
    run bash "$GUARD_ROOT/scripts/install-exempt-registry"
    assert_success
    grep -q "+i" "$GUARD_STUB_LOG"
    grep -q "$REGISTRY" "$GUARD_STUB_LOG"
}

@test "install-exempt-registry: preserves an existing registry byte-for-byte" {
    mkdir -p "$WORKSPACE_GUARD_EXEMPT_REGISTRY_DIR"
    printf 'version: 1\nexemptions:\n  - path: /w/keep\n    reason: keep me\n    added_by: op\n' > "$REGISTRY"
    before="$(cat "$REGISTRY")"
    run bash "$GUARD_ROOT/scripts/install-exempt-registry"
    assert_success
    after="$(cat "$REGISTRY")"
    assert_equal "$before" "$after"
    refute_output --partial "created"
}

@test "install-exempt-registry: strips then reapplies the immutable flag" {
    mkdir -p "$WORKSPACE_GUARD_EXEMPT_REGISTRY_DIR"
    printf 'version: 1\nexemptions: []\n' > "$REGISTRY"
    run bash "$GUARD_ROOT/scripts/install-exempt-registry"
    assert_success
    grep -q -- "-i $REGISTRY" "$GUARD_STUB_LOG"
    grep -q -- "+i $REGISTRY" "$GUARD_STUB_LOG"
}

@test "install-exempt-registry: refuses a symlinked registry" {
    mkdir -p "$WORKSPACE_GUARD_EXEMPT_REGISTRY_DIR"
    printf 'version: 1\nexemptions: []\n' > "$TEST_TMPDIR/real-registry"
    ln -s "$TEST_TMPDIR/real-registry" "$REGISTRY"
    run bash "$GUARD_ROOT/scripts/install-exempt-registry"
    assert_failure
    [ "$status" -eq 3 ]
    assert_output --partial "symlink"
}

@test "install-exempt-registry: reports a wrong mode as an invariant failure" {
    mkdir -p "$WORKSPACE_GUARD_EXEMPT_REGISTRY_DIR"
    printf 'version: 1\nexemptions: []\n' > "$REGISTRY"
    export GUARD_STAT_MODE="600"
    run bash "$GUARD_ROOT/scripts/install-exempt-registry"
    assert_failure
    [ "$status" -eq 3 ]
    assert_output --partial "mode is 600"
}
