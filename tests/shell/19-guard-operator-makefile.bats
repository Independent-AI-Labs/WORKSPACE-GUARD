#!/usr/bin/env bash
# 19-guard-operator-makefile.bats: guard-% operator target wiring regressions.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "guard Makefile uses guard-% pattern with script mode arg" {
    local mk="$GUARD_ROOT/Makefile"
    grep -q '^guard-%:' "$mk"
    grep -q "bash scripts/guard-operator.sh '\$\\*'" "$mk"
    ! grep -q "guard-operator.sh \$@" "$mk"
}

@test "guard Makefile does not declare empty phony guard-refresh" {
    local mk="$GUARD_ROOT/Makefile"
    grep -q '^\.PHONY: guard-%' "$mk"
    ! grep -qE '^\.PHONY:.*guard-refresh' "$mk"
}

@test "guard-refresh invokes operator refresh mode" {
    run make -n guard-refresh
    assert_success
    assert_output --partial "guard-operator.sh 'refresh'"
}

@test "guard-operator wires shell guard into up/refresh/down/check" {
    local op="$GUARD_ROOT/scripts/guard-operator.sh"
    grep -q '_shell_guard_up' "$op"
    grep -q 'install-shell-guard' "$op"
    grep -q 'uninstall-shell-guard' "$op"
    grep -q 'shell-guard-check' "$op"
    grep -q 'shell guard not yet implemented' "$op"
}

@test "guard-operator shell guard step soft-skips while scripts absent" {
    run bash -n "$GUARD_ROOT/scripts/guard-operator.sh"
    assert_success
    [ ! -e "$GUARD_ROOT/scripts/install-shell-guard" ]
    [ ! -e "$GUARD_ROOT/scripts/shell-guard-check" ]
    run bash -c '
        REPO_ROOT="'"$GUARD_ROOT"'"
        source <(sed -n "/^_shell_guard_available/,/^}/p" "'"$GUARD_ROOT"'/scripts/guard-operator.sh")
        _shell_guard_available
    '
    assert_failure
}

@test "guard Makefile declares shell guard install/uninstall/check targets" {
    local mk="$GUARD_ROOT/Makefile"
    grep -q '^install-shell-guard:' "$mk"
    grep -q '^uninstall-shell-guard:' "$mk"
    grep -q '^shell-guard-check:' "$mk"
    grep -q 'scripts/install-shell-guard not yet implemented' "$mk"
}