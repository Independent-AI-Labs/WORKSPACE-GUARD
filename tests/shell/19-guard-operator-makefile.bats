#!/usr/bin/env bash
# 19-guard-operator-makefile.bats: guard-% operator target wiring regressions.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "guard Makefile uses guard-% pattern with script mode arg" {
    local mk="$GUARD_ROOT/Makefile"
    grep -q '^guard-%:' "$mk"
    grep -q 'SCRIPT_BASH)" scripts/guard-operator.sh' "$mk"
    ! grep -q "guard-operator.sh \$@" "$mk"
}

@test "all recipes use the guarded bash" {
    local mk="$GUARD_ROOT/Makefile"
    grep -q '^SCRIPT_BASH := bash$' "$mk"
    ! grep -qE '^(SHELL|SCRIPT_BASH) := /bin/bash\.real$' "$mk"
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

@test "guard build removes stale binaries before invoking the deployment helper" {
    local recipe
    recipe="$(make -n build-guard 2>&1)"
    [[ "$recipe" == *'rm -f '*'/target/release/workspace-guard'* ]]
    [[ "$recipe" == *'bootstrap-workspace-guard" build-only'* ]]
    [[ "${recipe%%bootstrap-workspace-guard*}" == *'rm -f '* ]]
}

@test "guard install verifies deployed bytes after the deployment helper" {
    local recipe
    recipe="$(make -n GUARD_SKIP_BUILD=1 install-guard-host-exec 2>&1)"
    [[ "$recipe" == *'bootstrap-workspace-guard" install-host-exec'* ]]
    [[ "$recipe" == *'scripts/check-guard-host-exec-readonly'* ]]
    [[ "${recipe#*install-host-exec}" == *'scripts/check-guard-host-exec-readonly'* ]]
}

@test "guard-operator does not trigger the alternate rc shell rule" {
    ! grep -qE '(^|[[:space:]])rc(=|[[:space:]])' "$GUARD_ROOT/scripts/guard-operator.sh"
}

@test "guard-operator wires shell guard into up/refresh/down/check" {
    local op="$GUARD_ROOT/scripts/guard-operator.sh"
    grep -q '_shell_guard_up' "$op"
    grep -q 'install-shell-guard' "$op"
    grep -q 'uninstall-shell-guard' "$op"
    grep -q 'shell-guard-check' "$op"
    grep -q 'shell guard not yet implemented' "$op"
}

@test "guard-operator shell guard step activates now that scripts exist" {
    run bash -n "$GUARD_ROOT/scripts/guard-operator.sh"
    assert_success
    [ -x "$GUARD_ROOT/scripts/install-shell-guard" ]
    [ -x "$GUARD_ROOT/scripts/uninstall-shell-guard" ]
    [ -x "$GUARD_ROOT/scripts/shell-guard-check" ]
    run bash -c '
        REPO_ROOT="'"$GUARD_ROOT"'"
        source <(sed -n "/^_shell_guard_available/,/^}/p" "'"$GUARD_ROOT"'/scripts/guard-operator.sh")
        _shell_guard_available
    '
    assert_success
}

@test "guard-up installs shell guard alongside git guard in one bring-up" {
    run bash -c '
        REPO_ROOT="'"$GUARD_ROOT"'"
        MARKER=/nonexistent-guard-up-marker
        require_root() { :; }
        _user_mgmt_enabled() { return 1; }
        _guard_needs_install() { return 0; }
        _shell_guard_up() { echo "SHELL_GUARD_UP_CALLED"; }
        make() { echo "MAKE $*"; }
        source <(sed -n "/^guard_up()/,/^}/p" "'"$GUARD_ROOT"'/scripts/guard-operator.sh")
        guard_up
    '
    assert_success
    assert_output --partial "MAKE -C $GUARD_ROOT install-guard-host-exec"
    assert_output --partial "SHELL_GUARD_UP_CALLED"
}

@test "guard-up runs shell guard step after full host provision" {
    run bash -c '
        REPO_ROOT="'"$GUARD_ROOT"'"
        MARKER=/nonexistent-guard-up-marker
        require_root() { :; }
        _user_mgmt_enabled() { return 0; }
        _guard_needs_install() { return 1; }
        _shell_guard_up() { echo "SHELL_GUARD_UP_CALLED"; }
        make() { echo "MAKE $*"; }
        source <(sed -n "/^guard_up()/,/^}/p" "'"$GUARD_ROOT"'/scripts/guard-operator.sh")
        guard_up
    '
    assert_success
    assert_output --partial "MAKE -C $GUARD_ROOT provision-host"
    assert_output --partial "SHELL_GUARD_UP_CALLED"
}

@test "guard Makefile declares shell guard install/uninstall/check targets" {
    local mk="$GUARD_ROOT/Makefile"
    grep -q '^install-shell-guard:' "$mk"
    grep -q '^uninstall-shell-guard:' "$mk"
    grep -q '^shell-guard-check:' "$mk"
    grep -q 'SCRIPT_BASH) scripts/install-shell-guard' "$mk"
    grep -q 'SCRIPT_BASH) scripts/uninstall-shell-guard' "$mk"
    grep -q 'SCRIPT_BASH) scripts/shell-guard-check' "$mk"
    grep -q '^build-shell-guard:' "$mk"
}

@test "non-root guard checks use the read-only host-exec checker" {
    local mk="$GUARD_ROOT/Makefile"
    local op="$GUARD_ROOT/scripts/guard-operator.sh"
    local checker="$GUARD_ROOT/scripts/check-guard-host-exec-readonly"
    grep -q '^guard-check:' "$mk"
    grep -q 'scripts/check-guard-host-exec-readonly' "$mk"
    grep -q 'scripts/check-guard-host-exec-readonly' "$op"
    [ -x "$checker" ]
    ! grep -qE '(^|[[:space:]])(chattr|setcap|mv|rm)([[:space:]]|$)' "$checker"
    ! grep -qE '2>[[:space:]]*/dev/null|>[[:space:]]*/dev/null' "$checker"
}

@test "guard Makefile shell-guard-check uses guarded bash" {
    run make -n shell-guard-check
    assert_success
    assert_output --partial "bash scripts/shell-guard-check"
    refute_output --partial "/bin/bash.real"
}

@test "guard Makefile does not select an interpreter by uid" {
    local mk="$GUARD_ROOT/Makefile"
    ! grep -q '^ifeq ($(shell id -u),0)' "$mk"
}

@test "guard-operator shell check uses guarded bash and passes repo root" {
    local op="$GUARD_ROOT/scripts/guard-operator.sh"
    grep -q 'bash "$REPO_ROOT/scripts/shell-guard-check" "$REPO_ROOT"' "$op"
    ! grep -q '/bin/bash.real' "$op"
}

@test "guard test-shell target uses the isolated test harness" {
    local mk="$GUARD_ROOT/Makefile"
    grep -q 'scripts/podman/run-shell-tests.sh' "$mk"
    ! grep -q '#!/bin/bash.real' "$mk"
}
