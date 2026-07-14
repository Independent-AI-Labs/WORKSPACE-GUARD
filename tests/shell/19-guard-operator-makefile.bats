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