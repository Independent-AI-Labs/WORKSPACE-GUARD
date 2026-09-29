#!/usr/bin/env bash
# 25-exec-dispositions.bats: REQ-EXEC-150/151 disposition gate. Every rule in
# config/shell_guard_policy.yaml must have a row in the SPEC-EXEC-POLICY
# section 7 matrix, so a rule cannot be added without a disposition.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "exec-dispositions: repo passes the disposition gate" {
    run bash "$GUARD_ROOT/scripts/check-exec-dispositions.sh" "$GUARD_ROOT"
    [ "$status" -eq 0 ]
    [[ "$output" == *"policy rules disposed"* ]]
}

@test "exec-dispositions: a rule without a matrix row fails the gate" {
    mkdir -p "$TEST_TMPDIR/tree/config" "$TEST_TMPDIR/tree/docs/specifications"
    printf 'rules:\n  - id: power-verb\n  - id: not-disposed\n' \
        > "$TEST_TMPDIR/tree/config/shell_guard_policy.yaml"
    printf '| Rule id |\n| --- |\n| `power-verb` | ok |\n' \
        > "$TEST_TMPDIR/tree/docs/specifications/SPEC-EXEC-POLICY.md"
    run bash "$GUARD_ROOT/scripts/check-exec-dispositions.sh" "$TEST_TMPDIR/tree"
    [ "$status" -eq 1 ]
    [[ "$output" == *"not-disposed"* ]]
}

@test "exec-dispositions: a missing spec fails closed" {
    mkdir -p "$TEST_TMPDIR/tree/config"
    printf 'rules:\n  - id: power-verb\n' > "$TEST_TMPDIR/tree/config/shell_guard_policy.yaml"
    run bash "$GUARD_ROOT/scripts/check-exec-dispositions.sh" "$TEST_TMPDIR/tree"
    [ "$status" -eq 1 ]
    [[ "$output" == *"missing"* ]]
}
