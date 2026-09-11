#!/usr/bin/env bash
# 20-yaml-edit.bats: non-root tests for the workspace-yaml-edit binary
# (SPEC-YAML-EDIT, REQ-YE-700). Covers usage errors, the not-root
# refusal for mutations, read-only intents (get/list/validate), and
# the full mutation matrix via --dry-run (diff output, no install, no
# root needed). Real root-tier mutation behavior (install, chattr
# preservation, flock, audit) is exercised as container root by
# scripts/podman/e2e-yaml-edit.sh.

load lib/harness

setup() { guard_setup; }

teardown() { guard_teardown; }

# Locate (or build once) the binary under test. Agent-side builds are
# preferred so tests exercise the current source, then installed and
# other cargo outputs are considered.
_ye() {
    local b
    if [ -x "$GUARD_ROOT/target/agent/debug/workspace-yaml-edit" ]; then
        echo "$GUARD_ROOT/target/agent/debug/workspace-yaml-edit"
        return 0
    fi
    for b in release debug; do
        if [ -x "$GUARD_ROOT/target/$b/workspace-yaml-edit" ]; then
            echo "$GUARD_ROOT/target/$b/workspace-yaml-edit"
            return 0
        fi
    done
    if [ -x /usr/bin/workspace-yaml-edit ]; then
        echo /usr/bin/workspace-yaml-edit
        return 0
    fi
    (cd "$GUARD_ROOT" && CARGO_TARGET_DIR="$GUARD_ROOT/target/agent" \
        cargo build --quiet --bin workspace-yaml-edit) || return 1
    echo "$GUARD_ROOT/target/agent/debug/workspace-yaml-edit"
}

_q_fixture() {
    local f="$TEST_TMPDIR/quality_exceptions.yaml"
    cat > "$f" <<'EOF'
# quality gate exemptions
policy_version: 2
exceptions:
  - hook: quality
    added_by: alice
    reason: tracked upstream, remove after release
    paths:
      - src/a.py
EOF
    printf '%s\n' "$f"
}

_empty_fixture() {
    local f="$TEST_TMPDIR/quality_exceptions.yaml"
    cat > "$f" <<'EOF'
policy_version: 2
exceptions: []
EOF
    printf '%s\n' "$f"
}

_cov_fixture() {
    local f="$TEST_TMPDIR/coverage_thresholds.yaml"
    cat > "$f" <<'EOF'
coverage_thresholds:
  version: 2
  min_coverage: 90
  timeout: 300
EOF
    printf '%s\n' "$f"
}

# --- usage and preflight --------------------------------------------------

@test "no arguments prints usage and exits 1" {
    run "$(_ye)"
    assert_failure
    assert_equal "$status" 1
    assert_output --partial "usage:"
}

@test "unknown intent prints usage and exits 1" {
    run "$(_ye)" bogus file.yaml
    assert_equal "$status" 1
    assert_output --partial "usage:"
}

@test "mutation as non-root is refused with exit 2" {
    [ "$(id -u)" -eq 0 ] && skip "non-root refusal untestable as root"
    local f; f="$(_empty_fixture)"
    run "$(_ye)" add "$f" exceptions hook=quality
    assert_equal "$status" 2
    assert_output --partial "needs root"
}

@test "missing file is refused with exit 2" {
    run "$(_ye)" get "$TEST_TMPDIR/nope.yaml" anything
    assert_equal "$status" 2
    assert_output --partial "file not found"
}

@test "symlink is refused even for reads" {
    local f; f="$(_q_fixture)"
    ln -s "$f" "$TEST_TMPDIR/link.yaml"
    run "$(_ye)" list "$TEST_TMPDIR/link.yaml"
    assert_equal "$status" 2
    assert_output --partial "refusing symlink"
}

@test "malformed yaml exits 1" {
    local f="$TEST_TMPDIR/broken.yaml"
    printf 'exceptions: [\n' > "$f"
    run "$(_ye)" validate "$f"
    assert_equal "$status" 1
    assert_output --partial "not valid YAML"
}

# --- read-only intents ----------------------------------------------------

@test "list prints the whole file without a key" {
    local f; f="$(_q_fixture)"
    run "$(_ye)" list "$f"
    assert_success
    assert_output --partial "policy_version: 2"
    assert_output --partial "added_by: alice"
}

@test "list KEY prints only that block" {
    local f; f="$(_q_fixture)"
    run "$(_ye)" list "$f" exceptions
    assert_success
    assert_output --partial "hook: quality"
    refute_output --partial "policy_version"
}

@test "get prints a nested scalar by dotted key" {
    local f; f="$(_cov_fixture)"
    run "$(_ye)" get "$f" coverage_thresholds.min_coverage
    assert_success
    assert_output "90"
}

@test "get on a missing key exits 1" {
    local f; f="$(_cov_fixture)"
    run "$(_ye)" get "$f" coverage_thresholds.nope
    assert_equal "$status" 1
    assert_output --partial "key not found"
}

@test "get on a block key exits 2" {
    local f; f="$(_cov_fixture)"
    run "$(_ye)" get "$f" coverage_thresholds
    assert_equal "$status" 2
    assert_output --partial "not a scalar"
}

@test "validate passes a conforming file" {
    local f; f="$(_q_fixture)"
    run "$(_ye)" validate "$f"
    assert_success
    assert_output --partial "ok"
}

@test "validate fails a short reason and string paths" {
    local f="$TEST_TMPDIR/quality_exceptions.yaml"
    cat > "$f" <<'EOF'
exceptions:
  - hook: quality
    added_by: alice
    reason: too short
    paths: src/a.py
EOF
    run "$(_ye)" validate "$f"
    assert_equal "$status" 1
    assert_output --partial "'paths' must be a list with >=1 item"
    assert_output --partial "'reason' needs >= 20 chars"
}

# --- mutation matrix via --dry-run ----------------------------------------

@test "dry-run add prints a diff and leaves the file untouched" {
    local f; f="$(_empty_fixture)"
    local before; before="$(cat "$f")"
    run "$(_ye)" add "$f" exceptions hook=quality added_by=bob \
        "reason=needs a temporary waiver, ticket 42" "paths=[src/b.py]" --dry-run
    assert_success
    assert_output --partial "--- a/"
    assert_output --partial "+  - hook: quality"
    assert_output --partial "+      - src/b.py"
    assert_equal "$(cat "$f")" "$before"
}

@test "dry-run add duplicate exits 4" {
    local f; f="$(_q_fixture)"
    run "$(_ye)" add "$f" exceptions hook=quality added_by=alice \
        "reason=tracked upstream, remove after release" "paths=[src/a.py]" --dry-run
    assert_equal "$status" 4
    assert_output --partial "duplicate entry"
}

@test "dry-run remove prints the dropped lines" {
    local f; f="$(_q_fixture)"
    run "$(_ye)" remove "$f" exceptions hook=quality --dry-run
    assert_success
    assert_output --partial "-  - hook: quality"
    assert_output --partial "+exceptions: []"
}

@test "dry-run remove no-match exits 3, or 0 with --allow-no-match" {
    local f; f="$(_q_fixture)"
    run "$(_ye)" remove "$f" exceptions hook=nobody --dry-run
    assert_equal "$status" 3
    assert_output --partial "no matching entry"
    run "$(_ye)" remove "$f" exceptions hook=nobody --dry-run --allow-no-match
    assert_success
    assert_output --partial "unchanged"
}

@test "dry-run remove on a missing key exits 2" {
    local f; f="$(_q_fixture)"
    run "$(_ye)" remove "$f" nope hook=quality --dry-run
    assert_equal "$status" 2
    assert_output --partial "key not found"
}

@test "dry-run remove on a non-list key exits 2" {
    local f; f="$(_q_fixture)"
    run "$(_ye)" remove "$f" policy_version hook=quality --dry-run
    assert_equal "$status" 2
    assert_output --partial "not a list"
}

@test "dry-run set rewrites a nested scalar with typing" {
    local f; f="$(_cov_fixture)"
    run "$(_ye)" set "$f" coverage_thresholds.min_coverage 95 --dry-run
    assert_success
    assert_output --partial "-  min_coverage: 90"
    assert_output --partial "+  min_coverage: 95"
}

@test "dry-run set --string keeps quotes in the diff" {
    local f="$TEST_TMPDIR/unknown_policy.yaml"
    printf 'settings:\n  level: 9\n' > "$f"
    run "$(_ye)" set "$f" settings.level 95 --string --dry-run
    assert_success
    assert_output --partial "+  level: '95'"
}

@test "dry-run set --string on a numeric schema key exits 1" {
    local f; f="$(_cov_fixture)"
    run "$(_ye)" set "$f" coverage_thresholds.min_coverage 95 --string --dry-run
    assert_equal "$status" 1
    assert_output --partial "must be numeric"
}

@test "dry-run set on a block key exits 2" {
    local f; f="$(_cov_fixture)"
    run "$(_ye)" set "$f" coverage_thresholds 1 --dry-run
    assert_equal "$status" 2
    assert_output --partial "refusing set on block/list key"
}

@test "dry-run set on a missing key exits 1" {
    local f; f="$(_cov_fixture)"
    run "$(_ye)" set "$f" coverage_thresholds.nope 1 --dry-run
    assert_equal "$status" 1
    assert_output --partial "key not found"
}

@test "dry-run set --create inserts an absent leaf under an existing map" {
    local f="$TEST_TMPDIR/unknown_policy.yaml"
    printf 'labels:\n  a: 1\nother: 2\n' > "$f"
    run "$(_ye)" set "$f" labels.b 3 --create --dry-run
    assert_success
    assert_output --partial "+  b: 3"
}

@test "dry-run set --create refuses a missing parent" {
    local f="$TEST_TMPDIR/unknown_policy.yaml"
    printf 'labels:\n  a: 1\n' > "$f"
    run "$(_ye)" set "$f" nope.b 3 --create --dry-run
    assert_equal "$status" 1
    assert_output --partial "parent key not found"
}

@test "bootstrap creates a missing top-level scalar" {
    local f="$TEST_TMPDIR/bootstrap.yaml"
    printf 'version: 1\n' > "$f"
    run "$(_ye)" bootstrap "$f" max_file_bytes 262144 --dry-run
    assert_success
    assert_output --partial "+max_file_bytes: 262144"
}

@test "bootstrap creates a missing empty top-level list via []" {
    local f="$TEST_TMPDIR/bootstrap-list.yaml"
    printf 'version: 1\n' > "$f"
    run "$(_ye)" bootstrap "$f" module_overrides '[]' --dry-run
    assert_success
    assert_output --partial "+module_overrides: []"
}

@test "bootstrap still rejects non-empty sequence values" {
    local f="$TEST_TMPDIR/bootstrap-seq.yaml"
    printf 'version: 1\n' > "$f"
    run "$(_ye)" bootstrap "$f" module_overrides '[a, b]' --dry-run
    assert_equal "$status" 2
    assert_output --partial "parses as YAML sequence"
}

@test "bootstrap rejects an existing key" {
    local f="$TEST_TMPDIR/bootstrap-existing.yaml"
    printf 'version: 1\n' > "$f"
    run "$(_ye)" bootstrap "$f" version 2 --dry-run
    assert_equal "$status" 2
    assert_output --partial "key already exists"
}

@test "add rejects a schema-invalid entry in dry-run" {
    local f; f="$(_empty_fixture)"
    run "$(_ye)" add "$f" exceptions hook=quality added_by=bob \
        reason=short "paths=[src/b.py]" --dry-run
    assert_equal "$status" 1
    assert_output --partial "'reason' needs >= 20 chars"
}

@test "spec grammar: empty and duplicate items rejected with exit 2" {
    local f; f="$(_empty_fixture)"
    run "$(_ye)" add "$f" exceptions "paths=[a,,b]" --dry-run
    assert_equal "$status" 2
    assert_output --partial "empty list item"
    run "$(_ye)" add "$f" exceptions "paths=[a,a]" --dry-run
    assert_equal "$status" 2
    assert_output --partial "duplicate list item"
}

@test "scalar values keep commas literally" {
    local f; f="$(_empty_fixture)"
    run "$(_ye)" add "$f" exceptions hook=quality added_by=bob \
        "reason=waiver for src/a,b.py, ticket 7" "paths=[src/a.py]" --dry-run
    assert_success
    assert_output --partial "+    reason: waiver for src/a,b.py, ticket 7"
    assert_output --partial "+      - src/a.py"
}

@test "dry-run unset removes every wildcard field" {
    local f="$TEST_TMPDIR/hooks.yaml"
    printf 'hooks:\n  - id: one\n    safety: true\n  - id: two\n    safety: false\n' > "$f"
    run "$(_ye)" unset "$f" 'hooks[].safety' --dry-run
    assert_success
    assert_output --partial "-    safety: true"
    assert_output --partial "-    safety: false"
    assert_output --partial "removed 2 fields"
}

@test "dry-run unset supports dotted maps and rejects missing paths" {
    local f="$TEST_TMPDIR/nested.yaml"
    printf 'outer:\n  remove: true\n  keep: 1\n' > "$f"
    run "$(_ye)" unset "$f" outer.remove --dry-run
    assert_success
    assert_output --partial "-  remove: true"
    run "$(_ye)" unset "$f" outer.missing --dry-run
    assert_failure
    assert_output --partial "path not found"
}

@test "wildcard partial failure leaves the original bytes unchanged" {
    local f="$TEST_TMPDIR/partial.yaml"
    printf 'hooks:\n  - id: one\n    safety: true\n  - id: two\n' > "$f"
    local before; before="$(cat "$f")"
    run "$(_ye)" unset "$f" 'hooks[].safety' --dry-run
    assert_failure
    assert_equal "$(cat "$f")" "$before"
}

@test "remove-comment is literal and ignores scalars and similar text" {
    local f="$TEST_TMPDIR/comments.yaml"
    printf '# Retired term\nvalue: Retired term\n  # Retired term\n# Retired terms\n' > "$f"
    run "$(_ye)" remove-comment "$f" 'Retired term' --dry-run
    assert_success
    assert_output --partial "removed 2 comments"
    refute_output --partial "-value: Retired term"
    refute_output --partial "-# Retired terms"
}

@test "remove-comment missing text fails" {
    local f="$TEST_TMPDIR/comments.yaml"
    printf '# present\nvalue: 1\n' > "$f"
    run "$(_ye)" remove-comment "$f" missing --dry-run
    assert_failure
    assert_output --partial "no exact comment matched"
}

@test "delete requires a digest and root" {
    local f="$TEST_TMPDIR/delete.yaml"
    printf 'value: 1\n' > "$f"
    run "$(_ye)" delete "$f"
    assert_failure
    assert_output --partial "usage:"
    [ "$(id -u)" -eq 0 ] && skip "non-root refusal untestable as root"
    run "$(_ye)" delete "$f" --expected-sha256 0000000000000000000000000000000000000000000000000000000000000000
    assert_equal "$status" 2
    assert_output --partial "needs root"
}

@test "new Make mutation targets propagate root-gate failures" {
    [ "$(id -u)" -eq 0 ] && skip "non-root refusal untestable as root"
    run make -C "$GUARD_ROOT" yaml-unset FILE=nope.yaml KEY='hooks[].safety'
    assert_failure
    assert_output --partial "yaml-unset needs root"
    run make -C "$GUARD_ROOT" yaml-remove-comment FILE=nope.yaml VALUE=text
    assert_failure
    assert_output --partial "yaml-remove-comment needs root"
    run make -C "$GUARD_ROOT" yaml-delete FILE=nope.yaml EXPECT_SHA256=00
    assert_failure
    assert_output --partial "yaml-delete needs root"
}
