#!/usr/bin/env bash
# 20-exemption.bats: tests for scripts/exemption.sh and the awk engine
# in scripts/lib/exemption-yaml.sh (SPEC-EXEMPTION-EDIT). Covers the
# REQ-EX-700 matrix: add/remove/set/list over the fleet's YAML shapes
# (empty flow list, list-of-maps with inline flow lists, scalar lists,
# nested dotted scalars), duplicate/no-match exits, schema validation,
# root/symlink preflight, and audit logging.
#
# Root and ownership are faked with per-test stubs: the harness id stub
# already reports uid 0; this suite prepends its own stat stub so the
# root:root preflight passes for sandbox files. chown is a harness no-op
# stub. HOME is redirected into TEST_TMPDIR so the audit log lands in
# the sandbox (REPO_ROOT/config/guard_paths.yaml is read from the real
# repo the script lives in; log_file joins onto $HOME).

load lib/harness

setup() {
    guard_setup
    _make_stubs
    export HOME="$TEST_TMPDIR"
    # shellcheck disable=SC1091
    source "$GUARD_ROOT/scripts/lib/exemption-yaml.sh"
}

teardown() { guard_teardown; }

# Per-test stub dir placed ahead of the harness stubs so `stat -c %U:%G`
# reports root:root while every other stat call passes through.
_make_stubs() {
    EX_STUBS="$TEST_TMPDIR/ex-stubs"
    mkdir -p "$EX_STUBS"
    cat > "$EX_STUBS/stat" <<'EOF'
#!/usr/bin/env bash
# stat stub for 20-exemption: `-c %U:%G` reports root:root so the
# exemption.sh ownership preflight passes for sandbox files; all other
# invocations pass through to the real stat.
for a in "$@"; do
    case "$a" in
        %U:%G*) echo root:root; exit 0 ;;
    esac
done
exec /usr/bin/stat "$@"
EOF
    chmod +x "$EX_STUBS/stat"
    PATH="$EX_STUBS:$PATH"
    export PATH
}

# --- fixtures -------------------------------------------------------------

_q_fixture() {
    # quality_exceptions.yaml shape: empty flow list, or with entries.
    local f="$TEST_TMPDIR/quality_exceptions.yaml"
    cat > "$f" <<'EOF'
# quality gate exemptions
policy_version: 2
exceptions: []
EOF
    printf '%s\n' "$f"
}

_q_fixture_two() {
    local f="$TEST_TMPDIR/quality_exceptions.yaml"
    cat > "$f" <<'EOF'
# quality gate exemptions
policy_version: 2
exceptions:
  - hook: pre-commit
    added_by: alice
    reason: legacy module grandfathered in
    paths: ['src/old.py', 'src/older.py']
  - hook: pre-push
    added_by: bob
    reason: flake tracked in ticket WG-42
    paths: ['tests/flaky/']
# trailing comment must survive
coverage_thresholds:
  unit: 80
EOF
    printf '%s\n' "$f"
}

_scalar_fixture() {
    local f="$TEST_TMPDIR/sensitive_files_exceptions.yaml"
    cat > "$f" <<'EOF'
# allowed sensitive-looking paths
safe_exceptions:
  - docs/examples/keys.md
  - tests/fixtures/fake.pem
EOF
    printf '%s\n' "$f"
}

_nested_fixture() {
    local f="$TEST_TMPDIR/coverage_thresholds.yaml"
    cat > "$f" <<'EOF'
coverage_thresholds:
  unit: 80
  integration: 60
mode: strict
EOF
    printf '%s\n' "$f"
}

# Tab-separated specfile builders (F/L/S per engine contract).
_spec_field() { printf 'F\t%s\t%s\n' "$1" "$2" >> "$SPECFILE"; }
_spec_list()  { printf 'L\t%s\t%s\n' "$1" "$2" >> "$SPECFILE"; }
_spec_item()  { printf 'S\t\t%s\n' "$1" >> "$SPECFILE"; }

# --- engine: add ----------------------------------------------------------

@test "engine add: converts empty flow list key: [] into block list" {
    local f; f="$(_q_fixture)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_field hook pre-commit
    _spec_field added_by carol
    _spec_field reason "generated fixtures are not lintable"
    _spec_list  paths "gen/,vendor/"
    run ey_run add "$f" exceptions "$SPECFILE"
    assert_success
    assert_output --partial "exceptions:"
    assert_output --partial "  - hook: pre-commit"
    assert_output --partial "    paths:"
    assert_output --partial "      - gen/"
    assert_output --partial "      - vendor/"
    # header comment and unrelated key preserved
    assert_output --partial "# quality gate exemptions"
    assert_output --partial "policy_version: 2"
}

@test "engine add: appends to existing block list of maps" {
    local f; f="$(_q_fixture_two)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_field hook pre-commit
    _spec_field added_by carol
    _spec_field reason "third exemption appended by test"
    _spec_list  paths "src/new.py"
    run ey_run add "$f" exceptions "$SPECFILE"
    assert_success
    assert_output --partial "added_by: bob"
    assert_output --partial "added_by: carol"
    # trailing comment + unrelated block preserved verbatim
    assert_output --partial "# trailing comment must survive"
    assert_output --partial "  unit: 80"
}

@test "engine add: duplicate entry is rejected with rc 4" {
    local f; f="$(_q_fixture_two)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_field hook pre-commit
    _spec_field added_by alice
    _spec_field reason "legacy module grandfathered in"
    _spec_list  paths "src/old.py,src/older.py"
    run ey_run add "$f" exceptions "$SPECFILE"
    [ "$status" -eq 4 ]
}

@test "engine add: list-field match is set-wise, not order-wise" {
    local f; f="$(_q_fixture_two)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_field hook pre-commit
    _spec_field added_by alice
    _spec_field reason "legacy module grandfathered in"
    _spec_list  paths "src/older.py,src/old.py"
    run ey_run add "$f" exceptions "$SPECFILE"
    [ "$status" -eq 4 ]
}

@test "engine add: missing list key exits rc 2" {
    local f; f="$(_q_fixture)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_field hook pre-commit
    run ey_run add "$f" nonexistent_key "$SPECFILE"
    [ "$status" -eq 2 ]
}

# --- engine: remove -------------------------------------------------------

@test "engine remove: deletes the entry matching all fields" {
    local f; f="$(_q_fixture_two)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_field added_by bob
    run ey_run remove "$f" exceptions "$SPECFILE"
    assert_success
    assert_output --partial "added_by: alice"
    if printf '%s' "$output" | grep -Fq "added_by: bob"; then
        echo "bob entry should be gone" >&2
        return 1
    fi
    assert_output --partial "# trailing comment must survive"
}

@test "engine remove: no match exits rc 3 and prints nothing" {
    local f; f="$(_q_fixture_two)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_field added_by nobody
    run ey_run remove "$f" exceptions "$SPECFILE"
    [ "$status" -eq 3 ]
    [ -z "$output" ]
}

@test "engine remove: removing the last entry restores key: []" {
    local f; f="$(_q_fixture_two)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_field added_by alice
    _spec_field added_by bob
    # two remove passes in one specfile call is not supported; remove by
    # hook fields one at a time via the file twice
    : > "$SPECFILE"
    _spec_field hook pre-commit
    local once="$TEST_TMPDIR/once.yaml"
    ey_run remove "$f" exceptions "$SPECFILE" > "$once"
    : > "$SPECFILE"
    _spec_field hook pre-push
    run ey_run remove "$once" exceptions "$SPECFILE"
    assert_success
    assert_output --partial "exceptions: []"
    assert_output --partial "coverage_thresholds:"
}

# --- engine: scalar lists -------------------------------------------------

@test "engine add: bare value appends to scalar list" {
    local f; f="$(_scalar_fixture)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_item "scripts/tmp/gen.sh"
    run ey_run add "$f" safe_exceptions "$SPECFILE"
    assert_success
    assert_output --partial "  - scripts/tmp/gen.sh"
    assert_output --partial "  - docs/examples/keys.md"
}

@test "engine remove: bare value deletes scalar list item" {
    local f; f="$(_scalar_fixture)"
    SPECFILE="$TEST_TMPDIR/spec"
    _spec_item "docs/examples/keys.md"
    run ey_run remove "$f" safe_exceptions "$SPECFILE"
    assert_success
    if printf '%s' "$output" | grep -Fq "docs/examples/keys.md"; then
        echo "removed item still present" >&2
        return 1
    fi
    assert_output --partial "  - tests/fixtures/fake.pem"
}

# --- engine: set / get ----------------------------------------------------

@test "engine set: rewrites a nested dotted scalar" {
    local f; f="$(_nested_fixture)"
    run ey_run set "$f" coverage_thresholds.unit "" 85
    assert_success
    assert_output --partial "  unit: 85"
    assert_output --partial "  integration: 60"
    assert_output --partial "mode: strict"
}

@test "engine set: block/list key is refused with rc 2" {
    local f; f="$(_nested_fixture)"
    run ey_run set "$f" coverage_thresholds "" 85
    [ "$status" -eq 2 ]
}

@test "engine set: unknown scalar key fails rc 1" {
    local f; f="$(_nested_fixture)"
    run ey_run set "$f" coverage_thresholds.e2e "" 85
    [ "$status" -eq 1 ]
}

@test "engine get: reads back a nested scalar verbatim" {
    local f; f="$(_nested_fixture)"
    run ey_run get "$f" coverage_thresholds.unit
    assert_success
    assert_output "80"
}

# --- CLI: preflight -------------------------------------------------------

@test "cli: add as non-root exits rc 2" {
    local f; f="$(_q_fixture)"
    local noroot="$TEST_TMPDIR/noroot-stubs"
    mkdir -p "$noroot"
    cat > "$noroot/id" <<'EOF'
#!/usr/bin/env bash
# id stub override for the non-root test: uid 1000.
if [ "${1:-}" = "-u" ]; then echo 1000; else echo agent; fi
exit 0
EOF
    chmod +x "$noroot/id"
    run env PATH="$noroot:$PATH" \
        "$GUARD_ROOT/scripts/exemption.sh" add "$f" exceptions \
        hook=pre-commit added_by=x reason="twenty chars minimum ok" paths=a
    [ "$status" -eq 2 ]
    assert_output --partial "needs root"
}

@test "cli: add refuses a symlink with rc 2" {
    local f; f="$(_q_fixture)"
    local link="$TEST_TMPDIR/link.yaml"
    ln -s "$f" "$link"
    run "$GUARD_ROOT/scripts/exemption.sh" add "$link" exceptions \
        hook=pre-commit added_by=x reason="twenty chars minimum ok" paths=a
    [ "$status" -eq 2 ]
    assert_output --partial "symlink"
}

@test "cli: add refuses a missing file with rc 2" {
    run "$GUARD_ROOT/scripts/exemption.sh" add "$TEST_TMPDIR/nope.yaml" exceptions \
        hook=pre-commit added_by=x reason="twenty chars minimum ok" paths=a
    [ "$status" -eq 2 ]
    assert_output --partial "not found"
}

@test "cli: usage errors exit rc 1" {
    run "$GUARD_ROOT/scripts/exemption.sh" add
    [ "$status" -eq 1 ]
    run "$GUARD_ROOT/scripts/exemption.sh" bogus-intent
    [ "$status" -eq 1 ]
}

# --- CLI: happy paths + validation ----------------------------------------

@test "cli: add valid quality exemption succeeds and audits" {
    local f; f="$(_q_fixture)"
    run "$GUARD_ROOT/scripts/exemption.sh" add "$f" exceptions \
        hook=pre-commit added_by=carol \
        reason="generated fixtures are not lintable" paths=gen/,vendor/
    assert_success
    assert_output --partial "added entry"
    grep -Fq "  - hook: pre-commit" "$f"
    grep -Fq "      - gen/" "$f"
    grep -Fq "      - vendor/" "$f"
    grep -q "exemption add" "$HOME/.workspace-guard.log"
    grep -q "file=$f" "$HOME/.workspace-guard.log"
}

@test "cli: single path value is normalized to a one-element list" {
    local f; f="$(_q_fixture)"
    run "$GUARD_ROOT/scripts/exemption.sh" add "$f" exceptions \
        hook=pre-commit added_by=carol \
        reason="one path only but still a list" paths=gen/
    assert_success
    grep -Fq "    paths:" "$f"
    grep -Fq "      - gen/" "$f"
}

@test "cli: add quality exemption with short reason fails rc 1" {
    local f; f="$(_q_fixture)"
    run "$GUARD_ROOT/scripts/exemption.sh" add "$f" exceptions \
        hook=pre-commit added_by=carol reason="too short" paths=gen/,vendor/
    [ "$status" -eq 1 ]
    assert_output --partial "reason"
    # file untouched
    grep -Fq "exceptions: []" "$f"
}

@test "cli: add quality exemption without paths fails rc 1" {
    local f; f="$(_q_fixture)"
    run "$GUARD_ROOT/scripts/exemption.sh" add "$f" exceptions \
        hook=pre-commit added_by=carol reason="twenty chars minimum ok"
    [ "$status" -eq 1 ]
    assert_output --partial "paths"
}

@test "cli: duplicate add fails rc 1 and leaves file unchanged" {
    local f; f="$(_q_fixture_two)"
    cp "$f" "$TEST_TMPDIR/before.yaml"
    run "$GUARD_ROOT/scripts/exemption.sh" add "$f" exceptions \
        hook=pre-commit added_by=alice \
        reason="legacy module grandfathered in" paths=src/old.py,src/older.py
    [ "$status" -eq 1 ]
    assert_output --partial "duplicate"
    run diff "$f" "$TEST_TMPDIR/before.yaml"
    assert_success
}

@test "cli: remove matching entry succeeds" {
    local f; f="$(_q_fixture_two)"
    run "$GUARD_ROOT/scripts/exemption.sh" remove "$f" exceptions added_by=bob
    assert_success
    assert_output --partial "removed entry"
    if grep -Fq "added_by: bob" "$f"; then
        echo "bob entry should be gone" >&2
        return 1
    fi
    grep -Fq "added_by: alice" "$f"
}

@test "cli: remove with no match exits 0 with an unchanged message" {
    local f; f="$(_q_fixture_two)"
    cp "$f" "$TEST_TMPDIR/before.yaml"
    run "$GUARD_ROOT/scripts/exemption.sh" remove "$f" exceptions added_by=nobody
    assert_success
    assert_output --partial "no matching entry"
    run diff "$f" "$TEST_TMPDIR/before.yaml"
    assert_success
}

@test "cli: set nested scalar succeeds and verifies" {
    local f; f="$(_nested_fixture)"
    run "$GUARD_ROOT/scripts/exemption.sh" set "$f" coverage_thresholds.unit 90
    assert_success
    grep -Fq "  unit: 90" "$f"
    grep -q "exemption set" "$HOME/.workspace-guard.log"
}

@test "cli: set on a block key fails rc 1" {
    local f; f="$(_nested_fixture)"
    run "$GUARD_ROOT/scripts/exemption.sh" set "$f" coverage_thresholds 90
    [ "$status" -eq 1 ]
}

@test "cli: list prints the whole file without a key" {
    local f; f="$(_nested_fixture)"
    run "$GUARD_ROOT/scripts/exemption.sh" list "$f"
    assert_success
    assert_output --partial "coverage_thresholds:"
    assert_output --partial "mode: strict"
}

@test "cli: list with a key prints only that list block" {
    local f; f="$(_q_fixture_two)"
    run "$GUARD_ROOT/scripts/exemption.sh" list "$f" exceptions
    assert_success
    assert_output --partial "added_by: alice"
    assert_output --partial "added_by: bob"
    if printf '%s' "$output" | grep -Fq "coverage_thresholds"; then
        echo "block listing leaked sibling key" >&2
        return 1
    fi
}

@test "cli: list is allowed for non-root callers" {
    local f; f="$(_nested_fixture)"
    local noroot="$TEST_TMPDIR/noroot-stubs"
    mkdir -p "$noroot"
    cat > "$noroot/id" <<'EOF'
#!/usr/bin/env bash
# id stub override for the non-root list test: uid 1000.
if [ "${1:-}" = "-u" ]; then echo 1000; else echo agent; fi
exit 0
EOF
    chmod +x "$noroot/id"
    run env PATH="$noroot:$PATH" "$GUARD_ROOT/scripts/exemption.sh" list "$f"
    assert_success
}
