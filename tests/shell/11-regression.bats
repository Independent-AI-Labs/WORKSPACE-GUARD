#!/usr/bin/env bash
# 11-regression.bats: regression tests for previously fixed bugs.
# Each test documents a bug that was found and fixed, so a future
# regression is caught immediately. The bugs fixed were:
#   1. trap-shadow: per-step EXIT trap replacement leaked temp files
#      on mid-script abort (sync-gtfobins, suid-drift-check).
#   2. suid-drift-check section 4d: checked ALL baselined SUID paths
#      for .real existence, not just contained: true entries.
#   3. install-lock-runtime: staged guard AFTER dpkg-divert, leaving
#      a copy window where <path> was empty.
#   4. install-lock-runtime: per-name EXIT trap instead of single
#      register_temp + cleanup_temps.
#   5. config/binary-lock.yaml: obsolete 13-binary hand-curated file
#      superseded by generated res/binary-lock.yaml.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

# --- Regression 1: trap-shadow (single EXIT trap) ---

@test "regression: sync-gtfobins uses single EXIT trap (not per-step)" {
    local f="$GUARD_ROOT/scripts/sync-gtfobins"
    [ -f "$f" ]
    # Must have exactly one `trap cleanup_temps EXIT`.
    local n
    n="$(rg -c 'trap cleanup_temps EXIT' "$f" 2>"$DEVNULL" || echo 0)"
    [ "$n" -eq 1 ]
}

@test "regression: suid-drift-check uses single EXIT trap" {
    local f="$GUARD_ROOT/scripts/suid-drift-check"
    [ -f "$f" ]
    local n
    n="$(rg -c 'trap cleanup_temps EXIT' "$f" 2>"$DEVNULL" || echo 0)"
    [ "$n" -eq 1 ]
}

@test "regression: install-lock-runtime uses single EXIT trap" {
    local f="$GUARD_ROOT/scripts/install-lock-runtime"
    [ -f "$f" ]
    local n
    n="$(rg -c 'trap cleanup_temps EXIT' "$f" 2>"$DEVNULL" || echo 0)"
    [ "$n" -eq 1 ]
}

@test "regression: all three scripts define register_temp + cleanup_temps" {
    local scripts=(
        "$GUARD_ROOT/scripts/sync-gtfobins"
        "$GUARD_ROOT/scripts/suid-drift-check"
        "$GUARD_ROOT/scripts/install-lock-runtime"
    )
    local f
    for f in "${scripts[@]}"; do
        [ -f "$f" ] || continue
        grep -q 'register_temp()' "$f"
        grep -q 'cleanup_temps()' "$f"
    done
}

# --- Regression 2: suid-drift-check section 4d contained gating ---

@test "regression: suid-drift-check 4d gates on contained: true only" {
    local f="$GUARD_ROOT/scripts/suid-drift-check"
    [ -f "$f" ]
    # Section 4d should parse binary-lock.yaml for contained: true
    # entries, NOT iterate all known SUID paths.
    grep -q 'contained: true' "$f"
    grep -q 'binary-lock.yaml' "$f"
    # Should NOT use known_suid_tmp for the .real check.
    ! rg -q 'known_suid_tmp.*\.real' "$f" 2>"$DEVNULL" \
        || { echo "4d still iterates known_suid for .real" >&2; return 1; }
}

# --- Regression 3: install-lock-runtime stages guard before divert ---

@test "regression: install-lock-runtime stages guard_new BEFORE dpkg-divert" {
    local f="$GUARD_ROOT/scripts/install-lock-runtime"
    [ -f "$f" ]
    # The staging step (cp guard to .guard_new) must appear in the
    # script BEFORE the dpkg-divert --add call.
    local stage_line divert_line
    stage_line="$(rg -n 'guard_new' "$f" 2>"$DEVNULL" | head -1 | cut -d: -f1)"
    divert_line="$(rg -n 'dpkg-divert --add' "$f" 2>"$DEVNULL" | head -1 | cut -d: -f1)"
    [ -n "$stage_line" ] && [ -n "$divert_line" ]
    [ "$stage_line" -lt "$divert_line" ]
}

@test "regression: install-lock-runtime mv guard_new fills the path" {
    local f="$GUARD_ROOT/scripts/install-lock-runtime"
    [ -f "$f" ]
    # After dpkg-divert, there must be an mv guard_new -> $path.
    rg -q 'mv "\$guard_new" "\$path"' "$f" 2>"$DEVNULL" \
        || rg -q 'mv.*guard_new.*path' "$f" 2>"$DEVNULL"
}

# --- Regression 4: install-lock-runtime uses register_temp (not per-name trap) ---

@test "regression: install-lock-runtime does not use per-name EXIT trap" {
    local f="$GUARD_ROOT/scripts/install-lock-runtime"
    [ -f "$f" ]
    # The old buggy pattern was `trap 'rm -f ...' EXIT` inside the
    # per-binary loop. The fix uses register_temp + a single cleanup.
    ! rg -q 'trap.*EXIT.*\$path' "$f" 2>"$DEVNULL" \
        || { echo "per-name trap still present" >&2; return 1; }
}

# --- Regression 5: config/binary-lock.yaml removed ---

@test "regression: config/binary-lock.yaml no longer exists" {
    [ ! -f "$GUARD_ROOT/config/binary-lock.yaml" ]
}

@test "regression: res/binary-lock.yaml exists as generated lock" {
    [ -f "$GUARD_ROOT/res/binary-lock.yaml" ]
}

# --- Regression 6: install-lock-runtime uses res/binary-lock.yaml ---

@test "regression: install-lock-runtime CONFIG points at res/binary-lock.yaml" {
    local f="$GUARD_ROOT/scripts/install-lock-runtime"
    [ -f "$f" ]
    rg -q 'CONFIG=.*res/binary-lock.yaml' "$f" 2>"$DEVNULL"
}

# --- Regression 7: dpkg-divert stub performs --rename ---

@test "regression: dpkg-divert stub performs rename on --add --rename" {
    local stub="$GUARD_ROOT/tests/shell/stubs/dpkg-divert"
    [ -f "$stub" ]
    rg -q '\-\-rename' "$stub" 2>"$DEVNULL"
    rg -q 'mv.*\$path.*distrib' "$stub" 2>"$DEVNULL" \
        || rg -q 'mv.*path.*dest' "$stub" 2>"$DEVNULL"
}

# --- Regression 8: banned words banned from new bats files ---

@test "regression: no literal home-dir path in tests/shell/" {
    # The banned-words checker rejects literal HOMEPATH patterns in
    # tracked files. Search for the literal without embedding it in
    # this file's own source text.
    local needle
    needle="$(printf '/%s/' 'home')"
    ! rg -qF "$needle" "$GUARD_ROOT/tests/shell/" 2>"$DEVNULL" \
        || { echo "found literal home-dir path in tests" >&2; return 1; }
}