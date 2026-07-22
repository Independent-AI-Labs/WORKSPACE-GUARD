#!/usr/bin/env bash
# 08-drift-check.bats: tests for scripts/suid-drift-check. Compares
# live SUID/CAP surface against committed res/ baselines and classifies
# drift. Uses stubs for find/getcap and writes controlled baseline
# fixtures so the drift logic can be exercised deterministically.

load lib/harness

setup()    { guard_setup; load_fake_repo; }
teardown() { guard_teardown; }

# Build a fake repo with baselines + drift-check script. The live
# SUID/CAP surface is controlled via GUARD_FIND_FIXTURE and
# GUARD_GETCAP_FIXTURE. Sets FAKE_REPO and DRIFT.
_setup_drift() {
    FAKE_REPO="$(make_fake_repo)"
    copy_real_scripts "$FAKE_REPO"
    export DEVNULL="/dev/null"
}

# Write a minimal suid-baseline.yaml with the given paths. Each entry
# defaults to contained=false, gtfobins=false unless overridden.
_write_suid_baseline() {
    local dir="$1"; shift
    local p extra
    mkdir -p "$dir/res"
    {
        echo "# stub suid-baseline"
        echo "suid_binaries:"
        for p in "$@"; do
            local bn gtf="false" gtftags="[]"
            bn="$(basename "$p")"
            echo "  - path: \"$p\""
            echo "    owner: \"root\""
            echo "    group: \"root\""
            echo "    mode: \"4755\""
            echo "    sha256: \"stub\""
            echo "    gtfobins: $gtf"
            echo "    gtfobins_tags: $gtftags"
            echo "    konstruktoid: false"
            echo "    contained: false"
        done
    } > "$dir/res/suid-baseline.yaml"
}

# Write a suid-baseline with a gtfobins=true entry for the first path.
_write_suid_baseline_gtf() {
    local dir="$1"; shift
    local p="$2"
    mkdir -p "$dir/res"
    {
        echo "# stub suid-baseline"
        echo "suid_binaries:"
        for entry in "$@"; do
            local path="${entry%%:*}" gtf="${entry#*:}"
            echo "  - path: \"$path\""
            echo "    owner: \"root\""
            echo "    group: \"root\""
            echo "    mode: \"4755\""
            echo "    sha256: \"stub\""
            echo "    gtfobins: $gtf"
            echo "    gtfobins_tags: []"
            echo "    konstruktoid: false"
            echo "    contained: false"
        done
    } > "$dir/res/suid-baseline.yaml"
}

# Write a minimal fcap-baseline.yaml.
_write_fcap_baseline() {
    local dir="$1"; shift
    mkdir -p "$dir/res"
    {
        echo "# stub fcap-baseline"
        echo "file_capabilities:"
        local line
        for line in "$@"; do
            local path="${line%%\t*}" caps="${line#*\t}"
            echo "  - path: \"$path\""
            echo "    caps: \"$caps\""
            echo "    sha256: \"stub\""
            echo "    recommended: \"strip\""
            echo "    allowed: \"\""
            echo "    strip: []"
        done
    } > "$dir/res/fcap-baseline.yaml"
}

_run_drift() { run bash "$FAKE_REPO/scripts/suid-drift-check" "$@"; }

@test "drift-check: --help prints usage and exits 0" {
    _setup_drift
    _run_drift --help
    assert_success
    assert_output --partial "Usage:"
}

@test "drift-check: unknown arg exits 2" {
    _setup_drift
    _run_drift --bogus
    assert_failure
    [ "$status" -eq 2 ]
}

@test "drift-check: exits 2 when suid-baseline missing" {
    _setup_drift
    # Only fcap-baseline exists.
    mkdir -p "$FAKE_REPO/res"
    _write_fcap_baseline "$FAKE_REPO"
    _run_drift
    assert_failure
    [ "$status" -eq 2 ]
    assert_output --partial "baseline missing"
}

@test "drift-check: exits 2 when fcap-baseline missing" {
    _setup_drift
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo"
    _run_drift
    assert_failure
    [ "$status" -eq 2 ]
    assert_output --partial "baseline missing"
}

@test "drift-check: no drift when live surface matches baseline" {
    _setup_drift
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo" "/usr/bin/passwd"
    _write_fcap_baseline "$FAKE_REPO"
    printf '%s\n' /usr/bin/sudo /usr/bin/passwd > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    unset GUARD_GETCAP_FIXTURE
    _run_drift
    assert_success
    [ "$status" -eq 0 ]
    assert_output --partial "0 critical"
}

@test "drift-check: new SUID not in baseline -> WARNING" {
    _setup_drift
    _write_suid_baseline_gtf "$FAKE_REPO" "/usr/bin/sudo:true"
    _write_fcap_baseline "$FAKE_REPO"
    # Live has sudo (baseline) + a NEW SUID (passwd) not in baseline.
    # gtfobins_for_path can only check baselined paths, so a genuinely
    # new SUID is always WARNING (needs manual review for GTFOBins status).
    printf '%s\n' /usr/bin/sudo /usr/bin/passwd > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    unset GUARD_GETCAP_FIXTURE
    _run_drift
    assert_success
    assert_output --partial "WARNING"
    assert_output --partial "new SUID"
}

@test "drift-check: removed non-gtfobins SUID -> WARNING (exit 0)" {
    _setup_drift
    _write_suid_baseline_gtf "$FAKE_REPO" "/usr/bin/sudo:true" "/usr/bin/passwd:false"
    _write_fcap_baseline "$FAKE_REPO"
    # Live has only sudo; passwd is gone from the live surface -> removed.
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    unset GUARD_GETCAP_FIXTURE
    _run_drift
    assert_success
    assert_output --partial "WARNING"
    assert_output --partial "removed SUID"
}

@test "drift-check: removed SUID -> WARNING" {
    _setup_drift
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo" "/usr/bin/passwd"
    _write_fcap_baseline "$FAKE_REPO"
    # Live has only sudo (passwd is removed from the live surface).
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    unset GUARD_GETCAP_FIXTURE
    _run_drift
    assert_success
    assert_output --partial "removed SUID"
}

@test "drift-check: --quiet suppresses WARNING lines" {
    _setup_drift
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo" "/usr/bin/passwd"
    _write_fcap_baseline "$FAKE_REPO"
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    unset GUARD_GETCAP_FIXTURE
    _run_drift --quiet
    assert_success
    refute_output --partial "WARNING:  removed SUID"
}

@test "drift-check: new cap on agent-accessible path -> CRITICAL" {
    _setup_drift
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo"
    _write_fcap_baseline "$FAKE_REPO"
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    # New cap on /usr/bin/evil (agent-accessible prefix).
    printf '%s\n' '/usr/bin/evil cap_setuid=ep' > "$TEST_TMPDIR/caps.lst"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/caps.lst"
    _run_drift
    assert_failure
    [ "$status" -eq 1 ]
    assert_output --partial "CRITICAL"
    assert_output --partial "new file capability"
}

@test "drift-check: new cap on non-agent path -> WARNING" {
    _setup_drift
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo"
    _write_fcap_baseline "$FAKE_REPO"
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    # New cap on /opt/bin/evil: not agent-accessible (no CRITICAL) and
    # NOT excluded by the cap discovery filter (which skips /tmp, /var,
    # /proc, /sys, /dev, /run, and container paths).
    printf '%s\n' '/opt/bin/evil cap_setuid=ep' > "$TEST_TMPDIR/caps.lst"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/caps.lst"
    _run_drift
    assert_success
    assert_output --partial "new file capability"
    assert_output --partial "WARNING"
}

@test "drift-check: new cap under /usr/lib -> CRITICAL (M2)" {
    _setup_drift
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo"
    _write_fcap_baseline "$FAKE_REPO"
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    # snap-confine-style path: capability-bearing helpers live under
    # /usr/lib and are just as reachable by the agent as /usr/bin caps.
    printf '%s\n' '/usr/lib/snapd/evil-helper cap_sys_admin=ep' > "$TEST_TMPDIR/caps.lst"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/caps.lst"
    _run_drift
    assert_failure
    [ "$status" -eq 1 ]
    assert_output --partial "CRITICAL"
    assert_output --partial "new file capability"
}

@test "drift-check: writes drift-report.yaml with summary" {
    _setup_drift
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo"
    _write_fcap_baseline "$FAKE_REPO"
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    unset GUARD_GETCAP_FIXTURE
    _run_drift
    assert_success
    [ -f "$WORKSPACE_BINARY_GUARD_STATE_DIR/drift-report.yaml" ]
    grep -q '^summary:' "$WORKSPACE_BINARY_GUARD_STATE_DIR/drift-report.yaml"
    grep -q 'critical: 0' "$WORKSPACE_BINARY_GUARD_STATE_DIR/drift-report.yaml"
}

@test "drift-check: contained binary with no .real -> CRITICAL" {
    _setup_drift
    # Write a binary-lock.yaml with contained: true for a path that
    # has no .real file.
    mkdir -p "$FAKE_REPO/res"
    _write_suid_baseline "$FAKE_REPO" "/usr/bin/sudo"
    _write_fcap_baseline "$FAKE_REPO"
    cat >> "$FAKE_REPO/res/binary-lock.yaml" <<EOF
version: 1
binaries:
  - name: "sudo"
    path: "$TEST_TMPDIR/bin/sudo"
    contained: true
    policy: deny-non-root
    allow_subcommands: []
    allow_self_username: false
    env_sanitise: ["LD_PRELOAD"]
    reject_patterns: []
EOF
    mkdir -p "$TEST_TMPDIR/bin"
    touch "$TEST_TMPDIR/bin/sudo"
    # Live SUID matches baseline, no .real file exists.
    printf '%s\n' /usr/bin/sudo > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"
    unset GUARD_GETCAP_FIXTURE
    _run_drift
    # The contained: true binary has no .real -> CRITICAL.
    assert_failure
    assert_output --partial "CRITICAL"
    assert_output --partial "no"
}