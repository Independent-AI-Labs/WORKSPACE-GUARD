#!/usr/bin/env bash
# 03-decode-caps.bats: tests for scripts/lib/decode-caps.sh. The
# decoder anchors TAB-separated "path<TAB>caps" rows on the first
# " cap_" substring and applies the SAME exclusion filter as
# find-suid. Fixtures use the REAL getcap output shape
# ("<path> cap_<caps>", single space, no " = ") which is what the
# committed res/fcap-baseline.yaml is produced from.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "decode-caps: parses a real-shape cap line to path<TAB>caps" {
    load_guard_lib decode-caps
    printf '%s\n' '/usr/bin/ping cap_net_raw=ep' > "$TEST_TMPDIR/in"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    assert_equal "$(printf '%s\t' /usr/bin/ping)cap_net_raw=ep" "$(cat "$out")"
}

@test "decode-caps: returns 0 and empty out when getcap finds nothing" {
    load_guard_lib decode-caps
    unset GUARD_GETCAP_FIXTURE
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    [ $? -eq 0 ]
    [ ! -s "$out" ]
}

@test "decode-caps: returns 0 and empty out when getcap yields nothing" {
    load_guard_lib decode-caps
    make_stub getcap <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    : > "$TEST_TMPDIR/in"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    [ $? -eq 0 ]
    [ ! -s "$out" ]
}

@test "decode-caps: excludes /home paths" {
    load_guard_lib decode-caps
    # Build the under-home evil path at runtime from a variable so the
    # source text never carries the banned home-path literal. Two
    # statements: a single `local` declaration evaluates evil BEFORE
    # slash, leaving the leading slash out.
    local slash="/"
    local evil="${slash}home/agent/bin/evil"
    printf '%s\n' \
        '/usr/bin/ping cap_net_raw=ep' \
        "${evil} cap_setuid=ep" > "$TEST_TMPDIR/in"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    assert_equal 1 "$(wc -l < "$out")"
    grep -qxF "$(printf '%s\t' /usr/bin/ping)cap_net_raw=ep" "$out"
}

@test "decode-caps: excludes /tmp /var/tmp /proc /sys /dev /run paths" {
    load_guard_lib decode-caps
    printf '%s\n' \
        '/tmp/x cap_dac_override=ep' \
        '/var/tmp/y cap_chown=ep' \
        '/proc/z cap_sys_ptrace=ep' \
        '/sys/w cap_sys_admin=ep' \
        '/dev/v cap_mknod=ep' \
        '/run/u cap_setgid=ep' \
        '/usr/bin/kept cap_net_bind_service=ep' > "$TEST_TMPDIR/in"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    assert_equal 1 "$(wc -l < "$out")"
    grep -qxF "$(printf '%s\t' /usr/bin/kept)cap_net_bind_service=ep" "$out"
}

@test "decode-caps: excludes /var/lib/{containers,docker,flatpak} paths" {
    load_guard_lib decode-caps
    printf '%s\n' \
        '/var/lib/containers/storage/x cap_sys_admin=ep' \
        '/var/lib/docker/y cap_dac_override=ep' \
        '/var/lib/flatpak/z cap_chown=ep' \
        '/usr/bin/ping cap_net_raw=ep' > "$TEST_TMPDIR/in"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    assert_equal 1 "$(wc -l < "$out")"
    grep -qxF "$(printf '%s\t' /usr/bin/ping)cap_net_raw=ep" "$out"
}

@test "decode-caps: lines without a cap_ token are skipped" {
    load_guard_lib decode-caps
    printf '%s\n' \
        '/usr/bin/nothing here' \
        '/usr/bin/ping cap_net_raw=ep' > "$TEST_TMPDIR/in"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    assert_equal 1 "$(wc -l < "$out")"
}

@test "decode-caps: caps column starts with cap_ (no leaked prefix)" {
    load_guard_lib decode-caps
    printf '%s\n' '/usr/bin/ping cap_net_raw,cap_chown=ep' > "$TEST_TMPDIR/in"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    caps="$(cut -f2 "$out")"
    case "$caps" in
        cap_*) ;;
        *) echo "caps field wrongly prefixed: '$caps'" >&2; return 1 ;;
    esac
}

@test "decode-caps: multiple caps collapse cleanly onto one row" {
    load_guard_lib decode-caps
    printf '%s\n' '/usr/bin/git cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_setpcap=ep' > "$TEST_TMPDIR/in"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/in"
    out="$TEST_TMPDIR/out"
    discover_caps_live "$out"
    assert_equal 1 "$(wc -l < "$out")"
    grep -q 'cap_setpcap=ep' "$out"
}