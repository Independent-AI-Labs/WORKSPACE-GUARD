#!/usr/bin/env bash
# 15-guard-host-exec.bats: host-exec deployment class helpers.

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

@test "guard-host-exec: host profile resolves vm-ws to host-exec" {
    local ci_root profiles
    ci_root="$(cd "$GUARD_ROOT/../CI" && pwd)"
    profiles="$GUARD_ROOT/config/guard-host-profiles.yaml"
    run bash -c "
        _guard_dir='$GUARD_ROOT'
        source \"$ci_root/lib/guard-host-exec.sh\"
        guard_host_profile_class vm-ws
    "
    [ "$status" -eq 0 ]
    [ "$output" = "host-exec" ]
}

@test "guard-host-exec: getcap parser handles space-separated format" {
    run bash -c 'line="/usr/bin/git cap_chown,cap_setpcap=ep"; caps="${line#*cap_}"; printf "cap_%s" "$caps"'
    [ "$status" -eq 0 ]
    [ "$output" = "cap_chown,cap_setpcap=ep" ]
}

@test "guard-host-exec: getcap parser handles equals-separated format" {
    run bash -c 'line="/usr/bin/git = cap_setpcap,cap_chown=ep"; caps="${line#*cap_}"; printf "cap_%s" "$caps"'
    [ "$status" -eq 0 ]
    [ "$output" = "cap_setpcap,cap_chown=ep" ]
}

@test "guard-host-exec: normalized cap sets match regardless of order" {
    local ci_root
    ci_root="$(cd "$GUARD_ROOT/../CI" && pwd)"
    run bash -c "
        source \"$ci_root/lib/guard-drift.sh\"
        a=\$(guard_file_cap_normalize 'cap_chown,cap_setpcap=ep')
        b=\$(guard_file_cap_normalize 'cap_setpcap,cap_chown=ep')
        [[ \"\$a\" == \"\$b\" ]]
    "
    [ "$status" -eq 0 ]
}

@test "guard-host-exec: file cap string is five-cap ep set" {
    local ci_root
    ci_root="$(cd "$GUARD_ROOT/../CI" && pwd)"
    run bash -c "
        source \"$ci_root/lib/guard-drift.sh\"
        guard_workload_file_cap_string
    "
    [ "$status" -eq 0 ]
    [ "$output" = "cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid=ep" ]
}