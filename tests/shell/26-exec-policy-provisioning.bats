#!/usr/bin/env bash
# 26-exec-policy-provisioning.bats: exclusive-execution-posture provisioning
# state machine (REQ-EXEC-170 series). Fixture-based: WEP_ROOT redirects all
# absolute paths, so the suite runs read-only without root or a kernel.

load lib/harness

setup()    { guard_setup; _wep_build_fixture; }
teardown() { guard_teardown; }

WEP="$GUARD_ROOT/scripts/exec-policy"
WEP_GATE="$GUARD_ROOT/scripts/exec-policy-session-gate"

_wep_build_fixture() {
    WEP_ROOT="$TEST_TMPDIR/root"
    export WEP_ROOT
    mkdir -p \
        "$WEP_ROOT/etc/workspace-guard" \
        "$WEP_ROOT/etc/apparmor.d" \
        "$WEP_ROOT/etc/systemd/system/workspace-agent@.service.d" \
        "$WEP_ROOT/usr/local/bin" \
        "$WEP_ROOT/usr/local/lib/workspace-guard" \
        "$WEP_ROOT/run/workspace-exec-policy" \
        "$WEP_ROOT/sys/kernel/security" \
        "$WEP_ROOT/proc/sys/kernel/yama"
    : > "$WEP_ROOT/usr/local/bin/workspace-exec-policyd"
    : > "$WEP_ROOT/usr/local/lib/workspace-guard/exec_policy.bpf.o"
    : > "$WEP_ROOT/usr/local/bin/workspace-exec-policy-session-gate"
    : > "$WEP_ROOT/etc/systemd/system/workspace-exec-policyd.service"
    printf 'lockdown,capability,landlock,yama,apparmor,ima,evm\n' \
        > "$WEP_ROOT/sys/kernel/security/lsm"
    printf '[none] integrity confidentiality\n' \
        > "$WEP_ROOT/sys/kernel/security/lockdown"
    printf '1\n' > "$WEP_ROOT/proc/sys/kernel/yama/ptrace_scope"
    printf 'unarmed\n' > "$WEP_ROOT/etc/workspace-guard/exec-policy-state"
    printf 'profile workspace-exec-policy {\n}\n' \
        > "$WEP_ROOT/etc/apparmor.d/workspace-exec-policy"
    printf '[Service]\nCapabilityBoundingSet=CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER\nNoNewPrivileges=no\n' \
        > "$WEP_ROOT/etc/systemd/system/workspace-agent@.service.d/10-exec-policy.conf"
}

_wep_arm() {
    printf 'lockdown,capability,landlock,yama,apparmor,ima,evm,bpf\n' \
        > "$WEP_ROOT/sys/kernel/security/lsm"
    printf '[integrity] integrity confidentiality\n' \
        > "$WEP_ROOT/sys/kernel/security/lockdown"
    printf '2\n' > "$WEP_ROOT/proc/sys/kernel/yama/ptrace_scope"
    : > "$WEP_ROOT/run/workspace-exec-policy/bpf-ready"
    printf '%s\n' exec=bpf fs=apparmor ptrace=yama kernel=lockdown caps=capability \
        > "$WEP_ROOT/run/workspace-exec-policy/ready"
    printf 'armed\n' > "$WEP_ROOT/etc/workspace-guard/exec-policy-state"
}

_wep_run_check() {
    run env WEP_ROOT="$WEP_ROOT" bash "$WEP" check
}

@test "exec-policy check: nothing staged is NOT INSTALLED" {
    rm -rf "$WEP_ROOT/usr/local/bin/workspace-exec-policyd"
    run env WEP_ROOT="$WEP_ROOT" bash "$WEP" check
    assert_equal "$status" 2
    assert_output --partial "NOT INSTALLED"
}

@test "exec-policy check: staged and unarmed is NOT ARMED" {
    _wep_run_check
    assert_equal "$status" 0
    assert_output --partial "NOT ARMED"
}

@test "exec-policy check: armed with every owner verified is OK" {
    _wep_arm
    _wep_run_check
    assert_equal "$status" 0
    assert_output --partial "OK (armed)"
}

@test "exec-policy check: armed but bpf LSM absent is DRIFTED" {
    _wep_arm
    printf 'lockdown,capability,landlock,yama,apparmor,ima,evm\n' \
        > "$WEP_ROOT/sys/kernel/security/lsm"
    _wep_run_check
    assert_equal "$status" 1
    assert_output --partial "DRIFTED"
}

@test "exec-policy check: armed but ptrace scope unhardened is DRIFTED" {
    _wep_arm
    printf '1\n' > "$WEP_ROOT/proc/sys/kernel/yama/ptrace_scope"
    _wep_run_check
    assert_equal "$status" 1
    assert_output --partial "DRIFTED"
}

@test "exec-policy check: armed but lockdown inactive is DRIFTED" {
    _wep_arm
    printf '[none] integrity confidentiality\n' \
        > "$WEP_ROOT/sys/kernel/security/lockdown"
    _wep_run_check
    assert_equal "$status" 1
    assert_output --partial "DRIFTED"
}

@test "session gate: unarmed posture refuses to start the session" {
    run env WEP_ROOT="$WEP_ROOT" bash "$WEP_GATE"
    assert_equal "$status" 1
}

@test "session gate: armed with the full manifest allows the session" {
    _wep_arm
    run env WEP_ROOT="$WEP_ROOT" bash "$WEP_GATE"
    assert_equal "$status" 0
}

@test "session gate: armed with a partial manifest fails closed" {
    _wep_arm
    printf '%s\n' exec=bpf fs=apparmor > "$WEP_ROOT/run/workspace-exec-policy/ready"
    run env WEP_ROOT="$WEP_ROOT" bash "$WEP_GATE"
    assert_equal "$status" 1
}

@test "exec-policy stage: missing policy warns with the seed path" {
    local stage_root="$TEST_TMPDIR/stage-root"
    run env WEP_ROOT="$stage_root" WEP_REPO_ROOT="$GUARD_ROOT" \
        WEP_ALLOW_NONROOT=1 WEP_SYSTEMCTL=true \
        WEP_LOADER_SRC="$GUARD_ROOT/nonexistent-loader" \
        WEP_BPF_OBJ_SRC="$GUARD_ROOT/nonexistent-obj" \
        bash "$WEP" stage
    assert_equal "$status" 0
    assert_output --partial "allowlist policy missing"
    assert_output --partial "yaml-bootstrap"
}
