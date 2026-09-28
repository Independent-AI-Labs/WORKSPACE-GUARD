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
        "$WEP_ROOT/etc/systemd/system" \
        "$WEP_ROOT/usr/local/bin" \
        "$WEP_ROOT/usr/local/lib/workspace-guard" \
        "$WEP_ROOT/run/workspace-exec-policy" \
        "$WEP_ROOT/sys/kernel/security"
    : > "$WEP_ROOT/usr/local/bin/workspace-exec-policyd"
    : > "$WEP_ROOT/usr/local/lib/workspace-guard/exec_policy.bpf.o"
    : > "$WEP_ROOT/usr/local/bin/workspace-exec-policy-session-gate"
    : > "$WEP_ROOT/etc/systemd/system/workspace-exec-policyd.service"
    printf 'lockdown,capability,landlock,yama,apparmor\n' \
        > "$WEP_ROOT/sys/kernel/security/lsm"
    printf 'audit\n' > "$WEP_ROOT/etc/workspace-guard/exec-policy-mode"
    printf 'profile workspace-exec-policy flags=(complain) {\n}\n' \
        > "$WEP_ROOT/etc/apparmor.d/workspace-exec-policy"
}

_wep_lsm_add_bpf() {
    printf 'lockdown,capability,landlock,yama,apparmor,bpf\n' \
        > "$WEP_ROOT/sys/kernel/security/lsm"
}

_wep_profile_enforce() {
    printf 'profile workspace-exec-policy {\n}\n' \
        > "$WEP_ROOT/etc/apparmor.d/workspace-exec-policy"
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

@test "exec-policy check: staged complain with bpf off is NOT ACTIVE" {
    _wep_run_check
    assert_equal "$status" 0
    assert_output --partial "NOT ACTIVE"
}

@test "exec-policy check: bpf active in audit is AUDIT" {
    _wep_lsm_add_bpf
    _wep_run_check
    assert_equal "$status" 0
    assert_output --partial "AUDIT"
}

@test "exec-policy check: interim AppArmor authority is OK (interim)" {
    _wep_profile_enforce
    _wep_run_check
    assert_equal "$status" 0
    assert_output --partial "OK (interim)"
}

@test "exec-policy check: enforcing posture is OK (enforcing)" {
    _wep_lsm_add_bpf
    printf 'enforce\n' > "$WEP_ROOT/etc/workspace-guard/exec-policy-mode"
    _wep_run_check
    assert_equal "$status" 0
    assert_output --partial "OK (enforcing)"
}

@test "exec-policy check: bpf active with AppArmor still enforcing is DRIFTED" {
    _wep_lsm_add_bpf
    _wep_profile_enforce
    printf 'enforce\n' > "$WEP_ROOT/etc/workspace-guard/exec-policy-mode"
    _wep_run_check
    assert_equal "$status" 1
    assert_output --partial "DRIFTED"
}

@test "exec-policy check: enforce mode with bpf inactive is DRIFTED" {
    printf 'enforce\n' > "$WEP_ROOT/etc/workspace-guard/exec-policy-mode"
    _wep_run_check
    assert_equal "$status" 1
    assert_output --partial "DRIFTED"
}

@test "session gate: non-enforce mode never blocks" {
    run env WEP_ROOT="$WEP_ROOT" bash "$WEP_GATE"
    assert_equal "$status" 0
}

@test "session gate: enforce without readiness token fails closed" {
    printf 'enforce\n' > "$WEP_ROOT/etc/workspace-guard/exec-policy-mode"
    run env WEP_ROOT="$WEP_ROOT" bash "$WEP_GATE"
    assert_equal "$status" 1
}

@test "session gate: enforce with readiness token allows" {
    printf 'enforce\n' > "$WEP_ROOT/etc/workspace-guard/exec-policy-mode"
    : > "$WEP_ROOT/run/workspace-exec-policy/ready"
    run env WEP_ROOT="$WEP_ROOT" bash "$WEP_GATE"
    assert_equal "$status" 0
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
