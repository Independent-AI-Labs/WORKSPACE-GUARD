#!/usr/bin/env bash
# e2e-shell-guard-guest.sh: authoritative shell-guard E2E inside a
# bare QEMU Linux guest. Mutates guest / only. Requires root.
# See SPEC-SHELL-GUARD section 12.4 and WORKSPACE-VM SPEC-VM-HYPERVISOR
# section 12. Runs six phases:
#   0 preflight (clean slate if a previous run left the guard in)
#   1 cargo build (release + debug)
#   2 standalone runtime battery (scratch guard copy + manual bash.real)
#   3 install lifecycle + live-fire through /bin/bash (root + non-root)
#   4 survivability (divert, apt hook, login shells)
#   5 reconcile drift repair + fail-closed recovery runbook
#   6 uninstall + stock-restore verification
#
# This script may run while the guard is ACTIVE (reruns), so its body
# must never contain policy-pattern text: probe strings are built by
# concatenation, output discards use "$DEVNULL", and no barred idiom
# appears literally (same discipline as scripts/install-shell-guard).

set -uo pipefail

DEVNULL=/dev/null
PIPE='|'
WORKSPACE_ROOT="${WORKSPACE_ROOT:-/opt/workspace}"
GUARD_ROOT="$WORKSPACE_ROOT/projects/WORKSPACE-GUARD"
AGENT_USER="${SHG_E2E_USER:-workspace}"
RELEASE_BIN="$GUARD_ROOT/target/release/workspace-shell-guard"
DEBUG_BIN="$GUARD_ROOT/target/debug/workspace-shell-guard"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); echo "ok $PASS - $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL - $*" >&2; }

# expect_status <desc> <want> <cmd...>
expect_status() {
    local desc="$1" want="$2" st=0 out
    shift 2
    out="$("$@" 2>&1)" || st=$?
    if [ "$st" -eq "$want" ]; then
        ok "$desc"
    else
        bad "$desc (want status $want, got $st: ${out:0:200})"
    fi
}

# expect_blocked <desc> <rule-id> <runner...> -- <command-string>
# runner is the guard binary (phase 2) or bash (post-install).
expect_blocked() {
    local desc="$1" rule="$2" st=0 out
    shift 2
    out="$("$@" 2>&1)" || st=$?
    if [ "$st" -eq 1 ] && [ "${out#*BLOCKED}" != "$out" ] && [ "${out#*"$rule"}" != "$out" ]; then
        ok "$desc"
    else
        bad "$desc (want blocked by $rule, got status $st: ${out:0:200})"
    fi
}

section() { echo "==> $*"; }

# Probe strings, concatenated so this script's own text never matches
# the compiled policy (the guard scans untrusted script bodies).
PB_POWERVERB='sy''stemctl power''off'
PB_PROCNAME='pk''ill opencode'
PB_POWERCMD='shu''tdown -h now'
PB_FSDESTROY='mk''fs.ext4 /dev/sda1'
PB_ALTSHELL='z''sh -c true'
PB_BUSYBOX='busy''box sh'
PB_KILLMASS='kill -1''5 1234'
PB_CHATTR='chat''tr -i /etc/x'
PB_RMROOT='rm -rf --no-preserve''-root /'
PB_DD='dd if=x of=/dev/s''da'
PB_MOUNT='umount /usr/lib/workspace''-guard/bin'
PB_SWAP='swap''off -a'
PB_PIPE="somecmd $PIPE tail"
PB_NULL="somecmd 2>$DEVNULL"
PB_SWALLOW="somecmd $PIPE$PIPE :"

# run_battery <label> <runner>
# Core live-fire matrix against one guard entry point.
run_battery() {
    local label="$1" runner="$2"
    expect_blocked "$label: power verb"        power-verb      "$runner" -c "$PB_POWERVERB"
    expect_blocked "$label: process by name"   process-by-name "$runner" -c "$PB_PROCNAME"
    expect_blocked "$label: power command"     power-command   "$runner" -c "$PB_POWERCMD"
    expect_blocked "$label: fs destroy"        fs-destroy      "$runner" -c "$PB_FSDESTROY"
    expect_blocked "$label: alt shell"         alt-shell       "$runner" -c "$PB_ALTSHELL"
    expect_blocked "$label: busybox shell"     busybox-shell   "$runner" -c "$PB_BUSYBOX"
    expect_blocked "$label: kill mass"         kill-mass       "$runner" -c "$PB_KILLMASS"
    expect_blocked "$label: immutability strip" chattr-strip   "$runner" -c "$PB_CHATTR"
    expect_blocked "$label: rootfs delete"     rm-rootfs       "$runner" -c "$PB_RMROOT"
    expect_blocked "$label: dd to device"      dd-device       "$runner" -c "$PB_DD"
    expect_blocked "$label: guard mountpoint"  mount-protected "$runner" -c "$PB_MOUNT"
    expect_blocked "$label: swap teardown"     swap-teardown   "$runner" -c "$PB_SWAP"
    expect_blocked "$label: pipe truncation"   suppress-pipe   "$runner" -c "$PB_PIPE"
    expect_blocked "$label: output discard"    suppress-null   "$runner" -c "$PB_NULL"
    expect_blocked "$label: exit swallow"      suppress-swallow "$runner" -c "$PB_SWALLOW"
    expect_status  "$label: benign -c passes"  0 "$runner" -c 'echo shg-benign'
    expect_status  "$label: targeted kill allowed" 0 "$runner" -c 'kill -0 $$'
    expect_status  "$label: --version passthrough" 0 "$runner" --version
    expect_blocked "$label: bundled -xc scanned" suppress-pipe "$runner" -xc "$PB_PIPE"
    expect_blocked "$label: bundled -lc scanned" process-by-name "$runner" -lc "$PB_PROCNAME"
}

# ---------------------------------------------------------------------------
section "phase 0: preflight"
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: e2e-shell-guard-guest.sh requires root inside the QEMU guest" >&2
    exit 1
fi
[ -d "$GUARD_ROOT/scripts" ] || { echo "ERROR: WORKSPACE-GUARD not at $GUARD_ROOT" >&2; exit 1; }
if ! id "$AGENT_USER" >"$DEVNULL" 2>&1; then
    echo "ERROR: non-root test user '$AGENT_USER' missing in guest" >&2
    exit 1
fi
AGENT_HOME="$(getent passwd "$AGENT_USER" | cut -d: -f6)"

# Clean slate when a previous partial run left the guard installed.
if bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1; then
    section "phase 0: previous install detected; uninstalling"
    bash "$GUARD_ROOT/scripts/uninstall-shell-guard" || { echo "ERROR: cleanup uninstall failed" >&2; exit 1; }
fi

BASH_PATH="$(readlink -f /bin/bash)"
BASELINE_HASH="$(sha256sum "$BASH_PATH" | awk '{print $1}')"
echo "    stock bash: $BASH_PATH (${BASELINE_HASH:0:12}...)"

# ---------------------------------------------------------------------------
section "phase 1: build"
for envf in /root/.cargo/env "$HOME/.cargo/env" "$AGENT_HOME/.cargo/env"; do
    if [ -f "$envf" ]; then
        # shellcheck disable=SC1090
        . "$envf" || exit 1
        break
    fi
done
if ! command -v cargo >"$DEVNULL" 2>&1; then
    echo "ERROR: cargo not available in guest" >&2
    exit 1
fi
(cd "$GUARD_ROOT" && cargo build && cargo build --release) \
    || { echo "ERROR: cargo build failed" >&2; exit 1; }
[ -x "$RELEASE_BIN" ] || { echo "ERROR: release guard binary missing" >&2; exit 1; }
ok "cargo build (debug + release)"

# ---------------------------------------------------------------------------
section "phase 2: standalone runtime battery (scratch copy)"
SCRATCH="$(mktemp /tmp/shg-e2e.XXXXXX)"
cp "$RELEASE_BIN" "$SCRATCH"
chmod 755 "$SCRATCH"
setcap cap_dac_override=ep "$SCRATCH" || { echo "ERROR: setcap failed in guest" >&2; exit 1; }

cp "$BASH_PATH" /bin/bash.real
chown root:root /bin/bash.real
chmod 0700 /bin/bash.real

# AT_SECURE gate: a copy without file caps must fail closed.
NOCAP="$(mktemp /tmp/shg-e2e-nocap.XXXXXX)"
cp "$RELEASE_BIN" "$NOCAP"
chmod 755 "$NOCAP"
expect_status "no-cap copy exits 3 (AT_SECURE gate)" 3 "$NOCAP" -c 'echo no'
rm -f "$NOCAP"

run_battery "standalone" "$SCRATCH"

# Environment hygiene.
out="$(env PATH="/tmp/shg-fakebin:/usr/bin:/bin" "$SCRATCH" -c 'command -v ls')"
case "$out" in
    */bin/ls) [ "${out#*fakebin}" = "$out" ] && ok "env: PATH reset" || bad "env: PATH reset ($out)" ;;
    *) bad "env: PATH reset ($out)" ;;
esac
out="$(env LD_PRELOAD=/tmp/shg-evil.so "$SCRATCH" -c 'echo "${LD_PRELOAD:-unset}"')"
[ "$out" = "unset" ] && ok "env: LD_PRELOAD stripped" || bad "env: LD_PRELOAD stripped ($out)"
out="$(env LC_SHG=1 WORKSPACE_TAG=abc SHG_JUNK=no "$SCRATCH" -c 'echo "$LC_SHG:$WORKSPACE_TAG:${SHG_JUNK:-unset}"')"
[ "$out" = "1:abc:unset" ] && ok "env: allow-list filtering" || bad "env: allow-list filtering ($out)"

# Resource limits.
out="$("$SCRATCH" -c 'ulimit -c')"
[ "$out" = "0" ] && ok "rlimit: core dumps disabled" || bad "rlimit: core dumps disabled ($out)"
out="$("$SCRATCH" -c 'ulimit -n')"
[ -n "$out" ] && [ "$out" -le 4096 ] 2>"$DEVNULL" && ok "rlimit: NOFILE capped" || bad "rlimit: NOFILE capped ($out)"

# Trust tiers and sealed memfd (666 files are never trusted tier).
TDIR="$(mktemp -d /tmp/shg-tier.XXXXXX)"
printf '#!/bin/bash\necho "argv0=$0"\n' > "$TDIR/u.sh"
chmod 666 "$TDIR/u.sh"
out="$("$SCRATCH" "$TDIR/u.sh")"
case "$out" in
    argv0=/proc/self/fd/*) ok "tier: untrusted runs via sealed memfd" ;;
    *) bad "tier: untrusted runs via sealed memfd ($out)" ;;
esac
printf '#!/bin/bash\nif echo x >> "$0"; then echo writable; else echo sealed; fi\n' > "$TDIR/s.sh"
chmod 666 "$TDIR/s.sh"
out="$("$SCRATCH" "$TDIR/s.sh")"
[ "$out" = "sealed" ] && ok "tier: memfd body is sealed" || bad "tier: memfd body is sealed ($out)"
printf '#!/bin/bash\necho trusted-ran\nsomecmd %s tail\n' "$PIPE" > "$TDIR/t.sh"
chown root:root "$TDIR/t.sh"
chmod 755 "$TDIR" "$TDIR/t.sh"
out="$("$SCRATCH" "$TDIR/t.sh" 2>&1)"
if [ "${out#*trusted-ran}" != "$out" ] && [ "${out#*would-block}" != "$out" ]; then
    ok "tier: trusted script exempt-with-audit"
else
    bad "tier: trusted script exempt-with-audit ($out)"
fi
rm -rf "$TDIR"

# Oversize -c string exits 2.
BIG="$(head -c 1100000 /dev/zero | tr '\0' 'a')"
expect_status "oversize -c exits 2" 2 "$SCRATCH" -c "$BIG"
unset BIG

# Audit log (passwd home of the invoking uid).
ALOG="/root/.workspace-guard.log"
: > "$ALOG"
"$SCRATCH" -c "$PB_PIPE" >"$DEVNULL" 2>&1
if grep -q 'blocked rule: suppress-pipe' "$ALOG" && grep -q 'uid=0' "$ALOG"; then
    ok "audit: block logged to passwd home"
else
    bad "audit: block logged to passwd home"
fi
: > "$ALOG"
"$SCRATCH" -c "SHGTOKEN=hunter2 $PB_PIPE" >"$DEVNULL" 2>&1
if grep -q 'SHGTOKEN=...' "$ALOG" && ! grep -q hunter2 "$ALOG"; then
    ok "audit: NAME=value redaction"
else
    bad "audit: NAME=value redaction"
fi
rm -f "$ALOG"

# Verification failure fails closed.
chmod 0755 /bin/bash.real
expect_status "relaxed bash.real exits 3" 3 "$SCRATCH" -c 'echo no'
chmod 0700 /bin/bash.real
expect_status "bash.real restored" 0 "$SCRATCH" -c 'echo yes'

rm -f "$SCRATCH" /bin/bash.real

# ---------------------------------------------------------------------------
section "phase 3: install lifecycle + live-fire"
st=0
bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1 || st=$?
[ "$st" -eq 2 ] && ok "pre-install: check reports NOT INSTALLED" || bad "pre-install: check status $st"

bash "$GUARD_ROOT/scripts/install-shell-guard" || { echo "ERROR: install failed" >&2; exit 1; }
ok "install-shell-guard applied"

if bash "$GUARD_ROOT/scripts/shell-guard-check"; then
    ok "post-install: check reports OK"
else
    bad "post-install: check reports OK"
fi

[ "$(stat -c '%a %U:%G' /bin/bash.real)" = "700 root:root" ] \
    && ok "bash.real sealed 0700 root:root" || bad "bash.real seal"
lsattr -d /bin/bash.real 2>"$DEVNULL" | awk '{print $1}' | grep -q i \
    && ok "bash.real immutable" || bad "bash.real immutable"
getcap "$BASH_PATH" 2>"$DEVNULL" | grep -q 'cap_dac_override=ep' \
    && ok "guard caps in place" || bad "guard caps"
dpkg-divert --list "$BASH_PATH" 2>"$DEVNULL" | grep -q "diversion of $BASH_PATH" \
    && ok "dpkg divert registered" || bad "dpkg divert"
[ -f /etc/apt/apt.conf.d/99workspace-guard-shell ] \
    && ok "apt hook installed" || bad "apt hook"
[ "$(sha256sum "$BASH_PATH" | awk '{print $1}')" = "$(sha256sum "$RELEASE_BIN" | awk '{print $1}')" ] \
    && ok "guard hash matches release build" || bad "guard hash"

run_battery "installed-root" bash

# Live-fire as the non-root user, including its audit log.
expect_blocked "installed-$AGENT_USER: process by name" process-by-name \
    runuser -u "$AGENT_USER" -- bash -c "$PB_PROCNAME"
expect_status "installed-$AGENT_USER: benign -c passes" 0 \
    runuser -u "$AGENT_USER" -- bash -c 'echo agent-benign'
ULOG="$AGENT_HOME/.workspace-guard.log"
grep -q 'blocked rule: process-by-name' "$ULOG" \
    && ok "audit: non-root block logged to user home" || bad "audit: non-root block"

# Idempotent reconcile is a no-op.
bash "$GUARD_ROOT/scripts/install-shell-guard" >"$DEVNULL" 2>&1 \
    && bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1 \
    && ok "reinstall idempotent" || bad "reinstall idempotent"

# ---------------------------------------------------------------------------
section "phase 4: survivability"
grep -q 'DPkg::Post-Invoke' /etc/apt/apt.conf.d/99workspace-guard-shell \
    && ok "apt hook is a Post-Invoke warn hook" || bad "apt hook content"
expect_status "login shell works for $AGENT_USER" 0 su - "$AGENT_USER" -c 'echo login-ok'
out="$(runuser -u "$AGENT_USER" -- bash -lc 'echo nested-login-ok' 2>"$DEVNULL")"
[ "$out" = "nested-login-ok" ] && ok "nested login shell works" || bad "nested login shell ($out)"
# An apt transaction would land on the diverted path; the guard file
# itself must be untouched. Simulate the ops repair loop: re-run the
# installer (what the hook message advises) and confirm health.
bash "$GUARD_ROOT/scripts/install-shell-guard" >"$DEVNULL" 2>&1 \
    && bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1 \
    && ok "post-transaction repair loop healthy" || bad "post-transaction repair loop"

# ---------------------------------------------------------------------------
section "phase 5: reconcile drift repair"
rm -f /etc/apt/apt.conf.d/99workspace-guard-shell
st=0
bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1 || st=$?
[ "$st" -eq 1 ] && ok "drift: missing hook reported DRIFTED" || bad "drift: missing hook status $st"
bash "$GUARD_ROOT/scripts/install-shell-guard" >"$DEVNULL" 2>&1 \
    && bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1 \
    && ok "drift: hook repaired" || bad "drift: hook repaired"

# Stale binary (debug build swapped in, caps preserved).
cp "$DEBUG_BIN" "$BASH_PATH.stale"
chown root:root "$BASH_PATH.stale"
chmod 0755 "$BASH_PATH.stale"
setcap cap_dac_override=ep "$BASH_PATH.stale"
mv -T "$BASH_PATH.stale" "$BASH_PATH"
st=0
bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1 || st=$?
[ "$st" -eq 1 ] && ok "drift: stale hash reported DRIFTED" || bad "drift: stale hash status $st"
bash "$GUARD_ROOT/scripts/install-shell-guard" >"$DEVNULL" 2>&1 \
    && bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1 \
    && ok "drift: stale hash repaired to release" || bad "drift: stale hash repair"

# Fail-closed: stripping the caps breaks every new shell (exit 3).
# Recovery runbook: stage the installer root-owned and run it under
# the sealed /bin/bash.real (0700, root-only) which never scans.
setcap -r "$BASH_PATH"
expect_status "fail-closed: cap-stripped guard exits 3" 3 bash -c 'echo no'
install -d -m 0700 /run/workspace-guard
install -m 0700 -o root -g root "$GUARD_ROOT/scripts/install-shell-guard" /run/workspace-guard/shg-repair
if /bin/bash.real /run/workspace-guard/shg-repair >"$DEVNULL" 2>&1 \
    && bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1; then
    ok "fail-closed: recovery via bash.real runbook"
else
    bad "fail-closed: recovery via bash.real runbook"
fi
rm -f /run/workspace-guard/shg-repair

# ---------------------------------------------------------------------------
section "phase 6: uninstall + stock restore"
bash "$GUARD_ROOT/scripts/uninstall-shell-guard" || { echo "ERROR: uninstall failed" >&2; exit 1; }
ok "uninstall-shell-guard applied"
st=0
bash "$GUARD_ROOT/scripts/shell-guard-check" >"$DEVNULL" 2>&1 || st=$?
[ "$st" -eq 2 ] && ok "post-uninstall: check reports NOT INSTALLED" || bad "post-uninstall: check status $st"
[ ! -e /bin/bash.real ] && ok "bash.real removed" || bad "bash.real removed"
[ ! -e /etc/apt/apt.conf.d/99workspace-guard-shell ] && ok "apt hook removed" || bad "apt hook removed"
if dpkg-divert --list "$BASH_PATH" 2>"$DEVNULL" | grep -q "diversion of $BASH_PATH"; then
    bad "divert removed"
else
    ok "divert removed"
fi
[ "$(sha256sum "$BASH_PATH" | awk '{print $1}')" = "$BASELINE_HASH" ] \
    && ok "stock bash restored byte-identical" || bad "stock bash restored"
out="$(bash -c "echo unguarded $PIPE tail")"
[ "$out" = "unguarded" ] && ok "unguarded shell behaves as stock" || bad "unguarded shell ($out)"

# ---------------------------------------------------------------------------
section "summary"
if [ "$FAIL" -ne 0 ]; then
    echo "FAIL: shell-guard guest e2e ($FAIL failures, $PASS passed)"
    exit 1
fi
echo "PASS: shell-guard guest e2e ($PASS checks)"
