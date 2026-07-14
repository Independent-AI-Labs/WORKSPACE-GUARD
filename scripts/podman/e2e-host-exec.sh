#!/usr/bin/env bash
# Tier 3: host-exec guard install sanity check (privileged container, root).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-host-exec.sh requires root (container root)" >&2
    exit 1
fi

_CI_ROOT="/projects/CI"
_AGENT_USER="agent"
_AGENT_UID="1001"
_TEST_HOST="workspace-guard-test"

if [[ ! -f "$_CI_ROOT/scripts/bootstrap-workspace-guard" ]]; then
    echo "ERROR: bootstrap-workspace-guard not found at $_CI_ROOT" >&2
    exit 1
fi

hostname "$_TEST_HOST"

if ! id "$_AGENT_USER" >/dev/null 2>&1; then
    useradd -m -u "$_AGENT_UID" -s /bin/bash "$_AGENT_USER"
    echo "Created user $_AGENT_USER (uid $_AGENT_UID)"
fi

unset BUILD_MODE
export GUARD_NONINTERACTIVE=1

echo "==> Tier 3: installing guard (host-exec)..."
bash "$_CI_ROOT/scripts/bootstrap-workspace-guard" install-host-exec

echo "==> Tier 3: verifying installation..."
if ! command -v getcap >/dev/null 2>&1; then
    echo "ERROR: getcap not available" >&2
    exit 1
fi

_expected='cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid=ep'
_gc_out=""
_raw="$(getcap /usr/bin/git)"
_line="${_raw%%$'\n'*}"
if [[ -n "$_line" && "$_line" == *cap_* ]]; then
    _gc_out="cap_${_line#*cap_}"
else
    _gc_out=""
fi
if [[ "$_gc_out" != "$_expected" ]]; then
    echo "ERROR: /usr/bin/git file caps expected '$_expected', got '${_gc_out:-none}'" >&2
    exit 1
fi
echo "PASS: guard binary has host-exec file caps"

if [[ ! -f /usr/lib/workspace-guard/deployment-class ]] \
    || [[ "$(tr -d '[:space:]' < /usr/lib/workspace-guard/deployment-class)" != "host-exec" ]]; then
    echo "ERROR: deployment-class must be host-exec" >&2
    exit 1
fi
echo "PASS: deployment-class is host-exec"

if [[ -f /etc/security/capability.conf ]] \
    && grep -q 'workspace-guard ambient caps' /etc/security/capability.conf; then
    echo "ERROR: pam_cap artifact must not remain after host-exec install" >&2
    exit 1
fi
echo "PASS: no pam_cap artifacts in capability.conf"

_orig_mode="$(stat -c '%a' /usr/bin/git.original)"
_orig_owner="$(stat -c '%U:%G' /usr/bin/git.original)"
if [[ "$_orig_mode" != "700" || "$_orig_owner" != "root:root" ]]; then
    echo "ERROR: git.original permissions wrong: $_orig_mode $_orig_owner" >&2
    exit 1
fi
echo "PASS: git.original is 0700 root:root"

echo "==> Tier 3: sanity check tests as $_AGENT_USER (runuser)..."
tmpdir="$(mktemp -d)"
chmod 755 "$tmpdir"
cd "$tmpdir"
git init -q
sudo git config user.email "podman-host-exec@test.local"
sudo git config user.name "Podman Host Exec"
chown -R "$_AGENT_USER:$_AGENT_USER" "$tmpdir"

_agent_check="$(mktemp)"
cat > "$_agent_check" <<'EOS'
set -euo pipefail
cd "$1"
if ! git --version >/dev/null; then
    echo "ERROR: git --version failed for agent user" >&2
    exit 1
fi
echo "PASS: agent git --version succeeded"
_git_owner="$(stat -c '%U:%G' .git)"
if [[ "$_git_owner" != "root:root" ]]; then
    echo "ERROR: .git must be root:root after guard lock, got $_git_owner" >&2
    exit 1
fi
echo "PASS: .git is root:root after guard lock"
echo "test" > file.txt
git add file.txt
git commit -q -m "init"
if ! git status >/dev/null; then
    echo "ERROR: git status failed for agent user" >&2
    exit 1
fi
echo "PASS: agent git status succeeded"
_reset_rc=0
git reset --hard >/dev/null 2>&1 || _reset_rc=$?
if [[ $_reset_rc -eq 0 ]]; then
    echo "ERROR: agent git reset --hard was not blocked" >&2
    exit 1
fi
echo "PASS: agent git reset --hard blocked"
_orig_rc=0
/usr/bin/git.original --version >/dev/null 2>&1 || _orig_rc=$?
if [[ $_orig_rc -eq 0 ]]; then
    echo "ERROR: agent could execute /usr/bin/git.original" >&2
    exit 1
fi
echo "PASS: agent cannot execute git.original"
EOS
chmod 755 "$_agent_check"
runuser -u "$_AGENT_USER" -- bash "$_agent_check" "$tmpdir"
rm -f "$_agent_check"
rm -rf "$tmpdir"
cd /projects/WORKSPACE-GUARD

echo "==> Tier 3: policy-matrix E2E..."
bash scripts/podman/e2e-policy-matrix.sh

echo "==> Tier 3: uninstalling guard..."
bash "$_CI_ROOT/scripts/bootstrap-workspace-guard" uninstall

echo "==> Tier 3 complete"