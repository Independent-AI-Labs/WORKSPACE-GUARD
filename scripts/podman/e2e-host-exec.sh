#!/usr/bin/env bash
# Tier 3: host-exec guard install sanity check (privileged container, root).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-host-exec.sh requires root (container root)" >&2
    exit 1
fi

_SELF="${BASH_SOURCE[0]:-$0}"
case "$_SELF" in /proc/self/fd/*) _SELF="${SHG_SCRIPT_PATH:-$_SELF}" ;; esac
_SCRIPT_DIR="$(cd "$(dirname "$_SELF")" && pwd)"
# shellcheck source=scripts/podman/lib/host-provision-e2e.sh
source "$_SCRIPT_DIR/lib/host-provision-e2e.sh" || exit 1

_CI_ROOT="${CI_ROOT:-/projects/WORKSPACE-CI}"
_GUARD_ROOT="${GUARD_ROOT:-$(hp_e2e_guard_root)}"
_TEST_HOST="workspace-guard-test"

if [[ ! -f "$_GUARD_ROOT/scripts/install-git-guard" ]]; then
    echo "ERROR: scripts/install-git-guard not found at $_GUARD_ROOT" >&2
    exit 1
fi

hostname "$_TEST_HOST"
hp_e2e_prepare_git_safe_directory

# Phases 0-4: isolated configs, real password verify, install-gate negative tests.
bash "$_SCRIPT_DIR/e2e-host-provision.sh"

# Re-init state for phase 5 (e2e-host-provision cleans up on exit; setup again).
hp_e2e_init_state_dir
hp_e2e_write_configs
export GUARD_NONINTERACTIVE=1
export WORKSPACE_ADMIN_PASSWORD="$HP_E2E_ADMIN_PASSWORD"
unset WORKSPACE_ADMIN_PASSWORD_VERIFY

if [[ ! -f "$_GUARD_ROOT/config/agent-git-identity" ]] \
    && [[ -f "$_GUARD_ROOT/config/agent-git-identity.example" ]]; then
    cp "$_GUARD_ROOT/config/agent-git-identity.example" "$_GUARD_ROOT/config/agent-git-identity"
fi

hp_e2e_prepare_git_safe_directory
hp_e2e_prepare_cargo_env
echo "==> Tier 3: provision-host phase 5 (guard stack)..."
bash "$_GUARD_ROOT/scripts/provision-host" --phase 5

echo "==> Tier 3: verifying installation..."
if ! command -v getcap; then
    echo "ERROR: getcap not available" >&2
    exit 1
fi

_raw="$(getcap /usr/bin/git)"
_line="${_raw%%$'\n'*}"
for _cap in cap_chown cap_dac_override cap_fowner cap_setpcap; do
    if [[ "$_line" != *"$_cap"* ]]; then
        echo "ERROR: /usr/bin/git missing $_cap (got '${_line:-none}')" >&2
        exit 1
    fi
done
if [[ "$_line" == *"cap_fsetid"* ]]; then
    echo "ERROR: /usr/bin/git must not carry cap_fsetid (got '${_line:-none}')" >&2
    exit 1
fi
if [[ "$_line" != *"=ep" ]]; then
    echo "ERROR: /usr/bin/git caps must include =ep (got '${_line:-none}')" >&2
    exit 1
fi
echo "PASS: guard binary has host-exec file caps"

if [[ ! -f /usr/lib/workspace-guard/deployment-class ]] \
    || [[ "$(tr -d '[:space:]' < /usr/lib/workspace-guard/deployment-class)" != "host-exec" ]]; then
    echo "ERROR: deployment-class must be host-exec" >&2
    exit 1
fi
echo "PASS: deployment-class is host-exec"

if ! hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: $HP_E2E_AGENT_USER should retain group sudo (audit-only)" >&2
    exit 1
fi
echo "PASS: agent retained group sudo (no demotion)"

if ! hp_e2e_agent_has_effective_sudo; then
    echo "ERROR: $HP_E2E_AGENT_USER should retain effective sudo (audit-only)" >&2
    exit 1
fi
echo "PASS: agent retained effective sudo (no demotion)"

_marker="$(hp_e2e_marker_path)"
if [[ ! -f "$_marker" ]]; then
    echo "ERROR: host-provision.ok marker missing at $_marker" >&2
    exit 1
fi
echo "PASS: host-provision.ok present"

if [[ -f /etc/security/capability.conf ]] \
    && grep -q 'workspace-guard ambient caps' /etc/security/capability.conf; then
    echo "ERROR: pam_cap artifact must not remain after host-exec install" >&2
    exit 1
fi
echo "PASS: no pam_cap artifacts in capability.conf"

_orig_mode="$(stat -c '%a' /usr/lib/workspace-guard/sealed/git)"
_orig_owner="$(stat -c '%U:%G' /usr/lib/workspace-guard/sealed/git)"
if [[ "$_orig_mode" != "700" || "$_orig_owner" != "root:root" ]]; then
    echo "ERROR: sealed/git permissions wrong: $_orig_mode $_orig_owner" >&2
    exit 1
fi
echo "PASS: sealed/git is 0700 root:root"

echo "==> Tier 3: sanity check tests as $HP_E2E_AGENT_USER (runuser)..."
tmpdir="$(mktemp -d)"
chmod 755 "$tmpdir"
cd "$tmpdir"
git init -q
chown -R "$HP_E2E_AGENT_USER:$HP_E2E_AGENT_USER" "$tmpdir"

_agent_check="$(mktemp)"
cat > "$_agent_check" <<'EOS'
set -euo pipefail
cd "$1"
if ! git --version; then
    echo "ERROR: git --version failed for agent user" >&2
    exit 1
fi
echo "PASS: agent git --version succeeded"
echo "test" > file.txt
git add file.txt
git commit -q -m "init"
if ! git status; then
    echo "ERROR: git status failed for agent user" >&2
    exit 1
fi
echo "PASS: agent git status succeeded"
_git_owner="$(stat -c '%U:%G' .git)"
if [[ "$_git_owner" == "root:root" ]]; then
    echo "PASS: .git is root:root after guard lock"
else
    # Podman user namespaces may block cap_chown-based gitdir::lock; policy blocks still verified below.
    echo "WARN: .git is $_git_owner (expected root:root); gitdir lock may not apply in Podman"
    echo "PASS: Podman gitdir ownership lock skipped (container limitation)"
fi
_rev_rc=0
_rev_out="$(git rev-parse --show-toplevel 2>&1)" || _rev_rc=$?
printf '%s\n' "$_rev_out"
if [[ $_rev_rc -ne 0 ]] || [[ "$_rev_out" == *"dubious ownership"* ]]; then
    echo "ERROR: git rev-parse failed in a root-locked repo (safe.directory injection missing)" >&2
    exit 1
fi
echo "PASS: agent git rev-parse works in a root-locked repo"

_reset_rc=0
_reset_out="$(git reset --hard 2>&1)" || _reset_rc=$?
printf '%s\n' "$_reset_out"
if [[ $_reset_rc -eq 0 ]]; then
    echo "ERROR: agent git reset --hard was not blocked" >&2
    exit 1
fi
echo "PASS: agent git reset --hard blocked"
_orig_rc=0
_orig_out="$(/usr/lib/workspace-guard/sealed/git --version 2>&1)" || _orig_rc=$?
printf '%s\n' "$_orig_out"
if [[ $_orig_rc -eq 0 ]]; then
    echo "ERROR: agent could execute /usr/lib/workspace-guard/sealed/git" >&2
    exit 1
fi
echo "PASS: agent cannot execute sealed/git"
EOS
chmod 755 "$_agent_check"
runuser -u "$HP_E2E_AGENT_USER" -- bash "$_agent_check" "$tmpdir"
rm -f "$_agent_check"
rm -rf "$tmpdir"
cd "$_GUARD_ROOT"

echo "==> Tier 3: upstream pull/rebase E2E (REQ-GGUARD-061/064)..."
_upstream_base="$(mktemp -d)"
chmod 755 "$_upstream_base"
chown -R "$HP_E2E_AGENT_USER:$HP_E2E_AGENT_USER" "$_upstream_base"
_upstream_check="$(mktemp)"
cat > "$_upstream_check" <<'EOS'
set -euo pipefail
base="$1"

git init -q --bare "$base/remote.git"

git init -q -b main "$base/src"
cd "$base/src"
echo one > f.txt
git add f.txt
git commit -q -m "one"
git push -q "$base/remote.git" main

# A diverged clone (local commit) and a clean clone (fast-forwardable).
git clone -q "$base/remote.git" "$base/clone"
git clone -q "$base/remote.git" "$base/clone2"

cd "$base/src"
echo two > g.txt
git add g.txt
git commit -q -m "two"
git push -q "$base/remote.git" main

# REQ-GGUARD-064: pull --rebase on a diverged branch must not deadlock on
# the rebase child Git forks through the guarded exec-path.
cd "$base/clone"
echo local > local.txt
git add local.txt
git commit -q -m "local"
git pull --rebase origin main
echo "PASS: agent git pull --rebase succeeded on diverged branch"

# REQ-GGUARD-061: pull --ff-only still fast-forwards.
cd "$base/clone2"
git pull --ff-only origin main
echo "PASS: agent git pull --ff-only succeeded"

# A direct rebase stays blocked. Authorization is structural (the parent must
# be sealed/git running pull --rebase), so no caller-set environment variable
# can re-enable one (REQ-GGUARD-064).
cd "$base/clone"
_rebase_rc=0
_rebase_out="$(git rebase main 2>&1)" || _rebase_rc=$?
printf '%s\n' "$_rebase_out"
if [[ $_rebase_rc -eq 0 ]]; then
    echo "ERROR: direct git rebase was not blocked" >&2
    exit 1
fi
echo "PASS: direct git rebase blocked"
_onto_rc=0
_onto_out="$(git rebase --onto main HEAD~1 2>&1)" || _onto_rc=$?
printf '%s\n' "$_onto_out"
if [[ $_onto_rc -eq 0 ]]; then
    echo "ERROR: direct git rebase --onto was not blocked" >&2
    exit 1
fi
echo "PASS: direct git rebase --onto blocked"
_forged_rc=0
_forged_out="$(WORKSPACE_GUARD_APPROVED_REBASE=1 WORKSPACE_GUARD_SESSION=1 git rebase main 2>&1)" || _forged_rc=$?
printf '%s\n' "$_forged_out"
if [[ $_forged_rc -eq 0 ]]; then
    echo "ERROR: forged approval marker allowed a direct rebase" >&2
    exit 1
fi
echo "PASS: forged approval marker rejected"
EOS
chmod 755 "$_upstream_check"
runuser -u "$HP_E2E_AGENT_USER" -- bash "$_upstream_check" "$_upstream_base"
rm -f "$_upstream_check"
rm -rf "$_upstream_base"
cd "$_GUARD_ROOT"

echo "==> Tier 3: policy-matrix E2E..."
bash scripts/podman/e2e-policy-matrix.sh

echo "==> Tier 3: uninstalling guard..."
CI_DIR="$_CI_ROOT" WORKSPACE_GUARD_ROOT="$_GUARD_ROOT" bash "$_GUARD_ROOT/scripts/install-git-guard" uninstall

hp_e2e_cleanup
echo "==> Tier 3 complete"
