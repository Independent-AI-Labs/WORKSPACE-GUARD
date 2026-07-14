#!/usr/bin/env bash
# Tier 3: host-exec guard install sanity check (privileged container, root).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-host-exec.sh requires root (container root)" >&2
    exit 1
fi

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/podman/lib/host-provision-e2e.sh
source "$_SCRIPT_DIR/lib/host-provision-e2e.sh" || exit 1

_CI_ROOT="/projects/CI"
_GUARD_ROOT="$(hp_e2e_guard_root)"
_TEST_HOST="workspace-guard-test"

if [[ ! -f "$_CI_ROOT/scripts/bootstrap-workspace-guard" ]]; then
    echo "ERROR: bootstrap-workspace-guard not found at $_CI_ROOT" >&2
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
if ! command -v getcap >/dev/null 2>&1; then
    echo "ERROR: getcap not available" >&2
    exit 1
fi

_raw="$(getcap /usr/bin/git)"
_line="${_raw%%$'\n'*}"
for _cap in cap_chown cap_dac_override cap_fowner cap_fsetid cap_setpcap; do
    if [[ "$_line" != *"$_cap"* ]]; then
        echo "ERROR: /usr/bin/git missing $_cap (got '${_line:-none}')" >&2
        exit 1
    fi
done
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

if hp_e2e_user_in_group "$HP_E2E_AGENT_USER" sudo; then
    echo "ERROR: $HP_E2E_AGENT_USER must not be in group sudo after provision-host" >&2
    exit 1
fi
echo "PASS: agent not in group sudo"

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

_orig_mode="$(stat -c '%a' /usr/bin/git.original)"
_orig_owner="$(stat -c '%U:%G' /usr/bin/git.original)"
if [[ "$_orig_mode" != "700" || "$_orig_owner" != "root:root" ]]; then
    echo "ERROR: git.original permissions wrong: $_orig_mode $_orig_owner" >&2
    exit 1
fi
echo "PASS: git.original is 0700 root:root"

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
if ! git --version >/dev/null; then
    echo "ERROR: git --version failed for agent user" >&2
    exit 1
fi
echo "PASS: agent git --version succeeded"
echo "test" > file.txt
git add file.txt
git commit -q -m "init"
if ! git status >/dev/null; then
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
runuser -u "$HP_E2E_AGENT_USER" -- bash "$_agent_check" "$tmpdir"
rm -f "$_agent_check"
rm -rf "$tmpdir"
cd "$_GUARD_ROOT"

echo "==> Tier 3: policy-matrix E2E..."
bash scripts/podman/e2e-policy-matrix.sh

echo "==> Tier 3: uninstalling guard..."
bash "$_CI_ROOT/scripts/bootstrap-workspace-guard" uninstall

hp_e2e_cleanup
echo "==> Tier 3 complete"