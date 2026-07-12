#!/usr/bin/env bash
# Tier 3: capability-mode guard install sanity check test (privileged container, root).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-capability.sh requires root (container root)" >&2
    exit 1
fi

_CI_ROOT="/projects/CI"
_AGENT_USER="agent"
_AGENT_UID="1001"

if [[ ! -f "$_CI_ROOT/scripts/bootstrap-workspace-guard" ]]; then
    echo "ERROR: bootstrap-workspace-guard not found at $_CI_ROOT" >&2
    exit 1
fi

if ! id "$_AGENT_USER" >/dev/null 2>&1; then
    useradd -m -u "$_AGENT_UID" -s /bin/bash "$_AGENT_USER"
    echo "Created user $_AGENT_USER (uid $_AGENT_UID)"
fi

unset BUILD_MODE
export GUARD_NONINTERACTIVE=1

echo "==> Tier 3: installing guard (capability mode)..."
bash "$_CI_ROOT/scripts/bootstrap-workspace-guard" install

echo "==> Tier 3: verifying installation..."
if ! command -v getcap >/dev/null 2>&1; then
    echo "ERROR: getcap not available" >&2
    exit 1
fi

_gc_err="$(mktemp)"
_gc_out=""
_gc_rc=0
_gc_out="$(getcap /usr/bin/git 2>"$_gc_err")" || _gc_rc=$?
if [[ $_gc_rc -ne 0 ]]; then
    echo "ERROR: getcap failed: $(cat "$_gc_err")" >&2
    rm -f "$_gc_err"
    exit 1
fi
rm -f "$_gc_err"

for _cap in cap_setpcap cap_chown cap_dac_override cap_fowner cap_fsetid; do
    if ! echo "$_gc_out" | grep -q "$_cap"; then
        echo "ERROR: missing capability $_cap on /usr/bin/git" >&2
        echo "getcap output: $_gc_out" >&2
        exit 1
    fi
done
echo "PASS: file capabilities present"

_orig_mode="$(stat -c '%a' /usr/bin/git.original)"
_orig_owner="$(stat -c '%U:%G' /usr/bin/git.original)"
if [[ "$_orig_mode" != "700" || "$_orig_owner" != "root:root" ]]; then
    echo "ERROR: git.original permissions wrong: $_orig_mode $_orig_owner" >&2
    exit 1
fi
echo "PASS: git.original is 0700 root:root"

echo "==> Tier 3: sanity check tests as $_AGENT_USER..."
tmpdir="$(mktemp -d)"
chmod 755 "$tmpdir"
cd "$tmpdir"
git init -q
# ALWAYS: root runs `sudo git config` before agent sanity check (sudo-gated keys).
# Never GIT_AUTHOR_* env injection or plain git config.
sudo git config user.email "podman-cap@test.local"
sudo git config user.name "Podman Capability"
chown -R "$_AGENT_USER:$_AGENT_USER" "$tmpdir"

_agent_check="$(mktemp)"
cat > "$_agent_check" <<'EOS'
set -euo pipefail
cd "$1"
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
su - "$_AGENT_USER" -c "bash $_agent_check $tmpdir"
rm -f "$_agent_check"
rm -rf "$tmpdir"
cd /projects/WORKSPACE-GUARD

echo "==> Tier 3: policy-matrix E2E..."
bash scripts/podman/e2e-policy-matrix.sh

echo "==> Tier 3: uninstalling guard..."
bash "$_CI_ROOT/scripts/bootstrap-workspace-guard" uninstall

echo "==> Tier 3 complete"