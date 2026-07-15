#!/usr/bin/env bash
# Policy-matrix E2E: verify guard blocks plumbing, switch, and bypass vectors.
# Runs inside the Tier 3 container after guard install (as root + agent user).
set -euo pipefail

DEVNULL=/dev/null

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-policy-matrix.sh requires root" >&2
    exit 1
fi

_AGENT_USER="${WORKSPACE_GUARD_AGENT_USER:-agent}"
tmpdir="$(mktemp -d)"
chmod 755 "$tmpdir"
cd "$tmpdir"
git init -q
if [[ -f /projects/WORKSPACE-GUARD/config/home-lock-users.yaml ]]; then
    if ! sed -i "s/agent@example.local/policy-matrix@test.local/; s/Example Agent/Policy Matrix/" \
        /projects/WORKSPACE-GUARD/config/home-lock-users.yaml 2>"$DEVNULL"; then
        echo "WARN: home-lock-users.yaml sed skipped (optional E2E customization)" >&2
    fi
    bash /projects/WORKSPACE-GUARD/scripts/provision-user-git-identity
    bash /projects/WORKSPACE-GUARD/scripts/install-home-lock
fi
chown -R "$_AGENT_USER:$_AGENT_USER" "$tmpdir"

_agent_script="$(mktemp)"
cat > "$_agent_script" <<'EOS'
set -euo pipefail
cd "$1"
_fail=0

assert_blocked() {
    local label="$1"
    shift
    local rc=0
    "$@" >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "FAIL: $label was not blocked" >&2
        _fail=1
    else
        echo "PASS: $label blocked"
    fi
}

assert_blocked "reset --hard" git reset --hard
assert_blocked "update-ref" git update-ref refs/heads/main deadbeef
assert_blocked "read-tree --reset" git read-tree -u --reset HEAD
assert_blocked "write-tree" git write-tree
assert_blocked "symbolic-ref" git symbolic-ref HEAD refs/heads/x
assert_blocked "switch (sudo-gated)" git switch main
assert_blocked "checkout (sudo-gated)" git checkout main
assert_blocked "checkout -f" git checkout -f main
assert_blocked "checkout HEAD -- file" git checkout HEAD -- README.md
assert_blocked "checkout file" git checkout README.md
assert_blocked "restore file" git restore README.md
assert_blocked "checkout-index" git checkout-index -f -a
assert_blocked "update-index --force-remove" git update-index --force-remove stale.txt
assert_blocked "switch --discard-changes" git switch --discard-changes
assert_blocked "switch -C" git switch -C forced-branch
assert_blocked "stash drop" git stash drop
assert_blocked "push --force" git push --force origin main
assert_blocked "--hard after --" git -- --hard
assert_blocked "fetch -- --hard" git fetch -- --hard

# Alternate git bypass vector (seeded by tier3 harness).
if [[ -e /usr/local/bin/git ]]; then
    rc=0
    /usr/local/bin/git --version >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "FAIL: agent could execute /usr/local/bin/git" >&2
        _fail=1
    else
        echo "PASS: /usr/local/bin/git not executable by agent"
    fi
fi

exit "$_fail"
EOS
chmod 755 "$_agent_script"

# Seed alternate git path for bypass test (copy of real git, then lock down).
if [[ -x /usr/bin/git.original ]]; then
    _install_rc=0
    install -m 000 /usr/bin/git.original /usr/local/bin/git || _install_rc=$?
    if [[ $_install_rc -ne 0 ]]; then
        cp /usr/bin/git.original /usr/local/bin/git
        chmod 000 /usr/local/bin/git
    fi
    echo "Seeded /usr/local/bin/git (mode 000) for bypass test"
fi

su - "$_AGENT_USER" -c "bash $_agent_script $tmpdir"
rm -f "$_agent_script"
rm -rf "$tmpdir"

echo "==> e2e-policy-matrix complete"