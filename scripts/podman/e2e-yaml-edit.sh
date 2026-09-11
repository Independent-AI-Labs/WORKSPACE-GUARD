#!/usr/bin/env bash
# Tier 2b: workspace-yaml-edit root-tier E2E (runs inside the test
# container as root, after e2e-root-only.sh). Exercises the real
# mutation path that non-root tiers cannot reach: root gate passes,
# install via temp+rename, ownership preserved, chattr immutable flag
# detected and restored (when the container filesystem supports it),
# schema fail-closed behavior, symlink and ownership refusals, the
# global flock, and the audit log.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-yaml-edit.sh requires root (container root)" >&2
    exit 1
fi

_GUARD_ROOT="$(pwd)"
cd "$_GUARD_ROOT"

export PATH="/root/.cargo/bin:$PATH"

YE="$_GUARD_ROOT/target/debug/workspace-yaml-edit"
echo "==> Tier 2b: building current workspace-yaml-edit (debug)"
CARGO_TARGET_DIR="$_GUARD_ROOT/target" cargo build --bin workspace-yaml-edit
if [[ ! -x "$YE" ]]; then
    echo "ERROR: workspace-yaml-edit binary not found at $YE" >&2
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

Q="$TMP/quality_exceptions.yaml"
cat > "$Q" <<'EOF'
# quality gate exemptions
policy_version: 2
exceptions: []
EOF

COV="$TMP/coverage_thresholds.yaml"
cat > "$COV" <<'EOF'
coverage_thresholds:
  version: 2
  min_coverage: 90
  timeout: 300
EOF

CHATTR_OK=0
if _chattr_out="$(chattr +i "$Q" 2>&1)"; then
    CHATTR_OK=1
    echo "==> Tier 2b: chattr supported; immutable-flag preservation is tested"
else
    echo "==> Tier 2b: chattr unsupported here ($_chattr_out); flag test skipped"
fi

pass() { echo "PASS: $1"; }
die() { echo "ERROR: $1" >&2; exit 1; }

expect_rc() {
    local want="$1"; shift
    local got=0
    "$@" || got=$?
    if [[ "$got" -ne "$want" ]]; then
        echo "ERROR: expected exit $want, got $got: $*" >&2
        exit 1
    fi
}

echo "==> Tier 2b: add entry (immutable flag must survive)"
expect_rc 0 "$YE" add "$Q" exceptions hook=quality added_by=tier2 \
    "reason=podman root-tier coverage, safe to remove" "paths=[src/x.py]"
grep -q "hook: quality" "$Q" || die "entry missing after add"
grep -q -- "- src/x.py" "$Q" || die "paths item missing after add"
[[ "$(stat -c '%U:%G' "$Q")" == "root:root" ]] || die "ownership changed"
if [[ "$CHATTR_OK" -eq 1 ]]; then
    lsattr -d "$Q" | awk '{print $1}' | grep -q 'i' \
        || die "immutable flag lost after add"
fi
pass "add installs atomically and preserves ownership and flags"

echo "==> Tier 2b: duplicate add exits 4"
expect_rc 4 "$YE" add "$Q" exceptions hook=quality added_by=tier2 \
    "reason=podman root-tier coverage, safe to remove" "paths=[src/x.py]"
pass "duplicate add refused with exit 4"

echo "==> Tier 2b: schema-invalid add exits 1 and changes nothing"
before="$(cat "$Q")"
expect_rc 1 "$YE" add "$Q" exceptions hook=quality added_by=tier2 \
    reason=short "paths=[src/y.py]"
[[ "$(cat "$Q")" == "$before" ]] || die "file changed on schema failure"
pass "schema failure is fail-closed"

echo "==> Tier 2b: remove, no-match, --allow-no-match"
expect_rc 0 "$YE" remove "$Q" exceptions hook=quality
grep -q "hook: quality" "$Q" && die "entry still present after remove"
expect_rc 3 "$YE" remove "$Q" exceptions hook=quality
expect_rc 0 "$YE" remove "$Q" exceptions hook=quality --allow-no-match
pass "remove matrix ok"

echo "==> Tier 2b: set scalar with numeric schema"
expect_rc 0 "$YE" set "$COV" coverage_thresholds.min_coverage 95
[[ "$("$YE" get "$COV" coverage_thresholds.min_coverage)" == "95" ]] \
    || die "get disagrees after set"
expect_rc 1 "$YE" set "$COV" coverage_thresholds.min_coverage 95 --string
pass "set/get with numeric schema ok, string typing refused"

echo "==> Tier 2b: unset and exact comment removal"
HOOKS="$TMP/hooks.yaml"
cat > "$HOOKS" <<'EOF'
# Retired tier
hooks:
  - id: one
    safety: true
    mandatory: true
  - id: two
    safety: false
    mandatory: false
EOF
chmod 0600 "$HOOKS"
expect_rc 0 "$YE" unset "$HOOKS" 'hooks[].safety'
grep -q 'safety:' "$HOOKS" && die "unset field remains"
[[ "$(stat -c '%u:%g:%a' "$HOOKS")" == "0:0:600" ]] \
    || die "owner/group/mode changed after unset"
expect_rc 0 "$YE" remove-comment "$HOOKS" 'Retired tier'
grep -q 'Retired tier' "$HOOKS" && die "exact comment remains"
[[ "$(tail -c 1 "$HOOKS" | od -An -t x1 | tr -d ' ')" == "0a" ]] \
    || die "mutation lacks one terminal newline"
[[ "$(tail -c 2 "$HOOKS" | od -An -t x1 | tr -d ' \n')" != "0a0a" ]] \
    || die "mutation introduced a blank EOF line"
pass "unset/comment preserve metadata and terminal newline"

echo "==> Tier 2b: guarded deletion"
DEL="$TMP/delete.yaml"
printf 'value: 1\n' > "$DEL"
digest="$(sha256sum "$DEL" | cut -d' ' -f1)"
expect_rc 1 "$YE" delete "$DEL" --expected-sha256 \
    0000000000000000000000000000000000000000000000000000000000000000
[[ -f "$DEL" ]] || die "digest mismatch deleted file"
mkdir "$TMP/delete-dir"
expect_rc 2 "$YE" delete "$TMP/delete-dir" --expected-sha256 "$digest"
ln -s "$DEL" "$TMP/delete-link.yaml"
expect_rc 2 "$YE" delete "$TMP/delete-link.yaml" --expected-sha256 "$digest"
expect_rc 0 "$YE" delete "$DEL" --expected-sha256 "$digest"
[[ ! -e "$DEL" ]] || die "verified file was not deleted"
pass "guarded deletion rejects mismatch/symlink/directory and accepts digest"

echo "==> Tier 2b: symlink and ownership refusals"
ln -s "$Q" "$TMP/link.yaml"
expect_rc 2 "$YE" add "$TMP/link.yaml" exceptions hook=x "paths=[a]"
OTHER="$TMP/other.yaml"
cp "$Q" "$OTHER"
if _id_out="$(id testagent 2>&1)"; then
    chown testagent:testagent "$OTHER"
    expect_rc 2 "$YE" add "$OTHER" exceptions hook=x "paths=[a]"
    pass "non-root-owned file refused"
else
    echo "NOTICE: testagent user absent ($_id_out); ownership refusal covered by bats"
fi
pass "symlink refused"

echo "==> Tier 2b: audit log and flock artifacts"
LOG="/root/.workspace-guard.log"
grep -q "yaml-edit add" "$LOG" || die "audit line missing in $LOG"
grep -q "file=$Q" "$LOG" || die "audit line lacks target file"
[[ -f /var/lib/workspace-guard/yaml-edit.lock ]] || die "lock file missing"
[[ "$(stat -c '%a' /var/lib/workspace-guard)" == "700" ]] \
    || die "lock dir mode is not 700"
pass "audit log and flock artifacts ok"

echo "==> Tier 2b complete"
