#!/usr/bin/env bash
# REQ-EXEC-150/151 rule-disposition gate.
#
# Every rule in the shell-guard policy must have exactly one disposition in
# the rule-disposition matrix (SPEC-EXEC-POLICY section 6), so a rule cannot
# be added without a kernel/content/session classification. Fails closed when
# either input file is missing or a rule has no row.
#
# Usage: scripts/check-exec-dispositions.sh [repo-root]

set -euo pipefail

root="${1:-.}"
cd "$root"

policy="config/shell_guard_policy.yaml"
spec="docs/specifications/SPEC-EXEC-POLICY.md"

if [ ! -f "$policy" ]; then
    echo "exec-dispositions: missing $policy" >&2
    exit 1
fi
if [ ! -f "$spec" ]; then
    echo "exec-dispositions: missing $spec" >&2
    exit 1
fi

# Rule ids are the "- id: <name>" entries of the policy rule list.
if ! rules="$(grep -E '^[[:space:]]*- id:[[:space:]]*[^[:space:]]+' "$policy")"; then
    echo "exec-dispositions: no rule ids found in $policy" >&2
    exit 1
fi

total=0
missing=0
while IFS= read -r line; do
    [ -n "$line" ] || continue
    id="${line#*- id: }"
    total=$((total + 1))
    if ! grep -qF "| \`${id}\` |" "$spec"; then
        printf 'exec-dispositions: rule %s has no disposition row in %s\n' "$id" "$spec" >&2
        missing=$((missing + 1))
    fi
done <<< "$rules"

if [ "$missing" -ne 0 ]; then
    printf 'exec-dispositions: %s of %s rule(s) undisposed\n' "$missing" "$total" >&2
    exit 1
fi

printf 'exec-dispositions: all %s policy rules disposed\n' "$total"
