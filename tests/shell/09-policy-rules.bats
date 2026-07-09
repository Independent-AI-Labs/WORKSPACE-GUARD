#!/usr/bin/env bash
# 09-policy-rules.bats: structural validation of
# config/binary-policy-rules.yaml. Verifies the rule ordering, policy
# validity, tag-AND-name matching contract, and that the catch-all at
# the tail covers all remaining GTFOBins entries. These are pure
# config checks (no script execution).

load lib/harness

setup()    { guard_setup; }
teardown() { guard_teardown; }

RULES="$GUARD_ROOT/config/binary-policy-rules.yaml"

@test "policy-rules: file exists" {
    [ -f "$RULES" ]
}

@test "policy-rules: starts with version: 1" {
    head -n1 "$RULES" | grep -q 'version: 1' \
        || grep -q '^version: 1' "$RULES"
}

@test "policy-rules: has rules: top-level key" {
    grep -q '^rules:' "$RULES"
}

@test "policy-rules: sudo rule has arg-validate policy" {
    awk '/^  - name: sudo/{c=1} c && /policy:/{print; exit}' "$RULES" \
        | grep -q 'arg-validate'
}

@test "policy-rules: sudo rule has reject_patterns for Baron Samedit" {
    awk '/^  - name: sudo/{c=1} c && /CVE-2021-3156/{found=1} END{exit !found}' "$RULES"
}

@test "policy-rules: sudo rule rejects -R (chroot LPE CVE-2025-32463)" {
    awk '/^  - name: sudo/{c=1} c && /CVE-2025-32463/{found=1} END{exit !found}' "$RULES"
}

@test "policy-rules: pkexec rule has deny-all-non-root" {
    awk '/^  - name: pkexec/{c=1} c && /policy:/{print; exit}' "$RULES" \
        | grep -q 'deny-all-non-root'
}

@test "policy-rules: passwd rule has allow_self_username: true" {
    awk '/^  - name: passwd/{c=1} c && /allow_self_username:/{print; exit}' "$RULES" \
        | grep -q 'true'
}

@test "policy-rules: tag catch-all [suid] has deny-non-root" {
    # Tag catch-all entries have no name: field. Find the suid tag rule.
    awk '/tags:.*suid/ && !/name:/{print; exit}' "$RULES" \
        | grep -q 'suid'
    awk '/tags:.*suid/ && !/name:/{c=1} c && /policy:/{print; exit}' "$RULES" \
        | grep -q 'deny-non-root'
}

@test "policy-rules: tag catch-all [cap] has deny-non-root" {
    awk '/tags:.*cap/ && !/name:/{c=1} c && /policy:/{print; exit}' "$RULES" \
        | grep -q 'deny-non-root'
}

@test "policy-rules: final catch-all name: \"*\" has deny-all-non-root" {
    awk '/name: "\*"/{c=1} c && /policy:/{print; exit}' "$RULES" \
        | grep -q 'deny-all-non-root'
}

@test "policy-rules: all policies are from the valid set" {
    local p
    while IFS= read -r p; do
        case "$p" in
            deny-non-root|deny-all-non-root|arg-validate|pass-through) ;;
            *) echo "unknown policy: $p" >&2; return 1 ;;
        esac
    done < <(awk '/^    policy:/ && !/^#/{gsub(/.*policy: */,""); gsub(/[[:space:]].*/,""); print}' "$RULES")
}

@test "policy-rules: name rules appear before tag catch-alls" {
    # The first tag-only rule (no name:) should appear AFTER the last
    # explicit name rule (name: starts with a lowercase letter, not "*").
    local last_name_line first_tag_line
    last_name_line="$(awk '/^  - name: [a-z]/{print NR}' "$RULES" | tail -1)"
    first_tag_line="$(awk '/^  - tags:/ && !/name:/{print NR; exit}' "$RULES")"
    [ -n "$last_name_line" ] && [ -n "$first_tag_line" ]
    [ "$last_name_line" -lt "$first_tag_line" ]
}

@test "policy-rules: env_sanitise entries are uppercase identifiers" {
    local ok=1
    # Extract env var names from both inline (env_sanitise: [A, B]) and
    # block list forms (- A), skipping comment lines and empty values.
    awk '
        !/^#/ && /env_sanitise:/ {
            s=$0; sub(/.*env_sanitise: */, "", s); gsub(/[\[\]]/, "", s)
            n=split(s, a, /, */)
            for (i=1; i<=n; i++) {
                v=a[i]; gsub(/[" ]/, "", v)
                if (v=="" || v ~ /^[A-Z][A-Z0-9_]*$/) continue
                print "BAD:"v
            }
        }
        !/^#/ && /^      - / && !/env_sanitise/ && in_es {
            v=$2; if (v!="" && v !~ /^[A-Z][A-Z0-9_]*$/) print "BAD:"v
        }
        /^    env_sanitise:/ { in_es=1; next }
        /^    [a-z]/ { in_es=0 }
    ' "$RULES" | grep -q BAD && ok=0
    [ "$ok" -eq 1 ]
}

@test "policy-rules: sudo env_sanitise includes GCONV_PATH" {
    # Capture all lines from name: sudo until the next rule entry, then
    # search for GCONV_PATH (works with both inline and block forms).
    awk '/^  - name: sudo/{c=1; next} /^  - /{c=0} c' "$RULES" \
        | grep -q 'GCONV_PATH'
}

@test "policy-rules: newuidmap and newgidmap have empty tags" {
    awk '/^  - name: newuidmap/{c=1} c && /tags:/{print; exit}' "$RULES" \
        | grep -q '\[\]'
    awk '/^  - name: newgidmap/{c=1} c && /tags:/{print; exit}' "$RULES" \
        | grep -q '\[\]'
}