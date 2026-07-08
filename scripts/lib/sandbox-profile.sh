#!/usr/bin/env bash
# sandbox-profile.sh: first-match-wins hostname -> profile selector.
# Refactored from the inline awk in the Makefile sandbox-check
# target so the same algorithm is exercisable by both the Makefile
# and the bats suite.
#
# Exposes:
#   select_profile <hostname> <profiles_yaml>
#     Prints the chosen profile name (rootless|gvisor|firecracker)
#     for <hostname> by reading <profiles_yaml>: iterate entries in
#     declared order, the first whose `pattern:` regex matches the
#     hostname wins; return 0.
#     Returns 1 if <profiles_yaml> is missing or empty.
#     Returns 2 if file exists but yields no match (no catches).

: "${DEVNULL:=/dev/null}"

select_profile() {
    local hostname="$1" profiles_yaml="$2"
    if [[ ! -s "$profiles_yaml" ]]; then return 1; fi
    local sel
    sel="$(awk -v h="$hostname" '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*-[[:space:]]*pattern:/ {
            line=$0; sub(/^[^:]*:[[:space:]]*/,"",line); gsub(/"/,"",line)
            pat=line
            in_block=1
            next
        }
        in_block && /^[[:space:]]+[[:space:]]*profile:/ {
            line=$0; sub(/^[^:]*:[[:space:]]*/,"",line); gsub(/"/,"",line)
            sub(/[[:space:]]*#.*$/,"",line)
            prof=line
            if (h ~ pat) { print prof; exit 0 }
        }
        /^[[:space:]]*$/ { in_block=0 }
    ' "$profiles_yaml")"
    if [[ -z "$sel" ]]; then return 2; fi
    printf '%s\n' "$sel"
    return 0
}