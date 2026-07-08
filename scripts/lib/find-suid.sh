#!/usr/bin/env bash
# find-suid.sh: canonical live-SUID discovery. Used by sync-gtfobins
# and suid-drift-check so both scripts share the exact same exclusion
# filter (drift-class bugs would diverge otherwise).
#
# Exposes:
#   discover_suid_live <out_file>
#     Writes the sorted unique SUID paths (one per line) to <out_file>.
#     Returns 0 even when `find` reports permission-denied errors
#     (the partial result is still written). Caller can detect
#     emptiness via `wc -l`.
#
# Exclusion list: container overlay roots (${HOME} of caller,
# /var/lib/{containers,docker,flatpak}), transient mounts (/tmp,
# /var/tmp), and pseudo-filesystems (/proc /sys /dev /run). /snap
# squashfs layers are KEPT for audit awareness.
#
# Requires bash 4.3+, find, sort.

: "${DEVNULL:=/dev/null}"

discover_suid_live() {
    local out_file="$1"
    if ! find / -xdev -perm -4000 -type f \
        -not -path "${HOME}/*" \
        -not -path '/var/lib/containers/*' \
        -not -path '/var/lib/docker/*' \
        -not -path '/var/lib/flatpak/*' \
        -not -path '/tmp/*' \
        -not -path '/var/tmp/*' \
        -not -path '/proc/*' \
        -not -path '/sys/*' \
        -not -path '/dev/*' \
        -not -path '/run/*' \
        2>"$DEVNULL" | sort > "$out_file"; then
        return 0
    fi
    return 0
}