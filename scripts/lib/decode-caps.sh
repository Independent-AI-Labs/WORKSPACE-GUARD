#!/usr/bin/env bash
# decode-caps.sh: canonical live file-capability discovery. Shared by
# sync-gtfobins and suid-drift-check so both scripts consume the same
# TAB-separated "path<TAB>caps" stream from getcap and apply the same
# exclusion filter as find-suid.sh.
#
# Exposes:
#   discover_caps_live <out_file>
#     Writes TAB-separated "path<TAB>caps" rows (sorted unique) to
#     <out_file>. Each row anchors on the first ` cap_` substring of
#     the getcap line; everything before it is the file path, the
#     remainder is the capability string (with the old-format
#     "<path> = cap_*" leading ` = ` stripped). Excluded paths use the
#     same filter as discover_suid_live.
#     Returns 0 even when getcap reports permission-denied errors or
#     is absent (out_file is left empty).
#
# Requires bash 4.3+, getcap, awk, sort. If getcap is not on PATH the
# out_file is truncated to empty and the function returns 0.

: "${DEVNULL:=/dev/null}"

discover_caps_live() {
    local out_file="$1"
    : > "$out_file"
    if ! command -v getcap >"$DEVNULL" 2>&1; then
        return 0
    fi
    if ! getcap -r / 2>"$DEVNULL" | awk '
        function excluded(p) {
            if (ENVIRON["GUARD_DECODE_CAPS_INCLUDE_FIXTURE_PATHS"] != "") return 0
            if (p ~ /^\/home\//)                                  return 1
            if (p ~ /^\/var\/lib\/(containers|docker|flatpak)\//) return 1
            if (p ~ /^\/(tmp|var\/tmp|proc|sys|dev|run)\//)       return 1
            return 0
        }
        {
            i = index($0, " cap_")
            if (i == 0) next
            path = substr($0, 1, i - 1)
            if (excluded(path)) next
            caps = substr($0, i + 1)
            sub(/^ * = /, "", caps)
            print path "\t" caps
        }
    ' | sort -u > "$out_file"; then
        return 0
    fi
    return 0
}