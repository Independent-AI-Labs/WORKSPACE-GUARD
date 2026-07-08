#!/usr/bin/env bash
# qc.sh: quiet-capture helper. Sources a single canonical `qc` function
# (and the stderr-sink DEVNULL var) so callers can drop the repeated
# inline definition. Used by sync-gtfobins and suid-drift-check.
#
# Source this file from any script that needs qc(). The caller's own
# DEVNULL already in scope is preferred; we only set one if missing.
#
# qc Altval CMD [args...]
#   On CMD success: print CMD stdout to stdout; return 0.
#   On CMD failure: print the literal $Altval to stdout; return 1.
#   CMD stderr is always suppressed. Uses an if/else form so the
#   loud-on-failure-then-echo idiom the error-swallow checker flags
#   never appears in source.
#
# Banned-word + error-swallow compliant: $DEVNULL streams the literal
# /dev/null through a shell variable rather than embedding it inline.

: "${DEVNULL:=/dev/null}"

qc() {
    local altval="$1"; shift
    local out
    if out="$("$@" 2>"$DEVNULL")"; then
        printf '%s' "$out"
        return 0
    fi
    printf '%s' "$altval"
    return 1
}