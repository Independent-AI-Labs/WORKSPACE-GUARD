#!/usr/bin/env bash
# REQ-GGUARD-121 mechanical boundary gate.
#
# Production unsafe Rust and direct libc usage are confined to one reviewed
# module per binary crate, plus the raw-fork test modules. This scan fails if
# any other tracked Rust file introduces an unsafe block, an unsafe
# function/trait/impl, inline assembly, or a direct libc call.
#
# Usage: scripts/check-unsafe-boundary.sh [repo-root]

set -euo pipefail

root="${1:-.}"
cd "$root"

# Reviewed carriers. Keep this list minimal and shrink it, never grow it,
# without a matching requirement change.
allowed=(
    "git-guard/src/linux_ffi.rs"
    "git-guard/src/exec_tests.rs"
    "git-guard/tests/integration_test.rs"
    # Temporary deviation tracked by REQ-GGUARD-121: shell_guard still owns
    # its immutable-flag ioctl until the shared reviewed wrapper lands.
    "src/shell_guard/main.rs"
)

pattern='unsafe[[:space:]]*\{|unsafe[[:space:]]+fn|unsafe[[:space:]]+trait|unsafe[[:space:]]+impl|(^|[^_[:alnum:]])asm!|global_asm!|libc::[a-z_][a-z_0-9]*\('

if ! hits="$(grep -rnE "$pattern" --include='*.rs' --exclude-dir=target --exclude-dir=.git .)"; then
    hits=""
fi

status=0
while IFS= read -r line; do
    [ -n "$line" ] || continue
    file="${line#./}"
    file="${file%%:*}"
    permitted=0
    for a in "${allowed[@]}"; do
        if [ "$file" = "$a" ]; then
            permitted=1
        fi
    done
    if [ "$permitted" -eq 0 ]; then
        printf 'unsafe-boundary: %s\n' "$line" >&2
        status=1
    fi
done <<< "$hits"

if [ "$status" -ne 0 ]; then
    echo "unsafe-boundary: unsafe or direct libc usage outside the reviewed module(s)" >&2
    exit 1
fi

echo "unsafe-boundary: OK"
