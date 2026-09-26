#!/usr/bin/env bash
set -euo pipefail

for path in /tmp/WORKSPACE-GUARD/*; do
    [[ "$path" == /tmp/WORKSPACE-GUARD/target ]] || rm -rf "$path"
done
rm -f /tmp/WORKSPACE-GUARD/target/release/workspace-binary-guard
rm -rf /tmp/WORKSPACE-CI /tmp/workspace-guard.tar /tmp/ci.tar
mkdir -p /tmp/WORKSPACE-GUARD /tmp/WORKSPACE-CI
cp /bin/bash /bin/bash.real
chmod 700 /bin/bash.real
tar --exclude=target -cf /tmp/workspace-guard.tar -C /projects/WORKSPACE-GUARD .
tar --no-same-owner -xf /tmp/workspace-guard.tar -C /tmp/WORKSPACE-GUARD
tar --exclude=.git --exclude=.venv --exclude=node_modules --exclude=.boot-linux --exclude=target -cf /tmp/ci.tar -C /projects/WORKSPACE-CI .
tar --no-same-owner -xf /tmp/ci.tar -C /tmp/WORKSPACE-CI
cd /tmp/WORKSPACE-GUARD
export CI_ROOT=/tmp/WORKSPACE-CI
CARGO_TARGET_DIR=target/agent cargo build --workspace --bins
if [ -n "${BATS_TEST_FILTER:-}" ]; then
    bats --filter "$BATS_TEST_FILTER" --timing tests/shell/
else
    bats --timing tests/shell/
fi
