#!/usr/bin/env bash
set -euo pipefail

: "${PROJECTS_ROOT:=/projects}"
: "${ISOLATED_ROOT:=/tmp}"

for path in "$ISOLATED_ROOT"/WORKSPACE-GUARD/*; do
    [[ "$path" == "$ISOLATED_ROOT/WORKSPACE-GUARD/target" ]] || rm -rf "$path"
done
rm -rf "$ISOLATED_ROOT/WORKSPACE-CI"
mkdir -p "$ISOLATED_ROOT/WORKSPACE-GUARD" "$ISOLATED_ROOT/WORKSPACE-CI"
tar --exclude=target -cf "$ISOLATED_ROOT/workspace-guard.tar" -C "$PROJECTS_ROOT/WORKSPACE-GUARD" .
tar --no-same-owner -xf "$ISOLATED_ROOT/workspace-guard.tar" -C "$ISOLATED_ROOT/WORKSPACE-GUARD"
tar --exclude=.git --exclude=.venv --exclude=node_modules --exclude=.boot-linux -cf "$ISOLATED_ROOT/workspace-ci.tar" -C "$PROJECTS_ROOT/WORKSPACE-CI" .
tar --no-same-owner -xf "$ISOLATED_ROOT/workspace-ci.tar" -C "$ISOLATED_ROOT/WORKSPACE-CI"
