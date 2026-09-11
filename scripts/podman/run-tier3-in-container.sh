#!/usr/bin/env bash
set -euo pipefail

for path in /tmp/WORKSPACE-GUARD/*; do
    [[ "$path" == /tmp/WORKSPACE-GUARD/target ]] || rm -rf "$path"
done
bash /projects/WORKSPACE-GUARD/scripts/podman/lib/prepare-isolated-workspace.sh
export GUARD_ROOT=/tmp/WORKSPACE-GUARD _GUARD_ROOT=/tmp/WORKSPACE-GUARD CI_ROOT=/tmp/WORKSPACE-CI
cd "$GUARD_ROOT"
bash scripts/podman/e2e-host-exec.sh
