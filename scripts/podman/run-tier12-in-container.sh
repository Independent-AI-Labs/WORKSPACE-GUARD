#!/usr/bin/env bash
set -euo pipefail

for path in /tmp/WORKSPACE-GUARD/*; do
    [[ "$path" == /tmp/WORKSPACE-GUARD/target ]] || rm -rf "$path"
done
rm -rf /tmp/WORKSPACE-CI
mkdir -p /tmp/WORKSPACE-GUARD /tmp/WORKSPACE-CI
tar --exclude=target -cf /tmp/workspace-guard.tar -C /projects/WORKSPACE-GUARD .
tar --no-same-owner -xf /tmp/workspace-guard.tar -C /tmp/WORKSPACE-GUARD
tar --exclude=.git --exclude=.venv --exclude=node_modules -cf /tmp/workspace-ci.tar -C /projects/WORKSPACE-CI .
tar --no-same-owner -xf /tmp/workspace-ci.tar -C /tmp/WORKSPACE-CI
# The sealed artifact is not mounted into the container; the extracted
# source checkout is the CI root for all in-container make targets.
export CI_DIR=/tmp/WORKSPACE-CI
cd /tmp/WORKSPACE-GUARD
bash scripts/podman/tier1-test.sh
echo "==> Tier 2: root-only E2E"
bash scripts/podman/e2e-root-only.sh
echo "==> Tier 2b: yaml-edit root-tier E2E"
bash scripts/podman/e2e-yaml-edit.sh
