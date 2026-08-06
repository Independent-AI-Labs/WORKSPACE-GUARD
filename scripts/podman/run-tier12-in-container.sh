#!/usr/bin/env bash
set -euo pipefail

for path in /tmp/WORKSPACE-GUARD/*; do
    [[ "$path" == /tmp/WORKSPACE-GUARD/target ]] || rm -rf "$path"
done
rm -rf /tmp/CI
mkdir -p /tmp/WORKSPACE-GUARD /tmp/CI
tar --exclude=target -cf /tmp/workspace-guard.tar -C /projects/WORKSPACE-GUARD .
tar --no-same-owner -xf /tmp/workspace-guard.tar -C /tmp/WORKSPACE-GUARD
tar --exclude=.git --exclude=.venv --exclude=node_modules -cf /tmp/workspace-ci.tar -C /projects/CI .
tar --no-same-owner -xf /tmp/workspace-ci.tar -C /tmp/CI
cd /tmp/WORKSPACE-GUARD
bash scripts/podman/tier1-test.sh
echo "==> Tier 2: root-only E2E"
bash scripts/podman/e2e-root-only.sh
echo "==> Tier 2b: yaml-edit root-tier E2E"
bash scripts/podman/e2e-yaml-edit.sh
