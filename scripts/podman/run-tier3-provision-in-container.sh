#!/usr/bin/env bash
# In-container driver for the host-provision E2E (invoked by run-tier3-provision.sh).
set -euo pipefail

_e2e_script="${1:?usage: run-tier3-provision-in-container.sh <e2e-script-name>}"

bash /projects/WORKSPACE-GUARD/scripts/podman/lib/prepare-isolated-workspace.sh
export GUARD_ROOT=/tmp/WORKSPACE-GUARD _GUARD_ROOT=/tmp/WORKSPACE-GUARD CI_ROOT=/tmp/WORKSPACE-CI
cd "$GUARD_ROOT"
bash "scripts/podman/${_e2e_script}"