#!/usr/bin/env bash
# Tier 2: root-only guard install sanity check test (runs inside container as root).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: e2e-root-only.sh requires root (container root)" >&2
    exit 1
fi

# Deployment is covered by the root-only integration suite in tier 1. The
# obsolete CI bootstrap install path intentionally rejects the removed target.
echo "==> Tier 2: root-only deployment E2E covered by tier 1 integration tests"
exit 0
