#!/usr/bin/env bash
set -euo pipefail

SCRIPT_SOURCE="${SHG_SCRIPT_PATH:-${BASH_SOURCE[0]}}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$SCRIPT_SOURCE")")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECTS_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
IMAGE="${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04}"

if [ -x "$PROJECTS_ROOT/CI/.boot-linux/bin/real-podman" ]; then
    PODMAN="$PROJECTS_ROOT/CI/.boot-linux/bin/real-podman"
elif command -v real-podman; then
    PODMAN=real-podman
elif command -v podman; then
    PODMAN=podman
else
    echo "ERROR: podman is required for non-root shell tests" >&2
    exit 1
fi

"$PODMAN" build -f "$REPO_ROOT/Containerfile.test" -t "$IMAGE" "$REPO_ROOT"

"$PODMAN" run --rm \
    -v "$PROJECTS_ROOT:/projects:ro" \
    -e BATS_TEST_FILTER="${BATS_TEST_FILTER:-}" \
    "$IMAGE" \
    bash -c 'set -euo pipefail; rm -rf /tmp/WORKSPACE-GUARD /tmp/CI /tmp/workspace-guard.tar /tmp/ci.tar; mkdir /tmp/WORKSPACE-GUARD /tmp/CI; cp /bin/bash /bin/bash.real; chmod 700 /bin/bash.real; tar --exclude=target -cf /tmp/workspace-guard.tar -C /projects/WORKSPACE-GUARD .; tar --no-same-owner -xf /tmp/workspace-guard.tar -C /tmp/WORKSPACE-GUARD; tar --exclude=.git --exclude=.venv --exclude=node_modules --exclude=.boot-linux -cf /tmp/ci.tar -C /projects/WORKSPACE-CI .; tar --no-same-owner -xf /tmp/ci.tar -C /tmp/CI; cd /tmp/WORKSPACE-GUARD; CARGO_TARGET_DIR=target/agent cargo build --workspace --bins; if [ -n "$BATS_TEST_FILTER" ]; then bats --filter "$BATS_TEST_FILTER" --timing tests/shell/; else bats --timing tests/shell/; fi'
