#!/usr/bin/env bash
# Tier 1 quality gate inside the Podman test container.
# Capability integration tests run as testagent (non-root); root-only
# integration tests run as container root. See SPEC-PODMAN-TESTING.md.
set -euo pipefail

_TESTAGENT_USER="${WORKSPACE_GUARD_TESTAGENT:-testagent}"
_TESTAGENT_UID="${WORKSPACE_GUARD_TESTAGENT_UID:-1002}"
_CARGO_BIN="/root/.cargo/bin"

ensure_testagent() {
    if id "$_TESTAGENT_USER" >/dev/null 2>&1; then
        return 0
    fi
    useradd -m -u "$_TESTAGENT_UID" -s /bin/bash "$_TESTAGENT_USER"
    echo "Created user $_TESTAGENT_USER (uid $_TESTAGENT_UID)"
}

_chown_target_for_testagent() {
    if [[ ! -d target ]]; then
        return 0
    fi
    # Darwin Tier 0 leaves SUID fixtures here; virtiofs bind mounts reject chown on them.
    rm -rf target/.bats-sync-live
    chown -R "$_TESTAGENT_USER:$_TESTAGENT_USER" target
}

echo "==> Tier 1: lint"
make lint

echo "==> Tier 1: check"
make check

echo "==> Tier 1: unit tests (capability-mode)"
cargo test --workspace --bins

echo "==> Tier 1: unit tests (root-only)"
cargo test --no-default-features --features root-only --bins

ensure_testagent
_chown_target_for_testagent

echo "==> Tier 1: integration tests (capability-mode, as $_TESTAGENT_USER)"
su "$_TESTAGENT_USER" -c "export PATH=\"${_CARGO_BIN}:\$PATH\" CARGO_HOME=/root/.cargo RUSTUP_HOME=/root/.rustup; cd /projects/WORKSPACE-GUARD && cargo test --test integration_test"

echo "==> Tier 1: integration tests (root-only, as root)"
cargo test --no-default-features --features root-only --test integration_test

echo "==> Tier 1: test-shell (as $_TESTAGENT_USER)"
_chown_target_for_testagent
su "$_TESTAGENT_USER" -c "export PATH=\"${_CARGO_BIN}:\$PATH\"; cd /projects/WORKSPACE-GUARD && make test-shell"

echo "==> Tier 1: build-binary-guard"
make build-binary-guard

echo "==> Tier 1 complete"