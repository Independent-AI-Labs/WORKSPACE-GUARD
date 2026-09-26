#!/usr/bin/env bash
# Tier 1 quality gate inside the Podman test container.
# Capability integration tests run as testagent (non-root); root-only
# integration tests run as container root. See SPEC-PODMAN-TESTING.md.
set -euo pipefail

_TESTAGENT_USER="${WORKSPACE_GUARD_TESTAGENT:-testagent}"
_TESTAGENT_UID="${WORKSPACE_GUARD_TESTAGENT_UID:-1002}"
_CARGO_BIN="/root/.cargo/bin"
_REPO_ROOT="$(pwd)"

ensure_testagent() {
    if id "$_TESTAGENT_USER"; then
        return 0
    fi
    useradd -m -u "$_TESTAGENT_UID" -s /bin/bash "$_TESTAGENT_USER"
    echo "Created user $_TESTAGENT_USER (uid $_TESTAGENT_UID)"
}

_TARGET_CHOWNED=0
_chown_target_for_testagent() {
    # Recursive chown of the target trees is expensive; only the first
    # call in a run does work, later calls are no-ops unless a build step
    # ran in between (which re-creates root-owned artifacts). The
    # privileged git-guard package has its own agent target tree.
    if [[ ! -d target && ! -d git-guard/target ]]; then
        return 0
    fi
    if [[ "$_TARGET_CHOWNED" -eq 1 ]] \
        && ! find target git-guard/target ! -user "$_TESTAGENT_USER" -print -quit | grep -q .; then
        return 0
    fi
    # Darwin Tier 0 leaves SUID fixtures here; virtiofs bind mounts reject chown on them.
    rm -rf .bats-tmp/sync-live target/.bats-sync-live
    local _t
    for _t in target git-guard/target; do
        [[ -d "$_t" ]] || continue
        chown -R "$_TESTAGENT_USER:$_TESTAGENT_USER" "$_t"
    done
    if [[ -d .bats-tmp ]]; then
        chown -R "$_TESTAGENT_USER:$_TESTAGENT_USER" .bats-tmp
    fi
    _TARGET_CHOWNED=1
}

echo "==> Tier 1: lint"
make lint

echo "==> Tier 1: check"
make check

ensure_testagent
test "$(runuser -u "$_TESTAGENT_USER" -- id -u)" = "$_TESTAGENT_UID"
_chown_target_for_testagent

# testagent cannot write /root/.cargo; the harness Makefile isolates
# Cargo caches per uid (/tmp/workspace-guard-cargo-<uid>), so the
# capability-mode phases get their own registry home.
_TESTAGENT_CARGO_HOME="/tmp/workspace-guard-cargo-${_TESTAGENT_UID}"
mkdir -p "$_TESTAGENT_CARGO_HOME"
chown -R "$_TESTAGENT_USER:$_TESTAGENT_USER" "$_TESTAGENT_CARGO_HOME"

echo "==> Tier 1: unit tests (top-level tools package)"
runuser -u "$_TESTAGENT_USER" -- bash -c "export PATH=\"${_CARGO_BIN}:\$PATH\" CARGO_HOME=\"${_TESTAGENT_CARGO_HOME}\" RUSTUP_HOME=/root/.rustup RUSTUP_TOOLCHAIN=stable; cd \"$_REPO_ROOT\" && cargo test --workspace --bins"

echo "==> Tier 1: unit tests (git-guard, capability-mode)"
runuser -u "$_TESTAGENT_USER" -- bash -c "export PATH=\"${_CARGO_BIN}:\$PATH\" CARGO_HOME=\"${_TESTAGENT_CARGO_HOME}\" RUSTUP_HOME=/root/.rustup RUSTUP_TOOLCHAIN=stable; cd \"$_REPO_ROOT/git-guard\" && cargo test --workspace --bins -- --skip no_markers_hit_neither --skip lock_scope_skips_unrelated_tmp_repo --skip run_out_of_scope_repo_yields_no_drift"

_chown_target_for_testagent

echo "==> Tier 1: integration tests (git-guard, capability-mode, as $_TESTAGENT_USER)"
runuser -u "$_TESTAGENT_USER" -- bash -c "export PATH=\"${_CARGO_BIN}:\$PATH\" CARGO_HOME=\"${_TESTAGENT_CARGO_HOME}\" RUSTUP_HOME=/root/.rustup; cd \"$_REPO_ROOT/git-guard\" && cargo test --test integration_test"

echo "==> Tier 1: integration tests (git-guard, root-only, as root)"
(cd "$_REPO_ROOT/git-guard" && cargo test --no-default-features --features root-only --test integration_test)

echo "==> Tier 1: build-binary-guard"
make build-binary-guard

echo "==> Tier 1 complete"
