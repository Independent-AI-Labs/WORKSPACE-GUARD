# Requirements: Podman-Based Linux Test Harness (macOS + Linux Hosts)

**Date:** 2026-07-11
**Status:** ACTIVE
**Type:** Requirements

---

## Background

WORKSPACE-GUARD is a **Linux-only** Rust project. It depends on Linux kernel
features that do not exist on Darwin: file capabilities (`setcap`/`getcap`),
`chattr +i`, `dpkg-divert`, and `getauxval(AT_SECURE)`. Developers on macOS
cannot run `cargo test`, `cargo clippy`, or real guard installation natively.

Today, macOS developers get PATH-faked bats tests (`make test-shell`) and
pre-commit hooks that **skip** Rust fmt/clippy/test/coverage. Linux CI runs
the full gate, but local macOS feedback is incomplete.

Podman on macOS runs containers inside a Linux VM (`podman machine`), providing
a real Linux kernel. This document specifies a **three-tier Podman test
harness** so macOS (and Linux hosts without root) can run the full quality gate
and both deployment-mode E2E sanity check tests locally.

Installation and deployment of the guard remain specified in
[REQ-GIT-GUARD](REQ-GIT-GUARD.md) and
[SPEC-GIT-GUARD-INSTALL](../specifications/SPEC-GIT-GUARD-INSTALL.md). This
document covers **verification only**.

See also [ROOT-ONLY-MODE.md](../ROOT-ONLY-MODE.md) for the root-only threat
model exercised in Tier 2.

---

## Core Requirements

### 1. Host Platform Support

- **REQ-POD-001**: The harness shall run on **macOS (Darwin)** via Podman
  Machine and on **Linux** via native Podman (rootless or rootful).
- **REQ-POD-002**: On Darwin, `make init` shall bootstrap Podman (via
  `../CI/scripts/bootstrap-podman`) and ensure a running Podman Machine.
- **REQ-POD-003**: On Darwin, the pre-push hook (`ci-check-push`) shall run
  `make test-podman` instead of skipping Linux-only checks.
- **REQ-POD-003a**: On Linux, the pre-push hook (`ci-check-push`) shall run
  `make check-push`, which includes `make test-podman-provision` (host-provision
  phases 0-4 in a privileged Podman container).
- **REQ-POD-004**: On Darwin, pre-commit hooks for `cargo-fmt`, `cargo-clippy`,
  and `verify-coverage` may remain skipped on the host; Tier 1 inside the
  container covers fmt, clippy, check, and test.

### 2. Container Image

- **REQ-POD-010**: The test image base shall be **`ubuntu:22.04`**, matching
  WORKSPACE-VM convention.
- **REQ-POD-011**: The image shall install system packages equivalent to Linux
  `make init`: `build-essential`, `pkg-config`, `git`, `curl`, `ca-certificates`,
  `libcap2-bin`, `e2fsprogs`, `file`, `bats`, `dpkg-dev`, and a stable Rust
  toolchain via rustup.
- **REQ-POD-012**: The image shall be defined in `Containerfile.test` at the
  repo root and tagged `workspace-guard-test:ubuntu-22.04` by default.

### 3. Volume Mount and Layout

- **REQ-POD-020**: Containers shall mount the `projects/` sibling directory
  (parent of WORKSPACE-GUARD and WORKSPACE-CI) at `/projects` read-write so
  `cargo` artifacts persist across runs.
- **REQ-POD-021**: Container working directory shall be
  `/projects/WORKSPACE-GUARD`.
- **REQ-POD-022**: The harness shall require `../CI` (WORKSPACE-CI) to exist;
  guard install E2E delegates to `../CI/scripts/bootstrap-workspace-guard`.

### 4. Tier 0 :  macOS Host Shell Tests

- **REQ-POD-030**: On Darwin only, `make test-podman` shall run `make
  test-shell` on the host **before** any Podman tiers. This exercises bats
  PATH fakes that do not require a Linux kernel.
- **REQ-POD-031**: On Linux hosts, Tier 0 is skipped; shell tests run inside
  Tier 1.

### 5. Tier 1 :  Non-Privileged Quality Gate

- **REQ-POD-040**: Inside an unprivileged `ubuntu:22.04` container, the harness
  shall run, in order: `make lint`, `make check`, `make test`, `make
  test-shell`, `make build-binary-guard`.
- **REQ-POD-041**: Any failure in Tier 1 shall abort the harness with a
  non-zero exit code.

### 6. Tier 2 :  Root-Only E2E (Same Container, Root)

- **REQ-POD-050**: After Tier 1 in the same container session, the harness
  shall install the guard in **root-only mode** via
  `BUILD_MODE=root-only FORCE_ROOT_ONLY=1 GUARD_NONINTERACTIVE=1` and
  `../CI/scripts/bootstrap-workspace-guard install`.
- **REQ-POD-051**: Tier 2 sanity check tests shall verify: `git status` succeeds in a
  fresh repo; `git reset --hard` is blocked. Tier 2 runs as container root:
  repo identity may be set via root-local `git config` (operator bootstrap).
  Agents never configure identity; production agents consume root-locked
  per-user `~/.gitconfig` (and SSH keys via `git-ssh-wrapper`) per
  [SPEC-GIT-IDENTITY](../specifications/SPEC-GIT-IDENTITY.md).
  Harness shall not use `GIT_AUTHOR_*` / `GIT_COMMITTER_*` env injection.
- **REQ-POD-052**: Tier 2 shall uninstall the guard (`bootstrap-workspace-guard
  uninstall`) before the container exits, leaving no installed guard on the
  host.

### 7. Tier 3 :  Capability E2E (Privileged Container)

- **REQ-POD-060**: Tier 3 shall run in a **separate** `--privileged`
  `ubuntu:22.04` container (not optional in default `make test-podman`).
- **REQ-POD-061**: Tier 3 shall create a non-root `agent` user, install the
  guard in **capability mode** (default build), and verify:
  - `getcap /usr/bin/git` shows required capabilities
  - `/usr/bin/git.original` is mode `0700` root:root
  - as `agent`: `git status` passes; `git reset --hard` is blocked
  - as `agent`: direct execution of `/usr/bin/git.original` fails
- **REQ-POD-062**: Tier 3 shall uninstall the guard before the container exits.
- **REQ-POD-063**: `make test-podman-quick` shall run Tiers 0-2 only, skipping
  Tier 3 for faster iteration.

### 8. Makefile Targets

- **REQ-POD-070**: The Makefile shall expose: `init`, `init-check`,
  `test-podman`, `test-podman-quick`, `test-podman-provision`, and `check-push`
  (the latter includes `test-podman-provision` on Linux). System packages are
  `config/system-deps.yaml` and resolved via `../CI/scripts/install-system-deps`
  (no inline `brew install` / `apt-get` in the Makefile).
- **REQ-POD-071**: The Makefile shall expose guard delegation targets matching
  WORKSPACE-CI: `build-guard`, `install-guard`, `uninstall-guard`,
  `check-guard` (via `../CI/scripts/bootstrap-workspace-guard`).
- **REQ-POD-072**: `moon.yml` task `build-guard` shall resolve via
  `make build-guard` without error.

### 9. Shell Portability

- **REQ-POD-080**: All harness scripts under `scripts/podman/` and
  `scripts/test-in-podman.sh` shall avoid bash process substitution per
  `../CI/docs/PORTABILITY.md`.
- **REQ-POD-081**: Harness scripts shall use `set -euo pipefail`.

### 10. Non-Interactive Install

- **REQ-POD-090**: `../CI/scripts/bootstrap-workspace-guard` shall honour
  `GUARD_NONINTERACTIVE=1` to skip the `[y/N]` installation prompt (required
  for container E2E).

---

## Success Criteria

1. On macOS with Podman Machine running: `make test-podman` exits 0.
2. Darwin pre-push runs `make test-podman` and blocks push on failure.
3. Tier 3 verifies real `setcap` and non-root policy enforcement inside a
   privileged container.
4. No guard binaries remain installed on the host after the harness completes
   (install/uninstall occur only inside ephemeral containers).

---

## References

- [SPEC-PODMAN-TESTING](../specifications/SPEC-PODMAN-TESTING.md): implementation
- [REQ-GIT-GUARD](REQ-GIT-GUARD.md): guard functional requirements
- [ROOT-ONLY-MODE.md](../ROOT-ONLY-MODE.md): root-only threat model
- [PORTABILITY.md](../../../CI/docs/PORTABILITY.md): shell portability