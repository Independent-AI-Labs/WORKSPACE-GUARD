# Specification: Podman-Based Linux Test Harness

**Date:** 2026-07-11
**Status:** ACTIVE
**Type:** Specification
**Parent:** [REQ-PODMAN-TESTING](../requirements/REQ-PODMAN-TESTING.md)

---

## 1. Overview

This spec defines the **dev sanity check** layout for running WORKSPACE-GUARD's
Linux quality gate and guard-install E2E via Podman. It enables macOS developers
to iterate quickly without a dedicated Linux box.

**Authoritative** capability and policy-matrix E2E on real guest `/` runs inside
WORKSPACE-VM QEMU guests only (`make test-vm-guard`). See
[WORKSPACE-VM REQ-VM-HYPERVISOR](../../../../docs/requirements/REQ-VM-HYPERVISOR.md) §FR-7.

```
Host (Darwin or Linux)
  |
  |-- Tier 0 (Darwin only): make test-shell (bats + PATH fakes)
  |
  |-- Tier 1+2 (podman run, ubuntu:22.04, non-privileged, root inside)
  |     make lint / check / test / test-shell / build-binary-guard
  |     e2e-root-only.sh (install root-only guard, sanity check, uninstall)
  |
  |-- Tier 3 (podman run --privileged, ubuntu:22.04)
        e2e-capability.sh (install capability guard, non-root sanity check, uninstall)
```

Orchestrator: `scripts/test-in-podman.sh`

---

## 2. Files

| Path | Role |
|------|------|
| `Containerfile.test` | `FROM ubuntu:22.04`; apt + rustup toolchain |
| `scripts/test-in-podman.sh` | Top-level orchestrator |
| `scripts/podman/ensure-machine.sh` | Darwin: start Podman Machine; pull base image |
| `scripts/podman/tier1-test.sh` | Tier 1 quality gate (unit + feature-gated integration) |
| `scripts/podman/run-tier12.sh` | Non-privileged container: Tier 1 + Tier 2 |
| `scripts/podman/run-tier3.sh` | Privileged container: Tier 3 |
| `scripts/podman/e2e-root-only.sh` | Root-only install sanity check (runs inside container) |
| `scripts/podman/e2e-capability.sh` | Capability install sanity check (runs inside container) |
| `scripts/podman/e2e-policy-matrix.sh` | Policy-matrix live vectors (Tier 3, after capability install) |
| `scripts/qemu/e2e-guest.sh` | Authoritative gate orchestrator (bare QEMU guest, not container) |

---

## 3. Container Image (`Containerfile.test`)

Base: `ubuntu:22.04` (matches WORKSPACE-VM `Dockerfile.vm.j2`).

Packages (mirrors Linux `make init`):

```dockerfile
build-essential pkg-config git curl ca-certificates
libcap2-bin e2fsprogs file dpkg-dev ripgrep
bats-core v1.13.0 (install.sh /usr/local; apt bats on 22.04 is too old)
```

Rust: rustup stable minimal profile; components `clippy`, `rustfmt`.

Default tag: `workspace-guard-test:ubuntu-22.04` (overridable via
`WORKSPACE_GUARD_TEST_IMAGE`).

Build command (from repo root):

```bash
podman build -f Containerfile.test -t workspace-guard-test:ubuntu-22.04 .
```

---

## 4. Volume Mount

```text
Host:  <workspace>/projects/          -->  Container: /projects/
       ├── CI/
       └── WORKSPACE-GUARD/            -->  workdir: /projects/WORKSPACE-GUARD
```

`PROJECTS_ROOT` resolves to `$(cd "$REPO_ROOT/.." && pwd)`.

Mount flag: `-v "${PROJECTS_ROOT}:/projects:rw"`

Precondition: `test -d "${PROJECTS_ROOT}/CI/scripts/bootstrap-workspace-guard"`.

---

## 5. Podman Binary Resolution

Harness scripts resolve Podman in this order:

1. `real-podman` on `PATH` (WORKSPACE-CI boot dir wrapper bypass)
2. `podman` on `PATH` (Homebrew on Darwin, system on Linux)

Destructive commands blocked by `podman-guard` (`system reset`, `rm -a`, etc.)
are not used by this harness.

---

## 6. Tier 0 :  Darwin Host

When `uname -s` is `Darwin`, before building the image:

```bash
make test-shell
```

On Linux hosts, Tier 0 is skipped.

---

## 7. Tier 1 :  Quality Gate (Inside Container)

`scripts/podman/run-tier12.sh` runs:

```bash
podman run --rm \
  -v "${PROJECTS_ROOT}:/projects:rw" \
  -w /projects/WORKSPACE-GUARD \
  "${IMAGE}" \
  bash -c 'set -euo pipefail; bash scripts/podman/tier1-test.sh; bash scripts/podman/e2e-root-only.sh'
```

`tier1-test.sh` runs unit tests for both feature combinations, then:

- **Capability-mode integration** as non-root `testagent` (uid 1002)
- **Root-only integration** as container root
- **`make test-shell`** as `testagent` (shell tests assume non-root owner semantics)

Tier 1 does **not** prove capability-mode install properties (`setcap`,
`0700 git.original`); those are Tier 3 only.

Then invokes `e2e-root-only.sh` in the same container session (second
`podman run` is avoided by chaining in one `bash -c`).

---

## 8. Tier 2 :  Root-Only E2E

`scripts/podman/e2e-root-only.sh` (container root required):

Environment:

```bash
export BUILD_MODE=root-only
export FORCE_ROOT_ONLY=1
export GUARD_NONINTERACTIVE=1
```

Install:

```bash
bash /projects/CI/scripts/bootstrap-workspace-guard install
```

sanity check (fresh repo). Tier 2 runs as container root: repo identity may be
set with root-local `git config` (operator bootstrap). Tier 3 runs
`provision-host` (admin break-glass, agent sudo strip, per-user git/SSH,
home-lock, guard stack) before agent tests. Guard injects `GIT_CONFIG_*` from
locked `~/.gitconfig`.
Agents never run `git config` for `user.*`. Env-var injection
(`GIT_AUTHOR_*`, etc.) is never valid in harness or production paths.

```bash
tmpdir=$(mktemp -d)
cd "$tmpdir"
git init -q
git config user.email "podman@test.local"
git config user.name "Podman Test"
echo test > file.txt && git add file.txt && git commit -q -m "init"
git status          # expect success
git reset --hard    # expect failure (blocked)
```

Cleanup:

```bash
bash /projects/CI/scripts/bootstrap-workspace-guard uninstall
```

---

## 9. Tier 3 :  Capability E2E

`scripts/podman/run-tier3.sh`:

```bash
podman run --rm --privileged \
  -v "${PROJECTS_ROOT}:/projects:rw" \
  -w /projects/WORKSPACE-GUARD \
  "${IMAGE}" \
  bash scripts/podman/e2e-capability.sh
```

`scripts/podman/e2e-host-exec.sh`:

1. Create `agent` user (uid 1001) if missing; add to `sudo` (simulates fleet misconfig).
2. Copy `host-provision.yaml` / `home-lock-users.yaml` from `.example`.
3. `export GUARD_NONINTERACTIVE=1` + `WORKSPACE_ADMIN_PASSWORD`; run `provision-host`
   (admin break-glass, sudo strip, identities, guard stack).
4. Verify `getcap /usr/bin/git` includes `cap_setpcap`, `cap_chown`,
   `cap_dac_override`, `cap_fowner`, `cap_fsetid`.
5. Verify `agent` ∉ `sudo` and `/usr/lib/workspace-guard/host-provision.ok` exists.
6. As `agent`: sanity check repo (`git status` pass, `git reset --hard` blocked).
7. As `agent`: `/usr/bin/git.original` must fail (not executable).
8. `bash scripts/podman/e2e-policy-matrix.sh` (plumbing, switch, bypass vectors).
9. `bash /projects/CI/scripts/bootstrap-workspace-guard uninstall`

`--privileged` is required so `setcap` and `chattr` behave like bare metal.
This tier is a **dev sanity check**; release sign-off uses QEMU (`scripts/qemu/e2e-guest.sh`).

---

## 10. Darwin Podman Machine (`ensure-machine.sh`)

On Darwin:

1. Fail if `podman` is not on `PATH` (hint: `make init`).
2. If `podman info` fails, run `podman machine init` (if no machine exists)
   then `podman machine start`.
3. `podman pull docker.io/library/ubuntu:22.04`

On Linux: verify `podman` exists; pull base image.

---

## 11. Makefile Targets

```makefile
init:           bootstrap-homebrew + install-system-deps --install
                + bootstrap-rust + gitleaks + bootstrap-podman + ensure-machine.sh
init-check:     install-system-deps --check (config/system-deps.yaml)
test-podman:    init-check + scripts/test-in-podman.sh (all tiers)
test-podman-quick: init-check + TEST_PODMAN_QUICK=1 + scripts/test-in-podman.sh
test-podman-provision: init-check + scripts/podman/run-tier3-provision.sh (phases 0-4)
check-push:     lint + check + test + test-podman-provision (Linux pre-push)

build-guard:      bash ../CI/scripts/bootstrap-workspace-guard build-only
install-guard:    sudo bash ../CI/scripts/bootstrap-workspace-guard install-only
uninstall-guard:  sudo bash ../CI/scripts/bootstrap-workspace-guard uninstall
check-guard:      bash ../CI/scripts/bootstrap-workspace-guard check
```

`scripts/test-in-podman.sh` calls `ensure-machine.sh` at startup (machine
ready + base image pull) before Tier 0.

---

## 12. Pre-commit Integration

| Hook | Darwin behaviour | Linux behaviour |
|------|------------------|-----------------|
| `cargo-fmt` | SKIP (Tier 1 covers) | `cargo fmt --check` |
| `cargo-clippy` | SKIP (Tier 1 covers) | `cargo clippy` |
| `ci-check-push` | `make test-podman` (includes host-provision in Tier 3) | `make check-push` (includes `test-podman-provision`) |
| `verify-coverage` | SKIP (Tier 1 `make test`; coverage disabled in thresholds) | `ci_verify_coverage` |

---

## 13. `GUARD_NONINTERACTIVE` Patch

In `../CI/scripts/bootstrap-workspace-guard`, the install prompt:

```bash
if [[ -t 0 ]] && [[ "${GUARD_NONINTERACTIVE:-0}" != "1" ]]; then
    # read -r response ...
fi
```

When `GUARD_NONINTERACTIVE=1`, installation proceeds without prompting.

---

## 14. Environment Variables

| Variable | Default | Effect |
|----------|---------|--------|
| `WORKSPACE_GUARD_TEST_IMAGE` | `workspace-guard-test:ubuntu-22.04` | Image tag |
| `TEST_PODMAN_QUICK` | `0` | `1` skips Tier 3 |
| `GUARD_NONINTERACTIVE` | unset | `1` skips install prompt |
| `BUILD_MODE` | unset (capability) | `root-only` for Tier 2 |
| `FORCE_ROOT_ONLY` | unset | `1` allows root-only on multi-user |

---

## 15. Failure Modes

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `WORKSPACE-CI not found` | Missing `../CI` sibling | Clone/sync workspace repos |
| `podman: command not found` | Podman not bootstrapped | `make init` |
| `podman machine` errors (Darwin) | VM not running | `podman machine start` |
| Tier 3 `setcap` failure | Container not privileged | Ensure `run-tier3.sh` uses `--privileged` |
| Root-only refused | Non-root users in container | Set `FORCE_ROOT_ONLY=1` |