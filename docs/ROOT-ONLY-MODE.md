# Root-Only Mode: WORKSPACE-GUARD

**Date:** 2026-06-24
**Status:** ACTIVE
**Type:** Operational Documentation

---

## Overview

Root-only mode is a compile-time feature flag (`--features root-only`) that
allows the guard to run without Linux file capabilities. It is designed for
environments where `setcap`, `chattr +i`, and `dpkg-divert` are unavailable:

- PRoot / PRoot-Distro (Android host, ptrace-based emulation)
- User namespaces without `CAP_SYS_ADMIN`
- Containers where the runtime is already root and capabilities are not
  meaningful (e.g., Docker `--user 0` without `--cap-add`)

## Threat Model

### What Root-Only Mode Protects Against

| Threat | Protected? | Mechanism |
|--------|-----------|-----------|
| Accidental `git reset --hard` | Yes | Guard intercepts at `/usr/bin/git` |
| Accidental `git push --force` | Yes | Guard blocks before exec |
| CI agent running destructive git | Yes | Guard policy engine applies |
| Adversarial agent trying `git reset` | Yes (soft) | Guard blocks, but bypass is possible |
| Adversarial agent with root access | No | Root can bypass the guard entirely |

### What Root-Only Mode Does NOT Protect Against

1. **Direct execution of the original git binary**: In capability mode,
   the backup is mode 0700 root:root: only root can execute it. In
   root-only mode, the user IS root, so they can bypass the guard
   entirely by invoking the original binary directly.

2. **PATH manipulation**: A root user can install a git binary anywhere in
   PATH, or modify PATH to skip `/usr/bin/git`.

3. **Binary replacement**: A root user can replace `/usr/bin/git` with the
   original git binary, or remove the guard entirely.

### Comparison to Capability Mode

| Property | Capability Mode | Root-Only Mode |
|----------|----------------|----------------|
| Requires file capabilities | Yes (`CAP_DAC_OVERRIDE`) | No |
| Requires `setcap` | Yes | No |
| Requires `chattr +i` | Yes (recommended) | No |
| Requires `dpkg-divert` | Yes | No |
| Backup binary accessible to user | No (mode 0700, root-only) | Yes (user is root) |
| Bypass resistance | High (requires root + cap manipulation) | Low (root can bypass) |
| Suitable for production | Yes | No (soft barrier only) |
| Suitable for PRoot/containers | No (no setcap) | Yes (soft barrier) |

## Build Commands

```bash
# Root-only mode (default features disabled)
cargo build --release --no-default-features --features root-only

# Capability mode (default)
cargo build --release
```

## Installation in Root-Only Mode

Root-only mode uses a simplified installation: no `setcap`, no `chattr`,
no `dpkg-divert`:

```bash
# Build
cargo build --release --no-default-features --features root-only

# Install (as root)
cp target/release/workspace-guard /usr/bin/git.guard
mv /usr/bin/git /usr/bin/git.original
ln -s /usr/bin/git.guard /usr/bin/git
chmod 0755 /usr/bin/git.guard /usr/bin/git.original
```

Or via the Makefile:

```bash
make build-guard          # records build mode in .mode marker
BUILD_MODE=root-only make build-guard   # explicit root-only build
make install-guard-host-exec   # capability build only; root-only uses separate CI paths
```

Root-only installation does not use `install-guard-host-exec`. Build with
`BUILD_MODE=root-only` and install via documented Podman Tier 2 / PRoot paths only.

## Runtime Behavior

When built with `root-only`, the guard:

1. Skips the `CAP_DAC_OVERRIDE` capability check
2. Prints a notice to stderr on every invocation:
   ```
   [workspace-guard] running in root-only mode (soft barrier).
     See docs/ROOT-ONLY-MODE.md for threat model and limitations.
   ```
3. Applies the full 17-rule policy engine (same as capability mode)
4. Writes audit logs to `~/.workspace-guard.log` (same as capability mode)
5. Enforces WORKSPACE-CI contracts (same as capability mode)

## When to Use Root-Only Mode

| Scenario | Recommended Mode |
|----------|-----------------|
| Production server with non-root users | Capability mode |
| PRoot-Distro on Android | Root-only mode |
| Docker container running as root | Root-only mode |
| CI agent running as root (no caps) | Root-only mode |
| Real Linux with non-root CI agents | Capability mode |

## Security Recommendation

Root-only mode is a **soft barrier**: it prevents accidental damage and
raises the bar for adversarial agents, but it is NOT a security boundary.
For production environments with non-root users, always use capability mode.

## Authoritative E2E (capability mode)

Capability-mode install and policy-matrix E2E on **real** guest `/usr/bin/git`
(with `setcap`, mode-0700 `git.original`) is the release sign-off path. It runs
inside WORKSPACE-VM QEMU guests only:

```bash
# WORKSPACE-VM root:
make test-vm-guard

# Inside provisioned guest:
sudo bash /opt/workspace/projects/WORKSPACE-GUARD/scripts/qemu/e2e-guest.sh
```

Podman Tier 3 (`make test-podman`) is a faster dev sanity check in a privileged
container; it does not replace the QEMU gate. See
[WORKSPACE-VM REQ-VM-HYPERVISOR](../../../docs/requirements/REQ-VM-HYPERVISOR.md) §FR-7 and
[SPEC-VM-HYPERVISOR](../../../docs/specifications/SPEC-VM-HYPERVISOR.md) §12.
