# Git Guard - Deployment Reconciliation Plan

**Status:** PLAN - not implemented, not a specification  
**Date:** 2026-07-14  
**Location:** `docs/PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md`

This document is the single authoritative plan. Active specifications (`SPEC-GIT-GUARD-INSTALL.md`, etc.) remain wrong until Phase 5 completes. No partial workarounds, no runtime probing, no fallback paths.

---

## 1. Problem

vm-ws `git status` fails for the `agent` user in Grok terminals and SSH while `sudo git status` works. `make install-guard` and `make check-guard` report HEALTHY.

**Root cause:** `install_capability_delivery()` in `CI/lib/guard-pam.sh` probes `su - agent` for ambient capabilities. PAM login sets CapAmb → installer chooses pam delivery → strips file caps from `/usr/bin/git`. Grok shells never run PAM → CapAmb=0 → guard FATAL. `check-guard` uses the same `su -` probe → false HEALTHY.

The repo also documents five incompatible delivery mechanisms (SUID 4555, file caps, pam_cap, systemd ambient, root-only) without explicit deployment classes. That is stacked pivots, not architecture.

**What this change deletes:**

- `install_capability_delivery()` and all XOR / probe / fallback install logic
- `GUARD_ALLOW_FUNCTIONAL_FAIL`, `GUARD_DELIVERY`, `GUARD_HOST_PROFILE`, and any env var that switches class
- Universal pam drift and `guard_capability_delivery_healthy()` OR logic
- Permissive dual-path `workload_has_cap()` without reading installed class
- `make install-guard` as an ambiguous entry point (hard-fail only)
- pam install path and `install-guard-host-login` - no SSH-only production fleet exists; keeping hypothetical pam code preserves the tar pit

---

## 2. Architecture

### 2.1 Concern boundaries

| Concern | Owner | Must never own |
|---------|-------|----------------|
| Policy engine | `workspace-guard` Rust binary | Choosing delivery class |
| Git install (Program I) | `make install-guard-host-exec` | Sandbox systemd, GTFOBins, pam |
| Sandbox agents (Program II) | `make install-sandbox` + `workspace-agent@` | git file caps |
| Binary lockdown (Program II) | `make install-lock` | git delivery |
| Home lock (Program III) | `make install-home-lock` | cap delivery |
| Audit | `make install-auditd` | cap delivery |
| CI soft barrier | `BUILD_MODE=root-only` in Podman Tier 2 / PRoot only | Framework dev hosts |

`workspace-binary-guard` is **deny-non-root** on SUID/cap binaries - capability removal / root-only gate, not cap delivery to agents. One binary copied to many paths; policy by `basename(argv[0])`; real binary at `<path>.real` mode 0700. It does **not** share git deployment classes or `/usr/lib/workspace-guard/deployment-class`. Program II needs its own installed record under `/usr/lib/workspace-binary-guard/` if drift tracking is added later.

`BUILD_MODE=root-only` is orthogonal to deployment class - CI/PRoot only, never in `guard-host-profiles.yaml`, never on framework dev hosts.

### 2.2 Git deployment classes

One machine runs **one** git class for its lifetime unless uninstall + scrub + reinstall (§2.5). Two git deployment classes on one host is forbidden.

| Class | Caps from | `NoNewPrivs` | Framework use |
|-------|-----------|--------------|----------------|
| **host-exec** | `setcap` on `/usr/bin/git` at exec | Must be 0 | Agent dev hosts, Grok, QEMU guest, Podman Tier 3 |
| **sandbox-service** | systemd `AmbientCapabilities` on `workspace-agent@` | 1 | Program II sandbox runtime only |

**sandbox-service** is implemented only via `make install-sandbox`. It must not appear in git install scripts.

Kernel / standards mapping:

- Non-NNP arbitrary spawn (Grok, IDE terminals) → file-cap on the wrapped binary (**host-exec**). See [capabilities(7)](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).
- NNP sandbox services → systemd ambient + bounding set (**sandbox-service**). Matches `workspace-agent@.service`.

### 2.3 Install entry points

| Make target | Class | Configures | Removes on install |
|-------------|-------|------------|-------------------|
| `make install-guard-host-exec` | host-exec | setcap on `/usr/bin/git` | workspace-guard pam block + pam_cap auth lines from prior installs |
| `make install-sandbox` | sandbox-service | systemd unit | (git install is a separate explicit step) |

**`make install-guard`:** hard-fail with message naming `install-guard-host-exec`. No alias, no default guess.

**`make check-guard`:** hard-fail; use `make check-guard-host-exec`.

Both **`WORKSPACE-GUARD/Makefile`** and **`CI/Makefile`** get the same targets in Phase 1.

### 2.4 Fleet binding

Hostname → class in versioned config:

`config/guard-host-profiles.yaml`

```yaml
profiles:
  vm-ws: host-exec
```

**Canonical hostname:** short name from `hostname -s` (not FQDN). Install asserts `hostname -s` matches a profile entry and matches the target being run. Wrong target on wrong host = refused. No env override.

vm-ws binding: **host-exec** only.

### 2.5 Class change protocol

1. `make uninstall-guard` (full)
2. host-exec scrub removes pam artifacts (see Phase 1)
3. `make install-guard-host-exec`

Install refuses if `/usr/lib/workspace-guard/deployment-class` exists and differs from target without uninstall first.

### 2.6 Installed record

`/usr/lib/workspace-guard/deployment-class` - written at end of successful install.

Values: `host-exec` or `sandbox-service` (sandbox written by `install-sandbox`, not git install).

Drift, check, and runtime binary read this file. Install does not infer class from live getcap or CapAmb.

### 2.7 Workload cap set

```
cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid
```

host-exec on disk:

```
cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid=ep
```

Reconcile REQ-GGUARD-001 and SPEC-HARDENING to five caps everywhere.

### 2.8 Runtime enforcement

`workspace-guard` reads `/usr/lib/workspace-guard/deployment-class` at startup in `check_privileges()`:

| Installed class | Accept caps from | Reject |
|-----------------|------------------|--------|
| host-exec | effective+permitted from file exec (NNP=0) | ambient-only as sole source |
| sandbox-service | ambient+permitted | file-cap as sole source |

Error message names installed class and `make install-guard-host-exec`. No “try pam or file-cap” language.

---

## 3. Forbidden

| Forbidden | Reason |
|-----------|--------|
| `GUARD_DELIVERY`, `GUARD_HOST_PROFILE`, any env var switching class | Backdoor |
| `GUARD_ALLOW_FUNCTIONAL_FAIL` | Leaves broken guard installed |
| `install_capability_delivery()` and XOR / probe / fallback logic | Caused vm-ws outage |
| pam + file-cap on same host | Dual path |
| `make install-guard` without class suffix (except hard-fail) | Hides intent |
| `FORCE_ROOT_ONLY` on framework dev hosts | Env override of safety |
| `GUARD_RECONCILE` auto-repair until drift is class-pure | Reconciles with broken rules |
| Inferring class from getcap / CapAmb / pam state | False HEALTHY |
| “Re-login Grok” as operator fix | Grok may never run PAM |
| SUID 4555 in active install docs | Dead model |
| Manual `setcap` without `install-guard-host-exec` | Workaround |
| `config/guard-delivery.yaml` mode override | Same as env backdoor |
| Promoting this file to SPEC before implementation completes | Spec lies ahead of code |
| Two git deployment classes on one host | Split-brain |

**Allowed:** `GUARD_NONINTERACTIVE=1` (CI prompt skip only). `BUILD_MODE=root-only` only in Podman Tier 2 / documented PRoot paths.

---

## 4. Environment → class binding

| Environment | Class | Install |
|-------------|-------|---------|
| Agent dev host + Grok shells | host-exec | `install-guard-host-exec` |
| QEMU authoritative guest | host-exec | `install-guard-host-exec` |
| Podman Tier 3 | host-exec | `install-guard-host-exec` |
| systemd sandbox agents | sandbox-service | `install-sandbox` |
| Podman Tier 2 / PRoot / Docker-as-root CI | none (root-only) | `BUILD_MODE=root-only` |
| macOS dev | none | Podman tiers |
| Program II GTFOBins | deny-non-root per path | `install-lock` |

---

## 5. Agent dev host install stack

Explicit ordered install - each step is intentional, no meta-target that chooses class:

```bash
make build-guard
sudo make install-guard-host-exec    # Program I: git, host-exec
sudo make install-lock               # Program II: deny agents on SUID surface (optional, after git)
sudo make install-auditd             # audit (may run in parallel with lock)
```

Do **not** run `make install-sandbox` on vm-ws Grok shells - sandbox is for agents under `workspace-agent@` only.

After merge and install:

```bash
git status    # works in current Grok shell, no re-login
```

---

## 6. Implementation (single atomic change set)

Phases 1-5 ship together. No vm-ws recovery until the full set merges.

### Phase 1 - Install split (`CI/lib` + both Makefiles)

- Delete: `install_capability_delivery()`, pam install functions used only for git delivery, `GUARD_ALLOW_FUNCTIONAL_FAIL` branches
- Add: `install_guard_host_exec()` in `CI/lib/guard-install.sh` (or dedicated `guard-host-exec.sh`)
- host-exec: setcap, scrub pam artifacts (`/etc/security/capability.conf` marker block, pam stack lines), write `deployment-class=host-exec`, verify `runuser -u agent -- git --version`
- Assert `config/guard-host-profiles.yaml` `hostname -s` match
- Refuse class mismatch without uninstall
- **WORKSPACE-GUARD/Makefile** and **CI/Makefile:** `install-guard-host-exec`, `check-guard-host-exec`; `install-guard` / `check-guard` → hard error

### Phase 2 - Drift and check (class-scoped)

- Delete: universal pam drift, `guard_capability_delivery_healthy()` OR logic, live-state class inference
- `check-guard-host-exec` reads `deployment-class` only; verifies getcap on `/usr/bin/git`; functional probe via `runuser -u agent -- git --version` (not `su -`)

### Phase 3 - Rust runtime enforcement

- Read `deployment-class` in `check_privileges()`
- Enforce single cap source per class (§2.8)
- Error strings: class + `make install-guard-host-exec` only

### Phase 4 - E2E and tests

- Rename `e2e-capability.sh` → `e2e-host-exec.sh` (getcap required, `runuser` git works, pam not required)
- `e2e-guest.sh` calls `e2e-host-exec.sh`
- Delete pam-only install tests that assumed universal pam delivery; update `14-guard-pam-ambient.bats` or remove if pam path deleted
- Fix `ROOT-ONLY-MODE.md` contradiction

### Phase 5 - Requirements and spec purge

- **REQ-GGUARD-148:** class-specific drift only; delete “reconcile any legacy mixed state” wording
- **REQ-GGUARD-001:** five caps
- README, SPEC-INSTALL, SPEC-HARDENING, ambient/cap allowlists aligned to host-exec / sandbox-service
- Remove SUID 4555, pam-universal, bootstrap setcap auto-detect fallback
- Document Program II deny-non-root model separately from git classes
- Promote delivery rules into `docs/specifications/SPEC-GIT-GUARD-DEPLOYMENT.md` (new spec, derived from this plan)
- Update this file status to IMPLEMENTED

---

## 7. Definition of done

- [ ] `config/guard-host-profiles.yaml` exists; vm-ws → host-exec; matching uses `hostname -s`
- [ ] `install-guard-host-exec` and `check-guard-host-exec` in both Makefiles; `install-guard` hard-fails
- [ ] Zero class-switching env vars in code
- [ ] Zero install probe / XOR / fallback
- [ ] Runtime enforces class from `deployment-class`
- [ ] host-exec scrub removes pam artifacts
- [ ] Drift/check uses `runuser` verify for host-exec
- [ ] E2E matches §4
- [ ] REQ-GGUARD-148/001 updated
- [ ] `GUARD_ALLOW_FUNCTIONAL_FAIL` removed from production paths
- [ ] pam git install path deleted (no `install-guard-host-login`)
- [ ] New SPEC promoted only after checklist complete
- [ ] vm-ws: `sudo make install-guard-host-exec` → `git status` in Grok without re-login