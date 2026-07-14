# Specification: Host Provision (Admin, Fleet Users, Guard Stack)

**Date:** 2026-07-14
**Status:** DRAFT (implementation in progress)
**Type:** Specification
**Parent:** [SPEC-GIT-GUARD-INSTALL](SPEC-GIT-GUARD-INSTALL.md)
**Related:** [SPEC-GIT-IDENTITY](SPEC-GIT-IDENTITY.md), [SPEC-HOME-LOCK](SPEC-HOME-LOCK.md), [GAP-ANALYSIS-HARD-NUKE](../GAP-ANALYSIS-HARD-NUKE.md)

---

## 1. Problem

On agent dev hosts (`vm-ws`, `host-exec` class), fleet agents often start with
`sudo` membership. That closes **GAP-C06** only after a verified break-glass
operator path exists. On `vm-ws` specifically:

- `agent` ∈ group `sudo` (password required; not passwordless)
- `su root` fails (no usable root password in interactive sessions)
- Removing `agent` from `sudo` without a tested admin account bricks maintenance

Install today (`make install-guard-host-exec`) does not manage users, sudoers,
or the full guard stack. Operators run ad-hoc steps and risk locking themselves
out.

---

## 2. Goals

| # | Requirement |
|---|-------------|
| 1 | Ensure a configurable **admin** UNIX account exists with password-required full sudo via a **managed** sudoers drop-in |
| 2 | **Gate** phase 3 on proof of the admin password (interactive) |
| 3 | **Audit** fleet sudo (RED=has sudo, YELLOW=no sudo); **never modify** fleet sudo |
| 4 | **Provision** per-user git identity + SSH keys for admin and fleet users |
| 5 | **Run** remaining guard prerequisites (home-lock, git guard, optional lock/audit) in one orchestrated flow |

Non-goals: auto-editing third-party `/etc/sudoers.d/*` files; `install-sandbox`
on IDE shells.

---

## 3. Configuration

Live file: `config/host-provision.yaml` (**gitignored**). Template:
[config/host-provision.yaml.example](../../config/host-provision.yaml.example).
Schema: [config/host-provision.schema.yaml](../../config/host-provision.schema.yaml).

Fleet git/SSH users remain in `config/home-lock-users.yaml` (gitignored;
[example](../../config/home-lock-users.yaml.example)).

```yaml
version: 1
user_management:
  enabled: true          # false → skip phases 1-3; install gate disabled
admin:
  name: admin
  shell: /bin/bash
  create_home: true
  git_name: "Host Admin"
  git_email: admin@example.local
fleet_users_file: config/home-lock-users.yaml
guard_stack:
  install_lock: false
  install_auditd: false
```

When `user_management.enabled: false`, `provision-host` runs phases 4-5 only
(identity + guard stack) and `install-guard-host-exec` does not require the
completion marker.

---

## 4. Orchestrator

**Script:** `scripts/provision-host`
**Make targets:** `make provision-host`, `make install-host-stack`

Must run as **root** (`id -u == 0`). Entry from operator session:

```bash
cp config/host-provision.yaml.example config/host-provision.yaml
cp config/home-lock-users.yaml.example config/home-lock-users.yaml
# edit locally ,  never commit live files

sudo make install-host-stack
```

`install-host-stack` = `provision-host` (all phases).

### 4.1 Phase 1 ,  Admin break-glass

1. Read `admin.name` from config (default `admin`).
2. If account missing: `useradd -m -s <shell>` (when `create_home: true`).
3. If account exists but lacks sudo: continue to drop-in install only.
4. If account missing **or** newly created:
   - Generate password: `openssl rand -base64 24`
   - `chpasswd` once
   - **Print password to stdout** in a bordered banner (never write to disk or git)
5. Install `/etc/sudoers.d/90-workspace-guard-admin`:

   ```
   # BEGIN workspace-guard managed ,  do not edit manually
   <admin> ALL=(ALL:ALL) ALL
   # END workspace-guard managed
   ```

   No `NOPASSWD`. Validate with `visudo -cf`.

Managed marker files use prefix `90-workspace-guard-*` so they sort after most
site policy but remain identifiable.

### 4.2 Phase 2 ,  Admin password gate

Before phase 3 fleet account setup:

- **Interactive:** prompt for admin password (hidden input); verify against
  `/etc/shadow` via `perl` `crypt`.
- **Non-interactive:** set `WORKSPACE_ADMIN_PASSWORD` to the admin password
  (same value used in phase 1 when the account is new). `GUARD_NONINTERACTIVE=1`
  is optional when `WORKSPACE_ADMIN_PASSWORD` is set.

On success, write a root-owned phase-2 token at
`/usr/lib/workspace-guard/host-provision.phase2.ok`. Phase 3 **refuses** to run
without this token.

**Abort** phases 3-5 if verification fails.

Operator one-liner (fleet IDE host):

```bash
export WORKSPACE_ADMIN_PASSWORD='your-chosen-password'
sudo -E make install-host-stack
```

### 4.3 Phase 3 ,  Fleet user accounts (audit only)

Skipped when `user_management.enabled: false`.

**Privilege states** (computed per fleet user):

| State | Audit color |
|-------|-------------|
| `privileged` | **RED CRITICAL** - user exists and has sudo in any list |
| `none` | **YELLOW WARN** - user exists, no sudo in any list |
| `verify_failed` | **RED CRITICAL** - fail-closed |

Sudo lists checked: group `sudo`, `/etc/sudoers` and `/etc/sudoers.d/*` lines,
`sudo -l -U <user>` policy. **Fleet sudo is never modified** (no demotion).

**Direct-root gate:** if a fleet user has a **foreign** direct-root sudoers
grant outside managed allowlist, print **CRITICAL** and **exit 1** unless
`--acknowledge-direct-root-agent`.

1. Parse `fleet_users_file` for UNIX usernames.
2. `useradd -m -s /bin/bash` if missing.
3. Mandatory audit at start of run (full dump); phase 3 prints one-line summary
   per user referencing that audit.

Non-interactive probes only (`sudo -n`).

**Never run `provision-host --phase 3` alone.** Isolated phase 3 without a
phase-2 token exits with an error and leaves fleet users unchanged.

### 4.4 Phase 4 ,  Git / SSH identity

1. `scripts/provision-user-git-identity` for fleet users from
   `home-lock-users.yaml`.
2. Same script with `--admin-from config/host-provision.yaml` for admin git/SSH
   (even if admin is not listed in fleet file).
3. `scripts/install-home-lock` for root-owned identity paths.

Keys live under `/usr/lib/workspace-guard/ssh-keys/<user>/id_ed25519` (root
`0600`). See [SPEC-GIT-IDENTITY](SPEC-GIT-IDENTITY.md).

### 4.5 Phase 5 ,  Guard stack

From repo root, as root:

1. `make install-host-stack-phase5` (always runs `build-guard` or `build-host-stack`)
2. Fleet sudo state unchanged by provision (audit only)

Write completion marker `/usr/lib/workspace-guard/host-provision.ok` **before
phase 5** when `user_management.enabled: true` (phases 1-4 complete) so
`install-guard-host-exec` can run inside `install-host-stack`. Refresh the marker
**after all requested phase-5 steps succeed**:

```
admin=<name>
fleet_sha256=<sha256 of fleet_users_file>
completed_at=<ISO8601 UTC>
user_management=<true|false>
```

---

## 5. Install gate (hard-fail)

When **all** of the following hold:

- `config/host-provision.yaml` exists
- `user_management.enabled: true` in that file
- Target is `install-guard-host-exec` / `install_guard_host_exec()`

`CI/lib/guard-host-exec.sh` shall **refuse** install unless:

1. `/usr/lib/workspace-guard/host-provision.ok` exists and `admin=` matches config
2. Completion marker present (fleet sudo retention allowed under warn-only default)

Error message: `Run: sudo make provision-host` (or `install-host-stack`).

**Escape hatch:** no `host-provision.yaml` on host → gate skipped (Podman dev
images without fleet config).

---

## 6. Sudo policy summary

| File | Managed? | Content |
|------|----------|---------|
| `/etc/sudoers` | No | Preserved |
| `/etc/sudoers.d/*` (except `90-workspace-guard-*`) | No | Preserved; WARN if fleet user named |
| `/etc/sudoers.d/90-workspace-guard-admin` | Yes | Admin full sudo, password required |
| `/etc/sudoers.d/90-workspace-guard-agents` | Yes | Must not exist after provision |
| `sudo` group membership | Partially | Fleet users removed; admin untouched |
| Cloud-init drop-ins (`90-cloud-init-users`, etc.) | Yes (allowlist) | Fleet direct-root lines stripped |
| Effective sudo (`sudo -l -U <fleet>`) | Audited | Never modified by provision |

Operator maintenance: `admin` has break-glass sudo. Fleet users retain sudo
unless demotion was requested. Audit distinguishes persistent grants vs cached
tickets.

---

## 7. Testing

| Layer | Coverage |
|-------|----------|
| bats | `tests/shell/16-host-provision.bats`, `17-host-provision-sudo.bats` |
| Podman | `make test-podman-provision` ,  happy path + `e2e-host-provision-safety.sh` |
| Podman Tier 3 | `e2e-host-exec.sh` ,  full provision + guard install E2E |
| Live verify | `groups agent` excludes `sudo`; `sudo -u admin -k true` prompts password |

Safety E2E cases (privileged container):

- phase 3 alone blocked; fleet user stays in `sudo`
- bad admin password aborts before demotion
- missing phase-2 token blocks demotion
- RED CRITICAL when fleet user has sudo; YELLOW when exists without sudo
- `--demote-fleet-sudo` rejected (removed)
- bats `17-host-provision-sudo.bats` covers audit colors and always-build
- unmanaged direct-root grant blocks phase 3 with CRITICAL banner

Preflight (read-only): `sudo make provision-host-preflight`

---

## 8. Operator recovery

If locked out:

- Use hypervisor / image console as root, or
- Boot single-user / recovery mode, or
- Re-run `provision-host` from a root session outside the fleet agent session

Do **not** remove fleet users from `sudo` manually before phase 1-2 succeed on a
new host.

### 8.1 Symptom diagnosis

| Symptom | Likely cause |
|---------|----------------|
| `sudo` asks for password then "Sorry, try again" | Fleet user still in `sudo`; wrong **fleet user** login/sudo password |
| `agent is not in the sudoers file` | Fleet user already demoted; use `admin` or console root |
| `su admin` fails "does not exist" | Phase 1 never completed; use console root to create admin |
| Script hangs at phase 2 | `WORKSPACE_ADMIN_PASSWORD` unset; set it or type admin password at prompt |

---

## 9. File index

| Artifact | Path |
|----------|------|
| Orchestrator | `scripts/provision-host` |
| Admin helpers | `scripts/lib/host-provision-admin.sh` |
| Sudo helpers | `scripts/lib/host-provision-sudo.sh` |
| Operator warnings | `scripts/lib/host-provision-operator.sh` |
| Fleet user helpers | `scripts/lib/host-provision-users.sh` |
| Install gate | `CI/lib/guard-host-exec.sh` |
| Marker | `/usr/lib/workspace-guard/host-provision.ok` |