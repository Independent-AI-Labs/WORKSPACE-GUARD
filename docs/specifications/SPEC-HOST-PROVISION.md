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
| 2 | **Gate** agent privilege reduction on proof of the admin password (interactive) |
| 3 | **Strip** fleet agent accounts from `sudo`; preserve all other sudoers files |
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
  install_lock: true
  install_auditd: true
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

Before any fleet sudo strip:

- **Interactive:** prompt for admin password (hidden input); verify with
  `runuser -u "$admin" -- bash -c '…'` and PAM/chpasswd round-trip.
- **Non-interactive (CI/Podman only):** `GUARD_NONINTERACTIVE=1` and
  `WORKSPACE_ADMIN_PASSWORD` must match the admin password set in phase 1.

**Abort** phases 3-5 if verification fails.

### 4.3 Phase 3 ,  Fleet user hardening

Skipped when `user_management.enabled: false`.

1. Parse `fleet_users_file` for UNIX usernames (same awk style as
   `expand-home-lock-users.sh`).
2. For each fleet user: `useradd -m -s /bin/bash` if missing in `/etc/passwd`.
3. `gpasswd -d <user> sudo` when user is in group `sudo`.
4. Remove `/etc/sudoers.d/90-workspace-guard-agents` if present (managed only).
5. **Scan** `/etc/sudoers` and `/etc/sudoers.d/*` (excluding `90-workspace-guard-*`)
   for fleet usernames; emit **WARN** (do not edit foreign files).

Admin account is never stripped.

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

1. `make build-guard`
2. `make install-guard-host-exec` (blocked until marker when user mgmt enabled)
3. If `guard_stack.install_lock`: `make install-lock` (best-effort if script missing)
4. If `guard_stack.install_auditd`: `make install-auditd`

Write completion marker `/usr/lib/workspace-guard/host-provision.ok`:

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
2. No fleet user from `home-lock-users.yaml` appears in `getent group sudo`

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

Operator maintenance after provision: log in as `admin`, use `sudo` with
password. Agents (`agent`, etc.) have **no** sudo path through group or managed
drops.

---

## 7. Testing

| Layer | Coverage |
|-------|----------|
| bats | `tests/shell/16-host-provision.bats` ,  parse/sudo helpers (unit only) |
| Podman | `make test-podman-provision` ,  phases 0-4 in privileged container (Linux `check-push`) |
| Podman Tier 3 | `e2e-host-exec.sh` ,  full provision + guard install E2E |
| Live verify | `groups agent` excludes `sudo`; `sudo -u admin -k true` prompts password |

---

## 8. Operator recovery

If locked out:

- Use hypervisor / image console as root, or
- Boot single-user / recovery mode, or
- Re-run `provision-host` from a root session outside agent IDE

Do **not** remove `agent` from `sudo` manually before phase 1-2 succeed on a
new host.

---

## 9. File index

| Artifact | Path |
|----------|------|
| Orchestrator | `scripts/provision-host` |
| Admin helpers | `scripts/lib/host-provision-admin.sh` |
| Sudo helpers | `scripts/lib/host-provision-sudo.sh` |
| Fleet user helpers | `scripts/lib/host-provision-users.sh` |
| Install gate | `CI/lib/guard-host-exec.sh` |
| Marker | `/usr/lib/workspace-guard/host-provision.ok` |