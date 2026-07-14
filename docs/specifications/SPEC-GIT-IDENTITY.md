# Specification: Per-User Git Identity and SSH

**Date:** 2026-07-14
**Status:** DRAFT (implementation in progress)
**Type:** Specification
**Parent:** [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md)
**Related:** [SPEC-HOME-LOCK](SPEC-HOME-LOCK.md), [SPEC-GIT-GUARD-INSTALL](SPEC-GIT-GUARD-INSTALL.md)

---

## 1. Problem

The interim `agent-git-identity` file under `/usr/lib/workspace-guard/` supplies
**one** `user.name` / `user.email` pair for every non-root UID. Fleet hosts may
run multiple guarded UNIX accounts (`agent`, `builder`, …), each needing distinct
commit metadata and SSH credentials for `git fetch` / `git push`.

Agents must **never** configure identity themselves (`git config user.*` is
blocked for non-root). Private SSH keys cannot be root-locked inside
`~/.ssh/id_*` and still work with stock OpenSSH as the connecting user: OpenSSH
requires the key file to be owned by the session user with mode `0600`.

---

## 2. Design summary

| Concern | Mechanism |
|---------|-----------|
| Commit `user.name` / `user.email` | Guard reads root-locked `$HOME/.gitconfig` per `getuid()`, injects via `GIT_CONFIG_*`; `GIT_CONFIG_GLOBAL=/dev/null` |
| SSH private keys | Root generates and stores under `/usr/lib/workspace-guard/ssh-keys/<user>/id_ed25519` (mode `0600`, root-owned) |
| Git → SSH transport | Guard injects `GIT_SSH_COMMAND` → `/usr/lib/workspace-guard/git-ssh-wrapper` (file-cap `cap_dac_override`) |
| Anti-fabrication | `~/.ssh` dir root-owned `0755`; `ssh-keygen` denied (binary lock); user `GIT_SSH*` stripped; drift CRITICAL on user-owned `~/.ssh/id_*` |
| Fleet registry | `config/home-lock-users.yaml` (gitignored; copy from [home-lock-users.yaml.example](../../config/home-lock-users.yaml.example)) |

```mermaid
flowchart LR
    subgraph provision [Root bootstrap once]
        P[provision-user-git-identity]
        P --> K["ssh-keys/USER/id_ed25519"]
        P --> G["~USER/.gitconfig"]
        P --> C["~USER/.ssh/config"]
        P --> L[install-home-lock]
    end
    subgraph runtime [Non-root git via guard]
        U[UNIX user] --> GU[workspace-guard]
        GU --> ID["read locked .gitconfig"]
        GU --> WR[git-ssh-wrapper]
        GU --> GO[git.original]
        WR --> SSH[/usr/bin/ssh]
    end
    G -.-> ID
    K -.-> WR
```

---

## 3. Fleet user registry

`config/home-lock-users.yaml` lists UNIX accounts and their commit identity.
**This file is gitignored** (contains real emails). Commit only
[config/home-lock-users.yaml.example](../../config/home-lock-users.yaml.example);
on each host:

```bash
cp config/home-lock-users.yaml.example config/home-lock-users.yaml
# edit git_name / git_email per fleet user
```

Example shape:

```yaml
version: 1
users:
  - name: agent
    git_name: "Example Agent"
    git_email: agent@example.local
```

Add entries for each guarded login user on a host. `install-home-lock` and
`scripts/provision-user-git-identity` expand paths as `~<name>/...` for every
listed user (not only the installer's `$HOME`).

---

## 4. Root provisioning

**Script:** `scripts/provision-user-git-identity`  
**Make targets:** `make provision-git-identities`, `make provision-host`,
`make install-host-stack`

Preferred: full host bootstrap ([SPEC-HOST-PROVISION](SPEC-HOST-PROVISION.md)):

```bash
sudo make install-host-stack
```

Manual per-user provision:

```bash
sudo make provision-git-identities --admin-from config/host-provision.yaml
sudo make install-home-lock
sudo make install-guard-host-exec
```

The `--admin-from` flag provisions the break-glass admin account from
`host-provision.yaml` even when admin is not listed in `home-lock-users.yaml`.

Per user in `home-lock-users.yaml`:

1. `ssh-keygen -t ed25519 -N "" -C "<git_email>"` →
   `/usr/lib/workspace-guard/ssh-keys/<user>/id_ed25519` (skip if exists)
2. Write `~<user>/.gitconfig` with `[user] name` and `email`
3. Write `~<user>/.ssh/config`:

   ```ini
   Host *
       IdentitiesOnly yes
       IdentityFile /usr/lib/workspace-guard/ssh-keys/<user>/id_ed25519
       StrictHostKeyChecking accept-new
   ```

4. `install-home-lock` applies root ownership and modes
5. Operator registers `<user>/id_ed25519.pub` on the git host (manual)

**Deprecates:** machine-wide `/usr/lib/workspace-guard/agent-git-identity` and
repo file `config/agent-git-identity` (gitignored; interim until per-user
provision lands). Committed template:
[config/agent-git-identity.example](../../config/agent-git-identity.example).

**Fallback identity file (optional):** `/usr/lib/workspace-guard/identities/<username>`
(key=value format, same allowed keys as today) if `.gitconfig` is missing.

---

## 5. Guard runtime behaviour

### 5.1 Commit identity (non-privileged)

On `execve` to `git.original` when `geteuid() != 0`:

1. Resolve `getuid()` → `User::from_uid` → `$HOME`, username
2. Parse `$HOME/.gitconfig` `[user]` section (only `user.email`, `user.name`)
3. Require file `st_uid == 0` (defense-in-depth)
4. Set `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`
5. Inject parsed values via `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_*` / `GIT_CONFIG_VALUE_*`
6. Also inject `safe.directory=*`, `core.fsmonitor=`, `core.hooksPath=`

When `geteuid() == 0` (operator `sudo git`): skip nulling global config; inject
only `safe.directory` (existing privileged branch).

### 5.2 SSH wrapper injection (non-privileged)

Guard injects into `git.original` child env (user cannot override ,  vars not in
`config/guard_environment.yaml` `allowed` list):

```
GIT_SSH_COMMAND=/usr/lib/workspace-guard/git-ssh-wrapper
GIT_SSH=/usr/lib/workspace-guard/git-ssh-wrapper
```

**Wrapper (planned binary `workspace-git-ssh`):**

- Map `getuid()` → username → `/usr/lib/workspace-guard/ssh-keys/<user>/id_ed25519`
- Reject missing keys and path escape
- `exec` `/usr/bin/ssh` with `-i <key> -F $HOME/.ssh/config -o IdentitiesOnly=yes --` + args
- Installed with `cap_dac_override=ep` to read root `0600` keys

`core.sshCommand` remains blocked for non-root ([config/guard_config_keys.yaml](../../config/guard_config_keys.yaml)).

### 5.3 What agents cannot do

- `git config user.email` / `user.name` (sudo-gated keys)
- `git config core.sshCommand` (dangerous key)
- Set `GIT_SSH` / `GIT_SSH_COMMAND` / `GIT_AUTHOR_*` (stripped or sudo-gated)
- Run `ssh-keygen` (binary lock `deny-non-root`)
- Create `~/.ssh/id_*` (`.ssh` directory root-owned `0755`, not user-writable)

---

## 6. Home-lock integration

See [SPEC-HOME-LOCK](SPEC-HOME-LOCK.md) §3.1. For each user in
`home-lock-users.yaml`, lock:

| Path | Mode |
|------|------|
| `~user/.gitconfig` | 0644 |
| `~user/.config/git/config` | 0644 |
| `~user/.gitconfig.local` | 0644 |
| `~user/.ssh/config` | 0644 |
| `~user/.ssh/authorized_keys` | 0600 |
| `~user/.ssh/known_hosts` | 0644 |
| `~user/.ssh` (directory) | 0755 root:root |

Explicit `/root/...` entries remain for the operator account.

**Drift:** `home-drift-check` shall emit CRITICAL if any `~user/.ssh/id_*` file
exists and is not owned by root under `/usr/lib/workspace-guard/ssh-keys/`
(user-fabricated key bypass).

---

## 7. Testing

| Layer | Coverage |
|-------|----------|
| Unit | Per-user `.gitconfig` parse; reject non-root-owned; wrapper path allowlist |
| bats | `~agent/` home-lock expansion; drift on rogue `id_ed25519`; host-provision sudo strip |
| Podman Tier 3 | `provision-host` + `agent`; commit shows configured `git_email`; push uses wrapper |

---

## 8. Non-goals

- Wrapping `/usr/bin/ssh` globally (git transport only)
- GPG / `user.signingkey`
- Automatic deploy-key registration on GitHub/GitLab
- Per-repo identity overrides (fleet identity is per UNIX user)