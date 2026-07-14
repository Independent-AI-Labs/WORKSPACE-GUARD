# Operator Runbook - Git Guard and Host Stack

Quick reference for refreshing or recovering WORKSPACE-GUARD on a fleet host.
Full policy detail lives in `docs/specifications/`.

## Where to run commands

| Repo | Has |
|------|-----|
| **WORKSPACE-GUARD** | `install-host-stack`, `provision-host`, phase-5 guard install |
| **WORKSPACE-CI** | `build-guard`, `install-guard-host-exec`, `check-guard-host-exec` |

Both repos delegate guard build/install to the same bootstrap script. For fleet
hosts with `user_management.enabled: true`, run the **full stack from
WORKSPACE-GUARD** at least once.

## Decision table

| Goal | Where | Command |
|------|-------|---------|
| First-time fleet host | WORKSPACE-GUARD | `sudo make install-host-stack` |
| Rebuild + reinstall after code change | WORKSPACE-GUARD (as agent) | `sudo --preserve-env=HOME,SSH_AUTH_SOCK make reconcile-guard-host-exec` |
| Install only when drift detected | either repo | `sudo make install-guard-host-exec` |
| Check health (read-only) | either repo | `make check-guard-host-exec` |
| Guard install when already provisioned | WORKSPACE-GUARD | `sudo make install-host-stack-phase5` |
| Remove git guard, keep users/keys | either repo | `sudo make uninstall-guard` |
| Factory reset all guard state | either repo | `sudo GUARD_PURGE_CONFIRM=1 make purge-guard-state` then `sudo make install-host-stack` |

## Never do this

- **Do not use `uninstall-guard` to refresh** the guard after a code change.
  Use `reconcile-guard-host-exec` instead. Uninstall restores stock git but
  intentionally preserves `host-provision.ok`, SSH keys, and identities.
- **Do not run `install-guard-host-exec` alone** when
  `config/host-provision.yaml` has `user_management.enabled: true` and
  `provision-host` has not completed. Install will hard-fail on missing
  `/usr/lib/workspace-guard/host-provision.ok`.
- **Do not use `purge-guard-state` casually.** It destroys provision markers,
  SSH keys, and identity files. Requires `GUARD_PURGE_CONFIRM=1`.

## Build contract (CI Makefile)

Run guard targets **as the fleet agent**, not as a direct `root` login. Direct
root breaks Makefile path resolution (git `safe.directory`) and leaves
`target/` root-owned.

```bash
# As agent (recommended):
sudo --preserve-env=HOME,SSH_AUTH_SOCK make build-guard
sudo --preserve-env=HOME,SSH_AUTH_SOCK make reconcile-guard-host-exec
sudo --preserve-env=HOME,SSH_AUTH_SOCK,WORKSPACE_ADMIN_PASSWORD make install-host-stack
```

If you must use a root shell, `cd` into WORKSPACE-GUARD first - the Makefile
resolves paths from its own location, not `git rev-parse`. Direct root builds
leave `target/` root-owned and can force slow rebuilds or rustc LLVM crashes;
fix ownership: `chown -R agent:agent projects/WORKSPACE-GUARD/target`.

### rustc LLVM crash (`Cannot emit physreg copy instruction`)

Usually low RAM or a poisoned `target/` cache after root-owned builds.

```bash
chown -R agent:agent projects/WORKSPACE-GUARD/target
# If binaries already exist, skip rebuild and install only:
cd projects/WORKSPACE-GUARD
sudo make install-host-stack-phase5   # skips build when release bins present
# Or force clean rebuild as agent:
rm -rf target
CARGO_BUILD_JOBS=1 make build-guard
```

`build-guard` compiles both `workspace-guard` and `workspace-git-ssh`.

## Verify after install

```bash
make check-guard-host-exec
/usr/lib/workspace-guard/git-ssh-wrapper -T git@github.com
runuser -u agent -- git push origin main
```

## Recovery after a bad uninstall (legacy)

If `host-provision.ok` or SSH keys were wiped by an older uninstall:

```bash
cd /path/to/WORKSPACE-GUARD
sudo make install-host-stack
```

Re-register the SSH public key on GitHub if keys were regenerated.