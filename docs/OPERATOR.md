# Guard operator commands

Run from the **workspace root** (`WORKSPACE-VM`):

```bash
sudo make guard-up       # idempotent bring-up (provision + guard install as needed)
sudo make guard-refresh  # after pulling guard code (alias: refresh-guard)
make guard-check         # read-only health
sudo make guard-down     # remove shell guard first, then git guard (provision state preserved)
sudo GUARD_PURGE_CONFIRM=1 make guard-reset  # factory reset then bring-up
```

Policy and implementation detail: `docs/specifications/`.

## Shell guard (`/bin/bash` replacement)

The shell guard installs `workspace-shell-guard` at the resolved bash
path (usrmerge: `/usr/bin/bash`) via `dpkg-divert`, seals the stock
bash as `/bin/bash.real` (0700 root:root, `chattr +i`), and drops an
apt `Post-Invoke` warn hook (`/etc/apt/apt.conf.d/99workspace-guard-shell`).

```bash
sudo bash scripts/install-shell-guard    # install / reconcile (idempotent)
bash scripts/shell-guard-check           # read-only health: OK / DRIFTED / NOT INSTALLED
sudo bash scripts/uninstall-shell-guard  # restore stock bash byte-identical
```

While the guard is live, root shell invocations fail closed (exit 3,
`AT_SECURE == 0` by design). Only non-root users get scanning shells.

Drift repair: `shell-guard-check` exits 1 on drift (missing hook,
stale binary hash, relaxed `.real` mode, missing caps). Re-run
`install-shell-guard`; it reconciles all of it.

Fail-closed recovery (guard binary lost its caps; every new shell
exits 3):

```bash
sudo install -d -m 0700 /var/lib/workspace-guard
sudo install -m 0700 -o root -g root scripts/install-shell-guard \
    /var/lib/workspace-guard/shg-repair
sudo /bin/bash.real /var/lib/workspace-guard/shg-repair
sudo rm -f /var/lib/workspace-guard/shg-repair
```

The sealed `/bin/bash.real` (0700, root-only) never scans; the
root-owned staging copy satisfies the trusted-tier check.

## Policy YAML edits

Locked policy YAMLs are edited via the sudo-gated `workspace-yaml-edit`
binary (see `docs/specifications/SPEC-YAML-EDIT.md`). Field specs are
separated by `;` (so values may contain spaces); list fields use
brackets (`paths=[a,b]`, single-element `paths=[x]`):

```bash
sudo make yaml-add      FILE=config/quality_exceptions.yaml KEY=exceptions FIELDS="hook=pre-commit;added_by=me;reason=<20+ chars>;paths=[src/x.py]"
sudo make yaml-remove   FILE=config/quality_exceptions.yaml KEY=exceptions FIELDS="hook=pre-commit;paths=[src/x.py]"
sudo make yaml-set      FILE=config/coverage_thresholds.yaml KEY=unit.threshold VALUE=80
make yaml-get           FILE=config/coverage_thresholds.yaml KEY=unit.threshold
make yaml-list          FILE=config/quality_exceptions.yaml KEY=exceptions
make yaml-validate      FILE=config/quality_exceptions.yaml
```

Useful flags: `--dry-run` (print a unified diff, no install, no root
needed), `--allow-no-match` (remove: no-match exits 0), `--string`
(set: force string typing).

If a file carries the chattr immutable flag (e.g. it is under
WORKSPACE-CI's exemption manifest), the tool clears the flag only for
the atomic rename and restores it immediately after; the file keeps
its flags across every edit. Never `chattr -i` a policy file by hand.

## Migration from config-lock.sh

The old `scripts/config-lock.sh` (chattr/timed unseal) is removed, and
the awk-based `scripts/exemption.sh` that first replaced it has been
superseded by `workspace-yaml-edit`. To migrate repos that still carry
chattr-locked YAML policy files:

```bash
sudo find <repo>/config -maxdepth 1 -name '*.yaml' \
  -exec chown root:root {} + -exec chmod 0644 {} +
```

Keep any existing `chattr +i` flags in place: `workspace-yaml-edit`
preserves them, and WORKSPACE-CI's `validate_exemption_file` requires
the immutable bit on manifest files. After ownership migration, the
guard's glob ownership lock keeps files root-owned and all edits go
through `workspace-yaml-edit`.