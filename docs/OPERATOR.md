# Guard operator commands

Run from the **workspace root** (`WORKSPACE-VM`):

```bash
sudo make guard-up       # idempotent bring-up (provision + guard install as needed)
sudo make guard-refresh  # after pulling guard code (alias: refresh-guard)
make guard-check         # read-only health
sudo make guard-down     # remove git guard only (provision state preserved)
sudo GUARD_PURGE_CONFIRM=1 make guard-reset  # factory reset then bring-up
```

Policy and implementation detail: `docs/specifications/`.

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