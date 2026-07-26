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

Locked policy YAMLs are edited via the sudo-gated exemption tool (see
`docs/specifications/SPEC-EXEMPTION-EDIT.md`):

```bash
sudo make exemption-add    FILE=config/quality_exceptions.yaml KEY=exceptions FIELDS="hook=pre-commit;added_by=me;reason=<20+ chars>;paths=src/x.py"
sudo make exemption-remove FILE=config/quality_exceptions.yaml KEY=exceptions FIELDS="hook=pre-commit;paths=src/x.py"
scripts/exemption.sh list FILE=config/quality_exceptions.yaml KEY=exceptions
```

## Migration from config-lock.sh

The old `scripts/config-lock.sh` (chattr/timed unseal) is removed. To
migrate repos that still carry chattr-locked YAML policy files:

```bash
sudo find <repo>/config -maxdepth 1 -name '*.yaml' \
  -exec chattr -i {} + -exec chown root:root {} + -exec chmod 0644 {} +
```

After that, the guard's glob ownership lock keeps them root-owned and all
edits go through `exemption.sh`.