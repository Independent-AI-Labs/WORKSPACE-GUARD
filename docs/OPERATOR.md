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