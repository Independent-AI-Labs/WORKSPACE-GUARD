# SPEC-GIT-GUARD-DEPLOYMENT

**Status:** ACTIVE  
**Date:** 2026-07-14  
**Derived from:** `docs/PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md`

## Deployment classes (git only)

| Class | Install target | Cap source |
|-------|----------------|------------|
| host-exec | `make install-guard-host-exec` | `setcap` on `/usr/bin/git` |
| sandbox-service | `make install-sandbox` | systemd `AmbientCapabilities` |

One host runs one git class. Two git classes on one host is forbidden.

## Host binding

`config/guard-host-profiles.yaml` maps `hostname -s` → class. Install refuses
unknown hosts and class mismatches. No env override.

## Installed record

`/usr/lib/workspace-guard/deployment-class` - values `host-exec` or
`sandbox-service`. Drift, check, and the Rust binary read this file.

## host-exec install

1. Assert hostname profile is `host-exec`
2. Refuse if `deployment-class` differs without uninstall
3. Refuse legacy `delivery.mode=pam` without uninstall
4. Scrub pam artifacts (`capability.conf` block, pam_cap auth lines)
5. `setcap cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid=ep /usr/bin/git`
6. Write `deployment-class=host-exec`
7. Verify `runuser -u <agent> -- git --version`

## Drift / check

`make check-guard-host-exec` reads `deployment-class` only. Verifies file caps
and functional probe via `runuser`. `make check-guard` hard-fails.

## Runtime

`workspace-guard` enforces cap source per `deployment-class`:

- **host-exec:** effective+permitted from file exec (NNP=0)
- **sandbox-service:** ambient+permitted

## Removed

- `make install-guard`, `make check-guard` (hard-fail)
- `install_capability_delivery()`, pam git install, XOR/fallback probes
- `GUARD_ALLOW_FUNCTIONAL_FAIL`, `GUARD_DELIVERY`, class-switching env vars