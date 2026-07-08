# Specification: Capability Throttle (Per-Binary Cap Allowlist)

**Date:** 2026-07-08
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-SANDBOX](../requirements/REQ-SANDBOX.md)
**Threat Model:** [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md)

---

## 1. Architecture Overview

```
  scripts/sync-gtfobins
        |
        v
  getcap -r /  (live file capabilities)
        |
        v
  Match against config/cap-allowlist.yaml
        |
        +---> keep  (cap is in allowlist for this path)
        |
        +---> strip (cap is NOT in allowlist for this path)
        |
        +---> throttle (reduce cap set to only allowed caps)
        |
        v
  setcap <allowed-caps> <path>
  (pre-strip state recorded in res/fcap-baseline.yaml)
```

The capability throttle ensures that no binary on the host carries a
capability that an AI agent could use for privilege escalation. The
allowlist is the single source of truth: any capability not explicitly
allowed for a given path is stripped.

---

## 2. Discovery

`getcap -r /` enumerates every file with capabilities on the host. The
output format is:

```
/usr/bin/ping = cap_net_raw=ep
/usr/bin/mtr-packet = cap_net_raw=ep
/usr/bin/git = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_setpcap=ep
/usr/bin/true = cap_dac_override=ep
```

The sync script parses this output and matches each entry against the
allowlist in `config/cap-allowlist.yaml`.

---

## 3. Live Findings on This Host

| Path | Live caps | Recommended action | Reason |
|------|-----------|-------------------|--------|
| `/usr/bin/git` | `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_setpcap` | throttle to `cap_dac_override` | Guard needs dac_override for root-owned `.git/`. chown, fowner, fsetid, setpcap are not needed. |
| `/usr/bin/true` | `cap_dac_override` | strip | `true` is a no-op binary; having `cap_dac_override` is a BUG (possibly from a mistaken `setcap` during testing). |
| `/usr/bin/ping` | `cap_net_raw` | keep | ICMP echo; expected. |
| `/usr/bin/mtr-packet` | `cap_net_raw` | keep | MTR traceroute; expected. |

### 3.1 The `/usr/bin/true` anomaly

`/usr/bin/true` carrying `cap_dac_override=ep` is anomalous. `true` is a
no-op binary that always exits 0. The capability has no functional purpose
and presents a privilege-escalation vector: if an attacker can replace
`/usr/bin/true` with a malicious binary (or corrupt its page cache via
CVE-2026-31431), they gain `cap_dac_override`. The sync script strips this
capability and records the pre-strip state in the baseline for audit.

---

## 4. Allowlist (config/cap-allowlist.yaml)

```yaml
# config/cap-allowlist.yaml
# Per-path capability allowlist. Any capability NOT listed here for a
# given path is stripped during `make install-lock`.
#
# Format:
#   path:
#     allowed: [cap_name, ...]
#     reason: "why this cap is needed"

allowlist:
  /usr/bin/git:
    allowed: [cap_dac_override]
    reason: "Guard reads root-owned .git/ directory entries"

  /usr/bin/sudo:
    allowed: [cap_setuid, cap_setpcap, cap_dac_override]
    reason: "Identity switching (SUID equivalent via file caps)"

  /usr/bin/su:
    allowed: [cap_setuid, cap_dac_override]
    reason: "Identity switching"

  /usr/bin/passwd:
    allowed: [cap_setuid, cap_dac_override]
    reason: "Password change writes /etc/shadow"

  /usr/bin/ping:
    allowed: [cap_net_raw]
    reason: "ICMP echo requests"

  /usr/bin/mtr-packet:
    allowed: [cap_net_raw]
    reason: "Traceroute raw socket"

  /usr/bin/newuidmap:
    allowed: [cap_setuid, cap_setgid]
    reason: "Subordinate UID mapping for user namespaces"

  /usr/bin/newgidmap:
    allowed: [cap_setgid, cap_setuid]
    reason: "Subordinate GID mapping for user namespaces"

# No other path is in the allowlist. Any capability found on a path not
# listed above is stripped unconditionally.
```

---

## 5. Throttle Procedure

For each `(path, caps)` found by `getcap`:

```
1. Read allowlist for <path>
2. If <path> not in allowlist:
     action = strip
     setcap "" <path>       # remove all caps
3. If <path> in allowlist:
     allowed = allowlist[path].allowed
     current = parse(caps)
     if current == allowed:
       action = keep
     elif current is a superset of allowed:
       action = throttle
       setcap <allowed joined by ,> <path>
     else:
       action = keep  # current caps are a subset of allowed, unexpected but safe
4. Record (path, caps, action, allowed, stripped) in res/fcap-baseline.yaml
```

### 5.1 Pre-strip state

Before any `setcap` call, the current capability string is recorded in
`res/fcap-baseline.yaml`. This is the audit trail: the baseline contains
what was on the machine before the program touched it.

### 5.2 Post-strip verification

After `setcap`, the script re-runs `getcap <path>` and verifies the result
matches the allowlist. If verification fails, the script emits an error and
exits non-zero.

---

## 6. Systemd CapabilityBoundingSet

The systemd unit for agent workloads (defined in
[SPEC-SANDBOX](SPEC-SANDBOX.md)) sets `CapabilityBoundingSet=` to an empty
list plus a minimal allowlist. The current unit drops all capabilities:

```ini
[Service]
CapabilityBoundingSet=
NoNewPrivileges=yes
```

An empty `CapabilityBoundingSet=` means the unit starts with zero
capabilities. Any capability the workload needs must be explicitly added.
For the default agent workload, no capabilities are added: the agent runs
fully de-privileged inside the sandbox.

### 6.1 Caps that are ALWAYS dropped

The following capabilities are never granted to agent workloads, regardless
of profile:

| Capability | Blocked because |
|------------|----------------|
| `CAP_SYS_ADMIN` | Mount, pivot_root, overlayfs (CVE-2023-0386) |
| `CAP_NET_ADMIN` | nftables (CVE-2023-0179) |
| `CAP_NET_RAW` | Raw sockets, ESP6 (CVE-2022-27666) |
| `CAP_SYS_PTRACE` | Process inspection/injection |
| `CAP_SYS_MODULE` | Kernel module loading |
| `CAP_DAC_READ_SEARCH` | Shocker (CVE-2014-0038) |
| `CAP_LINUX_IMMUTABLE` | chattr +i manipulation |
| `CAP_BPF` | BPF programs |
| `CAP_PERFMON` | Performance monitoring |
| `CAP_CHECKPOINT_RESTORE` | Checkpoint/restore (CRIU) |
| `CAP_SYS_PACCT` | Process accounting |
| `CAP_SYS_NICE` | Priority/scheduler manipulation |
| `CAP_SYS_BOOT` | Reboot |
| `CAP_SYS_TIME` | Clock manipulation |
| `CAP_SYS_TTY_CONFIG` | TTY config |
| `CAP_WAKE_ALARM` | RTC alarm |
| `CAP_BLOCK_SUSPEND` | PM suspend |
| `CAP_AUDIT_READ` | Audit log read |
| `CAP_AUDIT_WRITE` | Audit log write |
| `CAP_AUDIT_CONTROL` | Audit config |
| `CAP_SETFCAP` | File capability manipulation |
| `CAP_MAC_ADMIN` | MAC (SELinux) admin |
| `CAP_MAC_OVERRIDE` | MAC override |

---

## 7. Drift Detection

The drift checker (`scripts/suid-drift-check`) compares the current
`getcap -r /` output against `res/fcap-baseline.yaml`:

- **New capability on a watched path**: WARNING (or CRITICAL if the path is
  agent-accessible).
- **Removed capability**: INFO (the program or operator removed it).
- **Changed capability string**: WARNING (caps were added or removed on a
  path that is in the baseline).

---

## 8. References

1. [references/capabilities.7.html](../references/capabilities.7.html): authoritative Linux capabilities(7) page
2. [references/systemshardening-cap-hardening.html](../references/systemshardening-cap-hardening.html): per-service cap allowlist guidance
3. [references/yunolay-caps-abuse.html](../references/yunolay-caps-abuse.html): cap escalation abuse taxonomy
4. [references/elastic-cap-escalation.html](../references/elastic-cap-escalation.html): cap escalation detection telemetry
5. [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md) section 3.6: Shocker (CVE-2014-0038)
6. [REQ-SANDBOX](../requirements/REQ-SANDBOX.md) section 2: REQ-CAP-* requirements