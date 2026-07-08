# Specification: Binary Lock (SUID/CAP Contain-via-Guard)

**Date:** 2026-07-08
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-SANDBOX](../requirements/REQ-SANDBOX.md)
**Threat Model:** [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md)

---

## 1. Architecture Overview

```
  User invokes: <binary> [args...]
                       |
                       v
            /usr/bin/<binary>          (guard, mode 0755, root:root)
            compiled Rust guard binary
                       |
           +-----------+----------------+
           |           |                |
           v           v                v
      Parse &     Check policy      Sanitise env
      validate    (deny-non-root    vars, PATH
        args      or subcommand
                   allowlist)
           |           |                |
           +-----------+----------------+
                       |
                 All clear?
                  +--+
                 NO   YES
                  |    |
                  v    v
             Block execve("<path>.real", argv, envp)
             + log  (real binary, mode 0700 root:root,
                     chattr +i)
```

The binary lock extends the git-guard pattern to every SUID and
capability-bearing binary on the host. Each contained binary gets:

1. A compiled Rust guard at the original path (mode 0755).
2. The real binary relocated to `<path>.real` (mode 0700, root:root).
3. `chattr +i` on `<path>.real` to prevent tampering.
4. A `dpkg-divert` so apt upgrades do not overwrite the guard.

The guard itself is a thin wrapper: it checks the policy, sanitises the
environment, and `execve()`s the real binary. It does NOT re-implement the
binary's logic.

---

## 2. Lock Surface (live SUID binaries on this host)

The discovery command `find / -xdev -perm -4000 -type f` produces the live
SUID set. The sync script matches each entry against the GTFOBins SUID list
(cached at [references/gtfobins-suid.html](../references/gtfobins-suid.html))
and the konstruktoid baseline (cached at
[references/konstruktoid-suid-list.txt](../references/konstruktoid-suid-list.txt)).

| Path | GTFOBins | konstruktoid | Guard policy | CVE |
|------|----------|-------------|---------------|-----|
| `/usr/bin/sudo` | Y (sudo) | Y | arg-validate | CVE-2021-3156, CVE-2025-32463 |
| `/usr/bin/su` | Y (su) | Y | deny-non-root | |
| `/usr/bin/mount` | Y (mount) | Y | deny-non-root | |
| `/usr/bin/umount` | Y (umount) | Y | deny-non-root | |
| `/usr/bin/passwd` | Y (passwd) | Y | arg-validate | |
| `/usr/bin/gpasswd` | Y (gpasswd) | Y | deny-non-root | |
| `/usr/bin/chsh` | Y (chsh) | Y | deny-non-root | |
| `/usr/bin/chfn` | Y (chfn) | Y | deny-non-root | |
| `/usr/bin/newgrp` | Y (newgrp) | Y | deny-non-root | |
| `/usr/bin/newuidmap` | N | N | arg-validate | |
| `/usr/bin/newgidmap` | N | N | arg-validate | |
| `/usr/bin/fusermount3` | Y (fusermount) | N | deny-non-root | |
| `/usr/bin/pkexec` | Y (pkexec) | Y | deny-all-non-root | CVE-2021-4034 |

### 2.1 SGID binaries

SGID binaries are discovered with `find / -xdev -perm -2000 -type f` and
recorded in the baseline, but the contain-via-guard procedure is NOT applied
to SGID binaries by default. SGID grants group privileges, not root. The
drift checker monitors SGID changes. SGID containment is a future extension
(documented in [SPEC-AUDIT](SPEC-AUDIT.md) section 6, known residual risks).

---

## 3. Per-Binary Guard Policies

Each guard reads its policy from `config/binary-lock.yaml` at install time.
The policy is compiled into the guard binary (no runtime config reads, to
match the git-guard security model).

### 3.1 Policy types

| Policy type | Behaviour for non-root | Behaviour for root |
|-------------|------------------------|---------------------|
| `deny-non-root` | Exit 2 | execve `.real` |
| `deny-all-non-root` | Exit 2 (no exceptions) | execve `.real` |
| `arg-validate` | Check subcommand allowlist; allow or exit 2 | execve `.real` |
| `pass-through` | execve `.real` (no checks) | execve `.real` |

### 3.2 Per-binary policy assignments

```yaml
# config/binary-lock.yaml (schema, compiled into each guard at build time)
binaries:
  /usr/bin/sudo:
    policy: arg-validate
    allow_subcommands:
      - sudo
      - sudoedit
    reject_patterns:
      - { pattern: '\\$', flags: [sudoedit, -s], reason: "Baron Samedit CVE-2021-3156" }
      - { flag: -R, reason: "chroot LPE CVE-2025-32463" }
      - { flag: --chroot, reason: "chroot LPE CVE-2025-32463" }
      - { flag: --host, reason: "host confusion CVE-2025-32462" }
    env_sanitise:
      - LD_PRELOAD
      - LD_LIBRARY_PATH
      - GCONV_PATH
      - GLIBC_TUNABLES
      - SUDO_ASKPASS

  /usr/bin/passwd:
    policy: arg-validate
    allow_subcommands:
      - passwd          # change own password (no args)
    allow_args:
      - own_username    # passwd <own-username>
    reject_patterns:
      - { flag: -S, reason: "status query requires root" }
    env_sanitise:
      - LD_PRELOAD
      - LD_LIBRARY_PATH

  /usr/bin/pkexec:
    policy: deny-all-non-root
    env_sanitise:
      - GCONV_PATH
      - LD_PRELOAD
      - LD_LIBRARY_PATH

  /usr/bin/su:
    policy: deny-non-root
    env_sanitise:
      - LD_PRELOAD
      - LD_LIBRARY_PATH

  /usr/bin/mount:
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  /usr/bin/umount:
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  /usr/bin/gpasswd:
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  /usr/bin/chsh:
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  /usr/bin/chfn:
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  /usr/bin/newgrp:
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  /usr/bin/newuidmap:
    policy: arg-validate
    allow_subcommands:
      - newuidmap
    validate: subordinate_uid_range
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  /usr/bin/newgidmap:
    policy: arg-validate
    allow_subcommands:
      - newgidmap
    validate: subordinate_gid_range
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  /usr/bin/fusermount3:
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]
```

### 3.3 sudo guard detail

The sudo guard is the most complex because sudo has two active CVEs:

- **CVE-2021-3156 (Baron Samedit):** heap overflow in the sudoers parser
  triggered by `sudoedit -s '\'` followed by a backslash-terminated argument.
  The guard rejects any argument ending with `\` when the subcommand is
  `sudoedit` and `-s` is present.

- **CVE-2025-32463 (chroot LPE):** sudo loads `/etc/nsswitch.conf` from a
  user-controlled directory when `--chroot` is used. The guard rejects `-R`
  and `--chroot` unconditionally for non-root. For root, the guard passes
  through (root does not need protection from itself).

- **CVE-2025-32462 (host confusion):** `--host` flag can confuse the
  sudoers host matching. The guard rejects `--host` for non-root.

The guard checks patterns in this order (first match wins):

```
1. subcommand is sudoedit AND -s flag present AND any arg endswith '\' -> BLOCK
2. -R or --chroot flag present -> BLOCK
3. --host flag present -> BLOCK
4. subcommand not in [sudo, sudoedit] -> BLOCK
5. ALL CLEAR -> execve /usr/bin/sudo.real
```

### 3.4 passwd guard detail

The passwd guard allows non-root users to change their own password only:

```
1. argc == 1 (no args) -> ALLOW (change own password)
2. argc == 2 AND argv[1] == current username -> ALLOW
3. -S (status) flag -> BLOCK (requires root)
4. any other arg -> BLOCK
```

The current username is determined via `getpwuid(getuid())->pw_name`.

### 3.5 newuidmap / newgidmap guard detail

These binaries are used by user namespaces to map subordinate UIDs/GIDs.
The guard validates that the requested mapping falls within the invoking
user's delegated subordinate range (from `/etc/subuid` and `/etc/subgid`):

```
1. Parse args: <pid> <inner> <outer> <count> [<inner2> <outer2> <count2> ...]
2. Read /etc/subuid for the current user
3. For each (inner, outer, count) tuple:
   - outer must be within a subordinate range allocated to the user
   - count must not exceed the range size
4. If any tuple is out of range -> BLOCK
5. ALL CLEAR -> execve <path>.real
```

### 3.6 pkexec guard detail

The pkexec guard rejects ALL non-root invocations. There is no safe
unprivileged use of pkexec on an agent-only host. CVE-2021-4034 (PwnKit)
showed that even with the polkit policy engine, the binary's own argument
parsing is exploitable. The guard exits 2 for any non-root call.

---

## 4. Installation Procedure

### 4.1 Contain-via-guard (per binary)

```
For each <path> in lock_surface:
  1. Verify <path> exists and is a regular file
  2. Copy <path> to <path>.real
  3. chown root:root <path>.real
  4. chmod 0700 <path>.real
  5. Verify SHA-256 of <path>.real matches <path>
  6. chattr +i <path>.real
  7. Build guard binary (from config/binary-lock.yaml policy)
  8. Copy guard binary to <path>
  9. chown root:root <path>
  10. chmod 0755 <path>
  11. dpkg-divert --add --rename --divert <path>.distrib <path>
  12. Verify: <path> --version or <path> responds (warm check)
```

### 4.2 Rollback on failure

If any step fails, the procedure reverses all prior steps for that binary:

```
rollback(path):
  if <path>.real exists:
    chattr -i <path>.real
    cp <path>.real <path>
    chown root:root <path>
    chmod 4755 <path>        # restore original SUID mode
    rm <path>.real
  if dpkg-divert exists for <path>:
    dpkg-divert --remove --rename <path>
  emit ERROR, exit 1
```

### 4.3 Uninstall

```
For each <path> in lock_surface:
  1. chattr -i <path>.real
  2. rm <path> (the guard)
  3. cp <path>.real <path>
  4. chown root:root <path>
  5. chmod 4755 <path>        # restore original SUID mode
  6. rm <path>.real
  7. dpkg-divert --remove --rename <path>
  8. Verify: <path> works
```

---

## 5. Guard Binary Build

Each guard binary is built from the same Rust codebase as the git guard
(under `src/`), with a compile-time policy injection. The build system
generates a per-binary `policy.rs` from `config/binary-lock.yaml`:

```
make install-lock:
  for each <path> in lock_surface:
    1. Generate src/policy_<binary>.rs from config/binary-lock.yaml
    2. cargo build --release --features "binary-guard,<binary>"
    3. Copy target/release/workspace-binary-guard to <path>
    4. Apply contain procedure (section 4.1)
```

The guard binary reuses the git-guard's security hardening (REQ-GGUARD-120
through REQ-GGUARD-125): `panic = "abort"`, full RELRO, stack protector,
no `unsafe` outside documented FFI, no network I/O, no dynamic loading.

---

## 6. Environment Sanitisation

Each guard sanitises the child environment before `execve()`. The
allow-list approach from SPEC-GIT-GUARD section 5.4 is reused: the guard
constructs a minimal environment from scratch rather than surgically removing
dangerous variables.

Common stripped variables (all guards):

```
LD_PRELOAD          LD_LIBRARY_PATH     LD_AUDIT          LD_DEBUG
GCONV_PATH          GETCONF_DIR         NLSPATH           TMPDIR
TZDIR               RES_OPTIONS         HOSTALIASES       LOCALDOMAIN
NIS_PATH            RESOLV_HOST_CONF    LOCPATH           MALLOC_TRACE
GLIBC_TUNABLES      PATH                (reset to known-safe value)
```

PATH is always reset to `//usr/local/bin:/usr/bin:/bin` (matching the
git-guard behaviour). HOME, USER, LANG, LC_* are preserved.

---

## 7. Audit Logging

Each guard logs blocked invocations to `//var/log/workspace-binary-guard.log`
with:

```
<ISO-8601-timestamp>|<cwd>|<binary>|<reason>|uid=<real-uid>|argv=<sanitized-args>
```

The log is written only after the block decision is made. If the log file
cannot be opened, the block is still enforced. Argument values that may
contain secrets are replaced with `...`.

---

## 8. Known Residual Risks

| Risk | Mitigation layer | Residual |
|------|-----------------|----------|
| Guard binary itself is replaced | `chattr +i` on guard? No: the guard is 0755, not immutable. | Partial: AIDE detects the change. |
| `.real` binary page-cache corruption (Copy Fail) | seccomp block `AF_ALG` | Full: See SPEC-SANDBOX. |
| New SUID binary added by apt upgrade | dpkg-divert + apt hook | Partial: hook warns but does not auto-contain. |
| SGID binaries not contained | drift checker monitors | Documented: future extension. |
| Kernel exploit via SUID binary (not in guard logic) | seccomp + cap drop in sandbox | Full when sandboxed. |

---

## 9. References

1. [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md) section 3: CVE catalog
2. [REQ-SANDBOX](../requirements/REQ-SANDBOX.md) section 1: REQ-LCK-* requirements
3. [references/gtfobins-suid.html](../references/gtfobins-suid.html): GTFOBins SUID list
4. [references/konstruktoid-suid-list.txt](../references/konstruktoid-suid-list.txt): curated SUID baseline
5. [references/NVD-CVE-2021-4034.html](../references/NVD-CVE-2021-4034.html): PwnKit advisory
6. [references/sudo-Baron-Samedit-CVE-2021-3156.html](../references/sudo-Baron-Samedit-CVE-2021-3156.html): Baron Samedit advisory
7. [references/sudo-chroot-CVE-2025-32463.html](../references/sudo-chroot-CVE-2025-32463.html): sudo chroot LPE advisory
8. [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md): the original guard pattern spec
9. [REQ-GIT-GUARD](../requirements/REQ-GIT-GUARD.md): the original guard requirements