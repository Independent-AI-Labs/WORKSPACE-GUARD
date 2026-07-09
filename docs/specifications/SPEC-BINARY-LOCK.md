# Specification: Binary Lock (SUID/CAP Contain-via-Guard)

**Date:** 2026-07-08
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-SANDBOX](../requirements/REQ-SANDBOX.md)
**Threat Model:** [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md)

---

## 1. Architecture Overview

### 1.1 One generic guard binary

There is ONE compiled Rust guard binary, not one per contained binary. The
same binary is installed at every contained path. At runtime the guard reads
`basename(argv[0])` and uses that to look up its policy in a
compile-time-baked table (`BINARY_POLICIES`). No runtime config file read:
the security model matches git-guard (policy decisions are immutable after
build, not readable or writable from the filesystem at runtime).

```
  User invokes: /usr/bin/sudoedit -s '\'  some_arg\
                       |
                       v
            /usr/bin/sudoedit          (guard, mode 0755, root:root)
            == target/release/workspace-binary-guard (a copy thereof)
                       |
           +-----------+----------------+
           |           |                |
           v           v                v
      Read         Check policy      Sanitise env
      basename     from table:       vars, PATH
      argv[0]      find_policy(
        -> sudo     "sudoedit")
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

1. A copy of the generic guard binary at the original path (mode 0755).
2. The real binary relocated to `<path>.real` (mode 0700, root:root).
3. `chattr +i` on `<path>.real` to prevent tampering.
4. A `dpkg-divert` so apt upgrades do not overwrite the guard.

The guard itself is a thin wrapper: it looks up the policy for
`basename(argv[0])`, validates args against that policy, sanitises the
environment, and `execve()`s the real binary. It does NOT re-implement the
binary's logic.

### 1.2 Why one binary, not one per contained path

GTFOBins lists 320+ SUID-exploitable binaries. Hand-curating a per-binary
lock surface per host fails the "full coverage, data-driven" objective: a
new host with a different distro ships a different SUID set, and the catalog
must already know how to handle each binary, not just the handful this host
happens to have today. So the policy table covers the entire GTFOBins
universe at build time, and the install step selects the on-host subset. No
recompile, no per-binary cargo feature, no `policy_<binary>.rs` source files.
The build produces exactly one `workspace-binary-guard` binary; `make
install-lock` copies that one binary to every contained path.

### 1.3 Codegen boundary

`build.rs` emits ONLY a data table:

```rust
// pub const BINARY_POLICIES: &[BinaryPolicy] = &[ ... ];   <-- generated
```

All struct definitions (`BinaryPolicy`, `RejectRule`), the `RejectKind`
enum, the `find_policy` function, and every runtime function (`decide`,
`check_arg_validate`, `build_sanitized_env`, `execve_real`, `log_block`,
`main`) live in hand-written source:

- `src/binary_policy_types.rs` -- `BinaryPolicy`, `RejectRule`,
  `RejectKind`, `find_policy`. Hand-written, IDE-supported, no string-built
  structs.
- `src/binary_guard.rs` -- the guard runtime binary. `include!`s the
  generated table.

The generated file contains zero `fn`, zero `struct`, zero `enum`. It is a
single `const` literal the type-checker validates against the hand-written
structs in `binary_policy_types.rs`.

---

## 2. Policy Catalog (full GTFOBins coverage)

### 2.1 Two files, one build pipeline

Policy data lives in two YAML files with distinct lifecycles:

| File | Lifecycle | Author | Scope |
|------|-----------|--------|-------|
| `config/binary-policy-rules.yaml` | hand-maintained, committed | human | host-INdependent rules covering the FULL GTFOBins universe |
| `res/binary-lock.yaml` | generated, committed snapshot | `make sync-gtfobins` | per-ON-host view: full GTFOBins set + `contained:` flag |

`config/binary-policy-rules.yaml` is the catalog of rules. Every GTFOBins
binary has a rule here (or falls through to a catch-all tag rule). Rules are
keyed on tag AND name, first-match-wins. The file never references a host
path or a live SUID listing -- only `name:` and `tags:` (suid, sudo, cap,
etc.).

`res/binary-lock.yaml` is produced by `make sync-gtfobins`, which:

1. Parses the canonical GTFOBins source (cached at
   [references/gtfobins-suid.html](../references/gtfobins-suid.html)) to get
   the full exploitable-binary list with names + tags. ~320 SUID entries,
   ~470 sudo entries, ~8 capability entries.
2. Parses the konstruktoid SUID baseline (cached at
   [references/konstruktoid-suid-list.txt](../references/konstruktoid-suid-list.txt))
   as a second source.
3. Runs `find / -xdev -perm -4000 -type f` (and `-perm -2000` for SGID, and
   `getcap -r /` for file capabilities) to get the live on-host surface.
4. Joins the full GTFOBins set against `config/binary-policy-rules.yaml`:
   name AND tags match, first rule wins. Every GTFOBins binary gets a rule
   (explicit name match, or a tag match, or the default catch-all).
5. For each binary, sets `contained: true` if the binary is present on THIS
   host AND already has a `<path>.real` sibling (i.e. install has run); else
   `contained: false`. This is a per-host snapshot field; the rules and the
   GTFOBins-derived fields are host-independent.
6. Emits `res/binary-lock.yaml` with the full GTFOBins coverage, each row
   carrying: `name`, `tags`, `policy`, `reject_patterns`, `allow_subcommands`,
   `env_sanitise`, `path` (host path), `contained`.

The install runtime reads `res/binary-lock.yaml` and acts ONLY on rows with
`contained: true` (or marks rows `contained: true` as it installs them).
This is how the catalog stays full-coverage while the install installs only
what is present on the host.

### 2.2 Lock surface on this host (generated example)

The discovery command `find / -xdev -perm -4000 -type f` produces the live
SUID set for THIS host. The table below is an example snapshot; the real
table is generated by `make sync-gtfobins` into `res/binary-lock.yaml`. The
`contained` column means install has placed a guard at that path.

| Path | GTFOBins | konstruktoid | Rule matched | Policy | CVE |
|------|----------|-------------|--------------|--------|-----|
| `/usr/bin/sudo` | Y (sudo) | Y | name=sudo | arg-validate | CVE-2021-3156, CVE-2025-32463, CVE-2025-32462 |
| `/usr/bin/su` | Y (su) | Y | tag=suid | deny-non-root | |
| `/usr/bin/mount` | Y (mount) | Y | tag=suid | deny-non-root | |
| `/usr/bin/umount` | Y (umount) | Y | tag=suid | deny-non-root | |
| `/usr/bin/passwd` | Y (passwd) | Y | name=passwd | arg-validate | |
| `/usr/bin/gpasswd` | Y (gpasswd) | Y | tag=suid | deny-non-root | |
| `/usr/bin/chsh` | Y (chsh) | Y | tag=suid | deny-non-root | |
| `/usr/bin/chfn` | Y (chfn) | Y | tag=suid | deny-non-root | |
| `/usr/bin/newgrp` | Y (newgrp) | Y | tag=suid | deny-non-root | |
| `/usr/bin/newuidmap` | N | N | name=newuidmap | arg-validate | |
| `/usr/bin/newgidmap` | N | N | name=newgidmap | arg-validate | |
| `/usr/bin/fusermount3` | Y (fusermount) | N | tag=suid | deny-non-root | |
| `/usr/bin/pkexec` | Y (pkexec) | Y | name=pkexec | deny-all-non-root | CVE-2021-4034 |

Rows for binaries NOT on this host still appear in
`res/binary-lock.yaml` with `contained: false` -- they are part of the
catalog and would be installed if the binary appeared (e.g. on a different
distro). This is how the same compiled guard binary is portable across hosts
without recompile.

### 2.3 SGID binaries

SGID binaries are discovered with `find / -xdev -perm -2000 -type f` and
recorded in the baseline, but the contain-via-guard procedure is NOT applied
to SGID binaries by default. SGID grants group privileges, not root. The
drift checker monitors SGID changes. SGID containment is a future extension
(documented in [SPEC-AUDIT](SPEC-AUDIT.md) section 6, known residual risks).

---

## 3. Policy Rules Catalog

### 3.1 Policy types

The generic guard supports four policy decisions, applied to whichever row
`find_policy(basename(argv[0]))` selects from the compiled-in table:

| Policy type | Behaviour for non-root | Behaviour for root |
|-------------|------------------------|---------------------|
| `deny-non-root` | Exit 2 | execve `.real` |
| `deny-all-non-root` | Exit 2 (no exceptions) | execve `.real` |
| `arg-validate` | Check subcommand allowlist + reject patterns; allow or exit 2 | execve `.real` |
| `pass-through` | execve `.real` (no checks) | execve `.real` |

### 3.2 Rule file schema (`config/binary-policy-rules.yaml`)

The rule file is host-independent. It never carries a `path:` field and never
references a live SUID listing. Each rule is keyed on an AND of `name` and
`tags`. `find_policy` walks the rules in order; first match wins; a final
catch-all rule applies `deny-non-root` to any unmatched `suid`-tagged binary.

```yaml
# config/binary-policy-rules.yaml -- full GTFOBins coverage, host-independent.
# Rules are walked top-to-bottom; first match wins. A row matches when ALL
# non-empty matcher fields agree (name AND tags). The catch-all at the end
# covers every GTFOBins binary without an explicit name rule.

version: 1
rules:
  # --- CVE-specific name rules ---------------------------------------------
  - name: sudo
    tags: [suid, sudo]
    policy: arg-validate
    allow_subcommands: [sudo, sudoedit]
    reject_patterns:
      - { kind: regex, subcommand: sudoedit, requires_flags: [-s],
          pattern: '\\$', reason: "Baron Samedit CVE-2021-3156" }
      - { kind: flag, flag: -R,    reason: "chroot LPE CVE-2025-32463" }
      - { kind: flag, flag: --chroot, reason: "chroot LPE CVE-2025-32463" }
      - { kind: flag, flag: --host, reason: "host confusion CVE-2025-32462" }
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH, GCONV_PATH,
                   GLIBC_TUNABLES, SUDO_ASKPASS]

  - name: pkexec
    tags: [suid]
    policy: deny-all-non-root
    env_sanitise: [GCONV_PATH, LD_PRELOAD, LD_LIBRARY_PATH]

  - name: passwd
    tags: [suid]
    policy: arg-validate
    allow_subcommands: [passwd]
    allow_self_username: true              # passwd <own-username>
    reject_patterns:
      - { kind: flag, flag: -S, reason: "status query requires root" }
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  - name: newuidmap
    tags: []
    policy: arg-validate
    allow_subcommands: [newuidmap]
    validate: subordinate_uid_range
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  - name: newgidmap
    tags: []
    policy: arg-validate
    allow_subcommands: [newgidmap]
    validate: subordinate_gid_range
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  # --- tag-level catch-all: every suid-tagged binary without an explicit ---
  # --- name rule above gets deny-non-root ----------------------------------
  - tags: [suid]
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  # --- capability-bearing binaries (not SUID) ------------------------------
  - tags: [cap]
    policy: deny-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]

  # --- final default: unknown binaries, fail closed ------------------------
  - name: "*"
    policy: deny-all-non-root
    env_sanitise: [LD_PRELOAD, LD_LIBRARY_PATH]
```

This file is the catalog of the full GTFOBins universe. It is hand-maintained
and reviewed. A new binary appearing on a host does NOT require a new rule
here unless it needs a CVE-specific arg-validate policy -- the tag catch-all
handles the rest.

### 3.3 Generated lock file (`res/binary-lock.yaml`)

`make sync-gtfobins` produces this. It is the join of the rule catalog with
the live on-host GTFOBins-derived surface. Each row carries the rule fields
PLUS a `path:` and a `contained:` field:

```yaml
# res/binary-lock.yaml -- generated, DO NOT hand-edit. Regenerate via:
#   make sync-gtfobins
version: 1
generated_at: 2026-07-09T00:00:00Z
binaries:
  - name: sudo
    tags: [suid, sudo]
    path: /usr/bin/sudo
    contained: true               # present on this host AND .real exists
    policy: arg-validate
    allow_subcommands: [sudo, sudoedit]
    reject_patterns: [...]
    env_sanitise: [...]
  - name: su
    path: /usr/bin/su
    contained: false              # present on host, NOT yet installed
    policy: deny-non-root
    ...
  - name: apt                     # not on host, part of full catalog
    tags: [suid]
    contained: false
    policy: deny-non-root
    ...
# ~320 rows total -- every GTFOBins binary, with contained flag per host
```

`build.rs` reads `res/binary-lock.yaml` and emits a single
`pub const BINARY_POLICIES: &[BinaryPolicy] = &[ ... ];` literal. It does
NOT emit structs, enums, or functions. Struct definitions and `find_policy`
live in `src/binary_policy_types.rs`; the guard runtime lives in
`src/binary_guard.rs` (section 5).

### 3.4 sudo guard detail

The sudo rule is the most complex because sudo has three active CVEs:

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

`sudoedit` is a symlink to `sudo` on most distros. The guard resolves this
through `find_policy`: a `name: sudo` rule lists `allow_subcommands: [sudo,
sudoedit]`, so `basename(argv[0]) == "sudoedit"` matches the sudo rule and
shares the same policy. No duplicate rule is needed for the symlink name.

### 3.5 passwd guard detail

The passwd guard allows non-root users to change their own password only:

```
1. argc == 1 (no args) -> ALLOW (change own password)
2. argc == 2 AND argv[1] == current username -> ALLOW
3. -S (status) flag -> BLOCK (requires root)
4. any other arg -> BLOCK
```

The current username is determined via `nix::unistd::User::from_uid(getuid())` (safe wrapper over `getpwuid_r(3)`), reading the `name` field.

### 3.6 newuidmap / newgidmap guard detail

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

### 3.7 pkexec guard detail

The pkexec guard rejects ALL non-root invocations. There is no safe
unprivileged use of pkexec on an agent-only host. CVE-2021-4034 (PwnKit)
showed that even with the polkit policy engine, the binary's own argument
parsing is exploitable. The guard exits 2 for any non-root call.

---

## 4. Installation Procedure

### 4.1 Build the guard binary (once)

```
make build-binary-guard
  -> cargo build --release --features binary-guard
  -> target/release/workspace-binary-guard
```

This build is performed EXACTLY ONCE. The resulting single binary is copied
to every contained path. The build reads `res/binary-lock.yaml` at compile
time and bakes `BINARY_POLICIES` into the binary; at runtime the binary
looks up `basename(argv[0])` in that table.

### 4.2 Contain-via-guard (per path)

For each row in `res/binary-lock.yaml` with `contained: true` (or marked as
installable by the install command):

```
For each <path> in installable rows:
  0. Build/copy guard binary to a staging path (one operation, done in 4.1)
  1. Verify <path> exists and is a regular file
  2. Copy <path> to <path>.real
  3. chown root:root <path>.real
  4. chmod 0700 <path>.real
  5. Verify SHA-256 of <path>.real matches <path>
  6. chattr +i <path>.real
  7. Install guard at <path> BEFORE diverting:
       a. cp guard_binary <path>.guard_new
       b. chown root:root <path>.guard_new
       c. chmod 0755 <path>.guard_new
       d. mv <path>.guard_new <path>      # atomic replace; path is never empty
  8. dpkg-divert --add --rename --divert <path>.distrib <path>
  9. Verify: <path> --version or <path> responds (warm check)
  10. Mark row contained: true in res/lock-state.yaml
```

CRITICAL: step 7 installs the guard at `<path>` BEFORE step 8 diverts. In
the previous destructive ordering, dpkg-divert moved the original to
`<path>.distrib` and left `<path>` empty until a guard was copied in later;
any invocation in that window hit a missing binary. The new ordering ensures
`<path>` is never empty: the original is preserved as `<path>.real` first,
then the guard atomic-mv replaces `<path>` in place, and dpkg-divert is only
registered AFTER the guard is live so apt upgrades cannot displace the guard.

### 4.3 Rollback on failure

If any step fails, the procedure reverses all prior steps for that binary:

```
rollback(path):
  if <path>.real exists:
    chattr -i <path>.real
    if <path> is the guard (verify via basename check, not path):
      rm <path>                       # remove the guard
    cp <path>.real <path>             # restore original from .real
    chown root:root <path>
    chmod 4755 <path>                 # restore original SUID mode
    rm <path>.real
  else if dpkg-divert exists for <path>:
    dpkg-divert --remove --rename <path>   # restore <path>.distrib -> <path>
  emit ERROR, exit 1
```

Rollback uses `register_temp()` (see `scripts/lib/qc.sh`) so any partial
artefact (`<path>.real`, `<path>.guard_new`, immutable bit) is cleaned up
even on unexpected exit (SIGTERM, pipefail in a subshell). The previous
hard-coded `trap '...' EXIT` is replaced by the shared `register_temp()`
registry, which is idempotent and already used by the rest of the toolkit.

### 4.4 Uninstall

```
For each <path> in lock_surface (contained: true rows):
  1. chattr -i <path>.real
  2. Verify <path>.real is a regular file
  3. rm <path> (the guard)
  4. cp <path>.real <path>
  5. chown root:root <path>
  6. chmod 4755 <path>                  # restore original SUID mode
  7. rm <path>.real
  8. dpkg-divert --remove --rename <path>
  9. Verify: <path> works
  10. Mark row contained: false in res/lock-state.yaml
```

---

## 5. Guard Binary Build

There is one guard binary target, `workspace-binary-guard`, built once per
release. There are NO per-binary cargo features and NO per-binary
`policy_<binary>.rs` source files. The full GTFOBins policy universe (~320
rows) is compiled into a single `BINARY_POLICIES` table; the install step
copies the one binary to every contained path.

### 5.1 Source layout

| File | Role | Generated? |
|------|------|-----------|
| `src/binary_policy_types.rs` | `BinaryPolicy`, `RejectRule`, `RejectKind` structs, `find_policy` function. Hand-written under full IDE support. | No |
| `src/binary_guard.rs` | The guard runtime: `decide`, `check_arg_validate`, `build_sanitized_env`, `execve_real`, `log_block`, `main`. `include!`s the generated table. | No |
| `src/binary_guard_tests.rs` | Unit tests for policy decision logic + env sanitisation. | No |
| `OUT_DIR/binary_policies.rs` | The generated `pub const BINARY_POLICIES: &[BinaryPolicy] = &[ ... ];` literal. | Yes (build.rs) |
| `build.rs` | Reads `res/binary-lock.yaml`, deserialises with serde_yaml, emits `OUT_DIR/binary_policies.rs`. Emits ONLY the const table. | -- |
| `res/binary-lock.yaml` | Generated by `make sync-gtfobins`. The build input. | Yes (sync script) |
| `config/binary-policy-rules.yaml` | Hand-maintained rule catalog (full GTFOBins coverage). Input to sync. | No |

The codegen boundary is strict: the generated file contains zero `fn`,
zero `struct`, zero `enum`. Baking logic (function bodies, struct
definitions) into generated strings is forbidden -- it breaks IDE support,
makes diffs unreadable, and is the maintainability failure that this
architecture is designed to avoid. `build.rs` emits a single `const`
literal that the type-checker validates against the hand-written structs
in `binary_policy_types.rs`.

### 5.2 Build command

```
make build-binary-guard
  -> cargo build --release --features binary-guard
  -> target/release/workspace-binary-guard

make install-lock            # ROOT
  -> ensure target/release/workspace-binary-guard is up to date
  -> for each <path> in res/binary-lock.yaml with installable flag:
       copy the one binary to <path>, apply contain procedure (section 4.2)
```

The `binary-guard` cargo feature pulls in the `regex` crate (used by the
arg-validate reject-pattern matcher) and the serde_yaml deserialiser structs
in `build.rs`. Without the feature, the workspace builds as the git-guard
only, with no binary-guard target and no new deps.

### 5.3 Hardening

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