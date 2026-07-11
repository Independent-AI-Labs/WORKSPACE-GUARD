# Requirements: System-Binary Lockdown, Capability Throttle, and Sandbox Stack

**Date:** 2026-07-08
**Status:** DRAFT
**Type:** Requirements

---

## Background

The git guard at `/usr/bin/git` (specified in [REQ-GIT-GUARD](REQ-GIT-GUARD.md))
proves the pattern: relocate the real binary to `0700 root:root`, install a
thin compiled wrapper that validates arguments and `execve()`s the real one,
and lock the inode with `chattr +i`. This document extends that pattern to the
rest of the privilege-granting surface on a Linux host so that an AI agent
running on the box cannot escalate to root, cannot read `/etc/shadow`, cannot
read `~/.ssh/id_rsa`, and cannot persist.

The program is split into four layers, each grounded in a public reference
cached in [docs/references/](../references/SOURCES.md):

1. **Binary lock** (file mode + immutable inode). [SPEC-BINARY-LOCK](../specifications/SPEC-BINARY-LOCK.md)
2. **Capability throttle** (per-binary cap drop). [SPEC-CAP-THROTTLE](../specifications/SPEC-CAP-THROTTLE.md)
3. **Sandbox stack** (seccomp + Landlock + namespaces + cgroups, or microVM).
   [SPEC-SANDBOX](../specifications/SPEC-SANDBOX.md)
4. **Audit + drift** (auditd, AIDE, baseline diff, remote syslog).
   [SPEC-AUDIT](../specifications/SPEC-AUDIT.md)

The threat model and CVE catalog that these requirements defend against are in
[RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md).

---

## 1. Binary Lock Requirements (REQ-LCK-*)

### 1.1 Scope and Discovery

- **REQ-LCK-001**: The binary lock program shall identify every SUID binary
  on the host by running `find / -xdev -perm -4000 -type f` and every file
  with capabilities by running `getcap -r /`. The combined set is the **lock
  surface**.
- **REQ-LCK-002**: The lock surface shall be matched against the GTFOBins
  SUID list (fetched from `https://gtfobins.github.io/#+suid`) and the
  konstruktoid curated SUID baseline (fetched from
  `https://raw.githubusercontent.com/konstruktoid/hardening/master/misc/suid.list`)
  on every run of `scripts/sync-gtfobins`. Only binaries present on the
  current machine AND listed in GTFOBins are locked; absent binaries are
  recorded but skipped.
- **REQ-LCK-003**: The script shall parse the GTFOBins HTML by extracting
  every `<h2>` tag whose text matches a binary name and whose sibling section
  contains the `#+suid` tag marker. The parse is pure text extraction from
  the fetched HTML body; no headless browser is used.
- **REQ-LCK-004**: The script shall output two YAML baselines to `res/`:
  `res/suid-baseline.yaml` (every live SUID binary with path, owner, mode,
  sha256, and GTFOBins match status) and `res/fcap-baseline.yaml` (every live
  file capability with path, cap string, and recommended action).

### 1.2 Contain-via-Guard Disposition

- **REQ-LCK-010**: No binary shall be purged or removed. The disposition for
  every lock-surface binary is **contain-via-guard**: relocate the real
  binary, install a guard, and audit. This is the only allowed action.
- **REQ-LCK-011**: For each lock-surface binary, the contain procedure is:
  1. Copy `<path>` to `<path>.real` with owner `root:root` and mode `0700`.
  2. Verify the copy matches the original via SHA-256 comparison.
  3. Install the compiled guard binary at `<path>` with mode `0755`.
  4. Set `chattr +i` on `<path>.real` to prevent modification even by root.
  5. Register a `dpkg-divert` so apt upgrades do not overwrite the guard.
- **REQ-LCK-012**: The guard binary for each contained binary shall reject
  invocation by non-root users with exit code 2, except where the binary has a
  documented need for unprivileged access (e.g., `passwd` for the user's own
  password change). The allow-unprivileged list is defined in
  [SPEC-BINARY-LOCK](../specifications/SPEC-BINARY-LOCK.md) section 3.
- **REQ-LCK-013**: The guard binary shall call `execve()` with an absolute
  path to `<path>.real`. It shall never use `execvp()` or PATH-based lookup.
- **REQ-LCK-014**: The guard binary shall verify `<path>.real` exists, is a
  regular file, is owned by root, and has mode `0700` before exec-ing it. If
  verification fails, exit code 2.

### 1.3 Inode Immutability

- **REQ-LCK-020**: `chattr +i` shall be set on every `<path>.real` file. This
  prevents deletion, rename, content modification, and mode change by any
  user including root while the immutable flag is set.
- **REQ-LCK-021**: The install procedure shall remove the immutable flag
  (`chattr -i`) before replacing or upgrading a guard, then re-apply it
  after. The procedure is documented in
  [SPEC-BINARY-LOCK](../specifications/SPEC-BINARY-LOCK.md) section 4.
- **REQ-LCK-022**: The drift checker (`scripts/suid-drift-check`) shall detect
  if the immutable flag has been removed from any `<path>.real` file and emit
  a CRITICAL alert. This is the primary tamper signal.

### 1.4 dpkg-divert Integration

- **REQ-LCK-030**: A `dpkg-divert` shall be registered for each contained
  binary so that `apt install <package>` and `apt upgrade` do not overwrite
  the guard. The divert redirects `<path>` to `<path>.distrib`.
- **REQ-LCK-031**: An apt post-invoke hook at
  `/etc/apt/apt.conf.d/99workspace-guard-binary-lock` shall detect when a
  package containing a contained binary is installed, upgraded, or removed,
  and emit a warning directing the user to re-run `make install-lock`. The
  hook shall NOT reinstall guards on its own; it only warns.

### 1.5 Per-Binary Policy

- **REQ-LCK-040**: Every exploitable binary (full GTFOBins coverage) shall
  have a rule in `config/binary-policy-rules.yaml` (host-independent:
  name + tags keyed, first-match-wins) and a generated entry in
  `res/binary-lock.yaml` (per-host snapshot with `path` + `contained` flag)
  specifying: binary name, tags, guard behavior (deny-all for non-root,
  allow-specific-subcommands, pass-through), environment sanitisation list,
  and audit-log fields. One generic guard binary is compiled from the
  generated table; no per-binary build target exists. The schema is defined
  in [SPEC-BINARY-LOCK](../specifications/SPEC-BINARY-LOCK.md) section 5.
- **REQ-LCK-041**: The default policy for a contained binary with no
  documented unprivileged use is **deny-all for non-root**: the guard exits 2
  for any non-root invocation and execs the real binary for root.
- **REQ-LCK-042**: The following binaries shall use a pass-through guard
  (root execs directly, non-root is denied) with no argument validation
  beyond the deny-non-root check: `mount`, `umount`, `su`, `newgrp`, `chsh`,
  `chfn`, `gpasswd`, `pkexec`.
- **REQ-LCK-043**: The following binaries shall use an argument-validating
  guard that allows specific subcommands for non-root and denies the rest:
  `passwd` (allow `passwd` with no args or `passwd <own-username>`),
  `sudo` (allow `sudo` and `sudoedit` with argument validation per
  REQ-LCK-044), `newuidmap` and `newgidmap` (allow only for the invoking
  user's own subordinate ID range).
- **REQ-LCK-044**: The `sudo` guard shall reject the following patterns
  (based on CVE-2021-3156 and CVE-2025-32463):
  - Any argument ending with a trailing backslash (`\`) when used with
    `sudoedit -s` (Baron Samedit trigger).
  - The `-R` / `--chroot` flag and `--host` flag (CVE-2025-32463 / 32462).
  - The `--` separator followed by a backslash-terminated argument.
- **REQ-LCK-045**: The `pkexec` guard shall reject ALL non-root invocations
  with exit code 2. There is no safe unprivileged use of pkexec on an
  agent-only host. (CVE-2021-4034 mitigation.)

---

## 2. Capability Throttle Requirements (REQ-CAP-*)

### 2.1 Discovery and Baseline

- **REQ-CAP-050**: The sync script shall enumerate every file capability on
  the host via `getcap -r /` and emit `res/fcap-baseline.yaml` with the path,
  capability string, and recommended action (keep, strip, or throttle).
- **REQ-CAP-051**: The recommended action for each capability is determined
  by the allowlist in `config/cap-allowlist.yaml`. Capabilities not in the
  allowlist for a given binary path are marked `strip`.

### 2.2 Throttle Policy

- **REQ-CAP-060**: The following capabilities shall be **stripped from every
  binary** that is not in the explicit allowlist:
  - `cap_dac_read_search` (Shocker CVE-2014-0038, never needed by agent
    workloads).
  - `cap_sys_admin` (broad privilege, only needed by mount/umount which are
    already SUID-contained).
  - `cap_sys_module` (kernel module loading, never needed by agent).
  - `cap_sys_ptrace` (ptrace, enables process inspection/injection, blocked
    by seccomp anyway).
  - `cap_net_raw` (raw sockets, dropped from agent workloads per
    SPEC-CAP-THROTTLE).
  - `cap_net_admin` (nftables CVE-2023-0179, dropped from agent workloads).
  - `cap_bpf` (BPF programs, never needed by agent).
  - `cap_linux_immutable` (only the install procedure needs this for
    `chattr +i`; no runtime binary should carry it).
- **REQ-CAP-061**: The following capabilities are **allowed** only for the
  listed binary paths:
  - `cap_dac_override` for `/usr/bin/git` (the guard, for reading
    root-owned `.git/` directory entries).
  - `cap_net_raw` for `/usr/bin/ping` and `/usr/bin/mtr-packet` (ICMP
    echo, expected).
  - `cap_setuid` for `/usr/bin/sudo`, `/usr/bin/su`, `/usr/bin/passwd`
    (identity switching, already SUID).
  - `cap_setpcap` for `/usr/bin/sudo` (transitive cap passing).
- **REQ-CAP-062**: Any capability found on a binary that is not in the
  allowlist shall be stripped via `setcap` during `make install-lock`. The
  pre-strip state is recorded in `res/fcap-baseline.yaml` for audit.
- **REQ-CAP-063**: The drift checker shall detect new file capabilities
  added after baseline and emit a WARNING. New caps on agent-accessible paths
  are a privilege-escalation signal.

### 2.3 Systemd CapabilityBoundingSet

- **REQ-CAP-070**: The systemd unit for agent workloads (defined in
  [SPEC-SANDBOX](../specifications/SPEC-SANDBOX.md)) shall set
  `CapabilityBoundingSet=` to drop: `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`,
  `CAP_NET_RAW`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH`,
  `CAP_LINUX_IMMUTABLE`, `CAP_BPF`, `CAP_PERFMON`, `CAP_CHECKPOINT_RESTORE`,
  `CAP_SYS_PACCT`, `CAP_SYS_NICE`, `CAP_SYS_BOOT`, `CAP_SYS_TIME`,
  `CAP_SYS_TTY_CONFIG`, `CAP_WAKE_ALARM`, `CAP_BLOCK_SUSPEND`,
  `CAP_AUDIT_READ`, `CAP_AUDIT_WRITE`, `CAP_AUDIT_CONTROL`,
  `CAP_SETFCAP`, `CAP_MAC_ADMIN`, `CAP_MAC_OVERRIDE`.
- **REQ-CAP-071**: The systemd unit shall set `NoNewPrivileges=yes` so that
  SUID binaries inside the unit cannot re-escalate. This is the PR_SET_NO_NEW_PRIVS
  equivalent at the systemd level.
- **REQ-CAP-072**: The systemd unit shall set `RestrictAddressFamilies=AF_UNIX
  AF_INET AF_INET6 AF_NETLINK` and explicitly omit `AF_ALG` (CVE-2026-31431
  Copy Fail mitigation).

---

## 3. Sandbox Stack Requirements (REQ-SBX-*)

### 3.1 Profile Picker

- **REQ-SBX-100**: The sandbox launcher (`scripts/sandbox-launcher`) shall
  accept a `--profile <name>` selector that chooses one of three profiles
  shipped in `config/sandbox/`:
  - `rootless`: Landlock + seccomp-bpf + user/mount/net namespaces + cgroups.
    Cold-start under 5ms. Shared kernel.
  - `gvisor`: gVisor runsc Sentry intercepts syscalls. Cold-start under
    200ms. No host kernel syscall from the workload.
  - `firecracker`: Firecracker microVM with a separate guest kernel.
    Cold-start under 125ms. Full kernel isolation.
- **REQ-SBX-101**: The launcher shall refuse to run without a profile. There
  is no default profile: the user picks per workload. If no `--profile` is
  given, exit code 2 with a message listing the available profiles.
- **REQ-SBX-102**: The profile selection may be stored in
  `config/sandbox/profiles.yaml` mapped by hostname pattern, so the launcher
  can auto-select based on the current hostname if `--profile auto` is passed.
  The auto-selection logic is in the launcher script, not in a compiled
  binary.

### 3.2 Rootless Profile (Landlock + seccomp)

- **REQ-SBX-110**: The rootless profile shall set `PR_SET_NO_NEW_PRIVS` on
  the child process before exec so SUID binaries inside the sandbox cannot
  re-escalate.
- **REQ-SBX-111**: The rootless profile shall apply a seccomp-bpf filter that
  blocks the following syscalls (returns `EPERM`):
  - `open_by_handle_at` (Shocker CVE-2014-0038).
  - `mount`, `mount_setattr`, `umount2`, `pivot_root`, `move_mount`,
    `open_tree` (overlayfs CVE-2023-0386, mount injection).
  - `ptrace`, `process_vm_readv`, `process_vm_writev` (process inspection).
  - `bpf`, `perf_event_open`, `fanotify_init`, `userfaultfd` (kernel
    observability / write primitives).
  - `io_uring_setup`, `io_uring_enter`, `io_uring_register` (io_uring
    attack surface).
  - `personality` (personality flags can disable ASLR).
  - `kexec_load`, `kexec_file_load` (kernel replacement).
  - `init_module`, `finit_module`, `delete_module` (kernel modules).
  - `create_module` (deprecated module syscall).
  - `settimeofday`, `clock_settime` (time manipulation).
- **REQ-SBX-112**: The rootless profile shall block `socket(AF_ALG, ...)`
  by filtering the `socket` syscall with seccomp: if `domain == AF_ALG`
  (38 on Linux), return `EPERM`. This is the Copy Fail CVE-2026-31431
  mitigation.
- **REQ-SBX-113**: The rootless profile shall create a new user namespace,
  mount namespace, and network namespace for the child. The network namespace
  has no interfaces (loopback only) unless `--net-host` is passed.
- **REQ-SBX-114**: The rootless profile shall apply Landlock rules that deny
  write access to: `/etc`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/boot`,
  `/root`, and every `~/.ssh/` directory. Read access is allowed to `/etc`
  (needed for resolver, nsswitch) but denied to `/etc/shadow`,
  `/etc/gshadow`, and `/root/.ssh/`.
- **REQ-SBX-115**: The rootless profile shall set the following cgroup limits
  on the child:
  - `memory.max`: 512 MiB (configurable in profile).
  - `cpu.max`: 200000 100000 (2 cores, configurable).
  - `pids.max`: 256 (configurable).
  - `rwqos.max`: 50 (block I/O, configurable).
- **REQ-SBX-116**: The rootless profile shall set `RLIMIT_CORE` to 0 (no
  core dumps) and `RLIMIT_NOFILE` to 256 on the child.

### 3.3 gVisor Profile

- **REQ-SBX-120**: The gVisor profile shall invoke `runsc` with
  `--platform=systrap` (or `ptrace` if systrap is unavailable) and a
  `--network=none` or `--network=host` flag per the profile config.
- **REQ-SBX-121**: The gVisor profile shall pass `--no-new-privs` to runsc
  to enforce `NoNewPrivileges` inside the sandbox.
- **REQ-SBX-122**: The gVisor profile shall not grant any file capabilities
  to the workload. The runsc Sentry intercepts syscalls, so the host kernel
  syscall surface is not directly reached.

### 3.4 Firecracker Profile

- **REQ-SBX-130**: The Firecracker profile shall boot a microVM with a
  separate guest kernel and a read-only root filesystem.
  The guest kernel is loaded from `config/sandbox/vmlinux` and the rootfs
  from `config/sandbox/rootfs.ext4`.
- **REQ-SBX-131**: The Firecracker profile shall not share any host
  namespace with the agent. Network is via a TAP device or `--net=none`.
- **REQ-SBX-132**: The Firecracker profile shall set a CPU limit (default 2
  vCPUs) and memory limit (default 512 MiB) configurable in the profile.

### 3.5 Sandbox Audit

- **REQ-SBX-140**: Every sandbox launch shall be logged to
  `/var/log/workspace-sandbox.log` with: timestamp (ISO 8601), profile name,
  hostname, PID, command, and exit code.
- **REQ-SBX-141**: A sandbox launch that fails to apply seccomp, Landlock,
  or namespace setup shall exit code 3 and NOT exec the workload. Failure to
  sandbox is a hard failure: the workload does not run unconfined.

---

## 4. Audit and Drift Requirements (REQ-AUD-*)

### 4.1 auditd Rules

- **REQ-AUD-150**: The install procedure shall install auditd rules that
  log the following events to `/var/log/audit/audit.log`:
  - `setxattr` / `removexattr` on any file (immutable flag change, cap
    change).
  - `setcap` (file capability change).
  - `open` with `O_WRONLY` or `O_RDWR` on any `*.real` file (guard
    binary tamper).
  - `execve` of any `*.real` file directly (bypass attempt).
  - `socket(AF_ALG, ...)` (Copy Fail vector, if seccomp is not in place).
  - `mount` syscall (overlayfs LPE vector).
  - `open_by_handle_at` (Shocker vector).
- **REQ-AUD-151**: The auditd rules shall be installed via
  `/etc/audit/rules.d/99-workspace-guard.rules` and activated with
  `augenrules --load`. The rules file is generated by
  `scripts/sync-gtfobins` from the baseline.

### 4.2 AIDE / FIM

- **REQ-AUD-160**: The install procedure shall configure AIDE (or sha256sum
  FIM if AIDE is not installed) to track: every `*.real` file, every guard
  binary, `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, and
  `/etc/sudoers.d/*`.
- **REQ-AUD-161**: AIDE database init shall run after `make install-lock`
  and the database shall be stored at `/var/lib/aide/aide.db` (or
  `res/fim-baseline.sha256` if AIDE is absent).
- **REQ-AUD-162**: `make drift-check` shall run AIDE `--check` (or
  sha256sum comparison) and report any file that changed since the baseline.
  Changes to `*.real` files are CRITICAL. Changes to `/etc/sudoers` are
  WARNING. Other changes are INFO.

### 4.3 Drift Detection

- **REQ-AUD-170**: `scripts/suid-drift-check` shall compare the current live
  SUID/SGID/fcap surface against `res/suid-baseline.yaml` and
  `res/fcap-baseline.yaml`. Any new SUID binary, any removed SUID binary,
  any new file capability, any mode change on a `*.real` file, or any
  removed `chattr +i` flag is a drift event.
- **REQ-AUD-171**: Drift events are classified:
  - **CRITICAL**: new SUID binary on a GTFOBins-listed path, removed
    immutable flag on a `*.real` file, mode change on a `*.real` file to
    anything other than `0700`, new file capability on an agent-accessible
    binary.
  - **WARNING**: new SUID binary not on GTFOBins, removed SUID binary (may
    indicate an apt upgrade overwriting a guard), sudoers file change.
  - **INFO**: new file in a watched directory that is not a binary.
- **REQ-AUD-172**: The drift checker shall exit non-zero if any CRITICAL
  drift is found. CI pipelines call `make drift-check` as a gate.
- **REQ-AUD-173**: The drift checker shall output a machine-readable YAML
  report at `res/drift-report.yaml` and a human-readable summary to stdout.

### 4.4 Remote Syslog (optional)

- **REQ-AUD-180**: The auditd rules may optionally forward to a remote
  syslog server if `config/audit-remote.yaml` is present and contains a
  `remote:` key with host and port. This is optional and not required for
  the program to function.
- **REQ-AUD-181**: If remote syslog is configured, the forwarder shall use
  TLS and shall buffer locally if the remote is unreachable. The buffer
  size is configurable in `config/audit-remote.yaml`.

---

## 5. Sync Script Requirements (REQ-SYNC-*)

- **REQ-SYNC-200**: `scripts/sync-gtfobins` shall fetch the GTFOBins SUID
  list, sudo list, and capabilities list from their canonical URLs on every
  run. The fetch uses `curl` with a 30-second timeout. If the fetch fails,
  the script exits non-zero and does NOT update the baseline.
- **REQ-SYNC-201**: The script shall parse the fetched GTFOBins HTML to
  extract binary names from `<h2>` tags in the `#+suid` filtered view. The
  parse logic is a simple text extraction: find `<h2>`, read text until
  `</h2>`, strip tags, match against a binary-name regex
  (`^[a-z][a-z0-9_-]+$`).
- **REQ-SYNC-202**: The script shall run `find / -xdev -perm -4000 -type f`
  and `getcap -r /` on the current machine and match the live result against
  the parsed GTFOBins list.
- **REQ-SYNC-203**: The script shall emit `res/suid-baseline.yaml` with
  the schema:
  ```yaml
  suid_binaries:
    - path: /usr/bin/sudo
      owner: root
      group: root
      mode: "4755"
      sha256: <hash>
      gtfobins: true
      gtfobins_tags: ["sudo"]
      contained: true
    - path: /usr/bin/mount
      ...
  ```
- **REQ-SYNC-204**: The script shall emit `res/fcap-baseline.yaml` with
  the schema:
  ```yaml
  file_capabilities:
    - path: /usr/bin/git
      caps: "cap_chown,cap_dac_override"
      recommended: "throttle"
      allowed: "cap_dac_override"
      strip: ["cap_chown"]
  ```
- **REQ-SYNC-205**: The script shall emit `res/cve-catalog.yaml` from the
  hardcoded CVE list in `docs/RESEARCH-SYSTEM-BINARIES.md` section 3. The
  catalog is maintained as a static reference, not fetched dynamically,
  because NVD rate-limits and the CVE list is curated.
- **REQ-SYNC-206**: The script shall support `--dry-run` which prints the
  planned actions (what would be contained, what caps would be stripped)
  without making any changes. Dry-run output goes to stdout.
- **REQ-SYNC-207**: The script shall support `--verify` which re-downloads
  every canonical source HTML and emits a SHA-256 manifest at
  `res/canonical-sources.sha256` so drift between the cached copy and the
  canonical URL is detectable.
- **REQ-SYNC-208**: The script shall NOT use bare interpreter invocations
  outside `uv run`. It is a bash script. All text processing uses standard tools
  (`grep`, `awk`, `find`, `sha256sum`, `stat`) available on the target
  host. (Exception: the script may invoke `uv run` with the venv
  interpreter if YAML generation needs a library, but the fetch and parse
  logic is bash.)

---

## 6. Makefile Target Requirements (REQ-MAKE-*)

- **REQ-MAKE-250**: The Makefile shall provide a `sync-gtfobins` target that
  runs `scripts/sync-gtfobins` and emits the YAML baselines to `res/`.
- **REQ-MAKE-251**: The Makefile shall provide a `drift-check` target that
  runs `scripts/suid-drift-check` and exits non-zero on CRITICAL drift.
- **REQ-MAKE-252**: The Makefile shall provide an `install-lock` target that
  runs `scripts/sync-gtfobins` (to generate baselines) and then applies the
  contain-via-guard procedure to every lock-surface binary. This target
  requires root and shall print a warning before making changes.
- **REQ-MAKE-253**: The Makefile shall provide an `install-sandbox` target
  that deploys the sandbox profiles to `config/sandbox/` and installs the
  launcher at `/usr/local/bin/workspace-sandbox-launcher`.
- **REQ-MAKE-254**: The Makefile shall provide an `install-auditd` target
  that installs the auditd rules and AIDE/FIM baseline.
- **REQ-MAKE-255**: The Makefile shall provide an `uninstall-lock` target
  that reverses the contain-via-guard procedure: removes `chattr +i`,
  restores `<path>.real` to `<path>`, removes the `dpkg-divert`, and
  recomputes the baseline.

---

## 7. Compliance Artifact Requirements (REQ-ART-*)

- **REQ-ART-300**: The program shall ship a CIS DIL mapping document at
  `docs/cis-mapping.md` that maps each CCE control in the CIS Debian/Linux
  Level 1 benchmark to the program layer that satisfies it. The cached CIS
  reference is at [references/cis-dil-benchmark-suid-rb.html](../references/cis-dil-benchmark-suid-rb.html).
- **REQ-ART-301**: The program shall ship a systemd unit template at
  `config/systemd/workspace-agent@.service` that codifies the
  `CapabilityBoundingSet=`, `NoNewPrivileges=yes`, `ProtectSystem=strict`,
  `ProtectHome=true`, `PrivateTmp=true`, and
  `RestrictAddressFamilies` settings from REQ-CAP-070 through REQ-CAP-072.
- **REQ-ART-302**: The program shall ship an auditd rules template at
  `config/auditd/99-workspace-guard.rules` that codifies the rules from
  REQ-AUD-150.

---

## Constraints

- **Root required**: `make install-lock`, `make install-auditd`, and
  `make uninstall-lock` require root. The sync script and drift checker do
  not require root (they read-only scan).
- **No purge**: No binary is ever removed. The disposition is always
  contain-via-guard + audit. Purging breaks system updates and package
  management.
- **No bare interpreter**: Scripts use bash only. No bare interpreter
  invocations outside a venv (`uv run`). YAML generation may use `uv run`
  with the venv interpreter if needed.
- **File length**: All `.sh` scripts are under 512 lines. All `.md`
  documents are not subject to file length limits but should be concise.
- **Banned words**: All documents follow the repo banned words policy. No
  AI slop terms, no corporate waffle, no Unicode em-dashes.
- **Offline reproducible**: The cached reference HTML in `docs/references/`
  is committed so the build is reproducible without network access. The
  sync script re-fetches on demand but the committed copy is the source of
  truth for documentation quotes.

---

## Non-Requirements

- **Kernel patching**: The program does not patch the kernel. Kernel CVE
  mitigations are via seccomp/cap drop/namespace isolation, not kernel
  upgrades. Kernel patching is the operator's responsibility.
- **Network firewall**: The program does not configure iptables/nftables.
  Network isolation is via network namespaces (no interfaces) or gVisor /
  Firecracker isolation.
- **Container runtime replacement**: The program does not replace Docker or
  Podman. The sandbox launcher is a separate tool for AI agent workloads,
  not a general container runtime.
- **Multi-host orchestration**: The program runs on a single host. Fleet
  management is out of scope.
  Ansible/playbook integration is a future extension.
- **GUI agents**: The program targets CLI AI agents. GUI automation agents
  that need X11/Wayland access are out of scope for the sandbox profiles
  defined here.