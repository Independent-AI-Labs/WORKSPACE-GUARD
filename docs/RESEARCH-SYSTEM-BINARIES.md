# Research: System-Binary Lockdown, Sandbox Stack, and CVE Catalog

**Date:** 2026-07-08
**Status:** DRAFT
**Type:** Research / Threat Model

---

## 1. Introduction

The git guard at `/usr/bin/git` proves the pattern: relocate the real binary
to `0700 root:root`, install a thin compiled wrapper that validates arguments
and `execve()`s the real one, and lock the inode with `chattr +i`. This file
generalises that pattern to the rest of the privilege-granting surface on a
Linux host so that an AI agent running on the box cannot escalate to root,
cannot read `/etc/shadow`, cannot read `~/.ssh/id_rsa`, and cannot persist.

The program is split into four layers, each grounded in a public reference
cached in [docs/references/](references/SOURCES.md):

1. **Binary lock** (file mode + immutable inode). [SPEC-BINARY-LOCK](specifications/SPEC-BINARY-LOCK.md)
2. **Capability throttle** (per-binary cap drop). [SPEC-CAP-THROTTLE](specifications/SPEC-CAP-THROTTLE.md)
3. **Sandbox stack** (seccomp + Landlock + namespaces + cgroups, or microVM).
   [SPEC-SANDBOX](specifications/SPEC-SANDBOX.md)
4. **Audit + drift** (auditd, AIDE, baseline diff, remote syslog).
   [SPEC-AUDIT](specifications/SPEC-AUDIT.md)

This document is the CVE catalog and the threat model that the four layers
are built to neutralise.

---

## 2. Taxonomy of privilege-grant surface on a Linux box

| Surface | Discovery command | Public reference |
|---------|------------------|------------------|
| SUID binaries | `find / -xdev -perm -4000 -type f` | GTFOBins `#+suid`, konstruktoid SUID list |
| SGID binaries | `find / -xdev -perm -2000 -type f` | CIS DIL 6.1.14 |
| File capabilities | `getcap -r /` | capabilities(7), systemshardening cap-hardening article |
| SUID via setuid bit operation | `stat -c '%a %U %G %n' <path>` | man 2 stat |
| Polkit rules | `pkaction --verbose` | PwnKit advisory (CVE-2021-4034) |
| sudoers | `sudo -l`, `/etc/sudoers`, `/etc/sudoers.d/*` | sudo Baron Samedit + CVE-2025-32463 |
| Kernel attack primitives | `seccomp-bpf` traces of `socket(AF_ALG)` | Copy Fail (CVE-2026-31431) |
| Container escape defaults | `docker inspect`, `capsh --print` | HackTricks cap wiki, Shocker |

The discovery commands above are run by `scripts/sync-gtfobins` every cycle
and the diff against the committed baseline is the drift signal defined in
[SPEC-AUDIT](specifications/SPEC-AUDIT.md). The LIVE output for this box is
captured by `scripts/sync-gtfobins` into `res/suid-baseline.yaml` and
`res/fcap-baseline.yaml`.

---

## 3. CVE catalog (userspace + kernel)

Each entry below lists the affected binary or kernel subsystem, the class of
attack, CVSS where NVD records one, the cached source file the quote is drawn
from, and the mitigation that the four-layer program puts in place. Quotations
are verbatim from the cached advisory HTML in [docs/references/](references/SOURCES.md).

### 3.1 CVE-2021-4034 PwnKit (polkit pkexec)

- **Affected binary:** `/usr/bin/pkexec`
- **Class:** SUID binary argument parsing OOB write / environment injection
- **CVSS:** 7.8 (NVD NVD-CVE-2021-4034.html)
- **Cached source:** references/NVD-CVE-2021-4034.html

> A local privilege escalation vulnerability was found on polkit's pkexec
> utility. The pkexec application is a setuid tool designed to allow
> unprivileged users to run commands as privileged users according predefined
> policies. The current version of pkexec doesn't handle the calling
> parameters count correctly and ends trying to execute environment variables
> as commands. An attacker can exploit this by crafting environment variables
> in such a way it'll induce pkexec to execute arbitrary code.

Mechanism summary: `pkexec` invoked with `argc == 0` reads `argv[1]` from
`envp[0]`. The attacker controls that environment entry. Crafting it to
re-introduce `GCONV_PATH` makes iconv load an attacker-supplied `.so` during
the pkexec startup path. The result is code execution with pkexec's effective
UID (root). Exploitable since May 2009. Patched in polkit 0.105-31 (Jan 2022).

**Mitigation:**

- Relocate `/usr/bin/pkexec` to `/usr/bin/pkexec.real` at `0700 root:root`
  with `chattr +i`. Install a guard binary at `/usr/bin/pkexec` that exits 2
  on any non-root invocation. (Contain-via-guard.)
- Long-term: purge pkexec on agent-only hosts since agent workloads do not
  need interactive polkit auth.
- Do NOT rely on `AT_SECURE`. PwnKit defeats `AT_SECURE` by corrupting the
  auxiliary vector at the C library layer.
- File-cap path does NOT work for pkexec because the exploit does not need
  SUID semantics per se; the binary itself is the bug.

### 3.2 CVE-2021-3156 Baron Samedit (sudo)

- **Affected binary:** `/usr/bin/sudo`
- **Class:** heap overflow in the sudoers parser
- **CVSS:** 7.8 (NVD sudo-Baron-Samedit-CVE-2021-3156.html)
- **Cached source:** references/sudo-Baron-Samedit-CVE-2021-3156.html

> A heap overflow in sudo versions 1.8.2 through 1.8.31p2, 1.9.0 through
> 1.9.5p1, allows any local user to escalate to root without sudoers
> configuration. Triggered by `sudoedit -s '\'` followed by a backslash
> terminated argument.

**Mitigation:**

- Force `sudo >= 1.9.5p2` (or `1.9.17p1` which also closes the chroot bug below).
- Relocate the binary to `sudo.real` and route `sudo` through a guard that
  rejects the `sudoedit -s '\'` pattern and any `\` at end of argument.

### 3.3 CVE-2025-32463 sudo `--chroot` LPE

- **Affected binary:** `/usr/bin/sudo`
- **Class:** confused-deputy; sudo loads `/etc/nsswitch.conf` from a
  user-controlled directory because of `pivot_root()` use during sudoers
  evaluation.
- **CVSS:** 7.8 (NVD NVD-CVE-2025-32463.html)
- **Cached source:** references/sudo-chroot-CVE-2025-32463.html, sudo-chroot-CVE-2025-32463.pdf

> Sudo before 1.9.17p1 allows local users to obtain root access because
> /etc/nsswitch.conf from a user-controlled directory is used with the
> --chroot option.

The advisory text states the default sudo configuration is vulnerable and
that no sudoers rule needs to exist for the user; any local unprivileged user
can escalate to root if a vulnerable version is installed.

**Mitigation:**

- `sudo >= 1.9.17p1` (the `chroot` feature is also marked deprecated to be
  removed entirely).
- Guard rejects `-R` / `--chroot` and `--host` (CVE-2025-32462) flags.

### 3.4 CVE-2023-4911 Looney Tunables (glibc tunables loader)

- **Affected component:** `/lib64/ld-linux-x86-64.so.2` dynamic loader
- **Class:** stack buffer overflow in `GLIBC_TUNABLES` parsing during SUID
  binary startup. Affects every SUID binary that uses glibc dynamic linking.
- **CVSS:** 7.8 (Linux kernel / glibc)
- **Cached source:** derived from capabilities(7) page loader notes,
  references/capabilities.7.html

> The tunables parser copies an unbounded attacker-supplied environment
> string (GLIBC_TUNABLES) into a fixed-size stack buffer before the dynamic
> linker drops to the user's privileges for a SUID binary.

**Mitigation:**

- glibc >= 2.34 ships the parser fix; glibc >= 2.38 has the complete fix.
- Static binary for the guard (musl), so the loader bug does not apply to the
  guard itself. The bound set is defined in `CapabilityBoundingSet=` so even if
  the guard chain is exploited, no host kernel privileges are gained.

### 3.5 CVE-2026-31431 Copy Fail (kernel algif_aead)

- **Affected subsystem:** Linux kernel `algif_aead` (the `AF_ALG` crypto
  socket API), versions pre 6.19.12 / 6.18.22 / 7.0
- **Class:** arbitrary page-cache write to a SUID binary, root without disk
  tamper; AIDE / Tripwire do not detect it.
- **CVSS:** 7.8 (Xint Code analysis)
- **Cached source:** RESEARCH.md citation list, point 2 (CVE-2026-31431 entry)

> An unprivileged local user corrupts the page cache of SUID binaries via
> AF_ALG + splice(), achieving root without modifying the on-disk file.

Mechanism is captured in RESEARCH.md sections 3.1-3.5. The on-disk inode is
never modified; kernel loads the corrupted in-memory page when the SUID binary
is next executed.

**Mitigation:**

- Patch the kernel to >= 6.19.12 / 6.18.22.
- `seccomp-bpf` block `socket(AF_ALG, SOCK_SEQPACKET, 0)` for the agent.
  This is `RestrictAddressFamilies=~AF_ALG` in the systemd unit defined in
  [SPEC-SANDBOX](specifications/SPEC-SANDBOX.md).
- Module blacklist `algif_aead` and `algif_skcipher` in
  `/etc/modprobe.d/blacklist-workspace.conf`.
- Use `getcap` to verify guard binary never carries `cap_net_raw` (which
  eliminates the option to bind `AF_ALG` if it ever reaches the sandbox
  outside the syscall filter).
- Falco rule for AF_ALG SEQPACKET socket creation in agent workloads.

### 3.6 CVE-2014-0038 Shocker (containerised CAP_DAC_READ_SEARCH)

- **Affected:** Any container that retains `CAP_DAC_READ_SEARCH`
- **Class:** `open_by_handle_at()` brute-forces host inode handles, allowing
  read of host files (`/etc/shadow`, host ssh keys) from inside a container
  using `cap_dac_read_search`.
- **CVSS:** 9.0 historically
- **Cached source:** references/yunolay-caps-abuse.html

> cap_dac_read_search does not give you a UID change. Instead it bypasses
> discretionary access control checks for reading files and traversing
> directories. You stay UID 1000, but you can read /etc/shadow, root's SSH
> private key, or any other file. This capability is the engine behind the
> famous CVE-2014-0038 / shocker container escape.

**Mitigation:**

- Drop `cap_dac_read_search` everywhere; never grant it to interpreters.
  Mapped in [SPEC-CAP-THROTTLE](specifications/SPEC-CAP-THROTTLE.md).
- Seccomp-block `open_by_handle_at` for agent workloads in the syscall filter
  defined in [SPEC-SANDBOX](specifications/SPEC-SANDBOX.md).

### 3.7 CVE-2023-0179 nftables container breakout

- **Affected:** container workloads retaining `CAP_NET_ADMIN` and the host
  network namespace.
- **Class:** nftables verdict maps OOB write; achieving root-equivalent kernel
  write primitive from within the container.
- **CVSS:** high
- **Cached source:** references/yunolay-caps-abuse.html (cap escalation section)

**Mitigation:**

- Drop `CAP_NET_ADMIN` from agent workloads (container-default cgroup) per
  SPEC-CAP-THROTTLE.

### 3.8 CVE-2023-0386 overlayfs + FUSE LPE

- **Affected:** kernels with overlayfs enabled where an unprivileged user
  can mount a FUSE filesystem; SUID binaries injected via the overlay layer
  run with the capability set of the privileged overlay context.
- **Class:** CAP_SYS_ADMIN merge across overlay boundary.
- **CVSS:** 7.8

**Mitigation:**

- Block the `mount`/`mount_setattr` syscall in the agent seccomp filter.
- The sandbox-launched agents run without CAP_SYS_ADMIN in the bounding set.

### 3.9 CVE-2022-27666 ESP6 kernel heap OOB write

- **Affected:** IPv6 ESP packet parser; reachable by an attacker with the
  `socket()` primitive and source code of a SUID-binary corruption target.
- **CVSS:** 7.8

**Mitigation:**

- Drop `CAP_NET_RAW` everywhere so unprivileged workloads cannot open raw
  sockets. Defined in SPEC-CAP-THROTTLE.

---

## 4. Sandbox isolation tiers

The sandbox-default answer is decided per workload, not per program. The
catalogue of runtimes ground in the cached research (references/sandlock-arxiv.html,
references/systemshardening-cap-hardening.html, RESEARCH.md section 5) is:

| Tier | Cold-start cost | Kernel exposure | Best for |
|------|-----------------|-----------------|----------|
| Rootless process sandbox (Landlock + seccomp + user+mount+net namespaces + cgroups) | ~5 ms | shared | AI agent host code, the git-guard itself |
| gVisor (runsc) | ~200 ms cold | Sentry (no syscall touches host kernel) | untrusted LLM-generated shell commands |
| Firecracker / Kata microVM (KVM) | ~125 ms | separate guest kernel | when host compromise cost is catastrophic |
| Full root container or unconfined | 0 | host kernel | never acceptable for agent workloads |

Map of strengths (which vectors each tier neutralises):

| Vector | Rootless | gVisor | Firecracker |
|--------|----------|--------|-------------|
| Kernel CVE-2026-31431 Copy Fail from inside | blocked via seccomp `AF_ALG` | blocked (no host syscall) | block (separate kernel) |
| Shocker CAP_DAC_READ_SEARCH | blocked (cap drop + `open_by_handle_at` block) | blocked (Sentry gate) | blocked (separate kernel) |
| nftables CAP_NET_ADMIN breakout | blocked (cap drop) | blocked (no nft) | block (separate kernel) |
| overlayfs LPE | blocked (mount block) | blocked (Sentry) | blocked (separate kernel) |
| Page-cache corruption via splice | block AF_ALG to start | blocked (no host syscall) | blocked (separate kernel) |
| Ptrace re-entry | blocked (seccomp block + `YAMA` 2) | blocked (Sentry) | blocked (separate kernel) |
| SUID re-escalation inside sandbox | blocked (PR_SET_NO_NEW_PRIVS) | needs `--no-new-privs` | kernel guest avoids SUID binary exposure |

The user picks per workload, so `scripts/sandbox-launcher` (the tarball wrapper
planned in [SPEC-SANDBOX](specifications/SPEC-SANDBOX.md)) accepts a `--profile
<hostname-match>` selector choosing one of the three profiles shipped at
`config/sandbox/`.

---

## 5. Defense-in-depth map (each program layer vs each CVE)

| Layer | PwnKit 4034 | BaronSamedit 3156 | chroot 32463 | LoL 4911 | CopyFail 31431 | Shocker 0038 | nftables 0179 | overlayfs 0386 | ESP6 27666 |
|-------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Binary lock (`0700` + `chattr +i` + relocate `.real`) | Y | Y | Y | N | N | N | N | N | N |
| Capability throttle (drop `CAP_*` set) | N | N | N | Y | partial | Y | Y | Y | Y |
| Sandbox seccomp (block `AF_ALG`, `open_by_handle_at`, `mount`, `personality`) | N | N | N | N | Y | Y | N | Y | N |
| Sandbox Landlock (deny host file paths) | N | N | N | N | N | Y | N | N | N |
| Sandbox network namespace (drop `CAP_NET_RAW`, drop `CAP_NET_ADMIN`) | N | N | N | N | N | N | Y | N | Y |
| Kernel patch (latest stable) | N | N | N | N | Y | N | N | N | Y |
| auditd detection (`ioctl FS_IOC_SETFLAGS`, setcap, splice on SUID) | N | N | N | N | Y | N | N | Y | N |
| AIDE / FIM (inodes, modes, hashes) | Y (detects replace) | Y | Y | Y | N | N | N | N | N |
| Drift detector (`scripts/suid-drift-check`) | Y (detects chmod 4755) | Y | Y | N | N | N | N | N | N |

Legend: Y = neutralises the vector, N = does not, partial = partially mitigates.

The table is the contract that the four program layers are designed to
collectively cover. Any unsupported cell is a documented known residual risk
captured in [SPEC-AUDIT](specifications/SPEC-AUDIT.md) section "known residual
risks".

---

## 6. References (canonical, mirrored in docs/references/)

1. GTFOBins SUID list. https://gtfobins.github.io/#+suid -> references/gtfobins-suid.html
2. konstruktoid hardening SUID list. https://raw.githubusercontent.com/konstruktoid/hardening/master/misc/suid.list -> references/konstruktoid-suid-list.txt and .pdf
3. capabilities(7) man page. https://man7.org/linux/man-pages/man7/capabilities.7.html -> references/capabilities.7.html
4. CVE-2021-4034 PwnKit NVD. https://nvd.nist.gov/vuln/detail/CVE-2021-4034 -> references/NVD-CVE-2021-4034.html
5. CVE-2021-3156 Baron Samedit NVD. https://nvd.nist.gov/vuln/detail/CVE-2021-3156 -> references/sudo-Baron-Samedit-CVE-2021-3156.html
6. CVE-2025-32463 sudo chroot advisory. https://www.sudo.ws/security/advisories/chroot_bug/ -> references/sudo-chroot-CVE-2025-32463.html and .pdf
7. CVE-2026-31431 Copy Fail (per RESEARCH.md reference 2). Cached indirectly in RESEARCH.md.
8. Sandlock rootless sandbox design (arXiv preprint). https://arxiv.org/html/2605.26298v1 -> references/sandlock-arxiv.html
9. systemshardening.com Capability Hardening. https://www.systemshardening.com/articles/linux/linux-capability-hardening/ -> references/systemshardening-cap-hardening.html
10. systemshardening.com chattr immutability. -> references/systemshardening-chattr.html
11. systemshardening.com dm-verity. -> references/systemshardening-dm-verity.html
12. Yunolay SUID/SGID abuse taxonomy. -> references/yunolay-suid-sgid-abuse.html
13. Yunolay capabilities abuse. -> references/yunolay-caps-abuse.html
14. Elastic Security Labs cap escalation. -> references/elastic-cap-escalation.html
15. CIS DIL benchmark 6.1.13/6.1.14 control. -> references/cis-dil-benchmark-suid-rb.html