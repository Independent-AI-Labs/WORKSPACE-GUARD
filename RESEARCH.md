# Research: SUID Binary Hardening & Agentic Environment Security

**Date:** 2026-05-19  
**Status:** DRAFT  
**Type:** Research / Threat Model

---

## 1. Introduction

WORKSPACE-GUARD is a SUID-root compiled binary that intercepts, validates, and sanitizes execution of a target program (PoC: `git`). This document surveys the attack surface of SUID binaries on Linux, evaluates historical and recent CVEs, and maps mitigations to WORKSPACE-GUARD's design.

---

## 2. SUID Attack Taxonomy

### 2.1 Environment Variable Injection

The kernel sets `AT_SECURE` in the auxiliary vector when executing a SUID binary. The dynamic linker (ld.so) uses this to strip dangerous environment variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `GCONV_PATH`, etc.). **Attackers bypass this via:**

- **CVE-2021-4034 (PwnKit)**: `pkexec` with `argc == 0` causes `argv[1]` to read from `envp[0]`, allowing out-of-bounds write to reintroduce `GCONV_PATH`. Exploitable since May 2009; patched January 2022.
- **Bypass via custom ld.so**: If an attacker can control `LD_LIBRARY_PATH` before `execve`, or use a static binary, `AT_SECURE` may not be set.
- **Unsanitized SUID binaries**: Some SUID programs re-read environment variables after startup. If the program doesn't use glibc's secure-execution helpers, `AT_SECURE` may be bypassed entirely.

**WORKSPACE-GUARD Mitigation**: The guard scrubs the environment itself before `execve`: only whitelisted variables survive. `PATH` is hardcoded. `GCONV_PATH`, `LD_*`, and all non-whitelisted variables are stripped regardless of `AT_SECURE`.

### 2.2 PATH / Binary Injection

A SUID binary that calls `execvp("git", ...)` or `system("git ...")` without an absolute path will follow the user-controlled `PATH`.

**WORKSPACE-GUARD Mitigation**: Guard calls `/usr/bin/git.original` via absolute path. The guard itself is SUID but only calls `git.original` through `execve` with a hardcoded path. No subprocess resolution ambiguity.

### 2.3 Shared Library Hijacking

- **`LD_LIBRARY_PATH`**: Stripped by `AT_SECURE`: but only for glibc. Static binaries and musl-linked binaries do not use `ld.so` and may ignore `AT_SECURE`.
- **`/etc/ld.so.conf` / `ldconfig`**: If an attacker can write to a directory in ldconfig's cache, they can inject `.so` files that SUID binaries load. This requires root or write access to system config directories.
- **Missing `RUNPATH` libraries**: A SUID binary that `dlopen()`s a library from a user-writable path can be exploited.

**WORKSPACE-GUARD Mitigation**: Statically linked via musl (preferred) or linked with gcc + `RUNPATH` controlled at build time. No `dlopen()`. No dynamic library loading at runtime. Only `libc` dependency: and for musl builds, even that is linked statically.

### 2.4 `GCONV_PATH` Injection

The glibc `iconv` framework loads gconv modules from `GCONV_PATH`. Normally stripped by `AT_SECURE`, but:

- **CVE-2021-4034** re-introduced it by corrupting `pkexec`'s environment.
- Custom charset conversion triggers `.so` loading from attacker-controlled directory.

**WORKSPACE-GUARD Mitigation**: 
- Guard uses musl (preferred), which lacks `GCONV_PATH` entirely.
- Guard's own env stripping removes any `GCONV_PATH` before `execve`.
- Even if gconv were triggered inside the real git binary, `GCONV_PATH` is not in the whitelist.

### 2.5 `/proc/self/mem` & `ptrace` Attacks

A SUID binary running as root is still debuggable by the user who launched it if `ptrace` scope allows. The attacker can:
- `ptrace` the SUID binary before it drops privileges
- Write to `/proc/<pid>/mem` to modify its memory

**WORKSPACE-GUARD Mitigation**: 
- Guard drops privileges via `setuid(getuid())` before `execve`: after that point, the real binary runs as the user and is not useful to attack.
- Guard sets `RLIMIT_CORE = 0` to prevent core dumps (memory leak).
- Guard's execution window is narrow: AT_SECURE check → parse → block/execve. No interactive phase.

### 2.6 `exec` Argument Injection

- **Null byte injection**: `git -c 'key\0value'` can confuse argument parsers.
- **`--no-verify` bypass**: Pre-commit hooks can be skipped.
- **Dangerous `-c` config keys**: `core.hookspath`, `core.sshcommand`, `credential.helper`, `http.proxy`, etc.

**WORKSPACE-GUARD Mitigation**: 
- Null bytes in any argument cause hard rejection.
- `--no-verify` is blocked unconditionally.
- 12 dangerous config keys are blocked. Both `-c key=val` and `--c=key=val` forms are checked.

### 2.7 SUID Binary Replacement (Race Window)

Between `stat()` and `execve()`, a TOCTOU attacker could replace the guard binary. Mitigated by:
- `chattr +i` on guard and real binary
- `dpkg-divert` prevents apt from overwriting the guard
- `/usr/bin/git.original` verified before each `execve` (owner + mode check)

---

## 3. CVE-2026-31431: "Copy Fail" (April 2026)

### 3.1 Summary

A critical Linux kernel vulnerability (CVSS 7.8) in the `algif_aead` module. An unprivileged local user corrupts the **page cache** of SUID binaries via `AF_ALG` + `splice()`, achieving root without modifying the on-disk file.

**Discovered by:** Xint Code (via AI analysis of crypto subsystem)  
**Affected:** Ubuntu 24.04, Amazon Linux 2023, RHEL 10.1, SUSE 16, all pre-6.19.12 / 6.18.22 / 7.0 kernels  
**Fix commit:** `a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5`

### 3.2 Mechanism

1. Open read-only FD to target SUID binary (`/usr/bin/su`)
2. Create `AF_ALG` socket bound to `authencesn(hmac(sha256),cbc(aes))`
3. `splice()` pages from the target binary into the crypto pipeline
4. `sendmsg()` with crafted AAD: `authencesn` scratch write deposits **4 bytes** at controlled offset in page cache
5. Repeat to stage shellcode at successive offsets
6. Execute the binary: kernel uses the corrupted in-memory copy, grants root

The file on disk is **never modified**. Traditional integrity checks (`sha256sum`, `tripwire`, `AIDE`) detect nothing.

### 3.3 Mitigations

- **Kernel patch**: Forces out-of-place AEAD operation (disables in-place optimization)
- **seccomp**: Block `AF_ALG` socket creation for untrusted workloads
- **Module blacklist**: `blacklist algif_aead` in `/etc/modprobe.d/`
- **Container fix**: Patch the *host* kernel; rebuilding container images does not help

### 3.4 Impact on WORKSPACE-GUARD

- The guard binary itself is a SUID target: Copy Fail can corrupt `/usr/bin/git` in memory.
- However, guard's non-SUID exit (`AT_SECURE` check) provides partial defense: the corrupted guard runs → SUID not set → `NotSuid` → exit.
- Real concern: attacker corrupts `/usr/bin/git.original`? No: mode 0700 is not world-readable, so a read-only FD cannot be opened.
- **Net effect**: WORKSPACE-GUARD is partially resilient to Copy Fail because:
  - `git.original` is unreadable by non-root (no FD to pass to `splice()`)
  - The guard itself, if corrupted, simply refuses to run (no SUID, no bypass)
  - Deeper concern: attacker corrupts a **different** SUID binary (`/usr/bin/su`, `/usr/bin/sudo`) to get root, then replaces the guard and git.original from root

### 3.5 Hardening Recommendations

1. Patch kernel to > 6.19.12 / 6.18.22
2. Block `AF_ALG` seccomp in agent sandboxes
3. Monitor for `AF_ALG SEQPACKET` socket creation (Falco rule available)
4. Consider `CONFIG_CRYPTO_USER_API_AEAD=n` on hosts without crypto-offload needs

---

## 4. ret2dso: Runtime Ret2dlresolve Under Full RELRO (January 2026)

### 4.1 Summary

Published at lowlevel.re (January 2026). Demonstrates that **Full RELRO does not protect against dynamic linker metadata corruption**. By writing controlled data into a loaded DSO's `link_map` structure, an attacker can redirect `_dl_fixup()` resolution to arbitrary code.

**Key insight:** Full RELRO makes GOT read-only and disables deferred (on-demand) symbol binding. But at runtime, the loader's internal `link_map` structs remain writable, and the loader implicitly trusts its own metadata.

### 4.2 Attack Requirements

- A weak relative write primitive (e.g., 1 byte at a known offset from a mapped region)
- No ASLR leak needed: relies on relative offsets between DSOs

### 4.3 Attack Flow

1. Write to `ld.so`'s writable memory region (entropy + `LDBASE_WRITABLE_OFFSET`)
2. Corrupt `l_info[DT_SYMTAB]` in libc's `link_map` to point at attacker-controlled data
3. Overwrite a concrete `Elf64_Sym` entry with forged `st_value` (e.g., one_gadget)
4. Trigger symbol resolution via a legitimate function call path
5. `_dl_fixup()` computes `sym->st_value + l_addr` and transfers control to attacker

### 4.4 Impact on WORKSPACE-GUARD

- Guard is a Rust binary with no dynamic symbol resolution after startup. No `dlopen()`, no deferred (on-demand) symbol binding.
- musl-static builds eliminate `ld.so` entirely: **immune to ret2dso**.
- gcc-dynamic builds still use `ld.so`. However:
  - Guard's code path is linear: AT_SECURE → parse → execve. No loops, no user interaction, no function pointer tables.
  - Guard uses `panic = "abort"`: unwinding is disabled, reducing exploitable surface.
  - The window between startup and `execve` is too small for a write primitive.

---

## 5. Agentic Environment Sandbox Escapes

### 5.1 Shared-Kernel Container Weaknesses

AI agents execute LLM-generated code in sandboxed environments. The consensus (February 2026, per Zylos Research) is that **standard Docker/runc isolation is insufficient for untrusted code execution**.

**Known escape vectors:**
- Kernel vulns shared with host (CVE-2026-31431 works from inside containers)
- `/proc/sysrq-trigger`, `/proc/kcore`, `/sys/kernel/security` access
- Mount propagation escape
- `userfaultfd` kernel race conditions
- `cgroup` / `release_agent` escape
- `cap_sys_admin` abuse for namespace re-entry

### 5.2 Isolation Technologies

| Technology | Approach | Boot Time | Host Kernel Exposure | Overhead |
|-----------|----------|-----------|---------------------|----------|
| Docker (runc) | Shared kernel cgroups | ~10ms | Full | ~10MB |
| gVisor (runsc) | Userspace kernel (Sentry) intercepts syscalls | ~100ms | None (Sentry) | ~20MB |
| Firecracker/Kata | KVM hardware VM | ~125ms | None | ~5MB |
| LXC | OS-level cgroups + namespaces | ~50ms | Full (shared kernel) | ~5MB |

**Consensus:** Default to Firecracker/Kata for untrusted code; gVisor for compute-heavy workloads with limited I/O.

### 5.3 Gemini CLI Sandbox (March 2026)

Gemini CLI shipped LXC + gVisor sandbox support in March 2026. The sandbox:
- Mounts the workspace via bind mount
- Forwards selected environment variables
- Blocks network access by default
- Uses `runsc` (gVisor) for syscall interception

### 5.4 gVisor Security Architecture (April 2026)

gVisor's Sentry process reimplements the Linux kernel API in userspace (Go). Benefits:
- No direct host kernel syscalls from sandboxed processes
- Checkpoint/restore support for agentic workloads
- Docker-in-gVisor allows safe code execution (Hermes Agent architecture)

**Limitations:**
- I/O overhead 10-30% on syscall-heavy workloads
- Not all syscalls supported (some require platform-specific patches)
- Does not protect against vulnerabilities in gVisor's own Sentry implementation (but this surface is much smaller than the full host kernel)

### 5.5 WORKSPACE-GUARD in Agentic Environments

WORKSPACE-GUARD's function in an agentic context:
- Prevents agents from rewriting git history or destroying work via `git reset --hard`, `git push --force`, etc.
- Blocks `--no-verify` to ensure hooks fire.
- Scrub environment of hook-bypass variables (`SKIP`, `PRE_COMMIT_ALLOW_NO_CONFIG`).
- Audits all blocked operations to `.workspace-guard.log`.
- Operates at the binary level, so it works regardless of whether the agent runs in Docker, gVisor, or directly on the host.

---

## 6. Defense-in-Depth Recommendations

| Layer | Measure | Status |
|-------|---------|--------|
| Kernel | Patch > 6.19.12 / 6.18.22 (Copy Fail) | Manual |
| Kernel | seccomp block AF_ALG + userfaultfd | Manual |
| Binary | `chattr +i` on guard and real binary | Done |
| Binary | `dpkg-divert` for apt protection | Done |
| Binary | musl-static (no ld.so → immune to ret2dso) | Preferred |
| Binary | `panic = "abort"`, `strip = true`, LTO, single CU | Done |
| Runtime | Environment scrubbing (whitelist only) | Done |
| Runtime | `RLIMIT_CORE = 0` (no memory dumps) | Done |
| Runtime | `RLIMIT_NOFILE = 256` (no fd exhaustion) | Done |
| Runtime | Hardcoded PATH | Done |
| Runtime | `git.original` mode verification before each execve | Done |
| Audit | Block logging to `~/.workspace-guard.log` | Done |
| Audit | `/var/log/workspace-guard/` system-wide directory | Deploy |
| Sandbox | gVisor/Firecracker for agent workloads | Manual |
| Monitoring | Falco rule for AF_ALG SEQPACKET sockets | Manual |
| Monitoring | Auditd for `splice()` + SUID exec correlation | Manual |

---

## 7. References

1. CVE-2021-4034: PwnKit: pkexec local privilege escalation (Qualys, Jan 2022)
2. CVE-2026-31431: Copy Fail: Linux kernel page cache corruption via AF_ALG (Xint Code / Theori, Apr 2026)
3. ret2dso: Runtime Ret2dlresolve Under Full RELRO (lowlevel.re, Jan 2026)
4. GTFOBins: SUID binary exploitation techniques (gtfobins.github.io)
5. Zylos Research: AI Agent Sandboxing: MicroVMs, gVisor, WASM (Apr 2026)
6. gVisor: Multi-Agent gVisor Isolation (MAGI) blog post (Apr 2026)
7. Gemini CLI: LXC/gVisor sandbox support PR #20735 (Mar 2026)
8. Agent Sandbox SIG: `kubernetes-sigs/agent-sandbox` (Nov 2025)
9. Elastic Security: Copy Fail detection rule (Apr 2026)
10. glibc `dl-fixup.c`: Dynamic linker resolution internals
