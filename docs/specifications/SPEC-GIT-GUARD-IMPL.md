# Specification: AMI Git Guard Implementation Details

**Date:** 2026-05-18
**Status:** DRAFT
**Type:** Specification
**Parent:** [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md)

---

## 8. Rust Implementation Details

### 8.1 Crate Structure

```
workspace-guard/
├── Cargo.toml
├── Cargo.lock
├── .cargo/
│   └── config.toml          # target = x86_64-unknown-linux-musl
└── src/
    └── main.rs              # multi-module binary (~500 LOC)
```

A single package is preferred over multiple crates for a single guard binary.

### 8.2 Dependencies

```toml
[dependencies]
libc = "0.2"    # irreducible FFI: getauxval, fork, _exit, lchown (no nix wrappers)
nix = "0.29"    # safe wrappers for everything else (user/process/signal/resource/fs)
```

`nix` is an always-on dependency (not feature-gated) with `default-features = false`
and features `["user", "process", "signal", "resource", "fs"]`. Argument parsing
is manual. No `clap`, no `thiserror`, no `anyhow`. The standard library is
sufficient. `libc` is kept ONLY for the four irreducible FFI calls that have no
safe `nix` substitute (see §8.3).

### 8.3 Unsafe Blocks

Only **four** FFI sites in production code require the `unsafe` gate. Every
other syscall goes through a safe `nix` wrapper or `std`. Each unsafe block
carries a `// SAFETY:` comment explaining why it cannot be made safe.

| # | File | Call | Why irreducible |
|---|------|------|-----------------|
| 1 | `src/main.rs` | `libc::getauxval(AT_SECURE)` | No `nix` wrapper; only correct SUID-context detection primitive |
| 2 | `src/exec.rs` | `libc::fork` | Async-signal-safety hazard; no safe substitute preserves fork-without-atfork-handler semantics |
| 3 | `src/exec.rs` | `libc::_exit` | Only async-signal-safe exit path; `std::process::exit` and Drop runtimes are forbidden post-fork; no `nix` wrapper |
| 4 | `src/gitdir.rs` | `libc::lchown` | `nix::unistd::chown` follows symlinks (would chown the wrong file); no `nix::lchown` wrapper as of 0.29 |

The test module `src/exec_tests.rs` keeps raw `libc::fork` + `libc::_exit` so
the suite exercises the exact FFI the production path uses (decision: tests
mirror prod FFI, not nix wrappers).

The call-site snippets (without the gating blocks):

1. **`getauxval(AT_SECURE)`** in `src/main.rs`:
   ```rust
   // SAFETY: getauxval(3) reads the process auxiliary vector, a
   // kernel-populated in-memory array available at process start and never
   // mutated thereafter. AT_SECURE is a libc integer constant naming a
   // well-known key. This is the only correct secure-execution detection
   // primitive; the dynamic linker uses the same call internally.
   unsafe { libc::getauxval(libc::AT_SECURE) as usize }
   ```

2. **`fork()`** in `src/exec.rs`:
   ```rust
   // SAFETY: libc::fork is an irreducible async-signal-safe primitive with
   // no safe nix substitute. No allocations or lock acquisitions occur
   // between fork and exec; the only calls in the child are
   // raise_child_dac_override() (caps syscalls), nix::execve (execve(2)),
   // and libc::_exit, all async-signal-safe.
   let pid = unsafe { libc::fork() };
   ```

3. **`_exit()`** in `src/exec.rs`:
   ```rust
   // SAFETY: libc::_exit is the only async-signal-safe exit path;
   // std::process::exit and Drop runtimes are forbidden in the post-fork
   // child. nix has no _exit wrapper.
   unsafe { libc::_exit(3); }
   ```

4. **`lchown()`** in `src/gitdir.rs`:
   ```rust
   // SAFETY: libc::lchown(3) takes a NUL-terminated path string and two
   // numeric ids. `c` is a valid CString from the OsStr bytes of `path`.
   // lchown does not follow symlinks, so there is no dereference hazard.
   let rc = unsafe { libc::lchown(c.as_ptr(), 0, 0) };
   ```

### 8.4 Cargo.toml

```toml
[package]
name = "workspace-guard"
version = "0.1.0"
edition = "2021"

[profile.release]
opt-level = "z"        # optimise for size
lto = true             # link-time optimisation
codegen-units = 1      # single codegen unit for better optimisation
panic = "abort"        # no unwinding in SUID binary
strip = true           # strip symbols

[dependencies]
libc = "0.2"
nix = { version = "0.29", default-features = false, features = ["user", "process", "signal", "resource", "fs"] }
```

### 8.5 Build Target

Primary target: `x86_64-unknown-linux-musl` (statically linked).

Static linking eliminates shared library injection vectors: there are no `.so` files to preload or replace. The binary is fully self-contained.

If musl toolchain is unavailable, fall back to `x86_64-unknown-linux-gnu` (dynamically linked). In that case, only `libc`, `nix`'s transitive deps (`bitflags`, `cfg-if`), and the musl-compatible minimal set of libraries are linked.

### 8.6 Resource Limits

Before `execve()`, the guard sets:
- `RLIMIT_NOFILE` to 256: limits open file descriptors
- `RLIMIT_CORE` to 0: disables core dumps (prevents memory disclosure from SUID context)

Set via `nix::sys::resource::setrlimit()` (safe wrapper over `setrlimit(2)`).

### 8.7 Error Handling Strategy

The guard uses a simple `Result` type with explicit exit codes:

```rust
enum GuardError {
    NotSuid,              // exit 3
    GitOriginalMissing,   // exit 3
    GitOriginalBadPerms,  // exit 3
    NullByteInArg,        // exit 2
    Blocked { reason: String, hint: String },  // exit 1
    ContractFailed,       // exit 4
}
```

No panics. `panic = "abort"` in release mode. Any unexpected condition is treated as a block (fail-closed) rather than a crash.

---

## 9. Security Threat Model

### 9.1 Threats Mitigated

| Threat | Mitigation |
|--------|-----------|
| User runs `git reset --hard` | Subcommand deny-list (§4, check 1) |
| User runs `git checkout main` | Subcommand deny-list (§4, check 1) |
| User runs `git push --force` | Flag deny-list (§4, check 3c) |
| User bypasses pre-commit hooks via `SKIP=1` | Env var sanitisation (§5.1) |
| User sets `-c core.hooksPath=/tmp/evil` | Config key block list (§4, check 3) |
| User puts malicious binary in PATH | PATH reset (§5.2) |
| User compiles own git wrapper and runs it | AT_SECURE check (§2.2) |
| User reads guard binary to find git.original path | git.original is 0700 root-only (§2.1) |
| User tries to exec git.original directly | Permission denied (0700 root:root) |
| User uses `LD_PRELOAD` to inject code | Env var unset (§5.1) + static linking |
| User pushes from CI script to bypass hooks | Background push detection (§4, check 4d) |
| User amends a pushed commit | Ancestor check via merge-base (§4, check 4e) |
| User reverts un-pushed work | Ancestor check (§4, check 4f) |
| User creates merge commit on main | Protected branch rule (§4, check 5) |
| User deletes .pre-commit-config.yaml then pushes | P3 contract check (§6.2) |
| User installs alternate git via apt | dpkg-divert prevents overwrite (§5.2 in SPEC-GIT-GUARD-INSTALL) |
| User accesses git via snap/flatpak | Snap/flatpak git binaries restricted to 000 (§12.1 in SPEC-GIT-GUARD-INSTALL) |
| User downloads git binary from upstream | PATH controlled; git at `/usr/bin` is the only canonical path. Pre-commit hooks detect unapproved git usage |
| User modifies .bashrc to add PATH bypass | PATH is reset by the guard before execve (§5.2). The guard does not trust the invoking environment |
| User replaces guard binary with own version | SUID bit set by root only; immutable attribute `chattr +i` prevents modification (§12.3 in SPEC-GIT-GUARD-INSTALL) |
| User modifies dpkg to remove diversion | Apt post-invoke hook detects and warns (§5.6 in SPEC-GIT-GUARD-INSTALL). Divert is root-only operation |
| User compiles git from source | Source compile goes to `/usr/local/bin/git` which is restricted to 000 (§12.1 in SPEC-GIT-GUARD-INSTALL) |

### 9.2 Threats NOT Mitigated (root-level attacks)

| Threat | Reason |
|--------|--------|
| User has root access | Root can remove SUID bit, reinstall git, remove diversion, etc. The guard protects against workspace users, not root. Root access IS a security boundary violation: all root actions are audited. |
| Kernel exploit | Out of scope. If the kernel is compromised, no user-space mechanism helps. |
| Hardware-level attack | Out of scope. |

### 9.3 Defense in Depth Layers

The guard implements multiple independent layers of defense:

1. **SUID Root**: Only the guard can invoke real git; real git is 0700 root:root
2. **Argument Validation**: All args parsed and validated before execve
3. **Environment Sanitisation**: Allow-list approach; no dangerous env vars passed through
4. **PATH Reset**: Known-safe PATH prevents PATH injection
5. **dpkg-divert**: Prevents apt from overwriting the guard
6. **Immutable Attribute**: `chattr +i` prevents filesystem-level tampering
7. **Apt Hook**: Detects git package changes and warns
8. **Pre-commit Hooks**: Second layer of defense at the repo level
9. **Audit Logging**: All blocks logged with timestamps, UIDs, and commands
10. **Static Linking**: No shared library injection vectors
11. **Resource Limits**: RLIMIT_CORE=0, RLIMIT_NOFILE=256 limit blast radius

### 9.4 Blast Radius

If the guard binary has a bug that allows arbitrary code execution with root privileges:
- The binary is ~500 LOC: small audit surface
- Static linking removes shared library attack vectors
- No network I/O, no file parsing, no deserialisation
- No heap allocations from untrusted input (argv is bounded)
- `RLIMIT_CORE=0` prevents core dump analysis
- `RLIMIT_NOFILE=256` limits file descriptor exhaustion
- The only privileged operation is `execve()` of a known-good binary

The worst-case RCE allows the attacker to run arbitrary commands as root: which they could already do if they compromised the real git binary. The guard doesn't increase the blast radius beyond what the existing SUID model already allows.

---

## 10. File Layout

| Path | Purpose |
|------|---------|
| `/usr/bin/git` | workspace-guard SUID binary (installed) |
| `/usr/bin/git.original` | real git binary (relocated, 0700 root:root) |
| `projects/WORKSPACE-GUARD/` | Rust source code repository |
| `projects/WORKSPACE-GUARD/src/main.rs` | Multi-module Rust implementation |
| `projects/WORKSPACE-GUARD/Cargo.toml` | Package manifest |
| `projects/WORKSPACE-GUARD/Cargo.lock` | Locked dependencies |

---

## 11. Requirements Traceability

| Requirement | Spec Section | Status |
|-------------|-------------|--------|
| REQ-GGUARD-001 | §2.1 | Covered |
| REQ-GGUARD-002 | §2.1 | Covered |
| REQ-GGUARD-003 | §2.2 | Covered |
| REQ-GGUARD-004 | §2.2 | Covered |
| REQ-GGUARD-005 | §2.3, §8.3 | Covered |
| REQ-GGUARD-006 | §2.3 | Covered |
| REQ-GGUARD-007 | §8.3 | Covered |
| REQ-GGUARD-010 | §3.3 | Covered |
| REQ-GGUARD-011 | §3.1 | Covered |
| REQ-GGUARD-012 | §3.2 | Covered |
| REQ-GGUARD-013 | §3.2 | Covered |
| REQ-GGUARD-014 | §3.1 | Covered |
| REQ-GGUARD-020 | §4, check 1 | Covered |
| REQ-GGUARD-021 | §4.1 | Covered |
| REQ-GGUARD-030 | §4, check 2 | Covered |
| REQ-GGUARD-031 | §4, check 3 | Covered |
| REQ-GGUARD-040 | §4, check 3 | Covered |
| REQ-GGUARD-041 | §3.1 Phase 2 | Covered |
| REQ-GGUARD-042 | §4, check 3 | Covered |
| REQ-GGUARD-050 | §4, check 4a | Covered |
| REQ-GGUARD-051 | §4, check 4b | Covered |
| REQ-GGUARD-052 | §4, check 4c | Covered |
| REQ-GGUARD-053 | §4, check 4d | Covered |
| REQ-GGUARD-054 | §4, check 4e | Covered |
| REQ-GGUARD-055 | §4, check 4f | Covered |
| REQ-GGUARD-060 | §4, check 5 | Covered |
| REQ-GGUARD-061 | §4, check 5a | Covered |
| REQ-GGUARD-062 | §4, check 5b | Covered |
| REQ-GGUARD-063 | §4, check 5 | Covered |
| REQ-GGUARD-070 | §5.1 | Covered |
| REQ-GGUARD-071 | §5.1 | Covered |
| REQ-GGUARD-072 | §5.2 | Covered |
| REQ-GGUARD-073 | §5.3 | Covered |
| REQ-GGUARD-074 | §2.2, §5.4 | Covered |
| REQ-GGUARD-080 | §6.2 | Covered |
| REQ-GGUARD-081 | §6.1 | Covered |
| REQ-GGUARD-082 | §6.1 | Covered |
| REQ-GGUARD-083 | §6.2 | Covered |
| REQ-GGUARD-084 | §6.2 | Covered |
| REQ-GGUARD-085 | §6.2 | Covered |
| REQ-GGUARD-086 | §6.4 | Covered |
| REQ-GGUARD-090 | §7.1 | Covered |
| REQ-GGUARD-091 | §7.1 | Covered |
| REQ-GGUARD-092 | §7.4 | Covered |
| REQ-GGUARD-093 | §7.3 | Covered |
| REQ-GGUARD-100 | §8.7 | Covered |
| REQ-GGUARD-101 | §8.7 | Covered |
| REQ-GGUARD-102 | §8.7 | Covered |
| REQ-GGUARD-103 | §8.7 | Covered |
| REQ-GGUARD-104 | §8.7 | Covered |
| REQ-GGUARD-110 | §4.1 | Covered |
| REQ-GGUARD-111 | §4.1 | Covered |
| REQ-GGUARD-112 | §6.4 | Covered |
| REQ-GGUARD-113 | §4.1 | Covered |
| REQ-GGUARD-120 | §8.4 | Covered |
| REQ-GGUARD-121 | §8.3 | Covered |
| REQ-GGUARD-122 | §8.2 | Covered |
| REQ-GGUARD-123 | §3.1 | Covered |
| REQ-GGUARD-124 | §8.6 | Covered |
| REQ-GGUARD-125 | §7.4 | Covered |
| REQ-GGUARD-130 | §4.2 | Covered |
| REQ-GGUARD-131 | §4.2 | Covered |
| REQ-GGUARD-132 | §4.2 | Covered |
| REQ-GGUARD-140 | SPEC-GIT-GUARD-INSTALL §1, §9 | Covered |
| REQ-GGUARD-141 | SPEC-GIT-GUARD-INSTALL §2 | Covered |
| REQ-GGUARD-142 | SPEC-GIT-GUARD-INSTALL §4.1-4.2 | Covered |
| REQ-GGUARD-143 | SPEC-GIT-GUARD-INSTALL §4.3, §5.1 | Covered |
| REQ-GGUARD-144 | SPEC-GIT-GUARD-INSTALL §5.2 | Covered |
| REQ-GGUARD-145 | SPEC-GIT-GUARD-INSTALL §5.3 | Covered |
| REQ-GGUARD-146 | SPEC-GIT-GUARD-INSTALL §5.7 | Covered |
| REQ-GGUARD-147 | SPEC-GIT-GUARD-INSTALL §6 | Covered |
| REQ-GGUARD-148 | SPEC-GIT-GUARD-INSTALL §5.1 | Covered |
| REQ-GGUARD-149 | SPEC-GIT-GUARD-INSTALL §7 | Covered |
| REQ-GGUARD-150 | SPEC-GIT-GUARD-INSTALL §5.2 | Covered |
| REQ-GGUARD-151 | SPEC-GIT-GUARD-INSTALL §5.5 | Covered |
| REQ-GGUARD-152 | SPEC-GIT-GUARD-INSTALL §12.3 | Covered |
| REQ-GGUARD-153 | SPEC-GIT-GUARD-INSTALL §5.6 | Covered |
| REQ-GGUARD-154 | SPEC-GIT-GUARD-INSTALL §5.0, §12 | Covered |
| REQ-GGUARD-160 | SPEC-GIT-GUARD-INSTALL §4.1 | Covered |
| REQ-GGUARD-161 | SPEC-GIT-GUARD-INSTALL §4.2 | Covered |
| REQ-GGUARD-162 | SPEC-GIT-GUARD-INSTALL §4.2 | Covered |
