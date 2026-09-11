# Specification: WORKSPACE Git Guard Implementation Details

**Date:** 2026-05-18
**Status:** DRAFT
**Type:** Specification
**Parent:** [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md)

---

## 8. Rust Implementation Details

### 8.1 Crate Structure

```text
WORKSPACE-GUARD/
├── Cargo.toml               # unrelated guard/tool packages only
├── git-guard/               # standalone privileged package; not a workspace member
│   ├── Cargo.toml
│   ├── Cargo.lock
│   ├── build.rs
│   ├── .cargo/config.toml   # trusted x86_64-unknown-linux-musl flags/source
│   └── src/
│       ├── main.rs
│       └── linux_ffi.rs
└── src/                     # shell/binary/SSH/YAML-editor package sources
```

The privileged Git guard is a standalone package with its own lockfile and no
path dependency on the broader repository package. This prevents dependencies
needed by shell guard, binary guard, SSH, YAML editing, or their tests from
entering Git guard resolution through workspace feature unification. Source files
shared today are moved or minimally duplicated; no shared local crate is added to
the privileged closure.

### 8.2 Dependencies

```toml
[dependencies]
libc = "0.2"    # four centralized irreducible Linux FFI operations
nix = { version = "0.29", default-features = false, features = ["user", "process", "signal", "resource", "fs"] }
caps = { version = "0.5", optional = true }

[build-dependencies]
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
regex = "1"
```

`nix` is an always-on dependency (not feature-gated) with `default-features = false`
and features `["user", "process", "signal", "resource", "fs"]`. Argument parsing
is manual. No `clap`, no `thiserror`, no `anyhow`. The standard library is
sufficient. `libc` is kept ONLY for the four irreducible FFI calls that have no
safe `nix` substitute (see §8.3). `caps` is present only in the capability-mode
normal closure. Root-only and capability-mode are mutually exclusive and exactly
one is selected.

Build dependencies are a distinct reviewed boundary: `serde`, `serde_yaml`, and
`regex` are used only by the policy compiler. Their complete normal/build/
proc-macro closure, including `serde_derive` and `unsafe-libyaml`, is recorded in
a versioned machine-readable closure manifest with exact versions, sources,
checksums, features, edge kinds, build scripts, and proc-macro status. No runtime
serialization, regex, YAML, hashing, or tooling crate enters the normal Git-guard
closure. `serde_json` is not used and is forbidden rather than justified.

The package uses resolver 2 and its own `Cargo.lock`. Builds select the exact
manifest, package, binary, target, and one deployment feature with
`--locked --frozen --offline`. A pre-build metadata gate compares normal, build,
and proc-macro edges against the approved closure for that mode and rejects Git/
path/alternate-registry sources, duplicate crate versions, checksum/source drift,
unexpected build scripts/proc macros, and feature drift. Sources come only from a
trusted read-only store whose Cargo checksums are verified. Third-party build
code runs as an unprivileged build identity without network or writes outside the
isolated build/target directory. Root verifies the closure manifest/artifact
binding and installs; it does not execute dependency build code.

### 8.3 Unsafe Blocks

Production code has one reviewed `src/linux_ffi.rs` boundary. Crate roots use
`#![deny(unsafe_code)]`; only that module receives the narrow lint allowance.
The module contains exactly four direct libc operations:

| # | Operation | Safe wrapper contract | Why irreducible |
|---|-----------|-----------------------|-----------------|
| 1 | `getauxval(AT_SECURE)` | Returns the kernel auxiliary-vector value as typed data | No safe approved wrapper exposes this process-start value |
| 2 | `fork` | Unsafe wrapper whose caller must satisfy the documented post-fork contract | Forking a potentially multithreaded Rust process requires caller invariants |
| 3 | `_exit` | Diverging child-only wrapper accepting the fixed internal status | Rust process exit and destructors are forbidden after fork |
| 4 | `ioctl(FS_IOC_GETFLAGS)` | Accepts a borrowed open regular-file descriptor and returns typed flags/error | No approved safe wrapper exposes this inode-flag operation |

Every unsafe block is minimal and immediately preceded by a `// SAFETY:`
contract proving pointer validity, alignment, lifetime, accepted command/value,
return/error interpretation, and post-fork restrictions as applicable. The
module exposes no general ioctl, arbitrary fork callback, arbitrary `_exit`
status, raw pointer, or raw-fd API.

All other operations use safe APIs. `nix::unistd::geteuid` supplies effective
UID. The safe `nix` prctl wrapper returns the exact `NoNewPrivileges` state and
error. `nix::unistd::fchownat` with no-follow semantics replaces `lchown`.
`nix::unistd::write` over a pre-created owned pipe supplies the fixed child-status
protocol. Exec, wait, signals, and resource limits remain safe wrappers.

Before fork, the parent constructs all argv/environment/C strings and creates a
close-on-exec status pipe. The child performs only the reviewed capability
syscalls, a safe allocation-free write of a fixed typed status on setup/exec
failure, `execve`, and `_exit`. It performs no allocation, formatting, environment
lookup, logging, locking, panic, unwinding, heap deallocation, or user-facing
diagnostic. Successful exec closes the pipe by close-on-exec; the parent reads
the typed status and owns all formatting/reporting. The post-fork call graph is
enumerated and mechanically checked rather than assumed safe because a function
ultimately invokes a syscall.

One dedicated test module may directly exercise raw `libc::fork` and
`libc::_exit` under equivalent adjacent safety contracts. No other production,
integration, unit, build-script, example, or benchmark code receives an unsafe
exception. Tests use safe UID and syscall wrappers otherwise.

The build gate parses/scans all Rust targets and rejects unsafe blocks/functions/
traits, inline assembly, direct `libc::*` calls, lint allowances, or approved-call
count/location drift outside the exact module/test allow-list. The policy YAML
exception lists only those exact files and is changed solely through the
sudo-gated YAML editor.

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
panic = "abort"        # no unwinding in privileged guard binary
overflow-checks = true # checked integer arithmetic in release
strip = true           # strip symbols

[profile.dev]
panic = "abort"
overflow-checks = true

[dependencies]
libc = "0.2"
nix = { version = "0.29", default-features = false, features = ["user", "process", "signal", "resource", "fs"] }
```

### 8.5 Build Target

Primary target: `x86_64-unknown-linux-musl` (statically linked).

Static linking eliminates shared library injection vectors: there are no `.so` files to preload or replace. The binary is fully self-contained.

The musl toolchain is a hard prerequisite, provisioned by the host bootstrap. If the musl target is not installed, the build aborts with a provisioning error directing the operator to install the toolchain; a dynamically-linked gnu build is never produced.

Committed trusted target configuration supplies the pinned linker and hardening
flags needed for static PIE, full RELRO, non-executable stack, and stack
protection. The build entry point starts from a controlled build environment and
rejects inherited `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, rustc wrappers, linker
overrides, target overrides, and other compiler/linker controls rather than
silently combining them with trusted flags. It builds with the pinned toolchain,
explicit target, release profile, selected guard feature, and locked dependency
graph.

An independent verifier inspects the resulting ELF rather than trusting Cargo
configuration. It requires static PIE, `GNU_RELRO`, non-executable `GNU_STACK`,
the pinned stack-protection evidence, no `PT_INTERP`, no dynamic dependencies,
and the expected stripped release artifact. It also verifies the pinned target/
architecture and records a cryptographic digest. Installation copies those exact
bytes, checks destination inode type/ownership/mode and digest, reruns the ELF
verifier against the destination, and only then applies file capabilities. Any
unsupported flag, missing verifier/tool, ambiguous output, property mismatch,
copy race, or digest mismatch aborts before capability labeling.

### 8.6 Resource Limits

Before `execve()`, the guard sets:
- `RLIMIT_NOFILE` to 256: limits open file descriptors
- `RLIMIT_CORE` to 0: disables core dumps from the capability-enabled process

Set via `nix::sys::resource::setrlimit()` (safe wrapper over `setrlimit(2)`).

### 8.7 Error Handling Strategy

The guard uses a simple `Result` type with explicit exit codes:

```rust
enum GuardError {
    GuardUnavailable { stage, cause, os_status }, // exit 3
    InvalidInvocation { kind, evidence }, // exit 2; caller-caused validation
    PolicyDenied { reason, hint },        // exit 1
    ContractRejected { child_code },      // exit 4
    ContractUnavailable { stage, cause, os_status }, // exit 4
    ContractRequiredOutsideWorkspace { destination }, // exit 4
}
```

Capability-set/query, deployment-class, `NoNewPrivileges`, resource-limit, and
root-only effective-UID failures map to `GuardUnavailable`. They exit 3 before
argument policy evaluation. Inspection errors remain distinct evidence and
cannot pass as an acceptable value. Exit 2 remains reserved for malformed
arguments.

Every typed contract variant maps to exit 4 and prevents requested Git from
starting. Normal runner rejection, unavailable scope/integrity/execution, and
outside-workspace protected or indeterminate destination remain distinct through
stderr, tty, and audit dispatch. Helper failure never becomes an empty successful
result. A propagated real-Git exit 4 is not a `GuardError` and emits no contract
diagnostic.

The exhaustive outcome dispatcher formats each guard-enforced failure once and
passes immutable bytes to one delivery function. That function returns typed
stderr, controlling-tty open/identity, and tty-write results; it never exits or
silently discards an I/O error. Safe terminal APIs compare terminal/session
identity rather than filesystem identity so `/dev/tty` and its aliased
`/dev/pts/N` are not double-written. Warnings and real-Git streams bypass this
dual-destination function.

Runtime warnings are a closed `WarningKind` enum with typed raw-byte fields.
Their formatter emits §5.6's single ASCII line through one checked stderr-only
writer and performs no audit or tty operation. The writer returns
`GuardUnavailable { stage: WarningStderr, ... }` on short/non-retryable writes;
before Git this prevents execution, while post-Git reconcile reporting states
that the operation may already stand. Environment values and reconcile paths
remain `OsStr` bytes rather than `String`/`Path::display()` output.

Stream ownership follows §5.7. Real Git inherits stdout/stderr directly and no
guard-generated text reaches stdout. Policy helpers pipe stdout only for typed
protocol parsing and encode stderr incrementally as contiguous
`HELPER-STDERR` chunks; reader/join failure is typed and never
`unwrap_or_default()`. Contract streams retain their separate concurrent
byte-streaming path. Trace enablement is one startup-snapshot boolean; trace uses
closed phase tokens, nanosecond decimal duration, and checked stderr writes.
Pre/post-Git diagnostic write failures map to the corresponding
`GuardUnavailable` stage, while contract stream failure remains exit 4.

Real-Git missing/bad identity also maps to `GuardUnavailable`. Its verifier uses
no-follow metadata, requires a regular `root:root` file with `st_mode & 07777`
equal to `0700`, and rejects the running guard's own device/inode pair.

Argument conversion uses raw Unix `OsStr` bytes. Non-UTF-8 is valid and remains
byte-identical except in fields with an explicit ASCII inspection contract.
Internal/test NUL, missing recognized global operands, indeterminate unknown
global-option arity, uninspectable safety-critical config keys, and `CString`
conversion failure map to `InvalidInvocation` and exit 2. Conversion never
inserts a replacement argument or drops an argument. Reliably classifiable Git
syntax errors are forwarded unchanged.

Parser state stores byte ranges/indexes into the original `Vec<OsString>` and
compares policy syntax with ASCII byte constants; it never calls `trim`,
`to_string_lossy`, `from_utf8_lossy`, or `from_utf8(...).unwrap_or("")` on
caller-controlled data. Paths remain `PathBuf`/`OsString`, helper protocols parse
exact byte grammars, and environment catalog matching uses name bytes. One
pre-fork conversion pass builds argv/environment `CString` vectors or returns a
typed error. Caller argv failure maps to exit 2; guard-owned construction failure
maps to exit 3. Accepted `argv[0]` and every remaining argument are forwarded
without substitution, omission, normalization, or reordering.

No panics. `panic = "abort"` in release mode. Unexpected internal conditions use
typed exit-3 failures rather than masquerading as invocation validation or policy
denial.

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
| User tries to redirect a guard-owned child through PATH | Fixed absolute verified child paths (§5.2) |
| User compiles own git wrapper and runs it | Required kernel capability-set and deployment-class checks (§2.2) |
| User reads guard binary to find git.original path | git.original is 0700 root-only (§2.1) |
| User tries to exec git.original directly | Permission denied (0700 root:root) |
| User uses `LD_PRELOAD` to inject code | Env var unset (§5.1) + static linking |
| User pushes from CI script to bypass hooks | Background push detection (§4, check 4d) |
| User amends a commit | Non-root amend sudo gate (§4, check 4d) |
| User reverts a local or pushed commit | Allowed forward operation; hooks and reconciliation apply |
| User creates merge commit on main | Protected branch rule (§4, check 5) |
| User deletes .pre-commit-config.yaml then pushes | P3 contract check (§6.2) |
| User installs alternate git via apt | dpkg-divert prevents overwrite (§5.2 in SPEC-GIT-GUARD-INSTALL) |
| User accesses git via snap/flatpak | Snap/flatpak git binaries restricted to 000 (§12.1 in SPEC-GIT-GUARD-INSTALL) |
| User downloads git binary from upstream | Installation/permission controls protect canonical `/usr/bin/git`; child PATH is not this boundary |
| User modifies PATH | Guard-owned children remain fixed absolute paths; caller tools retain intended PATH behavior (§5.2) |
| User replaces guard binary with own version | Root ownership and immutable attribute `chattr +i` prevent modification |
| User modifies dpkg to remove diversion | Apt post-invoke hook detects and warns (§5.6 in SPEC-GIT-GUARD-INSTALL). Divert is root-only operation |
| User compiles git from source | Source compile goes to `/usr/local/bin/git` which is restricted to 000 (§12.1 in SPEC-GIT-GUARD-INSTALL) |

### 9.2 Threats NOT Mitigated (root-level attacks)

| Threat | Reason |
|--------|--------|
| User has root access | Root can remove file capabilities, reinstall git, remove diversion, etc. The guard protects against workspace users, not root. Root access is a security boundary violation and root actions are audited. |
| Kernel exploit | Out of scope. If the kernel is compromised, no user-space mechanism helps. |
| Hardware-level attack | Out of scope. |

### 9.3 Defense in Depth Layers

The guard implements multiple independent layers of defense:

1. **Capability Boundary**: Only the four-capability guard can invoke real Git; real Git is 0700 root:root
2. **Argument Validation**: All args parsed and validated before execve
3. **Environment Sanitisation**: Allow-list approach; no dangerous env vars passed through
4. **Absolute Child Selection**: Caller PATH is preserved but never locates guard-owned executables
5. **dpkg-divert**: Prevents apt from overwriting the guard
6. **Immutable Attribute**: `chattr +i` prevents filesystem-level tampering
7. **Apt Hook**: Detects git package changes and warns
8. **Pre-commit Hooks**: Second layer of defense at the repo level
9. **Audit Logging**: All blocks logged with timestamps, UIDs, and commands
10. **Static Linking**: No shared library injection vectors
11. **Resource Limits**: RLIMIT_CORE=0, RLIMIT_NOFILE=256 limit blast radius

### 9.4 Blast Radius

If the guard binary has a bug that allows arbitrary code execution with its four capabilities:
- The binary is ~500 LOC: small audit surface
- Static linking removes shared library attack vectors
- No network I/O, no file parsing, no deserialisation
- No heap allocations from untrusted input (argv is bounded)
- `RLIMIT_CORE=0` prevents core dump analysis
- `RLIMIT_NOFILE=256` limits file descriptor exhaustion
- The only privileged operation is `execve()` of a known-good binary

The worst-case guard RCE receives `CAP_SETPCAP`, `CAP_CHOWN`,
`CAP_DAC_OVERRIDE`, and `CAP_FOWNER`, not UID 0. This remains a severe local
privilege boundary failure, but its authority is bounded by the capability set.

---

## 10. File Layout

| Path | Purpose |
|------|---------|
| `/usr/bin/git` | workspace-guard capability-enabled binary (installed) |
| `/usr/bin/git.original` | real git binary (relocated, 0700 root:root) |
| `projects/WORKSPACE-GUARD/` | Rust source code repository |
| `projects/WORKSPACE-GUARD/git-guard/src/main.rs` | Privileged multi-module Rust implementation |
| `projects/WORKSPACE-GUARD/git-guard/Cargo.toml` | Isolated package manifest |
| `projects/WORKSPACE-GUARD/git-guard/Cargo.lock` | Isolated locked dependencies |
| `projects/WORKSPACE-GUARD/git-guard/dependency-closure.json` | Approved normal/build/proc-macro closures |

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
| REQ-GGUARD-011 | §3.1 | Specified; implementation update tracked |
| REQ-GGUARD-012 | §3.4 | Specified; implementation update tracked |
| REQ-GGUARD-013 | §3.5 | Specified; implementation update tracked |
| REQ-GGUARD-014 | §3.1 | Covered |
| REQ-GGUARD-020/020a/020b | §4, check 1 | Specified; matrix validation tracked |
| REQ-GGUARD-021 | §4.1 | Specified; formatter and delivery updates tracked |
| REQ-GGUARD-030 | §3.1 phase 3, §4 check 2 | Specified; command-option parser update tracked |
| REQ-GGUARD-031 | §3.3 | Specified; config-option parser update tracked |
| REQ-GGUARD-040 | §3.3, §4 check 3 | Specified; catalog hardening tracked |
| REQ-GGUARD-041 | §3.3 | Specified; key parser hardening tracked |
| REQ-GGUARD-042 | §3.3, §4 check 3 | Specified; passthrough verification tracked |
| REQ-GGUARD-050 | §3.4, §4 check 1 | Enforced; cleanup and coverage tracked |
| REQ-GGUARD-051 | §3.2, §4 branch policy | Critical parser/enforcement work tracked |
| REQ-GGUARD-052 | §3.2, §4 push policy | Critical parser/config work tracked |
| REQ-GGUARD-053 | §4 push foreground check | Critical parser fix tracked |
| REQ-GGUARD-054 | §3.2, §4 check 4d | Enforced; parser coverage tracked |
| REQ-GGUARD-055 | §3.2, §7 reconciliation | Obsolete ancestry policy removal tracked |
| REQ-GGUARD-060 | §4 protected catalog/check 5 | Enforced; validation and coverage tracked |
| REQ-GGUARD-061 | §3.2, §4 check 5a | Critical effective-mode parser work tracked |
| REQ-GGUARD-062 | §3.2, §4 check 5b | Critical effective-mode parser work tracked |
| REQ-GGUARD-063 | §4 check 5, §4.3 | Critical context/error handling work tracked |
| REQ-GGUARD-070 | §5.1 | Critical allow-list implementation work tracked |
| REQ-GGUARD-071 | §4 check 6, §5.1 | Enforced; byte-safe/catalog coverage tracked |
| REQ-GGUARD-072 | §5.2 | Preservation/config migration tracked |
| REQ-GGUARD-073 | §5.1, §5.3 | Catalog migration and trust-boundary tests tracked |
| REQ-GGUARD-074 | §2.2, §5.4-5.5 | Universal secure_getenv retired; snapshot/diagnostics tracked |
| REQ-GGUARD-080 | §6, §6.2 | Policy catalog correction and coverage tracked |
| REQ-GGUARD-081 | §4.3, §6.1 | Critical trusted-registry replacement tracked |
| REQ-GGUARD-082 | §6.1 | Critical protected-destination resolution work tracked |
| REQ-GGUARD-083 | §6.2-6.4 | Critical fixed-runner implementation work tracked |
| REQ-GGUARD-084 | §6.2 | Naming, byte safety, and spoofing coverage tracked |
| REQ-GGUARD-085 | §4.1, §6.2 | Typed streaming/failure reporting tracked |
| REQ-GGUARD-086 | §6.2, §6.4 | Typed unavailable-deployment coverage tracked |
| REQ-GGUARD-090 | §7.1-7.4 | Critical root-owned audit sink work tracked |
| REQ-GGUARD-091 | §7.1-7.3 | Canonical byte-record implementation tracked |
| REQ-GGUARD-092 | §7.1-7.4 | Typed non-recursive failure handling tracked |
| REQ-GGUARD-093 | §4.1, §7.1-7.3 | Complete forensic evidence work tracked |
| REQ-GGUARD-100 | §8.5 | Exit/signal propagation and typed failures tracked |
| REQ-GGUARD-101 | §4.1-4.2 | Typed policy-denial dispatcher work tracked |
| REQ-GGUARD-102 | §3.1, §8.7 | Typed validation/parser work tracked |
| REQ-GGUARD-103 | §2.2-2.3, §8.6 | Critical exit-3 verification/supervision work tracked |
| REQ-GGUARD-104 | §6.1-6.4, §7.1-7.4, §8.7 | Critical typed exit-4 dispatch and fail-closed helper work tracked |
| REQ-GGUARD-110 | §4.1, §8.7 | Critical shared delivery and terminal-identity work tracked |
| REQ-GGUARD-111 | §4.1, §7.1 | Critical canonical formatter/evidence-object work tracked |
| REQ-GGUARD-112 | §4.1, §5.6, §7.1-7.2, §8.7 | Critical typed warning/write-failure work tracked |
| REQ-GGUARD-113 | §4.1, §5.5, §5.7, §6.2, §8.5-8.7 | Critical stream ownership/framing/write-failure work tracked |
| REQ-GGUARD-120 | §8.4-8.5 | Critical profile/linker/final-ELF/install verification work tracked |
| REQ-GGUARD-121 | §8.3 | Critical centralized FFI/post-fork/build-gate work tracked |
| REQ-GGUARD-122 | §8.1-8.2, §8.4-8.5 | Critical package split/closure/offline-build work tracked |
| REQ-GGUARD-123 | §3.1, §3.3-3.6, §5.1-5.5 | Critical byte-parser/path/helper/conversion work tracked |
| REQ-GGUARD-124 | §8.6 | Covered |
| REQ-GGUARD-125 | §7.4 | Covered |
| REQ-GGUARD-130 | §4.3 | Covered |
| REQ-GGUARD-131 | §4.3 | Covered |
| REQ-GGUARD-132 | §4.3 | Covered |
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
