# Requirements: WORKSPACE-GUARD SUID Guard Framework

**Date:** 2026-05-19  
**Status:** DRAFT  
**Type:** Requirements

---

## Background

The WORKSPACE-GUARD framework provides compiled, unbypassable privilege enforcement for tools that need to be intercepted at the binary level. The initial Proof of Concept targets `git`, replacing a 337-line bash wrapper (`ami/scripts/utils/git-guard`) that was trivially bypassable (PATH-based, readable source, editable).

The core insight: if the _real_ binary is mode 0700 root:root and the _guard_ binary is SUID root 4555 at the same path, non-root users **must** go through the guard and cannot read or modify its logic.

---

## Core Requirements

### 1. Privileged Execution Model

- **REQ-GGUARD-001**: The guard binary shall be installed at the target binary's system path with owner root:root and mode 4555 (SUID root, world-executable).
- **REQ-GGUARD-002**: The real binary shall reside at `<path>.original` with owner root:root and mode 0700.
- **REQ-GGUARD-003**: The guard shall detect privileged execution via `getauxval(AT_SECURE)`: not by comparing real/effective UID: to correctly handle file-capability contexts.
- **REQ-GGUARD-004**: If `AT_SECURE` is not set, the guard shall refuse to operate and exit with code 3.
- **REQ-GGUARD-005**: Exit 3 is the typed guard-unavailable class for deployment,
  privilege/capability, required resource setup, real-binary verification, and
  fork/exec/wait/signal supervision failures. It is distinct from a propagated
  real Git exit 3.
- **REQ-GGUARD-005**: The guard shall call `setuid(getuid())` before `execve` to drop root privileges before the real binary runs.
- **REQ-GGUARD-006**: The guard shall restrict file-descriptor limits (`RLIMIT_NOFILE`) to prevent fd-exhaustion attacks.
- **REQ-GGUARD-007**: The guard shall disable core dumps (`RLIMIT_CORE = 0`) to prevent memory-dump leaks.
- **REQ-GGUARD-008**: Both the guard binary and `<path>.original` shall be made immutable via `chattr +i`.

### 2. Argument Parsing & Validation

- **REQ-GGUARD-020**: Exit 2 is reserved for caller-caused invocation data the
  guard cannot safely or reliably classify, including internal/test NUL bytes,
  missing recognized global-option operands, and unknown leading-option arity
  that makes subcommand discovery indeterminate. Reliably classifiable Git
  syntax errors pass unchanged to Git.
- **REQ-GGUARD-021**: The guard shall parse `-c` / `-C` config flags and validate config keys against a dangerous-property blocklist.
- **REQ-GGUARD-022**: The guard shall identify the subcommand (first non-flag argument) and apply subcommand-specific validation.
- **REQ-GGUARD-023**: The guard shall detect long-form flags (`--hard`, `--no-verify`, `--force`, `--amend`, etc.) and short-form compound flags (`-f`, `-D`, `-c`) in any argument position.
- **REQ-GGUARD-024**: The guard shall handle `--` separator correctly (stop parsing flags after `--`).

### 3. Operation Blocking

- **REQ-GGUARD-030**: The guard shall block `git reset` unconditionally.
- **REQ-GGUARD-031**: The guard shall block `git checkout` unconditionally.
- **REQ-GGUARD-032**: The guard shall block `git clean` unconditionally.
- **REQ-GGUARD-033**: The guard shall block `git restore` unconditionally.
- **REQ-GGUARD-034**: The guard shall block `git rm` unconditionally.
- **REQ-GGUARD-035**: The guard shall block `git rebase` unconditionally.
- **REQ-GGUARD-036**: The guard shall block `git gc` unconditionally.
- **REQ-GGUARD-037**: The guard shall block `git prune` unconditionally.
- **REQ-GGUARD-038**: The guard shall block every actual `git commit --amend`
  option for non-root users; the verified root operator path may amend.
- **REQ-GGUARD-039**: The guard shall block `git push --force` and `git push -f`.
- **REQ-GGUARD-040**: The guard shall block `git branch -D` (force delete).
- **REQ-GGUARD-041**: The guard shall block `git stash drop` and `git stash clear`.
- **REQ-GGUARD-042**: The guard shall allow `git revert`; revert is a
  forward-only operation and remains subject to hooks and ownership
  reconciliation.
- **REQ-GGUARD-043**: The guard shall block unsafe `git pull` forms on branches
  classified by the authoritative compiled protected-branch catalog.
- **REQ-GGUARD-044**: The guard shall block unsafe `git merge` forms on branches
  classified by the same authoritative catalog.
- **REQ-GGUARD-045**: The guard shall block any command using `--no-verify`.
- **REQ-GGUARD-046**: The guard shall block any command using `--hard`.
- **REQ-GGUARD-047**: The guard shall block `git push` from background process groups (non-foreground).

### 4. Environment Sanitization

- **REQ-GGUARD-060**: The guard shall construct a minimal environment for `execve` containing only a whitelisted set of variables.
- **REQ-GGUARD-061**: The compiled environment-policy catalog shall be the sole
  authority for allowed exact names, allowed prefixes, root-only names,
  config-value carriers, and guard-owned variables.
- **REQ-GGUARD-062**: The guard shall preserve the caller's `PATH`. Guard-owned
  executables shall be selected by absolute verified paths rather than by
  resetting PATH.
- **REQ-GGUARD-063**: The guard shall inject `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=safe.directory`, `GIT_CONFIG_VALUE_0=*` to suppress git's ownership check without needing a user-level config.
- **REQ-GGUARD-064**: The guard shall block `-c` flags with dangerous config keys: `core.hookspath`, `core.sshcommand`, `core.excludesfile`, `protocol.allow`, `protocol.ext.allow`, `safe.directory`, `core.gitproxy`, `url.insteadof`, `credential.helper`, `http.proxy`, `https.proxy`. (See REQ-GGUARD-068 for sudo-gated keys.)
- **REQ-GGUARD-065**: The guard shall exit 1 when any cataloged hook-bypass
  environment variable has a non-empty byte value; empty values are removed by
  sanitization without blocking.
- **REQ-GGUARD-066**: The guard shall sanitize `-c` flags passed via `--c=key=val` long-form syntax.
- **REQ-GGUARD-067**: The guard shall treat an invocation with real UID 0 (`getuid()==0`, e.g. `sudo git`) as privileged.
- **REQ-GGUARD-068**: The guard shall block `-c`/`-C`/`--config`/`--config-env`/`git config <key>` use of sudo-gated config keys (`core.editor`, `sequence.editor`, `user.name`, `user.email`, `user.signingkey`) for non-root users (exit 1 + audit); root may set them.
- **REQ-GGUARD-069**: The guard shall drop cataloged root-only editor and
  identity variables for non-root users with byte-exact evidence diagnostics;
  effective-UID-zero operators may pass them through. `AT_SECURE` is not an
  operator authorization test.

### 5. Audit Logging

- **REQ-GGUARD-080**: Every blocked operation shall be logged only to the
  authoritative root-owned `/var/log/workspace-guard/git-<real-uid>.log`; no
  audit log or mirror may be written under a user-writable directory.
- **REQ-GGUARD-081**: Audit records shall use the versioned canonical byte
  encoding from detailed REQ-GGUARD-091 and include timestamp, event/exit class,
  real UID, cwd, boundary-preserving argv, and reason.
- **REQ-GGUARD-082**: Each policy block shall use the canonical ASCII
  `BLOCKED:` grammar from detailed REQ-GGUARD-111, with indexed byte-preserving
  argv, exact selected reason, one RFC3339 UTC `Z` timestamp, and a safe encoded
  remediation hint derived from the matched policy.
- **REQ-GGUARD-083**: Every guard-enforced failure report shall be attempted on
  stderr and on `/dev/tty` only when it is a distinct controlling terminal;
  terminal sameness shall use terminal/session identity rather than inode or
  pathname identity, and delivery failure shall not alter the original outcome.
- **REQ-GGUARD-084**: `/var/log/workspace-guard/` shall be `root:root` mode
  `0750`; per-UID Git audit files shall be `root:root` mode `0600`.
- **REQ-GGUARD-085**: Audit and diagnostic evidence shall remain complete and
  reversibly encoded without redaction, masking, omission, hashing, or
  truncation. Inline credentials are prohibited; agents must use sanctioned
  secret-store paths.

### 6. WORKSPACE-CI Integration

- **REQ-GGUARD-100**: Before `git commit` and `git push`, the guard shall execute the WORKSPACE-CI quality check script (`checks_quality.sh`).
- **REQ-GGUARD-101**: Every required WORKSPACE-CI contract rejection,
  unavailable runner/scope/integrity outcome, or outside-workspace protected or
  indeterminate push destination shall reject the operation with exit code 4;
  root has no bypass and requested Git shall not execute.
- **REQ-GGUARD-102**: The guard shall pass exactly one each of
  `WORKSPACE_GGUARD_CMD`, `WORKSPACE_GGUARD_REPO_ROOT`, and
  `WORKSPACE_GGUARD_WORKSPACE_ROOT`; legacy `AMI_GGUARD_*` names are forbidden.
- **REQ-GGUARD-103**: The guard shall detect the configured workspace root without treating an agent-writable deployment entry as authority, and shall resolve protected WORKSPACE-CI only at `/opt/workspace-ci`.
- **REQ-GGUARD-113**: The guard shall emit no guard-generated stdout; real Git
  shall inherit caller stdout/stderr unchanged, helper stdout shall remain typed
  internal protocol, helper stderr shall use reversible framed chunks, and trace
  shall use checked static-token stderr records enabled once from the startup
  environment snapshot.

### 7. Build And Runtime Constraints

- **REQ-GGUARD-120**: The exact privileged Git guard artifact shall use the
  pinned static-musl hardened profile and pass final-ELF, digest, and installed-
  inode verification before file capabilities are applied.
- **REQ-GGUARD-121**: Production unsafe Rust shall be confined to one reviewed
  module implementing only `getauxval(AT_SECURE)`, `fork`, `_exit`, and
  `ioctl(FS_IOC_GETFLAGS)`; all other system operations shall use safe standard,
  `nix`, or approved wrappers, and build gates shall reject boundary growth.
- **REQ-GGUARD-122**: The privileged Git guard shall be an isolated Cargo package
  with runtime direct dependencies limited to `libc`, minimal-feature `nix`, and
  optional `caps`; its separately approved build closure shall be locked,
  checksum-verified, offline, feature-exact, and mechanically compared before
  every privileged artifact build.
- **REQ-GGUARD-123**: Caller argv, paths, refs, environment values, and helper
  evidence shall remain raw Unix bytes; policy shall use byte comparisons and
  field-specific ASCII grammars without blanket UTF-8 validation or lossy
  conversion.
- **REQ-GGUARD-124**: Required file/core resource limits shall be established and
  checked before requested Git execution.
- **REQ-GGUARD-125**: Pre-exec file descriptors shall be limited to explicitly
  specified guard operations and closed-on-exec where not inherited by Git.

### 8. Deployment And Installation

- **REQ-GGUARD-140**: Git guard deployment shall use only `make build-guard` and
  `make install-guard-host-exec`; generic `make install` shall not modify Git.
- **REQ-GGUARD-141**: Installation shall notify the operator before relocating
  system Git or installing a capability-enabled replacement.
- **REQ-GGUARD-142**: The isolated package shall be built unprivileged under the
  pinned frozen/offline build contract before root verification/installation.
- **REQ-GGUARD-143**: Installation shall verify the hardened ELF artifact and
  existing system Git before relocation.
- **REQ-GGUARD-144**: Real Git shall be copied byte-exactly to the fixed trusted
  `.original` path with the required ownership, mode, and integrity checks.

### 9. Framework Architecture

- **REQ-GGUARD-160**: The framework shall support multiple guard crates, each targeting a different binary, with shared primitives (AT_SECURE check, env sanitization, execve wrapper).
- **REQ-GGUARD-161**: Each guard crate shall define its own `BLOCKED_SUBCOMMANDS`, `ALLOWED_VARS`, and `DANGEROUS_CONFIG_KEYS`.
- **REQ-GGUARD-162**: Each guard crate shall define its own `<path>.original` constant for the real binary path.

---

## Non-Requirements

The following are explicitly out of scope:

- **Filesystem-level mandatory access control** (SELinux, AppArmor): assumed to be configured separately if needed
- **Network-level controls**: the guard does not filter network access
- **User authentication**: the guard does not re-authenticate the user
- **Encryption**: the guard does not encrypt anything
- **Container/namespace isolation**: the guard does not enter namespaces
- **Runtime integrity monitoring**: the guard does not monitor itself for tampering after installation
- **Library call interception**: the guard does not prevent libgit2, GitPython, or other git library bypasses (detected at install time only)

---

## Traceability

| Requirement        | Source                                           |
| ------------------ | ------------------------------------------------ |
| REQ-GGUARD-001-008 | Privileged execution design                      |
| REQ-GGUARD-020-024 | Argument parsing (args.rs)                       |
| REQ-GGUARD-030-047 | Block logic (block.rs)                           |
| REQ-GGUARD-060-066 | Environment sanitization (exec.rs + main.rs)     |
| REQ-GGUARD-080-085 | Audit logging (`log.rs`)                         |
| REQ-GGUARD-100-103 | WORKSPACE-CI integration (`exec.rs`)             |
| REQ-GGUARD-113     | Stream ownership and diagnostics                 |
| REQ-GGUARD-120     | Verified privileged binary hardening             |
| REQ-GGUARD-121     | Centralized unsafe/FFI boundary                   |
| REQ-GGUARD-122     | Dependency boundary                              |
| REQ-GGUARD-123     | Byte-oriented input and forwarding               |
| REQ-GGUARD-124-125 | Resource and descriptor limits                   |
| REQ-GGUARD-140-144 | Deployment (`bootstrap_rust_guard.sh`, installer) |
| REQ-GGUARD-160-162 | Framework architecture                           |
