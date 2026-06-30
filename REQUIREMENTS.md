# Requirements: WORKSPACE-GUARD SUID Guard Framework

**Date:** 2026-05-19  
**Status:** DRAFT  
**Type:** Requirements

---

## Background

The WORKSPACE-GUARD framework provides compiled, unbypassable privilege enforcement for tools that need to be intercepted at the binary level. The initial Proof of Concept targets `git`, replacing a 337-line bash wrapper (`ami/scripts/utils/git-guard`) that was trivially bypassable (PATH-based, readable source, editable).

The core insight: if the *real* binary is mode 0700 root:root and the *guard* binary is SUID root 4555 at the same path, non-root users **must** go through the guard and cannot read or modify its logic.

---

## Core Requirements

### 1. Privileged Execution Model

- **REQ-GGUARD-001**: The guard binary shall be installed at the target binary's system path with owner root:root and mode 4555 (SUID root, world-executable).
- **REQ-GGUARD-002**: The real binary shall reside at `<path>.original` with owner root:root and mode 0700.
- **REQ-GGUARD-003**: The guard shall detect privileged execution via `getauxval(AT_SECURE)`: not by comparing real/effective UID: to correctly handle file-capability contexts.
- **REQ-GGUARD-004**: If `AT_SECURE` is not set, the guard shall refuse to operate and exit with code 3.
- **REQ-GGUARD-005**: The guard shall call `setuid(getuid())` before `execve` to drop root privileges before the real binary runs.
- **REQ-GGUARD-006**: The guard shall restrict file-descriptor limits (`RLIMIT_NOFILE`) to prevent fd-exhaustion attacks.
- **REQ-GGUARD-007**: The guard shall disable core dumps (`RLIMIT_CORE = 0`) to prevent memory-dump leaks.
- **REQ-GGUARD-008**: Both the guard binary and `<path>.original` shall be made immutable via `chattr +i`.

### 2. Argument Parsing & Validation

- **REQ-GGUARD-020**: The guard shall reject any argument containing a null byte (`\0`).
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
- **REQ-GGUARD-038**: The guard shall block `git commit --amend` unconditionally.
- **REQ-GGUARD-039**: The guard shall block `git push --force` and `git push -f`.
- **REQ-GGUARD-040**: The guard shall block `git branch -D` (force delete).
- **REQ-GGUARD-041**: The guard shall block `git stash drop` and `git stash clear`.
- **REQ-GGUARD-042**: The guard shall block `git revert` on commits not yet pushed to `origin/<branch>`.
- **REQ-GGUARD-043**: The guard shall block `git pull` on protected branches (`main`, `master`) unless `--ff-only` or `--rebase` is specified.
- **REQ-GGUARD-044**: The guard shall block `git merge` on protected branches unless `--ff-only` is specified.
- **REQ-GGUARD-045**: The guard shall block any command using `--no-verify`.
- **REQ-GGUARD-046**: The guard shall block any command using `--hard`.
- **REQ-GGUARD-047**: The guard shall block `git push` from background process groups (non-foreground).

### 4. Environment Sanitization

- **REQ-GGUARD-060**: The guard shall construct a minimal environment for `execve` containing only a whitelisted set of variables.
- **REQ-GGUARD-061**: The whitelist shall include: `HOME`, `USER`, `LANG`, `LC_*`, `TERM`, `DISPLAY`, `WAYLAND_DISPLAY`, `SSH_AUTH_SOCK`, `GPG_TTY`, `GIT_*`, `EMAIL`, `EDITOR`, `VISUAL`, `SHELL`, `PWD`.
- **REQ-GGUARD-062**: The guard shall set `PATH` to a hardcoded value: `/usr/local/bin:/usr/bin:/bin`.
- **REQ-GGUARD-063**: The guard shall inject `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=safe.directory`, `GIT_CONFIG_VALUE_0=*` to suppress git's ownership check without needing a user-level config.
- **REQ-GGUARD-064**: The guard shall block `-c` flags with dangerous config keys: `core.hookspath`, `core.sshcommand`, `core.editor`, `core.excludesfile`, `protocol.allow`, `protocol.ext.allow`, `safe.directory`, `core.gitproxy`, `url.insteadof`, `credential.helper`, `http.proxy`, `https.proxy`.
- **REQ-GGUARD-065**: The guard shall block `SKIP` and `PRE_COMMIT_ALLOW_NO_CONFIG` environment variables.
- **REQ-GGUARD-066**: The guard shall sanitize `-c` flags passed via `--c=key=val` long-form syntax.

### 5. Audit Logging

- **REQ-GGUARD-080**: Every blocked operation shall be logged to `~/.workspace-guard.log`.
- **REQ-GGUARD-081**: The log entry shall include: ISO-8601 timestamp, current working directory, the blocked command/reason, and the user's UID.
- **REQ-GGUARD-082**: The guard shall print a user-visible error message with a hint on how to proceed.
- **REQ-GGUARD-083**: The guard shall attempt to write to `/dev/tty` for immediate user notification.
- **REQ-GGUARD-084**: The system-level audit log directory `/var/log/workspace-guard/` shall exist with mode 1777.

### 6. AMI-CI Integration

- **REQ-GGUARD-100**: Before `git commit` and `git push`, the guard shall execute the AMI-CI quality check script (`checks_quality.sh`).
- **REQ-GGUARD-101**: If the quality check fails, the guard shall reject the operation with a `ContractFailed` error (exit code 4).
- **REQ-GGUARD-102**: The guard shall pass the `AMI_GGUARD_CMD`, `AMI_GGUARD_REPO_ROOT`, and `AMI_GGUARD_WORKSPACE_ROOT` environment variables to the quality check script.
- **REQ-GGUARD-103**: The guard shall detect the workspace root by walking up from the git toplevel looking for `.boot-linux` + `projects/CI` + `ami/scripts/utils/git-guard`.

### 7. Deployment & Installation

- **REQ-GGUARD-120**: Installation shall be performed exclusively via `sudo make pre-req`.
- **REQ-GGUARD-121**: The build process shall produce a statically linked musl binary (preferred) or a dynamically linked gnu binary with `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`, and `strip = true`.
- **REQ-GGUARD-122**: The sole Rust dependency shall be `libc` (system FFI).
- **REQ-GGUARD-123**: Installation shall configure `dpkg-divert` to redirect apt's git package from `/usr/bin/git` to `/usr/bin/git.distrib`.
- **REQ-GGUARD-124**: Installation shall register an apt post-invoke hook at `/etc/apt/apt.conf.d/99workspace-guard` that warns if the git package changes without the guard.
- **REQ-GGUARD-125**: Installation shall restrict alternate git binaries (`/snap/bin/git`, `/usr/local/bin/git`) to prevent guard bypass.
- **REQ-GGUARD-126**: Installation shall verify the guard works by running `git --version` and testing that `git reset --hard` is blocked.
- **REQ-GGUARD-127**: Installation shall support `--uninstall-workspace-guard` and `--reinstall-workspace-guard` flags.
- **REQ-GGUARD-128**: Uninstall shall restore the original git binary, remove `dpkg-divert`, and clean up all guard system paths.

### 8. Binary Hardening

- **REQ-GGUARD-140**: The guard binary shall be compiled with `panic = "abort"` to prevent unwind attacks.
- **REQ-GGUARD-141**: The guard binary shall have all symbols stripped (`strip = true`).
- **REQ-GGUARD-142**: The guard binary shall use LTO and single codegen unit to resist function-level replacement.
- **REQ-GGUARD-143**: The guard shall validate `<path>.original` ownership (root:root) and mode (0700) before each `execve`.
- **REQ-GGUARD-144**: `chattr +i` shall be applied to both `/usr/bin/git` and `/usr/bin/git.original`.

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

| Requirement | Source |
|------------|--------|
| REQ-GGUARD-001-008 | Privileged execution design |
| REQ-GGUARD-020-024 | Argument parsing (args.rs) |
| REQ-GGUARD-030-047 | Block logic (block.rs) |
| REQ-GGUARD-060-066 | Environment sanitization (exec.rs + main.rs) |
| REQ-GGUARD-080-084 | Audit logging (log.rs) |
| REQ-GGUARD-100-103 | AMI-CI integration (exec.rs) |
| REQ-GGUARD-120-128 | Deployment (bootstrap_rust_guard.sh, pre-req.sh) |
| REQ-GGUARD-140-144 | Binary hardening (Cargo.toml, deploy) |
| REQ-GGUARD-160-162 | Framework architecture |
