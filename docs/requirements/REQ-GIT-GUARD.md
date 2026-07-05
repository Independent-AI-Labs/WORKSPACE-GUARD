# Requirements: WORKSPACE-GUARD SUID Guard Framework (Git PoC)

**Date:** 2026-05-18
**Updated:** 2026-06-24
**Status:** ACTIVE
**Type:** Requirements

---

## Background

The current git-guard is a 337-line bash script at `workspace/scripts/utils/git-guard`. It intercepts git commands by being placed first in PATH, blocks destructive operations, and enforces WORKSPACE-CI contracts on commit/push. However, a bash wrapper is inherently bypassable: the source is readable, logic can be understood and circumvented, and it relies on PATH ordering alone.

The replacement is a **Rust binary** installed as a **capability-enabled** executable at `/usr/bin/git`, with the real git binary relocated to `/usr/bin/git.original` (owner root, mode 700). The guard validates all arguments in compiled code, sanitises the execution environment, and only then `execve()`s the real git. A user who reads the binary cannot trivially bypass it because:

1. The real git at `/usr/bin/git.original` is mode 700 root:root: unreadable and unexecutable by non-root.
2. No sudoers rule allows direct execution of git.original.
3. The guard itself is a compiled Rust binary, not a readable script.

For environments where file capabilities are unavailable (PRoot, containers running as root), a **root-only mode** (`--features root-only`) provides a soft barrier with the same policy engine.

This document specifies the requirements for the Rust binary. The installation/deployment procedure is specified in [SPEC-GIT-GUARD-INSTALL](../specifications/SPEC-GIT-GUARD-INSTALL.md) and is handled by `make build-guard` and `make install-guard`.

---

## Core Requirements

### 1. Privileged Execution Model

- **REQ-GGUARD-001**: The binary shall be installed at `/usr/bin/git` with owner root:root and mode 0755, with file capability `cap_dac_override+ep` (capability mode).
- **REQ-GGUARD-002**: The real git binary shall reside at `/usr/bin/git.original` with owner root:root and mode 0700.
- **REQ-GGUARD-003**: The binary shall detect privileged execution via `caps::has_cap()` (capability mode) or `geteuid() == 0` (root-only mode).
- **REQ-GGUARD-004**: If the capability check fails (capability mode) or euid is not 0 (root-only mode), the binary shall refuse to operate and exit with code 2. This prevents an attacker from compiling their own binary that bypasses the guard.
- **REQ-GGUARD-005**: The binary shall call `execve()` with an **absolute path** to `/usr/bin/git.original`: never `execvp()` or PATH-based lookup.
- **REQ-GGUARD-006**: The binary shall verify that `/usr/bin/git.original` exists, is a regular file, is owned by root, and has mode 0700 before exec-ing it. If verification fails, exit with code 2.
- **REQ-GGUARD-007**: The binary shall NOT use `system()`, `Command::new("sh")`, or any shell invocation at any point. All subprocess execution shall use explicit argument vectors.

### 2. Argument Parsing

- **REQ-GGUARD-010**: The binary shall parse all arguments before any decision logic, correctly handling the `--` option separator. Arguments after `--` shall not be interpreted as git flags.
- **REQ-GGUARD-011**: The first positional argument (after stripping leading flags and `--`) shall be identified as the **git subcommand**. If no subcommand is present, the binary shall pass through to real git with all arguments unchanged.
- **REQ-GGUARD-012**: The binary shall recognise all standard git subcommands (clone, commit, push, pull, fetch, merge, rebase, reset, checkout, clean, restore, rm, branch, tag, stash, revert, gc, prune, add, diff, log, status, show, config, init, submodule, etc.).
- **REQ-GGUARD-013**: If the identified subcommand is not in the recognised list and does not begin with `-`, the binary shall pass through to real git (fail-open for unknown subcommands, since git itself will reject invalid ones).
- **REQ-GGUARD-014**: The binary shall reject arguments containing null bytes (`\0`). If any argument contains a null byte, exit with code 2.

### 3. Destructive Command Blocks (Unconditional)

- **REQ-GGUARD-020**: The following subcommands shall be unconditionally blocked with exit code 1:
  - `reset`
  - `clean`
  - `restore`
  - `rm`
  - `rebase`
  - `gc`
  - `prune`
- **REQ-GGUARD-020a**: The following subcommands shall be sudo-gated (denied for non-root, allowed for root via `sudo`):
  - `submodule`
  - `checkout`
- **REQ-GGUARD-021**: The block message shall include the blocked command, a timestamp (ISO 8601), and shall be written to both stderr and `/dev/tty` (if available) so it cannot be silenced by `> /dev/null 2>&1`.

### 4. Destructive Flag Blocks (Global)

- **REQ-GGUARD-030**: The following flags shall be blocked in any invocation, regardless of subcommand:
  - `--hard`
  - `--no-verify`
  - `--force` / `-f` (when used with push, tag, or branch)
  - `--force-with-lease`
- **REQ-GGUARD-031**: The `-c` and `-C` flags (git config override) shall be validated: if the key portion matches any pattern in the **dangerous config keys** list (§5, REQ-GGUARD-040), the invocation shall be blocked.

### 5. Dangerous Git Config Key Injection

- **REQ-GGUARD-040**: The following git config keys, when set via `-c` or `-C`, shall be blocked:
  - `core.hooksPath`: redirects hook execution to attacker-controlled directory
  - `core.sshCommand`: replaces SSH command, enabling arbitrary execution
  - `core.editor` / `core.excludesFile`: can be used to execute arbitrary commands (`core.editor` is sudo-gated: blocked for non-root via `-c`, allowed for root)
  - `protocol.<name>.allow`: can enable dangerous protocols (e.g., `ext::`)
  - `safe.directory`: can bypass repository ownership checks
  - `core.gitProxy`: intercepts git network operations
  - `url.<base>.insteadOf`: can redirect remotes to attacker-controlled URLs
- **REQ-GGUARD-041**: A `-c key=value` argument shall be parsed by splitting on the first `=`. The key portion shall be compared case-insensitively against the block list.
- **REQ-GGUARD-042**: The `-c` and `-C` flags with keys NOT in the block list shall be allowed (pass through to real git).

### 6. Subcommand-Specific Blocks

- **REQ-GGUARD-050**: `stash` subcommand: block when any argument is `drop` or `clear` (non-root only; sudo-gated for root).
- **REQ-GGUARD-051**: `branch` subcommand: block when any argument is `-D` (force delete). The `-d` (safe delete) shall be allowed.
- **REQ-GGUARD-052**: `push` subcommand: block when `--force`, `-f`, or `--force-with-lease` is present.
- **REQ-GGUARD-053**: `push` subcommand: block when the process is **not in the foreground process group** of its controlling terminal. Detection: read `/proc/self/stat`, compare field 5 (pgrp) with field 8 (tpgid). If `tpgid > 0` and `pgrp != tpggid`, block. If `/proc/self/stat` is unreadable, emit a warning to stderr but allow the push (degraded operation).
- **REQ-GGUARD-054**: `commit` subcommand: block `--amend` when the current HEAD is already present on `origin/<current-branch>`. Determination: call real git with `merge-base --is-ancestor HEAD origin/<branch>`. If `--amend` is combined with a block on HEAD, exit code 1.
- **REQ-GGUARD-055**: `revert` subcommand: block when the target commit (default HEAD) is NOT present on `origin/<current-branch>`. Only block if the commit is verified to exist locally via `rev-parse --verify`. This prevents creating noisy revert commits for un-pushed work.

### 7. Protected Branch Rules

- **REQ-GGUARD-060**: A branch is **protected** if its name is `main` or `master`.
- **REQ-GGUARD-061**: `pull` on a protected branch: block unless `--ff-only`, `--rebase`, `--rebase=true`, `--rebase=interactive`, or `--rebase=merges` is present.
- **REQ-GGUARD-062**: `merge` on a protected branch: block unless `--ff-only` or `--abort` is present (non-root only; sudo-gated for root).
- **REQ-GGUARD-063**: Protected branch checks shall only apply when the current branch (from `rev-parse --abbrev-ref HEAD`) matches a protected name. Detached HEAD and no-repo contexts shall skip these checks.

### 8. Environment Variable Sanitisation

- **REQ-GGUARD-070**: Before calling `execve()`, the binary shall **unset** the following environment variables if present:
  - `GIT_EXEC_PATH`: can redirect git subcommand lookup to attacker-controlled directory
  - `GIT_TEMPLATE_DIR`: can install malicious hooks via template
  - `GIT_SSH`: can replace SSH command with arbitrary executable
  - `GIT_SSH_COMMAND`: same
  - `GIT_ASKPASS`: can execute arbitrary commands during auth prompts
  - `GIT_TERMINAL_PROMPT`: can affect interactive behaviour
  - `GIT_EDITOR` / `GIT_SEQUENCE_EDITOR`: can execute arbitrary commands (sudo-gated: dropped with a warning for non-root, passed through for root)
  - `GIT_CONFIG` / `GIT_CONFIG_GLOBAL` / `GIT_CONFIG_SYSTEM`: can redirect config loading
  - `GIT_CEILING_DIRECTORIES`: can affect repo discovery
  - `GIT_DIR` / `GIT_WORK_TREE` / `GIT_NAMESPACE`: can redirect git to wrong repository
  - `GIT_INDEX_FILE`: can point to attacker-controlled index
  - `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` / `LD_DEBUG`: dynamic linker injection (glibc ignores these for SUID, but defense-in-depth)
  - `GCONV_PATH` / `GETCONF_DIR` / `NLSPATH` / `TMPDIR` / `TZDIR` / `RES_OPTIONS` / `HOSTALIASES` / `LOCALDOMAIN` / `NIS_PATH` / `RESOLV_HOST_CONF` / `LOCPATH` / `MALLOC_TRACE`: glibc `unsecvars` list, defense-in-depth
  - `GLIBC_TUNABLES`: can affect malloc behaviour, defense-in-depth
- **REQ-GGUARD-071**: The binary shall **unset** the following hook-bypass variables:
  - `SKIP`: used by pre-commit framework to skip hooks
  - `PRE_COMMIT_ALLOW_NO_CONFIG`: used by pre-commit framework to bypass config requirement
- **REQ-GGUARD-072**: The binary shall set `PATH` to a **known-safe value** (`/usr/local/bin:/usr/bin:/bin`) before exec-ing real git, preventing PATH injection.
- **REQ-GGUARD-073**: The binary shall NOT modify `HOME`, `USER`, `LANG`, `LC_*`, or locale variables: these are needed by git for normal operation.
- **REQ-GGUARD-074**: The binary shall use `secure_getenv()` (via the `nix` crate or libc binding) when reading environment variables during its own execution, to prevent an attacker from influencing the guard's own logic via crafted env vars in the SUID context.

### 9. WORKSPACE-CI Contract Enforcement

- **REQ-GGUARD-080**: Contract enforcement shall run ONLY for `git commit` and `git push` subcommands. All other invocations skip this section entirely.
- **REQ-GGUARD-081**: The binary shall determine if the current repository is within an WORKSPACE workspace by walking up from the repo's `.git` directory (or `git rev-parse --show-toplevel`) and checking for the presence of `.boot-linux/` directory, `projects/CI/` directory, and `workspace/scripts/utils/git-guard` file at the same root.
- **REQ-GGUARD-082**: If the repo is NOT in an WORKSPACE workspace, contract enforcement shall be skipped.
- **REQ-GGUARD-083**: For WORKSPACE workspace repos, the binary shall source and execute the contract checks from `projects/CI/lib/checks_quality.sh`. The binary shall NOT re-implement the contract logic: it delegates to the WORKSPACE-CI shell script.
- **REQ-GGUARD-084**: The binary shall pass the following information to the contract check script via environment variables:
  - `WORKSPACE_GGUARD_CMD`: the git subcommand (`commit` or `push`)
  - `WORKSPACE_GGUARD_REPO_ROOT`: the repo's top-level directory
  - `WORKSPACE_GGUARD_WORKSPACE_ROOT`: the WORKSPACE workspace root
- **REQ-GGUARD-085**: If the contract check script exits non-zero, the binary shall exit with code 4, showing the script's stderr output.
- **REQ-GGUARD-086**: If the contract check script is not found at the expected path, contract enforcement shall be skipped with a warning to stderr (graceful skip).

### 10. Audit Logging

- **REQ-GGUARD-090**: Every blocked invocation shall be logged to `${HOME}/.workspace-guard.log` with the following fields: timestamp (ISO 8601), blocked command/reason, current working directory, full argv, and real UID of the invoking user.
- **REQ-GGUARD-091**: Log lines shall be pipe-delimited for machine parsing: `timestamp | cwd | cmd | reason | uid=<uid>`.
- **REQ-GGUARD-092**: If the log file cannot be opened (permission error, disk full, etc.), the block shall still be enforced: logging failure shall not bypass blocking.
- **REQ-GGUARD-093**: The binary shall NOT log argument values that could contain secrets (e.g., the value portion of `-c` config overrides). Only the key portion shall be logged.

### 11. Exit Codes

- **REQ-GGUARD-100**: Exit **0** when the invocation is allowed and real git is exec'd (the exit code of git itself is returned via exec).
- **REQ-GGUARD-101**: Exit **1** when a destructive command or flag is blocked.
- **REQ-GGUARD-102**: Exit **2** when an argument validation error occurs (null bytes, malformed arguments).
- **REQ-GGUARD-103**: Exit **3** when the binary is not running in a privileged (SUID) context, or when the real git binary cannot be found/verified.
- **REQ-GGUARD-104**: Exit **4** when the AMI-CI contract check script blocks the invocation.

### 12. Error Output

- **REQ-GGUARD-110**: Block messages shall be written to **both** stderr and `/dev/tty` (if writable). The `/dev/tty` write ensures messages survive `> /dev/null 2>&1` redirection in interactive use.
- **REQ-GGUARD-111**: Block messages shall include: a `BLOCKED` prefix, the specific command/reason, and a brief hint for the correct alternative (e.g., "use `git branch -d` instead of `-D`").
- **REQ-GGUARD-112**: Warning messages (non-blocking, such as background push detection unavailable) shall be written to stderr only.
- **REQ-GGUARD-113**: The binary shall NOT produce any output for allowed invocations: all output comes from real git.

### 13. Security Hardening (Rust-Specific)

- **REQ-GGUARD-120**: The binary shall be compiled with the following Rust security flags:
  - `panic = "abort"`: no panic unwinding in a SUID binary
  - Relocation read-only (`relro = "full"`)
  - Stack protector enabled
  - Code generation with `overflow-checks = true` in debug, configurable in release
- **REQ-GGUARD-121**: The binary shall NOT use `unsafe` blocks unless required for `getauxval(AT_SECURE)` or `/proc/self/stat` reading. All `unsafe` blocks shall be documented with a safety comment.
- **REQ-GGUARD-122**: The binary shall NOT depend on any crate that performs network I/O, file system watching, or dynamic loading. Only minimal crates: `std`, `nix` (or `libc`), and optionally `clap` for argument parsing.
- **REQ-GGUARD-123**: String allocations from user input (argv) shall be validated for UTF-8. Non-UTF-8 arguments shall be handled via `OsStr`/`OsString` and passed through to real git unmodified for non-blocking decisions.
- **REQ-GGUARD-124**: The binary shall set its own `RLIMIT_NOFILE` to a reasonable limit (e.g., 256) and `RLIMIT_CORE` to 0 (no core dumps) before exec-ing real git, to limit blast radius.
- **REQ-GGUARD-125**: The binary shall NOT open any file descriptors other than `/dev/tty`, `/proc/self/stat`, and the real git binary before exec-ing. No temporary files, no log file open during argument processing.

### 14. Performance

- **REQ-GGUARD-130**: Non-commit/non-push invocations shall complete guard logic in under 5ms (excluding real git execution).
- **REQ-GGUARD-131**: The binary shall NOT spawn any subprocess for argument parsing or decision logic, except for:
  - `merge-base --is-ancestor` (REQ-GGUARD-054, `commit --amend` check)
  - `rev-parse` (protected branch and revert checks)
  - AMI-CI contract check script (REQ-GGUARD-083)
- **REQ-GGUARD-132**: The `merge-base` and `rev-parse` subprocesses shall have a timeout of 2 seconds. If they time out, the associated check shall be skipped with a warning (fail-open for safety checks that depend on git, fail-closed for destructive command blocks).

### 15. Deployment and Installation

- **REQ-GGUARD-140**: The git guard shall be installed by `make build-guard` and `make install-guard`: not by `make install`. `make install` shall NOT touch the git binary or git guard.
- **REQ-GGUARD-141**: The `make install-guard` script shall inform the user **before** any git-related changes are made, including: that the existing system git will be relocated, that a capability-enabled binary will be installed at `/usr/bin/git`, and that the real git will be restricted to mode 0700 root:root.
- **REQ-GGUARD-142**: The installation script shall build the `workspace-guard` Rust binary from source (`projects/WORKSPACE-GUARD/`) before installing it. The build shall use `cargo build --release` with appropriate feature flags.
- **REQ-GGUARD-143**: Before relocating the real git, the script shall verify that: (a) the Rust binary compiled successfully, (b) the compiled binary is a valid ELF executable, and (c) `/usr/bin/git` exists and is the system git.
- **REQ-GGUARD-144**: The script shall relocate the real git binary as follows:
  1. Copy `/usr/bin/git` to `/usr/bin/git.original`
  2. Set ownership: `chown root:root /usr/bin/git.original`
  3. Set permissions: `chmod 0700 /usr/bin/git.original`
  4. Verify the copy matches the original via checksum comparison
- **REQ-GGUARD-145**: The script shall install the guard binary as follows:
  1. Copy the built binary to `/usr/bin/git`
  2. Set ownership: `chown root:root /usr/bin/git`
  3. Set permissions: `chmod 0755 /usr/bin/git`
  4. Set file capability: `setcap cap_dac_override+ep /usr/bin/git` (capability mode only)
- **REQ-GGUARD-146**: After installation, the script shall verify correctness by:
  1. Confirming `/usr/bin/git` has correct mode and owner
  2. Confirming `/usr/bin/git.original` has mode 0700 and owner root:root
  3. Running `git --version` as the current user and confirming it succeeds
  4. Running `git reset --hard` as the current user and confirming it is blocked
- **REQ-GGUARD-147**: If any step of the installation fails, the script shall attempt to restore the original state: copy `/usr/bin/git.original` back to `/usr/bin/git` and set permissions to 0755. A clear error message shall be displayed.
- **REQ-GGUARD-148**: The installation script shall detect if the guard is already installed (by checking `/usr/bin/git.original` exists with mode 0700). If already installed, the script shall inform the user and skip re-installation unless a `reinstall` mode is passed.
- **REQ-GGUARD-149**: An uninstall procedure shall be available via `make uninstall-guard` which:
  1. Removes `/usr/bin/git` (the guard)
  2. Restores `/usr/bin/git.original` to `/usr/bin/git` with mode 0755
  3. Restores the dpkg diversion (removes it, returning `/usr/bin/git` to dpkg control)
  4. Confirms `git --version` works
- **REQ-GGUARD-150**: The installation script shall configure a `dpkg-divert` for `/usr/bin/git` to prevent the `git` apt package from overwriting the guard binary during `apt install git` or `apt upgrade`. The diversion shall redirect `/usr/bin/git` → `/usr/bin/git.distrib`.
- **REQ-GGUARD-151**: The installation script shall remove the older bash wrapper at `.boot-linux/bin/git` to prevent PATH-based bypass. If `.boot-linux/bin/git` exists, it shall be removed during guard installation.
- **REQ-GGUARD-152**: If the guard detects that `/usr/bin/git` has been replaced (e.g., by a manual override or failed divert), the guard binary shall refuse to `execve()` real git if the inode of `/usr/bin/git` does not match its own. This prevents a scenario where an attacker replaces the SUID binary at the filesystem level.
- **REQ-GGUARD-153**: The installation script shall register an apt post-invoke hook (`/etc/apt/apt.conf.d/99workspace-guard`) that detects when the `git` package is installed, upgraded, or removed, and emits a warning directing the user to re-run `make install-guard`. The hook shall NOT reinstall the guard on its own; it only warns.
- **REQ-GGUARD-154**: The installation script shall detect and warn about alternative git installations (`snap`, `flatpak`, `nix`, `/usr/local/bin/git`). The user shall be informed that these provide alternate paths to git that bypass the guard. This is informational only: the guard does not attempt to disable them.

### 15A. Root-Only Mode

- **REQ-GGUARD-155**: When built with `--features root-only`, the guard shall skip the `CAP_DAC_OVERRIDE` capability check and instead verify `geteuid() == 0`.
- **REQ-GGUARD-156**: Root-only mode shall print a notice to stderr on every invocation, documenting that it is a soft barrier. The notice shall NOT reveal the bypass mechanism.
- **REQ-GGUARD-157**: Root-only mode shall apply the same 17-rule policy engine, environment sanitization, and audit logging as capability mode.
- **REQ-GGUARD-158**: Root-only mode shall NOT attempt `setcap`, `chattr +i`, or `dpkg-divert` during installation. The bootstrap script shall detect the absence of `setcap` and fall back to a simple copy + symlink installation.

### 16. Rust Project Structure

- **REQ-GGUARD-170**: The Rust project shall reside at `projects/WORKSPACE-GUARD/` with the following layout:
  ```
  projects/WORKSPACE-GUARD/
  ├── Cargo.toml
  ├── Cargo.lock
  ├── src/
  │   ├── main.rs
  │   ├── block.rs
  │   ├── exec.rs
  │   ├── args.rs
  │   └── log.rs
  └── tests/
      └── integration_test.rs
  ```
- **REQ-GGUARD-171**: The `Cargo.toml` shall specify: `edition = "2021"`, `panic = "abort"`, `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `strip = true`.
- **REQ-GGUARD-172**: The allowed dependencies are `libc = "0.2"` (required) and `caps = "0.5"` (optional, only for capability mode). No other crates shall be used.
- **REQ-GGUARD-173**: The `Cargo.toml` shall define the following feature flags:
  - `capability-mode` (default): enables `caps` dependency, cap checks
  - `root-only`: skips cap checks, verifies `geteuid() == 0`

---

## Constraints

- **Rust 1.75+** (minimum stable toolchain available on target systems).
- **Dependencies**: `libc` (required), `caps` (optional, capability mode only). No `clap` or argument parsing frameworks: manual `std::env::args_os()` parsing to minimise dependency surface.
- **Statically linked preferred** to avoid shared library injection vectors. If dynamically linked, only link against `libc`, `libgcc_s`, and `libm`.
- **Target**: `x86_64-unknown-linux-musl` (static) or `x86_64-unknown-linux-gnu` (dynamic) or `aarch64-unknown-linux-gnu` depending on availability of musl toolchain and target architecture.
- **No shell, no Python, no interpreter**: the binary is fully self-contained.
- **Binary size target**: under 500KB stripped.
- **Deployment is via `make build-guard` + `make install-guard`**: the `make install` flow shall NOT handle git or the git guard.

## Non-Requirements

- **Contract check logic**: the WORKSPACE-CI contract checks remain in shell (`checks_quality.sh`). The guard only invokes them; it does not re-implement them.
- **Pre-commit hook generation**: hook installation is handled by WORKSPACE-CI's `make install-hooks`.
- **Tier/enforcement resolution**: `project_enforcement.yaml` parsing is done by the WORKSPACE-CI shell script, not by the guard binary.
- **Interactive prompts**: the guard never prompts the user. It blocks or allows. User interaction is the responsibility of pre-commit hooks.
- **Network operations**: the guard does not make any network requests. All checks are local.
- **Windows/macOS support**: this binary is Linux-only. SUID has no equivalent on Windows, and macOS has different security semantics.
- **Subcommand aliasing**: the guard does not support git aliases. Aliases are resolved by real git after the guard passes through.
- **Custom block lists**: the destructive command list is hardcoded in the binary, not configurable at runtime. Configuration lives in WORKSPACE-CI's shell-based pre-commit hooks, not in the guard.
