# Requirements: Shell Guard (bash/sh Command Wrapper)

**Date:** 2026-07-27
**Status:** DRAFT
**Type:** Requirements
**Related Specs:** [SPEC-SHELL-GUARD](../specifications/SPEC-SHELL-GUARD.md)
**Related:** [REQ-GIT-GUARD](REQ-GIT-GUARD.md), [REQ-HOME-LOCK](REQ-HOME-LOCK.md)

---

## Background

The git guard ([REQ-GIT-GUARD](REQ-GIT-GUARD.md)) intercepts destructive
git operations, and the binary lock ([SPEC-BINARY-LOCK](../specifications/SPEC-BINARY-LOCK.md))
contains SUID/cap binaries. Neither layer controls what an AI agent
does through its most powerful tool: the shell itself. The agent's
shell tool runs `<shell> -c <command>` as a non-interactive,
non-login process (opencode resolves the shell from its `shell`
config key, then `$SHELL`, then `bash`/`sh` on Linux). A single
command string can kill the agent supervisor (`pkill`), power off the
host (`shutdown`, `systemctl poweroff`), destroy filesystems
(`mkfs.ext4`, `dd of=/dev/sda`, `wipefs`), or strip the immutability
that protects the guard stack (`chattr -i`).

Config-level mitigations exist in the agent (permission deny
patterns, `tool.execute.before` plugin hooks) but they live in
user-writable config and are trivially bypassed by editing
`opencode.json` or invoking a different client. The shell guard
closes the vector at the binary layer: a compiled Rust binary
installed as a **root-owned replacement at `/bin/bash`** (and
`/bin/sh` where it resolves to bash), with the real shell sealed as
`<path>.real` (mode 0700 root:root). The guard tokenizes every `-c`
command string (and script file content) in compiled code, blocks
known-destructive commands at every command position, sanitises the
environment, and only then `execve()`s the real shell with privileges
dropped. A non-root agent cannot read or execute the real shell
directly, and cannot bypass the guard by reading its source: it is a
compiled binary, not a script.

The installation/deployment procedure is specified in
[SPEC-SHELL-GUARD](../specifications/SPEC-SHELL-GUARD.md) §12 and is
handled by `make install-shell-guard`.

---

## 1. Scope (REQ-SHG-001 series)

- **REQ-SHG-001**: The program shall provide a Rust binary,
  `workspace-shell-guard`, installed as a root-owned replacement at
  `/bin/bash` with the real bash relocated to `/bin/bash.real`
  (owner root:root, mode 0700).

- **REQ-SHG-002**: Where `/bin/sh` is a symlink to bash (or is the
  bash binary), the guard shall also be installed at `/bin/sh`. The
  guard shall select its effective shell personality from
  `basename(argv[0])` (`bash`/`sh`, leading `-` stripped) and shall
  `execve()` the real shell with the original `argv[0]` preserved so
  POSIX-mode and login-shell behaviour are unchanged.

- **REQ-SHG-003**: The guard shall be INSTALLED only at `/bin/bash`
  and `/bin/sh`-resolving-to-bash; it does not replace any other
  shell binary. However, invocation of any OTHER shell from within a
  guarded shell shall be blocked (REQ-SHG-307), so the guarded pair
  cannot be used as a springboard to an unguarded interpreter.

- **REQ-SHG-004**: The block policy shall be data-driven from
  `config/shell_guard_policy.yaml`, compiled into the binary at build
  time via `build.rs`. No policy file is read at runtime.

- **REQ-SHG-005**: A case matrix in `config/shell_guard_policy_matrix.yaml`
  (argv/command-string → `blocked`|`allowed`) shall be validated at
  build time against the compiled policy, mirroring the git guard's
  `git_guard_policy_matrix.yaml` mechanism.

- **REQ-SHG-006**: The guard shall NOT modify, intercept, or replace
  the opencode (or any other agent) configuration. It defends at the
  shell binary layer only. Agent-side permission rules remain an
  independent, complementary layer.

---

## 2. Privileged Execution and Real-Shell Verification (REQ-SHG-100 series)

- **REQ-SHG-100**: The binary shall be installed at `/bin/bash` (and
  `/bin/sh` per REQ-SHG-002) with owner root:root and mode 0755, with
  file capability `cap_dac_override=ep`. It shall NOT be installed
  SUID-root: an `execve()` of the real shell from a SUID-root guard
  would preserve euid 0 and hand every caller a root shell.

- **REQ-SHG-101**: The real shell shall reside at `<path>.real` with
  owner root:root and mode 0700, sealed with `chattr +i` (matching
  the binary lock's `.real` sealing).

- **REQ-SHG-102**: The binary shall detect privileged execution via
  `getauxval(AT_SECURE)`. If `AT_SECURE == 0` (no capability context),
  the binary shall refuse to operate and exit with code 3.

- **REQ-SHG-103**: Before `execve()`, the binary shall verify that
  `<path>.real` exists, is a regular file, is owned by UID 0, and has
  mode exactly 0700. On failure: exit 3 (fail-closed).

- **REQ-SHG-104**: The binary shall call `execve()` with an absolute
  path to `<path>.real`: never `execvp()` or PATH-based lookup.

- **REQ-SHG-105**: The binary shall NOT use `system()`, `popen()`,
  `Command::new("sh")`, or any shell invocation at any point. All
  work is done in-process; the only exec is the final `execve()` of
  the verified real shell.

- **REQ-SHG-106**: Because the guard carries file capabilities and
  not SUID, `execve()` of the non-capability real shell shall drop
  all capabilities automatically. The guard shall NOT call
  `setuid()`/`setgid()` and shall NOT retain any permitted set across
  the exec.

---

## 3. Invocation Parsing (REQ-SHG-200 series)

- **REQ-SHG-200**: The binary shall classify each invocation into one
  of three forms: (a) `-c <string>` command-string execution,
  (b) script-file execution (`bash <file> [args...]`), (c)
  interactive/login shell (no command operand). Form (c) shall pass
  through to the real shell unchanged.

- **REQ-SHG-201**: Argument parsing shall handle combined short flags
  (`bash -xc 'cmd'`), `--` end-of-options, and the
  `bash -c cmd name args...` operand form. The `-c` string operand is
  the argument immediately following the flag bundle containing `c`.

- **REQ-SHG-202**: For form (b), the guard shall open and read the
  script file and tokenize its content with the same engine as `-c`
  strings. If the file is unreadable, the guard shall pass through
  (the real shell will fail identically) and emit a warning to
  stderr.

- **REQ-SHG-203**: The binary shall reject arguments containing null
  bytes (`\0`) with exit code 2.

- **REQ-SHG-204**: Command strings and script content larger than 1
  MiB shall be rejected with exit code 2 (resource bound).

- **REQ-SHG-205**: The tokenizer shall identify **command positions**
  per the shell grammar: after `;`, `&&`, `||`, `|`, `|&`, newline,
  `(`, `{`, `case`-arm `;;`, and the keywords `then`, `else`,
  `elif`, `do`. Function definitions shall be tokenized so their
  bodies are scanned as ordinary command positions.

- **REQ-SHG-206**: The tokenizer shall recurse into command
  substitutions `$( ... )` and backquotes `` ` ... ` `` and apply the
  same command-position rules to the inner text.

- **REQ-SHG-207**: The tokenizer shall strip single quotes, double
  quotes (preserving `$()`/backquote detection inside them), and
  backslash escapes when computing the effective first word of each
  command. Here-document bodies shall be skipped as data. Comments
  shall be skipped.

- **REQ-SHG-208**: The first word of each command position shall be
  reduced to its basename before policy matching:
  `/sbin/shutdown` matches the `shutdown` policy entry.

- **REQ-SHG-209**: The following transparent prefix commands shall be
  unwrapped (with their own options skipped) until the real command
  word is reached: `command`, `exec`, `env`, `nohup`, `time`,
  `timeout`, `nice`, `ionice`, `stdbuf`, `sudo`, `doas`, `xargs`.
  `xargs` shall always match against a denied-command result (the
  piped-in argv is unknowable) when the unwrapped command is blocked.

---

## 4. Block Policy (REQ-SHG-300 series)

- **REQ-SHG-300**: The following commands shall be unconditionally
  blocked at any command position, for ALL users including root
  (exit 1). Root's operator channel is invoking `<path>.real`
  directly, which only root can do:
  - Process signalling by name: `pkill`, `killall`, `skill`, `snice`
  - Power/session control: `shutdown`, `reboot`, `poweroff`, `halt`,
    `kexec`, `init`, `telinit`, `runlevel` (write forms), `loginctl`
    power actions (`poweroff`, `reboot`, `halt`, `suspend`,
    `hibernate`, `hybrid-sleep`, `soft-reboot`)
  - `systemctl` with a power/session verb (`poweroff`, `reboot`,
    `halt`, `kexec`, `soft-reboot`, `suspend`, `hibernate`,
    `hybrid-sleep`) or `systemctl kill`
  - Filesystem destruction: `mkfs`, `mkfs.*`, `fdisk`, `sfdisk`,
    `cfdisk`, `parted`, `wipefs`, `blockdev --rereadpt`-class
    partition-table rewrites, `swapoff -a`
  - `chattr` with `-i` (immutability strip)
  - `rm` with `--no-preserve-root`
  - `umount`/`mount` targeting a guard-protected path
    (`/usr/lib/workspace-guard`, any `<path>.real` mountpoint)

- **REQ-SHG-301**: `kill` (binary AND shell builtin) shall be blocked
  unless every signal target operand is a numeric PID or numeric
  `%`-free jobless form: `kill 1234`, `kill -9 1234`,
  `kill -TERM 1234 1235` are allowed; `kill %1`, `kill -9 -1`
  (process-group `-1` = "all processes"), and name-based forms are
  blocked. Negative PID `-1` shall always be blocked.

- **REQ-SHG-302**: `dd` shall be blocked when its `of=` operand
  resolves (after canonicalisation) to a block device
  (`lstat`/`stat` `S_ISBLK`) or matches a device prefix
  (`/dev/sd*`, `/dev/nvme*`, `/dev/mmcblk*`, `/dev/vd*`,
  `/dev/mapper/*`, `/dev/disk/*`).

- **REQ-SHG-303**: Policy evaluation shall happen BEFORE any exec.
  A blocked invocation shall never reach `execve()`.

- **REQ-SHG-304**: Unknown commands, unknown flags, and unrecognised
  grammar shall pass through (deny-list, not allow-list). The shell
  itself remains the authority on syntax errors.

- **REQ-SHG-305**: `eval` with a static (fully literal) argument
  string shall have that string tokenized recursively and subjected
  to the same policy. Dynamic `eval` of expanded variables is a
  documented residual risk (SPEC-SHELL-GUARD §16).

- **REQ-SHG-306**: The block message shall include the blocked
  command, the matched policy rule, a timestamp (ISO 8601), and a
  hint for the correct alternative, written to both stderr and
  `/dev/tty` (if openable) so it survives `> /dev/null 2>&1`.

- **REQ-SHG-307**: Invocation of any shell binary OTHER than the
  guarded pair shall be blocked at any command position (exit 1),
  for ALL users including root. The blocked set shall include at
  minimum: `zsh`, `dash`, `fish`, `nu`, `ksh`, `ksh93`, `mksh`,
  `csh`, `tcsh`, `ash`, `yash`, `rc`, `elvish`, `xonsh`, `pwsh`,
  `powershell`, and `busybox` with a shell applet (`busybox sh`,
  `busybox ash`). Nested invocations of `bash` and `sh` re-enter the
  guard and are allowed. The set shall be data-driven from the
  `blocked_shells` block of `config/shell_guard_policy.yaml`, matched
  by basename after prefix unwrapping (REQ-SHG-208/REQ-SHG-209).

---

## 5. Environment Sanitisation (REQ-SHG-400 series)

- **REQ-SHG-400**: Before `execve()`, the guard shall construct the
  child environment from an allow-list (build from scratch, not
  remove-list), preserving only: `HOME`, `USER`, `LOGNAME`, `LANG`,
  `LC_*`, `TERM`, `COLORTERM`, `DISPLAY`, `WAYLAND_DISPLAY`,
  `SSH_AUTH_SOCK`, `GPG_TTY`, `PWD`, `OLDPWD`, `SHLVL`, `SHELL`,
  `TMPDIR` (validated: absolute, user-writable), `XDG_*`, `TZ`,
  `OPENCODE_*` (agent detection markers are inert for the guard but
  required by the agent), and `WORKSPACE_*`.

- **REQ-SHG-401**: The following shall be dropped unconditionally:
  `BASH_ENV`, `ENV` (non-interactive rc injection), `SHELLOPTS`,
  `BASHOPTS`, `PROMPT_COMMAND`, `PS4` (xtrace `$( )` injection),
  `IFS`, `CDPATH`, `GLOBIGNORE`, `FIGNORE`, `HOSTFILE`, all
  `BASH_FUNC_*%%`/`BASH_FUNC_*()` exported-function variables
  (Shellshock class), and the full dynamic-linker/glibc unsecvars
  list (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`,
  `GCONV_PATH`, `GETCONF_DIR`, `NLSPATH`, `GLIBC_TUNABLES`, etc.) as
  enumerated in SPEC-SHELL-GUARD §8.

- **REQ-SHG-402**: `PATH` shall be reset to a known-safe value
  (`/usr/local/bin:/usr/bin:/bin`) before `execve()`.

- **REQ-SHG-403**: The binary shall use `secure_getenv()` when
  reading its own environment, so a crafted env var cannot influence
  guard logic in the capability context.

- **REQ-SHG-404**: The guard shall set `RLIMIT_CORE` to 0 (no core
  dumps) and `RLIMIT_NOFILE` to a bounded value before `execve()`.

---

## 6. Audit Logging, Exit Codes, Error Output (REQ-SHG-500 series)

- **REQ-SHG-500**: Every blocked invocation shall be appended to
  `${HOME}/.workspace-guard.log` (real user's home, resolved via
  `getpwuid_r(getuid())`) in pipe-delimited form:
  `timestamp|cwd|cmd|reason|uid=<uid>`, matching the git guard log
  format.

- **REQ-SHG-501**: Logged command strings shall be truncated to 200
  bytes and shall have single quotes neutralised, so log parsing
  cannot be confused by crafted content. Potential secret material
  after `=` in assignments shall be redacted.

- **REQ-SHG-502**: If the log file cannot be opened, the block shall
  still be enforced: logging failure shall never bypass blocking.
  The log file shall be opened `O_NOFOLLOW | O_APPEND`.

- **REQ-SHG-503**: The log file shall be opened and written only
  after a block decision is made, never on the pass-through path.

- **REQ-SHG-504**: Exit codes shall be: **0** pass-through (real
  shell exit code via exec), **1** policy block, **2** validation
  error (null bytes, oversize input, malformed argv), **3** not
  privileged or real shell unverifiable.

- **REQ-SHG-505**: The binary shall produce NO output for allowed
  invocations: all output comes from the real shell. Warnings
  (degraded script-scan, REQ-SHG-202) go to stderr only.

---

## 7. Deployment and Installation (REQ-SHG-600 series)

- **REQ-SHG-600**: Installation shall be via `make install-shell-guard`
  (script `scripts/install-shell-guard`), root-only, and shall be wired
  into the canonical operator flow (`scripts/guard-operator.sh`):
  `make guard-up` shall install the shell guard alongside the git
  guard (both guards in one bring-up), `make guard-down` shall remove
  it (before the git guard), `make guard-refresh` shall reconcile it,
  and `make guard-check` shall include its health. Until the shell
  guard scripts exist, the operator flow shall skip it with a NOTICE
  rather than failing. `make uninstall-shell-guard` shall fully
  reverse the install.

- **REQ-SHG-601**: Install shall relocate the real shell: copy
  `/bin/bash` to `/bin/bash.real`, `chown root:root`, `chmod 0700`,
  `chattr +i`, verify the copy by checksum, and only then install the
  guard binary at `/bin/bash` with `cap_dac_override=ep`.

- **REQ-SHG-602**: Install shall register a `dpkg-divert` for
  `/bin/bash` (and `/bin/sh` when covered) redirecting to
  `<path>.distrib`, plus an apt post-invoke hook that warns (never
  auto-reinstalls) when the `bash`/`dash` packages change.

- **REQ-SHG-603**: Install shall be idempotent and reconciling:
  re-running fixes stale guard hash, wrong caps, missing divert,
  missing immutable flag, or relaxed `.real` mode.

- **REQ-SHG-604**: On any failure, install shall roll back to the
  original state (restore `.real` over the guard path, mode 0755)
  and print a clear error. A host shall never be left without a
  working `/bin/bash`.

- **REQ-SHG-605**: Post-install verification shall confirm: correct
  modes/owners/caps; `bash -c 'echo ok'` succeeds for a non-root
  user; `bash -c 'pkill x'` is blocked with exit 1 for a non-root
  user; `bash --version` works; interactive `bash -l` works.

- **REQ-SHG-606**: Because `/bin/sh` and `/bin/bash` are on the
  critical path of every boot script and cron job, install shall
  verify the guard passes a sanity set of POSIX invocations (`sh -c`,
  `bash -c`, `bash script`, here-doc, pipeline, substitution) before
  committing the divert, and shall refuse to proceed (roll back)
  otherwise.

---

## 8. Security Hardening and Performance (REQ-SHG-700 series)

- **REQ-SHG-700**: The binary shall be compiled with
  `panic = "abort"`, full RELRO, stack protector, and `strip`. Binary
  size target: under 500KB stripped. Guard logic on the pass-through
  path shall complete in under 5ms.

- **REQ-SHG-701**: Dependencies shall be limited to `std`, `libc`
  (irreducible FFI only), and `nix` (safe wrappers). No `clap`, no
  regex engine: tokenization and matching are hand-rolled to keep the
  dependency surface minimal. `unsafe` is limited to documented
  `// SAFETY:` FFI sites (`getauxval`, `lstat` on `.real`).

- **REQ-SHG-702**: The guard shall NOT spawn any subprocess for
  parsing or decision logic. The only process transition is the final
  `execve()`.

- **REQ-SHG-703**: Non-UTF-8 bytes in the command string shall not
  cause a pass-through bypass: tokenization operates on bytes, and
  policy matching is byte-exact on the reduced command word.

---

## 9. Testing (REQ-SHG-800 series)

- **REQ-SHG-800**: A bats suite `tests/shell/21-shell-guard.bats`
  shall cover: `--help`/usage errors, null-byte rejection, oversize
  rejection, each unconditional block family (REQ-SHG-300), the
  `kill` numeric-PID matrix (allowed and blocked forms), `dd of=`
  device detection, prefix-command unwrapping (`sudo pkill`,
  `env pkill`, `xargs pkill`), basename reduction (`/sbin/shutdown`),
  command substitution recursion (`$(pkill x)`), function-body
  scanning, quote stripping, here-doc skipping, the blocked-shells
  set (REQ-SHG-307) including path-qualified (`/usr/bin/zsh`) and
  prefix-wrapped (`env fish`, `busybox sh`) forms, and pass-through
  of benign commands.

- **REQ-SHG-801**: The build-time policy matrix
  (`config/shell_guard_policy_matrix.yaml`) shall assert every case in the
  matrix agrees with the compiled policy; a disagreement fails the
  build.

- **REQ-SHG-802**: Rust unit tests shall cover the tokenizer as a
  pure function (input bytes → command-position words) including
  adversarial inputs: nested substitutions, mixed quoting, escaped
  newlines, `case` arms, and prefix chains.

- **REQ-SHG-803**: Env-sanitisation tests shall assert `BASH_ENV`,
  exported functions, and `LD_*` do not survive into the child
  environment, and `PATH` is the reset value.

- **REQ-SHG-804**: Config consistency tests in
  `src/config_consistency_tests.rs` shall verify
  `config/shell_guard_policy.yaml` parses, every blocked entry is a
  bare command name (no path separator), and device prefixes are
  absolute.

---

## 10. Non-Goals

- **REQ-SHG-NG-01**: The shell guard is NOT a sandbox. It does not
  restrict filesystem access, network, or resource consumption of
  allowed commands. Sandbox layers are specified in
  [REQ-SANDBOX](REQ-SANDBOX.md).

- **REQ-SHG-NG-02**: The guard does NOT attempt to block destruction
  performed through interpreters (`python3 -c 'os.kill(...)'`,
  `perl -e ...`). That surface is bounded by the binary lock and
  auditd layers, and documented as a residual risk.

- **REQ-SHG-NG-03**: The guard does NOT WRAP shells other than bash
  and sh-resolving-to-bash, but it DOES block their invocation from
  within a guarded shell (REQ-SHG-307). A shell binary renamed or
  copied to an unlisted name (e.g. a user-compiled zsh at
  `~/bin/mysh`) defeats basename matching; closing that residual is
  an operator decision (remove or binary-lock alternative shells),
  not enforced here.

- **REQ-SHG-NG-04**: The guard never prompts. It blocks or allows.
  Interactive approval flows belong to the agent's permission layer.

- **REQ-SHG-NG-05**: The guard does NOT re-implement shell parsing in
  full POSIX completeness. The tokenizer covers the grammar needed to
  find command positions reliably; anything unrecognised fails open
  to the real shell (REQ-SHG-304), with recursion into substitutions
  ensuring the common obfuscations are still scanned.

- **REQ-SHG-NG-06**: Agent-side config (opencode `permission` rules,
  plugins) is out of scope: it is a complementary, user-space layer
  that this binary neither depends on nor manages.
