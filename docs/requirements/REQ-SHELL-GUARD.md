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
`<path>.real` (mode 0700 root:root). The guard scans every `-c`
command string (and script file content) against a compiled regex
pattern table, blocks known-destructive and output-suppression
idioms anywhere in the text, sanitises the environment, and only
then `execve()`s the real shell with privileges dropped. A non-root agent cannot read or execute the real shell
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
  the `AT_SECURE` auxiliary-vector entry (read from
  `/proc/self/auxv`). If `AT_SECURE == 0` (no capability context),
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
  script file and scan its content with the same pattern table as
  `-c` strings. If the file is unreadable, the guard shall pass
  through (the real shell will fail identically) and emit a warning
  to   stderr. Script handling is tiered by ownership trust per
  REQ-SHG-211.

- **REQ-SHG-203**: The binary shall reject arguments containing null
  bytes (`\0`) with exit code 2.

- **REQ-SHG-204**: Command strings and script content larger than 1
  MiB shall be rejected with exit code 2 (resource bound).

- **REQ-SHG-205**: Policy matching shall be a **regex pattern
  table** applied to the raw command text (command string or script
  content) as bytes. There is no tokenizer and no AST: each policy
  entry is a `{id, regex, hint}` pattern compiled in from
  `config/shell_guard_policy.yaml`; a match anywhere in the text
  triggers the entry's decision. Patterns shall be matched with a
  byte-oriented regex engine so non-UTF-8 input cannot bypass or
  crash the scan.

- **REQ-SHG-206**: Because there is no tokenizer, **connector
  context shall be encoded in the patterns themselves**. A rule that
  only applies after a pipe spells the pipe in its pattern
  (`\|\s*(tail|head)\b`); a rule that only applies after `||` spells
  it (`\|\|\s*(true|:)\b`). Bare words without the connector
  (`tail file`, `true` after `;`) do not match and stay allowed.

- **REQ-SHG-207**: The scanner shall NOT strip quotes or skip
  comments: a pattern match inside quoted text or a comment blocks
  identically (e.g. `echo "use | tail"` is blocked). These false
  positives are accepted and documented (SPEC-SHELL-GUARD §16);
  root's channel for them is `<path>.real` directly.

- **REQ-SHG-208**: Known evasion classes of raw-text matching:
  quote-splitting (`pki''ll`), variable indirection (`$X` holding a
  blocked command), dynamic `eval`, shall be documented as
  residual risks (SPEC-SHELL-GUARD §16). They are NOT closed at this
  layer.

- **REQ-SHG-209**: Prefix commands (`sudo`, `env`, `nice`, ...)
  shall NOT be unwrapped: word-boundary patterns already match the
  command name anywhere in the text (`sudo pkill` matches
  `\bpkill\b`).

- **REQ-SHG-210**: The pattern table shall be data-driven from
  `config/shell_guard_policy.yaml`, compiled into the binary by
  `build.rs`. Adding or changing a rule is a YAML edit plus rebuild;
  no Rust changes.

- **REQ-SHG-211**: Script files shall be classified into two trust
  tiers before scanning, via `open(O_NOFOLLOW)` + `fstat()`:
  - **Trusted tier**: regular file, owned by UID 0, not group- or
    other-writable, and one of:
    (a) every parent directory component up to the filesystem root
    likewise root-owned and not group/other-writable; or
    (b) **anchored chain** (REQ-SHG-214): every parent component from
    the script up to a boundary directory is root-owned and not
    group/other-writable, and that boundary directory carries
    `FS_IMMUTABLE_FL` (`chattr +i`). The immutable anchor cannot be
    renamed or replaced by an agent-owned ancestor above it, which
    closes the unlink+recreate attack that plain root ownership under
    an agent-owned parent leaves open.
    Policy violations in trusted scripts are blocked with the same
    policy as untrusted scripts. The trusted tier only certifies that
    the agent cannot author or modify the file; it is not an
    execution exemption. Root maintenance that legitimately needs a
    forbidden idiom must invoke `/bin/bash.real` directly.
  - **Untrusted tier**: anything else. The full block policy applies
    to all users including root.
  Invocation context (`-c` vs script vs TTY vs parent process) shall
  NOT be used as a trust signal: the constrained party chooses the
  invocation form, so context-based discrimination is exploitable by
  construction. Ownership provenance is the only trust boundary.

- **REQ-SHG-214**: The anchored-chain trust decision shall read the
  boundary directory's inode flags via the `FS_IOC_GETFLAGS` ioctl,
  not by spawning `lsattr`. A chain whose topmost root-locked
  directory lacks `FS_IMMUTABLE_FL` shall be Untrusted. The QEMU E2E
  shall cover both directions: unanchored root-owned chain under an
  agent-owned parent (blocked) and immutable-anchored chain
  (blocked for policy violations).

- **REQ-SHG-212**: For untrusted-tier scripts, the guard shall close
  the scan-then-exec TOCTOU race by executing the SCANNED bytes, not
  the path: content is written to a sealed `memfd`
  (`F_ADD_SEALS`: `SEAL_SHRINK|SEAL_WRITE|SEAL_GROW|SEAL_SEAL`), the
  fd is inherited across `execve()`, and the real shell is invoked
  with `/proc/self/fd/<n>` as the script operand. The observable
  difference (`$0`/`BASH_SOURCE` name the fd path) is documented
  (SPEC-SHELL-GUARD §9.1). Trusted-tier scripts are exec'd by path
  (their content cannot be swapped by the agent).

- **REQ-SHG-213**: When staging a script per REQ-SHG-212, the guard
  shall publish the script's canonical original path to the child as
  `SHG_SCRIPT_PATH`, inserted into the scrubbed environment AFTER the
  allow-list filter so a caller-supplied value is always dropped and
  only the guard can set it. Scripts that resolve sibling files
  (`dirname "$0"`/`BASH_SOURCE`) should prefer it:
  `_SELF="${BASH_SOURCE[0]:-$0}"; case "$_SELF" in /proc/self/fd/*) _SELF="${SHG_SCRIPT_PATH:-$_SELF}";; esac`.

---

## 4. Block Policy (REQ-SHG-300 series)

  - **REQ-SHG-300**: The following commands shall be unconditionally
  blocked anywhere in the command text (word-boundary pattern match),
  for ALL users including root
  (exit 1). Root's operator channel is invoking `<path>.real`
  directly, which only root can do. Trusted-tier script bodies per
  REQ-SHG-211 are scanned with the same rules; they are NOT exempt.
  `-c` strings and untrusted script bodies are never exempt.
  Interactive shells are pass-through per REQ-SHG-200: typed REPL
  input is unscanned.)
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
  when its operand text contains a job spec (`%`), a `-1` target
  (process-group `-1` = "all processes"), or a negative PID
  (`-1234`): `kill 1234`, `kill -9 1234`, `kill -TERM 1234 1235`
  are allowed; `kill %1`, `kill -9 -1`, `kill -9 -1234` are blocked.
  Implemented as pattern-table entries over the raw text.

- **REQ-SHG-302**: `dd` shall be blocked when its `of=` operand
  matches a device prefix pattern (`/dev/sd*`, `/dev/nvme*`,
  `/dev/mmcblk*`, `/dev/vd*`, `/dev/mapper/*`, `/dev/disk/*`).
  Raw-text matching has no canonicalisation or `S_ISBLK` runtime
  check; symlink indirection for `of=` is a documented residual
  (SPEC-SHELL-GUARD §16).

- **REQ-SHG-303**: Policy evaluation shall happen BEFORE any exec.
  A blocked invocation shall never reach `execve()`.

- **REQ-SHG-304**: Unknown commands, unknown flags, and unrecognised
  grammar shall pass through (deny-list, not allow-list). The shell
  itself remains the authority on syntax errors.

- **REQ-SHG-305**: `eval` with a static (fully literal) argument
  string needs no special handling: the literal appears in the raw
  text and the pattern table matches it (`eval 'pkill x'` matches
  `\bpkill\b`). Dynamic `eval` of expanded variables is a documented
  residual risk (SPEC-SHELL-GUARD §16).

- **REQ-SHG-306**: The block message shall include the blocked
  command, the matched policy rule, a timestamp (ISO 8601), and a
  hint for the correct alternative, written to both stderr and
  `/dev/tty` (if openable) so it survives `> /dev/null 2>&1`.

- **REQ-SHG-307**: Invocation of any shell binary OTHER than the
  guarded pair shall be blocked anywhere in the command text (exit 1),
  for ALL users including root. The blocked set shall include at
  minimum: `zsh`, `dash`, `fish`, `nu`, `ksh`, `ksh93`, `mksh`,
  `csh`, `tcsh`, `ash`, `yash`, `rc`, `elvish`, `xonsh`, `pwsh`,
  `powershell`, and `busybox` with a shell applet (`busybox sh`,
  `busybox ash`). Nested invocations of `bash` and `sh` re-enter the
  guard and are allowed. The set shall be data-driven from the
  `blocked_shells` block of `config/shell_guard_policy.yaml`, matched
  by word-boundary pattern anywhere in the text (REQ-SHG-205).

- **REQ-SHG-308**: Command text containing a pipe (`|` or `|&`)
  followed by a member of the `suppression_pipe_sinks` set (`tail`,
  `head`) shall be blocked (exit 1) for ALL users including root, in
  every scanned context (`-c` strings, untrusted script bodies). The
  connector is encoded in the pattern (REQ-SHG-206), so bare
  `tail`/`head` on file operands (not after a pipe) remain allowed:
  they read files, they do not silence a command. Rationale: piping
  command output through a truncation filter discards the failure
  evidence the operator and the audit trail need; the incident
  driver was `make check-push 2>&1 | tail -15` hiding the one
  failing test. The set shall be data-driven from the
  `suppression_pipe_sinks` block of `config/shell_guard_policy.yaml`.

- **REQ-SHG-309**: Command text containing a redirection (`>`,
  `>>`, `N>`, `N>>`, `&>`, `&>>`) whose target is a member of
  `suppression_redirect_targets` (`/dev/null`) shall be blocked
  (exit 1) for ALL users including root, in every scanned context.
  This covers `> /dev/null`, `>> /dev/null`, `2> /dev/null`,
  `&> /dev/null`, and combined forms such as `>/dev/null 2>&1`.
  Rationale: discarding stdout/stderr is the same audit-trail
  destruction as REQ-SHG-308 by a different spelling. Trusted-tier
  scripts (REQ-SHG-211) are subject to the same block policy; root
  maintenance that legitimately needs suppressed output must invoke
  `/bin/bash.real` directly. The set shall be data-driven from the
  `suppression_redirect_targets` block.

- **REQ-SHG-310**: Command text containing `||`, `|`, or `|&`
  followed by a member of `suppression_null_commands` (`true`, `:`)
  shall be blocked (exit 1) for ALL users including root.
  `cmd || true` masks a failing exit code; `cmd | true` discards
  stdout. Bare `true`/`:` after `;`, `&&`, or at start-of-input
  masks nothing and remains allowed. The set shall be data-driven
  from the `suppression_null_commands` block.

- **REQ-SHG-311**: The block message for REQ-SHG-308/309/310 shall
  name the matched suppression rule and carry a remediation hint
  from the policy entry, e.g.:
  `BLOCKED: bash -c 'make check 2>&1 | tail -5' (output-suppression: pipe to 'tail') (<ts>)`
  `  -> Hint: run without truncation; write long output to a file and read it with offset/limit`

- **REQ-SHG-312**: Every policy pattern shall carry a `scope` field
  (`command` | `script` | `untrusted-script` | `both`, default `both`) selecting the
  invocation contexts the pattern applies to: `-c` command text
  (`command`), script bodies (`script`), or every scanned context
  (`both`). The scope is validated at build time; every pattern
  shall have at least one blocked matrix case in a context its
  scope applies to.

- **REQ-SHG-313**: Invocation of a general-purpose interpreter
  (`python*`, `perl*`, `ruby`, `irb`, `node`, `nodejs`, `deno`,
  `bun`, `php*`, `lua*`, `luajit`, `tclsh`, `wish`, `expect`,
  `Rscript`, `raku`, `julia`, and the `awk` family `awk`/`gawk`/
  `mawk`/`nawk`) in `-c` command text shall be blocked
  (exit 1) for ALL users including root: an interpreter hands the
  caller a full, unscanned command channel and voids every other
  rule. The rule applies to command text and untrusted script bodies.
  Trusted-tier status does not authorize inline code; trusted maintenance
  code must use approved isolated files or a compiled implementation.
  The match shall be **command-position only**: an interpreter name
  blocks at the start of the command text or directly after a command
  separator (`\n`, `;`, `|`, `&`, `&&`, `||`, `$(`, backtick) or a
  launcher word (`sudo`, `doas`, `env`, `exec`, `nice`, `nohup`,
  `setsid`, `stdbuf`, `timeout`, `xargs`, each with optional flags
  and `VAR=value` assignments). Names appearing as path components
  (`.venv/lib/python3.11/...`) or as arguments to other commands
  (`grep name pyproject.toml`, `command -v python3`) shall NOT match.
  `uv run python path/to/script.py` may match only as an approved isolated
  script invocation. `uv run python -c`, `uv run python -`, heredoc/stdin
  payloads, `exec`, `eval`, and equivalent inline forms shall be blocked.
  `uv` is the only sanctioned Python launcher; it does not authorize inline
  code. The same rule applies to every general-purpose interpreter.

 - **REQ-SHG-314**: Inline code shall not be used in any guarded execution
   context. This includes interpreter `-c`/`-e`/stdin forms, heredocs carrying
   program text, nested `bash -c`/`sh -c` payloads, `eval`, dynamic `source`,
   command substitution used as a code channel, and process substitution used
   to deliver executable text. Technology mixing shall use a checked-in,
   extension-qualified isolated script invoked through its sanctioned launcher.

 - **REQ-SHG-315**: Every direct subprocess launched by guard-owned Rust code
   shall have an absolute executable path, an explicit argument contract, a
   sanitized environment, a bounded timeout where applicable, and a policy
   classification. Avoidable helpers such as external date formatting shall
   be implemented in Rust instead of invoking a bare system command.

 - **REQ-SHG-316**: Tool-mediated writes and direct process launches that do
   not enter guarded Bash are outside the shell scanner and shall be governed
   by a separate execution-broker/file-write policy.

---

## 5. Environment Sanitisation (REQ-SHG-400 series)

- **REQ-SHG-400**: Before `execve()`, the guard shall construct the
  child environment from an allow-list (build from scratch, not
  remove-list), preserving only: `HOME`, `USER`, `LOGNAME`, `LANG`,
  `LC_*`, `TERM`, `COLORTERM`, `DISPLAY`, `WAYLAND_DISPLAY`,
  `SSH_AUTH_SOCK`, `GPG_TTY`, `PWD`, `OLDPWD`, `SHLVL`, `SHELL`,
  `TMPDIR` (validated: absolute, user-writable), `XDG_*`, `TZ`,
  `OPENCODE_*` (agent detection markers are inert for the guard but
  required by the agent), `WORKSPACE_*`, and `AMI_*` (workspace
  shell-environment contract vars, e.g. `AMI_QUIET_MODE`; stripping
  them re-triggers per-command banner/toolchain probes in every
  guarded shell).

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
  (unreadable script source, REQ-SHG-202) go to stderr only.

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

- **REQ-SHG-601**: Install shall relocate the real shell: copy the
  resolved bash path to `/bin/bash.real`, `chown root:root`,
  `chmod 0700`, verify the copy is a valid ELF, and seal it with
  `chattr +i`. On reconcile, an already-immutable `.real` proves
  ownership and mode; the chown/chmod step is skipped (it would
  fail EPERM). The guard binary is installed at the resolved bash
  path with `cap_dac_override=ep`.

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

- **REQ-SHG-605**: Post-install verification is split between the
  installer and the real-Linux guest e2e. The installer shall confirm:
  correct modes/owners/caps, divert registered, apt hook present,
  guard hash matches the release build, root `-c` exits 3
  (fail-closed), and non-root benign `-c` exits 0. The QEMU guest
  guest e2e shall additionally
  confirm: `bash -c 'pkill x'` blocked with exit 1 as non-root;
  `bash -c 'ls | tail'` and `bash -c 'ls 2>/dev/null'` blocked with
  exit 1 as non-root and fail-closed exit 3 as root; a trusted-tier
  fixture script (root-owned, mode 0755, under a root-owned
  directory) containing `2>/dev/null` is blocked; `bash --version`
  works; interactive/login `bash -l` works.

- **REQ-SHG-606**: Because `/bin/sh` and `/bin/bash` are on the
  critical path of every boot script and cron job, install shall
  sanity-probe the guard as a non-root probe user (benign `-c` exit
  0, `--version` exit 0, concat-built destructive probe exit 1) and
  shall confirm root probes exit 3, before and after committing the
  divert, and shall refuse to proceed (roll back) otherwise. The
  The guest e2e shall additionally prove a dpkg-style root-owned
  script exercising `2>/dev/null` keeps working via the trusted
  tier, so package operations keep functioning.

---

## 8. Security Hardening and Performance (REQ-SHG-700 series)

- **REQ-SHG-700**: The binary shall be compiled with
  `panic = "abort"`, full RELRO, stack protector, and `strip`. Binary
  size target: under 500KB stripped. Guard logic on the pass-through
  path shall complete in under 5ms.

- **REQ-SHG-701**: Dependencies shall be limited to `std`, `libc`,
  `nix` (safe wrappers), `rustix` (safe `memfd_create` with
  `MFD_EXEC`, which nix 0.29 does not expose), and the `regex`
  crate (already a workspace dependency; used with
  `regex::bytes::Regex` for byte-exact matching). No `clap`.
  `shell_guard.rs` shall contain no `unsafe` blocks: `AT_SECURE`
  from `/proc/self/auxv`, metadata via `std::fs::symlink_metadata`,
  memfd via `rustix`.

- **REQ-SHG-702**: The guard shall NOT spawn any subprocess for
  parsing or decision logic. The only process transition is the final
  `execve()`.

- **REQ-SHG-703**: Non-UTF-8 bytes in the command string shall not
  cause a pass-through bypass: patterns are matched against raw
  bytes (`regex::bytes::Regex`), never against a UTF-8-validated
  string.

---

## 9. Testing (REQ-SHG-800 series)

- **REQ-SHG-800**: A bats suite `tests/shell/21-shell-guard.bats`
  shall cover: `--help`/usage errors, null-byte rejection, oversize
  rejection, each unconditional block family (REQ-SHG-300), the
  `kill` matrix (allowed and blocked forms), `dd of=` device-prefix
  detection, prefixed forms (`sudo pkill`, `env pkill`), path-qualified
  names (`/sbin/shutdown`), command substitution (`$(pkill x)`: the
  literal text matches), the blocked-shells set (REQ-SHG-307)
  including path-qualified (`/usr/bin/zsh`) and prefix-wrapped
  (`env fish`, `busybox sh`) forms, the suppression families
  (REQ-SHG-308 pipe sinks incl. `| tail -n N` and `2>&1 | tail`,
  REQ-SHG-309 redirect targets incl. `2> /dev/null`, `&> /dev/null`,
  `>/dev/null 2>&1`; REQ-SHG-310 `|| true` / `| true` / `|| :` with
  allowed bare-`true` controls), the documented false positive
  (`echo "use | tail"` blocks), trusted-tier exemption-with-audit
  for root-owned scripts, the script-swap TOCTOU fixture (blocked
  idiom introduced between write and exec is still blocked via the
  sealed memfd), and pass-through of benign commands.

- **REQ-SHG-801**: The build-time policy matrix
  (`config/shell_guard_policy_matrix.yaml`) shall assert every case in the
  matrix agrees with the compiled policy; a disagreement fails the
  build.

- **REQ-SHG-802**: Rust unit tests shall cover the pattern table as
  pure functions (input bytes → first matching rule, if any)
  including adversarial inputs: patterns inside quotes (match:
  documented false positive), non-UTF-8 bytes, pipe-sink patterns
  with options (`| tail -n 5`), spaced redirections (`2> /dev/null`),
  quoted targets (`2>"/dev/null"`: matches, quotes are not
  stripped), and connector-less controls (`tail file`, `true` after
  `;`) that must NOT match.

- **REQ-SHG-803**: Env-sanitisation tests shall assert `BASH_ENV`,
  exported functions, and `LD_*` do not survive into the child
  environment, and `PATH` is the reset value.

- **REQ-SHG-804**: Config consistency tests in
  `src/config_consistency_tests.rs` shall verify
  `config/shell_guard_policy.yaml` parses, every pattern compiles as
  a valid bytes-regex, every entry carries a non-empty hint, and
  every matrix case references a known rule id.

- **REQ-SHG-805**: An authoritative end-to-end suite shall run inside a
  bare real-Linux guest as real root and cover: the full runtime block matrix
  through a capability-context guard, the install lifecycle
  (NOT INSTALLED -> install -> OK, idempotent reconcile), live-fire
  blocks through the installed `/bin/bash` as root and as a
  non-root user (with per-user audit), survivability (dpkg divert,
  apt hook, login shells), drift repair (missing hook, stale
  binary), and uninstall with byte-identical stock restore.
  Rootless container runtimes cannot establish AT_SECURE (file
  capabilities are stored as `user.overlay` xattrs the kernel
  ignores), so the capability-context battery is authoritative in
  the QEMU guest only.

- **REQ-SHG-806**: The QEMU suite shall verify the fail-closed
  property and its recovery runbook: stripping the guard's file
  capability makes every new shell exit 3, and recovery is staged
  root-owned execution of the installer under the sealed
  `/bin/bash.real` (0700, root-only), after which
  `shell-guard-check` reports OK.

- **REQ-SHG-807**: The diverted package copy at `<resolved-bash>.distrib`
  shall be root-owned with mode `0700`. It is recovery state only and shall
  never be used by tests, hooks, or user-facing tooling as an executable shell.
  `shell-guard-check` shall report drift when this mode or ownership is wrong.

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

- **REQ-SHG-NG-05**: The guard does NOT re-implement shell parsing.
  Raw-text pattern matching has no grammar awareness: anything the
  patterns do not match fails open to the real shell (REQ-SHG-304),
  and the evasion classes of REQ-SHG-208 are accepted residuals.

- **REQ-SHG-NG-06**: Agent-side config (opencode `permission` rules,
  plugins) is out of scope: it is a complementary, user-space layer
  that this binary neither depends on nor manages.

- **REQ-SHG-NG-07**: Suppression performed INSIDE an interpreter
  (`python3 -c 'subprocess.run(..., stdout=subprocess.DEVNULL)'`,
  redirecting to a log file that is never read) is not detectable by
  a shell-layer text scan and is out of scope, per the same
  interpreter-indirection boundary as REQ-SHG-NG-02. Suppression
  spelled with shell grammar (pipes to `tail`/`head`, `/dev/null`
  redirects, `|| true`) IS in scope (REQ-SHG-308/309/310).
