# Specification: Shell Guard (bash/sh Command Wrapper)

**Date:** 2026-07-27
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-SHELL-GUARD](../requirements/REQ-SHELL-GUARD.md)
**Related:** [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md), [SPEC-BINARY-LOCK](SPEC-BINARY-LOCK.md), [SPEC-AUDIT](SPEC-AUDIT.md)

---

## 1. Architecture Overview

```
Agent / user invokes: bash -c '<command string>'     (or: bash script.sh, sh -c ...)
                              │
                              ▼
              /bin/bash  (workspace-shell-guard, root:root 0755,
                          cap_dac_override=ep)
                              │
        ┌─────────────────────┼──────────────────────────┐
        │                     │                          │
        ▼                     ▼                          ▼
  Classify argv         Tokenize command           Sanitise env
  (-c / script /        string (or script          (allow-list,
   interactive)          file) into command         PATH reset,
                         positions, recurse         drop BASH_ENV,
                         into $( ) / ` `            LD_*, funcs)
        │                     │                          │
        └─────────────────────┼──────────────────────────┘
                              │
                        Any blocked command
                        at any command position?
                            ┌──┴──┐
                          YES     NO
                           │       │
                           ▼       ▼
                    Block + log  execve("/bin/bash.real",
                    (exit 1)     original argv, clean envp)
                                 real shell: root:root 0700, +i
```

The guard is a **thin capability-enabled wrapper**. Its sole purpose
is to:

1. Tokenize the command string (or script content) into command
   positions.
2. Match every command-position word against the compiled deny
   policy.
3. Sanitise the execution environment.
4. If safe, `execve()` the verified real shell with the original
   argv.
5. If unsafe, block with an audit log entry (exit 1).

It does NOT re-implement the shell. It does NOT sandbox allowed
commands. It does NOT read any config file at runtime: policy is
compiled in from `config/shell_guard_policy.yaml` via `build.rs`.

### Key Design Principle

> **Deny-list on command positions, not allow-list.** The shell's
> legitimate surface is unbounded; the catastrophic surface (kill the
> supervisor, power off the host, destroy filesystems, strip
> immutability) is small and enumerable. The guard blocks the
> catastrophic set at every command position and passes everything
> else through.

---

## 2. Threat Model

The threat, in order of severity:

1. A non-root AI agent (uid 1000, no capabilities) receives a shell
   tool whose implementation runs `<shell> -c <command>` as a
   non-interactive, non-login process. The agent emits a
   command string containing `pkill -f opencode`, `kill -9 -1`,
   `shutdown now`, `systemctl poweroff`, `mkfs.ext4 /dev/sda1`,
   `dd if=/dev/zero of=/dev/sda`, `wipefs -a /dev/sda`,
   `chattr -i /usr/bin/git.original`, or `umount` of a guard
   mountpoint.
2. The command executes with the agent's full user privileges,
   killing the supervisor, severing the session, or destroying
   guard-protected state that other layers (binary lock, home lock)
   depend on.
3. Agent-side mitigations (`permission.bash` deny patterns,
   `tool.execute.before` plugin hooks) live in user-writable config
   (`opencode.json`, `.opencode/plugins/`), so the same agent can
   edit them away. They are a complementary layer, not a control.

**Mitigation**: `/bin/bash` is a compiled root-owned guard. The real
shell at `/bin/bash.real` is mode 0700 root:root: a non-root agent
cannot read or execute it directly, cannot `LD_PRELOAD` around the
guard (§8), and cannot learn a bypass by reading guard source. The
guard tokenizes the command string before any exec and blocks the
catastrophic set unconditionally. Root's operator channel is invoking
`/bin/bash.real` directly.

---

## 3. Privileged Execution

### 3.1 Capability Model (not SUID)

The guard is installed with file capability `cap_dac_override=ep`,
mode 0755 root:root. It must NOT be SUID-root: on `execve()` of the
non-SUID real shell, a SUID-root guard would preserve euid 0 and
hand every caller a root shell. With file capabilities:

- euid stays the invoking user throughout.
- `cap_dac_override` lets the guard `execve()` the 0700-root real
  shell and read script files for scanning.
- On `execve()` of the real shell (which has no file caps), the
  kernel clears the permitted/effective sets automatically. No
  `setuid()`/`setgid()`/`prctl()` calls are needed or permitted.

### 3.2 Privileged Execution Detection

The guard detects its capability context via
`libc::getauxval(libc::AT_SECURE)` (same mechanism as the git guard,
SPEC-GIT-GUARD §2.2). If `AT_SECURE == 0`, the guard refuses to
operate (exit 3): an attacker-compiled copy of the guard without the
file capability cannot read `bash.real` and fails closed.

### 3.3 Real Shell Verification

Before `execve()`, the guard verifies `<path>.real`:

1. `lstat()`: must exist and be a regular file (`S_IFREG`), not a
   symlink.
2. Owner UID must be 0.
3. Mode bits must be exactly `0700`.

Any failure: exit 3. This prevents replacement of the real shell
with a malicious binary or a permission relaxation.

---

## 4. Invocation Forms and Argument Parsing

The guard classifies argv (after its own argv[0]) into three forms:

| Form | Shape | Handling |
|------|-------|----------|
| Command string | `bash -c STR [name [args...]]`, `bash -xc STR`, `bash -- -c STR` | Tokenize STR (§5) |
| Script file | `bash FILE [args...]`, `bash -- FILE` | Read FILE, tokenize content (§5); unreadable → warn + pass through |
| Interactive/login | `bash`, `bash -l`, `bash -i`, argv[0] `-bash` | Pass through unchanged |

Parsing rules:

- Short flags may be bundled (`-xc STR`): the bundle containing `c`
  consumes the next argv element as the command string. `c` is only
  special as the LAST flag of its bundle (`-cx` means `-c` with the
  NEXT bundle as string, which bash itself rejects: pass through).
- Long flags: `--help` and `--version` pass through (handled by the
  real shell). Any `--` ends option processing.
- Flags that take separate operands (`--init-file`, `--rcfile`) have
  their operand skipped during classification.
- A leading `-` in argv[0] (`-bash`, `-sh`) marks a login shell; it
  is preserved verbatim into the exec'd argv[0].
- Null bytes anywhere in argv: exit 2.
- Command strings or script content over 1 MiB: exit 2.

The sh personality is selected from `basename(argv[0])` with a
leading `-` stripped: `sh` at `/bin/sh` execs `/bin/bash.real` with
argv[0] `sh`, so bash runs in POSIX mode exactly as before.

---

## 5. Command-String Tokenizer

The tokenizer is a hand-rolled byte-level scanner (no regex, no
external crate). It does not build an AST; it finds **command
positions** and, for each, the effective first word.

### 5.1 Command Positions

A command position begins after any of: start of input, `;`, `&&`,
`||`, `|`, `|&`, newline, `(`, `{`, `;;` (case arm), or the keywords
`then`, `else`, `elif`, `do`. A function definition
`name() { ...; }` is tokenized so its body contributes its own
command positions (the definition site itself yields no command
word).

### 5.2 Quoting and Escapes

- `'...'`: literal; contributes text to the current word.
- `"..."`: literal except `$( )`, backquotes, and `\`-escapes, which
  are still recognised (so `"$(pkill x)"` is scanned).
- `\X`: contributes literal `X` to the current word.
- `#` at a word start: comment to end of line; skipped.
- Here-docs: after `<<[-]DELIM`, lines up to `DELIM` are skipped as
  data (no command positions inside).

### 5.3 Command Substitution Recursion

`$( ... )` and `` ` ... ` `` are tokenized recursively with the full
rule set. Nesting depth is bounded at 32; deeper input is treated as
a validation error (exit 2).

### 5.4 First-Word Reduction

For each command position:

1. Skip assignments (`NAME=value`) and redirections (`2>file`).
2. Strip quotes/escapes to compute the effective word.
3. Unwrap transparent prefixes (with their options skipped):
   `command`, `exec`, `env`, `nohup`, `time`, `timeout`, `nice`,
   `ionice`, `stdbuf`, `sudo`, `doas`, `xargs`.
4. Reduce to basename: `/sbin/shutdown` → `shutdown`.
5. If the word contains `=` or `$` after stripping (dynamic), it
   cannot be matched: the position is not blocked (deny-list
   principle; residual risk §16).

---

## 6. Block Decision Engine

Checks are applied to every command position; the first block wins:

```
1. Reduced word in blocked set?            → BLOCK (exit 1)
   (pkill, killall, skill, snice, shutdown, reboot, poweroff,
    halt, kexec, init, telinit, mkfs, mkfs.*, fdisk, sfdisk,
    cfdisk, parted, wipefs)
2. Reduced word in blocked_shells set?     → BLOCK
   (zsh, dash, fish, nu, ksh, ksh93, mksh, csh, tcsh, ash, yash,
    rc, elvish, xonsh, pwsh, powershell; busybox with a shell
    applet: busybox sh / busybox ash)
3. systemctl/loginctl power verb?          → BLOCK
   (poweroff, reboot, halt, kexec, soft-reboot, suspend,
    hibernate, hybrid-sleep; plus systemctl kill)
4. kill with non-numeric or -1 target?     → BLOCK
   (kill %1, kill -9 -1, kill <name>; kill <pid>..., kill -SIG <pid> allowed)
5. chattr with -i flag?                    → BLOCK
6. rm with --no-preserve-root?             → BLOCK
7. dd of= resolving to block device?       → BLOCK
   (canonicalise of= operand; S_ISBLK check; device-prefix list)
8. mount/umount on guard-protected path?   → BLOCK
9. swapoff -a?                             → BLOCK
10. eval with static literal argument?     → recurse tokenizer into it
11. ALL CLEAR → sanitise env, execve real shell
```

Step 2 closes the shell-escape vector: the guarded pair cannot be
used as a springboard to an unguarded interpreter. Nested `bash` /
`sh` invocations are NOT blocked: they resolve to the guard's own
paths and re-enter the guard, so policy is re-applied at every
nesting level. `busybox` is unwrapped one extra level: its first
operand is the applet name, and only shell applets (`sh`, `ash`)
match step 2; other applets pass (the binary lock covers SUID
busybox, SPEC-BINARY-LOCK).

### 6.1 Block Messages

```
BLOCKED: bash -c '<command>' (<rule>) (<ISO-8601-timestamp>)
  → Hint: <alternative>
```

Written to both stderr and `/dev/tty` (if openable), matching the
git guard format (SPEC-GIT-GUARD §4.1). Hints come from the policy
YAML (per-entry `hint:` field), e.g. `pkill` → "use `kill <pid>` on
the specific process instead".

### 6.2 kill Argument Matrix

| Invocation | Decision |
|------------|----------|
| `kill 1234` | allow |
| `kill -9 1234`, `kill -TERM 1234 1235`, `kill -s KILL 1234` | allow |
| `kill -l`, `kill -L` (list signals) | allow |
| `kill %1`, `kill %%` | block (job spec) |
| `kill -9 -1`, `kill -TERM -1` | block (all processes) |
| `kill -9 -1234` (negative pgrp) | block |
| `kill -0 1234` | allow (existence probe) |

Rule: after the signal option (`-SIGNAME`, `-s SIGNAME`, `-n SIGNUM`,
or `-l`/`-L`), every remaining operand must match `^[0-9]+$`.

---

## 7. Policy Config Schema

`config/shell_guard_policy.yaml` (with sibling
`shell_guard_policy.schema.yaml`), compiled in by `build.rs`:

```yaml
version: 1

# Unconditionally blocked command names (bare names; basename match).
blocked_commands:
  - {name: pkill,    hint: "use kill <pid> on the specific process"}
  - {name: killall,  hint: "use kill <pid> on the specific process"}
  - {name: skill,    hint: "use kill <pid> on the specific process"}
  - {name: shutdown, hint: "power actions are an operator operation"}
  - {name: reboot,   hint: "power actions are an operator operation"}
  - {name: poweroff, hint: "power actions are an operator operation"}
  - {name: halt,     hint: "power actions are an operator operation"}
  - {name: kexec,    hint: "power actions are an operator operation"}
  - {name: init,     hint: "power actions are an operator operation"}
  - {name: telinit,  hint: "power actions are an operator operation"}
  - {name: wipefs,   hint: "filesystem destruction is blocked"}
  - {name: fdisk,    hint: "partition-table edits are blocked"}
  - {name: sfdisk,   hint: "partition-table edits are blocked"}
  - {name: cfdisk,   hint: "partition-table edits are blocked"}
  - {name: parted,   hint: "partition-table edits are blocked"}

# Glob-style families (mkfs, mkfs.ext4, mkfs.xfs, ...).
blocked_globs:
  - {pattern: "mkfs.*", hint: "filesystem creation is blocked"}

# Shell escape: invocation of any shell other than the guarded
# bash/sh pair is blocked (REQ-SHG-307). Matched by basename after
# prefix unwrapping. bash and sh are deliberately absent: nested
# invocations re-enter the guard.
blocked_shells:
  - {name: zsh,        hint: "only bash/sh are permitted on this host"}
  - {name: dash,       hint: "only bash/sh are permitted on this host"}
  - {name: fish,       hint: "only bash/sh are permitted on this host"}
  - {name: nu,         hint: "only bash/sh are permitted on this host"}
  - {name: ksh,        hint: "only bash/sh are permitted on this host"}
  - {name: ksh93,      hint: "only bash/sh are permitted on this host"}
  - {name: mksh,       hint: "only bash/sh are permitted on this host"}
  - {name: csh,        hint: "only bash/sh are permitted on this host"}
  - {name: tcsh,       hint: "only bash/sh are permitted on this host"}
  - {name: ash,        hint: "only bash/sh are permitted on this host"}
  - {name: yash,       hint: "only bash/sh are permitted on this host"}
  - {name: rc,         hint: "only bash/sh are permitted on this host"}
  - {name: elvish,     hint: "only bash/sh are permitted on this host"}
  - {name: xonsh,      hint: "only bash/sh are permitted on this host"}
  - {name: pwsh,       hint: "only bash/sh are permitted on this host"}
  - {name: powershell, hint: "only bash/sh are permitted on this host"}

# busybox applets that count as shells for the one-level applet
# unwrap (busybox sh / busybox ash are blocked; other applets pass).
busybox_shell_applets: [sh, ash]

# Power verbs for service/session managers.
power_verbs:
  systemctl: [poweroff, reboot, halt, kexec, soft-reboot, suspend,
              hibernate, hybrid-sleep, kill]
  loginctl:  [poweroff, reboot, halt, suspend, hibernate,
              hybrid-sleep, soft-reboot]

# Flag-gated blocks.
flag_blocks:
  - {command: chattr, flag: "-i", hint: "immutability strip is blocked"}
  - {command: rm, flag: "--no-preserve-root", hint: "root-fs deletion is blocked"}
  - {command: swapoff, flag: "-a", hint: "swap teardown is blocked"}

# dd device prefixes (of= canonicalised then prefix-matched, plus
# S_ISBLK check).
device_prefixes: [/dev/sd, /dev/nvme, /dev/mmcblk, /dev/vd,
                  /dev/mapper/, /dev/disk/]

# mount/umount protected paths.
protected_paths: [/usr/lib/workspace-guard]

# Transparent prefixes unwrapped before matching.
prefix_commands: [command, exec, env, nohup, time, timeout, nice,
                  ionice, stdbuf, sudo, doas, xargs]
```

`config/shell_guard_policy_matrix.yaml` holds the case matrix
(`input` → `blocked`|`allowed`, with expected rule) validated at
build time against the compiled policy, mirroring the git guard's
`git_guard_policy_matrix.yaml` mechanism (`build.rs`
`validate_policy_matrix`).

---

## 8. Environment Sanitisation

### 8.1 Unset List

**Shell injection vectors** (dropped unconditionally):
```
BASH_ENV / ENV       → non-interactive rc file sourcing
SHELLOPTS / BASHOPTS → option injection into every child shell
PROMPT_COMMAND       → command run before every prompt
PS4                  → xtrace prefix, subject to $( ) expansion
IFS / CDPATH / GLOBIGNORE / FIGNORE / HOSTFILE → word-splitting and glob tricks
BASH_FUNC_*%% / BASH_FUNC_*() → exported functions (Shellshock class)
```

**Dynamic linker / glibc unsecvars** (defense-in-depth): the same
list as SPEC-GIT-GUARD §5.1 (`LD_PRELOAD`, `LD_LIBRARY_PATH`,
`LD_AUDIT`, `LD_DEBUG`, `LD_BIND_NOW`, `LD_PROFILE`, `GCONV_PATH`,
`GETCONF_DIR`, `NLSPATH`, `RES_OPTIONS`, `HOSTALIASES`, `LOCPATH`,
`MALLOC_TRACE`, `GLIBC_TUNABLES`, ...).

### 8.2 PATH Reset

PATH is set to `/usr/local/bin:/usr/bin:/bin`.

### 8.3 Preserved Variables

```
HOME USER LOGNAME LANG LC_* TERM COLORTERM
DISPLAY WAYLAND_DISPLAY SSH_AUTH_SOCK GPG_TTY
PWD OLDPWD SHLVL SHELL TZ XDG_*
TMPDIR        → only if absolute and user-writable, else dropped
OPENCODE_*    → agent detection markers; inert for the guard
WORKSPACE_*   → workspace tooling contract vars
```

### 8.4 Implementation

Allow-list construction from scratch (same rationale as
SPEC-GIT-GUARD §5.4): a deny-list of env vars is inherently
incomplete; the allow-list has a closed surface. The guard reads its
own environment via `secure_getenv()` only. Before `execve()` it
sets `RLIMIT_CORE` to 0 and `RLIMIT_NOFILE` to 4096.

---

## 9. Real Shell Exec

```rust
// argv is the ORIGINAL argv (with argv[0] possibly "-bash"/"sh"),
// path is the verified real shell. execve does not return on success.
match nix::unistd::execve(real_path, &argv_c, &envp) {
    Ok(inf) => match inf {},
    Err(errno) => {
        eprintln!("FATAL: execve failed: {}",
                  std::io::Error::from_raw_os_error(errno as i32));
        std::process::exit(3);
    }
}
```

- `real_path` is `/bin/bash.real` for both personalities; the sh
  personality is conveyed by argv[0] (`sh`/`-sh`), which bash
  honours by entering POSIX mode.
- `bash --version`, `bash --help`, interactive, and login forms
  reach the real shell byte-identical argv: observable behaviour is
  unchanged.

---

## 10. Audit Logging

### 10.1 Log Format

```
<ISO-8601-timestamp>|<cwd>|<blocked-command>|<reason>|uid=<real-uid>
```

Example:

```
2026-07-27T14:32:01+00:00|${HOME}/projects/WORKSPACE-GUARD|bash -c 'pkill -f opencode'|blocked command: pkill|uid=1000
```

Command strings are truncated to 200 bytes; single quotes are
replaced with `'` alternates (`'`) so pipe-delimited parsing is not
confusable; text after `=` in `NAME=value` assignments is redacted
to `...` (secret-safe logging, same rule as SPEC-GIT-GUARD §7.3).

### 10.2 Log Location and Timing

`${HOME}/.workspace-guard.log`, where HOME is resolved via
`getpwuid_r(getuid())` (the real user, not root). The file is opened
`O_WRONLY | O_APPEND | O_NOFOLLOW` and only after a block decision
is made. If the open or write fails, the block still stands: logging
failure never bypasses blocking.

---

## 11. Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Allowed; real shell exit code (via exec) |
| 1 | Policy block |
| 2 | Validation error (null bytes, oversize input, nesting depth, malformed argv) |
| 3 | Not privileged (`AT_SECURE == 0`) or real shell unverifiable |

---

## 12. Deployment

### 12.1 Install (`scripts/install-shell-guard`, `make install-shell-guard`)

Root-only. Flow:

1. Build `workspace-shell-guard` (`cargo build --release`) and
   verify the artifact is a valid ELF.
2. Sanity-test the built guard on a scratch copy: `sh -c`, `bash -c`,
   script file, here-doc, pipeline, `$( )`, `bash -l`: all must
   pass; `pkill x` must exit 1. Refuse to proceed otherwise
   (REQ-SHG-606).
3. `dpkg-divert` `/bin/bash` → `/bin/bash.distrib` (and `/bin/sh` →
   `/bin/sh.distrib` when `/bin/sh` resolves to bash).
4. Copy `/bin/bash` to `/bin/bash.real`; `chown root:root`;
   `chmod 0700`; checksum-verify the copy; `chattr +i`.
5. Install the guard at `/bin/bash` (root:root 0755,
   `setcap cap_dac_override=ep`). Copy it over `/bin/sh` when covered.
6. Register the apt post-invoke hook
   (`/etc/apt/apt.conf.d/99workspace-guard-shell`) that warns when
   the `bash` or `dash` package changes. The hook never
   auto-reinstalls.
7. Post-install verification (REQ-SHG-605): modes/owners/caps,
   `bash -c 'echo ok'` as non-root, `bash -c 'pkill x'` blocked
   exit 1 as non-root, `bash --version`, `bash -l`.

Any failure rolls back: `.real` is copied back over the guard path
(mode 0755), the divert is removed, and a clear error is printed. A
host is never left without a working `/bin/bash`.

Install is idempotent and reconciling (REQ-SHG-603): stale guard
hash, wrong caps, missing divert/hook, missing `+i`, or relaxed
`.real` mode are repaired; a fully healthy install is a no-op.

### 12.2 Uninstall (`make uninstall-shell-guard`)

1. `chattr -i /bin/bash.real`.
2. Copy `/bin/bash.real` back to `/bin/bash`, mode 0755 root:root.
3. Remove `/bin/bash.real`, the divert, and the apt hook (restore
   `/bin/sh` the same way when covered).
4. Verify `bash --version` and `sh -c 'echo ok'` succeed.

### 12.3 Makefile Targets and Operator Flow

```makefile
install-shell-guard:      sudo scripts/install-shell-guard (ROOT)
uninstall-shell-guard:    sudo scripts/uninstall-shell-guard (ROOT)
shell-guard-check:        read-only health check (modes, caps, divert, +i, hash)
```

The canonical operator flow (`scripts/guard-operator.sh`, REQ-SHG-600)
wires the shell guard in alongside the git guard:

- `guard-up`: after the git guard is healthy, runs
  `shell-guard-check`; on `NOT INSTALLED`/`DRIFTED`/check failure it
  runs `install-shell-guard`. While the shell guard scripts do not
  exist, the step is skipped with a NOTICE (soft-fail by design: a
  host must never fail bring-up because the shell guard is
  unimplemented).
- `guard-down`: removes the shell guard FIRST (it wraps the shell
  everything else runs under), then the git guard.
- `guard-refresh`: reconciles the shell guard after the git guard
  (install is idempotent/reconciling, REQ-SHG-603).
- `guard-check`: runs both health checks; combined exit status.

---

## 13. Rust Project Structure and build.rs

New binary in `Cargo.toml`:

```toml
[[bin]]
name = "workspace-shell-guard"
path = "src/shell_guard.rs"
```

```
src/shell_guard.rs          # entry, argv classification, exec
src/shell_tokenizer.rs      # byte-level command-position scanner (§5)
src/shell_policy.rs         # decision engine (§6), compiled tables
src/shell_env.rs            # env allow-list construction (§8)
```

`build.rs` parses `config/shell_guard_policy.yaml` into a compiled
`SHELL_POLICY` table and validates `config/shell_guard_policy_matrix.yaml`
against it (build fails on disagreement). Profile and dependency
constraints follow REQ-GIT-GUARD §13/§16 (`panic = "abort"`, full
RELRO, `strip`; `std` + `libc` + `nix` only; `unsafe` limited to
documented `// SAFETY:` FFI sites: `getauxval`, `lstat`).

---

## 14. bats Suite (tests/shell/21-shell-guard.bats)

| Area | Test classes |
|------|--------------|
| argv classification | `-c`, bundled `-xc`, `--` separator, `name args` operands, script file, unreadable script, interactive, login argv[0], null bytes, oversize |
| tokenizer | quoting, escapes, comments, here-doc skip, nested `$( )`, backquotes, function bodies, `case` arms, depth limit |
| policy | every blocked family, `mkfs.*` glob, blocked shells (path-qualified `/usr/bin/zsh`, prefix-wrapped `env fish`, `busybox sh`, nested `bash -c` allowed), power verbs, kill matrix (§6.2), chattr/rm/swapoff flag gates, dd device detection, protected-path mounts, basename reduction, prefix unwrapping (`sudo pkill`, `env pkill`, `xargs pkill`) |
| env | BASH_ENV/functions/LD_* dropped, PATH reset, OPENCODE_*/WORKSPACE_* preserved |
| logging | block line format, truncation, secret redaction, log-open failure still blocks |
| install | dry-run, idempotency, rollback on sanity-check failure, uninstall restores |

---

## 15. Security Properties

- A non-root agent CANNOT execute the real shell directly: it is
  0700 root:root and immutable.
- A non-root agent CANNOT bypass the guard via env injection:
  allow-list env, `secure_getenv()`, `AT_SECURE` gate.
- A non-root agent CANNOT escalate through the guard: file caps
  (not SUID) mean euid never changes, and caps are cleared by the
  kernel on the final `execve()`.
- Blocks are unconditional for ALL users including root; root's
  channel is `/bin/bash.real` directly, which only root can exec.
- Blocked invocations are always logged; logging failure never
  downgrades a block.
- A non-root agent CANNOT escape to an unguarded shell from within
  the guarded pair: other shell binaries are blocked at any command
  position, and nested `bash`/`sh` re-enters the guard.
- Common obfuscations (path-qualified names, `sudo`/`env` prefixes,
  `$( )` nesting, quoting, function bodies) are structurally covered
  by the tokenizer, not by pattern luck.

---

## 16. Known Residual Risks

- **Interpreter indirection**: `python3 -c 'import os; os.kill(...)'`
  or `perl -e 'system "pkill", "x"'` perform the same syscalls
  without a blocked command name. Bounded by the binary lock
  (SPEC-BINARY-LOCK) and auditd (SPEC-AUDIT), not by this guard.
- **Dynamic eval**: `eval "$x"` where `$x` expands to a blocked
  command is not statically knowable. Static-literal eval IS scanned
  (REQ-SHG-305).
- **Alternative shells**: invocation of other shells from within a
  guarded shell is blocked by basename (§6 step 2). The residual is
  a shell binary renamed or copied to an unlisted name (e.g. a
  user-compiled zsh at `~/bin/mysh`), which basename matching cannot
  recognise. Operators should additionally remove or binary-lock
  alternative shells so they cannot be executed at all.
- **logind over D-Bus**: `dbus-send`/`busctl` to
  `org.freedesktop.login1.Manager.PowerOff` bypasses the `systemctl`
  verb block. Documented; containment is a D-Bus policy concern.
- **Script-scan gap**: an unreadable script file passes through
  unwatched (REQ-SHG-202); the real shell then fails identically for
  the non-root agent, so the gap is root-adjacent only.

---

## 17. Non-Goals

Per REQ-SHELL-GUARD §10: not a sandbox; no interpreter-syscall
control; no WRAPPING of shells beyond bash/sh (other shells are
blocked, not wrapped); no interactive prompts; no full POSIX
parser; no management of agent-side config.
