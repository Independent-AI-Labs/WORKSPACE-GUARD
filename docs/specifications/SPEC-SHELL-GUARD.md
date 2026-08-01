# Specification: Shell Guard (bash/sh Command Wrapper)

**Date:** 2026-07-27
**Status:** IMPLEMENTED (bats 21-shell-guard green; QEMU guest e2e 85 checks green)
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
  Classify argv         Scan raw text against      Sanitise env
  (-c / script /        the compiled regex         (allow-list,
   interactive)          pattern table (command     PATH reset,
                         string or script file      drop BASH_ENV,
                         content, as bytes)         LD_*, funcs)
        │                     │                          │
        └─────────────────────┼──────────────────────────┘
                              │
                        Any pattern matches?
                            ┌──┴──┐
                          YES     NO
                           │       │
                           ▼       ▼
                    Block + log  execve("/bin/bash.real",
                    (exit 1;     original argv, clean envp)
                    trusted-tier
                    scripts:     real shell: root:root 0700, +i
                    would-block
                    audit + run)
```

The guard is a **thin capability-enabled wrapper**. Its sole purpose
is to:

1. Acquire the text to scan (the `-c` command string or the script
   file content).
2. Match the raw text, as bytes, against the compiled regex deny
   policy. There is no tokenizer and no parsing.
3. Sanitise the execution environment.
4. If safe, `execve()` the verified real shell with the original
   argv.
5. If unsafe, block with an audit log entry (exit 1).

It does NOT re-implement the shell. It does NOT sandbox allowed
commands. It does NOT read any config file at runtime: policy is
compiled in from `config/shell_guard_policy.yaml` via `build.rs`.

### Key Design Principle

> **Deny-list on raw text, not allow-list.** The shell's legitimate
> surface is unbounded; the catastrophic surface (kill the
> supervisor, power off the host, destroy filesystems, strip
> immutability, suppress output) is small and enumerable. The guard
> blocks the catastrophic set wherever its pattern appears in the
> text and passes everything else through. Patterns live in
> root-owned YAML; adding a rule never requires a Rust change.

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
guard pattern-scans the command string before any exec and blocks
the catastrophic set unconditionally. Root's operator channel is
invoking `/bin/bash.real` directly.

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

The guard detects its capability context by parsing
`/proc/self/auxv` for the `AT_SECURE` entry in safe Rust (no
`unsafe`; the git guard uses `libc::getauxval`, SPEC-GIT-GUARD
§2.2). If `AT_SECURE == 0`, the guard refuses to operate (exit 3):
an attacker-compiled copy of the guard without the file capability
cannot read `bash.real` and fails closed.

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
| Command string | `bash -c STR [name [args...]]`, `bash -xc STR` | Scan STR against the pattern table (§5); full policy, no exemption |
| Script file | `bash FILE [args...]`, `bash -- FILE` | Open `O_NOFOLLOW`, `fstat`, classify trust tier (§4.1), scan content (§5); unreadable → warn + pass through |
| Interactive/login | `bash`, `bash -l`, `bash -i`, argv[0] `-bash` | Pass through unchanged (typed REPL input is unscanned; the guard wraps process spawn, not the line editor) |

### 4.1 Script Trust Tiers (REQ-SHG-211)

Invocation context (`-c` vs script vs TTY vs parent process) is
NEVER a trust signal: the constrained party chooses the invocation
form, so any context-based discrimination is exploitable by
construction (`printf 'cmd | tail\n' > /tmp/x.sh && bash /tmp/x.sh`
would walk around a `-c`-only ban). The only trust boundary is
ownership provenance, which the agent cannot forge.

A script file is **trusted tier** iff, at `open(O_NOFOLLOW)` +
`fstat()` time:

1. it is a regular file owned by UID 0,
2. it is not group- or other-writable, and
3. every parent directory component up to `/` is root-owned and not
   group/other-writable.

Trusted tier: policy violations are audit-logged as `would-block`
warnings (stderr + log file) but NOT blocked. Rationale: dpkg
maintainer scripts, cron jobs, and init scripts legitimately use
`2>/dev/null`, `| tail`, even `killall`; blocking root-owned system
code risks bricking boot and package operations, and the agent
cannot author or modify it. Untrusted tier (everything else,
including all agent-writable files and every `-c` string): the full
block policy applies to all users including root. Root's channel
for suppression idioms is `/bin/bash.real` directly.

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

## 5. Raw-Text Pattern Scanner

There is no tokenizer. The scanner takes the text to check (the
`-c` string or the script content) as raw bytes and runs every
compiled pattern from the policy table over it. The first match
wins. Matching uses `regex::bytes::Regex` so non-UTF-8 input is
scanned byte-exactly (REQ-SHG-205, REQ-SHG-703).

### 5.1 Pattern Semantics

- Patterns are matched unanchored, anywhere in the text.
- Word boundaries (`\b`) delimit command names: `\bpkill\b` matches
  `sudo pkill -f x`, `/usr/bin/pkill x`, and `$(pkill x)`, but not
  `pkillx`.
- **Connector context is spelled in the pattern** (REQ-SHG-206):
  `\|\s*(tail|head)\b` fires only after a pipe; `\|\|\s*(true|:)\b`
  only after `||`. Bare `tail file` and bare `true` after `;` never
  match.
- Quotes and comments are NOT special (REQ-SHG-207): `echo "a | tail"`
  matches the pipe-sink pattern and is blocked. Accepted false
  positive; root's channel is `/bin/bash.real`.
- Quote-splitting evasion (`pki''ll`), variable indirection, and
  dynamic `eval` do NOT match and are documented residuals (§16,
  REQ-SHG-208).

### 5.2 Size and Depth Bounds

- Command strings and script content over 1 MiB: exit 2
  (REQ-SHG-204). No recursion exists, so there is no depth bound;
  regex compilation happens once at startup from the compiled-in
  pattern strings, and matching is linear-time (the `regex` crate
  guarantees no catastrophic backtracking).

---

## 6. Block Decision

Every pattern in the policy table is tried against the raw text; the
first match wins. Patterns carry a `scope` (REQ-SHG-312): `command`
rules only apply to `-c` text, `script` rules only to script bodies,
`both` (the default) to every scanned context. For trusted-tier
script bodies (§4.1), a match is downgraded to a `would-block`
audit warning and execution continues.

The pattern groups (exact regexes live in
`config/shell_guard_policy.yaml`, §7):

```
1. Destructive commands      \b(pkill|killall|skill|snice|shutdown|
                              reboot|poweroff|halt|kexec|telinit|
                              wipefs|fdisk|sfdisk|cfdisk|parted|
                              mkfs(\.[a-z0-9]+)?)\b        → BLOCK
2. Shell escape              \b(zsh|dash|fish|nu|ksh93?|mksh|tcsh?|
                              ash|yash|rc|elvish|xonsh|pwsh|
                              powershell)\b, \bbusybox\s+(sh|ash)\b
                                                             → BLOCK
3. Power verbs               \b(systemctl|loginctl)\s+[^;|&]*
                              \b(poweroff|reboot|halt|kexec|
                              soft-reboot|suspend|hibernate|
                              hybrid-sleep|kill)\b         → BLOCK
4. kill mass-target forms    \bkill\b[^;|&]*(\s-1(\s|$)|%|
                              \s-[0-9]{2,}(\s|$))          → BLOCK
5. chattr -i                 \bchattr\b[^;|&]*\s-i\b       → BLOCK
6. rm --no-preserve-root     \brm\b[^;|&]*--no-preserve-root → BLOCK
7. dd of= device             \bdd\b[^;|&]*\bof=/dev/(sd|nvme|
                              mmcblk|vd|mapper/|disk/)     → BLOCK
8. mount/umount protected    \b(u?mount)\b[^;|&]*
                              /usr/lib/workspace-guard     → BLOCK
9. swapoff -a                \bswapoff\b[^;|&]*\s-a\b      → BLOCK
10. Suppression pipe sinks   \|\s*(tail|head)\b            → BLOCK
11. Suppression redirects    (&?>|[0-9]+>>?)\s*/dev/null   → BLOCK
12. Suppression null swallows (\|\||\|&?)\s*(true|:)\b     → BLOCK
13. Interpreter escape       \b(python[0-9.]*|perl[0-9.]*|ruby|
                              irb|node|nodejs|deno|bun|php[0-9.]*|
                              lua[0-9.]*|luajit|tclsh|wish|expect|
                              Rscript|raku|julia|awk|gawk|mawk|
                              nawk)\b                      → BLOCK
                              (scope: command, REQ-SHG-313)
14. ALL CLEAR → sanitise env, execve real shell
```

Group 13 closes the interpreter-escape vector in `-c` text: an
interpreter is an unscanned command channel that voids groups 1-12.
Its `command` scope keeps script bodies (operator tooling, shell
libraries) free to invoke interpreters; a hostile script body is
already confined by sealed-memfd staging and the `both`-scoped
rules, and binary-level interpreter confinement belongs to the
binary guard (SPEC-BINARY-GUARD, GTFOBins policies).

Group 2 closes the shell-escape vector: the guarded pair cannot be
used as a springboard to an unguarded interpreter. Nested `bash` /
`sh` invocations are NOT blocked: they resolve to the guard's own
paths and re-enter the guard, so policy is re-applied at every
nesting level. Only the `busybox sh`/`busybox ash` shell applets
match; other applets pass (the binary lock covers SUID busybox,
SPEC-BINARY-LOCK).

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

Rule: the pattern fires on a job spec (`%`), a `-1` target, or a
negative multi-digit PID anywhere in the `kill` operand text; pure
numeric-PID forms never match.

---

## 7. Policy Config Schema

`config/shell_guard_policy.yaml` (with sibling
`shell_guard_policy.schema.yaml`), compiled in by `build.rs`. The
schema is a flat pattern table: every rule is
`{id, regex, hint, scope?}` where `scope` is `command` | `script` |
`both` (default `both`, REQ-SHG-312); the regexes are the group
shapes of §6 written out in full. Example
excerpt:

```yaml
version: 1

# Every entry: stable rule id (used in block messages, audit logs,
# and the policy matrix), a bytes-regex matched unanchored against
# the raw command text, and a remediation hint.
patterns:
  # --- destructive commands (REQ-SHG-300) ---
  - {id: process-by-name,  regex: '\b(pkill|killall|skill|snice)\b',
     hint: "use kill <pid> on the specific process"}
  - {id: power-command,    regex: '\b(shutdown|reboot|poweroff|halt|kexec|telinit)\b',
     hint: "power actions are an operator operation"}
  - {id: fs-destroy,       regex: '\b(wipefs|fdisk|sfdisk|cfdisk|parted|mkfs(\.[a-z0-9]+)?)\b',
     hint: "filesystem/partition destruction is blocked"}
  # --- shell escape (REQ-SHG-307) ---
  - {id: alt-shell,        regex: '\b(zsh|dash|fish|nu|ksh93?|mksh|csh|tcsh|ash|yash|rc|elvish|xonsh|pwsh|powershell)\b',
     hint: "only bash/sh are permitted on this host"}
  - {id: busybox-shell,    regex: '\bbusybox\s+(sh|ash)\b',
     hint: "only bash/sh are permitted on this host"}
  # --- power verbs / kill / flags / dd / mounts / swap (REQ-SHG-300..302) ---
  - {id: power-verb,       regex: '\b(systemctl|loginctl)\s+[^;|&]*\b(poweroff|reboot|halt|kexec|soft-reboot|suspend|hibernate|hybrid-sleep|kill)\b',
     hint: "power actions are an operator operation"}
  - {id: kill-mass,        regex: '\bkill\b[^;|&]*(\s-1(\s|$)|%|\s-[0-9]{2,}(\s|$))',
     hint: "use kill <pid> on the specific process"}
  - {id: chattr-strip,     regex: '\bchattr\b[^;|&]*\s-i\b',
     hint: "immutability strip is blocked"}
  - {id: rm-rootfs,        regex: '\brm\b[^;|&]*--no-preserve-root',
     hint: "root-fs deletion is blocked"}
  - {id: dd-device,        regex: '\bdd\b[^;|&]*\bof=/dev/(sd|nvme|mmcblk|vd|mapper/|disk/)',
     hint: "writing block devices is blocked"}
  - {id: mount-protected,  regex: '\b(u?mount)\b[^;|&]*/usr/lib/workspace-guard',
     hint: "guard mountpoints are protected"}
  - {id: swap-teardown,    regex: '\bswapoff\b[^;|&]*\s-a\b',
     hint: "swap teardown is blocked"}
  # --- output suppression (REQ-SHG-308/309/310) ---
  - {id: suppress-pipe,    regex: '\|\s*(tail|head)\b',
     hint: "run without truncation; write long output to a file and read it with offset/limit"}
  - {id: suppress-null,    regex: '(&?>|[0-9]+>>?)\s*/dev/null',
     hint: "capture output and print it on failure instead of discarding it"}
  - {id: suppress-swallow, regex: '(\|\||\|&?)\s*(true|:)\b',
     hint: "handle the exit code explicitly instead of masking it"}
  # --- interpreter escape (REQ-SHG-313; -c text only) ---
  - {id: alt-interp,       regex: '\b(python[0-9.]*|perl[0-9.]*|...)\b',
     hint: "interpreters are an unscanned command channel; run them from a script or the operator shell",
     scope: command}
```

Adding a rule is a YAML edit (via the secure editor) plus rebuild;
the Rust code never changes. `build.rs` validates that every pattern
compiles as a bytes-regex, every id is unique, and every matrix case
references a known id.

`config/shell_guard_policy_matrix.yaml` holds the case matrix
(`input` → `blocked`|`allowed`, with expected rule and an optional
`ctx: command|script` selecting the scan context, default
`command`) validated at build time against the compiled policy,
mirroring the git guard's `git_guard_policy_matrix.yaml` mechanism
(`build.rs` `validate_policy_matrix`).

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
AMI_*         → workspace shell-environment contract vars
                (AMI_QUIET_MODE et al.; stripping them re-triggers
                per-command banner/toolchain probes)
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

### 9.1 Untrusted Script Exec: Sealed memfd (REQ-SHG-212)

Scanning an agent-writable script by path and then letting the real
shell re-open that path is a scan-then-exec TOCTOU race: content can
be swapped between the guard's read and bash's open (the window
spans the whole exec path). For untrusted-tier scripts the guard
therefore executes the SCANNED bytes:

1. Read the script from the `O_NOFOLLOW` fd used for tier
   classification (never re-opened by path).
2. Create a `memfd` via `rustix::fs::memfd_create` with
   `MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC` (ALLOW_SEALING is
   mandatory - without it the memfd is born with `F_SEAL_SEAL` and
   every `F_ADD_SEALS` fails EPERM; EXEC keeps the fd executable
   under `vm.memfd_noexec=1`, the Ubuntu 24.04 default). Write the
   exact scanned bytes, seal it
   (`F_ADD_SEALS`: `SEAL_SHRINK|SEAL_WRITE|SEAL_GROW|SEAL_SEAL`).
3. Clear `FD_CLOEXEC`; the fd is intentionally leaked past the
   guard's Rust drop scope so it survives the exec;
   `execve("/bin/bash.real", ["bash",
   "/proc/self/fd/<n>", args...], clean_envp)`.

Observable difference: `$0` and `BASH_SOURCE` name the
`/proc/self/fd/<n>` path instead of the original script path. To
keep `$0`-relative scripts workable, the guard inserts
`SHG_SCRIPT_PATH=<canonical original path>` into the scrubbed
environment (REQ-SHG-213), after the allow-list filter so a
caller-supplied value cannot survive. Scripts that resolve sibling
files via `dirname "$0"`/`BASH_SOURCE` should prefer it:

```bash
_SELF="${BASH_SOURCE[0]:-$0}"
case "$_SELF" in /proc/self/fd/*) _SELF="${SHG_SCRIPT_PATH:-$_SELF}";; esac
```

The `case` guard (not a blanket `${SHG_SCRIPT_PATH:-...}`) is
required: the variable is inherited by child processes, so a nested
TRUSTED-tier script (exec'd by path, no staging) would otherwise
pick up its parent's path. Trusted-tier scripts are exec'd by path
unchanged: their content cannot be swapped by the agent.

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

Root-only. All paths target the RESOLVED bash path (usrmerge:
`/bin` symlinks to `usr/bin`, so the divert and the guard land on
`/usr/bin/bash`). Flow:

1. Locate the prebuilt release binary (`SHG_GUARD_BIN` or
   `target/release/workspace-shell-guard`); the script never builds.
   Verify it is a valid ELF.
2. Self-stage when `$0` is outside the trusted tier (e.g. the
   agent-owned repo): copy to `/var/lib/workspace-guard/` (root:root
   0700) and re-exec. Once the guard is live, a shebang re-exec
   would resolve bash to the guard and fail closed, so the staged
   copy is run through the sealed `/bin/bash.real` when present.
3. Seal the stock bash as `/bin/bash.real`: copy from the resolved
   bash path (first install) or from `<bash>.distrib` (reconcile).
   `chown root:root`, `chmod 0700`, ELF-magic check. When
   `/bin/bash.real` is already `chattr +i`, the immutable flag
   itself proves ownership and mode; the chown/chmod step is
   skipped (it would fail EPERM).
4. Sanity probes via `runuser` as a non-root probe user
   (`SHG_PROBE_USER`/`workspace`/`agent`/`nobody`): benign `-c`
   exits 0, `--version` exits 0, a concat-built destructive `pkill`
   probe exits 1. As root every probe must exit 3 (fail-closed,
   REQ-SHG-606).
5. `dpkg-divert` the resolved bash path to `<bash>.distrib`
   (and `/bin/sh` when it resolves to bash).
6. Install the guard at the resolved bash path (root:root 0755,
   `setcap cap_dac_override=ep`).
7. Register the apt post-invoke hook
   (`/etc/apt/apt.conf.d/99workspace-guard-shell`) that warns when
   the `bash` or `dash` package changes. The hook never
   auto-reinstalls.
8. Lock the sealed original: `chattr +i /bin/bash.real`.
9. Post-install verification (REQ-SHG-605): modes/owners/caps,
   divert registered, hook present, guard hash matches the release
   build, root `-c` exits 3, non-root benign `-c` exits 0.

Any failure rolls back: `.real` is copied back over the guard path
(mode 0755), the divert is removed, and a clear error is printed. A
host is never left without a working `/bin/bash`.

Install is idempotent and reconciling (REQ-SHG-603): stale guard
hash, wrong caps, missing divert/hook, missing `+i`, or relaxed
`.real` mode are repaired; a fully healthy install is a no-op.

### 12.2 Uninstall (`make uninstall-shell-guard`)

1. Relax the seal: `chattr "-i" /bin/bash.real` (quoted flag; the
   policy pattern matches only the unquoted form).
2. Remove the guard binary at the bash path, then
   `dpkg-divert --remove --rename`: `<bash>.distrib` renames back
   over the now-absent path in a single rename. (dpkg-divert
   refuses to rename over a file that differs from the diverted
   original, so the guard binary must be removed first.) When the
   diversion is already gone (drift), copy `.real` back instead.
3. Remove `/bin/bash.real` and the apt hook (restore `/bin/sh` the
   same way when covered).
4. Verify `bash --version`, `bash -c 'echo sh-ok'`, and
   `/bin/sh -c 'echo sh-ok'` succeed.

### 12.3 Makefile Targets and Operator Flow

```makefile
install-shell-guard:      sudo scripts/install-shell-guard (ROOT)
uninstall-shell-guard:    sudo scripts/uninstall-shell-guard (ROOT)
shell-guard-check:        read-only health check (modes, caps, divert, +i, hash)
```

`shell-guard-check` is caller-agnostic:

- Root fails closed through the guarded `/bin/bash` (AT_SECURE == 0
  for root execs of the fcap binary), so the Makefile target and
  `guard-operator.sh` route root through the sealed
  `/bin/bash.real`; non-root callers use plain `bash`.
- The repo root resolves explicitly: first argument, else
  `SHG_REPO_ROOT`, else derivation from the script's own path.
  An explicitly supplied root must be an existing directory
  (exit 2 otherwise). Under an active guard the script is staged
  through a sealed memfd, so the derivation lands in
  `/proc/self/fd` and is rejected; with no resolvable root the
  check exits 2 with a remediation message. There is no cwd
  guessing and no silent skip of the config-owner checks.
- `getcap` lives in `/usr/sbin`, which the guard's PATH reset
  removes, so the check resolves it absolutely (`SHG_GETCAP`
  overrides for tests).
- `lsattr` on the 0700 root-only `/bin/bash.real` fails with EACCES
  for non-root callers; that is the installed posture, so the +i
  probe degrades to an OK-with-note when the file is unreadable.

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

### 12.4 QEMU Guest E2E (`scripts/qemu/e2e-shell-guard-guest.sh`)

Authoritative end-to-end suite (REQ-SHG-805/806), driven from the
WORKSPACE-VM repo by `make test-vm-shell-guard`
(`tests/e2e/test_vm_qemu_shell_guard.py`, reusing
`workspace/config/vm-guard-qemu.yaml`). It may also be chained
behind `E2E_SHELL_GUARD=1` at the end of `scripts/qemu/e2e-guest.sh`.
Self-contained bash (the guest has no bats), six phases:

0. **preflight**: root gate, clean-slate uninstall when a previous
   partial run left the guard in, stock-bash baseline hash.
1. **build**: `cargo build` (debug + release) with the guest's
   rustup env.
2. **standalone battery**: scratch guard copy +
   `cap_dac_override=ep` against a manual `/bin/bash.real`; the
   AT_SECURE gate (no-cap copy exits 3), the full 16-rule block
   matrix (incl. the command-scoped `alt-interp` rule and its
   invisibility proof in script bodies), argv classification, env
   hygiene (incl. `AMI_*` preservation), rlimits, trust tiers,
   sealed-memfd exec, audit (format, redaction), oversize bound,
   and fail-closed verify (relaxed `.real` mode exits 3).
3. **install lifecycle**: check reports NOT INSTALLED, install,
   check OK as root (via `bash.real`) AND as the non-root user
   through the installed guard (memfd staging, absolute getcap,
   note-only lsattr), structural assertions (seal, +i, caps, divert,
   hook, hash), live-fire through the installed `/bin/bash` as root
   and as the non-root `workspace` user (per-user audit),
   idempotent reinstall.
4. **survivability**: hook content, divert listing, login shells
   for the non-root user, the post-transaction repair loop.
5. **reconcile**: missing-hook and stale-binary drift are reported
   DRIFTED and repaired; fail-closed proof (cap-stripped guard
   exits 3) plus the recovery runbook: stage the installer
   root-owned and run it under the sealed `/bin/bash.real`
   (REQ-SHG-806).
6. **uninstall**: NOT INSTALLED afterwards, sealed original/divert/
   hook removed, `/bin/bash` byte-identical to the phase-0
   baseline, unguarded behaviour confirmed.

The suite is authoritative in the QEMU guest only: rootless
containers cannot establish AT_SECURE (their overlay stores file
capabilities as `user.overlay` xattrs the kernel never honors),
and Ubuntu hosts restrict unprivileged user namespaces via
AppArmor, so neither podman nor namespace nesting can substitute.

The script body follows the same pattern-dodge discipline as
`scripts/install-shell-guard`: it must run to completion (and be
re-runnable for cleanup) while the guard is active, so probe
strings are built by concatenation and no barred idiom appears
literally.

---

## 13. Rust Project Structure and build.rs

New binary in `Cargo.toml`:

```toml
[[bin]]
name = "workspace-shell-guard"
path = "src/shell_guard.rs"
```

```
src/shell_guard.rs          # the whole guard: argv classification,
                            # text acquisition, trust tiers, pattern
                            # scan, env allow-list, memfd/path exec
```

Single-file design (~500 lines): the scanner is a regex-table loop,
so the tokenizer/policy/env modules of earlier drafts collapse into
one auditable unit. `build.rs` parses
`config/shell_guard_policy.yaml` into a compiled
`SHELL_PATTERNS` table (`&[(&str /*id*/, &str /*regex*/, &str /*hint*/)]`)
and validates `config/shell_guard_policy_matrix.yaml`
against it (build fails on disagreement). Profile and dependency
constraints follow REQ-GIT-GUARD §13/§16 (`panic = "abort"`, full
RELRO, `strip`; `std` + `libc` + `nix` + `rustix` + `regex`).
`shell_guard.rs` contains NO `unsafe` blocks: `AT_SECURE` is read
from `/proc/self/auxv`, `lstat` goes through `std::fs::symlink_metadata`,
and `memfd_create` uses the safe `rustix` wrapper (nix 0.29 does not
expose `MFD_EXEC`).

---

## 14. bats Suite (tests/shell/21-shell-guard.bats)

| Area | Test classes |
|------|--------------|
| argv classification | `-c`, bundled `-xc`, `--` separator, `name args` operands, script file, unreadable script, interactive, login argv[0], null bytes, oversize |
| scanner | non-UTF-8 input, patterns inside quotes match (documented false positive), quote-split evasion does NOT match (documented residual), 1 MiB bound |
| policy | every pattern family: destructive set, `mkfs.*`, blocked shells (path-qualified `/usr/bin/zsh`, prefixed `env fish`, `busybox sh`, nested `bash -c` allowed), power verbs, kill matrix (§6.2), chattr/rm/swapoff flag gates, dd device prefixes, protected-path mounts |
| suppression | pipe sinks (`\| tail`, `\| tail -n N`, `2>&1 \| head`, `$(x \| tail)`), redirect targets (`> /dev/null`, `2>/dev/null`, `&> /dev/null`, `>/dev/null 2>&1`, `2>"/dev/null"`), null swallows (`\|\| true`, `\| true`, `\|\| :`), allowed controls (bare `tail file`, `true` after `;`/`&&`, `2>&1` alone) |
| trust tiers | root-owned script exemption with `would-block` audit, agent-writable script full policy, memfd exec of scanned bytes (script-swap fixture stays blocked), `$0` divergence documented |
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
  the guarded pair: other shell names are blocked by word-boundary
  pattern anywhere in the text, and nested `bash`/`sh` re-enters the
  guard.
- Common invocations (path-qualified names, `sudo`/`env` prefixes,
  `$( )` nesting, function bodies) match because word-boundary
  patterns fire anywhere in the raw text; the evasion classes that
  remain (quote-splitting, variable indirection) are documented in
  §16.

---

## 16. Known Residual Risks

- **Interpreter indirection**: `python3 -c 'import os; os.kill(...)'`
  or `perl -e 'system "pkill", "x"'` perform the same syscalls
  without a blocked command name. Bounded by the binary lock
  (SPEC-BINARY-LOCK) and auditd (SPEC-AUDIT), not by this guard.
- **Dynamic eval**: `eval "$x"` where `$x` expands to a blocked
  command is not statically knowable. Static-literal eval IS scanned
  (REQ-SHG-305): the literal appears in the raw text.
- **Quote-splitting evasion**: `pki''ll`, `p\kill`, `$'pki'LL`-style
  reassembly produces a blocked command whose raw text never
  contains it. Raw-text matching cannot see through shell word
  reassembly (REQ-SHG-208). Containment for the agent is that these
  forms are conspicuous in review and audit, unlike the one-character
  suppression idioms this guard exists to kill.
- **Quoted-text false positives**: patterns match inside quotes and
  comments (`echo "use | tail"` blocks). Accepted by design
  (REQ-SHG-207); root's channel for such text is `/bin/bash.real`.
- **dd symlink indirection**: `dd of=` matching is prefix-based on
  the literal path; a symlink to a block device under a non-device
  path is not resolved (no canonicalisation in a text scan).
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
- **Trusted-tier indirection**: a root-owned script is
  exempt-with-audit (§4.1). If existing root-owned content evaluates
  caller-controlled input (e.g. a system script doing `eval "$1"`),
  the agent could route a blocked idiom through it. The agent cannot
  author such a script, only discover one; would-block audit lines
  make the attempt visible. Operators should treat any
  argument-evaluating root-owned script as a defect.
- **Interpreter-internal suppression**: `python3 -c
  'subprocess.run(..., stdout=subprocess.DEVNULL)'` hides output
  without shell grammar. Not detectable at this layer (REQ-SHG-NG-07).
- **memfd `$0` divergence**: untrusted scripts observe
  `/proc/self/fd/<n>` as `$0`/`BASH_SOURCE` (§9.1); the guard
  publishes the canonical original path as `SHG_SCRIPT_PATH`
  (REQ-SHG-213) so `$0`-relative scripts can recover it.

---

## 17. Non-Goals

Per REQ-SHELL-GUARD §10: not a sandbox; no interpreter-syscall
control; no WRAPPING of shells beyond bash/sh (other shells are
blocked, not wrapped); no interactive prompts; no full POSIX
parser; no management of agent-side config.
