# Specification: WORKSPACE-GUARD: SUID Guard Framework (Git PoC)

**Date:** 2026-05-18
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-GIT-GUARD](../requirements/REQ-GIT-GUARD.md)
**Implementation Details:** [SPEC-GIT-GUARD-IMPL](SPEC-GIT-GUARD-IMPL.md)

---

## 1. Architecture Overview

```
User invokes: git <subcommand> [args...]
                    │
                    ▼
        /usr/bin/git (SUID root, 4555)
        workspace-guard Rust binary
                    │
        ┌───────────┼────────────────┐
        │           │                │
        ▼           ▼                ▼
   Parse &     Check blocks    Sanitise env
   validate      (commands,     vars, PATH
     args         flags, -c)
        │           │                │
        └───────────┼────────────────┘
                    │
              All clear?
               ┌──┴──┐
              NO     YES
               │      │
               ▼      ▼
            Block   execve("/usr/bin/git.original", argv, envp)
            + log   (real git, mode 0700 root:root)
```

The guard is a **thin SUID-root wrapper**. Its sole purpose is to:
1. Validate the argument vector for destructive patterns.
2. Sanitise the execution environment.
3. If safe, `execve()` the real git binary.
4. If unsafe, block with an audit log entry.

It does NOT re-implement git logic. It does NOT re-implement WORKSPACE-CI contract checks. It delegates contract verification to the existing `checks_quality.sh` script.

### Key Design Principle

> **Deny-list, not allow-list.** The guard blocks known-dangerous operations and passes everything else through. An allow-list would require knowing every git subcommand and flag combination: impossible to maintain. The deny-list covers the operations that actually cause data loss or security breaches.

---

## 2. Privileged Execution

### 2.1 SUID Model

The binary is installed at `/usr/bin/git` with `chown root:root` and `chmod 4555`. When any user invokes `git`, the kernel runs the binary with:
- **Real UID**: the invoking user
- **Effective UID**: 0 (root)
- **Saved set-UID**: 0

The real git binary is at `/usr/bin/git.original` with `chown root:root` and `chmod 0700`. Only root can read or execute it. A non-root user who tries to run it directly gets `Permission denied`.

### 2.2 Privileged Execution Detection

The binary detects SUID context via `libc::getauxval(libc::AT_SECURE)`. This is superior to comparing real/effective UID because:

| Method | Handles SUID | Handles file capabilities | Handles NO_NEW_PRIVS reset |
|--------|-------------|--------------------------|---------------------------|
| `geteuid() != getuid()` | Yes | No | No |
| `getauxval(AT_SECURE)` | Yes | Yes | Yes |

If `AT_SECURE` returns 0, the binary refuses to operate (exit code 3). This prevents an attacker from compiling their own copy of the guard and running it without SUID privileges.

### 2.3 Real Git Verification

Before `execve()`, the binary verifies `/usr/bin/git.original`:
1. `stat()` the path: must exist and be a regular file (`S_IFREG`).
2. Owner UID must be 0.
3. Mode bits must be exactly `0700` (owner rwx only).

If any check fails, exit code 3. This prevents an attacker from replacing git.original with a malicious binary or relaxing its permissions.

---

## 3. Argument Parsing

### 3.1 Parsing Phases

Parsing is a multi-pass process over the argv array. Each phase operates on the result of the previous phase.

**Phase 1: Null-byte scan:** Every argument byte is checked for `0x00`. If found, exit 2 immediately.

**Phase 2: Subcommand identification:** Scan argv left-to-right, maintaining state:

```
state = scanning_flags
subcommand = None
has_amend = False
has_force_flag = False
has_hard_flag = False
has_no_verify_flag = False
has_force_with_lease_flag = False
dangerous_config_keys = []
stash_subcmd = False
branch_subcmd = False
has_branch_D = False
has_stash_drop = False
has_stash_clear = False

for each arg in argv[1..]:
    if state == past_separator:
        break  # arg is a pathspec, ignore

    if arg == "--":
        state = past_separator
        continue

    if state == expecting_config_value:
        # Previous arg was -c or -C, this arg is key=value
        if '=' in arg:
            key = arg.split('=')[0]
            if key in DANGEROUS_CONFIG_KEYS:
                dangerous_config_keys.push(key)
        else:
            # -c or -C without value: git will error, but check anyway
            if arg in DANGEROUS_CONFIG_KEYS:
                dangerous_config_keys.push(arg)
        state = scanning_flags
        continue

    if arg == "-c" or arg == "-C":
        state = expecting_config_value
        continue

    if arg.starts_with("--"):
        # Long flag analysis
        if arg == "--hard": has_hard_flag = True; block_now("--hard flag")
        if arg == "--no-verify": has_no_verify_flag = True; block_now("--no-verify flag")
        if arg == "--force" or arg == "-f": has_force_flag = True
        if arg == "--force-with-lease": has_force_with_lease_flag = True
        if arg.starts_with("--amend"): has_amend = True
        if arg.starts_with("--ff-only") or arg.starts_with("--rebase"):
            safe_pull_flag = True
        if '=' in arg:
            key = arg.split('=')[0].trim_start_matches('-')
            if key == "c" or key == "C":
                value = arg.split('=', 1)[1]
                config_key = value.split('=')[0]
                if config_key in DANGEROUS_CONFIG_KEYS:
                    dangerous_config_keys.push(config_key)
        continue

    if arg.starts_with("-") and arg.len() > 1:
        # Short flag analysis (e.g., -D, -f, -C)
        # For multi-char short flags like -Cf, each char is a flag
        # BUT -C and -c always consume the next arg as their value
        chars = arg[1..].chars()
        for ch in chars:
            if ch == 'c' or ch == 'C':
                state = expecting_config_value
                break  # remaining chars after -C are part of next arg? No: git treats -Cf as -C -f, but -C needs value
            if ch == 'f': has_force_flag = True
            if ch == 'D': has_branch_D = True
        continue

    # arg doesn't start with "-" → this is the subcommand
    if subcommand is None:
        subcommand = Some(arg.clone())
        match arg:
            "stash" => stash_subcmd = True
            "branch" => branch_subcmd = True
    continue
```

**Phase 3: Subcommand-specific flag collection:** After the subcommand is identified, continue scanning remaining args for subcommand-specific flags:

- For `push`: check for `--force`, `-f`, `--force-with-lease` in remaining args
- For `stash`: check for `drop` or `clear` as positional subcommands
- For `branch`: check for `-D` in remaining args
- For `commit`: check for `--amend` in remaining args
- For `revert`: identify the target commit (first non-flag arg after `revert`, or HEAD)

**Phase 4: Decision:** Apply the block decision engine (§4) using the collected state. If no block, proceed to `execve()`.

### 3.2 Edge Cases

| Input | Behaviour |
|-------|-----------|
| `git` (no args) | Pass through to real git |
| `git --` | Pass through (no subcommand, separator only) |
| `git -- --hard` | `--hard` is a pathspec after `--`, NOT a flag → pass through |
| `git -c` (no value) | Pass through: git will error on missing value |
| `git -C key=value` | Parse `key=value`, check against dangerous keys |
| `git -Cf key=value` | `-C` expects value, so `key=value` is the config. `-f` is a dangling flag. |
| `git -c core.hooksPath=/tmp/evil` | Blocked: key is `core.hooksPath` |
| `git --upload-pack=/bin/sh clone ...` | Blocked if `--upload-pack` is in the block list (it is a dangerous flag) |

### 3.3 Subcommand Recognition

The guard only needs to classify subcommands into two categories: **blocked unconditionally** and **flag-gated** (needs further inspection). All other subcommands pass through.

| Blocked unconditionally | Flag-gated blocks |
|------------------------|-------------------|
| `reset` | `commit` (check for `--amend`) |
| `checkout` | `branch` (check for `-D`) |
| `clean` | `push` (check for `--force`/`-f`/`--force-with-lease`, background) |
| `restore` | `stash` (check for `drop`/`clear`) |
| `rm` | `revert` (check target is on origin) |
| `rebase` | `pull` (protected branch check) |
| `gc` | `merge` (protected branch check) |
| `prune` | |

Any argument that doesn't match a blocked or flagged subcommand and doesn't start with `-` passes through: git itself validates and rejects unknown subcommands.

### 3.4 The `--` Separator

Git uses `--` to separate options from pathspecs. For example:
```
git checkout -- myfile.txt    # checkout the file "myfile.txt", not a branch
git log -- src/main.rs        # show log for this file only
```

The guard scans for `--` and stops flag interpretation at that point. Everything after `--` is treated as data, never as a git flag. This prevents bypass attacks like:
```
git -- --hard   # "--" makes "--hard" a pathspec, not a flag
```


---

## 4. Block Decision Engine

The guard applies checks in this order. The first block wins: later checks are not evaluated.

```
1. Destructive subcommand? → BLOCK (reset, clean, restore, rm, rebase, gc, prune). Sudo-gated (non-root blocked, root allowed): submodule, checkout
2. Global destructive flag? → BLOCK (--hard, --no-verify)
3. Dangerous -c/-C key? → BLOCK (core.hooksPath, core.sshCommand, etc.)
4. Subcommand-specific block?
   4a. stash drop/clear? → BLOCK
   4b. branch -D? → BLOCK
   4c. push --force/-f/--force-with-lease? → BLOCK
   4d. push from background? → BLOCK
   4e. commit --amend on pushed HEAD? → BLOCK
   4f. revert on unpushed commit? → BLOCK
5. Protected branch rule?
   5a. pull on main/master without --ff-only/--rebase? → BLOCK
   5b. merge on main/master without --ff-only (and without --abort)? → BLOCK
6. Hook-bypass env var? → BLOCK (SKIP, PRE_COMMIT_ALLOW_NO_CONFIG)
7. AMI-CI contract check? → BLOCK if contract fails (enforce mode)
8. ALL CLEAR → execve real git
```

### 4.1 Block Messages

Block messages follow this format:
```
BLOCKED: git <command> <reason> (<ISO-8601-timestamp>)
  → Hint: <alternative action>
```

Written to both stderr and `/dev/tty` (if openable). The `/dev/tty` write bypasses stdout/stderr redirection: a user running `git reset --hard > /dev/null 2>&1` will still see the block message on their terminal.

### 4.2 Subprocess Checks

Some checks require invoking real git:

| Check | Subcommand | Timeout | On timeout |
|-------|-----------|---------|------------|
| `commit --amend` | `git merge-base --is-ancestor HEAD origin/<branch>` | 2s | Skip check (warn) |
| `revert` | `git rev-parse --verify <target>^{commit}` | 2s | Skip check (warn) |
| `revert` (is-on-remote) | `git merge-base --is-ancestor <target> origin/<branch>` | 2s | Skip check (warn) |
| Protected branch | `git rev-parse --abbrev-ref HEAD` | 2s | Skip check (warn) |

When a subprocess times out, the associated safety check is **skipped** (not blocked). The rationale: these are preventive checks, not destructive command blocks. The destructive commands themselves (reset, clean, restore, etc.) are blocked by the static deny-list regardless of subprocess availability. `checkout` is sudo-gated (root may run it via sudo for conflict resolution).

---

## 5. Environment Sanitisation

### 5.1 Unset List

Before `execve()`, the guard removes these variables from the environment:

**Git-specific** (can redirect git behaviour to attacker-controlled resources):
```
GIT_EXEC_PATH        → subcommand binary lookup path
GIT_TEMPLATE_DIR     → template for new repos (can contain malicious hooks)
GIT_SSH              → SSH command replacement
GIT_SSH_COMMAND      → SSH command replacement (newer)
GIT_ASKPASS          → auth prompt command
GIT_TERMINAL_PROMPT  → interactive prompt control
GIT_EDITOR           → editor command (sudo-gated: passed through only for root)
GIT_SEQUENCE_EDITOR  → editor for interactive rebase (sudo-gated: passed through only for root)
GIT_CONFIG           → config file override
GIT_CONFIG_GLOBAL    → global config file override
GIT_CONFIG_SYSTEM    → system config file override
GIT_CEILING_DIRECTORIES → repo discovery boundary
GIT_DIR              → explicit .git directory
GIT_WORK_TREE        → explicit work tree root
GIT_NAMESPACE        → repository namespace
GIT_INDEX_FILE       → index file path
GIT_OBJECT_DIRECTORY → object store location
GIT_ALTERNATE_OBJECT_DIRECTORIES → alternate object stores
GIT_DISCOVERY_ACROSS_FILESYSTEM → cross-FS repo discovery
GIT_CONFIG_COUNT / GIT_CONFIG_KEY_* / GIT_CONFIG_VALUE_* → env-based config
```

**Dynamic linker** (defense-in-depth; glibc ignores these in SUID mode):
```
LD_PRELOAD           → preloaded shared libraries
LD_LIBRARY_PATH      → library search path
LD_AUDIT             → library auditing
LD_DEBUG             → linker debug output
LD_BIND_NOW          → immediate symbol resolution
LD_BIND_NOT          → skip symbol binding
LD_PROFILE           → profiling
LD_PROFILE_OUTPUT    → profiling output path
LD_TRACE_LOADED_OBJECTS → ldd-style output
LD_USE_LOAD_BIAS     → load bias control
LD_HWCAP_MASK        → hardware capability mask
LD_DEBUG_OUTPUT      → debug output file
```

**glibc unsecvars** (defense-in-depth):
```
GCONV_PATH           → iconv module path
GETCONF_DIR          → getconf directory
NLSPATH              → NLS message catalog path
TMPDIR               → temporary directory
TZDIR                → timezone data directory
RES_OPTIONS          → resolver options
HOSTALIASES          → hostname aliases
LOCALDOMAIN          → local domain name
NIS_PATH             → NIS path
RESOLV_HOST_CONF     → resolver host config
LOCPATH              → locale data path
MALLOC_TRACE         → malloc trace file
MALLOC_ARENA_MAX     → malloc arena count
GLIBC_TUNABLES       → glibc runtime tunables
```

**Hook bypass**:
```
SKIP                 → pre-commit framework: skip hooks
PRE_COMMIT_ALLOW_NO_CONFIG → pre-commit: allow without config
```

### 5.2 PATH Reset

PATH is set to `/usr/local/bin:/usr/bin:/bin`. This prevents PATH injection attacks where an attacker places a malicious binary earlier in the search path.

### 5.3 Preserved Variables

The following are explicitly preserved:
```
HOME                 → needed for git config, ssh keys
USER                 → needed for git author identification
LANG, LC_ALL, LC_*   → locale, affects git output formatting
TERM                 → terminal type, affects colour output
DISPLAY, WAYLAND_DISPLAY → GUI git tools (gitk, git-gui)
SSH_AUTH_SOCK        → SSH agent for git+ssh operations
GPG_TTY, PINENTRY_USER_DATA → GPG signing
GIT_PAGER            → output pager
EDITOR, VISUAL       → user's preferred editor (sudo-gated: dropped with a warning for non-root)
SHELL                → user's shell
PATH                 → set to known-safe value (§5.2)
PWD                  → current directory
```

The commit-identity vars `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`,
`GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, and `EMAIL`, plus the editor vars
above (`EDITOR`, `VISUAL`, `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`), are
**sudo-gated**: dropped (with an explicit warning, no exit) for non-root and
passed through only when the guard runs as root (`getuid()==0`).

### 5.4 Implementation: Allow-List Approach

The guard constructs a **minimal environment from scratch** rather than surgically removing dangerous variables. This is the only correct approach for a SUID binary: a deny-list of env vars is inherently incomplete because glibc and git can add new sensitive variables in future releases. An allow-list has a closed surface.

The implementation:

```rust
// ALLOWED_VARS is the definitive list of env vars to preserve
let mut envp: Vec<CString> = ALLOWED_VARS
    .iter()
    .filter_map(|&key| {
        std::env::var_os(key).map(|val| {
            // SAFETY: key is ASCII, val is valid UTF-8 from the environment.
            // Neither can contain null bytes (OsStr invariant on Linux).
            CString::new(format!("{}={}", key, val.to_string_lossy())).unwrap()
        })
    })
    .collect();

// Inject safe PATH
envp.push(CString::new("PATH=/usr/local/bin:/usr/bin:/bin").unwrap());

// execve expects a null-terminated pointer array
let envp_ptrs: Vec<*const libc::c_char> = envp.iter()
    .map(|s| s.as_ptr())
    .chain(std::iter::once(std::ptr::null()))
    .collect();

let argv_ptrs: Vec<*const libc::c_char> = argv_c.iter()
    .map(|s| s.as_ptr())
    .chain(std::iter::once(std::ptr::null()))
    .collect();

// SAFETY: All pointers are valid null-terminated C strings.
// execve replaces the process image and does not return on success.
// (The call site in src/exec.rs wraps this in the required unsafe block.)
libc::execve(
    GIT_ORIGINAL_PATH.as_ptr(),
    argv_ptrs.as_ptr(),
    envp_ptrs.as_ptr(),
)

// If execve returns, it failed
eprintln!("FATAL: execve failed: {}", std::io::Error::last_os_error());
std::process::exit(3);
```

This approach has two advantages over `remove_var()`:
1. **Completeness**: Any variable not in `ALLOWED_VARS` is absent from the child's environment. No future glibc variable can sneak through.
2. **Auditability**: The allowed list is the single source of truth: reviewers can verify each entry against its justification.

---

## 6. WORKSPACE-CI Contract Enforcement

### 6.1 Workspace Detection

The guard determines if the current repo is inside an WORKSPACE workspace by:
1. Getting the repo's top-level directory (via `rev-parse --show-toplevel` subprocess, or scanning for `.git`).
2. Walking up from that directory to `/`, checking each ancestor for:
   - `.boot-linux/` directory exists
   - `projects/CI/` directory exists
   - `workspace/scripts/utils/git-guard` file exists

The first ancestor with all three is the workspace root. If none found, skip contract enforcement.

### 6.2 Contract Check Delegation

When the repo is in an WORKSPACE workspace and the subcommand is `commit` or `push`, the guard runs:

```bash
bash /path/to/projects/CI/lib/checks_quality.sh
```

With environment variables:
```
WORKSPACE_GGUARD_CMD=<commit|push>
WORKSPACE_GGUARD_REPO_ROOT=<repo top-level>
WORKSPACE_GGUARD_WORKSPACE_ROOT=<workspace root>
```

The script outputs violations to stderr. If it exits non-zero, the guard blocks with exit code 4 and passes through the script's stderr.

### 6.3 Why Shell Delegation?

The contract checks involve:
- YAML parsing (`project_enforcement.yaml`)
- File content inspection (checking hook headers for `AUTO-GENERATED`)
- Tier resolution logic
- Makefile grep

Re-implementing this in Rust would:
1. Add YAML parsing dependency (violates the "no external dependencies" constraint)
2. Duplicate logic that already exists and is maintained in WORKSPACE-CI
3. Create two sources of truth for contract rules

Delegation keeps the guard binary thin and delegates policy to the policy engine.

### 6.4 Graceful Degradation

If `checks_quality.sh` is not found at the expected path, the guard emits a warning to stderr and allows the operation. This prevents a missing CI library from blocking all git operations across the workspace.

---

## 7. Audit Logging

### 7.1 Log Format

```
<ISO-8601-timestamp>|<cwd>|<blocked-command>|<reason>|uid=<real-uid>
```

Example:
```
2026-05-18T14:32:01+00:00|${HOME}/projects/WORKSPACE-PORTAL|git reset|destructive subcommand|uid=1000
```

### 7.2 Log Location

`${HOME}/.workspace-guard.log`: the HOME is the **real user's** home directory (from `getpwuid(getuid())`), not root's home. Since the guard runs as SUID root but the real UID is the invoking user, we must use the real UID to find the correct HOME.

### 7.3 Secret-Safe Logging

When logging `-c key=value` blocks, only the key is logged:
```
2026-05-18T14:32:01+00:00|${HOME}|git -c core.hooksPath=...|dangerous config key|uid=1000
```

The value portion is replaced with `...` to avoid logging potentially sensitive paths or commands.

### 7.4 Log Write Timing

The log file is opened and written **only after** the block decision is made: not during argument processing. This minimises the number of file descriptors opened during the critical path.
