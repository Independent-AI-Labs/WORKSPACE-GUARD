# Compiled Privilege Enforcement for Git

A Rust binary that replaces `/usr/bin/git` to enforce immutable, unbypassable
policies on destructive and history-rewriting operations. Uses **file
capabilities** (`CAP_SETPCAP` + `CAP_DAC_OVERRIDE` + `CAP_CHOWN` + `CAP_FOWNER`
+ `CAP_FSETID`): more granular than SUID, correctly handles `NO_NEW_PRIVS`
contexts, and keeps privilege analysis straightforward. The extra caps beyond
`DAC_OVERRIDE` exist for two purposes: (1) claiming the **entire** `.git/`
directory tree of every repository the guard touches as `root:root` (see
[`.git` Ownership Lock](#git-ownership-lock)), and (2) `CAP_SETPCAP` allows
the forked child to raise `CAP_DAC_OVERRIDE` into its Ambient set so that
`git.original` can write to root-owned `.git/` files during the authorized
subcommand only.

For environments where file capabilities are unavailable (PRoot, containers
running as root, user namespaces), a **root-only mode** provides a soft barrier
with the same policy engine but reduced bypass resistance. The `.git` lock is
**not** applied in root-only mode: the user IS root there and could trivially
chown the paths back, so the lock would only impede them.

## Deployment Modes

| Mode | Feature Flag | Enforcement Level | Requires | Suitable For |
|------|-------------|-------------------|----------|-------------|
| Capability (default) | `--features capability-mode` (default) | Hard barrier | `setcap 'cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid+ep'`, `chattr`, `dpkg-divert` | Production, non-root users |
| Root-only | `--features root-only` | Soft barrier | Root only | PRoot, containers, CI agents as root |

### Build Commands

```bash
# Capability mode (default: production)
cargo build --release
# or:
make build-guard

# Root-only mode (PRoot, containers)
cargo build --release --no-default-features --features root-only
# or (auto-detected by bootstrap script):
make build-guard BUILD_MODE=root-only
```

See [docs/ROOT-ONLY-MODE.md](docs/ROOT-ONLY-MODE.md) for the root-only threat
model and limitations.

## Why

Shell-based git guards (bash wrappers, pre-commit hooks) are readable, editable,
and bypassable: run `git` from an alternate path or unset the wrapper.
WORKSPACE-GUARD solves this by:

1. Installing a **compiled Rust binary** as `/usr/bin/git` (mode 0755, with file
   capabilities `CAP_SETPCAP,CAP_DAC_OVERRIDE,CAP_CHOWN,CAP_FOWNER,CAP_FSETID+ep`)
2. Relocating the real git to `/usr/bin/git.original` (mode **0700 root:root**
   : unreadable and unexecutable by non-root)
3. Guarding all arguments, config keys, and environment **before** `execve()`-ing
   the real binary
4. Sanitizing the execution environment from scratch (18-variable allow-list,
   hardcoded `PATH`, injected `safe.directory=*` to suppress ownership checks)
5. **Locking** the **entire** `.git/` directory tree of every repository
   encountered: recursively `chown`'d to `root:root` (0o755 dirs, 0o644
   files, 0o755 hooks) so a non-root user can READ/TRAVERSE but not WRITE.
   Hooks stay executable (0o755) so git **actually invokes them**; the
   protection is that only root can create/modify them (closes the local
   RCE vectors from `.git/config` injection of `core.fsmonitor` /
   `core.hooksPath` / `include.path`, and `.git/hooks/` trojaning -- see
   [CVE history](#documented-residual-risk))

The user cannot bypass the guard: they cannot read, modify, or directly execute
`/usr/bin/git.original`, and the compiled binary logic is opaque.

## Architecture

### Capability Mode (default)

```
User: git push --force
  │
  ▼
/usr/bin/git  (compiled Rust guard, file caps: SETPCAP+DAC_OVERRIDE+CHOWN+FOWNER+FSETID)
  │
  ├─ check: all 5 caps present?                      → MissingCap → exit 2
  ├─ setrlimit(NOFILE=256, CORE=0)                   ← resource limits
  ├─ raise_ambient_caps()                            ← raise 5 caps into Inheritable
  ├─ parse_args(&argv) → ArgState                    ← subcommand, flags, -c keys
  │    └─ check_null_bytes, resolve abbreviations,
  │       detect --amend, --force, --hard, --no-verify, -n/-N,
  │       --upload-pack, --receive-pack, --exec, --delete,
   │       parse -c/-C config keys against 96-pattern glob list
├─ check_blocked(&state, &argv)                    ← policy engine (17 rules)
   │    └─ blocked? → BLOCKED + audit log → exit 1
   ├─ gitdir::lock()                                  ← capability-mode only
   │    └─ rev-parse --absolute-git-dir (hardened env), then
   │       RECURSIVELY chown entire .git/ tree to root:root
   │       (0o755 dirs, 0o644 files, 0o755 hooks). Idempotent. Skipped under sudo.
   ├─ check_workspace_ci_contract(subcommand)         ← commit/push only
   │    └─ contract failed? → exit 4
  ├─ verify_git_original()                           ← exists? uid=0? mode=0700?
  ├─ construct child envp from ALLOWED_VARS (22 vars)
  ├─ fork()
  │    ├─ child: raise_child_dac_override() → CAP_DAC_OVERRIDE into Ambient
  │    │        execve(/usr/bin/git.original, argv, envp)
  │    └─ parent: waitpid() → gitdir::lock() (re-lock) → forward exit status
  ▼
Real git runs with user's uid/gid, sanitised env, no extra caps
```

## Blocked Operations (18 Policy Rules)

### Unconditionally Blocked Subcommands
`reset`, `clean`, `restore`, `rebase`, `gc`, `prune`, `bisect`,
`filter-branch`, `filter-repo`, `worktree`, `reflog`, `replace`,
`lfs`, `daemon`, `fast-import`

### Sudo-Gated Subcommands (denied for non-root; allowed for root via `sudo`)
`submodule`, `checkout`

### Flag-Gated Blocks

| Trigger | Effect |
|---------|--------|
| `git rm` without `--cached` | Blocks removal from disk |
| `git stash drop` / `stash clear` | Blocks stash stack destruction |
| `git branch -D` / `-M` | Blocks force-delete/rename |
| `git tag -f` / `-d` / `-D` | Blocks tag mutation |
| `git push --force` / `-f` / `--force-with-lease` | Blocks forced pushes |
| `git push --delete` / `-d` | Blocks remote branch deletion |
| `git commit --amend` | Blocks history rewriting |
| `git revert` (unpushed target) | Blocks reverting un-pushed work |
| `git pull` (protected branch, no `--ff-only`/`--rebase`) | Blocks merge-commit pulls |
| `git merge` (protected branch, no `--ff-only`/`--abort`) | Blocks merge-commit merges; `--abort` cancels an in-progress merge |
| Background `git push` (pgrp != tpgid from /proc/self/stat) | Blocks CI/non-TTY pushes |
| `SKIP=` env var present | Blocks pre-commit hook bypass |
| `PRE_COMMIT_ALLOW_NO_CONFIG=1` env var | Blocks pre-commit config bypass |

### Protected Branches
`main`, `master`, `develop`, `production`, `staging`, `release`, `release/*`

### Immediate-Fail Flags (Blocked During Parsing)
`--hard`, `--no-verify`, `-n`, `-N`, `--upload-pack`, `--receive-pack`, `--exec`,
any `\0` byte in arguments

## Dangerous Config Key Patterns (96 Patterns)

The `-c`/`-C`/`--config`/`--config-env` flags are intercepted. A dynamic
programming glob matcher checks each key against 96 patterns covering:

| Category | Examples |
|----------|----------|
| Core internals | `core.hookspath`, `core.sshcommand`, `core.fsmonitor`, `core.pager` |
| Protocol | `protocol.*.allow`, `protocol.allow` |
| Safe directory | `safe.directory` |
| Include files | `include.path`, `includeif.**.path` |
| Aliases | `alias.*` |
| URL redirects | `url.**.insteadof` |
| Credentials | `credential.helper`, `credential.**.helper` |
| HTTP/HTTPS | `http.proxy`, `http.sslverify`, `http.sslcainfo`, `http.extraheader` |
| Filters | `filter.*.clean`, `filter.*.smudge` |
| Diff/Merge tools | `diff.*.textconv`, `difftool.*.cmd`, `mergetool.*.cmd` |
| Remotes | `remote.*.proxy`, `remote.*.uploadpack`, `remote.*.receivepack` |
| Submodules | `submodule.*.url`, `submodule.recurse` |

Glob syntax: `*` matches one config-key segment (between dots), `**` matches
zero or more segments. Keys are matched case-insensitively.

## Sudo-Gated Keys & Environment Variables

Certain user-identity and editor settings are **not** in the always-allowed
env list or the always-dangerous config list: they are *sudo-gated*. An
invocation is privileged when the real UID is 0 (`getuid()==0`, i.e. the guard
was run via `sudo`/as root).

**Config keys** (`-c`/`-C`/`--config`/`--config-env`/`git config <key>`):
`core.editor`, `sequence.editor`, `user.name`, `user.email`, `user.signingkey`.

| Caller | Behavior |
|--------|----------|
| Non-root | Blocked (exit 1 + audit) |
| Root (`sudo`) | Allowed |

**Environment variables:** `EDITOR`, `VISUAL`, `GIT_EDITOR`,
`GIT_SEQUENCE_EDITOR`, `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`,
`GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, `EMAIL`.

| Caller | Behavior |
|--------|----------|
| Non-root | **Dropped** (not passed to the child) with an explicit warning to stderr, `/dev/tty`, and the audit log. The command still runs. |
| Root (`sudo`) | Passed through to the child |

The guard cannot distinguish an inline `export X=... && git` from a var that
was exported beforehand; both simply appear in the child's `envp`. So any
presence of a gated env var under non-root is treated uniformly: warn + drop.
Every dropped variable emits an explicit warning.

Warning strings:

- Identity vars: `[<VAR>] NON-ROOT USER HAS SET CUSTOM GIT CONFIG COMMITTER DATA - IGNORING.`
- Editor vars: `[<VAR>] NON-ROOT USER HAS SET CUSTOM GIT EDITOR - IGNORING.`

## Environment Sanitization

The guard **constructs the child environment from scratch** using an allow-list
rather than stripping dangerous variables. This is a closed surface: future
glibc or git variables cannot sneak through.

**Allowed variables (18):** `HOME`, `USER`, `LANG`, `LC_ALL`, `LC_CTYPE`,
`LC_COLLATE`, `LC_MESSAGES`, `LC_MONETARY`, `LC_NUMERIC`, `LC_TIME`, `TERM`,
`DISPLAY`, `WAYLAND_DISPLAY`, `SSH_AUTH_SOCK`, `GPG_TTY`, `PINENTRY_USER_DATA`,
`SHELL`, `PWD`. (The 9 user-identity/editor vars `GIT_AUTHOR_*`,
`GIT_COMMITTER_*`, `EMAIL`, `EDITOR`, `VISUAL`, `GIT_EDITOR`,
`GIT_SEQUENCE_EDITOR` are sudo-gated; see above.)

**Hardcoded:** `PATH=/usr/local/bin:/usr/bin:/bin`

**Injected for safety:** `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=safe.directory`,
`GIT_CONFIG_VALUE_0=*`: suppresses git's own repository ownership checks since
the guard handles authorization.

## `.git` Ownership Lock

Capability mode adds a runtime `.git` ownership lock that closes the local RCE
attack surface created by user-writable `.git/` internals. The guard claims the
**entire** `.git/` directory tree as `root:root`: every file, every subdirectory.
Users cannot directly write to ANY part of `.git/`. They can still operate the
repository normally because the guard grants `CAP_DAC_OVERRIDE` to `git.original`
via the Ambient capability set for the duration of the authorized subcommand only.

The lock runs **twice** per invocation:
1. **Before the policy engine**: closes the window where a planted `.git/config`
   payload could fire during policy-check sub-calls (`rev-parse --show-toplevel`,
   `merge-base --is-ancestor`, etc.).
2. **After `git.original` exits**: reclaims any files that git.original created
   or modified (which will be owned by the real user's uid) back to `root:root`.
   This closes the "backdoor" window where the user could write to agent-owned
   `.git/` files between git operations. The re-lock runs in the parent process
   immediately after `waitpid()` returns, before `process::exit()`.

### How it works

1. Resolves the repository's `.git` directory via
   `git.original rev-parse --absolute-git-dir` under a **hardened environment**
   that injects `core.fsmonitor=`, `core.hooksPath=`, `GIT_CONFIG_NOSYSTEM=1`,
   `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null` via `GIT_CONFIG_*`
   overrides. This neutralises any payload already planted in `.git/config` for
   the resolution call itself.
2. **Recursively** `chown`s the entire `.git/` directory tree to `root:root` and
   `chmod`s every entry so a non-root user can READ/TRAVERSE but not WRITE/EXEC:

   | Path type | Mode | Effect |
   |-----------|------|--------|
   | `.git/` (dir itself) | 0o755 | Traversable by all, only root can create/rename entries |
   | `.git/**/` (all subdirs) | 0o755 | Same: traversable, root-writable |
   | `.git/**` (all files) | 0o644 | World-readable, root-writable only |
   | `.git/hooks/*` (hook files) | 0o755 | Executable so git invokes them; root-writable only |
   | repo-root `.gitmodules` | 0o644 | User cannot redirect submodule paths (CVE-2025-48384 family) |

3. Symlinks inside `.git/` are `lchown`'d to root:root (no recursion through them).
4. The lock is **idempotent**: if a path is already `root:root` with the target
   mode, no `chown`/`chmod` syscall is issued, so the per-invocation overhead
   after the first lock is a metadata `stat` only.
5. The lock is **best-effort**: a failure on a single path is
   ignored and the lock continues. Locking MUST NEVER break a legitimate git
   invocation that already passed the policy engine.
6. The lock is **skipped under `sudo`** (real UID 0): root already owns the
   paths, and the policy engine's sudo-gated passthrough applies.

### Capability flow

The guard binary has 5 file capabilities:
`cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid+ep`.

At startup, `raise_ambient_caps()` raises all 5 into the **Inheritable** set
but does NOT raise anything into **Ambient**. This means:
- Policy-check sub-calls (block.rs `git_cmd()`): fork+exec git.original from
  the parent) get **no caps** because ambient is empty → least-privilege read.
- The main exec path (`execve_real_git`) forks → child raises
  `CAP_DAC_OVERRIDE` into its **Ambient** set → execs git.original.
  git.original (a non-privileged binary) inherits `CAP_DAC_OVERRIDE` in
  effective+permitted+ambient → can write to root-owned `.git/` files.
  When git.original exits, the capability dies with the process.

`CAP_SETPCAP` is required in effective (from file caps) for the child to call
`cap_set_ambient()`. On kernels with VFS caps, `CAP_SETPCAP` only allows
modifying your own process's cap sets (low blast radius).

### Threat model closed by the lock

| Threat | Vector | Mitigation |
|--------|--------|------------|
| `core.fsmonitor` RCE | Attacker plants `core.fsmonitor = malicious-cmd` in `.git/config`; any `git status`/`git add` fires it | `.git/config` is root-owned read-only; user cannot write the key |
| `core.hooksPath` RCE | Attacker redirects hooks to a worktree directory they control | `.git/config` root-owned; hooks dir root-owned |
| `.git/hooks/` trojan | Attacker drops an executable `post-checkout`/`pre-commit` script | Hooks dir root-owned; hook files 0o755 but root-writable only (user cannot create/modify them) |
| `.git/index` corruption | Attacker writes a crafted index to force staging of unwanted files | `.git/index` is root-owned read-only; re-locked after each git run |
| `.git/HEAD` redirection | Attacker points HEAD at a crafted ref to cause unintended branch operations | `.git/HEAD` is root-owned read-only |
| `.git/refs/` forging | Attacker creates/modifies branch/tag pointers | `.git/refs/` is root-owned; user cannot create or modify refs |
| `.git/objects/` planting | Attacker plants fake commits/trees in the object store | `.git/objects/` is root-owned; user cannot write objects |
| `.git/logs/` reflog forging | Attacker forges reflog history to hide destructive operations | `.git/logs/` is root-owned read-only |
| `include.path` injection | Attacker points `.git/config` `include.path` at a worktree file they control | `.git/config` root-owned read-only |
| CVE-2025-48384 submodule hook | Trailing-CR in `.gitmodules` path + symlink pivot into submodule `.git/hooks` | Repo-root `.gitmodules` root-owned read-only |
| Embedded bare repo (`core.fsmonitor`) | Planted `.git/config` in a worktree subdirectory triggers `core.fsmonitor` on `git status` from that dir | Resolving `git.original rev-parse` runs under hardened env (`core.fsmonitor=` forced empty); subsequent real git run hits the locked `.git/config` |

### Hook installation under the lock

Because `.git/hooks/*` files are root-owned in capability mode, hook
installation must run **as root** so the script can write into the root-owned
hooks directory:

```bash
sudo make install-hooks
```

The WORKSPACE-CI `generate-hooks` flow is invoked through the guard (it runs
`git` internally) and inherits the caps via the SUID-equivalent file-capability
binary, so the hooks it writes are owned `root:root` with the exec bit set.

User-invoked hook changes (e.g. `core.hooksPath` from the user's shell) are
blocked at two layers: the guard's `-c` config key filter (see Dangerous Config
Key Patterns), and the lock itself (the user cannot write `.git/config` or
`.git/hooks/`).

### Documented residual risk

Two hardening flags are documented but **not yet globally enforced**:

- **`safe.bareRepository=explicit`**: git's own defence against embedded bare
  repos (CVE-2025-48384 family). The guard already injects this for its own
  `rev-parse` resolution call, but does NOT inject it into the child `git`
  invocation. Enforcing globally requires git >= 2.39 and would change behaviour
  for legitimate bare-repo workflows. Tracked in
  `docs/specifications/SPEC-GIT-GUARD-HARDENING.md`.
- **Pre-existing payloads**: the lock is **locking-only**: it does NOT strip
  dangerous entries already present in `.git/config` before the first lock. A
  payload planted before the guard is installed will be muted for the guard's
  own `rev-parse` call (hardened env) but could still fire if the user runs
  `git.original` directly (blocked by 0700 perms) or if a future guard run
  fails to inject the hardened env. Mitigation: install the guard before
  untrusted users get shell access, or audit `.git/config` post-install.
- **Transient agent-owned files**: during a git operation, `git.original`
  creates new files (e.g. `.git/index.lock`, new objects) owned by the real
  user's uid. The re-lock (step 2) reclaims these immediately after git.original
  exits, but a sub-microsecond window exists between `waitpid` return and the
  re-lock's `chown`. An attacker with a pre-positioned process could write to
  agent-owned files in that window. Mitigation: the re-lock runs synchronously
  before `process::exit()`, so the window is bounded by syscall latency.

## WORKSPACE-CI Contract Enforcement

Before `git commit` and `git push`, the guard:
1. **(capability mode)** Locks the entire `.git/` directory tree to
   `root:root` (see [`.git` Ownership Lock](#git-ownership-lock))
2. Finds the git repository root via `git.original rev-parse --show-toplevel`
3. Walks up the directory tree to locate the workspace root (marked by
   `.boot-linux/`, `projects/CI/`, and `workspace/scripts/utils/git-guard`)
4. Checks for **vendored tier bypass**: reads
   `workspace/config/project_enforcement.yaml`, parses exemptions manually
   (no YAML dependency), blocks if the current project is exempted as
   `"vendored"` (quality gates disabled)
5. Shell-execs `<workspace-root>/projects/CI/lib/checks_quality.sh` with
   environment variables (`WORKSPACE_GGUARD_CMD`, `WORKSPACE_GGUARD_REPO_ROOT`,
   `WORKSPACE_GGUARD_WORKSPACE_ROOT`)
6. Returns exit code 4 on contract failure

Delegating to a shell script avoids re-implementing YAML parsing and CI policy
logic in Rust, keeping the binary thin and the policy engine as the single
source of truth.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Operation allowed, real git ran successfully |
| 1 | Policy block: destructive or disallowed operation |
| 2 | Infrastructure error: missing caps, missing git.original, bad permissions, null bytes |
| 4 | WORKSPACE-CI contract failure |
| (real git exit) | Forwarded from `/usr/bin/git.original` |

## Audit Log

Every blocked operation is logged to **`~/.workspace-guard.log`** with:

```
<timestamp>|<cwd>|git <command>|<reason>|uid=<uid>
```

The home directory is resolved via `libc::getpwuid()` using the **real UID**
(not `$HOME` which can be spoofed). Block messages are written to **both
stderr and `/dev/tty`**: the `/dev/tty` write ensures visibility even when
stderr is redirected.

## Deployment

Installation is orchestrated through the WORKSPACE-CI repo (its `pre-req.sh`
builds and installs the guard, configures `dpkg-divert`, `chattr`, apt hooks,
and restricts alternate git binaries). The WORKSPACE-GUARD repo provides the
source, build, test, and lint targets. The two repos coordinate via the
`make build-guard` / `make install-guard` / `make check-guard` targets in
WORKSPACE-GUARD's Makefile, which WORKSPACE-CI's `pre-req.sh` invokes.

### Capability Mode (production)

```bash
# From the WORKSPACE-CI repo root (as root):
sudo make pre-req            # Full install: deps + build guard + install + hooks

# Or, step-by-step from the WORKSPACE-GUARD repo root:
make build-guard             # Build the Rust binary (release)
sudo make install-guard      # Install (requires root: setcap, dpkg-divert, chattr)
make check-guard             # Verify installation

# What happens during install-guard:
#   1. Relocate /usr/bin/git -> /usr/bin/git.original (0700 root:root)
#   2. Install guard as /usr/bin/git (0755)
#   3. setcap 'cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid+ep' /usr/bin/git
#      (5 caps: SETPCAP so forked child can raise DAC_OVERRIDE into Ambient,
#       DAC_OVERRIDE for git.original to write root-owned .git/,
#       CHOWN+FOWNER+FSETID for the .git ownership lock)
#   4. Set up dpkg-divert to protect from apt overwrites
#   5. Attempt chattr +i on both binaries (skipped if unavailable)
#   6. Register apt post-invoke hook at /etc/apt/apt.conf.d/99workspace-guard
#   7. Restrict alternate git binaries (/snap/bin/git, /usr/local/bin/git)
#   8. Create /var/log/workspace-guard/ (1777) for system-wide audit trail

# Hook installation (REQUIRED as root in capability mode):
#   Because gitdir::lock() recursively claims the entire .git/ tree as
#   root:root (hooks kept 0o755 executable, rest 0o644), hook installation
#   must run as root so it can write into the root-owned hooks dir. The
#   WORKSPACE-CI generate-hooks flow inherits the guard's caps when it runs
#   git internally.
sudo make install-hooks      # Regenerate native git hooks (requires root)

# Uninstall:
sudo make uninstall-guard
```

### Root-Only Mode (PRoot, containers)

```bash
# The bootstrap script auto-detects root-only mode when setcap is unavailable:
make build-guard
make install-guard

# Manual:
cargo build --release --no-default-features --features root-only
cp target/release/workspace-guard /usr/bin/git.guard
mv /usr/bin/git /usr/bin/git.original
ln -s /usr/bin/git.guard /usr/bin/git
```

In root-only mode `make install-hooks` does NOT require sudo (the user is
already root) and `gitdir::lock()` is a no-op (the module is `#[cfg(feature =
"capability-mode")]` only).

## Development

```bash
cargo build                                              # Debug (capability-mode)
cargo build --no-default-features --features root-only   # Debug (root-only)
cargo build --release                                    # Release (opt-level=z, LTO, abort-on-panic, stripped)
cargo test                                               # Cap mode: 88 unit + 3 integration tests
cargo test --no-default-features --features root-only    # Root-only: 82 unit + 3 integration tests
cargo fmt --all -- --check                               # Format check
cargo clippy --workspace --all-targets -- -D warnings    # Strict lint
make test                                                # Full workspace test suite (cargo test + integration)
```

## Project Structure

```
WORKSPACE-GUARD/
├── Cargo.toml                  # Deps: libc (FFI), caps (optional, capability-mode)
├── Cargo.lock                  # Locked dependency tree
├── Makefile                    # Build, test, lint, compliance (includes CI contract)
├── .pre-commit-config.yaml     # 14 hooks: Rust + WORKSPACE-CI quality gates
├── .cargo/config.toml          # Linker config (system gcc for GNU target)
├── quality_exceptions.yaml     # WORKSPACE-CI compliance (empty: fully compliant)
├── config/
│   ├── banned_words_exceptions.yaml    # Allows `unsafe` in FFI code
│   ├── coverage_thresholds.yaml        # min_coverage: 1 (placeholder)
│   └── sensitive_files_exceptions.yaml # Allows .cargo/config.toml
├── docs/
│   ├── ROOT-ONLY-MODE.md              # Root-only threat model and limitations
│   ├── requirements/
│   │   └── REQ-GIT-GUARD.md           # Requirements document
│   └── specifications/
│       ├── SPEC-GIT-GUARD.md          # Architecture spec
│       ├── SPEC-GIT-GUARD-IMPL.md     # Implementation spec
│       ├── SPEC-GIT-GUARD-INSTALL.md  # Installation spec
│       └── SPEC-GIT-GUARD-HARDENING.md # System hardening spec
├── src/
│   ├── main.rs                 # Entry point, run(), config tables, DP glob matcher
│   ├── args.rs                 # ArgState parser, subcommand abbreviation, null-byte check
│   ├── block.rs                # 17-rule policy engine, proc/self/stat background detection
│   ├── exec.rs                 # File cap checks, execve, env construct, CI contract
│   ├── gitdir.rs               # Capability-mode .git recursive ownership lock
│   ├── config_keys.rs          # Dangerous/glob config key matching (96 patterns)
│   ├── log.rs                  # block() diverging fn, audit logging, /dev/tty output
├── tests/
│   └── integration_test.rs     # Operations: cap check, compile, blocked cmd
└── README.md
```

## Security Properties

1. **Compiled enforcement**: Guard logic is opaque binary, not readable or editable
2. **Ambient cap for child only**: The guard keeps Ambient empty at startup.
   Policy-check sub-calls get NO caps (least-privilege). The authorized child
   raises `CAP_DAC_OVERRIDE` into its own Ambient set before exec'ing
   `git.original`; the cap dies with the child on exit.
3. **File capabilities**: `CAP_SETPCAP+CHOWN+DAC_OVERRIDE+FOWNER+FSETID+ep` is
   granular, `NO_NEW_PRIVS`-safe, and keeps privilege analysis straightforward.
   `CAP_SETPCAP` is needed so the forked child can call `cap_set_ambient()`;
   on VFS-cap kernels it only lets you modify your own process's cap sets.
4. **`dpkg-divert` protected**: `apt` cannot overwrite `/usr/bin/git`: divert
   redirects to `git.distrib`
5. **`.git` ownership lock** (capability mode): the guard recursively
   chowns the **entire** `.git/` directory tree to `root:root` (0o755 dirs,
   0o644 files, 0o755 hooks) on every invocation, so a non-root user can
   read/traverse but not write to any part of `.git/`. Hooks stay executable
   so git invokes them (non-exec hooks are skipped by git, resulting in no enforcement).
   The lock runs twice: before the policy engine and after `git.original`
   exits (re-locking files the child created as agent-owned). See
   [`.git` Ownership Lock](#git-ownership-lock)
6. **Hardened rev-parse resolution**: the guard's own `git.original
   rev-parse --absolute-git-dir` call (used to locate `.git`) runs under a
   forced env that disables `core.fsmonitor`, `core.hooksPath`, and system
   config, neutralising any payload already planted in `.git/config` for
   the resolution call. Policy-check sub-calls in `block.rs` use the same
   hardened env.
7. **Allow-list environment**: Only 18 whitelisted variables reach the child;
   `PATH` is hardcoded; `safe.directory=*` injected to suppress ownership checks
8. **No core dumps**: `RLIMIT_CORE=0` prevents memory disclosure from crashes
9. **File descriptor limits**: `RLIMIT_NOFILE=256` prevents fd exhaustion attacks
10. **Null byte rejection**: `\0` in any argument immediately exits with error
11. **Audit trail**: Every block written to `~/.workspace-guard.log` (via real UID
    lookup, not spoofable `$HOME`) and `/dev/tty` for visibility
12. **Background push detection**: `/proc/self/stat` check prevents CI/daemon
    pushes without interactive oversight
13. **Release hardening**: `opt-level=z, lto=true, codegen-units=1,
    panic=abort, strip=true` for smallest attack surface
14. **2-second subprocess timeout**: Prevents hung git subprocesses from
    blocking the guard indefinitely
15. **Log symlink protection**: `O_NOFOLLOW` on all log file opens prevents
    symlink attacks on `~/.workspace-guard.log`
16. **HOME spoofing prevention**: Home directory resolved via `getpwuid(getuid())`,
    never from `$HOME` environment variable

## Subcommand Abbreviation

Git-style abbreviation is supported: `git com` resolves to `commit`, `git cl`
to `clean`, `git da` to `daemon`. Ambiguous prefixes pass through unchanged and
are rejected by real git with its own error. Case-insensitive matching.

## `--` Separator

Arguments after `--` are treated as pathspecs and bypass all flag parsing,
matching git's own behavior. `git -- force` interprets `force` as a pathspec,
not a flag. `git stash -- drop` interprets `drop` as a pathspec, not a stash
command.

## Framework Design

WORKSPACE-GUARD is a **framework** for hardening access to any tool via the
same caps + compiled policy pattern. The initial PoC targets `git`, but
the architecture supports extending to other binaries (ssh, rsync, make, etc.)
by creating separate guard crates with their own allow/block lists.

The binary is ~1,600 lines of Rust across 5 modules (guard). The only
dependencies are `libc` (FFI: fork, execve, waitpid, getuid, setrlimit,
localtime_r) and `caps` (optional, Linux capability management: only needed
for capability mode). No YAML, HTTP, or async dependencies: the binary
stays small and auditable.

## License

Internal. Independent AI Labs.
