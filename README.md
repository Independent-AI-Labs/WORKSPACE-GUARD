# Compiled Privilege Enforcement for Git

A Rust binary that replaces `/usr/bin/git` to enforce immutable, unbypassable
policies on destructive and history-rewriting operations. Uses **file
capabilities** (`CAP_DAC_OVERRIDE`): more granular, correctly handles
`NO_NEW_PRIVS` contexts, and keeps privilege analysis straightforward.

For environments where file capabilities are unavailable (PRoot, containers
running as root, user namespaces), a **root-only mode** provides a soft barrier
with the same policy engine but reduced bypass resistance.

## Deployment Modes

| Mode | Feature Flag | Enforcement Level | Requires | Suitable For |
|------|-------------|-------------------|----------|-------------|
| Capability (default) | `--features capability-mode` (default) | Hard barrier | `setcap`, `chattr`, `dpkg-divert` | Production, non-root users |
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

1. Installing a **compiled Rust binary** as `/usr/bin/git` (mode 0755, with
   `CAP_DAC_OVERRIDE` file capability)
2. Relocating the real git to `/usr/bin/git.original` (mode **0700 root:root**
  : unreadable and unexecutable by non-root)
3. Guarding all arguments, config keys, and environment **before** `execve()`-ing
   the real binary
4. Sanitizing the execution environment from scratch (18-variable allow-list,
   hardcoded `PATH`, injected `safe.directory=*` to suppress ownership checks)

The user cannot bypass the guard: they cannot read, modify, or directly execute
`/usr/bin/git.original`, and the compiled binary logic is opaque.

## Architecture

### Capability Mode (default)

```
User: git push --force
  │
  ▼
/usr/bin/git  (compiled Rust guard, file capabilities CAP_DAC_OVERRIDE)
  │
  ├─ check: CAP_DAC_OVERRIDE present?               → MissingCap → exit 2
  ├─ setrlimit(NOFILE=256, CORE=0)                   ← resource limits
  ├─ raise_ambient_caps()                            ← elevate for file access
  ├─ parse_args(&argv) → ArgState                    ← subcommand, flags, -c keys
  │    └─ check_null_bytes, resolve abbreviations,
  │       detect --amend, --force, --hard, --no-verify, -n/-N,
  │       --upload-pack, --receive-pack, --exec, --delete,
   │       parse -c/-C config keys against 96-pattern glob list
  ├─ check_blocked(&state, &argv)                    ← policy engine (17 rules)
  │    └─ blocked? → BLOCKED + audit log → exit 1
  ├─ check_workspace_ci_contract(subcommand)         ← commit/push only
  │    └─ contract failed? → exit 4
  ├─ verify_git_original()                           ← exists? uid=0? mode=0700?
  ├─ construct child envp from ALLOWED_VARS (22 vars)
  ├─ fork()
  │    ├─ child: clear_child_caps(), execve(/usr/bin/git.original, argv, envp)
  │    └─ parent: waitpid(), forward exit status
  ▼
Real git runs with user's uid/gid, sanitised env, no extra caps
```

## Blocked Operations (17 Policy Rules)

### Unconditionally Blocked Subcommands
`reset`, `checkout`, `clean`, `restore`, `rebase`, `gc`, `prune`, `bisect`,
`filter-branch`, `filter-repo`, `submodule`, `worktree`, `reflog`, `replace`,
`lfs`, `daemon`, `fast-import`

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
| `git merge` (protected branch, no `--ff-only`) | Blocks merge-commit merges |
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

## WORKSPACE-CI Contract Enforcement

Before `git commit` and `git push`, the guard:
1. Finds the git repository root via `git.original rev-parse --show-toplevel`
2. Walks up the directory tree to locate the workspace root (marked by
   `.boot-linux/`, `projects/CI/`, and `workspace/scripts/utils/git-guard`)
3. Checks for **vendored tier bypass**: reads
   `workspace/config/project_enforcement.yaml`, parses exemptions manually
   (no YAML dependency), blocks if the current project is exempted as
   `"vendored"` (quality gates disabled)
4. Shell-execs `<workspace-root>/projects/CI/lib/checks_quality.sh` with
   environment variables (`WORKSPACE_GGUARD_CMD`, `WORKSPACE_GGUARD_REPO_ROOT`,
   `WORKSPACE_GGUARD_WORKSPACE_ROOT`)
5. Returns exit code 4 on contract failure

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

### Capability Mode (production)

```bash
# From the WORKSPACE-CI repo root:
make build-guard        # Build the guard binary
make install-guard      # Install (requires root: setcap, dpkg-divert, chattr)
make check-guard        # Verify installation

# What happens:
#   1. Build the Rust binary (release: LTO, single codegen unit, abort-on-panic, stripped)
#   2. Relocate /usr/bin/git → /usr/bin/git.original (0700 root:root)
#   3. Install guard as /usr/bin/git (0755, file capability CAP_DAC_OVERRIDE)
#   4. Set up dpkg-divert to protect from apt overwrites
#   5. Attempt chattr +i on both binaries (skipped if unavailable)
#   6. Register apt post-invoke hook at /etc/apt/apt.conf.d/99workspace-guard
#   7. Restrict alternate git binaries (/snap/bin/git, /usr/local/bin/git)
#   8. Create /var/log/workspace-guard/ (1777) for system-wide audit trail

# Uninstall:
make uninstall-guard
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

## Development

```bash
cargo build                                              # Debug (capability-mode)
cargo build --no-default-features --features root-only   # Debug (root-only)
cargo build --release                                    # Release (opt-level=z, LTO, abort-on-panic, stripped)
cargo test                                               # 73 unit + 3 integration tests
cargo test --no-default-features --features root-only    # 72 unit + 3 integration tests
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
│   ├── log.rs                  # block() diverging fn, audit logging, /dev/tty output
├── tests/
│   └── integration_test.rs     # Operations: cap check, compile, blocked cmd
└── README.md
```

## Security Properties

1. **Compiled enforcement**: Guard logic is opaque binary, not readable or editable
2. **No privilege retained**: Capabilities cleared in child before `execve`: real
   git runs as the user, not with elevated caps
3. **File capabilities**: `CAP_DAC_OVERRIDE` is granular,
   `NO_NEW_PRIVS`-safe, and keeps privilege analysis straightforward
4. **dpkg-divert protected**: `apt` cannot overwrite `/usr/bin/git`: divert
   redirects to `git.distrib`
5. **Allow-list environment**: Only 18 whitelisted variables reach the child;
   `PATH` is hardcoded; `safe.directory=*` injected to suppress ownership checks
6. **No core dumps**: `RLIMIT_CORE=0` prevents memory disclosure from crashes
7. **File descriptor limits**: `RLIMIT_NOFILE=256` prevents fd exhaustion attacks
8. **Null byte rejection**: `\0` in any argument immediately exits with error
9. **Audit trail**: Every block written to `~/.workspace-guard.log` (via real UID
   lookup, not spoofable `$HOME`) and `/dev/tty` for visibility
10. **Background push detection**: `/proc/self/stat` check prevents CI/daemon
    pushes without interactive oversight
11. **Release hardening**: `opt-level=z, lto=true, codegen-units=1,
    panic=abort, strip=true` for smallest attack surface
12. **2-second subprocess timeout**: Prevents hung git subprocesses from
    blocking the guard indefinitely
13. **Log symlink protection**: `O_NOFOLLOW` on all log file opens prevents
    symlink attacks on `~/.workspace-guard.log`
14. **HOME spoofing prevention**: Home directory resolved via `getpwuid(getuid())`,
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
