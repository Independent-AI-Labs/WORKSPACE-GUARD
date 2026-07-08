# Compiled Privilege Enforcement for the Linux SUID & Capability Surface

WORKSPACE-GUARD is a framework that replaces exploitable SUID and
file-capability binaries on a Linux host with a compiled, policy-gating shim.
The shim validates arguments, configuration keys, and environment before
`execve()`-ing the real binary, which has been relocated to a mode-0700
`root:root` location the untrusted user can neither read nor execute directly.
The same pattern applies to every privileged entry point on the box, not just
one tool.

Two programs ship in this repo today:

| Program | Target surface | State |
|---------|----------------|-------|
| **Git Guard** (Program I) | `/usr/bin/git` only | Built, deployed, tested (90 unit + 3 integration tests) |
| **System-Binary Lockdown + Sandbox + Audit** (Program II) | Full GTFOBins SUID + file-capability catalog | Baselines, specs, sync + drift scripts, config artifacts; runtime install pending |

Both programs share the same core mechanics, described next. Detail for each
program follows. Architecture lives in `docs/specifications/`; tooling in
`scripts/`; policies in `config/`.

## The Guard Pattern

Every instance of the framework applies the same five steps:

1. **Relocate.** Move the real binary from its public path to
   `<path>.original` (git guard) or `<path>.real` (system-binary lockdown),
   mode 0700 `root:root`: unreadable and unexecutable by non-root.
2. **Install.** Place a compiled Rust shim (git guard, ~1,600 lines, 5
   modules) or a shell-driven guard layer (system-binary lockdown) at the
   public path, with a minimal set of Linux file capabilities.
3. **Gate.** Before `execve()` of the real binary, the shim validates the
   full argument vector, intercepted `-c`/`--config` keys, and the
   environment. Anything matching a deny rule is blocked and audited.
4. **Contain.** For authorized invocations, the real binary runs under a
   sanitised, allow-list environment with resource limits (`NOFILE=256`,
   `CORE=0`) and, in capability mode, a scoped `CAP_DAC_OVERRIDE` loaned to
   the child via the Ambient set that dies when the child exits.
5. **Audit.** Every block is written to an audit log (resolved via the real
   UID, not spoofable `$HOME`) and to `/dev/tty` for visibility.

File capabilities are granular, safe under `NO_NEW_PRIVS`, and simple to
audit. `dpkg-divert` protects the shim from `apt` overwrites; `chattr +i`
makes the relocated real binary immutable.

## Program I: Git Guard

A Rust binary replaces `/usr/bin/git` to enforce immutable, unbypassable
policies on destructive and history-rewriting operations.

### Deployment modes

| Mode | Feature flag | Enforcement | Requires | Suitable for |
|------|-------------|-------------|----------|-------------|
| Capability (default) | `--features capability-mode` (default) | Hard barrier | `setcap 'cap_setpcap,cap_chown,cap_dac_override,cap_fowner,cap_fsetid+ep'`, `chattr`, `dpkg-divert` | Production, non-root users |
| Root-only | `--features root-only` | Soft barrier | Root only | PRoot, containers, CI agents as root |

See [docs/ROOT-ONLY-MODE.md](docs/ROOT-ONLY-MODE.md) for the root-only threat
model.

### Blocked operations

18 policy rules cover three classes:

- **Unconditional subcommand blocks**: `reset`, `clean`, `restore`, `rebase`,
  `gc`, `prune`, `bisect`, `filter-branch`, `filter-repo`, `worktree`,
  `reflog`, `replace`, `lfs`, `daemon`, `fast-import`.
- **Sudo-gated subcommands** (denied for non-root, allowed via `sudo`):
  `submodule`, `checkout`.
- **Flag-gated blocks**: `rm` without `--cached`, `stash drop`/`clear`
  (non-root), `branch -D`/`-M`, `tag -f`/`-d`/`-D`, `push --force`/`-f`/
  `--force-with-lease`, `push --delete`, `commit --amend`, `revert` (unpushed
  target), `pull` (protected branch, no `--ff-only`/`--rebase`), `merge`
  (protected branch, no `--ff-only`/`--abort`, non-root), background `push`
  (`pgrp != tpgid`), `SKIP=` env, `PRE_COMMIT_ALLOW_NO_CONFIG=1` env.

Protected branches: `main`, `master`, `develop`, `production`, `staging`,
`release`, `release/*`.

Immediate-fail flags (rejected during parsing): `--hard`, `--no-verify`,
`-n`, `-N`, `--upload-pack`, `--receive-pack`, `--exec`, any null byte.

Full rule table and decision engine: [SPEC-GIT-GUARD.md §4](docs/specifications/SPEC-GIT-GUARD.md)

### Config key interception

`-c`/`-C`/`--config`/`--config-env` keys are matched against 96 glob patterns
covering core internals (`core.hooksPath`, `core.fsmonitor`, `core.sshCommand`),
protocol, `safe.directory`, `include.path`, aliases, URL redirects,
credentials, HTTP/HTTPS, filters, diff/merge tools, remotes, and submodules.
Syntax: `*` matches one segment, `**` matches zero or more. Case-insensitive.

Sudo-gated config keys (`core.editor`, `sequence.editor`, `user.name`,
`user.email`, `user.signingkey`) are blocked for non-root, allowed for root.
Sudo-gated env vars (`EDITOR`, `VISUAL`, `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`,
`GIT_AUTHOR_*`, `GIT_COMMITTER_*`, `EMAIL`) are dropped for non-root with an
explicit warning, passed through for root.

Full list: [SPEC-GIT-GUARD.md §3](docs/specifications/SPEC-GIT-GUARD.md) and
[§5](docs/specifications/SPEC-GIT-GUARD.md)

### Environment sanitisation

The child environment is constructed from scratch from an 18-variable allow-list
(`HOME`, `USER`, locale, `TERM`, display, `SSH_AUTH_SOCK`, `GPG_TTY`, `SHELL`,
`PWD`). `PATH` is hardcoded. `safe.directory=*` is injected to suppress git's
ownership checks. This is a closed surface: future glibc or git variables cannot
sneak through.

Detail: [SPEC-GIT-GUARD.md §5](docs/specifications/SPEC-GIT-GUARD.md)

### `.git` ownership lock (capability mode)

The guard recursively `chown`s the entire `.git/` directory tree to
`root:root` (0o755 dirs, 0o644 files, 0o755 hooks) so a non-root user can
read/traverse but not write to any part of `.git/`. The lock runs twice per
invocation: before the policy engine (closes planted-config windows during
policy-check sub-calls) and after `git.original` exits (reclaims
agent-owned files the child created). Idempotent, best-effort, skipped under
`sudo`.

This closes 11 local-RCE vectors: `core.fsmonitor` RCE, `core.hooksPath`
redirect, `.git/hooks/` trojaning, `.git/index` corruption, `.git/HEAD`
redirection, `.git/refs/` forging, `.git/objects/` planting, reflog forging,
`include.path` injection, CVE-2025-48384 submodule hook, and embedded bare
repo trigger. Full threat model table:
[SPEC-GIT-GUARD-HARDENING.md §11.7](docs/specifications/SPEC-GIT-GUARD-HARDENING.md)

### WORKSPACE-CI contract enforcement

Before `git commit` and `git push`, the guard locates the workspace root,
checks for vendored-tier bypass, and delegates to
`projects/CI/lib/checks_quality.sh`. Returns exit code 4 on contract failure.
Detail: [SPEC-GIT-GUARD.md §6](docs/specifications/SPEC-GIT-GUARD.md)

### Git guard exit codes

| Code | Meaning |
|------|---------|
| 0 | Operation allowed, real git ran successfully |
| 1 | Policy block: destructive or disallowed operation |
| 2 | Infrastructure error: missing caps, missing git.original, bad permissions, null bytes |
| 4 | WORKSPACE-CI contract failure |
| (real git exit) | Forwarded from `/usr/bin/git.original` |

### Audit log

Every blocked operation is logged to `~/.workspace-guard.log`:

```
<timestamp>|<cwd>|git <command>|<reason>|uid=<uid>
```

Home directory resolved via `libc::getpwuid()` using the real UID (not
spoofable `$HOME`). Block messages written to both stderr and `/dev/tty`.

### Git guard residual risk

- `safe.bareRepository=explicit` not yet globally enforced (needs git >= 2.39).
- Pre-existing `.git/config` payloads not stripped (lock is locking-only).
- Sub-microsecond re-lock window after `git.original` exits.

Detail: [SPEC-GIT-GUARD-HARDENING.md](docs/specifications/SPEC-GIT-GUARD-HARDENING.md)

## System-Binary Lockdown + Sandbox + Audit

The same guard pattern extends to the rest of the Linux SUID and
file-capability surface. This program is shell-driven (bash + YAML, no
Rust) and covers four pillars:

1. **Discover.** `scripts/sync-gtfobins` fetches the canonical GTFOBins
   catalog + konstruktoid SUID list on every run, parses them, and matches
   against the live host (`/proc`, `getcap`). The baseline matches whatever
   binaries are actually installed, not a static snapshot. Emits
   `res/suid-baseline.yaml`, `res/fcap-baseline.yaml`, `res/cve-catalog.yaml`.
2. **Contain.** Each exploitable binary gets a per-binary guard policy
   (`config/binary-lock.yaml`) plus a cap allowlist
   (`config/cap-allowlist.yaml`) that throttles `CAP_*` to a documented
   minimum. Disposition is **contain-via-guard only**: binaries are never
   purged. The real binary is moved to `<path>.real` and the guard installed
   at the public path, mirroring the git guard's relocate-and-replace step.
   `chattr +i` on `.real` so the swap cannot be undone.
3. **Sandbox.** A per-host profile picker (`config/sandbox/profiles.yaml`)
   selects one of rootless Landlock+seccomp (~5 ms), gVisor runsc (~200 ms),
   or Firecracker microVM (~125 ms). The resolved profile is materialised
   into a systemd unit (`config/systemd/workspace-agent@.service`) that drops
   ambient caps, sets `NoNewPrivileges`, applies a seccomp syscall allowlist,
   and pins private network + mount namespaces.
4. **Audit.** `config/auditd/99-workspace-guard.rules` watches every
   `execve` of a guarded binary. AIDE
   (`config/aide/aide-workspace-guard.conf`) file-integrity-checks the `.real`
   binaries and identity files. `scripts/suid-drift-check` compares the live
   SUID/CAP surface against the committed baselines and exits non-zero on any
   CRITICAL delta.

### End-to-end flow

```
scripts/sync-gtfobins                 <-- fetch canonical GTFOBins + konstruktoid
   |  parses gtfobins-*.html, matches against /proc + getcap
   v
res/suid-baseline.yaml  +  res/fcap-baseline.yaml  +  res/cve-catalog.yaml
   |
   v
make install-lock       <-- (root) mv binary -> binary.real, install guard, chattr +i
make install-auditd     <-- (root) deploy auditd + AIDE rules
make install-sandbox    <-- (root) install systemd unit + sandbox profile
make drift-check        <-- (any user) verify live surface == baseline
make sandbox-check      <-- (any user) resolve per-host profile
```

### Reading order

1. [docs/RESEARCH-SYSTEM-BINARIES.md](docs/RESEARCH-SYSTEM-BINARIES.md): CVE
   catalog (9 CVEs: PwnKit, Baron Samedit, sudo `--chroot`, overlayfs, Copy
   Fail), sandbox isolation tiers, defense-in-depth map.
2. [docs/requirements/REQ-SANDBOX.md](docs/requirements/REQ-SANDBOX.md):
   contract IDs `REQ-LCK-*`, `REQ-CAP-*`, `REQ-SBX-*`, `REQ-AUD-*`,
   `REQ-SYNC-*`, `REQ-MAKE-*`, `REQ-ART-*`.
3. [docs/specifications/SPEC-BINARY-LOCK.md](docs/specifications/SPEC-BINARY-LOCK.md):
   contain-via-guard procedure and per-binary policies.
4. [docs/specifications/SPEC-CAP-THROTTLE.md](docs/specifications/SPEC-CAP-THROTTLE.md):
   capability allowlist + systemd `CapabilityBoundingSet`.
5. [docs/specifications/SPEC-AUDIT.md](docs/specifications/SPEC-AUDIT.md):
   auditd execve watch rules + AIDE/FIM + drift detection.
6. [docs/specifications/SPEC-SANDBOX.md](docs/specifications/SPEC-SANDBOX.md):
   profile picker + seccomp/Landlock/namespaces + systemd unit template.
7. [docs/references/SOURCES.md](docs/references/SOURCES.md): offline-cached
   canonical sources (GTFOBins, konstruktoid, NVD, sudo advisories, man7).

### Why the layers

The research in `docs/RESEARCH-SYSTEM-BINARIES.md` surfaces a split: some
CVEs are arg/env validation bugs the guard stops at the gate (PwnKit env-var
handling, Baron Samedit arg-parse, sudo `--chroot`); others are in-binary
memory corruptions or kernel-layer flaws (overlayfs, Copy Fail) that no SUID
guard can reach. The layered design reflects that split: the guard is the
**first** control, the sandbox profile is the **post-exploit** control, and
auditd is the **detection** control. Removing any single layer re-opens the
class of CVEs that layer was responsible for.

## Deployment

### Git guard

```bash
# From the WORKSPACE-CI repo root (as root):
sudo make pre-req            # Full install: deps + build guard + install + hooks

# Or step-by-step from WORKSPACE-GUARD:
make build-guard
sudo make install-guard      # setcap, dpkg-divert, chattr, apt hook, alt-binary restriction
make check-guard
sudo make install-hooks      # Hooks live in root-owned .git/hooks/ (capability mode)
```

install-guard steps: relocate `git` to `git.original` (0700), install guard
(0755), `setcap` 5 caps, `dpkg-divert`, `chattr +i`, apt post-invoke hook,
restrict `/snap/bin/git` + `/usr/local/bin/git`, create
`/var/log/workspace-guard/`.

Uninstall: `sudo make uninstall-guard`.

Full procedure: [SPEC-GIT-GUARD-INSTALL.md](docs/specifications/SPEC-GIT-GUARD-INSTALL.md)

### System-binary lockdown

```bash
scripts/sync-gtfobins                    # fetch + parse + emit baselines (any user)
make sync-gtfobins-verify               # verify canonical-source SHA-256
sudo make install-lock                   # (root) apply binary lock baselines
sudo make install-auditd                 # (root) deploy auditd + AIDE rules
sudo make install-sandbox                # (root) install systemd unit + sandbox profile
make drift-check                         # verify live surface == baseline
make sandbox-check                       # resolve per-host sandbox profile
make gitleaks-ignore-regen               # refresh .gitleaksignore for docs/references/
```

## Development

```bash
cargo build                                              # Debug (capability-mode)
cargo build --no-default-features --features root-only   # Debug (root-only)
cargo build --release                                    # Release (opt-level=z, LTO, abort-on-panic, stripped)
cargo test                                               # Cap mode: 90 unit + 3 integration
cargo test --no-default-features --features root-only    # Root-only: 84 unit + 3 integration
cargo fmt --all -- --check                               # Format check
cargo clippy --workspace --all-targets -- -D warnings    # Strict lint
make test                                                # Full workspace test suite
```

## Security Properties

### Shared (both programs)

1. **Compiled enforcement**: Guard logic is opaque binary, not readable or
   editable (git guard). System-binary lockdown uses shell guards with
   `chattr +i` on `.real` files for tamper resistance.
2. **File capabilities**: granular, `NO_NEW_PRIVS`-safe. Git guard uses
   `SETPCAP+CHOWN+DAC_OVERRIDE+FOWNER+FSETID+ep`. `CAP_SETPCAP` lets the
   forked child raise `DAC_OVERRIDE` into Ambient; on VFS-cap kernels it only
   modifies your own process cap sets.
3. **Ambient cap for child only**: the guard keeps Ambient empty at startup.
   Policy-check sub-calls get no caps (least-privilege). The authorized child
   raises `CAP_DAC_OVERRIDE` into Ambient before exec'ing the real binary;
   the cap dies with the child on exit.
4. **`dpkg-divert` protected** (git guard): `apt` cannot overwrite the shim.
5. **Allow-list environment**: closed surface, future variables cannot sneak
   through. `PATH` hardcoded; `safe.directory=*` injected (git guard).
6. **Resource limits**: `RLIMIT_NOFILE=256` prevents fd exhaustion;
   `RLIMIT_CORE=0` prevents memory disclosure from crashes.
7. **Null byte rejection**: any `\0` in arguments exits immediately (git guard).
8. **Audit trail**: every block logged via real-UID home lookup (not
   spoofable `$HOME`) + `/dev/tty`.
9. **Release hardening**: `opt-level=z, lto=true, codegen-units=1,
   panic=abort, strip=true` for smallest attack surface.
10. **Log symlink protection**: `O_NOFOLLOW` on log opens prevents symlink
    attacks. **HOME spoofing prevention**: `getpwuid(getuid())`, never
    `$HOME`. **2-second subprocess timeout** (git guard).

### Git guard only

11. **`.git` ownership lock**: recursive `chown` to `root:root` on every
    invocation, closing 11 local-RCE vectors. See
    [SPEC-GIT-GUARD-HARDENING.md §11.7](docs/specifications/SPEC-GIT-GUARD-HARDENING.md).
12. **Hardened rev-parse resolution**: the guard's own `git.original
    rev-parse` runs under forced env that disables `core.fsmonitor`,
    `core.hooksPath`, and system config.
13. **Background push detection**: `/proc/self/stat` check prevents CI/daemon
    pushes without interactive oversight.

### System-binary lockdown only

14. **Sandbox profile isolation**: rootless Landlock+seccomp / gVisor /
    Firecracker microVM, selected per-host. Post-exploit containment for
    CVEs the gate cannot stop (memory corruption, kernel flaws).
15. **Capability throttle**: `config/cap-allowlist.yaml` drops
    file capabilities to a documented minimum per binary; systemd
    `CapabilityBoundingSet` enforces at the unit level.
16. **Continuous drift detection**: `scripts/suid-drift-check` compares live
    SUID/CAP surface to committed baselines; auditd watches every `execve`
    of guarded binaries; AIDE file-integrity-checks `.real` + identity files.

Full threat model (mitigated and not-mitigated):
[SPEC-GIT-GUARD-IMPL.md §9](docs/specifications/SPEC-GIT-GUARD-IMPL.md)

## License

Internal. Independent AI Labs.