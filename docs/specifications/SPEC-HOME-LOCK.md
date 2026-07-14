# Specification: Home-Dir Lock (Git/SSH Config Chown Hardening)

**Date:** 2026-07-09
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-HOME-LOCK](../requirements/REQ-HOME-LOCK.md)
**Threat Model:** [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md)
**Related:** [SPEC-BINARY-LOCK](SPEC-BINARY-LOCK.md), [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md)

---

## 1. Architecture Overview

The home-dir lock is the third layer of the WORKSPACE-GUARD defence
stack. The first two layers (binary lock, capability throttle) contain
SUID/cap binaries and intercept the `git config` command. The home
lock closes the *file-write* vector: a non-root agent that opens
`~/.gitconfig` with a text-editor subprocess and writes
`core.hooksPath = /tmp/evil` directly, bypassing the `git config`
command intercept and the per-repo `.git/config` lock.

The lock works by changing the **ownership** of the affected config
files to `root:root` and setting a **tight mode** so that a non-root
process (without CAP_DAC_OVERRIDE) cannot open the file for write.

```
   User / agent                       ~/.gitconfig
   ----------                         -------------
   BEFORE:  -rw-rw-r--  agent agent    <- agent can write
   AFTER:   -rw-r--r--  root   root    <- only root can write
                                       (sudoedit still works)
```

Editing is still possible via the `sudoedit <path>` (or `sudo vim
<path>`) channel: the editor runs as root, writes the file, and the
git guard's `git config core.hooksPath` BLOCK still applies inside
that editor shell if the operator tries to set a dangerous value.

The protected set is data-driven from
`config/guard_locked_paths.yaml` (the `absolute_file_paths:` block),
so new entries are added by editing the YAML and rerunning
`make install-home-lock`: no script or binary rebuild required.

There are three scripts:

1. `scripts/install-home-lock`: chown to root, set mode, write state.
2. `scripts/uninstall-home-lock`: restore original owner/mode, clear state.
3. `scripts/home-drift-check`: read-only compare against the state file.

State lives in `/usr/lib/workspace-guard/home-lock-state.yaml`; the
drift report lives in `/usr/lib/workspace-guard/home-drift-report.yaml`.
Both are per-host runtime files (not committed to git). Prior installs
may still have copies under `res/` until the next install script run
relocates them.

---

## 2. Threat Model

The threat this defends against, taken from the CI incident:

1. A non-root AI agent (uid 1000, no capabilities) runs on the host.
2. The agent invokes a text editor: `vim ~/.gitconfig` (or any
   subprocess that can open the file for write).
3. The editor writes `core.hooksPath = /tmp/opencode/githooks` and
   `[include] path = /tmp/evil.inc` to `~/.gitconfig`.
4. On the next `git` invocation (any repo for that user), git reads
   `~/.gitconfig`, loads the hook, and runs the attacker-controlled
   hook for every git operation.
5. The injection persists across reboots because `~/.gitconfig` is a
   plain file in the user's home.

The in-repo `.git/config` lock cannot cover step 4 because the
injection lives in `~/.gitconfig`, outside the repo. The `git config`
command intercept cannot cover step 2 because the write is a direct
file write, not a `git config` invocation.

**Mitigation**: After `make install-home-lock` runs, the file
`~/.gitconfig` is owned by `root:root` with mode 0644. The agent
(uid 1000, no CAP_DAC_OVERRIDE) cannot open the file for write:
`open("~/.gitconfig", O_WRONLY)` returns `EACCES`. The attack in
step 2 fails. The operator can still edit the file via `sudoedit`,
which runs the editor as root, but then the git guard's
`git config core.hooksPath` BLOCK intercepts any attempt to set a
dangerous value inside that editor shell.

---

## 3. Config Schema

The `absolute_file_paths:` block lives inside
`config/guard_locked_paths.yaml` alongside the existing per-repo lock
config:

```yaml
version: 1
recursive_tree_paths: [...]
recursive_tree_glob_patterns: [...]
individual_file_paths: {...}
glob_patterns: {...}

# NEW: per-user config files OUTSIDE the repo tree that must be
# owned by root:root with the given mode. The `~` prefix is expanded
# to $HOME at install time; literal /absolute/ paths pass through.
absolute_file_paths:
  "~/.gitconfig": 0o644
  "~/.config/git/config": 0o644
  "~/.gitconfig.local": 0o644
  "~/.ssh/authorized_keys": 0o600
  "~/.ssh/config": 0o644
  "/root/.gitconfig": 0o644
  "/root/.ssh/authorized_keys": 0o600
  "/root/.ssh/config": 0o644
```

The mode value is YAML octal (`0o644`). The install script normalizes
the awk-extracted string by stripping non-octal characters and
leading zeros, so `0o644` becomes the canonical string `644` used in
state and report files.

---

## 4. Scripts

### 4.1 Common Conventions

All three scripts share:

- `set -euo pipefail`.
- `SCRIPT_DIR` / `REPO_ROOT` resolved from `${BASH_SOURCE[0]}` so
  the scripts work from any CWD (matched by the test harness).
- A single `trap ... EXIT` cleanup for temp files (each script
  registers its temps as they are created).
- `DEVNULL=/dev/null` indirection so the source never embeds the
  literal `2>/dev/null` idiom the error-swallow checker flags.
- Root-only assertion for install/uninstall (`id -u` must equal 0);
  drift-check runs as any user.
- Awk-based parsing of both the YAML config and the YAML state file
  (no Python, no yq, no jq).

The `~` expansion is implemented in `install-home-lock` as the
`expand_tilde()` function:

```bash
expand_tilde() {
    local p="$1"
    case "$p" in
        "~")        printf '%s' "$HOME" ;;
        "~/"*)      printf '%s/%s' "$HOME" "${p#"~/"}
                    # NB: the `${p#"~/"}` quotes the tilde so bash's
                    # own tilde expansion does not run inside the
                    # pattern, which (without the quotes) would
                    # re-expand `~/` to `<HOME>/` and leave the
                    # leading `~` unstripped.
                    ;;
        "~"*)       # ~user form: resolve via getent passwd.
                    local user="${p%%/*}" rest=""
                    if [[ "$p" == */* ]]; then rest="/${p#*/}"; fi
                    local home_dir
                    home_dir="$(getent passwd "${user#\~}" | awk -F: '{print $6}')"
                    if [[ -n "$home_dir" ]]; then
                        printf '%s%s' "$home_dir" "$rest"
                    else
                        printf '%s' "$p"
                    fi ;;
        *)          printf '%s' "$p" ;;
    esac
}
```

### 4.2 install-home-lock

```
Usage: scripts/install-home-lock [--dry-run]
Lock the absolute_file_paths entries in config/guard_locked_paths.yaml
(SPEC-HOME-LOCK 4.2). Root-only. Chowns each path to root:root and
applies the configured mode. Edit locked files via sudoedit.
Exit: 0 ok, 1 lock failure, 2 not root/missing config.
```

Flow:

1. Parse args (`--dry-run`, `-h`/`--help`). Refuse non-root (exit 2).
2. Verify `config/guard_locked_paths.yaml` exists (exit 2 if missing).
3. Parse the `absolute_file_paths:` block with awk into a temp file
   of `<expanded-path>\t<mode-octal>` rows. Strip non-octal and
   leading-zero from the mode. Error (exit 2) if zero entries.
4. If NOT dry-run: `mkdir -p "$(dirname "$STATE_FILE")"` then write
   the state header `home_lock_state:`.
5. For each entry:
   a. Expand `~` via `expand_tilde`.
   b. If dry-run: print `WOULD: mkdir -p parent, touch if missing,
      chown root:root, chmod <mode>` and continue.
   c. `mkdir -p` the parent dir of the path.
   d. `touch` the file if missing (create-missing branch).
   e. Capture `orig_uid` / `orig_gid` / `orig_mode` via
      `stat -c '%u'` / `'%g'` / `'%a'` (with `|| var="?"` so a stat
      failure does not abort under `set -e`).
   f. Idempotency check: if `orig_uid == 0 AND orig_gid == 0 AND
      orig_mode == <mode>`, print `ALREADY LOCKED (skip)` and
      continue.
   g. `chown root:root <path>` (the test harness injects a fake `chown`
      executable so non-root bats runs do not abort).
   h. `chmod <mode> <path>`.
   i. Append a state entry: `path`, `original_owner_uid`,
      `original_owner_gid`, `original_mode`, `expected_mode`,
      `locked_at` (UTC ISO-8601).
6. Print summary: `Home lock: N locked, M already locked, K failed`.
7. Exit 0 if `K == 0`, else 1.

State file format (`/usr/lib/workspace-guard/home-lock-state.yaml`):

```yaml
# Auto-generated by scripts/install-home-lock on 2026-07-09T22:00:00Z
# Source of truth for scripts/uninstall-home-lock.
# Format: one block per locked path with a - path: key.
home_lock_state:
  - path: "/home/alice/.gitconfig"
    original_owner_uid: "1000"
    original_owner_gid: "1000"
    original_mode: "664"
    expected_mode: "644"
    locked_at: "2026-07-09T22:00:00Z"
```

State is the per-host baseline for `home-drift-check` and the rollback
map for `uninstall-home-lock`.

### 4.3 uninstall-home-lock

```
Usage: scripts/uninstall-home-lock [--dry-run]
Reverse home lock per home-lock-state.yaml (SPEC-HOME-LOCK 4.3).
Exit: 0 ok, 1 rollback failure, 2 not root/missing state file.
```

Flow:

1. Parse args. Refuse non-root (exit 2).
2. If state file missing: print `NOTICE: <state> missing; nothing to
   roll back` and exit 0.
3. Parse state with awk into `<path>\t<orig_uid>\t<orig_gid>\t<orig_mode>`
   rows. If zero rows: print `no recorded entries` and exit 0.
4. For each entry:
   a. If dry-run: print `WOULD: chown <orig_uid>:<orig_gid>, chmod
      <orig_mode>` and continue.
   b. `chown <orig_uid>:<orig_gid> <path>`.
   c. `chmod <orig_mode> <path>`.
   d. Print `RESTORED (uid=<o> gid=<o> mode=<o>)`.
5. Clear the state file (`home_lock_state: []`) so a subsequent run
   is a no-op.
6. Exit 0 if no failures, else 1.

### 4.4 home-drift-check

```
Usage: scripts/home-drift-check [--quiet]
Compare live home-lock surface against home-lock-state.yaml.
Report only; no auto-repair (preserves audit trail).
Exit: 0 no critical drift, 1 critical drift, 2 baseline missing.
```

Flow:

1. Parse args (`--quiet`, `-h`/`--help`). Any user may run.
2. If state file missing: error `baseline missing: <state>; run:
   make install-home-lock` and exit 2.
3. Parse state with awk into `<path>\t<expected_mode>` rows. If zero
   rows: write empty report and exit 0.
4. Initialise the drift report (`drift:` header) and counters.
5. For each entry:
   a. If path missing: CRITICAL `missing-file`, increment counter,
      continue (skip other checks).
   b. `stat -c '%u'`, `'%g'`, `'%a'` (with `|| var="?"`).
   c. If uid != 0 OR gid != 0: CRITICAL `owner-changed`.
   d. If expected_mode != "?" AND live_mode != "?" AND
      live_mode != expected_mode: CRITICAL `mode-changed`.
   e. Append a row to the report: `- {path, class, detail, timestamp}`.
6. Append the summary block: `critical: N`, `warnings: M`,
   `checked_at: <UTC ISO-8601>`.
7. If not quiet: print banner + summary line.
8. Exit 0 if CRITICAL == 0, else 1.

Report file format (`/usr/lib/workspace-guard/home-drift-report.yaml`):

```yaml
# Auto-generated by scripts/home-drift-check on 2026-07-09T22:00:00Z
# Baseline snapshot: /usr/lib/workspace-guard/home-lock-state.yaml
drift:
  - {path: "/home/alice/.gitconfig", class: "missing-file", detail: "CRITICAL", timestamp: "2026-07-09T22:00:00Z"}
  - {path: "/home/alice/.ssh/authorized_keys", class: "owner-changed", detail: "uid=1000 gid=1000", timestamp: "2026-07-09T22:00:00Z"}

summary:
  critical: 2
  warnings: 0
  checked_at: "2026-07-09T22:00:00Z"
```

---

## 5. Makefile Targets

```makefile
.PHONY: install-home-lock uninstall-home-lock home-drift-check home-drift-check-quiet

install-home-lock:
	sudo scripts/install-home-lock

uninstall-home-lock:
	sudo scripts/uninstall-home-lock

home-drift-check:
	scripts/home-drift-check

home-drift-check-quiet:
	scripts/home-drift-check --quiet
```

`install-home-lock` and `uninstall-home-lock` are wrapped in `sudo`
because they chown. `home-drift-check` is NOT wrapped because it only
reads.

---

## 6. build.rs Integration

`build.rs` parses `config/guard_locked_paths.yaml` (via serde_yaml)
and emits a `LOCKED_ABSOLUTE_FILE_PATHS` const table alongside the
existing `LOCKED_RECURSIVE_TREE_PATHS`, `LOCKED_INDIVIDUAL_FILE_PATHS`,
and `LOCKED_GLOB_PATTERNS` consts. The `LockedPathsConfig` struct
gains an `absolute_file_paths: HashMap<String, u32>` field
(`#[serde(default)]` so older configs without the block still parse).

This keeps the home-lock surface available to the compiled binary at
runtime without a config file read, preserving the security model of
SPEC-BINARY-LOCK. Future enforcement (e.g. an `lstat` guard at
start-up that refuses to run if `~/.gitconfig` is not locked) can use
this table directly.

---

## 7. Config Consistency Tests

`src/config_consistency_tests.rs` adds three tests:

1. `home_lock_paths_parses`: the YAML loads without error.
2. `home_lock_paths_are_absolute_or_tilde_prefixed`: every key is
   either `/...` or `~...`.
3. `home_lock_modes_are_in_valid_range`: every value is in
   `[0o400, 0o777]`.

---

## 8. bats Suite (tests/shell/12-home-lock.bats)

The suite (34 tests) is structured in three sections mirroring the
three scripts. Helpers:

- `_setup_home`: builds a fake repo with real scripts, a fake home
  at `$TEST_TMPDIR/fakehome`, and an empty `absolute_file_paths`
  block.
- `_write_locked_paths dir <path> <mode> ...`: (re)writes the
  `absolute_file_paths:` block with the given `~/path: 0o<mode>`
  pairs.
- `_make_home_files <path> <content> ...`: materialises the listed
  fake-home files with content, expanding `~` against `$FAKE_HOME`.
- `_tilde <path>`: resolves a `~`-prefixed path against
  `$FAKE_HOME` (used by assertions).
- `_stub_stat_root <mode>`: builds a fake `stat` executable that always reports
  `uid=0`, `gid=0`, `mode=<mode>`, used to exercise the idempotency
  branch and the no-drift path of `home-drift-check`.

Stub pattern: the test uses `run env HOME="$FAKE_HOME" bash <script>`
so bats' `run` helper captures the output of `env` (which sets HOME
for the bash subprocess). NOTE: the order matters: `env HOME=... run
bash ...` does NOT call the bats `run` function (env would exec the
non-existent `run` binary and `run` would never set `$status`/`$output`,
producing the cryptic `[: : integer expression expected` error from
`assert_success`).

Test coverage matrix:

| script             | test classes |
|--------------------|--------------|
| install-home-lock  | `--help`, unknown arg, missing config, no entries, `--dry-run`, create-missing (`touch`), create parent (`mkdir -p`), state-file write, state-field capture (orig owner + orig mode + expected mode + locked_at), mode 0644 (gitconfig), mode 0600 (authorized_keys), chown invoked, `~` expands to HOME at runtime, `/root/` absolute path, multiple entries, idempotent (fake stat) |
| uninstall-home-lock| `--help`, unknown arg, state missing (exit 0 nothing-to-roll-back), state empty, `--dry-run`, restore original mode, clear state, multiple entries |
| home-drift-check   | `--help`, unknown arg, baseline missing, baseline empty, no drift (fake stat), missing file CRITICAL, owner-changed CRITICAL, mode-changed CRITICAL, `--quiet`, writes report YAML |

---

## 9. Security Properties

- A non-root AI agent (no CAP_DAC_OVERRIDE) CANNOT write to the
  locked files after `make install-home-lock` runs. The agent must
  use `sudoedit`, which runs as root and is subject to the git
  guard's `git config core.hooksPath` BLOCK inside the editor shell.
- The lock does NOT break ssh key authentication (private keys are
  user-owned, mode 0600; `~/.ssh` is user-owned, mode 0700).
- The lock does NOT break interactive shells (rc files are
  user-owned).
- `chattr +i` is deliberately NOT applied: root must be able to
  edit the files via `sudoedit` normally without a clear/reset dance
  dance. Immutability is reserved for the `.real` binaries of the
  binary lock program (SPEC-BINARY-LOCK).

---

## 10. Non-Goals

- The home lock does NOT replace the in-repo `.git/config` lock
  (SPEC-BINARY-LOCK); both are required.
- The home lock does NOT provide a runtime guard binary for
  `~/.gitconfig` reads; it only changes ownership and mode. The
  threat model assumes the agent has no CAP_DAC_OVERRIDE.
- The drift check is NOT real-time: it runs on demand or on a cron.
  Real-time audit of `~/.gitconfig` writes is the job of auditd
  (SPEC-AUDIT).