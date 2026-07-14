# Requirements: Home-Dir Lock (Git/SSH Config Chown Hardening)

**Date:** 2026-07-09
**Status:** DRAFT
**Type:** Requirements
**Related Specs:** [SPEC-HOME-LOCK](../specifications/SPEC-HOME-LOCK.md)
**Threat Model:** [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md)

---

## Background

The git guard (specified in [REQ-GIT-GUARD](REQ-GIT-GUARD.md)) intercepts the
`git config` command so an AI agent cannot write `core.hooksPath = /tmp/evil`
on the command line. The lock on `.git/config` (mode 0644, root:root, plus
`include.path` block) closes the in-repo vector.

During a real CI incident in WORKSPACE-CI, a **rootless** agent wrote
`core.hooksPath = /tmp/opencode/githooks` directly to `~/.gitconfig` by
opening the file with a text-editor subprocess, bypassing both the `git
config` command intercept and the per-repo `.git/config` lock. Because
`~/.gitconfig` is read by EVERY git invocation on the host, the hook
compromised every repository for that user without raising an alert. The injection
persisted across reboots and produced no drift alert because no
baseline covers files outside `.git/`.

The home-dir lock closes that vector by chowning the user-controlled
git and SSH config files outside the repo tree to `root:root` with a
tight mode, so a non-root agent cannot write to them at all. Editing is
still possible for operators in a root session (`sudoedit`, `sudo vim`, or
direct root write), which does not require clearing the lock. AI agents
never edit these paths.

The threat model and the GTFOBins/cap-lock background are in
[RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md); the per-repo
binary lock this complements is in
[SPEC-BINARY-LOCK](../specifications/SPEC-BINARY-LOCK.md).

---

## 1. Scope (REQ-HL-001 series)

- **REQ-HL-001**: The home-dir lock program shall protect the following
  per-user files by chowning them to `root:root` with a tight mode:
  - `~/.gitconfig` (mode 0644)
  - `~/.config/git/config` (mode 0644)
  - `~/.gitconfig.local` (mode 0644)
  - `~/.ssh/authorized_keys` (mode 0600)
  - `~/.ssh/config` (mode 0644)

- **REQ-HL-002**: The program shall ALSO protect the root user's home
  counterparts:
  - `/root/.gitconfig` (mode 0644)
  - `/root/.ssh/authorized_keys` (mode 0600)
  - `/root/.ssh/config` (mode 0644)

- **REQ-HL-003**: The program shall NOT lock:
  - Private SSH keys (`id_*`): chowning them to root would break ssh
    key authentication (the user must read its own key).
  - Shell rc files (`~/.bashrc`, `~/.profile`, `~/.zshrc`): chowning
    them would break interactive shells.
  - The `~/.ssh` directory itself: SSH refuses to read keys if the
    directory is owned by anyone other than the user, but locking the
    directory's contents is sufficient for the threat model.
  - The `~` directory itself: same reason as `~/.ssh`.

- **REQ-HL-004**: The protected set MUST be data-driven from
  `config/guard_locked_paths.yaml` (the `absolute_file_paths:` block),
  not hardcoded in the scripts. New entries are added by editing the
  YAML and rerunning `make install-home-lock`: no script change
  required.

- **REQ-HL-005**: The `~` prefix in YAML expands to `$HOME` at runtime
  so source code never embeds a literal `/home/<user>` path. This
  keeps the banned-word `/home/` checker green and keeps the config
  portable across hosts.

---

## 2. Install Behaviour (REQ-HL-100 series)

- **REQ-HL-100**: `install-home-lock` shall create any missing target
  file (with `mkdir -p` for parent dirs and `touch` for the file)
  BEFORE locking, so an attacker never has a window where the path is
  absent and the lock is a no-op.

- **REQ-HL-101**: For each entry, install shall record the original
  owner uid, owner gid, and mode in `/usr/lib/workspace-guard/home-lock-state.yaml` so
  `uninstall-home-lock` can restore them.

- **REQ-HL-102**: Install shall be idempotent: re-running on an
  already-locked file (uid == 0 AND gid == 0 AND mode == expected)
  emits `ALREADY LOCKED` and skips. The state file is not corrupted
  by re-runs.

- **REQ-HL-103**: Install shall refuse to run as non-root (exit 2),
  because chown requires CAP_CHOWN.

- **REQ-HL-104**: `--dry-run` shall report the planned action
  (`WOULD: mkdir -p parent, touch if missing, chown root:root, chmod
  <mode>`) without touching the filesystem. The state file MUST NOT
  be written on a dry-run.

- **REQ-HL-105**: The `~user` form (e.g. `~alice/.gitconfig`) shall
  be supported by resolving the home dir via `getent passwd`. If
  the user cannot be resolved, the entry is left unchanged and a
  warning is printed.

- **REQ-HL-106**: `chattr +i` MUST NOT be applied to home-lock
  files. Root must be able to edit them normally via `sudoedit` /
  `sudo vim` without a clear/reset dance. Immutability is
  reserved for the `.real` binaries of the binary lock program
  (SPEC-BINARY-LOCK).

---

## 3. Uninstall Behaviour (REQ-HL-200 series)

- **REQ-HL-200**: `uninstall-home-lock` shall restore the original
  owner uid, owner gid, and mode recorded in
  `/usr/lib/workspace-guard/home-lock-state.yaml` for every entry.

- **REQ-HL-201**: After rolling back ALL entries, uninstall shall
  clear the state file (`home_lock_state: []`) so a subsequent run
  is a no-op.

- **REQ-HL-202**: If the state file is missing OR empty, uninstall
  shall exit 0 with `nothing to roll back` / `no recorded entries`
  rather than failing.

- **REQ-HL-203**: Uninstall shall refuse to run as non-root (exit 2).

- **REQ-HL-204**: `--dry-run` shall report the planned restore
  without touching the filesystem and without clearing the state.

---

## 4. Drift Check Behaviour (REQ-HL-300 series)

- **REQ-HL-300**: `home-drift-check` shall compare the live state of
  every entry in `/usr/lib/workspace-guard/home-lock-state.yaml` against the recorded
  baseline (owner uid, owner gid, mode) and emit a CRITICAL alert
  for any of:
  - **missing-file**: the path no longer exists (suspected tamper).
  - **owner-changed**: uid is not 0 OR gid is not 0 (lock bypassed).
  - **mode-changed**: mode differs from the recorded value.

- **REQ-HL-301**: Drift check is REPORT-ONLY: no auto-repair is
  performed, so a forensic audit trail is preserved. The operator
  must run `make install-home-lock` to repair (which re-locks from
  the YAML baseline).

- **REQ-HL-302**: Drift check shall exit 0 when no CRITICAL drift is
  present and exit 1 when any CRITICAL drift is detected. Exit 2
  means the baseline state file is missing entirely (run
  `make install-home-lock` first).

- **REQ-HL-303**: `--quiet` shall suppress all non-CRITICAL output
  (banner, summary line) but still print CRITICAL rows and still
  write the report YAML.

- **REQ-HL-304**: The drift check shall write a structured report to
  `/usr/lib/workspace-guard/home-drift-report.yaml` with per-entry `path`, `class`,
  `detail`, `timestamp` and a `summary` block with `critical` and
  `warnings` counts.

- **REQ-HL-305**: Drift check shall run as any user (no root
  required); it only reads the state file and runs `stat`.

---

## 5. Security Properties (REQ-HL-400 series)

- **REQ-HL-400**: After `make install-home-lock` runs on a host, a
  non-root AI agent (assuming it has no CAP_DAC_OVERRIDE) SHALL NOT
  be able to modify `~/.gitconfig`, `~/.config/git/config`,
  `~/.gitconfig.local`, `~/.ssh/authorized_keys`, or `~/.ssh/config`
  directly via a file write. Agents never edit these paths. Operators
  change them from a root session only (SSH/su, `sudoedit`, or
  equivalent operator channel).

- **REQ-HL-401**: The lock shall NOT break ssh key authentication:
  private keys remain user-owned mode 0600 and `~/.ssh` remains
  user-owned mode 0700.

- **REQ-HL-402**: The lock shall NOT break interactive shells:
  rc files remain user-owned.

- **REQ-HL-403**: The lock shall NOT break legitimate operator
  maintenance: a root operator can still edit `~/.gitconfig` from a
  root session. Agents never use `git config --global` or edit locked
  home paths. The git guard's `git config core.hooksPath` BLOCK still
  applies inside any non-root git invocation.

---

## 6. Testing (REQ-HL-500 series)

- **REQ-HL-500**: Install, uninstall, and drift-check shall each have
  a bats suite covering: `--help`, unknown arg, missing config/empty
  entries, `--dry-run`, the create-missing branch, the idempotent
  branch (using a fake `stat` executable), the `--quiet` branch, and the report
  YAML emissions.

- **REQ-HL-501**: Tests shall run as a non-root bats user. The
  root-only `chown` code path is exercised via a fake `chown` executable.
  The idempotency branch is exercised via a fake `stat` executable that
  reports `uid=0`, `gid=0`, `mode=$expected` (built per-test via
  `make_stub`).

- **REQ-HL-502**: The `~` expansion is verified by setting a custom
  `HOME` (different from the fake-home dir) and asserting the file
  lands in the custom dir, not a hardcoded path.

- **REQ-HL-503**: The Rust build pipeline (`build.rs`) shall parse
  the `absolute_file_paths` block and emit a `LOCKED_ABSOLUTE_FILE_PATHS`
  const so future in-binary enforcement of the home-lock surface
  (e.g. an `lstat` guard at start-up) does not require a config
  file read at runtime, preserving the security model of the
  binary lock.

- **REQ-HL-504**: Cross-config consistency tests in
  `src/config_consistency_tests.rs` shall verify:
  - The `absolute_file_paths` block parses.
  - Every key is either absolute (`/...`) or `~`-prefixed.
  - Every mode is in the range `[0o400, 0o777]`.

---

## 7. Non-Goals

- **REQ-HL-NG-01**: The home lock is NOT a replacement for the
  in-repo `.git/config` lock (SPEC-BINARY-LOCK). It covers the
  user-global git config files OUTSIDE the repo. Both are required.
- **REQ-HL-NG-02**: The home lock does NOT quarantine or block the
  `~user` form's home dir creation. It only locks files that exist
  or are listed in the YAML.
- **REQ-HL-NG-03**: The home lock does NOT provide a runtime guard
  binary for `~/.gitconfig` reads. It only changes ownership and
  mode; the threat model assumes the agent has no CAP_DAC_OVERRIDE.
- **REQ-HL-NG-04**: The drift check is NOT real-time: it runs on
  demand (`make home-drift-check`) or on a cron. A real-time audit
  of `~/.gitconfig` writes is the job of auditd (SPEC-AUDIT).