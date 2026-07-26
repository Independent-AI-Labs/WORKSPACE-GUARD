# Requirements: Sudo-Gated Exemption Add/Remove (YAML Policy Editing)

**Date:** 2026-07-26
**Status:** DRAFT
**Type:** Requirements
**Related Specs:** [SPEC-EXEMPTION-EDIT](../specifications/SPEC-EXEMPTION-EDIT.md)
**Related:** [REQ-HOME-LOCK](REQ-HOME-LOCK.md), [REQ-GIT-GUARD](REQ-GIT-GUARD.md), [SPEC-GIT-GUARD-HARDENING](../specifications/SPEC-GIT-GUARD-HARDENING.md)

---

## Background

Policy YAML files (`quality_exceptions.yaml`, `*_exceptions.yaml`,
`coverage_thresholds.yaml`, `file_length_limits.yaml`, `dead_code.yaml`,
`*_excludes.yaml`, ...) are locked to `root:root` by the git guard's
per-invocation ownership lock (`src/gitdir.rs`), so a non-root agent
cannot tamper with them. That ownership lock is sound and stays.

The mechanism for *legitimate edits* to those files is not sound. In
consumer repos, `scripts/config-lock.sh` seals `config/*.yaml` with
`chattr +i` and requires a **timed unseal dance** to edit anything:

1. `sudo make config-unseal` drops `chattr -i`, chowns files back to
   the repo owner, and records state in two places
   (`/var/lib/workspace-guard/config-unseal/*.files` and a
   root-owned mirror at `<gitdir>/config-unseal.files`).
2. A `systemd-run` transient timer relocks after N minutes.
3. The guard binary reads the mirror on every git invocation to skip
   relocking unsealed files.

This design is error-prone and exploitable:

- **Unseal window**: for the whole timer duration every policy YAML in
  the repo is writable by the repo owner, including by any process
  running as that user, not just the operator's editor. The window is
  the exploit: an agent that can influence the owner account during the
  window can rewrite any policy file, and the relock then *preserves*
  the tampered content under `root:root` + `chattr +i`.
- **State-machine fragility**: the dual state files, timer unit naming
  by path cksum, resume-on-existing-state branches, and the
  owner-writability probe are a large, untested shell state machine
  (no bats coverage exists for `config-lock.sh`). Failure modes leave
  repos permanently unsealed or permanently immutable.
- **Guard complexity**: the guard binary carries a runtime skip-list
  reader (`read_unseal_state`, src/gitdir.rs) whose only purpose is to
  punch holes in its own lock, an anti-feature in a fail-closed
  system.

The replacement follows the precedent set by the home lock
(REQ-HL-106): **root edits directly; files are never released**. Files stay
`root:root` at all times; edits happen through a single sudo-gated
tool, `scripts/exemption.sh`, that manipulates YAML *contents*
generically (add/remove/list/set) with atomic, fail-closed writes.
Because the tool runs as root and preserves `root:root` ownership, the
guard's ownership lock never needs a skip list, and there is no window
in which a non-root process can write policy files.

---

## 1. Scope (REQ-EX-001 series)

- **REQ-EX-001**: A single tool, `scripts/exemption.sh`, shall be the
  only supported mechanism for scripted edits to guard-locked YAML
  policy files. It shall operate on any YAML file path given to it
  (repo-agnostic), not on a hardcoded repo or directory glob.

- **REQ-EX-002**: The tool shall support four intents:
  - `add <file> <list-key> <field=value>...`: append one map entry to
    a list-of-maps key (e.g. `exceptions`, `safe_exceptions`).
  - `remove <file> <list-key> <field=value>...`: delete every list
    entry whose fields match ALL given `field=value` pairs.
  - `list <file> [list-key]`: print the file (or one key's entries)
    to stdout. Not root-gated.
  - `set <file> <key> <value>`: set a scalar top-level key (e.g.
    thresholds in `coverage_thresholds.yaml`).

- **REQ-EX-003**: The tool shall cover every YAML policy file shape
  currently in the fleet: `key: []` empty lists, block lists of maps
  (`- field: value`), nested list values under an entry (e.g.
  `paths:` sub-items), and flat scalar keys. It shall be generic: no
  per-filename hardcoding of structure beyond the optional validators
  of REQ-EX-300.

- **REQ-EX-004**: `add` on a key currently written as `key: []` shall
  convert it to block-list form. `remove` deleting the last entry
  shall rewrite the key as `key: []`.

- **REQ-EX-005**: `add` shall reject an entry that duplicates an
  existing entry on all provided fields (idempotent re-add is an
  error, not a silent no-op).

---

## 2. Atomicity and Fail-Closed Writes (REQ-EX-100 series)

- **REQ-EX-100**: Every mutation shall write to a temp file in the
  same directory as the target, validate the result, and only then
  atomically install it over the target. A failed transform or
  validation shall leave the target byte-identical.

- **REQ-EX-101**: The installed file shall be owned `root:root` with
  mode 0644 regardless of umask, matching the ownership the guard's
  lock enforces (`config/guard_locked_paths.yaml` glob policy).

- **REQ-EX-102**: The tool shall refuse to operate on:
  - a non-existent file (exit 2; it never creates policy files),
  - a symlink (resolved path must equal the given path),
  - a file not owned by `root:root` (refuse to silently bless a
    tampered-ownership file),
  - input it cannot parse (exit 1 with a diagnostic).

- **REQ-EX-103**: Header comments and unrelated keys shall be
  preserved byte-for-byte; the transform shall touch only the target
  key's block.

---

## 3. Validation (REQ-EX-300 series)

- **REQ-EX-300**: All mutations shall pass structural validation:
  the temp output shall be re-parsed after the transform and the edit
  verified to have taken effect exactly once (add: entry present;
  remove: entry absent; set: scalar updated).

- **REQ-EX-301**: Known files shall additionally carry schema
  validators dispatched by basename:
  - `quality_exceptions.yaml`: `hook` non-empty, `reason` >= 20
    characters, `paths` >= 1 entry, `added_by` non-empty.
  Validators shall be implemented as a small case dispatch in shell,
  reusing the same awk engine; unknown basenames get structural
  validation only.

- **REQ-EX-302**: Validation failure shall abort the mutation with a
  non-zero exit and shall not modify the target (per REQ-EX-100).

---

## 4. Sudo Gating (REQ-EX-400 series)

- **REQ-EX-400**: `add`, `remove`, and `set` shall refuse to run as
  non-root (exit 2), following the existing `require_root` convention.
  `list` shall run as any user (read-only).

- **REQ-EX-401**: Make targets shall be provided following the
  existing root-gate recipe pattern:
  - `exemption-add FILE=.. KEY=.. FIELDS="..."`,
  - `exemption-remove FILE=.. KEY=.. FIELDS="..."`,
  - `exemption-list FILE=.. [KEY=..]`.
  Non-root invocation shall print
  `ERROR: <target> needs root: sudo make <target>` and exit 1.

- **REQ-EX-402**: No filesystem release/relock cycle (chattr, ownership flip,
  timer, or state file) shall be performed by the tool, the Make
  targets, or any other part of the repo as part of editing a YAML
  policy file. The `root:root` ownership lock applied by the guard is
  the only gating mechanism.

---

## 5. Decommission of the Unseal Mechanism (REQ-EX-500 series)

- **REQ-EX-500**: `scripts/config-lock.sh` shall be deleted, together
  with its Make targets (`config-lock`, `config-unseal`,
  `config-relock`, `config-lock-status`) and the
  `CONFIG_LOCK_REPO`/`CONFIG_LOCK_MINUTES` variables.

- **REQ-EX-501**: The guard binary shall no longer read or honour
  `<gitdir>/config-unseal.files`. `UNSEAL_STATE_FILE`,
  `read_unseal_state`, and the skip call inside `gitdir::lock()` shall
  be removed, making the ownership lock unconditional for all matched
  paths.

- **REQ-EX-502**: Runtime leftovers shall be cleaned up:
  `/var/lib/workspace-guard/config-unseal/` and any stray
  `<gitdir>/config-unseal.files` mirrors.

- **REQ-EX-503**: Repos currently sealed with `chattr +i` by the old
  mechanism shall be migrated with a one-time pass: `chattr -i` +
  `chown root:root` + `chmod 0644` on every `config/*.yaml`. After
  migration the guard's ownership lock alone maintains the seal.

- **REQ-EX-504**: The home lock, binary lock, and guard self-lock
  shall NOT be touched; they protect non-YAML surfaces and have no
  unseal dance.

---

## 6. Audit (REQ-EX-600 series)

- **REQ-EX-600**: Every mutation shall append one audit line to the
  guard log file configured in `config/guard_paths.yaml`, recording:
  UTC timestamp, invoking user (`SUDO_USER` or uid), intent, target
  file, list key, and the field set.

- **REQ-EX-601**: Audit write failure shall not silently pass; it
  shall be reported on stderr (the mutation itself may still succeed:
  audit is append-only best-effort, the authoritative record is git
  history of the edited file, which is itself a locked, committed
  file).

---

## 7. Testing (REQ-EX-700 series)

- **REQ-EX-700**: A bats suite `tests/shell/20-exemption.bats` shall
  cover: `--help`, unknown intent, missing file, symlink target,
  non-root-owned target, add to `key: []`, add to an existing block
  list, add with a nested `paths` list, duplicate-add rejection,
  remove by single field, remove by multi-field match, remove of a
  non-matching entry (exit 0, file unchanged), remove-last-entry
  rewriting `key: []`, scalar `set`, non-root refusal for
  add/remove/set, root not required for `list`, ownership/mode of the
  output file, and comment/unrelated-key preservation.

- **REQ-EX-701**: Tests shall run as a non-root bats user; the
  root-only path is exercised via fake `id`/`chown` executables,
  following the established PATH-shadowing pattern under `tests/shell/`.

- **REQ-EX-702**: Rust-side: the `read_unseal_state` tests in
  `src/gitdir_tests.rs` shall be deleted, and a test shall assert that
  `gitdir::lock()` chowns a `*_exceptions.yaml` match unconditionally
  (no skip-list branch remains).

---

## 8. Non-Goals

- **REQ-EX-NG-01**: The tool is NOT a general YAML pretty-printer or
  arbitrary-path query engine (no yq-style expressions). It supports
  the fleet's actual shapes: top-level list-of-maps keys and top-level
  scalars.
- **REQ-EX-NG-02**: The tool does NOT validate consumer-side semantics
  (e.g. whether `hook` names a real hook id in WORKSPACE-CI's
  `required_hooks.yaml`); cross-repo semantic checks remain the
  consumer's job.
- **REQ-EX-NG-03**: No sudoers drop-in is introduced; the existing
  full-admin sudo grant (`/etc/sudoers.d/90-workspace-guard-admin`)
  already gates the tool. Fine-grained command aliases are a future
  hardening option, not part of this change.
- **REQ-EX-NG-04**: The guard binary gains no runtime YAML parsing.
  Policy YAMLs remain build-time inputs (`build.rs`, serde_yaml) or
  consumer-repo concerns; this feature changes only how they are
  edited.
