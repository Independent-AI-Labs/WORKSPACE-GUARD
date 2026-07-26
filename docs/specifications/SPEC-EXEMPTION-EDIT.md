# Specification: Sudo-Gated Exemption Add/Remove (YAML Policy Editing)

**Date:** 2026-07-26
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-EXEMPTION-EDIT](../requirements/REQ-EXEMPTION-EDIT.md)
**Related:** [SPEC-HOME-LOCK](SPEC-HOME-LOCK.md), [SPEC-GIT-GUARD-HARDENING](SPEC-GIT-GUARD-HARDENING.md), [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md)

---

## 1. Architecture Overview

The git guard keeps every policy YAML `root:root` via its
per-invocation ownership lock (`src/gitdir.rs` `lock()`, driven by the
`glob_patterns` block of `config/guard_locked_paths.yaml`). That lock
is the *only* gating mechanism after this change. Legitimate edits go
through one root-gated tool that manipulates YAML contents directly:

```
   Operator                          policy YAML (e.g. quality_exceptions.yaml)
   --------                          ------------------------------------------
   sudo make exemption-add \
     FILE=quality_exceptions.yaml \
     KEY=exceptions \
     FIELDS="hook=banned-words reason='legacy vendored copy' paths=vendor/ added_by=op@x"
        |
        v
   scripts/exemption.sh  (require_root)
        |  1. preflight: file exists, not symlink, root:root
        |  2. awk transform -> mktemp in same dir
        |  3. structural + schema validation of temp
        |  4. install -o root -g root -m 0644 temp target
        |  5. audit line -> guard log
        v
   file stays root:root 0644 at ALL times; guard lock unchanged
```

There is no release step, no timer, no state file, and no window in
which a non-root process can write the file. This replaces the deleted
`config-lock.sh` unseal dance (§7) with the same "root edits directly"
model the home lock already uses (REQ-HL-106).

Tooling constraint: all shell-side YAML handling in this repo is
hand-rolled **awk** (no yq, no python3/PyYAML), and this tool follows
that convention; no new system dependency is introduced.

---

## 2. Threat Model

Attacks closed by removing the unseal mechanism:

1. **Unseal-window tamper**: under `config-lock.sh unseal`, every
   `config/*.yaml` is writable by the repo owner for the timer
   duration. Any process running as that user (including an agent that
   escalated into the owner account) could rewrite policy, and the
   relock then sealed the tampered content. After this change the file
   is never writable by a non-root user, so the window class is
   eliminated.
2. **Skip-list forgery / confusion**: the guard's
   `<gitdir>/config-unseal.files` reader punched holes in the ownership
   lock based on runtime state. Removing the reader makes the lock
   unconditional and the guard simpler (fail-closed by construction).
3. **State-machine wedge**: dual state files + `systemd-run` timer
   failure modes could leave a repo permanently unsealed or permanently
   immutable. No state machine remains.

Attacks the remaining design still relies on:

- The operator's root channel (sudo) is trusted, as everywhere else in
  this stack (home lock, binary lock, guard install).
- The authoritative history of policy edits is git itself: edited
  files are committed, locked files, so tampering is visible in
  `git log` / `git diff` and in the audit lines (§6).

---

## 3. Command Grammar

```
scripts/exemption.sh add    <file> <list-key> <field=value> [<field=value>...]
scripts/exemption.sh remove <file> <list-key> <field=value> [<field=value>...]
scripts/exemption.sh list   <file> [<list-key>]
scripts/exemption.sh set    <file> <scalar-key> <value>
```

- Intents `add`/`remove`/`set`: root-only (exit 2 otherwise). `list`:
  any user, read-only.
- `<file>` may be absolute or relative; the tool canonicalises it with
  `readlink -f` and refuses if canonical != given (symlink, REQ-EX-102).
- `field=value` values may be quoted by the caller; the tool re-emits
  them with YAML quoting only when the value contains `: `, leading
  special characters, or matches a YAML boolean/null literal.
- A field whose value is a list (e.g. `paths=vendor/,src/legacy/`) is
  expressed comma-separated on the command line and emitted as a
  nested block list under the entry.

Exit codes: `0` ok (including remove-with-no-match), `1` transform or
validation failure, `2` usage/preflight/not-root.

---

## 4. The awk Transform Engine

A library `scripts/lib/exemption-yaml.sh` (sourced by
`scripts/exemption.sh`, mirroring the `scripts/lib/binary-lock-yaml.sh`
pattern) provides four awk programs operating on line streams. All
share a block scanner that tracks the current top-level key and the
current `- ` entry within a list-of-maps, using the same
indent-discipline as `binary-lock-yaml.sh` (2-space `- ` starts an
entry; deeper indents are nested content).

### 4.1 `add`

1. Locate `<list-key>:` at top level.
2. If the line is `<key>: []`, replace it with `<key>:` and emit the
   new entry directly below.
3. If it opens a block list, emit the new entry after the last entry
   of that list (before the next top-level key or EOF).
4. Entry emission: `- <field>: <value>` for the first field,
   `  <field>: <value>` for the rest; comma-separated list fields emit
   `  <field>:` followed by `    - <item>` lines.
5. Duplicate check: before transforming, scan the list for an entry
   matching all provided fields; if found, exit 1 (`duplicate entry`).

### 4.2 `remove`

1. Scan entries of `<list-key>`; an entry matches when every provided
   `field=value` pair equals the entry's field (list fields match on
   set equality of items).
2. Drop matching entry blocks entirely (including nested sub-items).
3. If the list becomes empty, rewrite the key line as `<key>: []`.
4. No match: file unchanged, exit 0.

### 4.3 `set`

Replace the line `<key>: <anything>` at top level with
`<key>: <value>`. Refuse if `<key>` opens a block (list or map); that
is what `add`/`remove` are for.

### 4.4 Preservation rules (REQ-EX-103)

The engine is line-oriented and only ever rewrites lines inside the
target key's block (plus the key line itself for `[]` conversion).
Header comments, other keys, and their formatting pass through
unchanged. Blank-line runes inside a list block are preserved.

---

## 5. Preflight, Atomic Install, Validation

`scripts/exemption.sh` flow for a mutation:

1. `require_root` (exit 2 as non-root).
2. Preflight (exit 2): file exists and is a regular file; canonical
   path equals given path; owner is `root:root`.
3. `tmp=$(mktemp "$(dirname "$file")/.exemption.XXXXXX")`; trap-based
   cleanup on EXIT (house convention).
4. Run the awk transform from target to `tmp`. Transform failure →
   exit 1, target untouched.
5. Schema validation by basename dispatch (REQ-EX-301):
   - `quality_exceptions.yaml`: for the added/resulting entry require
     non-empty `hook`, `reason` >= 20 chars, `paths` >= 1 item,
     non-empty `added_by`. Unknown basenames skip this step.
6. Structural re-verification: re-scan `tmp` and assert the edit took
   effect exactly once (add: new entry present; remove: matched
   entries absent; set: scalar line equals new value). Failure →
   exit 1, target untouched.
7. `install -o root -g root -m 0644 "$tmp" "$file"` (atomic within
   the same filesystem; ownership/mode explicit, umask-independent).
8. Append the audit line (§6).

---

## 6. Audit

One line per mutation appended to the log file named by
`config/guard_paths.yaml` (`log_file`), format:

```
<utc-iso8601> exemption <intent> user=<SUDO_USER:-uid> file=<path> key=<key> fields=<k=v,k=v> result=ok
```

The log path constant is already compiled into the guard; the script
reads the YAML value with the same awk pattern other scripts use.
Audit failure prints a stderr warning but does not roll back the
mutation (REQ-EX-601): git history is the authoritative record.

---

## 7. Decommission of config-lock.sh

Deleted:

| Item | Location |
|---|---|
| `scripts/config-lock.sh` | entire script (lock/unseal/relock/status, state files, systemd-run timers) |
| Make targets + vars | `config-lock`, `config-unseal`, `config-relock`, `config-lock-status`, `CONFIG_LOCK_REPO`, `CONFIG_LOCK_MINUTES` |
| Guard unseal reader | `UNSEAL_STATE_FILE`, `read_unseal_state`, and the skip branch in `gitdir::lock()` (src/gitdir.rs) |
| Rust unseal tests | `read_unseal_state` cases in src/gitdir_tests.rs |
| Spec §11.7.1.1 | docs/specifications/SPEC-GIT-GUARD-HARDENING.md (replace with a pointer to this spec) |
| Runtime state | `/var/lib/workspace-guard/config-unseal/`, stray `<gitdir>/config-unseal.files` mirrors |
| Doc comment | src/gitdir.rs comment describing the unseal skip |

After removal, `gitdir::lock()` chowns/chmods every matched path on
every invocation with no skip list.

### 7.1 Migration of chattr-sealed repos

One-time operator pass per consumer repo (documented in OPERATOR.md):

```bash
sudo find <repo>/config -maxdepth 1 -name '*.yaml' \
  -exec chattr -i {} + -exec chown root:root {} + -exec chmod 0644 {} +
```

No Make target is kept for this; it is a migration runbook step, after
which the guard's ownership lock maintains the seal.

---

## 8. Makefile Targets

```makefile
exemption-add:
	@if [ "$$(id -u)" != "0" ]; then echo "ERROR: exemption-add needs root: sudo make exemption-add" >&2; exit 1; fi
	scripts/exemption.sh add "$(FILE)" "$(KEY)" $(FIELDS)

exemption-remove:
	@if [ "$$(id -u)" != "0" ]; then echo "ERROR: exemption-remove needs root: sudo make exemption-remove" >&2; exit 1; fi
	scripts/exemption.sh remove "$(FILE)" "$(KEY)" $(FIELDS)

exemption-list:
	scripts/exemption.sh list "$(FILE)" $(KEY)
```

`FIELDS` is word-split deliberately (operator supplies
`FIELDS="hook=x reason=... paths=vendor/ added_by=..."`). `list` is
not root-gated.

---

## 9. bats Suite (tests/shell/20-exemption.bats)

Helpers follow the established PATH-shadowing pattern of fake
executables under `tests/shell/`: a fake repo dir with pre-seeded YAML
fixtures (empty `exceptions: []`, populated block list with nested
`paths`, flat scalar thresholds file), a fake `id` reporting uid 0 for
root-path tests, and a fake `chown`/`install` where ownership
assertions need a non-root harness.

Coverage matrix (REQ-EX-700):

| area | cases |
|---|---|
| usage | `--help`, unknown intent, missing args |
| preflight | missing file, symlink, non-root-owned file |
| add | to `key: []`, to existing block list, nested `paths` list field, duplicate rejection |
| remove | single-field match, multi-field match, no-match (exit 0, unchanged), last-entry → `key: []` |
| set | scalar replace, refuse on block key |
| gating | non-root add/remove/set exit 2; non-root list ok |
| output | owner root:root, mode 0644, header comments + unrelated keys byte-identical |
| audit | line appended with intent/user/file/key/fields |

---

## 10. Security Properties

- A non-root agent CANNOT write any policy YAML at any time: the guard
  ownership lock is unconditional, and the only editor runs as root.
- No release window, no skip list, no timer, no mutable runtime state
  that punches holes in the lock.
- All edits are atomic (temp + `install`), fail-closed (validation
  before install), and auditable (log line + git history).
- `chattr +i` remains reserved for the binary-lock `.real` binaries
  (SPEC-BINARY-LOCK); policy YAMLs do not need immutability because
  root is the only writer and root is trusted.

---

## 11. Non-Goals

Per REQ-EX-NG-01..04: no yq-style query language, no cross-repo
semantic validation, no sudoers drop-in (existing full-admin grant
suffices), no runtime YAML parsing in the guard binary.
