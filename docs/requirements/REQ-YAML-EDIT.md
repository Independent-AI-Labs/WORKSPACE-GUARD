# Requirements: Secure YAML Policy Editor (workspace-yaml-edit)

**Date:** 2026-07-27
**Status:** DRAFT
**Type:** Requirements
**Related Specs:** [SPEC-YAML-EDIT](../specifications/SPEC-YAML-EDIT.md)
**Related:** [REQ-HOME-LOCK](REQ-HOME-LOCK.md), [REQ-GIT-GUARD](REQ-GIT-GUARD.md), [SPEC-GIT-GUARD-HARDENING](../specifications/SPEC-GIT-GUARD-HARDENING.md)
**Supersedes:** REQ-EXEMPTION-EDIT (deleted; the awk tool it specified was
replaced after a 35-finding security audit)

---

## Background

Policy YAML files (`*_exceptions.yaml`, `coverage_thresholds.yaml`,
`file_length_limits.yaml`, `dead_code.yaml`, `*_excludes.yaml`,
`banned_words.yaml`, `guard_*.yaml`, consumer quality-gate and
content-filter configs, ...) are locked to `root:root` by the git
guard's per-invocation ownership lock (`src/gitdir.rs`), so a non-root
agent cannot tamper with them. That ownership lock is sound and stays.

Legitimate edits go through a single root-gated tool. The first
implementation (`scripts/exemption.sh`, awk transform engine) was
scoped to exemption files only and was replaced after a security audit
found 35 defects, six of them critical fail-open holes (scalar/list
confusion, empty-item injection, circular self-verification, silent
value reclassification, escape interpretation, Makefile word
splitting). The replacement:

1. Is **generic**: it edits any guard-locked YAML policy file, not
   just exemption lists. Quality gates, content filters, thresholds,
   allowlists, and nested guard configs are all in scope.
2. Is **Rust-native** (`workspace-yaml-edit`, `serde_yaml`): all
   semantic decisions come from a real YAML parser; line scanning is
   used only to locate splice regions. No new runtime dependency is
   introduced (serde_yaml is already vendored for build/dev).
3. Keeps the "root edits directly; files are never released" model
   (REQ-HL-106 precedent): no unseal window, no timer, no state file,
   no skip list in the guard.

---

## 1. Scope (REQ-YE-001 series)

- **REQ-YE-001**: A single tool, the `workspace-yaml-edit` binary,
  shall be the only supported mechanism for scripted edits to
  guard-locked YAML policy files. It shall operate on any YAML file
  path given to it (repo-agnostic), not on a hardcoded repo or
  directory glob.

- **REQ-YE-002**: The tool shall support six intents:
  - `add <file> <list-key> <field-spec>...`: append one map entry to
    a list-of-maps key, or one item to a scalar-list key.
  - `remove <file> <list-key> <field-spec>...`: delete every list
    entry matching ALL given field specs.
  - `set <file> <dotted.key> <value>`: set a scalar key, top-level or
    nested.
  - `get <file> <dotted.key>`: print a scalar value. Read-only.
  - `list <file> [list-key]`: print the file or one key's block.
    Read-only.
  - `validate <file>`: parse the file and run its schema validator
    (REQ-YE-301). Read-only; usable by CI gates.

- **REQ-YE-003**: The tool shall cover every YAML policy file shape
  in the fleet: `key: []` empty lists, block lists of maps, nested
  list values under an entry, scalar lists, nested maps addressed by
  dotted keys, and flat scalar keys. Structure hardcoding beyond the
  schema registry of REQ-YE-301 is forbidden.

- **REQ-YE-004**: `add` on a key currently written as `key: []` shall
  convert it to block-list form, preserving any trailing comment on
  the key line. `remove` deleting the last entry shall rewrite the
  key as `key: []`, preserving any trailing comment.

- **REQ-YE-005**: `add` shall reject an entry that duplicates an
  existing entry on all provided fields (exit 4).

- **REQ-YE-006**: All semantics (entry matching, duplicate detection,
  type interpretation, verification) shall be computed from a real
  YAML parse of the document. Line-oriented scanning may only locate
  byte ranges to splice; it shall never decide meaning.

---

## 2. Atomicity and Fail-Closed Writes (REQ-YE-100 series)

- **REQ-YE-100**: Every mutation shall write to a temp file in the
  same directory as the target, validate the result, and only then
  atomically rename it over the target. A failed transform or
  validation shall leave the target byte-identical.

- **REQ-YE-101**: The installed file shall be owned `root:root` with
  mode 0644 regardless of umask.

- **REQ-YE-102**: The tool shall refuse to operate on:
  - a non-existent file (exit 2; it never creates policy files),
  - a symlink (canonical path must equal the given path),
  - a file not owned by `root:root` for mutations (the tool exists to
    edit guard-locked policy files, not user-owned YAML),
  - a symlink for reads as well (`list`/`get`/`validate`),
  - input it cannot parse (exit 1 with a diagnostic).

- **REQ-YE-103**: Header comments, unrelated keys, and their
  formatting shall be preserved byte-for-byte; the transform shall
  touch only the target key's block.

- **REQ-YE-104**: Mutations shall hold an exclusive flock for the
  whole read-transform-verify-install sequence so concurrent
  invocations cannot interleave or lose updates.

- **REQ-YE-105**: `--dry-run` shall print the would-be result as a
  unified diff and shall not modify anything. Dry runs are read-only
  and not root-gated.

---

## 3. Field Grammar and Matching (REQ-YE-200 series)

- **REQ-YE-200**: Field specs shall be unambiguous:
  - `name=value` is a scalar field; the value is literal (a comma in
    a scalar, e.g. a regex quantifier, never reclassifies it),
  - `name=[v1,v2]` is a list field; `name=[x]` is a single-element
    list and shall be emitted as a YAML list, never a scalar,
  - a bare value (no `name=`) is a scalar-list item.
  Empty list items (`name=[a,]`, `name=[,]`) shall be rejected at
  parse time (exit 2). `name=[]` expresses the empty list and is
  valid for matching and removal.

- **REQ-YE-201**: List matching shall be set-wise (order-insensitive)
  with duplicate spec items rejected; matched entries are comparable
  for removal with the same spec that added them (round-trip
  symmetry).

- **REQ-YE-202**: Spec values shall be compared verbatim against
  parsed YAML values; the tool shall not strip quotes, whitespace, or
  backslashes from user input. No shell/awk-style escape
  reinterpretation is permitted anywhere.

- **REQ-YE-203**: Emitted YAML shall be produced by a real YAML
  emitter, so strings that resemble booleans, nulls, or numbers are
  quoted correctly and single-element lists keep list type. `set`
  shall type its value by parsing it as a YAML scalar (so `80` stays
  numeric); `--string` shall force string typing.

- **REQ-YE-204**: Dotted keys shall resolve literally first (a
  top-level key containing a dot wins over path splitting), then by
  path segments. `set` on a key that opens a block (list, map, or
  block scalar) shall be refused with exit 2.

---

## 4. Schema Registry and Validation (REQ-YE-300 series)

- **REQ-YE-300**: All mutations shall pass structural verification:
  the temp output shall be re-parsed with the real YAML parser and
  the edit verified to have taken effect exactly once (add: entry
  count +1 and new entry deep-equals the spec; remove: no entry
  matches; set: key equals the new value). Verification shall never
  reuse the transform's own intermediate representation.

- **REQ-YE-301**: A schema registry shall validate known files by
  basename. The registry shall consist of a compiled-in table for the
  fleet's known policy files plus an optional root-locked override
  file (`config/yaml_edit_schemas.yaml`) so consumers can declare new
  files without recompiling. Each schema declares, per list key, the
  required fields, which fields are lists, and constraints (e.g.
  minimum length). Validators shall run against the parsed
  post-transform document. Unknown basenames get structural
  verification only.

- **REQ-YE-302**: Validation failure shall abort the mutation with a
  non-zero exit and shall not modify the target.

- **REQ-YE-303**: `validate <file>` shall run the same parse plus
  schema check read-only, exiting non-zero with diagnostics on
  failure.

---

## 5. Sudo Gating (REQ-YE-400 series)

- **REQ-YE-400**: `add`, `remove`, and `set` shall refuse to run as
  non-root (exit 2). `list`, `get`, `validate`, and `--dry-run` shall
  run as any user.

- **REQ-YE-401**: Make targets shall be provided:
  `yaml-add FILE=.. KEY=.. FIELDS="a=b;c=[x,y]"`,
  `yaml-remove`, `yaml-set`, `yaml-get`, `yaml-list`,
  `yaml-validate`. `FIELDS` shall be split on `;` (never on spaces)
  so multi-word values work. Non-root invocation of a mutating target
  shall print `ERROR: <target> needs root: sudo make <target>` and
  exit 1.

- **REQ-YE-402**: No filesystem release/relock cycle (chattr strip,
  ownership flip, timer, or state file) shall be performed as part of
  editing a YAML policy file. The `root:root` ownership lock applied
  by the guard is the only gating mechanism; chattr `+i` is preserved
  per REQ-YE-800, not removed.

---

## 6. Decommission (REQ-YE-500 series)

- **REQ-YE-500**: `scripts/exemption.sh` and
  `scripts/lib/exemption-yaml.sh` shall be deleted, together with the
  `exemption-add`/`exemption-remove`/`exemption-list` Make targets.
  The historical decommission of `config-lock.sh` (former REQ-EX-500
  series) remains in force: no unseal mechanism shall be
  reintroduced.

---

## 7. Audit (REQ-YE-600 series)

- **REQ-YE-600**: Every mutation shall append one audit line to the
  guard log file, recording: UTC timestamp, invoking user, intent,
  target file, key, and the field set. The log file name is a
  compiled-in constant that a unit test keeps identical to `log_file`
  in `config/shared_paths.yaml`. The log path shall be joined onto the
  invoking operator's home resolved via `SUDO_UID`/`getpwuid`, never
  via `$HOME` (which is root's home under sudo).

- **REQ-YE-601**: Audit write failure shall abort the mutation before
  install (fail-closed): the target stays untouched and the error is
  reported on stderr.

---

## 8. Testing (REQ-YE-700 series)

- **REQ-YE-700**: Rust unit tests shall cover the transform engine,
  spec grammar, matching, emission, verification, and schema
  validators, including one regression case per finding of the 2026-07
  audit (traceability table in SPEC-YAML-EDIT section 9).

- **REQ-YE-701**: A bats suite `tests/shell/20-yaml-edit.bats` shall
  cover the CLI surface: usage errors, unknown intent, non-root
  refusal of mutations, preflight diagnostics, `list`/`get`/`validate`
  as non-root, and `--dry-run` transforms as non-root. Root-requiring
  mutation paths shall run in the privileged Podman tier following
  the suite 16/17 pattern (PATH interception cannot fake `geteuid()`
  for a compiled binary).

---

## 9. Immutability (REQ-YE-800 series)

- **REQ-YE-800**: If the target carries the chattr immutable flag,
  the tool shall detect it (via `lsattr -d`), clear it transiently
  inside the flock immediately before install (`chattr -i`), and
  restore it immediately after (`chattr +i`). The file shall end
  every mutation with exactly the flags it started with. Failure to
  restore shall abort with a loud error. The e2fsprogs binaries are
  used instead of ioctl FFI so the crate contains no `unsafe` code.

- **REQ-YE-801**: This transient clear is not an unseal window: the
  file stays `root:root` mode 0644 throughout, the flag is down only
  for the rename syscall inside an exclusive flock held by a root
  process, and no non-root process can write the file at any point.

---

## 10. Non-Goals

- **REQ-YE-NG-01**: The tool is NOT a general YAML query engine (no
  yq-style path expressions beyond dotted keys) and NOT a
  pretty-printer; untouched regions are preserved byte-for-byte
  rather than re-emitted.
- **REQ-YE-NG-02**: The tool does NOT validate consumer-side
  semantics (e.g. whether a `hook` names a real hook id in
  WORKSPACE-CI); cross-repo semantic checks remain the consumer's
  job.
- **REQ-YE-NG-03**: No sudoers drop-in is introduced; the existing
  full-admin sudo grant already gates the tool.
- **REQ-YE-NG-04**: The guard binary gains no runtime YAML parsing.
  The editor is a separate operator binary.
- **REQ-YE-NG-05**: No persistent `.bak` files are written next to
  policy files (stray root-owned files trip consumer gates). Rollback
  is git history plus `--dry-run` preview; install is atomic and only
  follows successful real-parser verification.
- **REQ-YE-NG-06**: Editing of user-owned (non-locked) YAML is out of
  scope; a normal text editor serves that case.
