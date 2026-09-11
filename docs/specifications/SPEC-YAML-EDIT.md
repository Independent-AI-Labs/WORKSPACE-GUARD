# Specification: Secure YAML Policy Editor (workspace-yaml-edit)

**Date:** 2026-07-27
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-YAML-EDIT](../requirements/REQ-YAML-EDIT.md)
**Related:** [SPEC-HOME-LOCK](SPEC-HOME-LOCK.md), [SPEC-GIT-GUARD-HARDENING](SPEC-GIT-GUARD-HARDENING.md), [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md)
**Supersedes:** SPEC-EXEMPTION-EDIT (deleted; see section 9 for the
audit traceability that motivated the rewrite)

---

## 1. Architecture Overview

The git guard keeps every policy YAML `root:root` via its
per-invocation ownership lock (`src/gitdir.rs` `lock()`). Legitimate
edits go through one root-gated Rust binary that edits YAML contents
directly, generically, atomically, and fail-closed:

```
   Operator                          policy YAML (any guard-locked file)
   --------
   sudo make yaml-add \
     FILE=config/quality_exceptions.yaml \
     KEY=exceptions \
     FIELDS="hook=banned-words;reason=legacy vendored copy here;paths=[vendor/];added_by=op@x"
      |
      v
   /usr/bin/workspace-yaml-edit  (require_root for mutations)
      |  0. flock /var/lib/workspace-guard/yaml-edit.lock
      |  1. preflight: regular, no-follow, canonical, root:root, outside /opt;
      |     capture parent fd + target device/inode/metadata
      |  2. serde_yaml parse (fail-closed) of the whole document
      |  3. locate splice region by indentation; transform
      |  4. emit entry via serde_yaml emitter (valid by construction)
      |  5. re-parse temp + assert exact semantic delta (real parser)
      |  6. schema registry validation by basename
      |  7. chattr +i detected -> transient clear inside flock
      |  8. temp -> preserve uid/gid/mode -> fsync -> identity check -> rename
      |  9. fsync parent; restore chattr flags; audit line -> guard log
      v
   file stays root:root with its original mode (+ immutable if present)
```

Design rule (REQ-YE-006): **serde_yaml decides meaning; line scanning
only locates byte ranges.** Entry matching, duplicate detection,
typing, and verification all come from parsing. The splice step
touches only the target key's block so comments and unrelated
formatting survive byte-for-byte (REQ-YE-103).

Tooling: `serde`/`serde_yaml` move from build/dev-dependencies to
`[dependencies]`. No new runtime dependency, no external CLI (no yq,
no python) is introduced on the security boundary.

---

## 2. Threat Model

Attacks closed by design:

1. **Unseal-window tamper** (inherited from REQ-EX decommission):
   no release mechanism exists; a non-root process can never write
   policy YAML.
2. **Fail-open transform bugs**: the audited awk tool could emit
   scalars where consumers need lists, inject empty list items, and
   reclassify scalars containing commas, each silently widening an
   exemption to the whole repo. All emission now goes through a real
   YAML emitter and all verification through a real parser.
3. **Circular verification**: the old tool verified output with the
   same parser that produced it. Verification here re-parses the temp
   file with serde_yaml and asserts the exact semantic delta against
   the pre-edit parse.
4. **Lost updates**: concurrent root invocations interleaved
   read-transform-install. A global flock serializes mutations.
5. **Invariant split with CI**: WORKSPACE-CI `validate_exemption_file`
   requires the immutable bit; the old tool neither preserved nor
   restored it. chattr flags are now detected, transiently cleared
   only for the rename, and restored (REQ-YE-800/801).
6. **Audit ambiguity**: audit lines landed in root's home because
   `$HOME` under sudo is `/root`. The operator home is resolved from
   `SUDO_UID` via `getpwuid`.

The operator's root channel (sudo) remains trusted, as everywhere
else in this stack. Git history of the locked, committed files is the
authoritative change record.

---

## 3. Command Grammar

```
workspace-yaml-edit add      <file> <list-key> <field-spec>...   (ROOT)
workspace-yaml-edit remove   <file> <list-key> <field-spec>...   (ROOT)
workspace-yaml-edit set      <file> <dotted.key> <value>         (ROOT)
workspace-yaml-edit bootstrap <file> <top-level-key> <value>      (ROOT)
workspace-yaml-edit unset    <file> <dotted.path>                 (ROOT)
workspace-yaml-edit remove-comment <file> <exact-comment-text>    (ROOT)
workspace-yaml-edit delete   <file> --expected-sha256 <digest>    (ROOT)
workspace-yaml-edit get      <file> <dotted.key>
workspace-yaml-edit list     <file> [<list-key>]
workspace-yaml-edit validate <file>
workspace-yaml-edit check    <file>
workspace-yaml-edit format   <file> [--dry-run]                   (ROOT)
```

Flags: `--dry-run` (mutations and format only; print unified diff, no
install, not root-gated), `--allow-no-match` (remove only; no-match
exits 0 instead of 3), `--string` (set only; force string typing),
`--create` (set only; insert an absent leaf key under an existing
block-mapping parent, REQ-YE-205), and `--expected-sha256` (delete
only; mandatory reviewed digest).

### 3.7 Syntax + format preflight (operator ruling 2026-09-06)

Every mutating intent runs two separate pre-mutation steps before any
transform: syntax (the document must parse) and format (every block
sequence's dash items must sit strictly deeper than their parent key
indent, section 4.1). A target with an indentless block sequence is
refused with exit 2, one precise error per offending key (key name,
line, both indents), and the instruction
`run: workspace-yaml-edit format <file>`; no mutation, not even
`--dry-run`, proceeds on an unformatted target. Formatting is its own
audited command (`format`), never a side effect of an edit.

`check` is the unprivileged read-only preflight: syntax, registry
schema, and splice-shape in one pass; exits 1 listing every finding.

`format` canonicalizes indentless block sequences (dash at key indent
+ 2). Comments, blank lines, key order, scalar spelling, and trailing
bytes survive byte-for-byte except for the inserted indentation
(REQ-YE-103); the result must re-parse to the identical document
(section 4.4 verification) and pass the registry schema; idempotent
(second run reports `unchanged`). Root-gated, lock-serialized,
audited, atomically installed like every mutation.

### 3.1 Field spec grammar (REQ-YE-200)

| spec | meaning |
|---|---|
| `name=value` | scalar field; value literal (commas included) |
| `name=[v1,v2]` | list field; emitted as a YAML list |
| `name=[x]` | single-element list (stays a list in output) |
| `name=[]` | empty list (valid for matching/removal) |
| `value` | bare item for scalar-list keys |

Rejected at parse time (exit 2): empty items (`[a,]`, `[,]`),
duplicate items within one list spec, malformed brackets, field names
outside `[A-Za-z0-9_.-]+`.

### 3.2 Matching semantics

An entry matches when every spec field deep-equals the parsed entry:
scalars compare verbatim (no quote/backslash stripping of user input),
lists compare set-wise. The same spec that adds an entry removes it
(round-trip symmetry, REQ-YE-201).

### 3.3 Dotted keys (REQ-YE-204)

`set`/`get` resolve a dotted key literally first (a key literally
containing a dot at the current level wins), then descend segment by
segment through maps. `set` refuses a key that opens a block (list,
map, or block scalar) with exit 2 and a dedicated message.

With `--create`, a `set` whose dotted key does not resolve instead
splits at the last dot: the parent path must resolve to an existing
block mapping, and the new leaf key is appended at the end of the
parent's block region at child indent. Missing parents, flow-style
parents, non-mapping parents, and top-level keys (use `bootstrap`)
all fail closed (REQ-YE-205).

### 3.4 Unset paths

`unset` uses a deliberately smaller path grammar than a general YAML query
language:

```text
path      = segment ("." segment)*
segment   = name | name "[]"
name      = one or more ASCII letters, digits, `_`, `-`, or `/`
```

`[]` is valid only on a non-final segment and applies the remaining path to
every sequence item. `hooks[].safety` therefore removes `safety` from every
mapping in `hooks`. Every branch is validated first: the sequence must be
non-empty, every item must be a mapping, every intermediate field must have
the required mapping/sequence kind, and every final field must exist. One bad
or missing branch aborts the whole operation before a splice is produced.

2026-09-06: map keys named after file paths (e.g. classification manifest
entries) contain dots and slashes. Unset resolves each level literal-first
like `set`/`get` (REQ-YE-204): the longest join of consecutive non-wildcard
segments that exists as a key at the current level wins over the
single-segment interpretation, so `files.config-staging/banned_words.yaml`
addresses the literal key `config-staging/banned_words.yaml` inside `files`.
The splice layer locates such key lines verbatim; comments and sibling
entries are untouched.

### 3.5 Exact comment text

`remove-comment` scans only lines whose first non-indentation byte is `#`.
For comparison it removes the indentation, `#`, and any indentation spaces
immediately following `#`. The remaining bytes must exactly equal the argument.
No regular expression engine, shell evaluation, substring match, inline-comment
match, or scalar-value match is involved. Every exact full-line match is
removed. Blank-line normalization is local to each removed line and limits a
newly adjacent blank run to one line without changing pre-existing runs
elsewhere.

### 3.6 Exit codes

| rc | meaning |
|---|---|
| 0 | ok |
| 1 | transform, parse, or validation failure |
| 2 | usage error, preflight failure, not-root, wrong key kind |
| 3 | remove matched nothing |
| 4 | add would duplicate an existing entry |

Error messages distinguish "key missing", "key is not a list", and
"key is not a scalar" (three different operator problems).

---

## 4. Transform Engine

Module layout (512-line house cap; `#[path]` mod pattern of
`binary_guard.rs`):

| file | role |
|---|---|
| `src/yaml_edit.rs` | bin: CLI parse, root gate, preflight, flock, orchestration, chattr, audit |
| `src/yaml_edit_engine.rs` | spec parsing, entry build/match, line-splice transform, verification |
| `src/yaml_edit_schema.rs` | schema registry: built-in table + override file, `validate` |
| `src/yaml_edit_diff.rs` | minimal unified diff for `--dry-run` |

### 4.1 add

1. Parse the document with serde_yaml (fail closed on any parse
   error: tabs, BOM, multi-document, anchors the emitter cannot
   round-trip).
2. Locate `<list-key>` at top level in the parsed value; it must be a
   sequence (distinct errors for missing vs wrong kind).
3. Build the new entry as a `serde_yaml::Value` from the field specs;
   serialize it with `serde_yaml::to_string` and re-indent under the
   key (entry indent = key indent + 2).
4. Duplicate check against the parsed sequence (deep equality on spec
   fields); duplicate -> exit 4.
5. Splice: line-scan only to find the key line and its block region
   (region = lines below the key line with indent > key indent, up to
   the next top-level key or EOF). `key: []` becomes `key:` with any
   trailing comment preserved; otherwise insert after the region's
   last content line.
6. Write temp, verify (section 4.4), schema-validate, install.

### 4.2 remove

1. Parse; find the sequence; compute matching item indexes from the
   parsed values.
2. No match -> exit 3 (or 0 with `--allow-no-match`), target
   untouched.
3. Line-scan the block region to map the i-th sequence item to its
   line range (entry starts at indent = region minimum `-` indent;
   extent = up to the next line at <= that indent). Drop matched
   ranges. Comments stay in place (documented trade-off: dropping
   them risks eating shared section comments).
4. If the list becomes empty, rewrite the key line as `key: []`
   preserving any trailing comment.
5. Temp, verify, validate, install.

### 4.3 set / get

Resolve the dotted key against the parsed document (literal-first,
then segments). The parent chain must consist of maps. For `set`:
the target node must be scalar (or absent as a leaf under an existing
map? No: the key must already exist; the tool never creates policy
structure). Type the new value by parsing it as a YAML scalar unless
`--string` is given. Splice replaces the key line (and, for a
multi-line scalar such as a block scalar being replaced, its whole
node line range) with `<indent><key>: <emitted>`.

### 4.4 Verification (REQ-YE-300)

After writing the temp file, re-parse it with serde_yaml and assert
exactly one semantic delta against the pre-edit parse:

- add: sequence length +1 and the new item deep-equals the spec entry
- remove: no item matches the spec and length decreased by the number
  of matched entries
- set: the resolved key deep-equals the new typed value

Any mismatch aborts before install. The verifier never sees the
transform's intermediate representation; it only sees two parses.

### 4.5 Preservation rules

Only the target key's block region (plus the key line for `[]`
conversion) is rewritten. Everything else is copied byte-for-byte,
including header comments, blank lines, and unrelated keys.

### 4.6 unset

The semantic engine parses and expands the complete strict path against a
clone of the parsed document. It records concrete mapping-field removals only
after every wildcard branch validates. The splice layer then removes each
field node from the original bytes, including that field's nested value block
but not unrelated surrounding comments. A field on a sequence dash line is
rewritten to a valid remaining mapping item; an emptied mapping is emitted as
`{}`. The result is reparsed and must deep-equal the independently mutated
clone. Success prints the number of removed fields.

### 4.7 remove-comment

The original document must parse before scanning. After literal full-line
comment removal and local blank normalization, the result must parse and
deep-equal the original semantic document. Success prints the number of
removed comments. A zero count is an error and publishes nothing.

### 4.8 Terminal normalization

Every text mutation passes through one final terminal normalizer. It removes
only terminal blank or whitespace-only lines, then appends exactly one `\n`.
Changed and emitted lines contain no trailing spaces. Interior unrelated bytes
are copied unchanged. This fixes the final-list-entry regression where
terminal line reconstruction produced a new blank line at EOF.

---

## 5. Schema Registry (REQ-YE-301)

Two layers, merged at runtime (override wins per basename):

1. **Built-in table** (compiled in `yaml_edit_schema.rs`) for the
   fleet's known files. Examples:
   - `quality_exceptions.yaml`: key `exceptions` list-of-maps;
     required `hook`, `added_by`; `paths` is a list with >= 1 item;
     `reason` >= 20 chars.
   - `banned_words_exceptions.yaml` / `silent_swallow_exceptions.yaml`:
     key `exceptions`; required `pattern`; `paths` list >= 1 item.
   - `sensitive_files_exceptions.yaml`: key `safe_exceptions` scalar
     list; items non-empty.
   - `coverage_thresholds.yaml`: scalar leaves under known groups must
     be numeric.
   - `file_length_limits.yaml`: `max_lines` numeric.
2. **Override file** `yaml_edit_schemas.yaml`, looked up next to the
   target file (repo-agnostic; typically itself a root-locked policy
   file) declaring schemas for additional basenames, so consumers
   (quality gates, content filters) register new files without
   recompiling. Format:

```yaml
version: 1
schemas:
  - basename: my_gate_exceptions.yaml
    key: exceptions
    kind: list-of-maps        # list-of-maps | scalar-list
    list_fields: [paths]      # if present in an entry, must be a list
    required_lists: [paths]   # must be present, list with >= 1 item
    required: [pattern, reason]
    min_length: {reason: 20}
    numeric_keys: [timeout]   # leaf key names (any depth) that must be numeric
```

Validators run against the parsed post-transform document (and, for
`validate`, against the file as-is). Unknown basenames get structural
verification only. If the override file exists it must parse and must
be `root:root`; a malformed or non-root-owned override fails closed.

---

## 6. Security Envelope

Mutation flow (`yaml_edit_ops.rs` / `yaml_edit_install.rs`):

1. `require_root` (geteuid == 0, else exit 2). Skipped for
   `list`/`get`/`validate`/`--dry-run`.
2. If a `yaml_edit_schemas.yaml` override exists next to the target,
   it must be a root:root regular file (exit 2 otherwise).
3. Preflight (exit 2): reject parent-directory traversal components; resolve
   an absolute path; reject `/opt` and every descendant for mutations; require
   an existing regular file whose canonical path equals the normalized input;
   and, for mutations, require owner uid/gid 0. Reads refuse symlinks too.
4. Open and flock `/var/lib/workspace-guard/yaml-edit.lock`
   (LOCK_EX; directory created root:root 0700 if missing).
5. Open the parent directory and target with no-follow descriptor-relative
   operations, capture device/inode/uid/gid/mode/timestamps, read the already
   open target, and parse with serde_yaml (exit 1 on parse error).
6. Transform in memory (splice), then verify: the result re-parses
   with serde_yaml to exactly the expected semantic document
   (REQ-YE-006), then schema validation against the registry.
7. Audit line (section 7). Write failure aborts before install
   (REQ-YE-601).
8. Install: detect the immutable flag via `lsattr -d` (unsupported
   filesystem means "no flags", with a stderr notice); `chattr -i` if
   set; write the verified content to a temp file in the same
   directory (mode 0600); apply the captured uid, gid, and permission mode;
   flush the temp file; recheck target device/inode immediately before
   descriptor-relative rename; rename over the target; flush the parent
   directory; restore `chattr +i`. Failure to restore is a
   loud error: the edit succeeded but the file must not be left
   unsealed.

`--dry-run` runs steps 3 and 5-6 in memory and prints a unified diff
(`yaml_edit_diff.rs`, LCS-based, no external `diff` dependency); it
requires no root and installs nothing.

### 6.1 Guarded deletion

`delete` runs under the same root gate, `/opt` prohibition, deployed-CI
restriction, global lock, no-follow preflight, root ownership check, malformed
YAML rejection, immutable-state handling, and audit requirement. The expected
digest must be exactly 64 hexadecimal characters. SHA-256 is computed from the
already-open file descriptor. A post-hash `fstat` must match the captured
identity and stability metadata, and a no-follow lookup through the open
parent directory must still identify the same device/inode immediately before
unlink. Digest mismatch or identity drift leaves the path untouched. Success
unlinks only that basename through the parent descriptor, fsyncs the parent,
and prints both the deleted path and verified lowercase digest. Directories,
symlinks, globs, and recursive deletion have no command grammar.

---

## 7. Audit

One line per mutation is appended only to the verified root-owned
`/var/log/workspace-guard/yaml-edit-<invoking-uid>.log`. No HOME log or mirror
exists. Secure directory-fd opening, metadata checks, locking, append, sync, and
failure diagnostics follow SPEC-GIT-GUARD §7.2. `SUDO_UID` identifies the
operator for this root-only editor; it never selects an audit directory:

```
<utc-iso8601> yaml-edit <intent> user=<name> file=<path> key=<key> fields=<k=v;k=[x,y]> result=ok
```

(`set` records `value=<v>` in place of `fields=`; delete records the verified
digest.) Audit write failure aborts before install or unlink (REQ-YE-601).

---

## 8. Makefile Targets and Install

```makefile
yaml-add:      ## (ROOT) FIELDS="hook=x;reason=...;paths=[a,b];added_by=.."
yaml-remove:   ## (ROOT) FIELDS="hook=x;paths=[a]"
yaml-set:      ## (ROOT) FILE=.. KEY=unit.threshold VALUE=80
yaml-bootstrap: ## (ROOT) FILE=.. KEY=top_level VALUE=123
yaml-unset:    ## (ROOT) FILE=.. KEY='hooks[].safety'
yaml-remove-comment: ## (ROOT) FILE=.. VALUE='exact comment text'
yaml-delete:   ## (ROOT) FILE=.. EXPECT_SHA256=<reviewed digest>
yaml-get:      ## FILE=.. KEY=unit.threshold
yaml-list:     ## FILE=.. [KEY=exceptions]
yaml-validate: ## FILE=..
yaml-check:    ## FILE=..
yaml-format:   ## (ROOT) FILE=..
```

`FIELDS` is split on `;` via `IFS=';' read -ra` inside the recipe, so
multi-word values (reasons, patterns with spaces) work. Mutating
targets print `ERROR: <target> needs root: sudo make <target>` and
exit 1 as non-root.

Install: `make install-yaml-edit` (root) runs
`install -o root -g root -m 0755 target/release/workspace-yaml-edit /usr/bin/`,
following the `install-lock-runtime` precedent (WG-owned install, no
CI bootstrap change required). Adding the binary to CI's drift-check
manifest is an optional follow-up requiring operator sudo on the
root-owned CI repo.

---

## 9. Audit Traceability (2026-07 awk-tool audit, 35 findings)

| # | finding | fix |
|---|---|---|
| 1 | single-element list emitted as scalar | emitter-driven output (4.1 step 3); schema declares list fields (5) |
| 2 | trailing comma injects `''` item | empty items rejected in spec parse (3.1) |
| 3 | circular self-verification | real-parser delta verification (4.4) |
| 4 | comma in scalar reclassifies as list | list syntax is bracketed only (3.1) |
| 5 | awk -v backslash escapes | Rust strings; no escape layer (3.2) |
| 6 | Makefile word-split FIELDS | `;` separator via IFS (8) |
| 7 | YAML type confusion on emission | serde_yaml emitter quotes correctly (3.4/REQ-YE-203) |
| 36 | timestamp strings emitted plain, PyYAML (YAML 1.1) re-reads them as `datetime.date` | `needs_quotes` in `yaml_edit_emit.rs` quotes YAML 1.1 timestamp shapes (`YYYY-M-D` with optional `[T ]hh:mm:ss` suffix) alongside booleans/nulls/numbers (2026-09-07 activation fix) |
| 8 | chattr +i invariant mismatch with CI | lsattr detect / chattr -i / install / chattr +i restore (6 step 8) |
| 9/13 | no mutual exclusion | global flock (6 step 2) |
| 10 | hardcoded 2-space indent | indents computed from the document (4.1 step 5) |
| 11 | inline comment breaks `[]` detection | key-line rewrite preserves trailing comment (4.1) |
| 12 | S-spec truncation drops fields | entry built as one Value, emitted whole (4.1) |
| 14 | duplicate list values round-trip asymmetry | duplicate spec items rejected (3.1) |
| 15 | empty-list entries unremovable | `name=[]` spec (3.1) |
| 16 | tabs/CRLF mis-parse | serde_yaml parse fails closed (4.1 step 1) |
| 17 | inline comments parsed into values | semantics from parse, not line text (REQ-YE-006) |
| 18 | multi-line flow lists | handled by the parser |
| 19 | cannot add to inline flow list | `key: [a]` region spliced like block form |
| 20 | dotted-key ambiguity | literal-first resolution (3.3) |
| 21 | remove no-match exits 0 | exit 3 default, `--allow-no-match` opt-out (3.4) |
| 22 | audit fail-open, wrong home | abort-on-failure, SUDO_UID home (7) |
| 23 | list skips symlink preflight | reads refuse symlinks (6 step 3) |
| 24 | GNU-only stat | Rust `std::os::unix::fs::MetadataExt` (portable) |
| 25 | no backup/rollback | atomic rename + verify + dry-run + git history (REQ-YE-NG-05) |
| 26 | quoted keys unsupported | handled by the parser |
| 27 | BOM breaks first key | handled by the parser |
| 28 | block scalars orphaned by set | node line range replaced wholesale (4.3) |
| 29 | `[]` add/remove drops key-line comment | comment preserved (4.1/4.2) |
| 30 | comment reshuffle on remove | comments preserved in place (4.2, documented) |
| 31 | deqspec strips quotes from spec values | verbatim comparison (3.2) |
| 32 | no dry-run | `--dry-run` unified diff (6) |
| 33 | no schema validation for set | registry validators cover scalars (5) |
| 34 | validators for one basename only | registry covers fleet + override file (5) |
| 35 | conflated rc-2 messages | distinct key-kind errors (3.4) |

---

## 10. Testing

- Rust unit tests (`src/yaml_edit_tests.rs`,
  `src/yaml_edit_engine_tests.rs`, `src/yaml_edit_schema_tests.rs`):
  engine, grammar, matching, emission, verification, schemas, and one
  regression test per section-9 finding.
- bats `tests/shell/20-yaml-edit.bats`: usage/exit codes, non-root
  refusal, preflight diagnostics, `list`/`get`/`validate`, and
  `--dry-run` transforms as a non-root user. Root mutation paths
  (install, chattr, flock, audit) run in the privileged Podman tier
  following the suite 16/17 pattern; PATH interception cannot fake
  `geteuid()` for a compiled binary and `unshare -Ur` is blocked in
  this container.
- Root-tier deletion tests cover required/correct/mismatched digests,
  symlinks, directories, concurrent replacement detection, parent fsync,
  immutable handling, and exact owner/group/mode preservation for rewrites.
- EOF regressions assert exactly one terminal newline after every mutation and
  specifically after removing the final list entry.

---

## 11. Security Properties

- A non-root agent CANNOT write any policy YAML at any time: the
  guard ownership lock is unconditional, and the only editor runs as
  root.
- No release window, no skip list, no timer, no mutable runtime state
  that punches holes in the lock.
- All edits are atomic and durable (temp + file fsync + rename + parent fsync),
  fail-closed (parse,
  verification, schema, audit all abort before install), and
  auditable (log line + git history).
- chattr `+i` is preserved end-to-end: files under WORKSPACE-CI's
  exemption manifest keep passing `validate_exemption_file` after
  every edit, with the flag down only for the rename syscall inside
  the flock.
- No mutation can target `/opt`; source policy changes must flow through
  review and the deployment control plane before reaching installed artifacts.

---

## 12. Non-Goals

Per REQ-YE-NG-01..06: no yq-style query language beyond the documented unset
wildcard, no whole-document
re-emission, no consumer-side semantic validation, no sudoers
drop-in, no YAML parsing in the guard binary, no persistent `.bak`
files, no editing of user-owned YAML.
