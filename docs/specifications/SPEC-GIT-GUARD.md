# Specification: WORKSPACE-GUARD Capability Guard Framework (Git PoC)

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
        /usr/bin/git (root-owned 0755, four file capabilities)
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

The guard is a **thin capability-enabled wrapper**. Its sole purpose is to:

1. Validate the argument vector for destructive patterns.
2. Sanitise the execution environment.
3. If safe, `execve()` the real git binary.
4. If unsafe, block with an audit log entry.

It does NOT re-implement git logic. It does NOT re-implement WORKSPACE-CI contract checks. It delegates contract verification to the existing `checks_quality.sh` script.

### Key Design Principle

> **Deny-list, not allow-list.** The guard blocks known-dangerous operations and passes everything else through. An allow-list would require knowing every git subcommand and flag combination: impossible to maintain. The deny-list covers the operations that actually cause data loss or security breaches.

---

## 2. Privileged Execution

### 2.1 Capability Model

The host-exec binary is installed at `/usr/bin/git` with owner `root:root`,
mode `0755`, and file capabilities
`cap_setpcap,cap_chown,cap_dac_override,cap_fowner=ep`. It is not SUID-root.
The process keeps the invoking user's real and effective UID.

The real Git binary is at `/usr/bin/git.original` with owner `root:root` and
mode `0700`. A non-root user cannot execute it directly. The guard loans only
`CAP_DAC_OVERRIDE` to the authorized `git.original` child. `CAP_SETPCAP`,
`CAP_CHOWN`, and `CAP_FOWNER` remain guard-only.

The sandbox-service deployment class receives the same four capabilities from
the systemd service's ambient capability set instead of file capabilities. One
host uses exactly one deployment class.

### 2.2 Privileged Execution Detection

Capability mode treats kernel capability sets, not UID differences or
`AT_SECURE`, as the privilege authority:

- `host-exec` requires all four approved capabilities in Effective and
  Permitted and requires `PR_GET_NO_NEW_PRIVS == 0`;
- `sandbox-service` requires all four in Ambient and Permitted, then promotes
  them to Effective;
- a missing, non-regular, non-root-owned, or unknown deployment-class record
  fails closed.

Checking every capability prevents an unprivileged copy of the guard from
running and prevents a partially provisioned installation from proceeding.
`AT_SECURE` may inform behavior that depends on secure execution, but it is not
the capability-mode privilege check.

Root-only builds do not use process capabilities. They require effective UID 0
and remain an explicitly documented soft barrier.

Any failure in this section exits 3 before argument policy evaluation or real
Git execution. Exit 2 is reserved for malformed invocation arguments.

Privilege/deployment inspection returns typed outcomes. A `PR_GET_NO_NEW_PRIVS`
syscall error is failure, never equivalent to value 0. Capability-query errors
are distinct from a verified missing capability, though both exit 3. Root-only
effective-UID failure, deployment-class trust/parse failure, and capability
promotion failure use the same guard-unavailable class and preserve their stage
and OS status.

### 2.3 Real Git Verification

Before `execve()`, the binary verifies `/usr/bin/git.original`:

1. Inspect the path with no-follow metadata; a symlink is rejected even when
   its target is otherwise valid.
2. The path must exist and be a regular file (`S_IFREG`).
3. Owner UID and GID must both be 0.
4. `st_mode & 07777` must equal exactly `0700`, rejecting setuid, setgid, and
   sticky bits as well as relaxed permissions.
5. Device and inode must differ from `/proc/self/exe`, preventing a copied or
   recursively installed guard from serving as real Git.

If any check fails, exit code 3 before executing real Git. `/usr/bin` is
root-controlled, so a non-root caller cannot replace the directory entry
between verification and the absolute-path `execve()`.

---

## 3. Argument Parsing

### 3.1 Parsing Phases

Parsing is a multi-pass process over the argv array. Each phase operates on the result of the previous phase.

**Phase 1: Byte-preserving argv conversion:** Linux `execve()` cannot deliver
an embedded null inside argv. The guard nevertheless treats `CString`
construction as fallible for internally constructed/test inputs. Every raw
`OsStr` byte is copied unchanged, including non-UTF-8 bytes. An embedded-null
conversion failure exits 2; no placeholder, truncation, lossy conversion, or
argument omission is permitted.

Exit 2 is a typed invocation-validation class, not a generic fail-closed status.
It also covers a missing operand for a recognized value-taking global option
when subcommand discovery cannot continue and an unknown leading option whose
unknown arity makes the subcommand indeterminate. Empty or uninspectable
safety-critical config keys follow §3.3. Other malformed command-specific syntax
is forwarded unchanged once the guard can reliably identify and apply policy;
real Git remains syntax authority. Non-UTF-8 bytes outside explicitly ASCII
inspected fields are valid. Terminal-query and no-subcommand forms are valid.
Git's own exit 2 is an ordinary propagated Git outcome, while internal,
privilege, integrity, exec, and supervision failures use guard exit 3.

There is no whole-argument UTF-8 conversion. Parser state retains indexes/ranges
into the original byte arguments. ASCII option names, separators, subcommands,
and policy prefixes are compared directly as bytes. A failed `from_utf8` shall
never become `""`, a non-match, or a shortened token. Opaque option values,
operands, pathspecs, refs, remote names/URLs, and everything after the applicable
`--` remain bytes. If an ASCII policy prefix applies independently of an opaque
attached value, the prefix is still classified and only the value remains
opaque. A non-ASCII positional subcommand candidate matches no compiled ASCII
category and follows the capless unknown-command path. A non-ASCII leading option
uses the same arity rule as any unknown option and exits 2 only when reliable
subcommand discovery is impossible.

All accepted arguments, including caller `argv[0]`, are converted exactly once
with fallible `CString::new` before fork and retain order, count, and empty
arguments. The fixed `execve` pathname is separate from `argv[0]`. Conversion
failure for caller argv is `InvalidInvocation` exit 2. Conversion failure for a
guard-owned argument, environment entry, binding, or path is
`GuardUnavailable` exit 3. No placeholder, replacement character, truncation,
drop, `filter_map(...ok())`, or reconstructed forwarding vector is permitted.

Security and evidence paths never use `to_string_lossy`, `from_utf8_lossy`,
`Path::display`, or UTF-8-dependent containment. Repository/workspace identities
remain `PathBuf`/`OsString` and path-component comparisons. Environment names are
matched against ASCII catalogs as bytes; admitted values remain raw. A helper
protocol field becomes text only after its complete bytes satisfy that field's
exact ASCII grammar. Opaque helper streams use the reversible framing in §5.5.

**Phase 2: Subcommand identification:** Walk leading arguments with a compiled
global-option arity table:

1. Terminal query options (`--version`, `--help`, bare `--exec-path`,
   `--html-path`, `--man-path`, `--info-path`) terminate subcommand discovery;
   the complete invocation passes through unchanged.
2. Modifier options without operands are consumed as modifiers.
3. Value-taking options consume their attached or following operand before
   scanning continues. This includes repeated `-C <path>`, `-c name=value`,
   `--git-dir`, `--work-tree`, `--namespace`, and `--config-env` in every form
   accepted by Git.
4. `-C` changes directory. Only lowercase `-c` and `--config-env` carry config
   keys for dangerous-key validation.
5. The first remaining positional token is the subcommand.
6. A leading `--` before a subcommand leaves the invocation without an
   identified subcommand; real Git remains the syntax authority.
7. An unknown leading option whose operand arity is not known exits 2. The
   parser never guesses and thereby skips a later destructive subcommand.

**Phase 3: Subcommand-specific option collection:** After the subcommand is
identified, parse its remaining argv with a command-specific option-arity
table. Values consumed by `-m`, `--message`, and other value-taking options are
data even when they begin with `-`. Stop option interpretation at the applicable
`--` separator.

- For `push`: block `--force`, `-f`, bare `--force-with-lease`, and
  `--force-with-lease=<value>`.
- For `tag`: block actual `--force`/`-f` options.
- For `branch`: block actual `--force`/`-f`, `-D`, and force-rename options.
- For hook-running commands: block `--no-verify` and only the short aliases
  defined by that command's grammar.
- For `commit`: check for `--amend` in remaining args
- For `revert`: do not classify targets; pass argv through to Git

**Phase 4: Decision:** Apply the block decision engine (§4) using the collected state. If no block, proceed to `execve()`.

### 3.2 Edge Cases

| Input                                 | Behaviour                                                                  |
| ------------------------------------- | -------------------------------------------------------------------------- |
| `git` (no args)                       | Pass through to real git                                                   |
| `git --`                              | Pass through (no subcommand, separator only)                               |
| `git -- --hard`                       | Guard passes through; real Git rejects the separator before a subcommand   |
| `git log -- --hard`                   | `--hard` is a pathspec after the subcommand separator, not a flag           |
| `git -c` (no value)                   | Pass through: git will error on missing value                              |
| `git -C repo status`                  | Consume `repo` as directory; identify `status` as subcommand                |
| `git -Crepo reset`                    | Consume attached directory; identify and block `reset`                     |
| `git --git-dir repo/.git reset`       | Consume option operand; identify and block `reset`                          |
| `git -c core.hooksPath=/tmp/evil`     | Blocked: key is `core.hooksPath`                                           |
| `git --upload-pack=/bin/sh clone ...` | Blocked if `--upload-pack` is in the block list (it is a dangerous flag)   |

### 3.3 Config-Bearing Global Options

Config injection is parsed only in the leading global-option region. Supported
forms are:

```text
-c name=value
-c name
-cname=value
-cname
--config-env=name=environment_variable
```

Each complete option is consumed before subcommand discovery continues. The
guard stores only the exact key byte range, normalizes it with ASCII-only case
folding for compiled-pattern matching, and retains the original argv separately
as forensic evidence. Repeated overrides
are all checked; one blocked key blocks the invocation. Dangerous keys block
all users, while sudo-gated keys follow the effective-UID operator rule.

For `-c`, splitting occurs on the first `=` only. Additional `=` bytes remain
part of the opaque value. When no `=` exists, Git treats the complete payload as
a key with implicit boolean true, so both separate and attached no-value forms
must still be checked. The key is the exact pre-`=` bytes: whitespace is not
trimmed or otherwise rewritten. Keys are parsed without lossy UTF-8 conversion
and use explicit ASCII case folding. Empty, non-ASCII, or structurally
uninspectable keys exit 2; they are never replaced with an empty string. Values
are not needed in normalized policy state, but original argv values are forwarded
byte-identically and remain complete report/audit evidence.

After policy accepts a syntactically valid key, execution uses the original
argv byte slices rather than reconstructed or normalized arguments. This
preserves safe config options and opaque values exactly. It does not preserve
environment variables that the guard independently removes under its mandatory
environment-sanitization policy.

Uppercase `-C` consumes a repository-directory operand and is never config.
There is no synthetic `--config` option. Once the subcommand or applicable `--`
separator is reached, later tokens are interpreted only by that command's
grammar. Malformed global config forms are forwarded unchanged for Git's own
diagnostic unless their arity prevents reliable subcommand identification, in
which case REQ-GGUARD-011 exits 2.

#### Dangerous Config Policy Catalog

`config/git_guard_config_keys.yaml` is the only key-pattern authority. Each
entry records:

- glob pattern (`*` is one key segment, `**` is zero or more segments);
- enforcement class (`dangerous` or `sudo_gated`);
- threat class;
- concrete reason tied to Git behavior.

The catalog covers every known configuration surface that can execute a
command, redirect hooks/aliases/filters/merge drivers/pagers, expose
credentials, alter transport or protocol policy, redirect repository/worktree
or remote operations, or disable integrity checks. Unconditional entries apply
to root as well as non-root. Sudo-gating is limited to reviewed operator
identity and editor settings.

Every entry has a positive blocked matrix case and a syntactically adjacent
allowed control so wildcard overreach is visible. The pinned Git upgrade
procedure inventories new configuration keys and requires an explicit threat
classification before the upgrade is accepted.

### 3.4 Subcommand Recognition

The guard does not maintain a catalog of every harmless Git command. It
classifies only commands carrying policy:

- `blocked`: unconditional denial;
- `sudo_gated`: denied to non-root and allowed to the operator path;
- `partial`: requires command-specific argument policy;
- `contract_check`: invokes the immutable WORKSPACE-CI policy engine;
- `capability_loan`: may receive Ambient `CAP_DAC_OVERRIDE` while real Git
  executes;
- `mutating`: requires post-execution ownership reconciliation.

`config/git_guard_subcommands.yaml` and the associated compiled reconciliation
table are the source of truth. Build-time consistency checks reject category
conflicts and require matrix coverage for every policy-bearing command.

Matching is exact. The guard does not turn prefixes such as `reba` into
`rebase`: Git may treat the former as an external `git-reba` command, and guard
classification must not describe a different command from the one Git sees.
Matching compares raw bytes with compiled ASCII names; non-ASCII positional
command bytes therefore remain an unknown capless command rather than a failed
text conversion.
Commands outside the policy categories follow the unknown-subcommand rule and
execute without an Ambient capability loan.
Each supported Git upgrade requires a review for newly introduced commands that
can violate guarded invariants.

### 3.5 Unknown Commands and Capability Loan

Unknown names are not assumed invalid: Git may resolve aliases, external
`git-<name>` helpers, or commands introduced by a newer Git release. They pass
through with argv unchanged but Ambient empty. The guard still has Effective
`CAP_DAC_OVERRIDE` when the kernel checks execute permission on the root-only
`git.original`; because the target has no file capabilities and Ambient is
empty, all guard capabilities disappear across exec.

Only exact commands in the compiled `capability_loan` category may raise
Ambient `CAP_DAC_OVERRIDE`. The category is independent from block, contract,
and reconciliation categories. Its inventory is justified by installed tests
against root-owned repository metadata; a command is not added speculatively.
No-subcommand and terminal-query invocations are capless.

### 3.6 The `--` Separator

Git uses `--` to separate options from pathspecs. For example:

```
git checkout -- myfile.txt    # checkout the file "myfile.txt", not a branch
git log -- src/main.rs        # show log for this file only
```

The guard identifies the separator in the applicable Git command context and
stops option interpretation there. Everything after it is treated as data,
never as a Git flag. The original argv remains unchanged. For example:

```
git log -- --hard   # "--hard" names a path; it is not the reset option
```

The separator does not weaken subcommand policy: `git reset -- file` remains a
`reset` invocation and is blocked by the subcommand rule. Conversely, a global
rescan must not reclassify post-separator pathspecs such as `--hard`,
`--force`, or `--no-verify` as options.

---

## 4. Block Decision Engine

The guard applies checks in this order. The first block wins: later checks are not evaluated.

```
1. Exact subcommand in compiled `blocked` category? → BLOCK for every user.
   Exact subcommand in `sudo_gated`? → deny non-root, then apply any
   unconditional destructive-form checks before allowing root. Exact
   subcommand in `partial`? → run its command-specific policy.
2. Destructive option in the identified command's parsed option state? → BLOCK.
3. Dangerous `-c`/`--config-env` key? → BLOCK (core.hooksPath, core.sshCommand, etc.)
4. Subcommand-specific block?
   4a. branch -D? → BLOCK
   4b. push force option, including `--force-with-lease=<value>`? → BLOCK
   4c. push from background? → BLOCK
   4d. commit --amend as non-root? → BLOCK; verified root continues to contract
5. Protected branch rule?
   5a. pull on a catalog-protected branch without a final explicit ff-only or
       enabled-rebase mode? → BLOCK
   5b. non-root merge on a catalog-protected branch without final ff-only,
       --abort, or --quit mode? → BLOCK
6. Hook-bypass env var? → BLOCK (SKIP, PRE_COMMIT_ALLOW_NO_CONFIG)
7. WORKSPACE-CI contract required? -> continue only on `Passed`; every typed
   non-success exits 4 and is not an exit-1 policy block.
8. ALL CLEAR → execve real git
```

`stash` is an unconditional category-1 block. The decision occurs before stash
operation parsing, so bare `stash`, all named operations, unknown future
operations, and operands after `--` have the same result for root and non-root.
Although `list` and `show` are read-only, they remain blocked to avoid a second
stash grammar and gaps as Git evolves. The hint names the sanctioned temporary
worktree and `git diff` snapshot alternatives; it must not recommend another
stash operation.

`branch` policy derives operations from branch's own option grammar. Any actual
force option blocks, whether standalone or combined with delete, move, or copy.
Consequently `-D`, `--delete --force`, `-df`, `-fd`, `-f`, `--force`, `-M`,
`-C`, and equivalent move/copy-plus-force forms block. Safe `-d`, `-m`, and
`-c` remain allowed without force. Short clusters and long-option spellings are
interpreted exactly as the pinned Git parser interprets them; tokens after the
applicable `--` are operands. Lowercase branch `-c` and uppercase branch `-C`
are copy operations, never global config options once the subcommand has been
identified.

`push` policy likewise derives force semantics from push's grammar rather than
literal token equality. It blocks `-f` clusters, `--force`, every
`--force-with-lease` form, leading-`+` force refspecs, and `--mirror`. The parser
accounts for whether a repository was supplied positionally or by option before
classifying remaining operands as refspecs. `--` stops option parsing but not
refspec parsing, so a post-separator leading-`+` refspec still blocks while a
post-separator option-like operand is not treated as an option.
`--force-if-includes` is allowed when no actual force mechanism is present.
Before execution, the guard checks effective
trusted repository values for `remote.<name>.push` force refspecs and
`remote.<name>.mirror=true` under the same sanitized Git environment used for
execution. The dangerous-config catalog unconditionally prevents those unsafe
defaults from being introduced through guarded config-bearing paths. A block
hint recommends only a normal non-forced push; `--force-with-lease` is not an
allowed alternative.

#### Protected Branch Catalog

`config/git_guard_protected_branches.yaml` is the only authority for protected
exact names and prefixes. Exact entries compare with the complete current branch
name; prefix entries compare from byte zero and end in `/` so boundaries are
explicit. Both policy and candidate use ASCII-only case folding. This deliberate
conservative match may protect differently cased Git refs even though Git treats
those refs as distinct. Root status does not change classification.

The build rejects empty, non-ASCII, non-lowercase, duplicate, and invalid exact
or prefix entries. A prefix is validated as a branch namespace rather than as a
complete ref because its trailing `/` is intentional. The generated exact and
prefix tables are the only runtime inputs; prose examples never define an
additional list.

Protected-branch `pull` policy computes two ordered option states: effective
fast-forward mode and effective rebase mode. `--ff-only` sets the first safe;
later `--ff` or `--no-ff` replaces it. `-r`, `--rebase`, and pinned-Git-supported
non-false rebase values set the second safe; `--rebase=false` and `--no-rebase`
replace it with unsafe. The pull is allowed if either final state is safe.
Configuration does not supply the required explicit choice. Command-specific
value consumption, short clusters, long abbreviations, and `--` follow the
pinned pull parser; a value or post-separator operand that resembles a safe
option has no policy effect.

Protected-branch `merge` policy uses an ordered effective FF mode. `--ff-only`
sets safe mode; a later `--ff` or `--no-ff` replaces it, and a later
`--ff-only` restores it. Actual `--abort` and `--quit` modes are allowed for
non-root recovery because they do not create a merge commit. `--continue` may
create that commit and remains root-only. Merge's value-taking options are
consumed before policy classification, so values such as the message in
`-m --ff-only` or `-m --abort` cannot authorize a merge. Long abbreviations and
`--` follow the pinned parser. Config-derived FF mode does not replace the
required explicit argv choice. Verified root may use other merge modes.

For every otherwise-allowed push, the guard parses `/proc/self/stat` by finding
the final `)` of `comm` and then treating the following state token as absolute
field 3. `pgrp` is relative index 2 and `tpgid` is relative index 5. A positive
`tpgid` must equal `pgrp`; a mismatch is a background-push block. A non-positive
`tpgid` means there is no controlling foreground terminal group and is allowed
for non-interactive operation. Read failure, missing delimiter or fields,
numeric parse failure, and overflow all block with exit 1. Detection failure is
never downgraded to a warning.

### 4.1 Failure Report Delivery

Policy block messages use this exact ASCII grammar:

```text
BLOCKED: ts=<RFC3339-UTC-Z>|reason=<encoded>|argc=<decimal>|arg0=<encoded>|...|argN=<encoded>
hint=<encoded>
```

The second line ends with exactly one newline; there are no other bytes. `argc`
counts exact process arguments including `argv[0]`, and contiguous `arg0..argN`
preserves empty arguments and boundaries. Encoded fields use §7.1's canonical
uppercase `%HH` value encoding, including its unreserved ASCII set. The formatter
never uses lossy conversion, joined argv, shell quoting, ANSI sequences,
localization, masking, omission, hashing, or truncation. The fixed timestamp is
UTC `YYYY-MM-DDTHH:MM:SSZ`.
If the signed system time cannot be represented in that grammar, formatting
returns a typed failure under REQ-GGUARD-110/092 rather than fabricating the Unix
epoch or emitting a malformed block/audit record; the policy denial still stands.

The first block in §4's ordered decision engine supplies the sole reason and
hint; later matching checks are not evaluated and cannot append competing text.
The reason names the exact compiled policy and blocked form. The hint is
policy-owned static data, except for encoded evidence fields, and cannot contain
unencoded caller bytes. It does not recommend an action blocked in the same
caller/repository context. Where an alternative depends on root authority,
repository state, or another precondition, the text states that condition and
does not promise success. Hints are displayed as data and are never passed to a
shell or subprocess.

Argument bytes, selected reason bytes, and one timestamp are captured in a
single immutable evidence object. The visible formatter and canonical audit
formatter consume that object, preventing disagreement between destinations.
The visible hint is additional policy-owned evidence; §7.1's audit schema does
not duplicate it. One formatted visible payload is reused for stderr and any
distinct controlling tty under REQ-GGUARD-110.

One shared delivery function accepts an immutable byte payload and returns typed
per-destination results; it does not exit. The dispatcher uses it for policy,
validation, guard-unavailable, contract-summary, and non-recursive audit-failure
reports. Each write is checked to completion, partial writes continue, and only
valid `EINTR` conditions are retried. The same payload bytes are reused rather
than reformatted per destination.

The report is always attempted on stderr. The guard then opens `/dev/tty`
write-only and close-on-exec when a controlling terminal exists. If stderr is
not a terminal, the tty receives the report. If stderr is a terminal, safe tty
APIs compare terminal/session identity for stderr and the controlling terminal;
filesystem pathname, inode, `st_dev`, and ordinary file identity are forbidden
for this decision because `/dev/tty` may alias the same `/dev/pts/N` through
different metadata. A proven same terminal receives no second copy; a proven
distinct terminal does. If stderr is a terminal but identity cannot be proven,
the already-attempted stderr report stands and the tty copy is skipped to avoid
duplication. Thus an ordinary interactive failure appears once, while redirected
stderr still permits a distinct controlling-terminal report.

Expected no-controlling-terminal results are not errors. Unexpected tty open,
terminal-identity, stderr-write, and tty-write failures become typed delivery
results and are surfaced non-recursively through any surviving destination.
They never alter the original typed exit or execution decision. Separately
streamed contract bytes are not copied into the summary payload. Warnings remain
stderr-only and ordinary real Git output never uses this function. The tty write
is defense in depth; shell-layer output-suppression rules remain independent.

### 4.2 Policy-Denial Exit

`PolicyDenied { reason, hint }` is the sole guard outcome that maps to exit 1.
It covers every static or contextual command/config/environment/repository
policy denial without a more specific contract class, not merely operations
described as destructive. The central denial dispatcher emits one complete
stderr/distinct-tty report and attempts one canonical root-owned
`event=block|exit=1` audit append before exiting. Reporting/audit failure is
reported separately but cannot change the original denial or permit Git.

Validation, privilege/integrity/supervision, and contract outcomes map to exits
2, 3, and 4 respectively. A real Git process may independently exit 1; that
status is propagated without `BLOCKED` output or a block audit event. Internal
fork/exec/capability/wait failures never use exit 1.

### 4.3 Subprocess Checks

Some checks require invoking real git:

| Check                   | Subcommand                                              | Timeout | On timeout        |
| ----------------------- | ------------------------------------------------------- | ------- | ----------------- |
| Effective repository    | fixed repository-resolution helper                      | 2s      | Block affected operation |
| Protected branch        | `git symbolic-ref --quiet HEAD`                         | 2s      | Block known-repository operation |

Timeout behavior is defined by each subprocess-backed requirement. Commands in
the compiled `blocked` category and static sudo-gated decisions such as
non-root `commit --amend` do not invoke a subprocess and cannot be skipped by a
timeout. Partial commands retain their explicit policy; subprocess failure
shall not silently reclassify one category as another.

Repository resolution consumes the validated location selectors from the
original global-option region and is performed once. A typed no-repository
result differs from timeout, malformed output, and operational failure. In a
resolved repository, fixed `symbolic-ref --quiet HEAD` output must be a
byte-exact `refs/heads/<name>` plus its single line terminator. This recognizes
unborn branches and linked-worktree HEAD files without lossy UTF-8 conversion.
The helper's status identifies detached HEAD; no-repository is accepted only
from the shared resolver. Those two proven states skip branch policy. Every
other failure blocks an affected pull or non-root merge with exit 1. The same
resolved repository and branch result feed policy, locking, sealing, execution,
and reconciliation so checks cannot silently target different repositories.

---

## 5. Environment Sanitisation

### 5.1 Catalog Allow-List

`config/git_guard_environment.yaml` is the only environment authority. Its
compiled categories are allowed exact names, allowed prefixes, effective-root
editor/identity names, blocked bypass names, reserved `--config-env` value
carriers, and guard-owned exact names/prefixes. Unknown inherited names are
dropped with a byte-exact evidence warning; the specification does not maintain a
second finite deny list.

The sanitizer starts empty. It copies each catalog-allowed inherited name at
most once with its value bytes unchanged, admits root-only names only when
effective UID is zero, and admits a reserved config-value carrier only when the
validated argv references it. It then inserts fixed guard-owned values after
discarding every caller version, including complete config-injection and SSH
wrapper families. `AT_SECURE` indicates secure execution, not operator
authorization.

Build-time checks reject non-ASCII or invalid names, duplicates, category
overlap, unsafe broad prefixes, and allow entries that expose known Git, loader,
shell, pager, editor, credential, object-store, repository, or config-injection
controls. Allowed values may be non-UTF-8 and remain byte-exact whenever emitted
as evidence. Policy helpers,
the contract runner, and final Git all begin with this same environment; each may
add only its documented fixed variables. Removed, replaced, malformed, and
unauthorized inherited names and values are reported as reversible evidence;
filtering is never
silent.

The catalog's blocked-bypass category is evaluated before helper execution and
is not merely filtered. A non-empty byte value blocks the complete invocation
with exit 1 for every user; an empty value is inactive, is omitted from the child
environment, and produces a byte-exact evidence warning. Detection uses
`OsStr` bytes rather than
`std::env::var`, so non-UTF-8 values cannot evade the decision. Reports contain
the cataloged name and exact value under reversible escaping. Hook-framework upgrades require a
review of new environment bypass controls and matrix coverage before the pinned
version changes.

### 5.2 PATH Preservation

`PATH` is a cataloged allowed exact variable. Its caller value is preserved as
bytes for root and non-root; absence remains absence. The guard never uses that
value to locate guard-owned programs: real Git, the contract shell/script, SSH
wrapper, and policy helpers use fixed absolute paths and their applicable
integrity checks. Git, hooks, contract scripts, and external `git-*` helpers may
use caller PATH for ordinary tool resolution. Resetting PATH after the guard has
already been selected does not secure initial guard lookup and would break
workspace tools, toolchain shims, hooks, and external Git commands.

### 5.3 Preserved Variables

Only names in the compiled environment catalog are preserved; this section does
not duplicate that list. Root-only editor and identity entries are dropped with
a byte-exact evidence warning for non-root and admitted for effective-UID-zero operators.
File-capability secure execution does not authorize them. Command-selecting
pager, editor, diff, credential, and helper variables are not ordinary preserved
variables.

The required caller-visible identity/locale surface is exact `HOME`, `USER`,
`LANG`, and `LANGUAGE`, plus prefix `LC_`. Presence, absence, emptiness, and value
bytes are preserved. `LOCPATH`, `NLSPATH`, and other loader/catalog path controls
are outside that prefix and remain excluded. Caller HOME and USER are data for
Git and its tools only; guard authority derives from kernel UID/GID and passwd
records. In particular they cannot select audit-log homes, trusted Git identity,
provisioned SSH keys, policy files, or protected filesystem paths.

### 5.4 Implementation: Allow-List Approach

The guard constructs a minimal environment from scratch rather than surgically
removing dangerous variables. A deny-list is incomplete as libc, Git, and helper
tools add controls. Names are matched as ASCII bytes against compiled exact and
prefix categories; admitted values remain arbitrary `OsString` bytes. The guard
serializes each unique admitted name and value directly into `CString` storage
without Unicode conversion, then adds canonical guard-owned entries. `execve`
receives only that finalized vector. This makes absence the default and keeps the
catalog auditable without duplicating it in code or prose.

### 5.5 Untrusted Snapshot and Diagnostics

The guard snapshots inherited environment entries once at startup as raw Unix
name/value bytes. The snapshot is immutable and is consumed only by compiled
environment-policy categories. It is never authority for executable or policy
paths, user/home identity, capabilities, integrity, repository selection, or
other security decisions. Universal `secure_getenv()` is intentionally not used:
under file-capability `AT_SECURE` execution it returns no caller values and would
disable required detection and preservation. No additional FFI site is needed.

`WORKSPACE_GUARD_TRACE` is a cataloged guard-diagnostic name. Its enablement is
computed once from the immutable startup snapshot: only a present non-empty
value enables tracing. The name is consumed and never forwarded. Trace records
use this exact ASCII grammar:

```text
TRACE: phase=<static-token>|event=start
TRACE: phase=<static-token>|event=end|elapsed-ns=<decimal>
```

Each record has exactly one final newline and is written completely to stderr.
Phase tokens come from a closed compiled set. Trace records contain no argv,
environment values, credentials, repository paths, policy contents, helper
output, or caller-controlled bytes. Re-reading the process environment per phase,
free-form phase names, empty-value activation, `eprintln!`, and unchecked writes
are forbidden.

Policy-helper stderr is surfaced on helper success and failure using bounded
incremental chunks with this exact ASCII grammar:

```text
HELPER-STDERR: helper=<static-token>|seq=<decimal>|final=<0|1>|data=<encoded>
```

Each chunk has exactly one final newline. Helper tokens come from a closed
compiled set. For non-empty stderr, sequence starts at zero and is contiguous,
exactly one final chunk has `final=1`, and concatenating decoded `data` fields
reproduces the exact stderr bytes. Empty helper stderr emits no chunks. `data` uses §7.1's canonical
uppercase `%HH` encoding. Successful helper stdout remains an internal typed
protocol and is never emitted. Failed or malformed protocol stdout is preserved
as encoded failure evidence, not copied raw to stdout. Spawn errors, reader
failures, signals, timeouts, malformed results, and non-zero statuses retain
distinct typed diagnostics and are never converted to empty output or a silent
fallback.

An ordinary successful invocation with no diagnostic condition remains
transparent. Transparency never suppresses explicit trace output, filtering
warnings, helper diagnostics, policy warnings, validation/provisioning errors,
contract output, or block reports.

### 5.6 Runtime Warnings

The runtime warning catalog is closed:

| `kind` | Ordered encoded fields | Origin |
| --- | --- | --- |
| `filtered-environment` | name, value, filter-reason token | REQ-GGUARD-070 |
| `empty-hook-bypass-environment` | name, explicit empty value | REQ-GGUARD-071 |
| `workspace-marker-drift` | path, observed condition | REQ-GGUARD-081, only when inspected |
| `reconcile-symlink-skipped` | path | REQ-GGUARD-176 |
| `reconcile-protected-path-drift` | path, observed condition | REQ-GGUARD-178 |

One inherited entry produces at most one warning. The specialized empty
hook-bypass variant supersedes the generic filtered-environment variant; a
non-empty hook-bypass value is an exit-1 denial and produces no warning.

No other runtime condition may be relabeled as a warning to avoid its policy,
validation, guard-unavailable, contract, audit, or reconciliation outcome. Trace
lines, helper stderr, contract streams, and installer output retain their own
contracts. In particular, background-push detection failure remains an exit-1
policy denial.

Each warning is one immutable byte payload with this exact grammar:

```text
WARNING: ts=<RFC3339-UTC-Z>|kind=<catalog-token>|fieldc=<decimal>|field0=<encoded>|...|fieldN=<encoded>
```

The line has exactly one final newline. The variant fixes canonical field count
and order. `kind` is its static lowercase ASCII token; dynamic fields use §7.1's
uppercase `%HH` encoding. Environment name/value bytes, including an explicit
empty value, and Unix path bytes remain exact. Lossy conversion, ANSI sequences,
localization, masking, omission, and truncation are forbidden.

Warnings use a checked complete-write loop to stderr only. A successful write
does not alter execution or the eventual real-Git outcome. No warning is copied
to `/dev/tty`, prefixed `BLOCKED:`, or appended to an audit sink. Expected absence
of a warning is silent. Short write, `EPIPE`, or any other non-retryable stderr
failure returns `GuardUnavailable { stage=warning-stderr, cause, os_status }`;
only a valid `EINTR` is retried. Before requested Git starts, exit 3 executes no
Git. After Git starts, exit 3 reports that its operation may already stand. An
independent documented reconciliation failure retains its exit-74 precedence.
The guard-unavailable summary then uses §4.1 delivery, including a distinct tty;
the warning itself never does.

### 5.7 Stream Ownership and Ordering

The guard emits no guard-generated bytes to stdout. Real Git inherits caller
stdout and stderr directly: the guard does not pipe, buffer, decode, encode,
prefix, merge, reorder, or duplicate either stream. This preserves binary output,
terminal detection, prompts, progress, color, broken-pipe behavior, and Git's own
write-error outcome. Stdout may otherwise contain only incrementally streamed
WORKSPACE-CI stdout under §6.2. Contract stderr is likewise streamed under its
contract and is not helper framing or a guard diagnostic.

Guard diagnostics, warning records, trace records, helper-stderr chunks, and
post-Git reconcile reports use stderr. Enforced failure reports additionally use
the distinct-tty rules in §4.1. Successful audit persistence emits no terminal
output. Successful helper protocol stdout remains internal.

Causal ordering is mandatory: pre-Git warnings, trace records, and helper
diagnostics complete before requested Git starts; contract stdout/stderr is
surfaced before Git starts; a failed contract's concise summary follows its
preserved streams; and post-Git trace/reconcile diagnostics begin only after Git
is reaped. Bytes remain ordered within each individual stream. The guard does not
claim a total ordering between independently written stdout and stderr.

Checked trace/helper diagnostic writes return typed outcomes. Before Git starts,
a write failure maps to `GuardUnavailable` exit 3 and launches no requested Git.
After Git starts, it maps to exit 3 and reports that Git's operation or mutation
may already stand; an independent reconciliation invariant failure retains the
documented exit-74 precedence. Contract stream read/write failure remains a typed
exit-4 contract outcome. Failure-report delivery follows §4.1 without changing
its original exit class. Errors produced by real Git while writing its inherited
streams remain real-Git outcomes and are propagated under §8.5.

---

## 6. WORKSPACE-CI Contract Enforcement

The compiled `contract_check` category is an exact two-element set: `commit` and
`push`. It mirrors the trusted script's only supported command values and is not
an open-ended list. Root and non-root use the same contract. Static blocks and
effective repository resolution precede one contract invocation; capability
loan and requested real-Git execution follow only after success.

`cherry-pick`, `am`, `apply`, and recovery operations do not invoke this runner.
Their native hooks and reconciliation still apply, and any resulting history is
contract-checked before push. Adding another command requires first specifying
and implementing what prospective or resulting content the trusted runner can
correctly validate for that command.

### 6.1 Workspace Detection

The guard reads workspace authority from the fixed root-owned runtime registry
`/etc/workspace-guard/workspace-roots`. Its parent chain must be root-owned and
not group/other-writable. The registry contains canonical absolute root paths and
is accepted only as a no-follow regular file with `root:root`, exact mode `0644`,
and the filesystem immutable flag. Registry absence, parse failure,
replacement, or metadata/integrity drift blocks a contract-eligible invocation;
it is never interpreted as “outside workspace.”

The effective repository resolved once under §4.3 is canonicalized and compared
to registered roots by path components. Equality or descendant containment is a
match; lexical prefixes such as `/workspace-a` versus `/workspace-agent` are
not. For explicitly overlapping roots, the longest matching ancestor supplies
the workspace binding. Paths remain Unix bytes rather than lossy strings, and
root/non-root classification is identical.

Legacy workspace markers such as `.boot-linux` and source-checkout paths are not
authority. They may be inspected as drift evidence, with every mismatch surfaced,
but forging, deleting, replacing, or symlinking all markers cannot alter registry
membership. Repositories outside every verified registered root proceed to the
REQ-GGUARD-082 outside-workspace rule.

Outside-workspace behavior depends on the exact contract command. `commit`
skips without reading local remotes; mutable repository config is not commit
scope authority. `push` first resolves its effective destination from the parsed
repository operand and, when needed, sanitized Git's named/default remote and
push-URL resolution. Explicit URLs and effective rewrite rules are included.

A compiled protected-remote catalog records reviewed canonical host plus
repository path/namespace rules. Host-only matching is insufficient. An
outside-workspace push proceeds without the contract only when its typed
destination is successfully proven unrelated. Protected destinations block with
exit 4 and require operation from a registered workspace. Missing, ambiguous,
malformed, failed, or otherwise indeterminate resolution also exits 4. The same
resolved destination feeds subsequent push policy, and helper status/stderr is
never converted to an unrelated result or swallowed.

### 6.2 Contract Check Delegation

When the repo is in an WORKSPACE workspace and the subcommand is `commit` or
`push`, the guard first verifies the deployed WORKSPACE-CI artifact and then
runs the fixed argument vector:

```text
argv[0] = /bin/bash
argv[1] = /opt/workspace-ci/lib/checks_quality.sh
cwd     = <canonical effective repository root>
stdin   = /dev/null
```

`/bin/bash` and the script path are absolute constants. The guard does not use
`-c`, stdin program text, `source`, generated code, PATH lookup, workspace-root
prefixing, or a caller override. This is the only shell subprocess permitted by
the Git guard. Immediately before spawn, `/bin/bash` is verified against the
installed shell-guard identity/integrity contract. The script and each trusted
parent component are inspected without following a final symlink and must match
the deployed root ownership, non-writability, exact mode, immutable state, and
content identity. The contract child receives no Git capability loan.

With environment variables:

```
WORKSPACE_GGUARD_CMD=<commit|push>
WORKSPACE_GGUARD_REPO_ROOT=<repo top-level>
WORKSPACE_GGUARD_WORKSPACE_ROOT=<workspace root>
```

These are the only runner bindings. `CMD` is the exact compiled contract command;
the two roots are the same canonical byte-oriented identities already selected
for effective repository policy and verified registry membership. They are not
re-resolved or converted through UTF-8. The runner cwd and `REPO_ROOT` binding
refer to the same repository identity.

The child environment is cleared and rebuilt from the same sanitized
environment contract used for real Git, then the three bindings above are
inserted exactly once. Dynamic-loader variables, Git redirection variables,
hook-skip variables, caller-supplied `WORKSPACE_GGUARD_*`, and legacy
`AMI_GGUARD_*` values never survive and each spoofing removal is reported with
its exact value as evidence. Legacy aliases are neither emitted nor accepted. Missing, duplicate,
NUL-invalid, or identity-inconsistent bindings fail closed with exit 4. The
trusted script quotes the values and treats spaces, newlines, non-UTF-8 bytes,
and leading-hyphen path components as data. The
configured contract timeout is mandatory and timeout fails closed with exit 4.

The runner drains stdout and stderr concurrently while the timeout is active so
pipe capacity cannot deadlock the script. Both streams are incrementally surfaced
on success and failure without truncation or masking, using bounded per-chunk
memory. The runner
starts the script in a dedicated process group; timeout terminates and reaps the
whole group. Spawn, pipe, output, wait, signal, timeout, integrity, and non-zero
exit outcomes retain distinct diagnostics and all failures map to exit 4.

The runner returns a typed outcome: `Passed`, `Rejected { code }`,
`Signaled { signal }`, `TimedOut`, `SpawnFailed`, `OutputFailed`, `WaitFailed`,
or `IntegrityFailed`. Only `Passed` continues to requested Git. Contract stream
bytes are emitted once and are not embedded in the outcome message. On any other
outcome the guard emits a separate concise summary containing status metadata,
exits 4, and uses standard stderr/distinct-tty/audit delivery. The audit event
records the command and outcome; script stdout/stderr remains separately
preserved evidence and is not duplicated in the summary record. Output bytes and
per-stream order are preserved, including non-UTF-8 data.

### 6.3 Why Shell Delegation?

The contract checks involve:

- YAML parsing (`project_enforcement.yaml`)
- File content inspection (checking hook headers for `AUTO-GENERATED`)
- Tier resolution logic
- Makefile grep

Re-implementing this in Rust would:

1. Add a runtime YAML parser outside REQ-GGUARD-122's privileged runtime closure
2. Duplicate logic that already exists and is maintained in WORKSPACE-CI
3. Create two sources of truth for contract rules

Delegation keeps the guard binary thin and delegates policy to the policy
engine. The exception is safe only because both executable paths are fixed,
the deployed script is integrity-checked before launch, argv contains no inline
program text, stdin is `/dev/null`, cwd is the effective repository, the
environment is rebuilt, no Git capability is loaned, and execution/output are
time-bounded.

### 6.4 Missing Deployment

Only a contract-required invocation probes runner availability. Missing
`/opt/workspace-ci`, script, or `/bin/bash`, and every type, ownership, mode,
parent-writability, immutable, deployed-content, permission, inspection,
replacement, or pre-spawn race failure produces a typed contract-unavailable
outcome and exit 4 for every user. The concise report identifies the fixed path
and failure class through stderr, distinct tty, and audit without copying mutable
file content or secrets. Missing/untrusted deployment is never permission to
skip, and the guard performs no source-checkout fallback, alternate selection,
repair, installation, or network retrieval. Invocations outside contract scope
do not inspect the runner.

---

## 7. Audit Logging

### 7.1 Log Format

```
v=1|ts=<RFC3339-UTC-Z>|event=<class>|exit=<decimal>|uid=<decimal>|cwd=<encoded>|argc=<decimal>|arg0=<encoded>|...|reason=<encoded>
```

Example:

```
v=1|ts=2026-05-18T14:32:01Z|event=block|exit=1|uid=1000|cwd=%2Fworkspace|argc=2|arg0=git|arg1=reset|reason=destructive%20subcommand
```

Fields are fixed-order ASCII `name=value` pairs separated by raw `|`, followed
by exactly one newline. Values preserve only the approved unreserved ASCII set;
`%`, delimiters, spaces, CR/LF, controls, and bytes `>=0x7f` use canonical
uppercase `%HH`. Encoding is fully reversible and performs no redaction. `argc` plus contiguous
`arg0..argN` fields preserves empty arguments and boundaries; space-joined argv
is never audited. Event classes are `block`, `contract-reject`,
`contract-unavailable`, and, only when a separate authoritative sink
successfully stores it, `audit-failure`. Version, names/order,
decimal forms, and event vocabulary are parser-enforced. Unsupported versions,
bad escapes, duplicate/missing/reordered fields, count mismatch, unknown classes,
and embedded/extra record newlines are invalid. Records are never truncated.

### 7.2 Log Location

The only Git audit location is
`/var/log/workspace-guard/git-<real-uid>.log`. No authoritative or convenience
mirror is written beneath HOME or any user-writable directory. `/var/log` and
the fixed audit directory are opened/verified by trusted directory descriptors;
the latter is `root:root` exact `0750` and non-writable by group/other. The
decimal filename comes from kernel real UID. The target is opened no-follow and
must be a regular `root:root` exact-`0600` file with no special bits.

Each denial builds one complete encoded record, locks the file, appends the
record without interleaving, syncs, checks every result, and closes. A missing
per-UID file may be created only inside the verified root-owned directory and is
immediately secured before any record is accepted. Audit failure never changes
the denial but is reported through stderr and a distinct tty; it is not silent.
Exit-1 policy blocks and exit-4 contract failures use this same sink.
Runtime warnings never open or append this sink.

Audit append returns a typed stage error rather than exiting or discarding an
error. Parent verification, open/create, metadata, lock, encode, write, sync,
unlock, and close failures each retain OS status where available. Main policy
handling reports one reversibly escaped `AUDIT FAILURE` diagnostic through stderr
and a distinct tty and exits with the original denial's code. No requested Git
execution, path fallback, or integrity retry occurs. HOME, `/tmp`, workspace,
caller-selected, world-writable, and unverified alternate destinations are
forbidden. A successful append plus sync is required before persistence may be
claimed. Failure reporting never recursively invokes the failed writer; an
`audit-failure` record is valid only if a separate verified authoritative sink
actually persists it.

### 7.3 Complete Forensic Evidence

Blocked config values and every other caller-supplied byte remain evidence:

```
v=1|ts=2026-05-18T14:32:01Z|event=block|exit=1|uid=1000|cwd=%2Fworkspace|argc=3|arg0=git|arg1=-c|arg2=core.hooksPath%3D%2Ftmp%2Fevil|reason=dangerous%20config%20key
```

No input is redacted, masked, omitted, hashed, or truncated. Inline credentials
or tokens violate the agent operating contract; agents must use sanctioned
secret-store paths. Such misuse remains complete root-owned forensic evidence.
Terminal escaping and audit percent encoding are reversible framing only.
Separately streamed helper output need not be duplicated in a summary audit
record, but every destination that receives it preserves the exact bytes.

### 7.4 Log Write Timing

The log file is opened and written **only after** the block decision is made: not during argument processing. This minimises the number of file descriptors opened during the critical path.

## 8. Post-Exec Policy Reconcile (REQ-GGUARD-174..178)

### 8.1 Position in the Exec Flow

```
parse args -> block decision -> audit log (on block)
  -> sanitise env -> conditionally loan ambient CAP_DAC_OVERRIDE
  -> exec git
  -> wait -> reconcile policy manifest (this section) -> exit(git status)
```

Reconcile runs in the guard process AFTER `wait()` reaps git, while
the guard still holds its own effective/permitted capability set. The Ambient
loan applies only when the exact subcommand is in the compiled
`capability_loan` category. Unknown, external, alias, no-subcommand, and
terminal-query execution keeps Ambient empty, so real Git starts capless.
Reconcile uses the guard's own `cap_chown`/`cap_fowner` from its permitted set.

### 8.2 Trigger Set

Reconcile runs only when ALL hold:

1. git exited (any status; a failed merge still mutates the tree);
2. the subcommand is in the mutating set: `pull, merge, checkout,
switch, restore, rebase, cherry-pick, revert, apply, am,
submodule` (update), `reset/clean` (root-only paths);
3. the cwd is inside a guarded worktree (`.git` present).

Read-only porcelains (`status, log, diff, fetch, show, ...`) skip
reconcile: zero added latency on the hot path.

### 8.3 Manifest

Union of, in order:

1. exemption policy files: covered via the compiled
   `LOCKED_GLOB_PATTERNS` / `LOCKED_INDIVIDUAL_FILE_PATHS` from
   `config/shared_locked_paths.yaml` (`*_exceptions.yaml`,
   `exemption_files.yaml`, `.gitmodules`, ...). The guard parses no
   YAML at runtime (REQ-GGUARD-172 dependency ceiling), so the CI
   `exemption_files.yaml` manifest is honored through these compiled
   filename patterns, which every CI exemption file matches;
2. `<repo>/config/*.yaml` (policy configs; tracked or not, since untracked
   policy files have no git audit trail and need reconcile most);
3. `.git/hooks/*` and the two tier registries: ownership + immutable
   check only (warn on drift, REQ-GGUARD-178; `+i` re-apply stays a
   root-run repair action).

### 8.4 Reconcile Algorithm (per manifest path)

```
lstat(path)
  missing                       -> skip (not every repo has every file)
  symlink (any kind)            -> WARN, skip (audit C3: never follow)
  directory (config/, hooks/)   -> chown root:root, chmod 0755
  regular file                  -> chown root:root, chmod 0644
                                   (preserve exec bit for hooks:
                                    0755 when any x bit was set)
all via fchownat(AT_SYMLINK_NOFOLLOW) / fchmodat; no recursion beyond
the manifest's explicit entries and the two named directories.
```

Failure of any single path: record, continue, then exit
`EX_IOERR (74)` with the full drift list on stderr. The git result is
NOT rolled back (the tree is valid; the invariant is not).

### 8.5 Outcome Propagation

The parent waits because post-exec relock/reconciliation must run before the
guard returns control. After that work, a normally exited Git child supplies its
exact exit code. A signaled Git child causes the guard to restore/default and
raise the same signal after reconciliation; converting it into a normal
`128 + signal` exit is forbidden because callers must retain `WIFSIGNALED`
semantics. If reconciliation detects invariant drift, documented `EX_IOERR` 74
overrides the child outcome and states that the Git operation already stands.

Fork, capability-loan, exec, and wait/supervision failures are typed guard
failures and use their assigned guard exit classes. They never become exit 1 or
pretend to be Git's outcome. A normal non-zero Git result is not a policy denial,
does not create a block audit event, and preserves Git stdout/stderr unchanged.

### 8.6 Guard-Unavailable Exit

`GuardUnavailable { stage, cause, os_status }` is the sole internal outcome that
maps to exit 3. It covers deployment/privilege/capability verification,
`NoNewPrivileges` inspection, required resource limits, real-Git verification,
capability promotion/loan, fork, exec, wait, signal propagation, and otherwise
unclassified internal supervision failures. Validation, policy, contract,
audit-delivery, and reconciliation outcomes retain exits 2, 1, 4, their original
denial code, and 74 respectively.

Inspection errors never become acceptable state. `EINTR` is retried only where
the syscall contract permits it. A pre-exec failure launches no requested Git.
If failure occurs after Git starts, the diagnostic explicitly states that the
outcome is unknown or mutation may already stand. Stage, cause, and OS status are
reversibly escaped evidence. Exit 3 is not a policy block and does not create an
`event=block` record. A real Git exit 3 remains a normal propagated child result
without guard-unavailable output.

### 8.7 Contract Exit

The exhaustive contract error types are `ContractRejected { child_code }`,
`ContractUnavailable { stage, cause, os_status }`, and
`ContractRequiredOutsideWorkspace { destination }`; each maps to exit 4.
`ContractRejected` records a verified runner's normal non-zero exit.
`ContractRequiredOutsideWorkspace` records a protected or indeterminate
outside-workspace push destination. `ContractUnavailable` covers every inability
to determine required scope or verify/build/run/drain/wait/terminate/reap the
contract safely, including workspace, repository, destination, consumer-hook,
deployment, binding, runner, pipe, output, signal, timeout, integrity, and
cleanup stages. Inspection/helper failure is evidence, never an empty result or
successful check.

Only a verified `Passed` contract outcome proceeds to requested Git. Every other
outcome launches no requested Git, including for effective UID 0, and emits one
concise reversible summary through stderr, distinct tty, and the authoritative
audit API. `ContractRejected` and `ContractRequiredOutsideWorkspace` use
`event=contract-reject`; `ContractUnavailable` uses
`event=contract-unavailable`. Runner stream bytes remain separately preserved
once and are not copied into the summary. Report/audit delivery failure is
surfaced non-recursively while the original exit 4 remains enforced.

Validation, policy, and guard-unavailable outcomes reached before contract
evaluation retain exits 2, 1, and 3. A normal real-Git exit 4 after a passed
contract is propagated unchanged and creates no contract summary or audit event.
The dispatcher therefore classifies typed outcomes, never the numeric code
alone.

### 8.8 What Reconcile Deliberately Does NOT Do

- No `chattr` (needs `cap_linux_immutable`, which the guard does not
  carry; tracked policy files no longer use `+i`, REQ-GGUARD-174).
- No content validation (consumers validate; guard asserts
  provenance only).
- No locking around concurrent git processes (two reconciles
  interleave safely: idempotent chown/chmod).

### 8.9 One-Time Migration (root, operator)

Per guarded repo: `chown root:root config/ config/*.yaml`,
`chmod 0755 config/`, `chattr -i` tracked policy files (drop the
flag), keep `+i` on `.git/hooks/*` + registries. Delivered as a
`/tmp` operator script; never a committed target (AGENTS.md).

### 8.10 Interactions

- **stash**: blocked (REQ-GGUARD-050); reconcile does not special-case it.
- **pre-push cap scrub** (`setpriv --inh-caps=-all`): unaffected; the
  scrub targets the hook's children, reconcile runs in the guard
  before the hook is ever spawned.
- **root-only mode** (REQ-GGUARD-158): reconcile is inert. Root-only
  builds resolve no git dir for the exec path and carry no caps; the
  operator is root and keeps the invariant themselves. The module is
  compiled only in capability mode.
