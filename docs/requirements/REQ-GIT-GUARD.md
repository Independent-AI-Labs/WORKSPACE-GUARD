# Requirements: WORKSPACE-GUARD SUID Guard Framework (Git PoC)

**Date:** 2026-05-18
**Updated:** 2026-06-24
**Status:** ACTIVE
**Type:** Requirements

---

## Background

The current git-guard is a 337-line bash script at `workspace/scripts/utils/git-guard`. It intercepts git commands by being placed first in PATH, blocks destructive operations, and enforces WORKSPACE-CI contracts on commit/push. However, a bash wrapper is inherently bypassable: the source is readable, logic can be understood and circumvented, and it relies on PATH ordering alone.

The replacement is a **Rust binary** installed as a **capability-enabled** executable at `/usr/bin/git`, with the real git binary relocated to `/usr/bin/git.original` (owner root, mode 700). The guard validates all arguments in compiled code, sanitises the execution environment, and only then `execve()`s the real git. A user who reads the binary cannot trivially bypass it because:

1. The real git at `/usr/bin/git.original` is mode 700 root:root: unreadable and unexecutable by non-root.
2. No sudoers rule allows direct execution of git.original.
3. The guard itself is a compiled Rust binary, not a readable script.

For environments where file capabilities are unavailable (PRoot, containers running as root), a **root-only mode** (`--features root-only`) provides a soft barrier with the same policy engine.

This document specifies the requirements for the Rust binary. The installation/deployment procedure is specified in [SPEC-GIT-GUARD-DEPLOYMENT](../specifications/SPEC-GIT-GUARD-DEPLOYMENT.md) and is handled by `make build-guard` and `make install-guard-host-exec`.

---

## Core Requirements

### 1. Privileged Execution Model

- **REQ-GGUARD-001**: The binary shall be installed at `/usr/bin/git` with owner root:root and mode 0755, with file capabilities `cap_setpcap,cap_chown,cap_dac_override,cap_fowner=ep` (host-exec deployment class). The guard shall loan only `cap_dac_override` to `/usr/bin/git.original`; `cap_setpcap`, `cap_chown`, and `cap_fowner` remain guard-only. `cap_fsetid` is not required because the guarded ownership and mode reconciliation does not preserve set-ID bits.
- **REQ-GGUARD-002**: The real git binary shall reside at `/usr/bin/git.original` with owner root:root and mode 0700.
- **REQ-GGUARD-003**: In capability mode, the binary shall read the root-owned
  deployment class and verify every capability required by REQ-GGUARD-001 using
  kernel process-capability state. `host-exec` shall require each capability in
  both the Effective and Permitted sets and shall require
  `PR_GET_NO_NEW_PRIVS == 0`. `sandbox-service` shall require each capability in
  both the Ambient and Permitted sets before promoting it to Effective. A
  missing, untrusted, or unknown deployment class shall fail closed. In
  root-only mode, the binary shall instead require `geteuid() == 0`.
- **REQ-GGUARD-004**: If any capability-mode verification required by
  REQ-GGUARD-003 fails, or effective UID is not 0 in root-only mode, the binary
  shall refuse to operate and exit with code 3 before argument policy or real
  Git execution. The diagnostic shall identify the failed deployment or
  privilege condition without weakening the fail-closed decision.
- **REQ-GGUARD-005**: The binary shall call `execve()` with an **absolute path** to `/usr/bin/git.original`: never `execvp()` or PATH-based lookup.
- **REQ-GGUARD-006**: Before execution, the binary shall inspect
  `/usr/bin/git.original` without following symlinks and verify that the path
  itself is an existing regular file, is owned by uid 0 and gid 0, has mode
  exactly `0700` including no setuid, setgid, or sticky bits, and is not the
  running guard's inode. Any failure shall exit with code 3 before executing
  real Git.
- **REQ-GGUARD-007**: The binary shall NOT use `system()`, PATH-resolved
  executables, shell `-c`, stdin-delivered code, generated executable text, or
  a general shell invocation. All subprocesses shall use absolute executable
  paths and explicit argument vectors. The sole shell exception is the
  REQ-GGUARD-083 contract runner: after deployment integrity verification, the
  guard may execute exactly `/bin/bash` with exactly
  `/opt/workspace-ci/lib/checks_quality.sh` as its script argument. That runner
  shall use no `-c`, shall clear and rebuild its environment from the guard's
  sanitized environment contract plus the REQ-GGUARD-084 bindings, and shall
  enforce the configured contract timeout. No agent-writable script path is
  permitted.

### 2. Argument Parsing

- **REQ-GGUARD-010**: The binary shall validate the complete raw argument
  vector before policy decisions and shall handle Git's `--` option separator
  in the applicable command context. Arguments after that separator are data
  or pathspecs and shall not be interpreted as Git flags by the guard. The
  original argument vector shall be forwarded unchanged. A blocked subcommand
  identified before its separator remains blocked.
- **REQ-GGUARD-011**: The binary shall identify the Git subcommand by parsing
  Git's global-option grammar, not by selecting the first non-dash token. It
  shall classify leading global options as: terminal query options that admit
  no subcommand, modifier options with no operand, and value-taking options
  whose separate or attached operand must be consumed. At minimum, operand
  handling shall cover `-C`, `-c`, `--git-dir`, `--work-tree`, `--namespace`,
  and `--config-env`; repeated `-C` options shall be supported. `-C` is a
  directory-changing option and shall never be interpreted as a config key.
  The first positional token remaining after valid global modifiers and their
  operands is the subcommand. If a terminal option is present or no subcommand
  exists, the invocation shall pass through unchanged. An unknown leading
  option whose arity prevents reliable subcommand identification shall fail
  closed with exit code 2 rather than permit a later destructive subcommand to
  evade classification.
- **REQ-GGUARD-012**: The binary shall exactly classify every policy-relevant
  Git subcommand declared in `config/git_guard_subcommands.yaml`: blocked,
  sudo-gated, partial, contract-check, capability-loan, and
  mutating/reconciliation categories.
  Harmless standard commands need no registry entry. Subcommand matching shall
  be byte-exact after valid global-option parsing; the guard shall not invent
  abbreviations or prefix expansion because Git may resolve an unmatched name
  as an external `git-<name>` command. Every configured policy-relevant command
  shall have build-time validation and policy-matrix coverage. Git upgrades
  shall include an audit for newly introduced policy-relevant commands.
- **REQ-GGUARD-013**: If the identified subcommand is not in a configured
  policy-relevant category and does not begin with `-`, the guard shall pass the
  original argv to real Git without raising any Ambient capability. The guard's
  own Effective `cap_dac_override` may authorize the `execve()` permission check
  on `/usr/bin/git.original`, but real Git and any alias or external
  `git-<name>` helper shall begin with no capabilities after exec. Commands that
  legitimately require access to root-owned repository state shall be listed
  explicitly in the compiled `capability_loan` category; only that category may
  receive Ambient `cap_dac_override`. No-subcommand and terminal-query
  invocations are also capless.
- **REQ-GGUARD-014**: Linux process argv cannot contain an embedded null byte,
  so null handling is an internal conversion invariant rather than an external
  input boundary. The binary shall preserve every argument byte exactly,
  including non-UTF-8 bytes, when constructing the `execve()` vector. If any
  internally constructed argument cannot be represented as a `CString` because
  it contains an embedded null, conversion shall fail closed with exit code 2.
  The binary shall never substitute, truncate, lossy-convert, or silently drop
  an argument.

### 3. Destructive Command Blocks (Unconditional)

- **REQ-GGUARD-020**: Every exact subcommand in the compiled `blocked`
  category of `config/git_guard_subcommands.yaml` shall be unconditionally
  blocked for all users, including root, with exit code 1. The policy file is
  the single command-list authority; prose shall not duplicate a partial list.
  Build-time validation and the policy matrix shall require at least one block
  case for every entry, including destructive plumbing commands.
- **REQ-GGUARD-020a**: Every exact subcommand in the compiled `sudo_gated`
  category shall be denied to non-root users and allowed only for an effective
  UID 0 operator invocation, subject to any unconditional destructive-form
  checks. The category currently covers `submodule`, `checkout`, `switch`, and
  `restore`; the policy file remains authoritative.
- **REQ-GGUARD-020b**: Every exact subcommand in the compiled `partial`
  category shall run its command-specific policy before execution. In
  particular, `git rm --cached` may pass because it preserves worktree files
  while other `git rm` forms are blocked; `git rebase --continue`, `--abort`,
  and `--skip` may pass to recover an existing operation while starting or
  rewriting a rebase is blocked. Partial commands shall have both blocked and
  allowed matrix cases for each sanctioned distinction.
- **REQ-GGUARD-021**: A blocked invocation shall produce one reversibly escaped,
  unambiguous report containing the blocked command with stable argument
  boundaries, the policy reason, one RFC3339 UTC `Z` timestamp, and the remediation
  hint. The guard shall always attempt stderr delivery and shall also attempt
  `/dev/tty` delivery when a controlling terminal exists and is not the same
  terminal as stderr. Sameness shall be established from terminal/session
  identity, not pathname, inode, or ordinary file-device identity: `/dev/tty`
  may alias the same pseudoterminal through different filesystem metadata. It
  shall not print the report twice to the same terminal. Failure to open,
  identify, or completely write either destination shall be surfaced through
  any surviving destination but shall never permit the invocation or change exit
  code 1. Redirecting stderr shall not suppress a distinct controlling-terminal
  report. If stderr is a terminal but its terminal identity cannot be established,
  the guard shall retain the already-attempted stderr report and skip the tty
  copy rather than risk duplicate terminal output.

### 4. Destructive Command Options

- **REQ-GGUARD-030**: Destructive options shall be interpreted only through the
  identified subcommand's option grammar, including value-taking options,
  attached short forms, and the applicable `--` separator. Flag-like option
  operands and post-separator data shall never be classified as options. The
  policy shall enforce at least:
  - `reset` is governed by the unconditional blocked-subcommand category;
    `--hard` is not globally rescanned.
  - Hook-bypass `--no-verify` and any command-specific short alias are blocked
    for every Git command that defines them as options. A short token such as
    `-n` with a different meaning under another command remains allowed.
  - `push` blocks every force mechanism defined by REQ-GGUARD-052.
  - `tag` blocks `--force` and `-f` when they are actual tag options.
  - `branch` blocks `--force` and `-f` when they are actual branch options;
    force-delete and force-rename forms remain governed by their specific
    rules.
  Every blocked command-option pair shall have operand-lookalike and
  post-separator allowed controls in the policy matrix. Remediation text shall
  never recommend another option blocked by the same rule.
- **REQ-GGUARD-031**: Before subcommand discovery, the parser shall validate
  exactly the config-bearing global forms accepted by the pinned Git version:
  `-c name=value`, attached `-cname=value`, and
  `--config-env=name=environment_variable`. It shall consume each complete
  option, extract and retain only the config key, and compare the key
  case-insensitively against the compiled dangerous and sudo-gated patterns.
  If any repeated override contains a blocked key, the invocation shall be
  blocked. Config values and environment-variable names shall never enter block
  reports or audit logs. `-C <path>` is a directory-changing option and shall
  never be interpreted as config. Nonstandard `--config` forms and tokens after
  subcommand discovery or the applicable `--` separator shall not be treated as
  global config options. Malformed forms shall remain byte-identical for Git to
  reject unless their unknown arity makes reliable subcommand identification
  impossible under REQ-GGUARD-011.

### 5. Dangerous Git Config Key Injection

- **REQ-GGUARD-040**: `config/git_guard_config_keys.yaml` shall be the sole
  authority for dangerous and sudo-gated Git config-key patterns; prose shall
  not duplicate a partial key list. Every policy entry shall declare its
  pattern, enforcement class, threat class, and concrete reason. Required threat
  classes are command execution, hook/alias execution, filter/merge/pager
  execution, credential redirection, transport/protocol changes,
  repository/worktree redirection, remote fetch/push redirection, integrity
  bypass, and narrowly justified operator identity/editor settings. Command
  execution, credential/transport redirection, repository redirection, and
  integrity-bypass entries shall remain unconditional for all users. Only
  explicitly justified operator settings may be sudo-gated. Every pattern shall
  have a blocked positive case and a near-match allowed control, and each pinned
  Git upgrade shall audit newly added executable or redirecting config keys.
- **REQ-GGUARD-041**: A separate or attached `-c` payload shall be split on
  the first `=` when present; all remaining bytes belong to the value and shall
  not influence config-key policy and shall never be altered; the original value
  remains complete report/audit evidence under REQ-GGUARD-093. When `=` is absent, the complete
  payload is the key because Git assigns implicit boolean true. The key shall be
  non-empty and inspectable under the guard's explicit ASCII Git-key grammar,
  normalized with ASCII case folding, split into key segments, and matched
  against the compiled policy. A non-ASCII, non-UTF-8, empty, or otherwise
  uninspectable key shall fail closed with exit code 2 rather than become an
  empty/non-matching key. Separate and attached forms shall produce identical
  policy decisions.
- **REQ-GGUARD-042**: Syntactically valid config-bearing global options whose
  keys are classified as allowed by the authoritative catalog shall be passed
  to real Git with their original argv bytes unchanged. Key normalization is
  policy-only and shall not rewrite the forwarded argument. Config values shall
  remain opaque to policy but shall appear byte-exactly in diagnostics and audit
  evidence under reversible escaping. This
  argv-preservation rule does not disable mandatory inherited-environment
  sanitization and does not override REQ-GGUARD-041 rejection of malformed or
  uninspectable keys.

### 6. Subcommand-Specific Blocks

- **REQ-GGUARD-050**: The exact top-level `stash` subcommand shall be in the
  compiled unconditional `blocked` category and shall exit 1 for every user,
  including root, before stash-operation parsing. This includes bare `stash` and
  every operation, including `push`, legacy `save`, `pop`, `apply`, `list`,
  `show`, `drop`, and `clear`; operands and `--` shall not weaken the top-level
  block. Mutating stash forms can unlink/recreate worktree or index state and can
  fail partway on root-owned immutable policy files. Read-only forms are also
  denied so enforcement remains one exact, auditable subcommand rule without
  operation-classification gaps. The block report shall recommend the sanctioned
  alternatives from `AGENTS.md`: a temporary worktree for baseline comparisons
  or `git diff` output for snapshots.
- **REQ-GGUARD-051**: The `branch` command shall block branch-force semantics,
  not only the literal `-D` spelling. Block forced deletion (`-D` and every
  delete-plus-force combination), forced create/reset (`-f` or `--force`),
  forced rename (`-M` and move-plus-force), and forced copy (`-C` and
  copy-plus-force). Short-option clusters and every equivalent long-option form
  accepted by the pinned Git parser shall produce the same decision. Safe
  delete `-d`, move `-m`, and copy `-c` shall remain allowed when force is
  absent. Branch option interpretation shall stop at its applicable `--`, and
  post-separator operands shall not be classified as force options.
- **REQ-GGUARD-052**: The `push` command shall block force-push semantics for
  every user, not only literal force flags. Block `-f` in every valid short
  cluster, `--force`, bare and value-bearing `--force-with-lease`, refspecs whose
  force marker is a leading `+`, and `--mirror`. Equivalent option spellings
  accepted by the pinned Git parser shall produce the same decision. The guard
  shall also reject a push whose effective trusted repository configuration
  supplies a force refspec through `remote.*.push` or enables
  `remote.*.mirror`; these keys shall be unconditional dangerous catalog
  entries so new unsafe defaults cannot be set through guarded config paths.
  Push option interpretation shall stop at its applicable `--`, but refspec
  classification shall continue because post-separator operands are still
  refspecs and a leading `+` still requests force.
  `--force-if-includes` alone is not a force mechanism. Every force-push block
  shall exit 1 and its hint shall recommend an ordinary non-forced push, never a
  different force mechanism.
- **REQ-GGUARD-053**: A `push` process with a controlling terminal shall be
  blocked unless it is in that terminal's foreground process group. Read
  `/proc/self/stat`, locate the final `)` terminating `comm`, and parse absolute
  fields 5 (`pgrp`) and 8 (`tpgid`), which are indexes 2 and 5 respectively in
  the whitespace fields beginning at absolute field 3. If `tpgid > 0`, allow
  only when `pgrp == tpgid`; if `tpgid <= 0`, allow because no foreground
  terminal process group exists. Unreadable, truncated, malformed, non-numeric,
  or out-of-range stat data shall fail closed as a policy block with exit 1 and
  no real-Git execution.
- **REQ-GGUARD-054**: `commit --amend` shall be sudo-gated without inspecting
  ancestry: every actual amend option accepted by the pinned commit parser shall
  exit 1 for non-root users, while the verified root operator path may proceed
  through the normal commit contract checks. Parsing shall follow commit's
  option grammar and applicable `--`; prefixes or operands that are not amend
  options shall not block. The decision shall not depend on branch state,
  upstream naming, remote-tracking freshness, detached-HEAD state, a subprocess,
  or network access.
- **REQ-GGUARD-055**: `revert` shall not be blocked based on whether a target is
  present on a remote-tracking ref. Revert is forward-only and shall pass to real
  Git with argv unchanged, including multiple targets, ranges, `--stdin`,
  `--no-commit`, and sequencer recovery operations. The guard shall not parse
  revert targets or spawn branch, verification, or ancestry subprocesses for
  this decision. Normal hook enforcement, environment sanitization, capability
  policy, and post-operation ownership reconciliation remain mandatory.

### 7. Protected Branch Rules

- **REQ-GGUARD-060**: `config/git_guard_protected_branches.yaml` shall be the
  sole authority for protected branch names and prefixes; prose shall not
  duplicate a partial branch list. Exact entries match complete branch names and
  prefix entries match branch names beginning with that prefix. Matching shall
  use explicit ASCII case folding as a conservative policy independent of Git's
  case-sensitive ref identity and shall be identical for root and non-root.
  Build-time validation shall reject empty, non-ASCII, non-canonical-lowercase,
  duplicate, or syntactically invalid exact/prefix entries; prefixes shall end
  in `/`. Branch discovery, detached HEAD, and no-repository outcomes remain
  governed by REQ-GGUARD-063.
- **REQ-GGUARD-061**: `pull` on a protected branch shall exit 1 for every user
  unless the final effective command-line mode guarantees no merge commit. Safe
  modes are effective fast-forward-only or rebase enabled through `-r`,
  `--rebase`, or a non-false rebase value accepted by the pinned Git parser.
  Pull options shall be interpreted in order with Git's last-wins behavior:
  `--rebase=false` and `--no-rebase` disable rebase, while a later `--ff` or
  `--no-ff` overrides an earlier `--ff-only`. The invocation is allowed when at
  least one final effective mode remains safe. Value-taking options, short
  clusters, accepted long-option abbreviations, and the applicable `--` shall
  follow pull's command grammar so option operands and post-separator data cannot
  create safety state. Repository configuration alone shall not satisfy this
  rule; the safe mode must be explicit in argv.
- **REQ-GGUARD-062**: On a protected branch, non-root `merge` shall exit 1
  unless its final effective command-line mode is fast-forward-only or it is an
  actual non-committing recovery operation `--abort` or `--quit`. Merge FF
  options shall use Git's ordered last-wins behavior: a later `--ff` or
  `--no-ff` overrides an earlier `--ff-only`, while a later `--ff-only` restores
  safe mode. `--continue` is not a safe recovery exception because it may create
  the pending merge commit. Value-taking options, accepted long-option
  abbreviations, and the applicable `--` shall follow merge's grammar so option
  values and post-separator operands cannot create safety state. Configuration
  alone shall not satisfy the explicit FF-only requirement. The verified root
  operator path may perform other merge modes.
- **REQ-GGUARD-063**: Protected-branch classification shall use the same
  effective repository context as the eventual Git command, including every
  validated global repository selector. Repository resolution shall return a
  typed result distinguishing proven no-repository from operational failure;
  every resolver outcome other than resolved or proven no-repository shall block
  an affected protected-branch operation. In
  a resolved repository, the guard shall invoke verified real Git with fixed
  argv `symbolic-ref --quiet HEAD`, the sanitized environment, and a two-second
  timeout; a successful byte-exact `refs/heads/<name>` result supplies the branch
  name, including for unborn branches and linked worktrees. Proven detached HEAD
  and proven no-repository contexts shall skip protected-branch policy. Timeout,
  spawn/exec failure, malformed output, an unexpected symbolic-ref namespace,
  or any other discovery failure in a known repository shall fail closed as an
  exit-1 policy block with no execution of the requested command. One discovery
  result shall be reused by pull and merge policy and later repository handling.

### 8. Environment Variable Sanitisation

- **REQ-GGUARD-070**: `config/git_guard_environment.yaml` shall be the sole
  authority for child environments. The guard shall construct a new environment
  from cataloged allowed exact names and prefixes rather than subtracting known
  dangerous names from the inherited environment; unknown names shall be
  dropped for root and non-root. Cataloged editor and identity names may be
  inherited only when effective UID is zero; `AT_SECURE` shall not authorize
  them. Caller-supplied guard-owned names and prefixes, including all
  `GIT_CONFIG_*` and SSH-wrapper variables, shall always be discarded before one
  canonical guard value is injected. Policy-approved `--config-env` value
  carriers shall use a reserved otherwise-uninterpreted namespace and shall be
  inherited only when referenced by an accepted option. Every admitted name
  shall occur at most once; admitted values shall remain byte-exact and shall
  remain complete evidence whenever reported. One sanitizer shall serve policy helpers, the contract
  runner, and final real Git, with narrowly specified helper additions layered
  afterward. Every removed, replaced, or rejected inherited name shall produce
  a byte-exact evidence diagnostic; filtering shall never be silent. The build shall
  reject overlapping categories,
  duplicate names, unsafe prefixes, and attempts to allow known Git, loader,
  shell, pager, editor, credential, object-store, repository, or config-injection
  control variables outside their explicit guarded category.
- **REQ-GGUARD-071**: `config/git_guard_environment.yaml` shall be the sole
  authority for blocked hook-bypass environment names. Before any policy helper
  or requested Git execution, the guard shall inspect each cataloged name as
  bytes. Any occurrence with a non-empty value, including a non-UTF-8 value,
  shall produce an exit-1 policy block for root and non-root. Empty values shall
  not block, shall be omitted by REQ-GGUARD-070 sanitization, and shall produce a
  byte-exact evidence warning that explicitly preserves the empty value. Block
  reports and audit records shall include the variable name and exact value under
  reversible encoding; omission or masking is forbidden under REQ-GGUARD-093.
  Every catalog entry shall have non-empty blocked, empty
  allowed, root, evidence, and no-child-execution coverage. Each pinned hook-
  framework upgrade shall inventory newly introduced bypass controls before
  acceptance.
- **REQ-GGUARD-072**: `PATH` shall be an allowed exact variable in the
  authoritative environment catalog and shall be preserved byte-identically for
  root and non-root. If absent, it shall remain absent; the guard shall not
  synthesize or reset it. Every guard-owned executable used for final execution
  or a policy helper shall instead be selected through its fixed absolute path
  and verified under its applicable integrity contract. Git, hooks, contract
  scripts, and external Git helpers may use the preserved caller PATH for their
  intended child command resolution. PATH preservation does not authorize
  caller overrides of guard-owned executable paths.
- **REQ-GGUARD-073**: The authoritative environment catalog shall preserve
  caller `HOME`, `USER`, `LANG`, and `LANGUAGE` as allowed exact names and `LC_`
  as an allowed prefix. Present values, including empty and non-UTF-8 values,
  shall remain byte-identical; absent names shall remain absent. This locale
  scope does not include command/path-loading controls such as `LOCPATH` or
  `NLSPATH`. Policy helpers, the contract runner, and final Git shall receive the
  same preserved base values. The guard shall never use caller `HOME` or `USER`
  as identity or path authority: logs, trusted home, identity, keys, and policy
  paths shall be resolved from kernel credentials and the passwd database.
- **REQ-GGUARD-074**: At startup the guard shall take one immutable byte-oriented
  snapshot of the inherited environment and treat every entry as untrusted data.
  `secure_getenv()` shall not be used as a universal reader because it hides all
  values under `AT_SECURE` and would disable REQ-GGUARD-070 through 073. The
  snapshot may influence only catalog sanitization/preservation, bypass
  detection, validated config-value carriers, effective-root-only catalog
  entries, and cataloged guard diagnostics. It shall never supply authority for
  executable or policy paths, identity/home resolution, capabilities, integrity,
  repository classification, or security policy. `WORKSPACE_GUARD_TRACE` shall
  be a cataloged guard-diagnostic input: a non-empty value requests phase timing
  on stderr, the variable is not forwarded to children, and tracing shall report
  its configured phase evidence. Every policy helper's stderr and failure status
  shall be surfaced with reversible byte escaping rather than discarded,
  modified, or collapsed into an unreported fallback.

### 9. WORKSPACE-CI Contract Enforcement

- **REQ-GGUARD-080**: The compiled `contract_check` category shall contain
  exactly the top-level subcommands `commit` and `push`, matching the trusted
  runner's supported `WORKSPACE_GGUARD_CMD` values. Matching shall be exact and
  root shall receive no bypass. For each qualifying invocation, run the contract
  exactly once after static policy and effective-repository resolution but before
  capability loan or requested real-Git execution. Every other subcommand shall
  skip the contract runner. Commit-producing commands outside this category,
  including `cherry-pick` and `am`, remain subject to native hooks, environment
  policy, and reconciliation, and their resulting history must pass the contract
  before a later push. Additional contract commands require a prior explicit
  extension of the trusted script's command/content-state contract; the guard
  shall never pass an undocumented command value.
- **REQ-GGUARD-081**: Workspace membership shall be authorized only by a
  verified root-owned runtime registry of canonical absolute workspace roots at
  `/etc/workspace-guard/workspace-roots`. Before use, the guard shall verify its
  parent chain as root-owned and not group/other-writable and the registry as a
  no-follow regular file with `root:root`, exact mode `0644`, and the filesystem
  immutable flag; missing, unreadable, malformed, replaceable,
  or drifted registry state shall fail closed for contract-eligible commands.
  Using the single effective repository result from REQ-GGUARD-063, membership
  shall compare canonical path components: a repository is in scope when its
  canonical root equals or descends from a registered root. Lexical string
  prefixes shall not match; if registered roots overlap, the longest matching
  ancestor wins. Classification shall be byte-safe and identical for root and
  non-root. Agent-writable marker paths may be checked only as drift evidence;
  their creation, deletion, replacement, type, or contents shall never grant,
  remove, or redirect workspace membership, and any observed drift diagnostic
  shall not be swallowed.
- **REQ-GGUARD-082**: For exact `commit`, a repository outside every verified
  registered workspace shall skip contract enforcement without consulting
  mutable remote configuration. For exact `push`, an outside-workspace repository
  may skip only when its effective destination is successfully resolved and
  proven unrelated to the authoritative protected-remote catalog. A protected
  destination shall be blocked with exit 4 and a requirement to push from a
  registered workspace; an absent, malformed, ambiguous, failed, or otherwise
  indeterminate destination shall fail closed with exit 4. Destination resolution
  shall use push's validated command grammar and the same sanitized Git
  configuration as final execution, covering explicit URLs, named remotes, push
  URLs, default remote selection, and effective URL rewrites. Catalog matching
  shall compare canonical host and repository path/namespace components rather
  than host-only or substring matches. One typed destination result shall be
  reused by contract scope and later push policy, and every helper diagnostic
  shall be surfaced under REQ-GGUARD-113.
- **REQ-GGUARD-083**: For WORKSPACE workspace repos, the binary shall execute
  contract checks from the fixed absolute path
  `/opt/workspace-ci/lib/checks_quality.sh` through the narrowly scoped
  REQ-GGUARD-007 contract runner. It shall never prepend a workspace root,
  resolve a source checkout, or accept an override for this path. The binary
  shall invoke exactly executable/argv `["/bin/bash",
  "/opt/workspace-ci/lib/checks_quality.sh"]`, set cwd to the canonical effective
  repository root, and attach `/dev/null` to stdin. Immediately before spawn it
  shall verify `/bin/bash` under the installed shell-guard identity/integrity
  contract and verify the script plus trusted parent chain no-follow for expected
  type, root ownership, non-writability, exact mode, immutable state, and deployed
  content identity. The child shall receive no Git capability loan. Its
  environment shall be rebuilt from the shared sanitized snapshot after removing
  every caller `WORKSPACE_GGUARD_*` value, then exactly the REQ-GGUARD-084
  bindings shall be added. Stdout and stderr shall be drained concurrently and
  surfaced on success and failure without deadlock, truncation, masking, or
  silent loss, using bounded per-chunk memory. Timeout shall
  terminate and
  reap the complete contract process group. Spawn, pipe, output, wait, signal,
  timeout, integrity, and non-zero-exit failures shall retain distinct
  diagnostics and fail closed with exit 4. The binary shall NOT re-implement the
  contract logic: it delegates to the immutable WORKSPACE-CI artifact.
- **REQ-GGUARD-084**: After shared environment sanitization, the guard shall
  remove with byte-exact evidence diagnostics every caller-supplied
  `WORKSPACE_GGUARD_*` and legacy `AMI_GGUARD_*` entry, then insert exactly one
  each of these trusted bindings:
  - `WORKSPACE_GGUARD_CMD`: the exact compiled contract command, `commit` or
    `push` only;
  - `WORKSPACE_GGUARD_REPO_ROOT`: the canonical effective repository root from
    the single REQ-GGUARD-063 result;
  - `WORKSPACE_GGUARD_WORKSPACE_ROOT`: the exact verified registry root selected
    by REQ-GGUARD-081.
  Names shall be ASCII constants and path values shall remain raw Unix bytes
  without lossy conversion. Presence of spaces, newlines, non-UTF-8 bytes, or
  leading-hyphen path components shall not change argument or environment
  boundaries. The bindings shall use the same immutable identities as runner
  cwd, membership, locking, and policy and shall not be recomputed. Duplicate,
  missing, embedded-NUL construction, or inconsistent binding state shall fail
  closed with exit 4. The trusted script shall quote and consume every binding as
  data. No `AMI_GGUARD_*` compatibility alias shall be emitted or accepted.
- **REQ-GGUARD-085**: Contract stdout and stderr shall be streamed once as bytes
  during execution, preserving every byte and each stream's order without
  redaction. Non-UTF-8 output shall not be lossy-converted. A
  zero exit is `Passed`; every non-zero script exit is `Rejected` and shall make
  the guard exit 4 regardless of the script's numeric code. The child code shall
  remain diagnostic metadata. Signal, timeout, spawn, pipe/read/write, wait, and
  integrity failures are distinct typed outcomes and also map to exit 4. After
  any failure, the guard shall emit one concise status summary that does not
  duplicate already-streamed script output, deliver it through standard
  stderr/distinct-tty/audit block reporting. Script streams remain separately
  preserved evidence and are not duplicated inside the summary record. No non-`Passed` outcome may execute the
  requested Git command, and no helper output or failure may be swallowed.
- **REQ-GGUARD-086**: Whenever REQ-GGUARD-080/082 requires a contract, any
  unavailable or untrusted runner deployment shall fail closed with exit 4 for
  root and non-root. This includes missing `/opt/workspace-ci`, missing script or
  `/bin/bash`, no-follow/type/owner/group/mode/parent-writability/immutable/content
  mismatch, permission or inspection error, and replacement/race detected before
  spawn. Verifier mechanics remain defined by REQ-GGUARD-083. The guard shall
  retain the distinct failure class, report the fixed affected path through
  stderr/distinct-tty/audit delivery with reversible evidence encoding,
  and never execute requested Git. It shall not skip, use a workspace source
  checkout, select an alternate runner, install/repair files, or perform network
  retrieval. When no contract is required, runner availability shall not be
  probed.

### 10. Audit Logging

- **REQ-GGUARD-090**: Every policy denial, including exit-1 blocks and exit-4
  contract rejection/unavailability, shall attempt one authoritative append only
  to `/var/log/workspace-guard/git-<real-uid>.log`; Git guard audit logs or
  mirrors shall never be created under a user-writable directory. The fixed
  directory shall be verified through a trusted parent-chain directory fd as
  `root:root` exact mode `0750`, not group/other-writable. The decimal filename
  shall derive only from kernel real UID. The opened target shall be a no-follow
  regular file, `root:root`, exact mode `0600`, with no special bits; a newly
  created file shall be secured before use. The guard shall lock the file, append
  one fully encoded byte-exact evidence record, sync it, verify every operation, and then
  unlock/close it. Concurrent records shall not interleave. Open, verification,
  lock, write, sync, or close failure shall never allow requested Git and shall
  be surfaced through stderr and distinct tty rather than swallowed. Audit
  records shall use trusted real UID/passwd and byte-safe cwd/argv data, never
  environment HOME/USER or lossy conversion.
- **REQ-GGUARD-091**: Each audit event shall be one versioned canonical ASCII
  line with fixed-order pipe-delimited `name=value` fields:
  `v=1|ts=<RFC3339-Z>|event=<class>|exit=<decimal>|uid=<decimal>|cwd=<encoded>|argc=<decimal>|arg0=<encoded>|...|reason=<encoded>\n`.
  Required event classes include `block`, `contract-reject`,
  `contract-unavailable`, and `audit-failure`. Runtime warnings are stderr-only
  under REQ-GGUARD-112 and shall not create audit records. Raw byte values shall
  be percent-encoded before insertion: preserve only the approved unreserved
  ASCII set and encode every `%`, `|`, `=`, space, CR/LF, control byte, and byte
  `>=0x7f` as uppercase `%HH`. Encoding is reversible framing, not redaction;
  decoding shall recover the exact original bytes.
  `argc` and contiguous indexed argument fields shall preserve boundaries and
  empty arguments; joined command strings are forbidden. Field names/order,
  event vocabulary, decimal grammar, and one final newline are fixed by schema
  version. Records shall never be truncated or split across appends. Writers and
  readers shall reject malformed escapes, duplicate/missing/out-of-order fields,
  `argc` mismatch, unknown required event classes, extra newlines, and unsupported
  versions. An `audit-failure` diagnostic shall not recursively attempt another
  audit append.
- **REQ-GGUARD-092**: Audit append shall return a typed error identifying its
  stage: parent verification, open/create, metadata verification, lock, encode,
  write, sync, unlock, or close. Any failure shall preserve the original policy
  result and exit class: exit-1 denials remain 1, exit-4 contract outcomes remain
  4, and requested Git shall never execute. The guard shall emit one separate
  non-recursive reversibly escaped diagnostic through stderr and distinct tty with
  the fixed audit path, failure stage, OS status where available, and confirmation
  that denial remains enforced. It shall not retry integrity failures, claim
  persistence without successful append and sync, or fall back to HOME, `/tmp`,
  workspace/caller paths, world-writable files, or any unverified alternate
  logger. Only interrupted syscalls may be safely retried. An `audit-failure`
  record may be persisted only through a separate already-verified authoritative
  channel; otherwise it is a delivered diagnostic, not a stored audit event.
- **REQ-GGUARD-093**: The guard shall not redact, mask, omit, hash, or truncate
  caller input, environment evidence, helper output, reasons, or hints from any
  destination where another requirement requires that evidence to be delivered
  or persisted. This does not require duplicating separately streamed helper
  output inside a summary audit record. Inline credentials or tokens are
  prohibited agent behavior: agents shall use only sanctioned secret-store paths,
  and any violation shall remain complete forensic evidence. Terminal output
  shall use reversible escaping for unsafe bytes; audit values shall use the
  reversible REQ-GGUARD-091 percent encoding. Decoding shall reproduce the exact
  original bytes and argument boundaries. Encoding is never a secrecy control.

### 11. Exit Codes

- **REQ-GGUARD-100**: Policy allowance shall preserve real Git's process outcome,
  not force success. After required relock/reconciliation, normal Git exit `0`
  shall produce guard exit `0`, every other normal Git exit shall preserve the
  exact code, and signal termination shall terminate the guard with the same
  signal so callers observe signaled status rather than a synthetic normal exit.
  Because the guard forks and waits to perform post-exec policy work, the outcome
  is propagated after `wait`, not returned “via exec.” A documented post-exec
  invariant/reconciliation failure may override Git's outcome with `EX_IOERR`
  (`74`) after reporting that Git's operation already stands. Fork, capability-
  loan, exec, wait, and other supervision failures shall use their typed guard
  error/exit class and shall never masquerade as Git status or an exit-1 policy
  block. Ordinary Git failure shall produce no guard block audit record and Git
  stdout/stderr shall remain byte-exact.
- **REQ-GGUARD-101**: Exit **1** shall mean a typed guard policy denial with no
  more specific exit class, including unconditional/partial command policy,
  sudo-gated denial, dangerous or sudo-gated config keys, hook-bypass environment
  attempts, protected-branch rules, background-push policy, sealed-repository
  policy, and other command/repository safety rules. Before exit, emit exactly
  one complete block report to stderr and a distinct tty under REQ-GGUARD-021 and
  attempt exactly one authoritative `event=block|exit=1` audit append under
  REQ-GGUARD-090..093. Report or audit failure shall be surfaced but shall not
  change exit 1, and requested Git shall never execute. Argument validation
  remains exit 2, privilege/integrity/supervision failures remain exit 3, and
  contract outcomes remain exit 4. A real Git exit 1 is propagated under
  REQ-GGUARD-100 without a guard block report or block audit event; exit code
  alone shall not classify an outcome as policy denial.
- **REQ-GGUARD-102**: Exit **2** shall be reserved for typed, caller-caused
  invocation validation failures that prevent safe or reliable policy
  classification: internal/test argv containing NUL, missing operands for
  recognized value-taking global options when discovery becomes indeterminate,
  unknown leading options whose unknown arity prevents reliable subcommand
  identification, malformed/uninspectable safety-critical config keys under
  REQ-GGUARD-041, and failed byte-exact argv-to-`CString` construction. Arbitrary
  non-UTF-8 argv remains valid unless the specific inspected field has an
  explicit ASCII requirement. Terminal queries and no-subcommand invocations are
  valid passthroughs. Reliably classifiable malformed command-specific syntax
  shall reach real Git unchanged; Git remains syntax authority, and Git's own
  exit 2 is propagated under REQ-GGUARD-100 without a guard validation report.
  Unexpected internal, privilege, integrity, exec, or supervision failures shall
  use exit 3, never exit 2 or policy exit 1. Validation diagnostics shall be
  stable, reversibly escaped, and shall never substitute, omit, or alter argv.
- **REQ-GGUARD-103**: Exit **3** when capability-mode or root-only privilege
  verification fails, when the real Git binary cannot be found or verified, or
  when the guard cannot safely establish/supervise execution. This typed
  guard-unavailable class includes missing/untrusted/malformed/unknown deployment
  class; capability absence or capability inspection/promotion/loan failure;
  invalid `NoNewPrivileges` state or inspection failure; root-only effective UID
  failure; REQ-GGUARD-006 real-Git identity/integrity failure; required resource-
  limit setup failure; fork, exec, wait, or signal-propagation failure; and other
  internal failures not assigned to validation, policy, contract, audit-delivery,
  or reconciliation classes. The diagnostic shall preserve stage, cause, and OS
  status as reversible forensic evidence. Inspection errors shall never be
  interpreted as acceptable state; only safely retryable `EINTR` conditions may
  be retried. Pre-exec failures shall execute no requested Git. A post-start
  supervision failure shall state whether Git's outcome or mutation is unknown
  or may already stand. Exit 3 shall not emit an exit-1 policy-block event.
  Real Git's own normal exit 3 remains an ordinary outcome propagated under
  REQ-GGUARD-100 without a guard-unavailable diagnostic. Reconciliation drift
  retains its explicit `EX_IOERR` 74 override.
- **REQ-GGUARD-104**: Exit **4** for every non-success outcome whenever an exact
  `commit` or `push` requires the WORKSPACE-CI contract. Typed outcomes shall
  distinguish `ContractRejected { child_code }`, `ContractUnavailable { stage,
  cause, os_status }`, and `ContractRequiredOutsideWorkspace { destination }`.
  This class includes a normal non-zero runner exit; protected or indeterminate
  outside-workspace push destination; unavailable workspace membership,
  effective-repository, destination, hook, deployment, binding, runner, pipe,
  output, wait, signal, timeout, integrity, or cleanup state; and every other
  inability to verify or complete the required contract. Root has no bypass.
  Inspection or helper failure shall never be interpreted as an empty result or
  a successful check.
  Only a fully verified `Passed` outcome may continue to requested Git; every
  exit-4 guard outcome shall state its exact class, preserve complete reversible
  evidence, emit one concise stderr/distinct-tty report, and attempt one
  authoritative `contract-reject` or `contract-unavailable` audit append.
  Separately streamed runner output shall not be duplicated in the summary.
  Report or audit failure shall be surfaced without changing exit 4. Earlier
  typed policy, validation, or guard-unavailable outcomes retain exits 1, 2, or
  3. Real Git's own normal exit 4 is propagated under REQ-GGUARD-100 without a
  contract report or contract audit event; exit code alone shall not classify an
  outcome as a contract failure.

### 12. Error Output

- **REQ-GGUARD-110**: One shared byte-safe delivery primitive shall handle every
  guard-enforced failure report: exit-1 policy denials, exit-2 invocation
  validation, exit-3 guard-unavailable outcomes, exit-4 contract summaries, and
  non-recursive audit-delivery failure diagnostics. It shall construct one
  immutable reversibly escaped payload, attempt a complete checked stderr write,
  and then follow REQ-GGUARD-021's terminal/session-identity rule for a distinct
  controlling-terminal copy. `/dev/tty` shall be opened close-on-exec. Partial
  writes shall be completed; only valid interrupted operations may be retried.
  Expected absence of a controlling terminal is not an error. Unexpected open,
  identity, or write failures shall be typed and surfaced through any surviving
  destination without recursion, changing the original exit class, or changing
  the execution decision. Separately streamed contract output, stderr-only
  warnings under REQ-GGUARD-112, and ordinary real Git output/outcomes shall not
  enter this dual-destination failure-report path.
- **REQ-GGUARD-111**: Policy block messages shall use this exact ASCII grammar,
  followed by exactly one final newline:
  `BLOCKED: ts=<RFC3339-UTC-Z>|reason=<encoded>|argc=<decimal>|arg0=<encoded>|...|argN=<encoded>\nhint=<encoded>\n`.
  The indexed fields shall include exact `argv[0]` through `argv[argc-1]` and
  preserve empty arguments. `reason`, every argument, and `hint` shall use the
  canonical uppercase `%HH` value encoding from REQ-GGUARD-091; lossy UTF-8,
  shell quoting, joined argv, ANSI control sequences, localization, masking, and
  truncation are forbidden. The dispatcher shall construct one evidence object
  containing argv, the first-blocking policy's exact reason, and one timestamp,
  then reuse it for visible and audit formatting so those fields cannot diverge.
  The reason shall identify the exact matched compiled policy/form under the
  established first-block-wins precedence. The brief hint shall come from that
  policy rather than caller-controlled text and shall not recommend an action
  blocked in the same context; conditional alternatives shall state their
  condition. A hint is evidence only and shall never be executed or interpreted
  as shell syntax.
- **REQ-GGUARD-112**: Runtime warnings are limited to the typed catalog in the
  specification: filtered environment entries, empty hook-bypass entries,
  inspected legacy workspace-marker drift, reconcile symlink skips, and
  protected hook/registry ownership or immutable-state drift. Each warning shall
  use the exact one-line ASCII grammar
  `WARNING: ts=<RFC3339-UTC-Z>|kind=<catalog-token>|fieldc=<decimal>|field0=<encoded>|...|fieldN=<encoded>\n`.
  The typed warning variant fixes field count/order; dynamic fields use
  REQ-GGUARD-091 uppercase `%HH` encoding and preserve exact bytes without lossy
  path/environment conversion, masking, or truncation. One event produces one
  complete checked stderr write and no `/dev/tty`, audit, or `BLOCKED:` output.
  Each inherited environment entry shall produce at most one warning: the empty
  hook-bypass variant supersedes the generic filtered-environment variant.
  The warning condition remains non-blocking when delivery succeeds. A partial
  or failed stderr write shall not be ignored: before Git starts it becomes typed
  exit-3 `GuardUnavailable { stage=warning-stderr, ... }` and executes no Git;
  after Git starts it becomes exit 3 and states that Git's operation may already
  stand. The resulting guard-unavailable report, not the warning, follows
  REQ-GGUARD-110. Expected trace output, helper stderr, contract streams,
  validation/integrity/audit failures, and installer diagnostics retain their
  own classes. A background-push detection failure is not a warning;
  REQ-GGUARD-053 requires an exit-1 fail-closed block.
- **REQ-GGUARD-113**: An ordinary allowed invocation with no guard diagnostic
  condition shall add no guard output to real Git's output. Guard-generated
  diagnostics shall use stderr, plus a distinct tty only where another
  requirement mandates it; the guard shall never emit its own text to stdout.
  Real Git shall inherit the caller's stdout/stderr unchanged and shall never be
  piped, decoded, escaped, buffered, prefixed, merged, reordered, or duplicated
  by the guard. Stdout may therefore contain only real Git bytes or separately
  streamed WORKSPACE-CI stdout. Successful policy-helper stdout is internal
  typed protocol; helper stderr on success or failure shall be incrementally
  surfaced as canonical reversible `HELPER-STDERR` chunks with helper identity,
  contiguous sequence, final marker, and byte-exact payload. Trace enablement
  shall be computed once from the immutable startup snapshot and requires a
  non-empty `WORKSPACE_GUARD_TRACE`; canonical start/end records use static phase
  tokens, stderr only, and disclose no caller/policy values. Pre-Git warnings,
  trace, and helper diagnostics shall complete before requested Git starts;
  contract streams precede Git and a contract-failure summary follows its
  streams; post-Git trace/reconcile diagnostics occur only after Git is reaped.
  Per-stream byte order shall be preserved, without promising total ordering
  between stdout and stderr. Required diagnostics shall never be swallowed,
  replaced with empty output, masked, or lossily converted. Pre-Git trace/helper
  diagnostic delivery failure is typed guard-unavailable exit 3 and executes no
  Git; post-Git diagnostic delivery failure exits 3 and states that mutation may
  already stand, subject to reconciliation exit-74 precedence. Contract stream
  failure remains exit 4, enforced-report delivery preserves its original class
  under REQ-GGUARD-110, and real Git output/write failures remain Git outcomes.

### 13. Security Hardening (Rust-Specific)

- **REQ-GGUARD-120**: Hardening shall be a verified property of the exact
  privileged `workspace-guard` ELF, not an assumed Cargo setting. The release and
  development profiles shall use `panic = "abort"` and
  `overflow-checks = true`; release shall additionally use `opt-level = "z"`,
  `lto = true`, `codegen-units = 1`, and `strip = true`. The pinned
  `x86_64-unknown-linux-musl` release artifact shall be static PIE, have a
  `GNU_RELRO` segment covering writable relocation state, have a non-executable
  `GNU_STACK`, use stack protection, and contain no ELF interpreter or dynamic
  dependencies. Full-RELRO linker semantics shall include immediate binding when
  a dynamic target is explicitly specified by a future requirement; no dynamic
  fallback is currently permitted. The build shall use committed trusted target/
  linker flags and a pinned toolchain, reject inherited compiler/linker overrides,
  and fail closed if the toolchain cannot produce or the verifier cannot prove
  every required property. Verification shall inspect the built artifact, record
  its digest, copy/install those exact bytes, reverify the installed inode before
  applying file capabilities, and confirm its digest matches. The guard uses file
  capabilities and is not an SUID binary.
- **REQ-GGUARD-121**: Production unsafe Rust shall be confined to one reviewed
  `linux_ffi` module exposing safe or explicitly unsafe narrow wrappers for
  exactly four irreducible Linux operations: `libc::getauxval(AT_SECURE)`,
  `libc::fork`, `libc::_exit`, and `libc::ioctl(FS_IOC_GETFLAGS)`. The crate shall
  deny unsafe code everywhere except that module. Each unsafe block shall have an
  adjacent `// SAFETY:` contract covering pointer validity, lifetime/alignment,
  accepted values, return/error handling, and post-fork restrictions where
  applicable. `geteuid`, `PR_GET_NO_NEW_PRIVS`, no-follow ownership changes,
  writes, exec, wait, signals, and resource operations shall use safe `nix` or
  standard-library wrappers; no-follow ownership shall use
  `fchownat` with the no-follow flag rather than `lchown`. A pre-fork close-on-exec
  status pipe shall let the child report typed setup/exec failure to the parent
  using a safe allocation-free write wrapper; the child shall not format or emit
  user diagnostics. Between fork and exec/_exit, only an audited fixed set of
  allocation-free, lock-free, async-signal-safe operations over prebuilt storage
  is permitted. Build gates shall reject new `unsafe` blocks/functions/traits,
  inline assembly, direct libc calls, or unapproved post-fork calls outside the
  allow-list. Dedicated tests may retain raw `fork`/`_exit` only in one exact
  allow-listed test module with equivalent safety contracts; all other tests use
  safe wrappers.
- **REQ-GGUARD-122**: The privileged `workspace-guard` binary shall live in its
  own Cargo package so unrelated shell, binary, SSH, and YAML-editor dependencies
  cannot enter its closure. It shall have no local/path/Git dependency. Its only
  direct runtime dependencies are `libc = "0.2"` for REQ-GGUARD-121's four-call
  boundary; `nix = "0.29"` with `default-features = false` and only the reviewed
  `user`, `process`, `signal`, `resource`, and `fs` features; and `caps = "0.5"`
  optional only for capability mode. Root-only mode shall contain no `caps`;
  capability mode shall contain exactly one locked approved `caps` version; the
  two modes are mutually exclusive. No runtime dependency may provide network
  I/O, file watching, dynamic loading, CLI parsing, serialization, regex, hashing,
  or plugin facilities. Argument parsing remains manual `OsStr`/`OsString` code.
  The policy compiler may directly build-depend only on locked `serde`,
  `serde_yaml`, and `regex` with exact reviewed features; their normal/build/
  proc-macro transitive closure, including `unsafe-libyaml` and `serde_derive`,
  shall be a separately versioned allow-list. Builds shall use Cargo resolver 2,
  exact package/binary/feature/target selection, and
  `--locked --frozen --offline` against a trusted checksum-verified source store.
  Git dependencies, alternate registries, unapproved path dependencies, duplicate
  crate versions, unexpected build scripts/proc macros, source/checksum changes,
  feature unification/drift, and closure differences shall fail before code
  execution. Third-party build scripts/proc macros shall run without root,
  network, or write access outside the isolated build/target directory; root
  shall only verify and install the resulting artifact. The final static ELF
  shall retain no dynamic dependency. Build gates shall compare Cargo metadata/
  tree output for normal, build, and proc-macro edges against both deployment
  feature closures and bind the accepted closure manifest to the artifact digest.
- **REQ-GGUARD-123**: No blanket UTF-8 validation shall be applied to caller
  argv, Unix paths, refs, remotes, environment values, or helper evidence. They
  shall remain `OsStr`/`OsString` or byte slices from the immutable snapshot
  through policy, helper binding, diagnostics/audit, and final execution. Policy
  syntax shall be recognized by direct comparison with compiled ASCII byte
  constants. Only a field whose requirement defines an ASCII grammar may reject
  non-ASCII bytes; config keys do so under REQ-GGUARD-041, while config values,
  option operands, pathspecs, refs, paths, and post-`--` data remain opaque bytes.
  An unknown leading byte option exits 2 only when its unknown arity prevents
  reliable classification. A non-ASCII subcommand candidate that matches no
  exact compiled command shall follow REQ-GGUARD-013 capless passthrough. ASCII
  option prefixes whose policy applies independently of an opaque value shall
  still be recognized without decoding that value. Parsing shall never map
  failed UTF-8 to empty/non-matching text, trim or normalize forwarded bytes, or
  use lossy conversion for a security, containment, execution, or evidence
  decision. Original accepted argv order/count/empty arguments and bytes,
  including `argv[0]`, shall reach real Git unchanged; the fixed executable path
  passed separately to `execve` does not replace `argv[0]`. `CString` creation shall consume exact bytes once before fork and
  remain fallible: caller argv conversion failure is typed exit 2; failure of a
  guard-constructed argument, environment entry, helper binding, or path is typed
  exit 3. Substitution, replacement characters, truncation, omission, silent
  `filter_map`, or reordered reconstruction are forbidden. Helper protocol fields
  may become `String` only after their exact grammar validates the complete byte
  sequence; opaque helper stdout/stderr remains byte evidence. Terminal output
  and audit records use reversible framing and shall decode to the original bytes.
- **REQ-GGUARD-124**: The binary shall set its own `RLIMIT_NOFILE` to a reasonable limit (e.g., 256) and `RLIMIT_CORE` to 0 (no core dumps) before exec-ing real git, to limit blast radius.
- **REQ-GGUARD-125**: The binary shall NOT open any file descriptors other than `/dev/tty`, `/proc/self/stat`, and the real git binary before exec-ing. No temporary files, no log file open during argument processing.

### 14. Performance

- **REQ-GGUARD-130**: Non-commit/non-push invocations shall complete guard logic in under 5ms (excluding real git execution).
- **REQ-GGUARD-131**: The binary shall NOT spawn any subprocess for argument parsing or decision logic, except for:
  - fixed repository resolution and `symbolic-ref --quiet HEAD` helpers for
    REQ-GGUARD-063
  - fixed WORKSPACE-CI contract check script (REQ-GGUARD-083)
- **REQ-GGUARD-132**: Permitted repository-discovery subprocesses shall have a
  timeout of 2 seconds. Their command-specific requirements define
  timeout handling; static destructive and sudo-gated decisions shall never be
  skipped because of a subprocess failure.

### 15. Deployment and Installation

- **REQ-GGUARD-140**: The git guard shall be installed by `make build-guard` and `make install-guard-host-exec`: not by `make install`. `make install` shall NOT touch the git binary or git guard. `make install-guard` shall hard-fail.
- **REQ-GGUARD-141**: The `make install-guard-host-exec` script shall inform the user **before** any git-related changes are made, including: that the existing system git will be relocated, that a file-capability guard binary will be installed at `/usr/bin/git`, and that the real git will be restricted to mode 0700 root:root.
- **REQ-GGUARD-142**: The installation flow shall build the isolated
  `git-guard/Cargo.toml` package as an unprivileged build identity using the exact
  package/binary/target/mode selection and `--locked --frozen --offline` contract
  in REQ-GGUARD-120/122 before root verifies and installs it.
- **REQ-GGUARD-143**: Before relocating the real git, the script shall verify that: (a) the Rust binary compiled successfully, (b) the compiled binary is a valid ELF executable, and (c) `/usr/bin/git` exists and is the system git.
- **REQ-GGUARD-144**: The script shall relocate the real git binary as follows:
  1. Copy `/usr/bin/git` to `/usr/bin/git.original`
  2. Set ownership: `chown root:root /usr/bin/git.original`
  3. Set permissions: `chmod 0700 /usr/bin/git.original`
  4. Verify the copy matches the original via checksum comparison
- **REQ-GGUARD-145**: The script shall install the guard binary as follows:
  1. Copy the built binary to `/usr/bin/git`
  2. Set ownership: `chown root:root /usr/bin/git`
  3. Set permissions: `chmod 0755 /usr/bin/git`
  4. Set file capabilities: `setcap cap_setpcap,cap_chown,cap_dac_override,cap_fowner=ep /usr/bin/git` (host-exec only)
- **REQ-GGUARD-146**: After installation, the script shall verify correctness by:
  1. Confirming `/usr/bin/git` has correct mode and owner
  2. Confirming `/usr/bin/git.original` has mode 0700 and owner root:root
  3. Running `git --version` as the current user and confirming it succeeds
  4. Running `git reset --hard` as the current user and confirming it is blocked
- **REQ-GGUARD-147**: If any step of the installation fails, the script shall attempt to restore the original state: copy `/usr/bin/git.original` back to `/usr/bin/git` and set permissions to 0755. A clear error message shall be displayed.
- **REQ-GGUARD-148**: `make install-guard-host-exec` shall be idempotent for the host-exec class: it reconciles drift when `deployment-class` is `host-exec` or missing after legacy uninstall, including stale guard binary hash, stale `git-ssh-wrapper` or `agent-git-identity` hash, wrong file caps on `/usr/bin/git` or `git-ssh-wrapper`, pam artifacts, missing `dpkg-divert`, apt hook, or immutable flags. Drift detection shall read `/usr/lib/workspace-guard/deployment-class` only (not infer from CapAmb or pam state). Functional verify shall use `runuser`, not `su -`. The script shall skip re-installation only when **fully healthy**. `make reconcile-guard-host-exec` with `GUARD_FORCE_RECONCILE=1` shall always reconcile.
- **REQ-GGUARD-149**: An uninstall procedure shall be available via `make uninstall-guard` which:
  1. Removes `/usr/bin/git` (the guard)
  2. Restores `/usr/bin/git.original` to `/usr/bin/git` with mode 0755
  3. Restores the dpkg diversion (removes it, returning `/usr/bin/git` to dpkg control)
  4. Removes git-install artifacts (`deployment-class`, `git-ssh-wrapper`, apt hook) but **preserves** host-provision state (`host-provision.ok`, `ssh-keys/`, `agent-git-identity`)
  5. Confirms `git --version` works
- **REQ-GGUARD-150**: The installation script shall configure a `dpkg-divert` for `/usr/bin/git` to prevent the `git` apt package from overwriting the guard binary during `apt install git` or `apt upgrade`. The diversion shall redirect `/usr/bin/git` → `/usr/bin/git.distrib`.
- **REQ-GGUARD-151**: The installation script shall remove the older bash wrapper at `.boot-linux/bin/git` to prevent PATH-based bypass. If `.boot-linux/bin/git` exists, it shall be removed during guard installation.
- **REQ-GGUARD-152**: If the guard detects that `/usr/bin/git` has been replaced (e.g., by a manual override or failed divert), the guard binary shall refuse to `execve()` real git if the inode of `/usr/bin/git` does not match its own. This prevents a scenario where an attacker replaces the capability-enabled guard binary at the filesystem level.
- **REQ-GGUARD-153**: The installation script shall register an apt post-invoke hook (`/etc/apt/apt.conf.d/99workspace-guard`) that detects when the `git` package is installed, upgraded, or removed, and emits a warning directing the user to re-run `make install-guard-host-exec`. The hook shall NOT reinstall the guard on its own; it only warns.
- **REQ-GGUARD-154**: The installation script shall detect and warn about alternative git installations (`snap`, `flatpak`, `nix`, `/usr/local/bin/git`). The user shall be informed that these provide alternate paths to git that bypass the guard. This is informational only: the guard does not attempt to disable them.

### 15A. Root-Only Mode

- **REQ-GGUARD-155**: When built with `--features root-only`, the guard shall skip the `CAP_DAC_OVERRIDE` capability check and instead verify `geteuid() == 0`.
- **REQ-GGUARD-156**: Root-only mode shall print a notice to stderr on every invocation, documenting that it is a soft barrier. The notice shall NOT reveal the bypass mechanism.
- **REQ-GGUARD-157**: Root-only mode shall apply the same 17-rule policy engine, environment sanitization, and audit logging as capability mode.
- **REQ-GGUARD-158**: Root-only mode shall NOT attempt `setcap`, `chattr +i`, or `dpkg-divert` during installation. Root-only installation is explicitly copy + symlink; the bootstrap script does not probe for capability tooling in this mode.

### 16. Rust Project Structure

- **REQ-GGUARD-170**: The privileged Git guard shall reside in the isolated
  standalone package required by REQ-GGUARD-122:
  ```text
  projects/WORKSPACE-GUARD/
  ├── Cargo.toml                    # unrelated tools package/workspace
  └── git-guard/                    # standalone; not a workspace member
      ├── Cargo.toml
      ├── Cargo.lock
      ├── dependency-closure.json
      ├── build.rs
      ├── .cargo/config.toml
      ├── src/
      │   ├── main.rs
      │   ├── linux_ffi.rs
      │   ├── block.rs
      │   ├── exec.rs
      │   ├── args.rs
      │   └── log.rs
      └── tests/
          └── integration_test.rs
  ```
- **REQ-GGUARD-171**: `git-guard/Cargo.toml` shall specify edition `2021`; release
  `panic = "abort"`, `overflow-checks = true`, `opt-level = "z"`, `lto = true`,
  `codegen-units = 1`, and `strip = true`; and development
  `panic = "abort"`, `overflow-checks = true`. Target/linker hardening that Cargo
  profiles cannot express shall live in committed trusted build configuration
  and remain subject to REQ-GGUARD-120 final-ELF verification.
- **REQ-GGUARD-172**: The isolated Git-guard package's direct runtime and build
  dependencies, resolved feature closures, source/checksum identities, and
  forbidden dependency forms shall exactly follow REQ-GGUARD-122. The broader
  workspace may contain dependencies required by other packages, but they shall
  not appear in the Git guard's normal dependency closure or final ELF.
- **REQ-GGUARD-173**: The `Cargo.toml` shall define the following feature flags:
  - `capability-mode` (default): enables `caps` dependency, cap checks
  - `root-only`: skips cap checks, verifies `geteuid() == 0`
  The build shall reject both features together and reject neither feature.

### 17. Guard-Mediated Policy-File Locking (no operator `chattr` cycle)

Motivation (incident 2026-07-28): the `chattr +i` invariant on policy
files is a point-in-time state applied by root-run locking processes
(`install-hooks-recursive`, `workspace-yaml-edit`, one-off scripts).
Any window without the flag (fresh clone, intentional unseal, failed
`git stash pop`) is silently exploitable: root ownership alone does
not protect a file whose parent directory is agent-owned, because
unlink+recreate needs only directory write permission. Git operations
and tampering are the same syscalls; only the actor differs. The
guard is the one trusted channel through which git runs privileged
(cap loan, REQ-GGUARD-15x), so the lock lifecycle belongs inside the
guard, not in operator discipline.

- **REQ-GGUARD-174**: Policy files and their directories shall be
  root-owned: `config/` in guarded repos `root:root 0755`, tracked
  policy files `root:root 0644`. For git-tracked policy files this
  ownership+dir-control REPLACES `chattr +i`; immutability is no
  longer part of the tracked-file invariant.
- **REQ-GGUARD-175**: Git invoked through the guard wrapper shall be
  able to write root-owned worktree paths (pull, merge, checkout,
  switch, restore, rebase, cherry-pick, revert, apply, am, submodule
  update) via the existing capability loan, with NO unseal/reseal
  step and no operator action.
- **REQ-GGUARD-176**: After any mutating porcelain exits, the guard
  shall reconcile the policy manifest (union of WORKSPACE-CI
  `config/exemption_files.yaml` and the repo's `config/*.yaml` policy
  set): re-assert `root:root` and mode `0644` (regular files) via its
  own `cap_chown`/`cap_fowner` (never loaned onward), never following
  symlinks (`AT_SYMLINK_NOFOLLOW`; symlink entries are skipped with a typed
  `reconcile-symlink-skipped` REQ-GGUARD-112 warning). Rationale: git's
  unlink+recreate creates agent-owned
  inodes; reconcile restores the invariant in the same guard
  invocation. Reconcile failure shall exit nonzero with a stderr
  diagnostic but shall NOT roll back the completed git operation.
- **REQ-GGUARD-177**: Fail-closed provenance backstop: `build.rs`
  shall refuse to compile guard policy configs not owned by uid 0,
  and CI consumers shall keep validating uid-0 ownership (already
  deployed for exemption files). A missed reconcile shall halt the
  pipeline, never silently pass.
- **REQ-GGUARD-178**: `chattr +i` shall be retained ONLY for
  `.git/hooks/*` (untracked, auto-executed) and the tier registries
  (`ci/config/project_enforcement.yaml`,
  `workspace/config/project_enforcement.yaml`): paths that never
  change via `git pull`. The guard shall emit a typed
  `reconcile-protected-path-drift` REQ-GGUARD-112 warning
  when reconcile finds these missing root ownership or the immutable
  flag; re-applying `+i` remains a root-run repair action
  (`install-hooks-recursive`), not a guard duty.

---

## Constraints

- **Rust toolchain**: exact repository-pinned toolchain from REQ-GGUARD-120; an
  arbitrary system `rustc` or merely meeting a minimum version is insufficient.
- **Runtime direct dependencies**: isolated-package `libc`, minimal-feature
  `nix`, and mode-optional `caps` only. Build dependencies and their complete
  transitive/proc-macro closure are separately allow-listed under REQ-GGUARD-122.
  No `clap` or argument parsing framework is permitted.
- **Static linking required**: no dynamic fallback or final dynamic dependency.
- **Target**: pinned `x86_64-unknown-linux-musl` static PIE only. Missing target,
  linker, stack-protection support, or verifier is a hard provisioning failure;
  there is no GNU or architecture fallback.
- **No shell, no Python, no interpreter**: the binary is fully self-contained.
- **Binary size target**: under 500KB stripped.
- **Deployment is via `make build-guard` + `make install-guard-host-exec`**: the `make install` flow shall NOT handle git or the git guard.

## Non-Requirements

- **Contract check logic**: the WORKSPACE-CI contract checks remain in shell (`checks_quality.sh`). The guard only invokes them; it does not re-implement them.
- **Pre-commit hook generation**: hook installation is handled by WORKSPACE-CI's `make install-hooks`.
- **Tier/enforcement resolution**: `project_enforcement.yaml` parsing is done by the WORKSPACE-CI shell script, not by the guard binary.
- **Interactive prompts**: the guard never prompts the user. It blocks or allows. User interaction is the responsibility of pre-commit hooks.
- **Network operations**: the guard does not make any network requests. All checks are local.
- **Windows/macOS support**: this binary is Linux-only. SUID has no equivalent on Windows, and macOS has different security semantics.
- **Subcommand aliasing**: the guard does not support git aliases. Aliases are resolved by real git after the guard passes through.
- **Custom block lists**: the destructive command list is hardcoded in the binary, not configurable at runtime. Configuration lives in WORKSPACE-CI's shell-based pre-commit hooks, not in the guard.
