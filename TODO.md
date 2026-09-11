# Implementation TODO

Requirements and specifications are authoritative. These tasks track code,
tests, provisioning, policy, and live-state changes required by approved
requirement decisions.

## REQ-GGUARD-001: Four-Capability Host-Exec Model

- [ ] Remove `CAP_FSETID` from `src/main.rs` required workload capabilities
  and diagnostics.
- [ ] Remove `CAP_FSETID` from `src/exec.rs` inheritable capability setup.
- [ ] Change `GUARD_WORKLOAD_FILE_CAP_STRING` in
  `WORKSPACE-CI/lib/guard-drift.sh` to
  `cap_setpcap,cap_chown,cap_dac_override,cap_fowner=ep`.
- [ ] Update host-exec installer and drift tests for the exact four-capability
  set.
- [ ] Update `scripts/podman/e2e-host-exec.sh` to require the four approved
  capabilities and reject `cap_fsetid`.
- [ ] Update capability fixtures and diagnostics in
  `tests/shell/03-decode-caps.bats`, `tests/shell/13-guard-install-passwd.bats`,
  and `tests/shell/15-guard-host-exec.bats`.
- [ ] Update `config/cap-allowlist.yaml` through the sudo-gated YAML editor to
  allow exactly `cap_setpcap`, `cap_chown`, `cap_dac_override`, and
  `cap_fowner` for `/usr/bin/git`.
- [ ] Rebuild and run the Rust and shell gates.
- [ ] Reconcile the live host through `make install-guard-host-exec` and verify
  that `/usr/bin/git` has exactly the four approved file capabilities.

## REQ-GGUARD-003: Deployment-Class Capability Verification

- [ ] Update the capability arrays and messages to the four-capability model.
- [ ] Add tests proving host-exec requires every approved capability in both
  Effective and Permitted sets.
- [ ] Add a test proving host-exec fails when `NoNewPrivileges=1`.
- [ ] Add tests proving sandbox-service requires every approved capability in
  Ambient and Permitted before promotion to Effective.
- [ ] Add tests proving missing, non-regular, non-root-owned, and unknown
  deployment-class records fail closed.
- [ ] Retain and verify the root-only `geteuid() == 0` gate independently of
  capability mode.

## REQ-GGUARD-004: Privilege-Failure Exit Contract

- [ ] Map missing or incomplete capability sets, untrusted deployment classes,
  host-exec `NoNewPrivileges=1`, ambient-to-effective promotion failure, and
  non-root root-only execution to exit code 3 in `src/main.rs`.
- [ ] Keep exit code 2 reserved for malformed arguments.
- [ ] Replace generic privilege-error handling with a dedicated error variant
  whose process mapping is exit 3.
- [ ] Update capability-mode integration tests to assert exact exit code 3,
  not merely a nonzero status.
- [ ] Add root-only coverage asserting non-root execution exits 3.
- [ ] Verify privilege failure occurs before argument policy evaluation by
  testing a blocked-looking command without the required privilege context.

## REQ-GGUARD-006: Real-Git Verification

- [ ] Change `verify_git_original()` to inspect `/usr/bin/git.original` without
  following symlinks.
- [ ] Require both uid 0 and gid 0.
- [ ] Compare `st_mode & 0o7777` with exactly `0o700` so setuid, setgid, and
  sticky bits are rejected.
- [ ] Retain the device/inode comparison that rejects the running guard as real
  Git, using no-follow metadata consistently.
- [ ] Map every missing, symlink, type, owner, mode, and guard-inode failure to
  exit code 3.
- [ ] Add isolated tests for missing path, symlink, directory, non-root uid,
  non-root gid, each relaxed permission class, every special bit, guard inode,
  and a valid `root:root 0700` regular file.
- [ ] Add an installed-host check proving `/usr/bin/git.original` remains a
  no-capability `root:root 0700` regular file and direct agent execution fails.

## REQ-GGUARD-007: Trusted Contract Runner

- [ ] Replace `format!("{}/{}", wsroot, CONTRACT_SCRIPT)` in `src/exec.rs` with
  the fixed absolute `/opt/workspace-ci/lib/checks_quality.sh` constant.
- [ ] Keep `/bin/bash` as the sole shell executable and pass the contract script
  as `argv[1]`; prohibit `-c`, stdin program text, `source`, and generated code.
- [ ] Call `env_clear()` for the contract child and rebuild its environment from
  the guard's sanitized environment helper plus trusted
  `WORKSPACE_GGUARD_CMD`, `WORKSPACE_GGUARD_REPO_ROOT`, and
  `WORKSPACE_GGUARD_WORKSPACE_ROOT` values.
- [ ] Refactor real-Git and contract-child environment construction to share one
  sanitizer so their bypass-variable policy cannot drift.
- [ ] Preserve deployment integrity verification before spawning the contract
  runner and preserve the configured fail-closed timeout.
- [ ] Add tests asserting the exact executable, argv, fixed script path,
  sanitized environment, timeout behavior, and rejection of caller-supplied
  `WORKSPACE_GGUARD_*` values.
- [ ] Add a regression test proving an absolute `CONTRACT_SCRIPT` is never
  prefixed with the workspace root.
- [ ] Set contract cwd to REQ-GGUARD-063's canonical effective repository root
  and stdin to `/dev/null`; test `-C`, git-dir/work-tree selectors, and hostile
  caller cwd/stdin.
- [ ] Verify `/bin/bash` immediately before spawn under the installed shell-guard
  identity/integrity contract and ensure PATH cannot select a replacement.
- [ ] Verify `/opt/workspace-ci/lib/checks_quality.sh` and its trusted parent
  chain no-follow for expected type, root ownership, non-writability, exact mode,
  immutable state, and deployed content identity immediately before spawn.
- [ ] Ensure the contract child receives no Ambient/effective Git capability
  loan and add a child-side capability assertion.
- [ ] Place the runner in a dedicated process group and on timeout terminate and
  reap the script plus every descendant before returning exit 4.
- [ ] Drain stdout and stderr concurrently during execution with bounded
  per-chunk memory, surface both streams on success and failure without
  truncation or masking, without introducing a pipe deadlock.
- [ ] Preserve typed spawn, pipe, read, wait, signal, timeout, integrity, and
  non-zero-exit diagnostics rather than generic or empty contract failures.
- [ ] Add high-volume stdout/stderr, successful-warning, partial-output timeout,
  forked-descendant timeout, signal death, closed-pipe, malformed output, and
  byte-fidelity tests.
- [ ] Audit every production `Command::new` and exec site in the Git guard:
  require an absolute executable and explicit argv, documenting the contract
  runner as the only shell exception.

## REQ-GGUARD-010: Option Separator Semantics

- [ ] Remove the post-parse global `--hard` scan from `src/args.rs`; it
  incorrectly reclassifies post-separator data as an option.
- [ ] Replace `parse_args_hard_after_separator_blocked` with a pass-through
  assertion.
- [ ] Add pre/post-separator matrix tests for `--hard`, `--no-verify`,
  `--force`, `-f`, `--force-with-lease`, `--amend`, `-D`, and `--delete`.
- [ ] Add tests proving a blocked subcommand remains blocked when followed by
  `--` and pathspecs.
- [ ] Add tests proving argv forwarded to real Git is byte-for-byte unchanged,
  including non-UTF-8 post-separator data.
- [ ] Keep malformed global forms such as `git -- --hard` as pass-through to
  real Git, which remains the syntax authority.

## REQ-GGUARD-011: Operand-Aware Subcommand Discovery

- [ ] Replace first-non-dash subcommand discovery in `src/args.rs` with a
  global-option arity table covering terminal, modifier, and value-taking
  options.
- [ ] Consume separate, attached, and equals-form operands for `-C`, `-c`,
  `--git-dir`, `--work-tree`, `--namespace`, and `--config-env`; support
  repeated `-C`.
- [ ] Treat `-C` only as a directory option and remove it from dangerous-config
  parsing.
- [ ] Make terminal query options leave the invocation without a subcommand and
  pass argv through unchanged.
- [ ] Fail with exit code 2 when an unknown leading option makes operand arity
  and subcommand identification ambiguous.
- [ ] Add bypass regressions for a blocked subcommand following every separate
  value-taking global option, especially `--git-dir <path> reset`,
  `--work-tree <path> reset`, and `--namespace <name> reset`.
- [ ] Add attached/equals-form and repeated-`-C` tests plus terminal-option and
  unknown-option tests.
- [ ] Share the parsed global location options with `repo_location_args()` so
  policy, repository resolution, locking, contract checks, and real Git target
  the same repository.
- [ ] Update dangerous-config tests that currently treat uppercase `-C` as a
  config override.

## REQ-GGUARD-012: Exact Policy-Relevant Subcommands

- [ ] Delete `resolve_subcommand_abbreviation()` and perform exact subcommand
  matching only.
- [ ] Remove `ABBREV_CANDIDATES` and `ABBREV_PREFERRED` generation from
  `build.rs` and the generated guard configuration.
- [ ] Delete abbreviation-expansion tests and add regressions proving names
  such as `reba`, `com`, and `cl` remain unchanged for Git/external-command
  resolution.
- [ ] Extend `config/git_guard_subcommands.schema.yaml` and add `mutating` and
  `capability_loan` categories to `config/git_guard_subcommands.yaml` through
  the sudo-gated YAML editor; remove the separate hardcoded reconciliation
  mutator table.
- [ ] Add build-time checks for category conflicts and matrix coverage for
  every blocked, sudo-gated, partial, contract-check, and mutating command.
- [ ] Add a documented Git-upgrade check that inventories newly introduced
  commands and requires an explicit policy-relevance decision.
- [ ] Verify commands outside configured policy categories follow the finalized
  REQ-GGUARD-013 unknown-subcommand behavior without prefix expansion.

## REQ-GGUARD-013: Capless Unknown Commands

- [ ] Generate a compiled exact-match `capability_loan` set from
  `config/git_guard_subcommands.yaml`.
- [ ] Inventory commands that require access to root-owned repository metadata
  using installed-host tests; include only commands with demonstrated need.
- [ ] Pass an explicit loan decision into `execve_real_git()` rather than
  calling `raise_child_dac_override()` unconditionally.
- [ ] Clear Ambient for every child and raise only `CAP_DAC_OVERRIDE` when the
  exact subcommand is in `capability_loan`.
- [ ] Prove the guard's Effective capability permits `execve()` of root-only
  `git.original` while Ambient empty causes real Git to start capless.
- [ ] Add runtime tests for unknown names, external `git-<name>` helpers,
  aliases, no-subcommand invocations, and terminal query options; assert none
  receive capabilities.
- [ ] Add positive tests for every capability-loan command against root-owned
  repository metadata and assert only `CAP_DAC_OVERRIDE` reaches real Git.
- [ ] Add consistency tests requiring every capability-loan command to have a
  justification and positive installed-runtime case.
- [ ] Update post-fork failure handling so a failed authorized loan exits 3,
  while capless execution performs no loan operation.

## REQ-GGUARD-014: Byte-Exact Argument Conversion

- [ ] Replace the `"<binary-arg>"` fallback in `src/exec.rs` with a propagated
  conversion error mapped to exit code 2.
- [ ] Consolidate the redundant null-byte pre-scan and `CString` construction
  so one fallible byte-preserving conversion owns the invariant.
- [ ] Rename `NullByteInArg` to an internal conversion error that does not imply
  Linux can deliver embedded-null argv.
- [ ] Add tests proving non-UTF-8 arguments survive conversion byte-for-byte.
- [ ] Add a synthetic embedded-null test proving exit 2 and no substituted,
  truncated, or omitted argument.
- [ ] Add an argv forwarding test that compares every child argument byte with
  the original `OsString` input.

## REQ-GGUARD-020: Destructive Command Categories

- [ ] Extend build-time consistency checks so every `blocked` and `sudo_gated`
  command has matrix coverage and every `partial` command has both blocked and
  sanctioned allowed coverage.
- [ ] Add an all-users matrix proving every compiled `blocked` command remains
  blocked for effective UID 0 as well as non-root users.
- [ ] Add sudo-gated coverage for `submodule`, `checkout`, `switch`, and
  `restore`, including unconditional destructive checkout/switch forms that
  remain blocked for root.
- [ ] Add focused `rm` tests proving only `--cached` worktree-preserving forms
  pass and separator/pathspec placement cannot change that classification.
- [ ] Add focused rebase tests proving only `--continue`, `--abort`, and
  `--skip` recovery forms pass while every rebase-start/rewrite form blocks.
- [ ] Audit documentation and diagnostics for hardcoded destructive-command
  lists; runtime decisions and generated messages must use the compiled policy
  categories rather than another list.

## REQ-GGUARD-021: Block Report Delivery

- [ ] Delete lossy space-joined `cmd_str()` and construct one immutable block
  evidence object containing exact `argv[0]` through `argv[argc-1]`, selected
  reason, policy hint, and one timestamp.
- [ ] Format indexed argv, reason, and hint with the same canonical uppercase
  `%HH` encoder used by audit records; add no shell-quoting or second terminal
  escape scheme.
- [ ] Include the policy `reason` in the visible block report, not only the
  audit record.
- [ ] Generate one exact RFC3339 UTC `YYYY-MM-DDTHH:MM:SSZ` timestamp and reuse
  it for stderr, tty, and audit output.
- [ ] After writing stderr, open `/dev/tty` write-only/close-on-exec and compare
  terminal/session identity through safe tty APIs; never use path, inode,
  `st_dev`, or ordinary file identity for the alias-sensitive decision.
- [ ] If stderr is non-terminal, write the controlling tty; if it is proven the
  same terminal, skip the copy; if proven distinct, write both; if stderr is a
  terminal whose identity is indeterminate, retain stderr only and surface the
  identity failure without risking duplicate output.
- [ ] Keep block enforcement and exit code 1 independent from stderr and tty
  open/write failures.
- [ ] Add tests for ordinary interactive delivery without duplication,
  redirected stderr with distinct tty delivery, unavailable tty, tty write
  failure, stderr write failure, both writes failing, `/dev/tty` aliasing the
  same pseudoterminal through different filesystem metadata, and a proven
  distinct terminal.
- [ ] Add formatter tests for spaces, quotes, control bytes, non-UTF-8 argv,
  empty arguments, byte-exact values, reason/hint injection, exact timestamp,
  contiguous argument indexes, one final newline, and visible/audit agreement.

## REQ-GGUARD-030: Command-Specific Destructive Options

- [ ] Replace global token/short-character scanning with command-specific
  option-arity tables that consume operands before recording policy flags.
- [ ] Remove global `--hard` handling; rely on the compiled `reset` subcommand
  block.
- [ ] Treat `-n` as hook bypass only for commands whose Git grammar defines it
  that way; add `git log -n 5` and equivalent allowed controls.
- [ ] Block hook-bypass `--no-verify` across every Git command that supports it,
  with command-specific short aliases and operand-lookalike controls.
- [ ] Block branch `-f`/`--force`; add the missing regression for force-resetting
  an existing branch.
- [ ] Block push `--force-with-lease=<value>` in addition to the bare form.
- [ ] Parse tag and branch message/name operands so values such as `-f`,
  `--force`, and `--no-verify` are not misclassified.
- [ ] Add pre-separator blocked and post-separator allowed matrices for every
  destructive command-option pair.
- [ ] Correct the push remediation hint so it does not recommend
  `--force-with-lease`, which the policy also blocks.
- [ ] Add differential parser tests against the pinned system Git for option
  arity, attached forms, short bundles, and separator behavior.

## REQ-GGUARD-031: Config-Bearing Global Options

- [ ] Replace the generic `expecting_config` boolean with explicit global-option
  parsing for separate `-c`, attached `-c`, and equals-form `--config-env`.
- [ ] Remove uppercase `-C` and nonstandard `--config` forms from config-key
  parsing; `-C` must consume its directory operand under REQ-GGUARD-011.
- [ ] Stop global config-option interpretation after subcommand discovery and
  at the applicable `--` separator.
- [ ] Store only normalized config keys in parser state; never retain values or
  `--config-env` environment-variable names in policy state; retain original
  argv separately as byte-exact diagnostic and audit evidence.
- [ ] Check every repeated override and block when any key matches dangerous or
  non-root sudo-gated policy.
- [ ] Add matrices for separate/attached forms, repeated safe and mixed keys,
  case variants, wildcard patterns, root/non-root sudo-gated keys, malformed
  forms, post-subcommand operands, and post-separator data.
- [ ] Add evidence tests proving values containing credentials, control bytes,
  spaces, and non-UTF-8 data round-trip exactly through reports and audit logs.
- [ ] Differential-test accepted and rejected config-option forms against the
  pinned Git executable so parser grammar cannot drift from Git.

## REQ-GGUARD-040: Dangerous Config-Key Catalog

- [ ] Change `config/git_guard_config_keys.schema.yaml` from scalar pattern
  lists to entries carrying `pattern`, `enforcement`, `threat_class`, and
  `reason`.
- [ ] Migrate `config/git_guard_config_keys.yaml` through the sudo-gated YAML
  editor; do not hand-edit the root-owned policy file.
- [ ] Add reviewed coverage for at least `filter.*.process`, `merge.*.driver`,
  `pager.*`, `interactive.difffilter`, `tar.*.command`, `remote.*.url`,
  `remote.*.pushurl`, `core.worktree`, and `core.attributesfile`.
- [ ] Audit the pinned Git documentation/source for all command-executing,
  hook/alias/filter/merge/pager, credential, transport/protocol,
  repository/worktree, remote-redirection, and integrity-bypass keys.
- [ ] Keep dangerous execution/redirection/integrity patterns unconditional;
  require an explicit operator-use justification for every sudo-gated entry.
- [ ] Update `build.rs` and generated config types for structured policy entries
  while retaining segment-aware case-insensitive matching.
- [ ] Require one blocked positive and one near-match allowed matrix case per
  pattern, including `*` and `**` segment-boundary controls.
- [ ] Add consistency tests rejecting duplicate patterns, unknown threat or
  enforcement classes, empty reasons, overlapping contradictory entries, and
  sudo-gated execution/redirection classes.
- [ ] Add a Git-upgrade inventory check that fails until every newly introduced
  executable or redirecting config key receives a reviewed classification.

## REQ-GGUARD-041: Config-Key Payload Parsing

- [ ] Parse separate and attached `-c` payloads with one shared byte-oriented
  function.
- [ ] Split on the first `=` only and keep every remaining value byte opaque and
  byte-identical.
- [ ] Treat a no-`=` payload as an implicit-true key for both `-c key` and
  `-ckey`; remove the attached-form `=` prerequisite that currently permits
  `-ccore.hooksPath` to evade policy.
- [ ] Replace `from_utf8(...).unwrap_or("")` and Unicode `to_lowercase()` with
  explicit ASCII key validation and ASCII case folding.
- [ ] Map empty, malformed, non-ASCII, and non-UTF-8 config keys to exit code 2
  before subcommand execution.
- [ ] Ensure parser state retains normalized keys only and never config values.
- [ ] Add separate/attached parity tests for dangerous, sudo-gated, safe,
  implicit-true, empty-value, and multi-`=` values.
- [ ] Add regressions for attached `-ccore.hooksPath`, non-UTF-8 wildcard-key
  bypass attempts, mixed-case keys, empty keys, and values containing secrets,
  spaces, control bytes, and additional equals signs.
- [ ] Differential-test implicit-true and malformed forms against the pinned
  Git executable while preserving the guard's stricter fail-closed key rule.

## REQ-GGUARD-042: Allowed Config Passthrough

- [ ] Verify accepted config options execute with their original argv bytes;
  policy-normalized keys must never replace caller arguments.
- [ ] Add passthrough tests for separate and attached `-c`, mixed-case allowed
  keys, empty values, spaces, control bytes, and values containing multiple `=`
  bytes.
- [ ] Assert block reports and audit records contain the blocked key and original
  config value as reversibly escaped byte-exact evidence.
- [ ] Test that allowed config argv remains byte-identical while independently
  blocked inherited environment variables are still removed.

## REQ-GGUARD-050: Unconditional Stash Block

- [ ] Remove unreachable drop/clear-only handling from `src/block.rs`, including
  its unsafe recommendation to use `git stash pop`.
- [ ] Remove `has_stash_drop` and `has_stash_clear` plus their operation scan
  from `ArgState`, parser initialization, and parser/block tests; the compiled
  top-level block makes this state unnecessary.
- [ ] Update the subcommand schema description through the sudo-gated YAML
  editor so it no longer presents stash as a partial-policy example.
- [ ] Give the generic unconditional stash block a specific hint naming the
  sanctioned temporary-worktree and `git diff` snapshot alternatives without
  adding stash-operation parsing.
- [ ] Add matrix cases for bare `stash`, `push`, legacy `save`, `pop`, `apply`,
  `list`, `show`, `drop`, `clear`, an unknown future operation, and an operand
  after `--`.
- [ ] Run every stash matrix case as non-root and root and assert exit 1, no
  execution of real Git, and a report that never recommends another stash
  operation.
- [ ] Add consistency coverage proving `stash` occurs only in the unconditional
  `blocked` category and never in `sudo_gated`, `partial`, capability-loan, or
  reconciliation categories.

## REQ-GGUARD-051: Branch Force Semantics

- [ ] Replace global branch-related booleans with command-specific branch option
  parsing after exact subcommand discovery and before the applicable `--`.
- [ ] Block every actual branch force option, including `-f`, `--force`, `-D`,
  `-M`, `-C`, and short clusters containing force with delete, move, or copy.
- [ ] Recognize delete-plus-force, move-plus-force, and copy-plus-force when the
  options are separate, reordered, clustered, or expressed with equivalent long
  spellings accepted by the pinned Git parser.
- [ ] Stop treating branch `-c` and `-C` as global config options; after
  subcommand discovery they are safe-copy and force-copy options respectively.
- [ ] Preserve safe `-d`, `-m`, and `-c` behavior when force is absent, including
  operands that begin with option-like text after `--`.
- [ ] Add blocked matrix cases for `-D`, attached/clustered `-D`,
  `--delete --force`, `-d -f`, `-fd`, standalone `-f`/`--force`, `-M`, `-C`,
  and separate move/copy-plus-force forms.
- [ ] Add allowed controls for `-d`, `--delete`, `-m`, `--move`, `-c`, `--copy`,
  ordinary branch creation, and post-`--` option-like operands.
- [ ] Differential-test branch option spellings and clusters against the pinned
  Git parser, including its accepted long-option abbreviations.
- [ ] Assert every blocked form exits 1 for root and non-root and every safe form
  reaches real Git with argv unchanged.

## REQ-GGUARD-052: Push Force Semantics

- [ ] Replace literal push-force booleans with command-specific parsing of push
  options, repository operands, refspec operands, and the applicable `--`.
- [ ] Block `-f` in valid short clusters, `--force`, bare
  `--force-with-lease`, every `--force-with-lease=<value>` form, leading-`+`
  refspecs, and `--mirror`.
- [ ] Recognize equivalent long-option spellings accepted by the pinned Git
  parser without treating `--force-if-includes` alone as force.
- [ ] Add unconditional dangerous catalog entries for `remote.*.push` and
  `remote.*.mirror` through the sudo-gated YAML editor; include threat class and
  rationale under REQ-GGUARD-040's structured schema.
- [ ] Before push, inspect effective trusted repository config under the same
  sanitized Git environment and block selected-remote `remote.*.push` values
  with leading-`+` refspecs or `remote.*.mirror=true`.
- [ ] Define fail-closed exit 3 handling for inability to inspect effective
  trusted push configuration; do not execute push on an indeterminate result.
- [ ] Remove the current hint recommending `--force-with-lease`; every force
  block must recommend only an ordinary non-forced push.
- [ ] Add blocked matrix cases for force short clusters, both force flags, empty
  and populated lease values, `+src`, `+src:dst`, `--mirror`, reordered options,
  positional and option-supplied repositories, and config-derived force/mirror
  behavior.
- [ ] Add allowed controls for ordinary refspecs, plus signs not in the force
  marker position, `--force-if-includes` alone, and post-`--` option-like
  operands; add a blocked post-`--` leading-`+` refspec control.
- [ ] Differential-test push option and refspec classification against the
  pinned Git parser, including accepted long-option abbreviations.
- [ ] Assert every force path exits 1 for root and non-root, never contacts a
  remote, and never exposes lease expectations, URLs, or refspec secrets in its
  report.

## REQ-GGUARD-053: Foreground Push Detection

- [ ] Extract `/proc/self/stat` decoding into a small parser that locates the
  final `)` and reads relative indexes 2 (`pgrp`) and 5 (`tpgid`) after `comm`;
  replace the current incorrect `ppid`/`tty_nr` indexes 1 and 4.
- [ ] Return a typed parse failure for missing delimiters, too few fields,
  non-numeric fields, and integer overflow instead of substituting zero or
  silently allowing.
- [ ] Map stat open/read and parse failures to an exit-1 policy block before
  real Git executes; do not emit a non-blocking warning.
- [ ] Allow `tpgid <= 0`, allow positive `tpgid == pgrp`, and block positive
  `tpgid != pgrp` for both root and non-root.
- [ ] Add parser fixtures for foreground, background, no-terminal `-1`, zero,
  process names containing spaces and parentheses, missing final `)`, truncated
  fields, non-numeric values, and signed-integer overflow.
- [ ] Add Linux integration tests that run push decision probes in a foreground
  process group, a background process group, and without a controlling terminal;
  use a fake real-Git target and assert blocked cases never execute it.
- [ ] Remove or update tests and messages that characterize unavailable
  background-push detection as a warning.

## REQ-GGUARD-054: Sudo-Gated Commit Amend

- [ ] Parse amend only within commit's command-specific option grammar before
  the applicable `--`; replace `starts_with("--amend")` prefix matching.
- [ ] Recognize every amend spelling accepted by the pinned Git parser while
  allowing unknown prefixes such as `--amendment` to reach Git's own diagnostic.
- [ ] Keep the decision static: non-root exits 1 and verified root proceeds
  without branch, upstream, ancestry, remote, or network inspection.
- [ ] Ensure an allowed root amendment still runs the normal commit contract
  check and receives no special hook or quality-gate bypass.
- [ ] Add blocked non-root and allowed-root matrix cases for amend with ordinary
  commit options, reordered options, and accepted abbreviations.
- [ ] Add allowed controls for option-like pathspecs after `--`, near-match
  prefixes, ordinary commits, detached HEAD, missing upstream, and stale or
  absent remote-tracking refs.
- [ ] Remove stale amend ancestry/timeout test fixtures and subprocess mocks;
  assert no ancestry subprocess is launched for either policy decision.
- [ ] Keep top-level `REQUIREMENTS.md`, detailed requirements, README, policy
  matrix, implementation specification, and operator guidance consistent on the
  non-root-denied/root-allowed rule.

## REQ-GGUARD-055: Allow Forward-Only Revert

- [ ] Remove the revert target/branch/ancestry block from `src/block.rs`; no
  remote-tracking state shall affect whether revert executes.
- [ ] Remove `extract_revert_target` and remove `run_git` if the ancestry block
  is its final caller.
- [ ] Remove `revert` from the compiled `partial` subcommand category through
  the sudo-gated YAML editor while retaining its mutating/reconciliation and
  required capability classifications.
- [ ] Remove stale revert verification/ancestry subprocess mocks, timeout paths,
  messages, and tests.
- [ ] Add allowed passthrough cases for one target, multiple targets, ranges,
  `--stdin`, `--no-commit`, and `--continue`, `--abort`, `--quit`, and `--skip`.
- [ ] Assert allowed revert argv is byte-identical, normal hooks remain enabled,
  inherited environment sanitization still applies, and successful mutation
  triggers ownership reconciliation.
- [ ] Add consistency coverage proving revert has no partial-policy handler or
  decision subprocess but remains in every required mutation/capability table.

## REQ-GGUARD-060: Protected Branch Catalog

- [ ] Replace Unicode `to_lowercase()` in protected-branch classification with
  explicit ASCII validation/folding consistent with the compiled policy.
- [ ] Extend `build.rs` validation to reject empty, non-ASCII,
  non-canonical-lowercase, and case-insensitive duplicate exact/prefix entries.
- [ ] Validate exact entries as Git branch names and prefix entries as branch
  namespaces ending in `/`, without invoking an external Git process at build
  time.
- [ ] Add generated-catalog tests covering every exact entry and prefix from the
  authoritative YAML for both root and non-root.
- [ ] Add mixed-case controls proving the deliberate ASCII-insensitive policy,
  plus prefix-boundary and near-match controls that do not overmatch unrelated
  branch names.
- [ ] Add schema/catalog consistency tests proving the policy and schema describe
  the same ASCII matching and trailing-slash prefix contract.
- [ ] Add documentation consistency checks preventing requirements or specs from
  reintroducing a partial hard-coded protected-branch list.

## REQ-GGUARD-061: Protected Pull Effective Mode

- [ ] Replace monotonic `safe_pull_flag` and global `starts_with` checks with a
  command-specific ordered pull option state parsed after subcommand discovery.
- [ ] Track final fast-forward mode so later `--ff` or `--no-ff` overrides an
  earlier `--ff-only`, and a later `--ff-only` restores safe mode.
- [ ] Track final rebase mode so `-r`, `--rebase`, and pinned-Git-supported
  non-false values enable it while `--rebase=false` and `--no-rebase` disable it.
- [ ] Allow a catalog-protected pull only when either final effective mode is
  safe; keep the rule identical for root and non-root.
- [ ] Consume pull option values, short clusters, accepted long abbreviations,
  repository/refspec operands, and `--` according to the pinned Git grammar.
- [ ] Keep safe-mode selection explicit in argv; add tests proving
  `pull.ff=only` or `pull.rebase=true` configuration alone does not satisfy the
  policy.
- [ ] Add ordered blocked cases for `--rebase --no-rebase`,
  `--ff-only --no-ff`, `--ff-only --ff`, `--rebase=false`, no safe option, and
  safe-looking option values or post-`--` operands.
- [ ] Add ordered allowed cases for `--ff-only`, `-r`, `--rebase`, every
  supported non-false rebase value, safe options after earlier negations, and
  combinations where either final mode remains safe.
- [ ] Add malformed near-match controls such as `--rebase-other` and
  `--ff-only-other` that receive Git's diagnostic rather than setting policy
  state.
- [ ] Differential-test ordered pull option handling against the pinned Git
  parser and assert blocked forms never invoke real Git.

## REQ-GGUARD-062: Protected Merge Effective Mode

- [ ] Replace `has_ff_only` and `has_merge_abort` token scans with one
  command-specific ordered merge parser after exact subcommand discovery.
- [ ] Track final FF mode so later `--ff` or `--no-ff` overrides an earlier
  `--ff-only`, and a later `--ff-only` restores safe mode.
- [ ] Recognize actual `--abort` and `--quit` recovery modes as non-root safe;
  keep `--continue` and ordinary non-FF-only merges restricted to verified root.
- [ ] Consume merge value-taking options before policy classification so
  `-m --ff-only`, `-m --abort`, strategy values, and strategy-option values
  cannot create safety state.
- [ ] Parse accepted long abbreviations, option ordering, merge heads, and the
  applicable `--` according to the pinned Git grammar.
- [ ] Keep FF-only selection explicit in argv; add tests proving
  `merge.ff=only` configuration alone does not authorize a non-root merge.
- [ ] Add blocked non-root cases for no safe mode, `--ff-only --ff`,
  `--ff-only --no-ff`, `--continue`, safe-looking option values, and
  post-separator option-like operands.
- [ ] Add allowed non-root cases for exact/abbreviated `--ff-only`, safe mode
  after earlier overrides, `--abort`, and `--quit`; run corresponding ordinary
  merge cases through the verified-root path.
- [ ] Add malformed near-match controls that reach Git's own diagnostic without
  setting policy state.
- [ ] Differential-test merge parsing against pinned Git and assert every
  blocked case exits 1 without invoking real Git.

## REQ-GGUARD-063: Effective Repository Branch Discovery

- [ ] Move effective repository resolution before protected-branch policy and
  reuse its result for branch checks, locking, sealing, execution, and
  reconciliation instead of resolving different contexts.
- [ ] Replace `Option<PathBuf>` repository resolution with a typed result that
  distinguishes resolved repository, proven no-repository, timeout, malformed
  output, and operational failure.
- [ ] Apply every validated repository selector (`-C`, `--git-dir`,
  `--work-tree`, `--namespace`, and any other pinned-Git selector) identically to
  repository resolution, branch discovery, and final execution.
- [ ] In a resolved repository, run verified real Git with fixed
  `symbolic-ref --quiet HEAD` argv, sanitized environment, and only the minimum
  capability loan required to read protected repository metadata.
- [ ] Implement a real two-second timeout that kills and reaps each discovery
  helper; never leave a helper running after a policy decision.
- [ ] Parse symbolic-ref output as bytes, require `refs/heads/<name>` and exactly
  one line terminator, and pass the branch-name bytes to ASCII catalog matching
  without lossy conversion.
- [ ] Represent branch discovery as typed branch, detached, no-repository, or
  failure states; skip only detached and no-repository and map every resolver or
  known-repository failure to exit 1 before requested Git execution.
- [ ] Add integration cases for cwd repositories, repeated `-C`, separate and
  equals-form git/work-tree selectors, namespaces, linked worktrees, bare repos,
  unborn protected branches, detached HEAD, and no repository.
- [ ] Add failure cases for wrong-repository selection, helper spawn/exec error,
  timeout, signal death, malformed/truncated output, unexpected ref
  namespace, and repository disappearance between resolution and discovery.
- [ ] Assert pull and non-root merge consume one shared branch result and that
  blocked discovery failures never execute the requested command.

## REQ-GGUARD-070: Child Environment Allow-List

- [ ] Replace inherited-environment collection in `src/exec.rs` with one shared
  sanitizer that starts empty and consults the compiled environment catalog.
- [ ] Migrate `config/git_guard_environment.schema.yaml` and its policy through
  the sudo-gated YAML editor to structured allowed exact/prefix, root-only,
  blocked-bypass, config-value-carrier, and guard-owned exact/prefix categories.
- [ ] Remove every caller-supplied guard-owned exact name and family before
  injecting canonical `GIT_CONFIG_*`, safe-directory, identity, and SSH-wrapper
  values exactly once.
- [ ] Replace `is_sudo()`/`AT_SECURE` editor and identity gating with effective
  UID zero authorization; drop them for non-root with byte-exact evidence warnings.
- [ ] Reserve a non-Git-interpreted carrier namespace for `--config-env`, admit a
  carrier only when referenced by validated argv, and report removed/blocked
  carrier values as reversible evidence.
- [ ] Route repository/branch helpers, contract execution, other policy helpers,
  and final Git through the same base sanitizer with explicit fixed additions.
- [ ] Preserve admitted non-UTF-8 values byte-exactly, emit each admitted name at
  most once, and reject/drop non-ASCII or malformed names without lossy matching.
- [ ] Add build-time consistency checks for duplicate names, category overlap,
  unsafe prefixes, and allow entries intersecting Git, loader, shell, pager,
  editor, credential, object-store, repository, or config-injection controls.
- [ ] Add adversarial execution tests for inherited `GIT_EXEC_PATH`, template,
  askpass, pager/diff, repository/index/object-store, `GIT_CONFIG_*`, `LD_*`,
  glibc, shell-startup, credential, editor, and identity variables as root and
  non-root.
- [ ] Assert unknown variables are absent, approved exact/prefix values survive
  byte-identically, root-only values survive only for effective root, canonical
  guard values cannot be shadowed, and every filtered name/value emits one typed
  byte-exact `filtered-environment` warning.

## REQ-GGUARD-071: Hook-Bypass Environment Attempts

- [ ] Replace `std::env::var` bypass checks with one byte-oriented inherited-
  environment scan shared with REQ-GGUARD-070's sanitizer.
- [ ] Block every cataloged bypass name whose value is non-empty, including
  non-UTF-8 values, for root and non-root before any policy helper starts.
- [ ] Treat an empty value as inactive, omit it from every helper and final-Git
  child environment, and emit an `empty-hook-bypass-environment` warning whose
  second field explicitly encodes the empty value.
- [ ] Ensure block reports and audit records contain the cataloged variable name
  and exact value under reversible escaping, never a lossy rendering.
- [ ] Add generated tests for every `blocked_bypass` catalog entry with non-empty
  UTF-8, empty, and non-UTF-8 values, including root/non-root decisions.
- [ ] Use fake helper and real-Git targets to prove blocked attempts launch no
  child, while empty-value controls proceed with the variable absent.
- [ ] Add catalog consistency checks requiring unique valid ASCII names and one
  blocked/empty/root/evidence matrix family per entry.
- [ ] Add a pinned pre-commit upgrade inventory check requiring classification
  of newly introduced environment-based hook/config bypass controls.

## REQ-GGUARD-072: Preserve Caller PATH

- [ ] Add `PATH` to the allowed-exact category when migrating
  `config/git_guard_environment.yaml` through the sudo-gated YAML editor.
- [ ] Remove the child PATH reset value from `config/shared_paths.yaml` and its
  schema through the sudo-gated YAML editor once no runtime consumer remains.
- [ ] Preserve present PATH values byte-identically, including empty and
  non-UTF-8 values, and preserve absence without injecting a default.
- [ ] Inventory every Git guard child process and convert any guard-owned
  executable lookup to a fixed absolute path with its required identity and
  integrity verification.
- [ ] Keep caller-visible command resolution inside Git, hooks, external
  `git-*` helpers, and the trusted contract script on the preserved PATH.
- [ ] Add root/non-root execution tests for ordinary, empty, absent, long, and
  non-UTF-8 PATH values using a fake real-Git child that records raw env bytes.
- [ ] Add integration tests proving workspace tools, toolchain shims, hook
  dependencies, and external Git helpers remain discoverable from caller PATH.
- [ ] Add adversarial tests proving PATH entries cannot replace real Git, the
  contract shell/script, SSH wrapper, or policy-helper executables.
- [ ] Remove stale PATH-reset constants, tests, threat mappings, and documentation
  after all callers use the shared preservation sanitizer.

## REQ-GGUARD-073: Preserve Identity and Locale Environment

- [ ] During the sudo-gated environment-policy migration, keep exact `HOME`,
  `USER`, `LANG`, and `LANGUAGE`, replace enumerated LC categories with allowed
  prefix `LC_`, and keep `LOCPATH`/`NLSPATH` excluded.
- [ ] Preserve present, empty, non-UTF-8, and long values byte-identically and
  preserve absence for every exact name and representative `LC_*` names.
- [ ] Route repository/branch helpers, contract execution, SSH setup helpers,
  and final Git through the same preserved base identity/locale environment.
- [ ] Audit every read of `HOME` and `USER` in Git guard code; replace any use as
  authority with real/effective UID, GID, and `User::from_uid` as appropriate.
- [ ] Assert spoofed HOME/USER cannot redirect block/audit logs, root-locked Git
  identity, provisioned SSH keys, trusted policy/config paths, workspace
  authority, or ownership reconciliation.
- [ ] Add catalog validation proving `LC_` is the only approved broad locale
  prefix and does not overlap excluded loader/catalog path variables.
- [ ] Add raw-env root/non-root tests for all exact names, uncommon locale
  categories such as `LC_PAPER` and `LC_TELEPHONE`, arbitrary future `LC_*`, and
  excluded `LOCPATH`/`NLSPATH` controls.
- [ ] Add cross-child consistency tests proving helpers and final Git observe the
  same approved value bytes; assert no guard output only when no explicit
  diagnostic or filtering condition exists.

## REQ-GGUARD-074: Untrusted Environment Snapshot

- [ ] Capture one immutable inherited-environment snapshot at process startup as
  raw name/value bytes and pass it to bypass detection, sanitization, helpers,
  contract execution, and final Git instead of rereading process globals.
- [ ] Do not add `secure_getenv()` or a new unsafe FFI site; document with tests
  that `AT_SECURE` would hide values required by REQ-GGUARD-070 through 073.
- [ ] Audit every environment read in Git guard modules and classify it as
  preserved data, bypass input, config carrier, effective-root-only input,
  guard-owned replacement, or guard diagnostic; remove all unclassified reads.
- [ ] Add a structured guard-diagnostic category to the environment schema and
  migrate `WORKSPACE_GUARD_TRACE` through the sudo-gated YAML editor.
- [ ] Consume trace input without forwarding it; preserve explicit trace stderr
  for root and non-root while proving phase output contains no argv, environment
  values, credentials, paths, or policy secrets.
- [ ] Replace helper `.ok()?`, null-stderr, generic-status, and fallback paths
  that swallow diagnostics with typed outcomes carrying spawn, timeout, signal,
  malformed-output, stderr, and exit-status information.
- [ ] Forward or report helper stderr on success and failure with bounded
  reversible escaping; never mask or discard it solely because it belongs to an
  internal policy helper.
- [ ] Update REQ-GGUARD-113 tests: ordinary success remains transparent, while
  requested trace, filtering warnings, helper diagnostics, validation/errors,
  contract output, and block reports are all observable.
- [ ] Add regression tests proving environment values cannot select trusted
  executable/policy paths, identity/home, capabilities, integrity expectations,
  repository classification, or policy decisions.

## REQ-GGUARD-080: Exact Contract Command Scope

- [ ] Remove `cherry-pick`, `apply`, and `am` from
  `config/git_guard_subcommands.yaml` `contract_check` through the sudo-gated
  YAML editor, leaving exactly `commit` and `push`.
- [ ] Update the subcommand schema description through the sudo-gated YAML
  editor to state that contract membership mirrors the trusted runner's explicit
  command protocol rather than providing an extensible example list.
- [ ] Add build-time consistency checks requiring exact `commit`/`push`
  membership and rejecting undocumented contract command values.
- [ ] Assert root and non-root each invoke the contract exactly once for exact
  `commit` and `push`, after static/repository checks and before capability loan
  or requested Git execution.
- [ ] Add no-runner controls for `cherry-pick`, `apply`, `am`, their recovery
  forms, similarly named commands, aliases, external helpers, and unrelated Git
  commands.
- [ ] Verify native hooks and ownership reconciliation remain active for
  `cherry-pick` and `am`, and verify their resulting history is rejected at push
  when the contract fails.
- [ ] Refactor contract-child capture so stderr is drained without deadlock and
  surfaced on both success and failure; successful warnings must not be
  swallowed.
- [ ] Add ordering/fake-runner tests proving a static block launches no contract,
  contract failure launches no requested Git, and success launches requested Git
  only after the single runner exits successfully.
- [ ] Add documentation/constant consistency tests restricting
  `WORKSPACE_GGUARD_CMD` to `commit|push` across requirements, generated policy,
  runner argv validation, and test fixtures.

## REQ-GGUARD-081: Trusted Workspace Root Registry

- [ ] Add `/etc/workspace-guard/workspace-roots` to provisioning/deployment
  specifications with a root-owned non-group/other-writable parent chain and a
  no-follow regular-file `root:root`, exact `0644`, immutable-file contract.
- [ ] Add sudo-gated provisioning that atomically writes canonical absolute
  workspace roots, verifies the installed inode/metadata/content, and rejects
  relative, duplicate, non-canonical, or malformed entries.
- [ ] Replace `WORKSPACE_MARKERS` ancestor authority and `WorkspaceRoot::Full /
  Partial` classification with a typed verified-registry result.
- [ ] Reuse REQ-GGUARD-063's single effective repository identity and compare it
  to registered roots component-wise as Unix path bytes; never use
  `to_string_lossy()` or textual `starts_with` for containment.
- [ ] Select the longest matching registered ancestor when explicit roots overlap
  and add consistency validation for duplicates and ambiguous equal bindings.
- [ ] Map missing/unreadable registry, parent/type/owner/mode/immutable drift,
  malformed content, replacement, and canonicalization failures to a surfaced
  fail-closed result before contract-eligible Git execution.
- [ ] Remove workspace-marker existence from contract scope decisions in
  `src/wsroot.rs`, `src/exec.rs`, locking, and reconciliation; retain marker
  checks only if they produce non-authoritative, non-swallowed drift diagnostics.
- [ ] Add root/non-root tests for exact roots, descendants, outside roots,
  lexical-prefix near matches, nested registered roots, non-UTF-8 components,
  symlink entry/escape, and repository movement during classification.
- [ ] Add adversarial tests proving creation, deletion, replacement, wrong type,
  and symlinking of every legacy marker cannot add, remove, or redirect contract
  scope.
- [ ] Add registry attack tests for symlink registry paths, inode replacement,
  ownership/mode/immutable drift, truncation, duplicates, invalid bytes, relative
  paths, and TOCTOU between verification and read.
- [ ] Remove `workspace_markers` from `config/shared_paths.yaml` and its schema
  through the sudo-gated YAML editor after all authority consumers are removed.

## REQ-GGUARD-082: Outside-Workspace Contract Scope

- [ ] Remove remote inspection from outside-workspace `commit`; allow it without
  the contract while retaining hooks, environment policy, and reconciliation.
- [ ] Add a root-owned structured protected-remote catalog and schema through the
  sudo-gated YAML editor with canonical host and repository path/namespace rules,
  rationale, and positive/near-match cases.
- [ ] Replace `repo_targets_provisioned_host()` and hostname-only string parsing
  with a byte-safe typed effective-push-destination resolver.
- [ ] Reuse REQ-GGUARD-052's command-specific push parser to distinguish explicit
  URL/repository operands from named remotes and option values.
- [ ] Resolve named, omitted/default, and push-specific remotes through verified
  real Git under the same sanitized config/environment and effective repository
  context used by final push; include effective URL rewrite behavior.
- [ ] Return typed unrelated, protected, absent, ambiguous, malformed, timeout,
  helper-failure, and unsupported-transport outcomes; only proven unrelated may
  skip outside-workspace contract enforcement.
- [ ] Block protected and every indeterminate outside destination with exit 4,
  launch no requested Git, and surface byte-exact reversibly escaped helper diagnostics.
- [ ] Reuse one destination result for contract scope, force/default inspection,
  SSH policy, capability policy, and final push instead of resolving mutable
  config repeatedly.
- [ ] Remove H4 remote-host checks from git-dir locking and reconciliation where
  they currently make mutable remote config filesystem-scope authority.
- [ ] Add explicit URL, named remote, `pushurl`, default remote,
  `remote.pushDefault`, branch remote, rewrite, reordered-option, and post-`--`
  tests against protected and unrelated destinations.
- [ ] Add bypass cases for deleted/changed remotes, explicit protected URLs,
  helper errors, non-UTF-8/malformed output, same-host near-match repositories,
  deceptive usernames/paths, URL encoding, ports, IPv4/IPv6, and supported
  transport variants.
- [ ] Assert outside commits never invoke destination helpers, outside unrelated
  pushes skip the contract, and inside-workspace commit/push behavior remains
  governed by REQ-GGUARD-080.

## REQ-GGUARD-084: Trusted Contract Bindings

- [ ] Add `WORKSPACE_GGUARD_*` and legacy `AMI_GGUARD_*` to the guard-owned
  environment-prefix policy through the sudo-gated YAML editor so every caller
  entry is removed and reported with its exact value as evidence.
- [ ] Delete legacy `AMI_GGUARD_*` terminology from top-level requirements,
  generated constants, fixtures, scripts, and deployment checks; add no
  compatibility aliases.
- [ ] Construct exactly one `WORKSPACE_GGUARD_CMD` from the compiled exact
  `commit|push` category and reject every other internal command value.
- [ ] Carry repository and selected workspace roots as `PathBuf`/`OsString`
  identities from REQ-GGUARD-063/081 into cwd, policy, and bindings without
  `String`, `to_string_lossy()`, or re-resolution.
- [ ] Insert exactly one repo/workspace binding after sanitization and fail exit
  4 on missing, duplicate, embedded-NUL, or cross-component identity mismatch.
- [ ] Update the trusted `/opt/workspace-ci/lib/checks_quality.sh` contract to
  quote all three variables and treat their contents only as data.
- [ ] Add fake-runner raw-environment tests for caller spoofing, duplicate input,
  exact output names/count, absent legacy names, and agreement between cwd,
  repository identity, registry selection, and binding bytes.
- [ ] Add deployment tests for spaces, newlines, leading hyphens, long paths, and
  non-UTF-8 path bytes without argument splitting, command interpretation,
  truncation, lossy output, or swallowed diagnostics.

## REQ-GGUARD-085: Contract Failure and Output Semantics

- [ ] Replace `GuardError::ContractFailed(String)` output embedding with a typed
  runner outcome carrying passed, rejected code, signal, timeout, spawn,
  output-I/O, wait, and integrity states.
- [ ] Map every outcome except `Passed` to guard exit 4 and prove requested real
  Git is never launched on any failure path.
- [ ] Stream stdout and stderr as bytes exactly once during execution, preserving
  non-UTF-8 data and per-stream order without `read_to_string`, lossy conversion,
  post-exit-only reads, duplication, or truncation.
- [ ] Preserve all stream bytes across chunk boundaries with bounded per-chunk
  memory; test evidence split at every possible boundary.
- [ ] Remove ignored pipe/read/write/wait errors and ambiguous `StillAlive`
  fallback handling; every error must produce a typed outcome and complete child
  process-group cleanup.
- [ ] After failure, emit one concise status summary with child code/signal or
  failure class but no duplicated stream content; all values remain evidence.
- [ ] Route the summary through stderr, distinct `/dev/tty`, and audit delivery;
  keep separately streamed script bytes out of the summary record to avoid
  duplication, not to hide evidence.
- [ ] Add fake-runner cases for exits 0, 1, 2, 4, 125, and 255; success with
  stderr; mixed/high-volume stdout/stderr; non-UTF-8 bytes; and output exceeding
  pipe capacity.
- [ ] Add signal, timeout with partial output, spawn, closed-pipe, output read/
  write, wait, and integrity failure tests, including descendant cleanup.
- [ ] Add suppression tests proving the concise failure summary reaches a
  distinct tty when stderr is redirected while script output is emitted once and
  audit data remains byte-exact and reversible.

## REQ-GGUARD-086: Contract Deployment Unavailable

- [ ] Replace `Path::exists()` and workspace-prefixed checks with the fixed
  REQ-GGUARD-083 no-follow verifier and typed unavailable-deployment outcomes.
- [ ] Invoke deployment verification only after exact command, workspace, and
  protected-destination policy determines that a contract is required.
- [ ] Map missing `/opt/workspace-ci`, missing script/bash, wrong type/owner/group/
  mode, writable parent, missing immutable state, content mismatch, permission/
  inspection error, inode replacement, and pre-spawn race to exit 4.
- [ ] Preserve each failure class, fixed path, and inspected evidence in a concise
  reversibly escaped stderr/distinct-tty/audit report.
- [ ] Assert root and non-root receive identical failure decisions and requested
  real Git is never executed.
- [ ] Add fake workspace-source scripts, alternate PATH runners, symlinks, and
  caller path overrides proving no fallback or alternate runner is selected.
- [ ] Add tests proving the guard performs no repair, install, chmod/chown,
  immutable mutation, package-manager action, or network retrieval on failure.
- [ ] Add out-of-scope commit/push and unrelated-command controls proving runner
  deployment is not probed when no contract is required.

## REQ-GGUARD-090: Root-Owned Git Audit Logs

- [ ] Remove all Git guard writes to `${HOME}/.workspace-guard.log`; do not retain
  a user-home audit or convenience mirror.
- [ ] Provision `/var/log/workspace-guard` as `root:root` exact `0750` with a
  trusted root-owned non-group/other-writable parent chain; replace the insecure
  top-level `1777` contract and tests.
- [ ] Replace `LOG_FILE=.workspace-guard.log` in shared path policy/schema through
  the sudo-gated YAML editor with the fixed audit directory contract, or delete
  the setting if the absolute path is a code-level security constant.
- [ ] Derive `git-<uid>.log` only from kernel real UID and open it relative to a
  verified directory fd with no-follow/create/append/close-on-exec semantics.
- [ ] On creation, set `root:root` exact `0600` before accepting a record; on
  every append verify regular type, owner/group, exact mode, no special bits,
  link count, and opened inode identity.
- [ ] Build each reversibly escaped audit record fully in memory, take an exclusive
  file lock, append it without interleaving, sync it, and check lock/write/sync/
  unlock/close outcomes.
- [ ] Route every exit-1 policy block and exit-4 contract rejection/unavailable
  outcome through one audit API; remove direct stderr-only denial exits.
- [ ] Surface every audit open/verification/lock/write/sync/close failure through
  stderr and distinct tty while preserving the original denial and exit class.
- [ ] Remove `get_user_home`, environment HOME/USER dependence, and lossy cwd/
  argv conversion from Git auditing; reuse the byte-safe evidence formatter.
- [ ] Add adversarial tests for user-home files/symlinks, central directory/file
  symlinks, hard links, wrong owner/group/mode/type/link count, replacement,
  concurrent writers, partial writes, disk-full, lock/sync/close errors, and
  non-UTF-8/newline/pipe/control-byte fields.
- [ ] Assert agents cannot create, replace, truncate, delete, chmod, chown, or
  forge authoritative records, and that no Git audit artifact appears anywhere
  under a user-writable directory.
- [ ] Migrate shell-guard auditing from HOME to verified root-owned
  `/var/log/workspace-guard/shell-<uid>.log` with the same secure append helper;
  remove every user-writable shell audit path and mirror.
- [ ] Migrate YAML-editor auditing from HOME to verified root-owned
  `/var/log/workspace-guard/yaml-edit-<uid>.log`; remove `LOG_FILE_NAME`, passwd-
  home path construction, and every user-writable YAML audit path or mirror.
- [ ] Add repository-wide consistency tests rejecting audit-log paths beneath
  HOME, `/tmp`, workspace roots, or any other user-writable directory and
  rejecting world/group-writable audit-directory modes.

## REQ-GGUARD-091: Canonical Audit Record Encoding

- [ ] Replace raw formatted log strings with one shared byte-oriented v1 audit
  record type and encoder used by Git block, contract, warning, and audit-failure
  paths.
- [ ] Emit fixed-order `v`, `ts`, `event`, `exit`, `uid`, `cwd`, `argc`, indexed
  argv, and `reason` fields with exactly one final newline.
- [ ] Implement canonical uppercase `%HH` encoding for every byte outside the
  approved unreserved ASCII set, always including `%`, `|`, `=`, spaces, CR/LF,
  controls, and bytes `>=0x7f`.
- [ ] Encode raw argv/reason bytes without redaction and prove decoding
  reconstructs every original value and argument boundary exactly.
- [ ] Remove `cmd_str` space joining and all `to_string_lossy()` conversions from
  audit construction; preserve empty and non-UTF-8 arguments with `argc` and
  contiguous indexed fields.
- [ ] Implement a strict v1 parser for tests/operator tooling that rejects bad or
  non-canonical escapes, unsupported versions, duplicate/missing/reordered fields,
  unknown event classes, invalid decimals/timestamps, `argc` mismatch, and extra
  record newlines.
- [ ] Build the complete encoded record before taking the REQ-GGUARD-090 file
  lock and append it as one logical record without truncation or interleaving.
- [ ] Add event coverage for block, contract rejection, contract unavailable,
  warning, and audit failure; ensure audit-failure reporting never recursively
  invokes the audit writer.
- [ ] Add round-trip tests for every byte `0x01..0xff` except NUL, delimiters,
  empty/repeated arguments, embedded CR/LF, large argv, inline-token evidence,
  exit 1/4, and
  concurrent writers.
- [ ] Add golden records and schema-consistency tests shared by documentation,
  parser, encoder, audit readers, and deployment diagnostics.
- [ ] Migrate shell-guard records to the same v1 encoder, remove its 200-byte
  truncation/space-joined command format, and share golden/parser tests.

## REQ-GGUARD-092: Audit Append Failure Semantics

- [ ] Refactor the audit writer to return `Result<(), AuditError>` with distinct
  parent, open/create, metadata, lock, encode, write, sync, unlock, and close
  stages plus OS status where available; it must not call `process::exit`.
- [ ] Keep policy/contract outcome ownership in the main denial dispatcher so an
  audit failure preserves exit 1 versus exit 4 and never launches requested Git.
- [ ] Emit exactly one non-recursive reversibly escaped audit-failure diagnostic to
  stderr and distinct tty containing fixed path, stage/status, and confirmation
  that the denial remains enforced.
- [ ] Remove ignored audit/tty `Result`s and never claim persistence until the
  complete canonical record append and sync have succeeded.
- [ ] Retry only safely interruptible syscalls; reject metadata/inode drift and
  other integrity failures without retry or path switching.
- [ ] Prohibit and test every fallback to HOME, `/tmp`, workspace, caller paths,
  world-writable files, syslog/other unverified loggers, or alternate filenames.
- [ ] Treat `event=audit-failure` as persistable only through a separate already-
  verified authoritative sink; otherwise test it solely as a delivered
  diagnostic and prevent recursive writer calls.
- [ ] Add fault injection for every stage, including symlink/wrong inode,
  permissions, lock contention/failure, short/partial write, `ENOSPC`, sync,
  unlock, close, directory drift, and concurrent replacement.
- [ ] Assert each injected failure preserves the original report and exit code,
  emits the failure diagnostic despite stderr redirection via distinct tty,
  executes no Git, and creates no artifact under any user-writable directory.
- [ ] Reuse the same typed non-recursive audit failure API in shell guard and
  YAML editor, preserving each tool's original block/mutation outcome and
  prohibiting alternate sinks.

## REQ-GGUARD-093: Complete Forensic Evidence

- [ ] Remove Git and shell masking/redaction from block reports, tty output,
  helper/contract streams, filtering diagnostics, reasons/hints, and audit
  records; do not omit, hash, or truncate caller-controlled bytes.
- [ ] Keep terminal escaping and audit `%HH` encoding fully reversible and add
  decode tests proving exact recovery of original argv, values, output, and
  argument boundaries.
- [ ] Replace `sanitize_cmd` assignment masking and every redaction-specific unit
  or Bats expectation with complete-evidence assertions.
- [ ] Add inline-token/PAT, authorization-header, config-value, URL-userinfo,
  environment-carrier, control-byte, and non-UTF-8 fixtures and assert the exact
  bytes survive in all required evidence destinations.
- [ ] Document and test the operating rule that inline credentials are prohibited
  agent behavior and sanctioned secret-store paths are mandatory; do not mask a
  violation after it occurs.
- [ ] Add repository-wide consistency checks rejecting normative redaction,
  masking, hashing, omission, or truncation of guard evidence.

## REQ-GGUARD-100: Real Git Outcome Propagation

- [ ] Refactor child supervision to return a typed Git outcome (`Exited(code)` or
  `Signaled(signal)`) separately from fork, capability-loan, exec, and wait
  failures.
- [ ] Propagate every normal Git exit code exactly, including 0, 1, 2, 4, 74,
  125, and 255, after required relock/reconciliation.
- [ ] After relock/reconciliation, restore/default and re-raise Git's terminating
  signal so the guard remains `WIFSIGNALED`; use a surfaced typed failure only if
  signal propagation itself cannot be completed.
- [ ] Change child capability-loan failure from synthetic exit 2 to the privilege/
  capability exit class 3 and retain its distinct diagnostic.
- [ ] Map fork, exec, and every unexpected/error `waitpid` outcome to typed guard
  failures rather than `GitOriginalMissing`, policy exit 1, or an arbitrary Git
  code.
- [ ] Keep the documented reconcile/invariant override at `EX_IOERR` 74 and
  report both the original Git outcome and that the Git operation already
  stands.
- [ ] Assert ordinary non-zero Git and signal outcomes do not create block or
  contract audit records and do not add guard output beyond explicit diagnostics.
- [ ] Add fake-Git integration cases for normal exits, each catchable signal,
  core-dump signal status, fork/exec/loan/wait failures, and reconcile success/
  failure after both normal and signaled child outcomes.
- [ ] Verify Git stdout/stderr bytes, including non-UTF-8 and high-volume output,
  pass through unchanged for every normal Git outcome.

## REQ-GGUARD-101: Policy-Denial Exit Class

- [ ] Rename/refactor `GuardError::Blocked` into a typed `PolicyDenied` outcome
  and make it the only guard path that maps to exit 1.
- [ ] Route unconditional/partial command, sudo-gated, config-key, bypass-env,
  protected-branch, background-push, sealed-repository, and other safety denials
  through the same central dispatcher.
- [ ] Replace `log::block() -> !` with report and audit functions that return
  typed delivery results; keep final exit ownership in the main dispatcher.
- [ ] Emit exactly one complete stderr/distinct-tty block report and attempt one
  canonical root-owned `event=block|exit=1` record for every policy denial.
- [ ] Preserve exit 1 and no-Git execution when stderr, tty, audit open/write/
  sync, or other delivery operations fail; surface those failures separately.
- [ ] Remove exit 1 from fork, capability-loan, exec, wait/supervision,
  validation, integrity, and contract failure paths and enforce their assigned
  typed exit classes.
- [ ] Add process-level paired tests where the guard denies with exit 1 versus
  fake real Git itself exits 1; assert only the former emits `BLOCKED` and an
  `event=block` audit record.
- [ ] Add one installed-path matrix covering every policy-denial category for
  root/non-root as applicable, complete forensic evidence, exact single report/
  record counts, and proof real Git was not invoked.

## REQ-GGUARD-102: Invocation Validation Exit Class

- [ ] Add typed `InvalidInvocation` variants for internal/test NUL, missing
  recognized global-option operand, indeterminate unknown-option arity,
  uninspectable config key, and argv `CString` conversion failure.
- [ ] At parser completion, reject pending operands for `-C`, `-c`,
  `--git-dir`, `--work-tree`, `--namespace`, `--config-env`, and every other
  compiled value-taking global option when discovery is indeterminate.
- [ ] Fail exit 2 on an unknown leading option only when its unknown arity makes
  subcommand identification unreliable; forward unknown forms that remain
  reliably classifiable for Git's own diagnostic.
- [ ] Remove `<binary-arg>` and every argv substitution/drop fallback from
  `exec.rs`; propagate a byte-exact validation error before fork instead.
- [ ] Keep arbitrary non-UTF-8 argv byte-identical outside explicitly ASCII
  safety fields and add non-UTF-8 options, operands, pathspecs, and post-`--`
  passthrough controls.
- [ ] Forward reliably classified malformed command-specific syntax unchanged
  and add paired tests distinguishing guard validation exit 2 from fake real Git
  exit 2; only the former emits a validation diagnostic.
- [ ] Replace the generic main error-to-exit-2 fallback with exhaustive typed
  dispatch so internal, privilege, integrity, fork/exec, and supervision errors
  use exit 3.
- [ ] Add stable reversibly escaped validation diagnostics containing complete
  forensic argv evidence without substitution, omission, or lossy conversion.
- [ ] Add process-level matrices for each missing operand, attached/separate
  malformed forms, unknown-option ambiguity, empty/uninspectable config keys,
  terminal queries, no-subcommand invocation, and proof invalid invocations never
  execute real Git.

## REQ-GGUARD-103: Guard-Unavailable Exit Class

- [ ] Replace `MissingCap`, `MissingCapabilities`, `GitOriginalMissing`,
  `GitOriginalBadPerms`, and generic fallbacks with typed `GuardUnavailable`
  stages and one exhaustive exit-3 dispatcher.
- [ ] Change root-only effective-UID failure and every current privilege/default
  exit 2 to exit 3 while preserving the exact failed condition.
- [ ] Remove stale `CAP_FSETID` requirements from capability arrays, messages,
  tests, generated expectations, and sandbox-service
  `CapabilityBoundingSet`/`AmbientCapabilities`; require only the four
  REQ-GGUARD-001 caps.
- [ ] Replace boolean `PR_GET_NO_NEW_PRIVS` probing with a typed safe-wrapper
  result; value 0 passes host-exec, value 1 and syscall errors fail exit 3.
- [ ] Preserve capability query errors separately from verified absent caps and
  test failures for Effective, Permitted, Ambient, Inheritable promotion, Ambient
  clear, and child DAC loan stages.
- [ ] Enforce the complete trusted deployment-class file contract and preserve
  missing, symlink/type, owner/group, mode/special-bit, immutable/integrity,
  parse, and unsupported-class failures distinctly.
- [ ] Replace real-Git `metadata()` with REQ-GGUARD-006 no-follow verification of
  type, uid/gid, exact `0700` including special bits, no file capabilities, and
  non-guard inode identity.
- [ ] Make both `RLIMIT_NOFILE` and `RLIMIT_CORE` setup checked and map either
  failure to typed exit 3 before policy or Git execution.
- [ ] Map fork, child exec, capability-loan, wait, and signal-propagation failures
  to distinct exit-3 stages; retry only valid `EINTR` and remove exit-1/2 or
  missing-Git substitutions.
- [ ] For post-start supervision failures, report whether child outcome is
  unknown or mutation may already stand; preserve complete reversible evidence.
- [ ] Add paired process tests for guard-unavailable exit 3 versus fake real Git
  exit 3; assert only the former emits a guard diagnostic and neither is logged
  as an exit-1 policy block.
- [ ] Add installed-host and fault-injection matrices for every exit-3 stage,
  exact status, no pre-exec Git launch, no swallowed diagnostics, and unchanged
  reconciliation exit 74 behavior.

## REQ-GGUARD-104: Contract Exit Class

- [ ] Replace `GuardError::ContractFailed(String)` with exhaustive
  `ContractRejected`, `ContractUnavailable`, and
  `ContractRequiredOutsideWorkspace` variants carrying typed status/evidence.
- [ ] Map every required-contract non-success to exit 4, including scope,
  registry/repository/destination, hook/deployment/binding integrity, spawn,
  pipe/output, wait/signal, timeout, termination/reap, and cleanup failures.
- [ ] Remove fail-open CI integrity paths: tracked/untracked enumeration and
  every helper status, stderr, parse, and inspection failure must produce a
  typed unavailable outcome rather than an empty violation set or skipped check.
- [ ] Route runner non-zero and outside-workspace protected/indeterminate
  decisions to `contract-reject`; route unavailable states to
  `contract-unavailable`, with one stderr/distinct-tty summary and one
  authoritative audit attempt.
- [ ] Preserve separately streamed runner output exactly once; keep summary and
  audit records complete without copying those stream bytes into either.
- [ ] Preserve exit 4 when report or audit delivery fails, surface that failure
  non-recursively, prohibit root bypass, and prove requested Git never executes.
- [ ] Add paired process tests distinguishing each guard contract exit 4 from a
  fake real Git exit 4 after `Passed`; only guard outcomes emit contract reports
  and audit events.
- [ ] Add fault-injection tests for every exit-4 stage, helper failure, child
  status/signal, partial output, timeout, and cleanup path with exact evidence and
  no swallowed diagnostics.

## REQ-GGUARD-110: Shared Failure-Report Delivery

- [ ] Replace direct `eprintln!`, unconditional `/dev/tty` writes, and ignored
  write results with one byte-oriented delivery function returning typed
  per-destination outcomes and owning no process exit.
- [ ] Build each report once as immutable reversibly escaped bytes and use
  checked complete-write loops for stderr and tty, retrying only valid `EINTR`.
- [ ] Open `/dev/tty` write-only with close-on-exec and use safe tty/session APIs
  to distinguish the controlling terminal from stderr; add no raw unsafe ioctl
  site or filesystem-identity fallback.
- [ ] Route policy, validation, guard-unavailable, contract-summary, and
  non-recursive audit-failure reports through the shared dispatcher while
  keeping warnings stderr-only and real-Git/contract streams separate.
- [ ] Preserve the original typed exit and execution decision on every delivery
  failure; surface typed stderr/tty open, identity, partial-write, and terminal
  write failures through any surviving destination without recursive reporting.
- [ ] Add PTY process tests for same-terminal `/dev/tty` aliasing without
  duplication, redirected/non-terminal stderr, proven distinct terminals,
  indeterminate terminal identity, absent controlling tty, partial writes,
  `EINTR`, closed stderr, `EPIPE`, tty open/write failure, and both destinations
  unavailable.
- [ ] Add one matrix proving guard exits 1, 2, 3, and 4 each use the shared
  failure path exactly once while warnings, runner streams, and propagated real
  Git exits do not.

## REQ-GGUARD-111: Canonical Block Report

- [ ] Implement the exact two-line ASCII `BLOCKED:` schema with fixed field
  order, canonical decimal `argc`, contiguous `arg0..argN`, and exactly one final
  newline; reject formatter states with count/index mismatch.
- [ ] Reuse the REQ-GGUARD-091 uppercase `%HH` encoder and parser/golden vectors
  for reason, argv, and hint, including `%`, delimiters, spaces, CR/LF, controls,
  empty values, and bytes at or above `0x7f`.
- [ ] Replace pre-epoch fallback-to-zero and `+0000` output with signed time
  conversion and exact RFC3339 UTC `Z`; return a typed formatting failure when
  the value is outside the representable grammar rather than fabricating a
  timestamp.
- [ ] Carry the selected first-block-wins policy identity/reason and its hint as
  policy-owned bytes; remove independently assembled visible/audit reasons.
- [ ] Audit every policy hint against its matching parser state so it never
  recommends an operation blocked in the same caller/repository context; make
  root/state-dependent alternatives explicitly conditional.
- [ ] Remove Unicode arrows, ANSI formatting, localization, lossy conversion,
  joined argv, and unencoded dynamic text from Git block reports.
- [ ] Add golden parser/formatter tests for exact grammar, malformed indexes and
  counts, multiple simultaneous policy matches, first-reason precedence,
  caller-controlled terminal sequences/newlines, all byte values, very long
  argv without truncation, and byte-for-byte stderr/tty/audit field agreement.
- [ ] Correct the block-engine contract stage and tests so WORKSPACE-CI typed
  non-success maps to exit 4 without a `BLOCKED:` prefix or exit-1 block event.

## REQ-GGUARD-112: Typed Runtime Warnings

- [ ] Add a closed `WarningKind` enum for filtered environment, empty hook-bypass
  environment, inspected workspace-marker drift, reconcile symlink skip, and
  protected hook/registry drift, with fixed raw-byte fields per variant.
- [ ] Implement the exact one-line ASCII `WARNING:` grammar using the shared
  RFC3339 UTC timestamp and REQ-GGUARD-091 uppercase `%HH` encoder; enforce fixed
  field count/order and exactly one final newline.
- [ ] Replace `log::warn(String)`, direct reconcile `eprintln!`, and
  `Path::display()` with one typed warning formatter over `OsStr`/environment
  bytes; remove warning writes to `/dev/tty` and user-home/authoritative audit
  files.
- [ ] Write each warning to stderr exactly once with checked complete-write
  handling; retry only valid `EINTR`, and map short writes, `EPIPE`, and other
  failures to `GuardUnavailable { stage: WarningStderr, ... }`.
- [ ] Before-Git warning delivery failure must exit 3 without launching Git;
  post-Git failure must exit 3 with operation-may-stand evidence, while an
  independent reconciliation invariant failure retains exit-74 precedence.
- [ ] Remove `warning` from the Git audit schema, parser, fixtures, and event
  vocabulary; prove successful runtime warnings never open or append an audit
  sink and create no user-home log artifact.
- [ ] Add golden tests for every warning variant, exact field count/order,
  explicit empty values, non-UTF-8 environment/path bytes, controls/newlines,
  very long values without truncation, one stderr line, and no tty/audit copy.
- [ ] Prove each inherited environment entry emits at most one warning: empty
  hook-bypass uses only its specialized variant, while non-empty bypass values
  block without emitting a warning.
- [ ] Add stderr fault tests for partial writes, `EINTR`, `EPIPE`, closed fd, and
  post-Git reconcile warnings, including the resulting shared exit-3 report.
- [ ] Add classification regressions proving background-push detection and every
  validation, integrity, contract, audit, and reconciliation failure retain their
  assigned class, while trace/helper/contract/installer output is not formatted
  as a runtime warning.

## REQ-GGUARD-113: Stream Transparency and Diagnostics

- [ ] Centralize stream ownership: prohibit guard-generated stdout, inherit
  caller stdout/stderr directly for real Git, keep successful helper stdout
  internal, and retain the separate concurrent WORKSPACE-CI stream path.
- [ ] Remove every real-Git pipe/buffer/decode/prefix path so binary output,
  terminal detection, prompts, progress, color, `EPIPE`, exit status, and signals
  remain owned by Git and propagate unchanged.
- [ ] Replace helper `Stdio::null()` stderr, ignored reader/join results,
  `unwrap_or_default()` output fallbacks, lossy strings, and silent `.ok()?`
  paths with typed byte-oriented helper outcomes.
- [ ] Add closed static helper tokens and incrementally encode non-empty helper
  stderr as bounded `HELPER-STDERR` chunks with zero-based contiguous sequence,
  exactly one final marker, canonical `%HH` data, and exactly one newline per
  chunk; decoded concatenation must reproduce the exact original bytes.
- [ ] Keep successful helper stdout solely as its typed protocol. On failed or
  malformed protocol, preserve stdout as encoded failure evidence without
  copying raw helper bytes to guard stdout.
- [ ] Compute trace enablement once from the immutable startup environment
  snapshot; enable only for a present non-empty `WORKSPACE_GUARD_TRACE`, consume
  it, and never forward it to helpers, contract, or Git.
- [ ] Replace free-form trace `eprintln!` calls with checked canonical `TRACE`
  start/end records using a closed phase-token set and decimal `elapsed-ns`;
  prohibit argv, environment values, credentials, paths, policy data, and other
  caller-controlled bytes in trace records.
- [ ] Enforce causal output sequencing: pre-Git warning/trace/helper diagnostics
  complete before Git, contract streams precede Git, rejection summary follows
  contract streams, and post-Git trace/reconcile output starts after child reap;
  promise only per-stream ordering across stdout/stderr.
- [ ] Map pre-Git trace/helper diagnostic write failure to a typed
  `GuardUnavailable` stage and exit 3 without Git; map post-Git failure to exit 3
  with operation-may-stand evidence, preserving reconciliation exit-74
  precedence.
- [ ] Keep contract stream read/write failures in typed exit 4, preserve enforced
  report exits under REQ-GGUARD-110, and leave real-Git inherited-stream errors
  to Git's propagated outcome.
- [ ] Audit every Git-guard `print!`/`println!`/`eprint!`/`eprintln!`, child
  `Stdio`, reader thread, lossy conversion, and output fallback; classify or
  remove each path under the stream-ownership contract.
- [ ] Add process tests proving no guard-generated stdout for passthrough,
  warning, validation, policy, guard-unavailable, contract, audit, trace, and
  reconcile paths.
- [ ] Add fake-Git tests for byte-exact/high-volume stdout and stderr, all byte
  values, redirected streams, interactive PTY behavior, exit 0/non-zero, signal,
  broken pipe, and post-Git diagnostics without guard buffering or duplication.
- [ ] Add helper tests for success/failure stderr, empty stderr, malformed
  protocol stdout, non-UTF-8/control bytes, every chunk boundary, high-volume
  output, missing/duplicate/reordered/final chunks, reader panic/error, timeout,
  signal, and no raw helper stdout leakage.
- [ ] Add contract ordering tests proving concurrent high-volume stdout/stderr is
  emitted exactly once before Git on pass and before the summary on rejection,
  with per-stream byte order and no claimed cross-stream total order.
- [ ] Add trace tests for absent, empty, and non-empty startup values, immutable
  enablement across phases, exact start/end grammar, closed phase tokens, no
  child forwarding, no sensitive fields, checked-write failure, and pre/post-Git
  exit behavior.

## REQ-GGUARD-120: Verified Binary Hardening

- [ ] Change release `opt-level` from `3` to `"z"` and add
  `overflow-checks = true`; add development `panic = "abort"` and
  `overflow-checks = true` so `Cargo.toml` matches REQ-GGUARD-120/171.
- [ ] Add and enforce a repository-pinned Rust toolchain and committed trusted
  `x86_64-unknown-linux-musl` target/linker configuration for static PIE, full
  RELRO, non-executable stack, and stack protection.
- [ ] Pin a toolchain/linker combination that supports the required stack-
  protection mechanism; treat unsupported or ignored hardening flags as a build
  failure rather than silently producing a weaker binary.
- [ ] Make `make build-guard` and the WORKSPACE-CI bootstrap use the explicit
  pinned toolchain, `--locked`, release profile, exact target, exact binary, and
  selected deployment feature without GNU/architecture fallback.
- [ ] Start privileged builds from a controlled environment and reject inherited
  `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, rustc wrappers, target/linker overrides,
  and other compiler/linker controls that could replace or weaken trusted flags.
- [ ] Implement one deterministic final-ELF verifier using fixed absolute trusted
  tools and parser-stable output; do not infer security from Cargo configuration
  or a broad `file | grep ELF` check.
- [ ] Verify x86-64 static PIE ELF type, `GNU_RELRO`, non-executable `GNU_STACK`,
  pinned stack-protection evidence, no `PT_INTERP`, no dynamic dependencies, and
  expected stripping; fail on missing, malformed, duplicate, contradictory, or
  unknown verifier output.
- [ ] Define and verify build-manifest evidence for properties not reliably
  recoverable from a stripped ELF alone, including pinned toolchain/target,
  trusted flags, panic abort, and release overflow checks; bind it to the artifact
  digest.
- [ ] Record the verified source artifact's cryptographic digest, install those
  exact bytes, and compare destination digest before applying file capabilities.
- [ ] Reopen/verify the installed destination no-follow as the expected regular
  inode with trusted owner/mode, rerun all ELF checks on it, and detect replacement
  or copy races before `setcap` labels the inode privileged.
- [ ] Ensure every build/property/digest/inode verification failure aborts without
  modifying the existing installation or applying capabilities to an unverified
  destination; preserve complete diagnostics.
- [ ] Remove dynamic GNU and architecture fallback language/behavior from build,
  bootstrap, install, root-only, operator, and deployment paths for the privileged
  Git guard; missing musl target/linker/verifier is a provisioning failure.
- [ ] Add positive build/install tests for the pinned artifact and exact source/
  destination digest, ELF properties, owner/mode, and capability-label ordering.
- [ ] Add one negative fixture/test per property: non-PIE, missing RELRO,
  executable stack, absent stack protection, interpreter present, dynamic
  dependency, wrong architecture, unstripped artifact, wrong target/profile,
  unsupported flag, inherited override, malformed verifier output, digest
  mismatch, inode replacement, and post-copy tampering.
- [ ] Add regression checks that reject `opt-level = 3`, disabled release overflow
  checks, missing dev panic abort/overflow checks, unpinned toolchains, plain
  `cargo build --release`, and capability application before destination
  verification.
- [ ] Run the final verifier against `/usr/bin/git` after host-exec installation
  and include its property/digest result in guard drift checks so package or
  operator replacement cannot retain an unverified privileged artifact.
- [ ] Reuse the verifier for shell and binary guard artifacts that claim
  REQ-GGUARD-120 hardening; verify each artifact/digest independently rather
  than treating shared workspace profile settings as proof.

## REQ-GGUARD-121: Centralized Unsafe Boundary

- [ ] Add one `src/linux_ffi.rs` module and move the four approved production
  operations into minimal wrappers: `getauxval(AT_SECURE)`, `fork`, `_exit`, and
  `ioctl(FS_IOC_GETFLAGS)`.
- [ ] Add crate-level `#![deny(unsafe_code)]` to every binary/library root and a
  narrow module-local allowance only for `linux_ffi`; prohibit additional lint
  allowances, inline assembly, unsafe functions/traits, and raw pointer/fd escape
  APIs.
- [ ] Write an adjacent complete `// SAFETY:` contract for each of the four
  blocks covering pointer validity, alignment, lifetime, accepted values,
  return/error interpretation, and post-fork restrictions.
- [ ] Make the immutable-flag wrapper accept a borrowed verified file descriptor
  and return typed flags/error; remove duplicate ioctl implementations from
  `reconcile.rs` and `shell_guard.rs` and expose no arbitrary ioctl command.
- [ ] Replace `libc::geteuid` in shell/integration code with
  `nix::unistd::geteuid`; replace raw `prctl(PR_GET_NO_NEW_PRIVS)` with the safe
  typed `nix` wrapper and preserve syscall error separately from values 0/1.
- [ ] Replace `libc::lchown` with safe `nix::unistd::fchownat` no-follow handling,
  preserving CString/path errors and exact syscall status without following a
  symlink.
- [ ] Remove raw child `libc::write` diagnostics. Create a close-on-exec status
  pipe before fork and use safe allocation-free writes of fixed typed setup/exec
  statuses; successful exec closes the channel and the parent owns all visible
  diagnostics.
- [ ] Prebuild argv, environment, C strings, status storage, and all other child
  inputs before fork; audit capability promotion/loan and `execve` wrappers for
  allocation, locks, formatting, panic, unwinding, destructors, environment
  reads, and other non-async-signal-safe behavior.
- [ ] Enumerate the exact post-fork call graph and add a mechanical source/build
  check allowing only reviewed capability syscalls, fixed status write,
  `execve`, and `_exit` before successful exec.
- [ ] Convert child setup/exec status into typed parent-side
  `GuardUnavailable` stages with exact OS evidence; remove child-selected public
  exit 2/3 and ad hoc stderr text that can be confused with real Git outcomes.
- [ ] Confine raw `libc::fork`/`libc::_exit` tests to one dedicated test module
  with equivalent safety contracts; migrate every other unit/integration test to
  safe UID/syscall wrappers.
- [ ] Add a repository build gate scanning all Rust targets, build scripts,
  examples, benches, and tests for unsafe blocks/functions/traits, inline asm,
  direct `libc::*`, lint allowances, and approved call count/location drift.
- [ ] Update `config/banned_words_exceptions.yaml` only through the sudo-gated
  YAML editor so the unsafe exception names exactly `src/linux_ffi.rs` and the
  dedicated raw-fork test module; remove broad historical FFI descriptions and
  every retired source path.
- [ ] Add wrapper tests for auxv values/errors, immutable flag set/clear/error,
  no-follow ownership on regular files/symlinks, `NoNewPrivileges` 0/1/error,
  fork failure, child setup failure, exec failure, and typed status-pipe closure.
- [ ] Add adversarial post-fork tests for multithreaded parent state, full/closed
  status pipe, `EINTR`, partial writes, capability failure, exec success/failure,
  no child formatting/allocation, no duplicate diagnostics, and complete reap.
- [ ] Add gate-negative fixtures for a fifth unsafe block, direct libc call,
  unsafe trait/function, inline assembly, unauthorized lint allowance, moved
  wrapper, duplicate ioctl, and unsafe code in integration/build-script targets.

## REQ-GGUARD-122: Isolated Dependency Closure

- [ ] Create a standalone `git-guard/` Cargo package with its own `Cargo.toml`,
  `Cargo.lock`, `build.rs`, trusted `.cargo/config.toml`, source/tests, and target
  directory; exclude it from the broader package/workspace and add no path/local
  dependency back to repository tooling.
- [ ] Move the privileged `workspace-guard` binary and only its required modules,
  policy compiler, fixtures, and tests into the isolated package; remove the
  binary target and Git-only modules from the broad root package without adding
  a shared runtime crate.
- [ ] Limit isolated direct runtime dependencies to `libc = "0.2"`, reviewed
  minimal-feature `nix = "0.29"`, and optional `caps = "0.5"`; remove `rustix`,
  `regex`, `serde*`, `sha2`, and all unrelated tool dependencies from its normal
  closure.
- [ ] Remove unused direct `serde_json` from the broad root manifest; if another
  non-Git package still brings it transitively, classify it only in that
  package's closure and prove it is absent from the isolated Git guard.
- [ ] Keep only `serde`, `serde_yaml`, and `regex` as isolated direct build
  dependencies, minimize and pin their reviewed features, and inventory every
  transitive normal/build/proc-macro edge including `serde_derive` and
  `unsafe-libyaml`.
- [ ] Set Cargo resolver 2 and define capability/root-only features so exactly one
  must be selected; capability mode includes exactly one approved locked `caps`
  version and root-only mode has no `caps` edge.
- [ ] Generate and commit a versioned `git-guard/dependency-closure.json` with
  exact package name/version/source/checksum/features, dependency edge kind,
  target predicate, build-script flag, and proc-macro flag for both deployment
  modes; bind its digest into the REQ-GGUARD-120 build manifest.
- [ ] Implement a metadata-only pre-build gate that compares Cargo metadata/tree
  normal, build, and proc-macro closures against the selected-mode manifest
  before dependency code executes.
- [ ] Reject Git dependencies, alternate registries, unapproved path sources,
  duplicate crate versions, unexpected build scripts/proc macros, unknown target
  predicates, checksum/source drift, default/feature unification drift, and any
  package absent from the approved closure.
- [ ] Provision a trusted read-only offline Cargo source store and verify every
  source against `Cargo.lock`/Cargo checksums before use; prohibit network access,
  online fallback, `cargo update`, and lockfile generation during build/install.
- [ ] Run dependency build scripts and proc macros under an unprivileged build
  identity with no network and no write access outside the isolated target/OUT_DIR;
  root shall execute only closure/artifact verification and installation.
- [ ] Audit the Git guard `build.rs` for deterministic inputs/outputs, fixed
  policy paths, `rerun-if-changed` coverage, no subprocess/network access, no
  unclassified environment authority, and writes confined to `OUT_DIR`.
- [ ] Update `make build-guard`, WORKSPACE-CI bootstrap, lint/check/test targets,
  Podman builds, root-only paths, and installation to use
  explicit `--config git-guard/.cargo/config.toml --manifest-path
  git-guard/Cargo.toml --package workspace-guard --bin
  workspace-guard --locked --frozen --offline --release --target
  x86_64-unknown-linux-musl` plus one explicit mode feature.
- [ ] Ensure fmt, clippy, tests, unsafe gates, policy consistency, closure checks,
  and final-ELF verification all include the standalone package despite its
  exclusion from the broader workspace.
- [ ] Add positive closure tests for capability and root-only modes, proving
  normal closure exactness, build/proc-macro closure exactness, `caps` presence/
  absence, no unrelated package dependency, source/checksum agreement, and no
  final ELF dynamic dependency.
- [ ] Add negative tests for both/neither mode, added direct/transitive crate,
  added feature/default feature, duplicate version, Git/path/alternate-registry
  source, changed checksum, stale/missing lock entry, unexpected build script or
  proc macro, target-specific hidden edge, and closure-manifest mismatch.
- [ ] Add isolated-build tests in a network namespace with empty/unavailable
  network, read-only source store, non-root UID, clean target, and `--frozen`;
  prove missing sources/checksums/lock data fail closed without network access.
- [ ] Add sandbox-negative build-dependency fixtures attempting network,
  environment authority, and writes outside OUT_DIR; prove they are denied before
  a privileged artifact can be accepted, and statically reject unapproved
  subprocess spawning in approved build scripts.
- [ ] Document and gate the reviewed lockfile/closure update procedure separately
  from ordinary builds so dependency changes cannot be accepted implicitly by
  running installation.

## REQ-GGUARD-123: Byte-Oriented Input And Forwarding

- [ ] Rewrite Git argument parsing over `OsStrExt::as_bytes()`/byte slices and
  original argument indexes; remove every `from_utf8(...).unwrap_or("")`, lossy
  conversion, and caller-derived `String` from parser and policy state.
- [ ] Compare global options, separators, subcommands, and command-specific flags
  with compiled ASCII byte constants and command-specific arity; retain opaque
  value/operand ranges into original argv rather than reconstructed strings.
- [ ] Remove subcommand abbreviation resolution and compare exact command bytes;
  pass non-ASCII positional command candidates through capless as unknown while
  treating non-ASCII leading options under the typed unknown-arity rule.
- [ ] Recognize ASCII policy prefixes independently of opaque attached values so
  blocked keys/flags cannot evade inspection merely because their value contains
  non-UTF-8 bytes.
- [ ] Parse `-c`/`--config-env` key boundaries directly as bytes, split only at
  the specified first `=`, apply the exact ASCII key grammar/case fold, and remove
  `trim()` or any other mutation of the inspected/forwarded key.
- [ ] Keep config values, option operands, pathspecs, refs, remote names/URLs,
  commit messages, filenames, and all post-`--` arguments opaque and
  byte-identical; never globally rescan their bytes as options.
- [ ] Preserve caller `argv[0]`, empty arguments, order, count, and every byte in
  the final real-Git vector; keep the fixed `execve` pathname separate from
  `argv[0]`.
- [ ] Replace manual NUL append/`CStr` reconstruction and `"<binary-arg>"` with
  one pre-fork fallible `CString::new` conversion over each exact argument;
  caller conversion failure is typed exit 2 with no child execution.
- [ ] Replace environment `filter_map(|...| CString::new(...).ok())` with a
  complete checked conversion that cannot silently drop or reorder entries;
  guard-owned environment/binding/path conversion failure maps to typed exit 3.
- [ ] Carry repositories, workspace roots, cwd, remotes, audit paths, and
  reconciliation identities as `PathBuf`/`OsString` and compare canonical path
  components as bytes; remove `String`, textual prefixes, `Path::display()`, and
  `to_string_lossy()` from every security/containment decision.
- [ ] Convert environment sanitization/catalog matching to raw name/value bytes;
  keep catalog names ASCII, preserve admitted values exactly, and retain exact
  filtered name/value warning evidence.
- [ ] Parse repository, branch, destination, integrity, and contract-helper stdout
  as explicit byte protocols; convert only completely validated ASCII fields to
  text and preserve opaque stdout/stderr through reversible evidence framing.
- [ ] Remove `String::from_utf8_lossy`, `.to_str()` fallbacks, replacement
  characters, lossy trimming, and empty/default substitutions from Git-guard
  diagnostics, helper errors, CI integrity, workspace detection, audit, and
  reconciliation paths.
- [ ] Add an isolated-package build gate rejecting `to_string_lossy`,
  `from_utf8_lossy`, `Path::display`, and failed-UTF8-to-default patterns in
  production security/evidence code; require an exact reviewed justification for
  any remaining text conversion.
- [ ] Add fake-real-Git capture tests comparing exact argv count/order/bytes and
  sanitized environment name/value bytes, including empty argv entries and a
  caller-controlled non-UTF-8 `argv[0]`.
- [ ] Add exhaustive non-NUL byte matrices at every parser boundary: leading
  option, attached/separate value, subcommand candidate, flag, flag value,
  operand, pathspec, ref, remote/URL, config key/value, and post-`--` data.
- [ ] Add config regressions for ASCII dangerous/allowed keys with non-UTF-8
  values, non-ASCII keys, whitespace-bearing keys, first-`=` behavior, attached/
  separate forms, and proof blocked ASCII prefixes remain visible.
- [ ] Add option regressions for recognized ASCII tokens with non-UTF-8 suffixes,
  opaque values beginning with blocked-looking flags, separator lookalikes, and
  unknown non-ASCII option arity without accidental empty-string classification.
- [ ] Add non-UTF-8 repository/workspace/branch/remote path tests, component-
  containment near matches, helper protocol successes/failures, contract bindings,
  reconcile paths, and exact cwd agreement.
- [ ] Add report/audit round-trip tests proving `%HH` decoding reproduces every
  original byte and argument boundary with no replacement character,
  `"<binary-arg>"`, trimming, omission, truncation, duplication, or reordering.
- [ ] Retain synthetic embedded-NUL tests for caller argv exit 2 and guard-owned
  construction exit 3, proving conversion completes before fork and no requested
  Git executes on either failure.
