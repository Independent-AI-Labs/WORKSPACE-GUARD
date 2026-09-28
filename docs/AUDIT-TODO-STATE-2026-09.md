# TODO State Audit

**Date:** 2026-09-28
**Type:** Audit
**Scope:** Every task in `../TODO.md` (the `REQ-GGUARD-*` backlog), checked
against the current `git-guard/src/` implementation, `config/`, and the live
host.
**Method:** Read-only. For each requirement section, the "remove X" and "add Y"
targets named by the tasks were searched for in the source and config, and the
git guard is read directly. This is a structural audit (specified change present
or absent), not a line-by-line execution of all 525 tasks. Sections marked
UNVERIFIED had no decisive code signal found in this pass.

## Executive Summary

`TODO.md` is not stale or filler. It is an accurate gap list. The
specifications in `docs/specifications/` and `docs/requirements/` describe a
target state that is substantially ahead of the deployed `git-guard/src/`
implementation, and the TODO records the distance.

- 54 `REQ-GGUARD-*` sections, 525 task items, 1 checked before this audit.
- Of the 54 sections, none are fully implemented as written. The dominant
  verdict is PARTIAL: an earlier, working version of the feature exists, and the
  hardening/typing/canonicalization the tasks demand has not landed.
- The clearest NOT DONE sections are the ones whose tasks name a symbol to
  delete: `CAP_FSETID`, the subcommand abbreviation tables, the
  `<binary-arg>` substitution branch, the `fs::metadata` real-git check, the
  `--force-with-lease` push hint, the home-directory audit log, and the
  `cherry-pick`/`apply`/`am` contract entries are all still present.

The consequence: several statements in the specifications read as settled
guarantees but are targets, not current behavior. The security-relevant ones are
the audit sink (the guard writes to `${HOME}/.workspace-guard.log`, not the
root-owned `/var/log/workspace-guard/`), the real-Git verification (follows
symlinks, no group check), and the guard-unavailable exit code (still 2, not 3).

The blocker is not the TODO's existence. It is that the requirement set grew
faster than the implementation, and 1 checked item in 525 means the backlog is
not being drained at the rate it is being written.

## Verdict Legend

| Verdict | Meaning |
| --- | --- |
| DONE | The specified behavior is present as written. |
| PARTIAL | An earlier form exists; part of the task (typing, canonical form, edge handling, tests) is absent. |
| NOT DONE | The named symbol, behavior, or removal has not happened. |
| STALE | The task targets code that no longer exists; the task should be rewritten or closed. |
| UNVERIFIED | No decisive signal found in this pass. |

## Section Table

Item counts are from `TODO.md`. Verdicts are this audit's assessment.

| REQ | Items | Verdict | Key evidence |
| --- | --- | --- | --- |
| 001 Four-Capability Host-Exec Model | 9 | NOT DONE | `git-guard/src/main.rs:176-182` still requires `CAP_FSETID`; `exec.rs:32-38` raises it; live `/usr/bin/git` has `cap_fsetid`. |
| 003 Deployment-Class Capability Verification | 6 | PARTIAL | `main.rs:201-302` reads the class and checks caps; still the five-cap set, still `MissingCap` exit 2. |
| 004 Privilege-Failure Exit Contract | 6 | NOT DONE | `main.rs:138-153` maps `MissingCap`/`MissingCapabilities` to exit 2, not 3. |
| 006 Real-Git Verification | 7 | PARTIAL | `exec.rs:108-132` uses `fs::metadata` (follows symlinks), checks uid only, mask `0o777`; device/inode guard check present. |
| 007 Trusted Contract Runner | 16 | PARTIAL | `exec.rs:413-429` uses the fixed `CONTRACT_SCRIPT` with `/bin/bash` argv, but inherits the environment (no clear/rebuild) and pipes stderr only. |
| 010 Option Separator Semantics | 6 | PARTIAL | Separator handled in `args.rs`, but the post-separator global `--hard` scan remains at `args.rs:420-428`. |
| 011 Operand-Aware Subcommand Discovery | 9 | PARTIAL | `args.rs:179-184` skips `-C` operand; unknown-arity leading option does not exit 2. |
| 012 Exact Policy-Relevant Subcommands | 7 | NOT DONE | `resolve_subcommand_abbreviation` and `ABBREV_CANDIDATES`/`ABBREV_PREFERRED` remain (`args.rs:40-71`, `build.rs:368-392`). |
| 013 Capless Unknown Commands | 9 | PARTIAL | `exec.rs:25-43` raises inheritable caps and loans `CAP_DAC_OVERRIDE`; compiled loan-set generation absent. |
| 014 Byte-Exact Argument Conversion | 6 | NOT DONE | `exec.rs:226` substitutes `<binary-arg>`; `child.rs`/`exec.rs` use `to_string_lossy`. |
| 020 Destructive Command Categories | 6 | PARTIAL | Category blocks exist (`block.rs:29-66`); the TODO's matrix/schema additions are not present. |
| 021 Block Report Delivery | 9 | NOT DONE | `log.rs:42` emits `BLOCKED: {cmd} ({ts})\n  -> Hint:`; not the indexed canonical grammar. |
| 030 Command-Specific Destructive Options | 10 | PARTIAL | Short-flag handling is command-scoped (`args.rs:436-449`), global `--hard`/`--no-verify` scans remain. |
| 031 Config-Bearing Global Options | 8 | PARTIAL | `-c`/`--config`/`--config-env` parsed (`args.rs:172-256`); still interprets config options after the subcommand and accepts `--config`. |
| 040 Dangerous Config-Key Catalog | 9 | PARTIAL | Glob catalogs exist (`config/git_guard_config_keys.yaml`); no per-entry threat class or structured schema fields. |
| 041 Config-Key Payload Parsing | 9 | PARTIAL | Splits on first `=`, but through `from_utf8` with `unwrap_or("")` (`args.rs:186-197`). |
| 042 Allowed Config Passthrough | 4 | UNVERIFIED | Passthrough behavior not isolated in this pass. |
| 050 Unconditional Stash Block | 7 | PARTIAL | `config/git_guard_subcommands.yaml` lists `stash` under `blocked`, but `block.rs:104-115` retains the drop/clear conditional path. |
| 051 Branch Force Semantics | 9 | PARTIAL | Blocks `-D`/`-M` (`block.rs:117-129`); full cluster/grammar handling absent. |
| 052 Push Force Semantics | 11 | PARTIAL | Blocks `-f`/`--force-with-lease` (`block.rs:145-152`) but the hint still recommends `--force-with-lease`, which the task says to remove. |
| 053 Foreground Push Detection | 7 | PARTIAL | `block.rs:161-179` reads `/proc/self/stat`; `unwrap_or(0)` on parse failure does not fail closed. |
| 054 Sudo-Gated Commit Amend | 8 | PARTIAL | `commit::check_commit_attribution` runs; full amend grammar not verified. |
| 055 Allow Forward-Only Revert | 7 | NOT DONE | `block.rs:223-260` still contains the revert ancestry block and `run_git`. |
| 060 Protected Branch Catalog | 7 | PARTIAL | Catalog and `PROTECTED_BRANCHES` exist; classification uses `to_lowercase` (`block.rs:326`), not ASCII folding. |
| 061 Protected Pull Effective Mode | 10 | NOT DONE | `state.safe_pull_flag` is monotonic (`args.rs:268-270`, `block.rs:262`). |
| 062 Protected Merge Effective Mode | 10 | NOT DONE | `has_ff_only`/`has_merge_abort` token scan (`block.rs:269-279`). |
| 063 Effective Repository Branch Discovery | 10 | PARTIAL | `gitdir.rs`, `child::run_with_timeout` exist; typed branch result and byte-exact parsing not verified. |
| 070 Child Environment Allow-List | 10 | NOT DONE | `exec.rs:230-258` filters `std::env::vars_os()`; the compiled allow-list is not the child env source. |
| 071 Hook-Bypass Environment Attempts | 8 | PARTIAL | `block.rs:288-297` checks `std::env::var` on `BLOCKED_BYPASS_VARS`; byte-oriented inherited snapshot absent. |
| 072 Preserve Caller PATH | 9 | NOT DONE | `config/git_guard_environment.yaml` `allowed:` does not contain `PATH`; PATH is dropped. |
| 073 Preserve Identity and Locale Environment | 8 | PARTIAL | `HOME`/`USER`/`LANG`/`LC_*` are in the allow-list; identity routing audit not done. |
| 074 Untrusted Environment Snapshot | 9 | NOT DONE | The guard reads the live environment (`std::env`), no startup snapshot. |
| 080 Exact Contract Command Scope | 9 | NOT DONE | `config/git_guard_subcommands.yaml` `contract_check` still lists `cherry-pick`, `apply`, `am` alongside `commit`, `push`. |
| 081 Trusted Workspace Root Registry | 10 | NOT DONE | Uses `wsroot.rs` markers; `/etc/workspace-guard` absent. One item closed (marker removal from `shared_paths.yaml`). |
| 082 Outside-Workspace Contract Scope | 12 | PARTIAL | `remote.rs` `repo_targets_provisioned_host`; protected-remote catalog absent. |
| 084 Trusted Contract Bindings | 8 | PARTIAL | Three `WORKSPACE_GGUARD_*` bindings set (`exec.rs:424-426`); sanitization/`env_clear` absent. |
| 085 Contract Failure and Output Semantics | 10 | PARTIAL | Exit 4 via `ContractFailed`; no streamed stdout/stderr, no typed variants. |
| 086 Contract Deployment Unavailable | 8 | PARTIAL | `exec.rs:414-420` checks the script path; not the full deployment verification. |
| 090 Root-Owned Git Audit Logs | 14 | NOT DONE | `log.rs:59-70,88-99,142-149` write to `${HOME}/.workspace-guard.log` via `get_user_home`; `/var/log/workspace-guard` is `1777` and unused. |
| 091 Canonical Audit Record Encoding | 11 | PARTIAL | `pct_encode` and a v1 line exist for the sanitize event (`log.rs:137-158`); block/warn records are not canonical. |
| 092 Audit Append Failure Semantics | 10 | NOT DONE | `block()` ignores write errors (`log.rs:62-69`); no typed `AuditError`. |
| 093 Complete Forensic Evidence | 6 | PARTIAL | `pct_encode` present; block report does not carry complete indexed argv. |
| 100 Real Git Outcome Propagation | 9 | PARTIAL | `exec.rs:311-336` propagates exit and signal; typed outcome and reconcile precedence not implemented. |
| 101 Policy-Denial Exit Class | 8 | PARTIAL | `Blocked` maps to `block()` exit 1; not the typed `PolicyDenied` with shared delivery. |
| 102 Invocation Validation Exit Class | 9 | PARTIAL | `NullByteInArg` exit 2 and argv substitution paths remain. |
| 103 Guard-Unavailable Exit Class | 12 | NOT DONE | `MissingCap`/`MissingCapabilities`/`GitOriginalMissing` exit 2 (`main.rs:138-153`). |
| 104 Contract Exit Class | 8 | PARTIAL | `ContractFailed` exit 4; not the exhaustive typed set. |
| 110 Shared Failure-Report Delivery | 7 | NOT DONE | Inline `eprintln!` + `/dev/tty` in `log.rs`; no shared delivery function. |
| 111 Canonical Block Report | 8 | NOT DONE | Non-canonical format and `+0000` timestamp (`log.rs:42,179-190`). |
| 112 Typed Runtime Warnings | 10 | NOT DONE | `log::warn(&str)` (`log.rs:75-100`), not a closed `WarningKind` grammar. |
| 113 Stream Transparency and Diagnostics | 16 | PARTIAL | Real Git inherits stdout/stderr; contract stderr is piped and buffered (`exec.rs:427,465-472`). |
| 120 Verified Binary Hardening | 17 | NOT DONE | `opt-level = 3` (`git-guard/Cargo.toml`), no pinned toolchain, no final-ELF verifier. |
| 121 Centralized Unsafe Boundary | 16 | NOT DONE | No `linux_ffi.rs`; `unsafe` appears inline in `main.rs:97`, `exec.rs:272-294`, `reconcile.rs:329`; no `deny(unsafe_code)`. |
| 122 Isolated Dependency Closure | 19 | PARTIAL | The isolated `git-guard/` package exists; no `dependency-closure.json`, no offline/closure gate. |
| 123 Byte-Oriented Input And Forwarding | 21 | NOT DONE | Parser and exec use `String`, `from_utf8`, `to_string_lossy`, and `<binary-arg>`. |

## Cross-Cutting Findings

### T-01 HIGH: The audit sink is the home directory, not the root-owned path

`log.rs` derives the log path from `get_user_home(uid)` and writes
`${HOME}/.workspace-guard.log`. `REQ-GGUARD-090` exists specifically to remove
this and move to `/var/log/workspace-guard/`. The live directory is `1777` and
empty. Every block/warn record lands in an agent-writable directory.

### T-02 HIGH: Guard-unavailable and privilege failures exit 2, not 3

`main.rs:138-153` maps capability and real-Git verification failures to exit 2.
The exit-code contract (`REQ-GGUARD-103`, `SPEC-GIT-GUARD` section 2) reserves
exit 2 for malformed invocation and exit 3 for guard-unavailable. A caller
cannot distinguish "bad arguments" from "guard is unconfigured".

### T-03 HIGH: The real-Git check follows symlinks and omits the group check

`exec.rs:108-132` uses `fs::metadata` (follows symlinks), checks only uid, and
masks `0o777` rather than `0o7777`. The spec requires no-follow, uid and gid
zero, and the exact `0700` mask. The guard-inode comparison is present and
correct.

### T-04 MEDIUM: Spec and code disagree on the contract command set

`config/git_guard_subcommands.yaml` sets `contract_check` to five commands;
`SPEC-GIT-GUARD` section 6 says the set is exactly `commit` and `push`. One of
the two is wrong, and the config is what the deployed guard reads.

### T-05 MEDIUM: The push block hint recommends a blocked alternative

`block.rs:148-150` tells the user to use `--force-with-lease`, which the same
function blocks at `block.rs:145`. `REQ-GGUARD-052` says to remove that hint.

### T-06 LOW: A code comment cites a TODO line that is already wrong

`git-guard/src/exec.rs:206` cites `TODO.md:613` for the authorship forgeries.
`TODO.md:613` is now the `is_sudo`/`AT_SECURE` task. Line-number citations into a
mutable backlog break on every reorder. Cite the requirement id instead.

## Why the File Is Large

The TODO is 1645 lines because it restates 54 requirement sections as
fine-grained tasks and none of them are closed. It grew by ~90 lines when the
residual-coverage audit was appended. It is the visible symptom of a
requirement-first process where the specs run ahead of the code and the backlog
is written faster than it is drained. That is a process choice; the audit only
records that it is currently true.

## Recommendations

| ID | Action | Priority |
| --- | --- | --- |
| R-01 | Land `REQ-GGUARD-090` (root-owned audit sink) or mark `SPEC-AUDIT`/`SPEC-GIT-GUARD` residual claims as target-state. | High |
| R-02 | Fix the exit-code contract (`REQ-GGUARD-103`) so guard-unavailable is exit 3. | High |
| R-03 | Tighten the real-Git check to no-follow, uid+gid, exact `0700` (`REQ-GGUARD-006`). | High |
| R-04 | Reconcile the contract command set between `REQ-GGUARD-080` and the config. | Medium |
| R-05 | Remove the `--force-with-lease` push hint (`REQ-GGUARD-052`). | Medium |
| R-06 | Replace `TODO.md:613` with the requirement id in `exec.rs`. | Low |
| R-07 | Split the backlog into "in progress" and "target state" so the 1-checked-of-525 ratio is visible per release, not only in aggregate. | Low |

## References

- [SPEC-GIT-GUARD](specifications/SPEC-GIT-GUARD.md)
- [SPEC-GIT-GUARD-IMPL](specifications/SPEC-GIT-GUARD-IMPL.md)
- [SPEC-AUDIT](specifications/SPEC-AUDIT.md)
- [REQ-GIT-GUARD](requirements/REQ-GIT-GUARD.md)
- [AUDIT-RESIDUAL-COVERAGE-2026-09](AUDIT-RESIDUAL-COVERAGE-2026-09.md)
- [TODO](../TODO.md)
