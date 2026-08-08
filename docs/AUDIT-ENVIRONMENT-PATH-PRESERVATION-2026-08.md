# Environment and PATH Preservation Audit

**Date:** 2026-08-07  
**Scope:** Shell guard, Git guard, guarded child processes, SSH helpers, tests, configuration, and requirements  
**Status:** Open audit; remediation tracked in the session task list

## Executive Summary

The guard stack does not have one environment policy. It has several
independent policies with materially different behavior:

1. The shell guard rebuilds the child environment from an allowlist and
   forcibly sets `PATH=/usr/local/bin:/usr/bin:/bin`.
2. The Git guard rebuilds another environment from a separate allowlist,
   forcibly sets the same PATH, and replaces `HOME` with a resolved value.
3. Git, CI, remote, Git-dir, and SSH helper subprocesses repeatedly call
   `env_clear()` and add small hand-written environment subsets.
4. The binary guard instead copies the caller environment and removes only
   policy-listed variables.

This inconsistency caused a directly observable regression: the shell used by
Opencode could no longer resolve `browser`, because the command is installed
under `/home/agent/WORKSPACE-VM/.boot-linux/bin`, which the shell guard removes
from PATH. The browser launcher resolves to the workspace virtualenv and is a
normal part of the caller's tool environment.

The correct baseline for ordinary child execution is caller-environment
preservation. Security must come from absolute paths for guard-owned
executables and narrowly scoped removal of variables that are explicitly
classified as unsafe for a particular privileged operation. A blanket PATH
reset is not an acceptable substitute for absolute executable paths.

## Findings

### F-001: Shell guard destroys caller PATH

**Location:** `src/shell_guard.rs:25`, `src/shell_guard.rs:318-347`

`build_envp` iterates a fixed allowlist, drops all other variables, and then
appends a hardcoded PATH. The caller's PATH is never consulted for the child.

Observed consequence:

```text
browser: command not found
```

The affected launcher is:

```text
/home/agent/WORKSPACE-VM/.boot-linux/bin/browser
```

The current implementation also removes project-local binaries, language
runtimes, virtual environments, package-manager shims, and other toolchain
entries that were intentionally present in the invoking environment.

**Severity:** Critical functional regression for agent-mediated shell calls.

### F-002: Shell guard performs allowlist reconstruction rather than filtering

**Location:** `src/shell_guard.rs:27-44`, `src/shell_guard.rs:318-347`

The implementation copies only selected exact names and prefixes. It drops
all other caller variables, including application-specific variables and
toolchain state. `SHG_SCRIPT_PATH` is then injected after the filter as a
special case.

This creates two environment semantics in one function: destructive filtering
followed by post-filter reinsertion. The special case is appropriate for a
guard-owned provenance value; applying the same pattern to normal caller state
is not.

**Severity:** High functional incompatibility and maintenance risk.

### F-003: Git guard repeats a separate allowlist and PATH reset

**Location:** `src/exec.rs:227-255`

The Git exec path independently iterates generated `ALLOWED_VARS`, skips and
re-adds `HOME`, then appends `PATH=CHILD_PATH`. This does not share semantics
with the shell guard or binary guard.

**Severity:** High consistency and compatibility risk.

### F-004: Multiple helper subprocesses clear the environment

The following paths independently discard the caller environment:

- `src/exec.rs:353-355`
- `src/exec.rs:431-438`
- `src/ci_integrity.rs:44-52`
- `src/ci_integrity.rs:146-154`
- `src/ci_integrity.rs:189-195`
- `src/remote.rs:33-45`
- `src/gitdir.rs:307-316`
- `src/git_ssh.rs:109-115`
- `src/git_ssh.rs:126-136`
- `src/git_ssh.rs:144-155`

Most of these add only PATH and `HOME=/`. Git-dir resolution restores
`GIT_DIR` and `GIT_WORK_TREE` afterward. SSH helpers separately restore
SSH-specific variables. This is repeated discard/re-add logic with no single
auditable contract.

**Severity:** High; behavior differs by subprocess and can silently break
credentials, plugins, user configuration, agent tooling, locale, desktop
integration, and project runtimes.

### F-005: HOME is rewritten in multiple child contexts

**Locations:**

- `src/exec.rs:240-243`
- `src/exec.rs:354-355`
- `src/exec.rs:432-434`
- `src/ci_integrity.rs:46-48,148-150,190-192`
- `src/remote.rs:35-37`
- `src/gitdir.rs:309`

The main Git child receives a resolved safe home, while helper children often
receive `/`. This is security-heavy behavior applied to ordinary inspection
and contract operations without a documented per-operation necessity.

**Severity:** High compatibility risk.

### F-006: SSH helpers use a third PATH policy

**Location:** `src/git_ssh.rs:40`, `src/git_ssh.rs:112-151`

SSH subprocesses use `CHILD_PATH_ENV=/usr/bin:/bin`, which differs from both
the shell guard and Git guard. They also clear all inherited variables before
adding a small SSH-specific set.

**Severity:** Medium to high; especially risky for SSH agent integrations and
workspace-provided helper binaries.

### F-007: Binary guard has incompatible, more permissive semantics

**Location:** `src/binary_guard.rs:250-265`

The binary guard copies all caller variables and removes only entries listed in
its policy. It does not force PATH. This is materially closer to the desired
behavior, but it means the same caller sees different environments depending
on which guard is invoked.

**Severity:** High policy inconsistency.

### F-008: Configuration and requirements mandate the bad behavior

**Locations:**

- `config/shared_paths.yaml:19`
- `config/git_guard_environment.yaml:16-35`
- `docs/requirements/REQ-SHELL-GUARD.md:399-426`
- `REQUIREMENTS.md:63`
- `src/shell_guard_tests.rs:218-225`

The hardcoded PATH and allowlist behavior are encoded in configuration,
requirements, and tests. A code-only fix would be rejected by the repository's
own consistency expectations or would leave contradictory documentation.

**Severity:** High; remediation must update the contract and tests together.

## Security Boundary Clarification

Preserving the caller environment does not require using caller PATH to locate
guard-owned executables. These are separate concerns:

- Guard-owned binaries must continue to execute through absolute verified
  paths.
- Child processes that intentionally inherit the caller environment may use
  the caller PATH for their own normal command resolution.
- Variables with a concrete, documented security impact may be removed by a
  narrow operation-specific policy.
- A blanket PATH reset must not be used to compensate for a caller-controlled
  executable lookup where the guard can use an absolute path instead.

The audit does not authorize restoring known dynamic-loader injection values
inside a capability-sensitive guard without classification. Those variables
must be handled explicitly and tested. The required default is preservation,
not an undocumented allowlist.

## Required Invariants

1. Ordinary guarded shell execution preserves the caller environment and PATH.
2. `browser` and other caller-visible workspace tools remain discoverable.
3. No guard-owned executable is resolved through an uncontrolled PATH lookup.
4. Child-specific additions are explicit and do not require `env_clear()`.
5. Any removed variable has a named policy reason and a regression test.
6. Shell, Git, binary, SSH, CI, and remote paths use one documented model.
7. Guard provenance values such as `SHG_SCRIPT_PATH` cannot be spoofed by the
   caller.
8. Tests distinguish environment preservation from absolute-path enforcement.

## Remediation Worklist

### Phase 1: Policy

- Define the shared preservation helper and its narrow exclusion interface.
- Classify dynamic-loader, shell injection, Git bypass, and guard provenance
  variables separately.
- Decide which operations genuinely require a reduced environment rather than
  inheriting the caller environment.

### Phase 2: Shell guard

- Replace allowlist reconstruction with caller-environment preservation.
- Preserve caller PATH.
- Keep only explicitly justified removals.
- Continue injecting `SHG_SCRIPT_PATH` after caller values are removed and
  reject caller spoofing.
- Update unit and Bats coverage for PATH, browser, custom variables, and
  dangerous-variable handling.

### Phase 3: Git and helpers

- Remove unnecessary `env_clear()` calls.
- Replace fixed PATH/HOME assignments with inherited values unless a specific
  operation documents a reduced environment.
- Keep absolute paths for guard-owned Git, SSH, and shell executables.
- Centralize child-specific additions to prevent repeated re-add logic.

### Phase 4: Contract and verification

- Update configuration and requirements that mandate hardcoded PATH or full
  allowlists.
- Replace tests that assert PATH destruction with preservation tests.
- Add cross-guard consistency tests.
- Run focused tests, `make test-shell`, and the Rust gates required by
  `AGENTS.md`.

## Non-Goals

- This audit does not weaken absolute-path execution for guard-owned tools.
- This audit does not remove policy checks for destructive commands.
- This audit does not modify unrelated staged or untracked worktree changes.
- This audit does not silently preserve variables that are proven to subvert
  the guard itself; those require explicit classification and tests.
