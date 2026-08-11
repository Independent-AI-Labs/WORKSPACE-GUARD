# Shell and Execution Surface Audit

Date: 2026-08-06
Scope: WORKSPACE-GUARD repository, including Rust binaries, shell guard,
operator scripts, Makefile recipes, Podman/QEMU harnesses, policy files, and
the documented execution contract.

## Executive Summary

The repository has several independent execution layers, but the policy model
only fully controls one of them: text passed to the guarded Bash binary. The
other layers can execute interpreters, write executable files, launch shells,
or invoke host programs without passing through the shell guard scanner.

The most important contradiction is that the repository explicitly permits
`uv run python -c` in the shell policy matrix while also describing `uv` as
the sanctioned Python launcher. `uv` is a launcher, not a justification for
inline Python. The command remains an inline, unscanned interpreter channel.

The second critical issue is the production fallback in
`scripts/lib/host-provision-admin.sh`: it invokes Perl both with `-e` and with
a heredoc. Those paths are not `uv`-managed and are not blocked when the
script is scanned as a script body because `alt-interp` is command-scoped.

The shell guard also cannot see tool-mediated writes or direct subprocesses.
`apply_patch`-style writes, Rust `Command`, and binaries launched directly by
the operator/tool layer require a separate execution and file-write control.

This audit is an inventory and gap report. It does not claim that every listed
test fixture is a production vulnerability. Test and provisioning fixtures are
listed because they define behavior that can be copied into production paths
or can invalidate the repository's stated no-inline-code contract.

## Control Model Found

### Shell guard

`src/shell_guard.rs` classifies invocations into:

- `-c` command text, scanned with `find_hit(..., false)`.
- Script-file content, scanned with `find_hit(..., true)`.
- Interactive/pass-through invocations, which are not scanned.

`config/shell_guard_policy.yaml` has scope-aware regex rules. The interpreter
rule `alt-interp` is `scope: command`, so interpreter calls in script bodies
are deliberately allowed. This is documented by `REQ-SHG-313` and the shell
guard specification, but it conflicts with the stronger repository objective
that inline code must never be used.

### Rust subprocesses

Rust code launches processes directly with `std::process::Command` or
`nix::execve`. Those calls do not pass through shell text scanning. Some use
absolute paths and sanitized environments; others use bare names and are
test-only. The repository has no single centralized subprocess allowlist.

### Shell scripts and Makefile

Shell scripts execute commands directly. Their own source is scanned only when
they are passed as script operands to the guarded shell, and only according to
the script scope rules. Make recipes, CI hooks, Podman entrypoints, and tool
wrappers can therefore create additional execution boundaries.

### Tool-mediated actions

File-writing tools and external orchestration are outside the shell guard. A
patch tool can write an interpreter heredoc without executing Bash first. The
shell guard cannot retroactively inspect or approve that write.

## Findings

### SHG-001 Critical: Inline Python is explicitly allowed under `uv run`

Evidence:

- `config/shell_guard_policy_matrix.yaml:140-143` marks
  `uv run python -c print(1)` as `allowed`.
- `docs/requirements/REQ-SHELL-GUARD.md:373-376` exempts all `uv run python`
  forms.
- `docs/OPERATOR.md:43-48` repeats that exemption.

Impact: `uv run python -c`, `uv run python -`, stdin-fed Python, and similar
forms provide an inline interpreter channel. The launcher being approved does
not make the payload reviewable or isolated.

Required direction: allow `uv run python path/to/script.py` only when the
target is an explicit approved script file. Block `-c`, `-`, heredoc/stdin
payloads, `exec`, `eval`, and equivalent inline options for every interpreter.

### SHG-002 Critical: Untrusted shell scripts allow general interpreters

Evidence:

- `src/shell_guard.rs` scans untrusted scripts, while trusted direct regular
  scripts are classified by provenance and executed by path without body
  scanning.
- `config/shell_guard_policy.yaml:67-70` sets `alt-interp` to
  `scope: command`.
- `scripts/lib/host-provision-admin.sh:183-200` executes Perl from a script
  body, including a heredoc.

Impact: an agent-writable Bash script can contain Python, Perl, Node, Ruby,
Lua, PHP, Awk, or another interpreter and execute an unscanned payload.

Required direction: add an untrusted-script context and reject interpreter
execution there except for explicit extension-qualified script files that are
validated as isolated artifacts. Trusted status must not silently authorize
inline code if the repository contract is “no inline code”.

### SHG-003 Critical: Production Perl fallback violates the UV-only contract

Evidence:

- `scripts/lib/host-provision-admin.sh:74-84` falls back to bare `perl -e`.
- `scripts/lib/host-provision-admin.sh:177-205` falls back to `perl - ... <<'PERL'`.
- No `uv run` is used for either operation.

Impact: password generation and password verification execute unsanctioned
interpreter code on the host. The heredoc is precisely an inline payload.

Required direction: replace both with a checked-in, extension-qualified,
reviewed implementation executed through the sanctioned launcher, or use a
compiled implementation. No bare Perl fallback should remain.

### SHG-004 High: Heredoc payloads are not modeled as a policy class

Evidence:

Heredoc writers and payloads occur in:

- `scripts/podman/e2e-yaml-edit.sh:35,42`
- `scripts/podman/e2e-host-exec.sh:117`
- `scripts/podman/e2e-policy-matrix.sh:29`
- `scripts/podman/lib/host-provision-e2e.sh:60,75,97,223`
- `scripts/podman/e2e-host-provision-safety.sh:154`
- the external real-Linux guest shell-guard suite
- `scripts/lib/host-provision-admin.sh:184`

Impact: the guard does not distinguish a data heredoc, a shell program, or an
interpreter program delivered through stdin. A heredoc can therefore create a
second code channel even when the outer command contains no obvious inline
interpreter token.

Required direction: block interpreter stdin/heredoc forms in all untrusted
contexts and add explicit policy tests for `python3 - <<EOF`, `perl -`,
`node < file`, and equivalent launcher-wrapped forms.

### SHG-005 High: Nested inline shells remain an unscanned code channel

Evidence:

- `src/shell_guard.rs:97-105` scans only a `-c` operand when it identifies
  the `-c` flag in the current Bash invocation.
- Nested Bash and `sh` are intentionally allowed by the requirements because
  they are expected to re-enter the guard.
- Podman and test runners use `bash -c` extensively, for example
  `scripts/podman/run-shell-tests.sh:29` and `run-tier12.sh:41-53`.

Impact: the guarantee depends on every nested shell resolving to the guarded
path. A path-qualified, copied, container-provided, or alternate shell can
execute inline code outside the host guard.

Required direction: block inline shell payloads in untrusted script bodies and
command text unless the executable is proven to be the installed guard path.
Treat container entrypoints as a separate explicitly sanctioned harness
boundary, not as ordinary agent shell text.

### SHG-006 High: Tool-mediated writes bypass all shell scanning

Evidence:

- The shell guard only receives Bash command arguments or script operands.
- Patch/file-write tooling can create a script containing an interpreter
  heredoc without invoking the guarded shell scanner.
- The repository has no file-write admission controller tying writes to the
  shell policy.

Impact: a prohibited payload can be written to an agent-owned file even if its
later execution is blocked. If another tool, service, executable bit, or
operator action executes that file, the write-time policy was bypassed.

Required direction: enforce file-write policy at the tool/agent boundary or
through an independent filesystem admission layer. The shell guard alone
cannot solve this gap.

### SHG-007 High: Direct Rust subprocesses bypass shell policy and lack one allowlist

Production subprocess sites include:

- `src/exec.rs:353`: direct Git resolver command.
- `src/exec.rs:431-441`: direct `/bin/bash` contract checker.
- `src/gitdir.rs:308`: direct Git invocation.
- `src/remote.rs:34`: direct remote Git invocation.
- `src/git_ssh.rs:110-155`: direct `ssh-add` and `ssh-agent` invocations.
- `src/yaml_edit_install.rs:21-44`: direct `lsattr` and `chattr`.
- `src/yaml_edit_ops.rs:214-217`: bare `date` invocation.

Impact: these processes never pass through shell regex policy. The direct
`date` call is PATH-sensitive and violates the repository's preference for
absolute, controlled executables. The direct `/bin/bash` launch is a separate
shell entrypoint requiring explicit guard validation.

Required direction: define a centralized Rust subprocess policy with absolute
paths, per-binary argument contracts, environment construction, timeouts, and
audit classification. Remove unnecessary external calls such as `date` where
Rust can provide the value directly.

### SHG-008 High: Bare system interpreters are used by operational scripts

Evidence:

- Bare Perl appears in `scripts/lib/host-provision-admin.sh:79-80` and
  `:183-200`.
- Awk is used extensively by operational shell libraries, including
  `scripts/lib/binary-lock-yaml.sh`, `host-provision-parse.sh`,
  `sandbox-profile.sh`, and `decode-caps.sh`.
- The policy treats Awk as a general-purpose interpreter only in command
  position, not as a script-body execution class.

Impact: the repository says higher-level interpreter use must be controlled by
`uv run`, but the operational shell layer has no equivalent allowlist for Awk
or Perl. Awk is a language execution channel even when used for text parsing.

Required direction: classify approved standard text processors separately from
general-purpose interpreters, pin them to absolute system paths, and prohibit
dynamic program text in untrusted contexts. Remove Perl entirely unless it is
converted to an approved isolated script.

### SHG-009 High: Command policy is raw regex, not shell grammar

Evidence:

- `config/shell_guard_policy.yaml:3-13` documents unanchored raw-text matching.
- `docs/requirements/REQ-SHELL-GUARD.md:631-634` accepts grammar evasion as a
  non-goal.

Impact: quoting splits, variable expansion, aliases, functions, command
substitution, redirections, process substitution, and encoded payloads can
change execution semantics without matching the intended token form.

Required direction: use a restricted execution model rather than attempting to
turn regexes into a shell parser. At minimum, reject code-bearing constructs
such as command substitution, process substitution, here-documents, `eval`,
`source` of agent paths, function definitions, aliases, and dynamic expansion
in untrusted script bodies.

### SHG-010 Medium: Interactive/pass-through paths are intentionally unscanned

Evidence:

- `src/shell_guard.rs:83-85` passes `--help` and `--version` through.
- `src/shell_guard.rs:106-107` passes interactive `-i` through.
- `src/shell_guard.rs:451` executes `Invocation::PassThrough` without content
  scanning.

Impact: interactive input is not inspected by the raw command scanner. The
security model depends on the guarded shell being the only shell and on other
layers controlling interactive execution.

Required direction: document this as a deliberate boundary and enforce the
same interpreter and inline-code restrictions at the interactive permission
layer. Do not represent pass-through as policy approval.

### SHG-011 Medium: Podman harnesses are broad execution boundaries

Evidence:

- `scripts/podman/run-tier12.sh:38-53` launches `bash -c` inside a container.
- `scripts/podman/run-tier3.sh` and `run-tier3-provision.sh` launch container
  shells, including privileged tiers.
- `scripts/podman/run-shell-tests.sh:23-29` builds and runs a container with
  mounted project content.

Impact: host shell scanning does not inspect the complete command text or
files executed inside the container. Privileged tiers can create host-like
effects inside the test environment, and mounted source can contain arbitrary
payloads.

Required direction: make harness entrypoints fixed, extension-qualified files;
avoid inline `bash -c` bodies; use immutable or read-only source mounts where
possible; and add a container execution policy that validates image, mounts,
privileges, entrypoint, and command vector.

### SHG-012 Medium: Test fixtures normalize prohibited patterns

Evidence:

- `config/shell_guard_policy_matrix.yaml:105-174` contains allowed script
  interpreter examples and an allowed `uv run python -c` case.
- Multiple Podman and QEMU fixtures construct scripts with heredocs.

Impact: tests encode the current permissive behavior as correct. Regression
tests therefore protect the wrong contract and make future tightening look
like a regression.

Required direction: split fixtures into `approved-isolated-script` and
`prohibited-inline-code` classes. Delete allowed inline interpreter vectors and
replace them with extension-qualified file vectors.


Evidence:

- `docs/OPERATOR.md:43-48` says interpreters may run from script bodies.
- `REQ-SHG-313` and `SPEC-SHELL-GUARD.md` define script-level interpreter
  confinement as out of scope.
- `REQ-SANDBOX.md:416-420` and `:472-474` say bare interpreters must not be
  used outside `uv run`, but operational Perl paths violate that statement.

interpreters are allowed, whether `uv run -c` is allowed, or whether Awk is a
sanctioned standard tool.

extension-qualified isolated scripts; only sanctioned launchers; direct
subprocesses require explicit allowlist entries. Update requirements, specs,
operator docs, matrix, and tests together.



- The shell guard controls `/bin/bash` and conditionally `/bin/sh` only.
- Rust `Command` calls and external tool invocations do not enter
  `config/shell_guard_policy.yaml`.
- The repository's commit gates validate source and tests but do not provide a
  universal execution broker for tools.

shell guard reports a healthy posture.

allowlist for commands, arguments, paths, write destinations, and interpreters.
The shell guard should remain one defense, not the universal execution policy.


|---|---|---|---|
| `bash -c` | Raw regex command scan | Grammar and inline payload gaps | Critical |
| Bash script body | Raw regex script scan | `alt-interp` excluded by scope | Critical |
| `uv run python -c` | Explicitly allowed | Inline interpreter channel | Critical |
| Perl fallback | Bare Perl and heredoc | Not UV-managed or isolated | Critical |
| Heredoc stdin | No general rule | Code channel not modeled | High |
| Nested shell | Expected re-entry | Copies/containers can escape | High |
| Rust `Command` | Per-call controls | No central allowlist | High |
| Podman | Harness conventions | Broad privileged container boundary | Medium/High |
| QEMU | Guest boundary | Fixture scripts and shell commands | Medium |
| Tool writes | No shell involvement | Write-time policy absent | Critical |
| Awk/text tools | Bare system commands | No explicit command allowlist | High |
| Interactive shell | Pass-through | No command scanner coverage | Medium |

## Required Remediation Sequence

1. Establish the normative “no inline code” contract in requirements and
   policy schema.
2. Remove `uv run python -c` and all equivalent allowed matrix cases.
3. Add script-context restrictions for all general-purpose interpreters.
4. Replace the production Perl paths with approved isolated implementations.
5. Add heredoc, stdin, command-substitution, process-substitution, `eval`,
   `source`, background, and nested-shell regressions.
6. Centralize Rust subprocess policy and eliminate avoidable bare commands.
7. Refactor Podman/QEMU entrypoints from inline shell strings into fixed script
   files with explicit mounts and privilege contracts.
8. Add a tool/file-write admission layer; do not claim the shell guard covers
   patch tools or direct external tool calls.
9. Update all contradictory docs and policy matrices.
10. Rebuild and reinstall the guard, then run the full shell, Rust, Podman, and
    authoritative QEMU gates.

## Residual Boundary

Even after the shell policy is tightened, a shell guard cannot enforce a
universal “no unsanctioned system calls” rule. It observes shell invocation
text, not arbitrary syscalls, direct process launches, container internals,
editor/tool writes, or interpreter behavior. That requirement needs a
separate execution broker and sandbox layer with syscall, process, filesystem,
and network controls.
