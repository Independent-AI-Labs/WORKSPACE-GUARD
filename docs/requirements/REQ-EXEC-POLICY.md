# Requirements: Exclusive Execution Policy (REQ-EXEC-*)

**Date:** 2026-09-28
**Status:** DRAFT
**Type:** Requirements
**Specification:** [SPEC-EXEC-POLICY](../specifications/SPEC-EXEC-POLICY.md)
**Related:** [REQ-SHELL-GUARD](REQ-SHELL-GUARD.md), [REQ-SANDBOX](REQ-SANDBOX.md), [REQ-GIT-GUARD](REQ-GIT-GUARD.md)

---

## Background

The host adopts an **exclusive execution posture**: process execution is
deny-by-default, and only a reviewed allowlist of executables may run in the
agent's confined session. The posture is always on, enforced in the kernel, and
fail-closed.

The existing [SPEC-SHELL-GUARD](../specifications/SPEC-SHELL-GUARD.md) is a
userspace raw-text scanner on `/bin/bash`. It is a content policy, not an
execution authority: any non-bash parent can `execve` an arbitrary binary, and
`/bin/sh` resolves to unwrapped `dash`
([AUDIT-RESIDUAL-COVERAGE](../AUDIT-RESIDUAL-COVERAGE-2026-09.md) D-04). This
document makes the kernel the authority.

The enforcement authority is an **eBPF LSM** program attached to
`security_bprm_check`, backed by AppArmor (interim) and Landlock
(defense-in-depth). The rule-by-rule treatment of the existing shell-guard
policy is normative in
[SPEC-EXEC-POLICY §6](../specifications/SPEC-EXEC-POLICY.md#6-rule-disposition-matrix).

---

## 1. Posture (REQ-EXEC-100 series)

- **REQ-EXEC-100**: Process execution shall be deny-by-default in the
  confined agent session; only executables present in the allowlist may run.
- **REQ-EXEC-101**: The posture shall be always on and shall not depend on a
  per-workload sandbox launch.
- **REQ-EXEC-102**: The enforcement authority shall be the Linux kernel, not a
  userspace wrapper around a shell.
- **REQ-EXEC-103**: The posture shall fail closed: if the authority is not
  attached and the secondary layers are not enforced, the confined session
  shall not start.
- **REQ-EXEC-104**: Root shall remain break-glass and unconfined; the agent
  shall have no path to modify the policy, stop the loader, or unload the
  program.
- **REQ-EXEC-105**: The posture shall not alter the shell guard's content
  contract; the two shall coexist as specified in
  [SPEC-EXEC-POLICY §8](../specifications/SPEC-EXEC-POLICY.md).

## 2. Kernel Authority (REQ-EXEC-110 series)

- **REQ-EXEC-110**: The authority shall be a `BPF_PROG_TYPE_LSM` program
  attached to `bprm_check_security`, mediating every `execve`/`execveat`.
- **REQ-EXEC-111**: The program shall allow only executables whose
  identity matches an allowlist entry; a decision shall require a content-hash
  match, not a path match alone.
- **REQ-EXEC-112**: The program shall deny anonymous and `memfd`
  (`execveat(AT_EMPTY_PATH)`) execution by default.
- **REQ-EXEC-113**: The loader (`workspace-exec-policyd`) shall run at boot
  before the agent login service and shall attach the program before any agent
  process exists.
- **REQ-EXEC-114**: The loader shall require `CAP_BPF` and `CAP_SYS_ADMIN`;
  the agent shall have neither.
- **REQ-EXEC-115**: Enabling BPF LSM (`bpf` appended to the kernel
  `lsm=` list) shall be an operator action, documented with the exact value and
  the required reboot; until it is enabled the posture shall deny by default,
  never allow.
- **REQ-EXEC-116**: The loader shall publish a readiness token only after the
  program link is attached, and the agent session unit shall require it.
- **REQ-EXEC-117**: Allowlist updates shall take effect through a pinned map
  reload without recompiling the program and without restarting agents.
- **REQ-EXEC-118**: A program or map load failure, or a failed policy hash
  check, shall be fail-closed.

## 3. Secondary Layers (REQ-EXEC-120 series)

- **REQ-EXEC-120**: An AppArmor enforce-mode profile bound to the agent session
  shall allow execution only of the allowlisted paths and deny all other
  execution, as the interim authority and the fail-closed backstop.
- **REQ-EXEC-121**: A session wrapper shall apply Landlock rules denying
  `LANDLOCK_ACCESS_FS_EXECUTE` outside the allowlist in addition to
  `PR_SET_NO_NEW_PRIVS`, before the agent process runs.
- **REQ-EXEC-122**: The secondary layers shall be installed by the same
  reconcile target and verified by the same drift check as the authority.
- **REQ-EXEC-123**: The secondary layers shall not weaken the kernel authority
  or permit an executable the authority denies.

## 4. Effect Coverage (REQ-EXEC-130 series)

- **REQ-EXEC-130**: Signals to processes outside the session's descendant tree
  shall be denied (`task_kill`).
- **REQ-EXEC-131**: Mount/umount of guard and system paths shall be denied
  (`sb_mount`/`sb_umount`).
- **REQ-EXEC-132**: Writes to block devices and guard-owned files shall be
  denied (`file_open`/`inode_permission`).
- **REQ-EXEC-133**: Immutability/capability/xattr tampering shall be denied
  (`inode_setxattr` and the file-ioctl path).
- **REQ-EXEC-134**: Kernel module load and kexec image read shall be denied
  (`kernel_read_file`/`kernel_module_request`).
- **REQ-EXEC-135**: `AF_ALG` and unapproved socket families/endpoints shall be
  denied (`socket_create`/`socket_connect`).
- **REQ-EXEC-136**: A failure to attach any required hook shall be treated as
  fail-closed, not as a warning.

## 5. Policy and Provenance (REQ-EXEC-140 series)

- **REQ-EXEC-140**: The allowlist shall be root-owned data at
  `config/exec_allowlist.yaml`, matched by a schema, and edited only through
  the sudo-gated secure YAML editor.
- **REQ-EXEC-141**: The allowlist shall carry, per entry, `path`, `sha256`,
  `allow_uid`, and `note`.
- **REQ-EXEC-142**: A build-time validator shall reject malformed entries,
  non-64-hex hashes, and entries under agent-writable paths.
- **REQ-EXEC-143**: The policy shall be re-read and the map re-seeded on
  reconcile; drift between the file and the pinned map shall be a CRITICAL
  finding.
- **REQ-EXEC-144**: No agent-writable file shall be able to change the allow
  decision.

## 6. Rule Disposition (REQ-EXEC-150 series)

- **REQ-EXEC-150**: Every rule in `config/shell_guard_policy.yaml` shall be
  assigned exactly one disposition in
  [SPEC-EXEC-POLICY §6](../specifications/SPEC-EXEC-POLICY.md):
  `kernel-authoritative`, `hybrid`, `content-policy`, or `session-layer`.
- **REQ-EXEC-151**: A build-time or shell gate shall fail if a policy rule has
  no disposition entry, so a rule cannot be added without a disposition.
- **REQ-EXEC-152**: A `kernel-authoritative` rule may be removed from the
  policy file only after the corresponding hook is proven to deny the effect
  for path, renamed-copy, and syscall forms and an audit record is produced.
- **REQ-EXEC-153**: `content-policy` rules (output suppression, inline-code
  contract, argv-dependent inline forms) shall remain in the shell guard
  permanently until a documented argv-enforcement phase supersedes them.

## 7. Audit and Detection (REQ-EXEC-160 series)

- **REQ-EXEC-160**: Every denial shall be logged with timestamp, uid, pid/ppid,
  path or `<anon>`, hash, and denying policy class, without downgrading the
  denial on log failure.
- **REQ-EXEC-161**: Loader readiness, map reload, and hook attach/detach shall
  be logged.
- **REQ-EXEC-162**: The audit destination and mode shall follow
  [SPEC-AUDIT](../specifications/SPEC-AUDIT.md).

## 8. Installation, Reconcile, Recovery (REQ-EXEC-170 series)

- **REQ-EXEC-170**: `make build-exec-policy`, `make install-exec-policy`
  (root), and `make check-exec-policy` shall build, install/reconcile, and
  verify the loader, program, map seed, AppArmor profile, and session wrapper.
- **REQ-EXEC-171**: Install shall be idempotent and reconciling, matching the
  guard install precedent.
- **REQ-EXEC-172**: `check-exec-policy` shall exit non-zero on any drift and on
  any missing secondary layer.
- **REQ-EXEC-173**: A documented recovery procedure shall exist for an
  over-restrictive policy: unconfined root may stop the loader and load the
  profile in complain mode; the agent cannot invoke this path.
- **REQ-EXEC-174**: The boot-param change and reboot shall be recorded as an
  operator step in the deployment documentation.

## 9. Testing (REQ-EXEC-180 series)

- **REQ-EXEC-180**: A kernel matrix shall prove: allowlisted exec passes;
  non-listed path denied; renamed copy denied by hash; `dash`/`zsh`/interpreters
  denied; `memfd`/`execveat(AT_EMPTY_PATH)` denied; `task_kill` outside the
  tree denied; device write denied; module load denied; `AF_ALG` denied.
- **REQ-EXEC-181**: A test shall prove the confined session refuses to start
  when the loader/program is absent (fail-closed).
- **REQ-EXEC-182**: A test shall prove no agent-writable file changes the allow
  decision.
- **REQ-EXEC-183**: The shell suite shall cover install/reconcile/check and the
  secondary layers; the Rust suite shall cover policy parse, hash mismatch, and
  the readiness gate.
- **REQ-EXEC-184**: The disposition gate of REQ-EXEC-151 shall be exercised by
  a negative test.

---

## Non-Goals

- No confinement of root (break-glass).
- No per-workload sandbox requirement in this document (see
  [REQ-SANDBOX](REQ-SANDBOX.md)).
- No network egress policy beyond the sockets in REQ-EXEC-135.
- No elimination of the shell guard's content contract in this phase.

---

## Traceability

| Requirement | Spec section |
| --- | --- |
| REQ-EXEC-100-105 | SPEC-EXEC-POLICY §1 |
| REQ-EXEC-110-118 | SPEC-EXEC-POLICY §3, §4 |
| REQ-EXEC-120-123 | SPEC-EXEC-POLICY §3, §9 |
| REQ-EXEC-130-136 | SPEC-EXEC-POLICY §7 |
| REQ-EXEC-140-144 | SPEC-EXEC-POLICY §5 |
| REQ-EXEC-150-153 | SPEC-EXEC-POLICY §6 |
| REQ-EXEC-160-162 | SPEC-EXEC-POLICY §10 |
| REQ-EXEC-170-174 | SPEC-EXEC-POLICY §9 |
| REQ-EXEC-180-184 | SPEC-EXEC-POLICY §11 |
