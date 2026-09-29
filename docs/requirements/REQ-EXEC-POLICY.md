# Requirements: Exclusive Execution Policy (REQ-EXEC-*)

**Date:** 2026-09-29
**Status:** DRAFT
**Type:** Requirements
**Specification:** [SPEC-EXEC-POLICY](../specifications/SPEC-EXEC-POLICY.md)
**Related:** [REQ-SHELL-GUARD](REQ-SHELL-GUARD.md), [REQ-SANDBOX](REQ-SANDBOX.md), [REQ-GIT-GUARD](REQ-GIT-GUARD.md)

---

## Background

The host adopts an **exclusive execution posture**: process execution is
deny-by-default, and only a reviewed allowlist of executables may run in the
agent's confined session. The posture is always on, enforced in the kernel,
and fail-closed.

The existing [SPEC-SHELL-GUARD](../specifications/SPEC-SHELL-GUARD.md) is a
userspace raw-text scanner on `/bin/bash`. It is a content policy, not an
execution authority: any non-bash parent can `execve` an arbitrary binary,
and `/bin/sh` resolves to unwrapped `dash`
([AUDIT-RESIDUAL-COVERAGE](../AUDIT-RESIDUAL-COVERAGE-2026-09.md) D-04). This
document makes the kernel the authority.

The posture follows a **single-owner law**: each concern has exactly one
owner, no concern is decided by two layers, and no layer substitutes for
another. The exec lane is an **eBPF LSM**; the filesystem and effects lanes
are **AppArmor**; ptrace is **YAMA**; kernel code is **Lockdown**;
capabilities are the **capability LSM** plus the agent unit bounding set. The
rule-by-rule treatment of the existing shell-guard policy is normative in
[SPEC-EXEC-POLICY section 7](../specifications/SPEC-EXEC-POLICY.md#7-rule-disposition-matrix).

---

## 1. Posture (REQ-EXEC-100 series)

- **REQ-EXEC-100**: Process execution shall be deny-by-default in the
  confined agent session; only executables present in the allowlist may run.
- **REQ-EXEC-101**: The posture shall be always on and shall not depend on a
  per-workload sandbox launch.
- **REQ-EXEC-102**: The enforcement authority shall be the Linux kernel, not a
  userspace wrapper around a shell.
- **REQ-EXEC-103**: The posture shall be fail-closed: the agent session shall
  refuse to start unless every lane owner is verified active. There shall be
  no state in which the agent session runs unenforced and no layer shall
  substitute for a missing owner.
- **REQ-EXEC-104**: Root shall remain break-glass and unconfined; the agent
  shall have no path to modify the policy, stop the loader, or unload the
  program.
- **REQ-EXEC-105**: The posture shall not alter the shell guard's content
  contract; the two shall coexist as specified in
  [SPEC-EXEC-POLICY section 8](../specifications/SPEC-EXEC-POLICY.md#8-shell-guard-coexistence).

## 2. Exec Lane (REQ-EXEC-110 series)

- **REQ-EXEC-110**: The exec owner shall be a `BPF_PROG_TYPE_LSM` program
  attached to `bprm_check_security`, mediating every `execve`/`execveat`.
- **REQ-EXEC-111**: The program shall allow only executables whose identity
  matches an allowlist entry; a decision shall require a content-hash match,
  not a path match alone.
- **REQ-EXEC-112**: The program shall deny anonymous and `memfd`
  (`execveat(AT_EMPTY_PATH)`) execution by default.
- **REQ-EXEC-113**: The loader (`workspace-exec-policyd`) shall run at boot
  before the agent login service and shall attach the program before any agent
  process exists.
- **REQ-EXEC-114**: The loader shall require `CAP_BPF` and `CAP_SYS_ADMIN`;
  the agent shall have neither.
- **REQ-EXEC-115**: Enabling BPF LSM (`bpf` appended to the kernel `lsm=`
  list) shall be an operator action, documented with the exact value and the
  required reboot; until it is enabled the agent session shall not start.
- **REQ-EXEC-116**: The loader shall publish the loader token
  `/run/workspace-exec-policy/bpf-ready` only after the program link is
  attached, and the arming step shall require it.
- **REQ-EXEC-117**: Allowlist updates shall take effect through a pinned map
  reload without recompiling the program and without restarting agents.
- **REQ-EXEC-118**: A program or map load failure, or a failed policy hash
  check, shall be fail-closed.
- **REQ-EXEC-119**: The program shall decide only for tasks in the agent
  session, by cgroup and task ancestry, and shall return allow for every other
  task.

## 3. Single-Owner Lanes (REQ-EXEC-120 series)

- **REQ-EXEC-120**: AppArmor shall own the filesystem lane and the effects
  lane. Its profile shall be installed and loaded in enforcing mode; there
  shall be no complain state. It shall grant `/** ix`, `ptrace,` and
  `capability,` so that it is never a second decider for exec, ptrace, or
  capability.
- **REQ-EXEC-121**: Ptrace shall be owned by YAMA at `ptrace_scope=2`; kernel
  code shall be owned by Lockdown `integrity`; capabilities shall be owned by
  the capability LSM plus the agent unit bounding set. No layer other than
  the owner shall write a rule for these concerns.
- **REQ-EXEC-122**: Every lane shall be installed by the same reconcile target
  and verified by the same drift check.
- **REQ-EXEC-123**: No lane shall decide another lane's concern, and no lane
  shall substitute for another. A layer whose sole unique property is already
  provided by an owner (Landlock, IMA, EVM) shall hold no lane; the rationale
  shall be recorded in the specification.
- **REQ-EXEC-124**: The readiness manifest `/run/workspace-exec-policy/ready`
  shall list every lane owner, and the session gate shall require all of them.

## 4. Effect Coverage (REQ-EXEC-130 series)

- **REQ-EXEC-130**: Signals to processes outside the session's descendant
  tree shall be denied by AppArmor (effects lane).
- **REQ-EXEC-131**: Mount and unmount of every path shall be denied by
  AppArmor (effects lane).
- **REQ-EXEC-132**: Writes to block devices and to guard-owned policy and
  audit state shall be denied by AppArmor (filesystem lane).
- **REQ-EXEC-133**: Immutability tampering shall be denied by the filesystem
  lane and by the absence of `CAP_LINUX_IMMUTABLE` in the capability lane.
- **REQ-EXEC-134**: Kernel module load and kexec image read shall be denied by
  Lockdown (kernel-code lane).
- **REQ-EXEC-135**: `AF_ALG`, raw and packet socket families shall be denied
  by AppArmor (effects lane).
- **REQ-EXEC-136**: A missing lane owner shall be fail-closed: the session
  refuses to start, and the finder reports `DRIFTED`.

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
  [SPEC-EXEC-POLICY section 7](../specifications/SPEC-EXEC-POLICY.md#7-rule-disposition-matrix).
- **REQ-EXEC-151**: A build-time or shell gate shall fail if a policy rule has
  no disposition entry, so a rule cannot be added without one. Implemented by
  `scripts/check-exec-dispositions.sh`, run from `make check`
  (`make check-exec-dispositions`) and the pre-push gate.
- **REQ-EXEC-152**: A kernel-owned rule may be removed from the policy file
  only after the owning lane is proven to deny the effect for path,
  renamed-copy and syscall forms and an audit record is produced.
- **REQ-EXEC-153**: `content` rules (output suppression, inline-code contract,
  argv-dependent inline forms) shall remain in the shell guard permanently
  until a documented argv-enforcement phase supersedes them.

## 7. Audit and Detection (REQ-EXEC-160 series)

- **REQ-EXEC-160**: Every denial shall be logged with timestamp, uid, pid/ppid,
  path or `<anon>`, hash, and denying lane, without downgrading the denial on
  log failure.
- **REQ-EXEC-161**: Loader readiness, map reload, and link attach/detach shall
  be logged.
- **REQ-EXEC-162**: The audit destination and mode shall follow
  [SPEC-AUDIT](../specifications/SPEC-AUDIT.md).

## 8. Installation, Arming, Recovery (REQ-EXEC-170 series)

- **REQ-EXEC-170**: `make build-exec-policy`, `make install-exec-policy`
  (root), and `make check-exec-policy` shall build, install/reconcile, and
  verify the loader, program, map seed, AppArmor profile, session gate, unit
  and drop-in.
- **REQ-EXEC-171**: Install shall be idempotent and reconciling, matching the
  guard install precedent.
- **REQ-EXEC-172**: `check-exec-policy` shall be read-only and shall report
  `NOT INSTALLED` (exit 2), `NOT ARMED` (exit 0 with a warning), `OK` (exit 0
  when armed and every owner verified), and `DRIFTED` (exit 1 when armed but
  an owner is not verified).
- **REQ-EXEC-173**: A documented recovery procedure shall exist for an
  over-restrictive policy: unconfined root may stop the loader; the agent
  cannot invoke this path.
- **REQ-EXEC-174**: The boot-param change and reboot shall be recorded as an
  operator step in the deployment documentation.
- **REQ-EXEC-175**: `install-exec-policy` shall stage every lane and leave
  state `unarmed`. `enable-exec-policy` shall require `CONFIRM=1`, the staged
  layers, the seeded policy, and every lane owner verified; it shall run a
  denial canary and stay `unarmed` on canary failure.
- **REQ-EXEC-176**: `scripts/guard-operator.sh` shall stage the posture on
  `up`/`refresh` (warn-only; never arm), report it on `check`, and unstage it
  on `down`. Arming shall remain the explicit `enable-exec-policy` target
  alone.
- **REQ-EXEC-177**: The posture shall use the state files
  `/etc/workspace-guard/exec-policy-state` (`unarmed|armed`),
  `/etc/workspace-guard/exec_allowlist.yaml` (installed from the reviewed
  source), `/run/workspace-exec-policy/bpf-ready` (loader token), and
  `/run/workspace-exec-policy/ready` (readiness manifest). The session-gate
  drop-in on the agent unit shall refuse the session unless state is `armed`
  and the manifest lists every owner.

## 9. Testing (REQ-EXEC-180 series)

- **REQ-EXEC-180**: A kernel matrix shall prove: allowlisted exec passes;
  non-listed path denied; renamed copy denied by hash; `dash`/`zsh` and
  interpreters denied; `memfd`/`execveat(AT_EMPTY_PATH)` denied; mount denied;
  signal outside the tree denied; `AF_ALG` denied; device write denied; module
  load and kexec denied; ptrace outside the tree denied.
- **REQ-EXEC-181**: A test shall prove the confined session refuses to start
  when any lane owner is missing (fail-closed).
- **REQ-EXEC-182**: A test shall prove no agent-writable file changes the allow
  decision.
- **REQ-EXEC-183**: The shell suite shall cover the staging and arming state
  machine (`tests/shell/26-exec-policy-provisioning.bats`), install/reconcile/
  check, and the session gate; the loader suite shall cover policy parse,
  hash mismatch, and the readiness gate.
- **REQ-EXEC-184**: The disposition gate of REQ-EXEC-151 shall be exercised by
  a negative test.

---

## Non-Goals

- No confinement of root (break-glass).
- No per-workload sandbox requirement in this document (see
  [REQ-SANDBOX](REQ-SANDBOX.md)).
- No network egress policy beyond the socket families in REQ-EXEC-135.
- No elimination of the shell guard's content contract in this phase.

---

## Traceability

| Requirement | Spec section |
| --- | --- |
| REQ-EXEC-100-105 | SPEC-EXEC-POLICY section 1, 3 |
| REQ-EXEC-110-119 | SPEC-EXEC-POLICY section 3, 4 |
| REQ-EXEC-120-124 | SPEC-EXEC-POLICY section 3, 5, 6 |
| REQ-EXEC-130-136 | SPEC-EXEC-POLICY section 5, 6, 12 |
| REQ-EXEC-140-144 | SPEC-EXEC-POLICY section 4 |
| REQ-EXEC-150-153 | SPEC-EXEC-POLICY section 7 |
| REQ-EXEC-160-162 | SPEC-EXEC-POLICY section 10 |
| REQ-EXEC-170-177 | SPEC-EXEC-POLICY section 9 |
| REQ-EXEC-180-184 | SPEC-EXEC-POLICY section 11 |
