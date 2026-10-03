# Specification: Exclusive Execution Policy (Single-Owner Kernel Posture)

**Date:** 2026-09-29
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-EXEC-POLICY](../requirements/REQ-EXEC-POLICY.md)
**Related:** [SPEC-SHELL-GUARD](SPEC-SHELL-GUARD.md), [SPEC-SANDBOX](SPEC-SANDBOX.md), [SPEC-BINARY-LOCK](SPEC-BINARY-LOCK.md), [SPEC-AUDIT](SPEC-AUDIT.md)

---

## 1. Purpose and Posture

The host adopts an **exclusive execution posture**: process execution is
deny-by-default, and only a reviewed allowlist of executables may run in the
agent's confined session. The posture is **always on** (not a per-workload
sandbox), it is **enforced in the kernel**, and it is **fail-closed**.

### 1.1 The single-owner law

> **One concern, one owner. Each layer decides only its own concern and
> permits every other concern.** No concern is decided by two layers, and no
> layer substitutes for another. There is no staged-but-enforced middle
> state, no complain authority, and no layer that covers for a missing one.

LSMs compose conjunctively: a denial by any layer wins, and a layer that
default-denies every operation implicitly decides every concern. Overlap is
therefore avoided by giving each layer exactly one lane, and by having each
layer either grant-broad (so it is not a decider) or deny exclusively its
own lane.

### 1.2 Layer set

| Lane | Concern | Sole owner | Mechanism |
| --- | --- | --- | --- |
| **Exec** | Which images may be executed | eBPF LSM | `BPF_PROG_TYPE_LSM` on `bprm_check_security` |
| **Filesystem** | Path read/write/create/remove; policy and audit write protection | AppArmor | enforce-mode profile |
| **Effects** | Mount/umount, signals outside the tree, socket families | AppArmor | enforce-mode profile |
| **ptrace** | Process inspection | YAMA | `ptrace_scope=2` |
| **Kernel code** | Module load, kexec, `/dev/mem`, MSR, ioperm | Lockdown | `lockdown=integrity` |
| **Capability** | Which capabilities the session may hold | capability LSM + systemd bounding set | `CapabilityBoundingSet=` |
| **Content** | Shell text with no syscall (output suppression, inline channels) | shell guard | raw-text scanner (SPEC-SHELL-GUARD) |
| **Gate** | Session admission | systemd | `ExecCondition=` readiness manifest |

Landlock, IMA and EVM remain available system layers but hold **no lane in
this posture**. Landlock would require `PR_SET_NO_NEW_PRIVS`, which voids
file capabilities and therefore breaks the four-cap host-exec model
(REQ-GGUARD-001); its only unique property, irrevocable descendant-wide
enforcement, is already provided by AppArmor being root-loaded and inherited
on `ix`. IMA appraisal would re-decide exec content that the eBPF LSM already
owns, with coarser session scoping.

### 1.3 Key design principle

> **Allowlist in the kernel, deny-list in text.** The exec lane allows only
> the executables the operator has reviewed; everything else is denied
> regardless of shell grammar, quoting, aliasing, renaming, or path. The
> textual layer is retained for the contracts that have no kernel-observable
> effect and for explanatory block reports.

---

## 2. Host Enforcement Capability

Observed on the reference host (2026-09-29, kernel `7.1.8`):

| Capability | State | Consequence |
| --- | --- | --- |
| Active LSMs | `lockdown,capability,landlock,yama,apparmor,ima,evm` | `bpf` is **not** active; the exec lane needs a boot cmdline change |
| `CONFIG_BPF_LSM` | `=y` | BPF LSM programs can be built |
| Lockdown | `[none]` | the kernel-code lane needs `lockdown=integrity` |
| YAMA | `ptrace_scope=1` | raise to `2` for the ptrace lane |
| AppArmor | enabled, `apparmor_parser` present | filesystem and effects lanes available now |
| `unprivileged_bpf_disabled` | `2` | only root / `CAP_BPF` may load programs (intended) |

One operator boot change enables the exec and kernel-code lanes:

```
lsm=<existing list>,bpf
lockdown=integrity
```

Preserve the existing LSM entries in their current order and append `bpf`.
Both parameters are operator actions, not agent actions; the reboot is
documented in the deployment runbook (REQ-EXEC-174).

---

## 3. Single-Owner Architecture

```
                       agent session start
                                │
                  systemd ExecCondition: readiness manifest
                  lists every lane owner (fail closed if absent)
                                │
   ┌────────────┬───────────────┼───────────────┬───────────────┐
   ▼            ▼               ▼               ▼               ▼
 exec lane    fs lane        effects lane    ptrace lane    kernel-code lane
 eBPF LSM     AppArmor       AppArmor        YAMA           Lockdown
 bprm_check   (profile)      (profile)       scope=2        integrity
   │                            │
   └─ deny-by-default allowlist; apparmor grants everything outside its
      two lanes (`/** ix`, `ptrace`, `capability`) so it never decides
      exec, ptrace or capability; it denies only filesystem writes it
      does not grant and the effect classes it owns.
```

### 3.1 Lane-keeping rules

- **Exec lane.** The BPF program is attached globally but decides only for
  tasks in the agent session (by cgroup and task ancestry); every other task
  receives `0` (allow). It never mediates mounts, signals, sockets or files.
- **Filesystem and effects lanes.** The AppArmor profile is the sole
  filesystem authorizer and the sole authorizer of mount, signal-outside-tree
  and socket-family operations. It grants `/** ix`, `ptrace,` and
  `capability,` so it is not a second decider for exec, ptrace or capability.
- **ptrace, kernel code, capability lanes.** YAMA, Lockdown and the
  capability LSM plus the agent unit bounding set are global and single;
  no other layer writes a rule for their concerns.

### 3.2 Fail-closed admission

1. The loader (`workspace-exec-policyd`) attaches the program at boot and
   writes the loader token `/run/workspace-exec-policy/bpf-ready` only after
   `BPF_LINK_CREATE` succeeds.
2. `enable-exec-policy CONFIRM=1` verifies every lane owner and, only then,
   writes the readiness manifest `/run/workspace-exec-policy/ready` with one
   line per owner, and sets state `armed`.
3. The agent unit's `ExecCondition=` gate requires state `armed` and every
   owner line. If any owner is absent, the session refuses to start. No
   layer substitutes for another.

There is no `audit` state in which the agent runs unenforced. Staging
installs the layers and leaves state `unarmed`; while unarmed the agent
session does not start. Building the allowlist happens out of band, under
root, never by running the real agent session.

---

## 4. Exec Lane: eBPF LSM

- Type `BPF_PROG_TYPE_LSM`; attach to `bprm_check_security`.
- Reads `bprm->file` and the calling task's cgroup and ancestry; decides only
  for the agent session and returns `0` for every other task.
- Allows only executables whose identity matches an allowlist entry; a
  decision requires a content-hash match, not a path match alone.
- Denies anonymous and `memfd` (`execveat(AT_EMPTY_PATH)`) execution by
  default, because they present no path.
- The loader pre-hashes allowlisted paths and maintains `(dev, ino, size,
  mtime, sha256)` tokens; a path-only positive is insufficient.
- Returns `0` to allow, `-EPERM` to deny.

---

## 5. Filesystem and Effects Lane: AppArmor

The installed profile `workspace-exec-policy` is loaded in enforcing mode
(there is no complain state). It owns two lanes.

- **Filesystem.** Grants broad read/map/lock/write access and denies writes
  to guard-owned policy and audit state (`/etc/workspace-guard/**`,
  `/var/log/workspace-guard/**`, `/etc/apparmor.d/**`,
  `/etc/systemd/system/**`). A deployment review may tighten the grants to a
  path allow-list.
- **Effects.** Denies mount and unmount of every path; permits signals only
  to processes in the same profile (the session's own descendant tree); and
  denies `AF_ALG`, raw and packet sockets.

The profile grants `/** ix`, `ptrace,` and `capability,` so it defers exec,
ptrace and capability to their owners.

---

## 6. ptrace, Kernel-Code and Capability Lanes

- **ptrace:** YAMA `ptrace_scope=2` is the sole decider. The AppArmor profile
  grants `ptrace,` so it is not a second gate.
- **Kernel code:** Lockdown `integrity` is the sole decider for module load,
  kexec, `/dev/mem`, MSR access and ioperm/iopl.
- **Capability:** the capability LSM plus the agent unit bounding set
  (`CAP_SETPCAP CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER`, matching
  REQ-GGUARD-001) own which capabilities the session may hold.
  `NoNewPrivileges=no` is required so the file-capped host-exec path can
  raise the reviewed set at exec time.

---

## 7. Rule Disposition Matrix

Every shell-guard rule in `config/shell_guard_policy.yaml` is assigned one
disposition. Dispositions name the single owner:

- **exec**: the eBPF LSM exec allowlist denies the binary by content.
- **fs**: AppArmor, as the filesystem owner, denies the operation.
- **effect**: AppArmor denies the effect (mount, signal, socket family).
- **kcode**: Lockdown denies the kernel-code operation.
- **caps**: the capability LSM and bounding set deny the capability.
- **content**: no kernel-observable effect; the shell guard keeps it.
- **hybrid**: the binary is denied by the exec owner and the argv case stays
  in content.
- **session**: delivered by session configuration, not the scanner.

| Rule id | Prevents | Owner enforcement | Disposition |
| --- | --- | --- | --- |
| `power-verb` | `systemctl`/`loginctl` power verbs | exec deny by hash; D-Bus/polkit rule | exec |
| `process-by-name` | `pkill`/`killall`/`skill`/`snice` | exec deny by hash | exec |
| `power-command` | `shutdown`/`reboot`/`poweroff`/`kexec` | exec deny by hash; kexec also kcode | exec |
| `fs-destroy` | `wipefs`/`fdisk`/`parted`/`mkfs*` | exec deny by hash | exec |
| `alt-shell` | unguarded shells (`zsh`,`dash`,...) | exec allowlist deny defeats rename/copy | exec |
| `busybox-shell` | `busybox sh`/`ash` | exec denies `busybox`; the `sh` argument is argv | hybrid |
| `kill-mass` | `kill -1`, `%`, `kill -NN` | effect: AppArmor denies signals outside the tree | effect |
| `chattr-strip` | clearing `+i` | fs write deny on policy; caps lack `CAP_LINUX_IMMUTABLE` | fs |
| `rm-rootfs` | `rm --no-preserve-root` | filesystem permission; behavioral contract | content |
| `dd-device` | writes to block devices | fs: AppArmor denies device writes | fs |
| `mount-protected` | mount/umount of guard paths | effect: AppArmor denies mount | effect |
| `swap-teardown` | `swapoff -a` | exec deny by hash | exec |
| `suppress-pipe` | `\| tail`/`head` truncation | none (text/UX contract) | content |
| `suppress-null` | `>/dev/null` discard | none (text/UX contract) | content |
| `suppress-swallow` | `\|\| true`, `\|:` masking | none (text/UX contract) | content |
| `alt-interp` | interpreters as command channel | exec denies non-allowlisted interpreter hashes | exec |
| `podman-command` | container execution channel | exec deny by hash | exec |
| `system-manager-command` | mutating `systemctl`/`loginctl`/`service`/`systemd-run` operations | exec deny by hash; D-Bus/polkit; shell guard blocks the direct command until the exec lane is armed | exec |
| `system-admin-command` | direct system-administration binaries (`useradd`, `modprobe`, `iptables`, `mount`, ...) | exec deny by hash; shell guard blocks the direct command until the exec lane is armed | exec |
| `inline-shell` | nested `bash -c`/`sh -c` | exec cannot read the `-c` argument | content |
| `uv-inline-interp` | `uv run <interpreter> -c` | argv-dependent | content |
| `inline-code-channel` | heredoc/`eval`/`source <()` | shell grammar, not a syscall | content |

### 7.1 Session-layer items

Environment sanitisation (SPEC-SHELL-GUARD section 8), the capability gate
and untrusted-script memfd staging are **session** items, delivered by the
session configuration, not by the scanner.

### 7.2 Retirement rule

A rule may move to `retired` only when the owning lane is verified active on
the running host, a matrix case proves the effect is denied for path,
renamed-copy and syscall forms, and an audit record is produced. Until then
the textual rule stays enabled as defense in depth.

---

## 8. Shell-Guard Coexistence

- The kernel allows by identity; the scanner enforces the content contract
  and produces explanatory blocks.
- The shell guard continues to cover `bash`/`sh`; `/bin/sh` must resolve to
  the guarded shell or its real target (`dash`) must be covered, closing
  D-04.
- Rules owned by the kernel lanes are retained as advisory until their
  section 7.2 proof, then deleted from the policy file (a YAML edit, not a
  code change).

---

## 9. Install, Arm, Recovery

The lifecycle is a state machine in `scripts/exec-policy`, exposed as Make
targets. It keeps **staging** (safe, idempotent) separate from **arming**
(the explicit operator decision), and the agent session runs only when
armed.

- `make build-exec-policy`: build the loader and BPF object (kernel phase).
- `make install-exec-policy` (root; `stage`): install the loader, BPF object,
  AppArmor profile, session gate, unit, drop-in and the pinned map seed from
  `config/exec_allowlist.yaml` to `/etc/workspace-guard/exec_allowlist.yaml`;
  create `exec-policy-state` as `unarmed`; enable the boot-time service.
  Idempotent and reconciling. If the authority artifacts are not built or the
  allowlist is unseeded, stage warns and leaves the posture unarmed.
- `make enable-exec-policy CONFIRM=1` (root; `arm`): refuse without
  `CONFIRM=1`; require the staged layers, the seeded policy, and every lane
  owner verified (exec `bpf`, fs `apparmor`, ptrace `yama`, kernel `lockdown`,
  caps `capability`); run the denial canary and stay `unarmed` if it fails;
  write the readiness manifest and set state `armed`.
- `make disable-exec-policy` (root): remove the readiness manifest and set
  state `unarmed`. The agent session then refuses to start (fail closed).
- `make check-exec-policy` (any): read-only report; exit 2 `NOT INSTALLED`,
  exit 0 `NOT ARMED`, exit 0 `OK` when armed and every owner verified, exit 1
  `DRIFTED` when armed but an owner is not verified.
- `make uninstall-exec-policy` (root): remove the staged artifacts and the
  readiness manifest; the policy and state are preserved.

`scripts/guard-operator.sh` integrates the posture: `guard-up` and
`guard-refresh` stage it (warn-only); `guard-check` reports it; `guard-down`
unstages it. None of these arm it - that is `enable-exec-policy` alone.

- **Break-glass**: root remains unconfined. Recovery uses `/bin/bash.real` and
  a loader stop from an unconfined root shell. The agent has no path to
  modify policy or stop the loader (`CAP_BPF` absent).

---

## 10. Audit

Denials and enforcement-state transitions are logged: loader readiness, map
reload, link attach/detach, and every denial with uid, path (or `<anon>`),
hash and ppid. The destination and mode follow
[SPEC-AUDIT](SPEC-AUDIT.md). Audit delivery failure never downgrades a
denial.

---

## 11. Testing

- **Loader unit tests**: policy parse/validate, map seed, hash-mismatch
  denial, fail-closed readiness.
- **Kernel matrix (root, real host or guest)**: allowlisted exec passes;
  non-listed path denied; renamed copy denied by hash; `dash`/`zsh` and
  interpreters denied; `memfd`/`execveat(AT_EMPTY_PATH)` denied; mount denied;
  signal outside the tree denied; `AF_ALG` denied; device write denied;
  module load and kexec denied; ptrace outside the tree denied; the session
  refuses to start when any owner is missing.
- **Shell suite**: `tests/shell/26-exec-policy-provisioning.bats` covers the
  staging and arming state machine against a `WEP_ROOT` fixture (no root, no
  kernel): `NOT INSTALLED`, `NOT ARMED`, `OK`, `DRIFTED`, the session gate
  with a complete and a partial readiness manifest, and the unseeded-policy
  warning.
- **Disjointness gate**: for the disposition matrix, `scripts/check-exec-dispositions.sh`
  fails when any rule id in `config/shell_guard_policy.yaml` is absent from
  section 7. Run from `make check`; `tests/shell/25-exec-dispositions.bats`
  covers it, including the fail-closed missing-spec case.

---

## 12. Residual Risks

- **Pre-arm window**: while unarmed the agent session does not start; there
  is no window in which it runs unenforced.
- **Kernel/verifier limits**: complex in-kernel hashing is bounded; the
  loader maintains hash tokens out of band.
- **argv-dependent rules**: `inline-shell` and `uv-inline-interp` remain
  text-based until an argv-enforcement phase lands.
- **D-Bus/polkit**: power actions are not fully mediated by LSM; the binary
  deny plus a polkit rule are required.
- **Root adversary**: out of scope by trust model (root is break-glass).

---

## 13. Non-Goals

- No per-workload sandbox requirement (see [SPEC-SANDBOX](SPEC-SANDBOX.md)).
- No network egress policy beyond the socket families in section 5.
- No replacement of the shell guard's content contract by text-free means in
  this phase.
- No confinement of root.
