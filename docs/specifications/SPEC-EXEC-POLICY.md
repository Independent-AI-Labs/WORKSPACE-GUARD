# Specification: Exclusive Execution Policy (eBPF LSM Authority)

**Date:** 2026-09-28
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-EXEC-POLICY](../requirements/REQ-EXEC-POLICY.md)
**Related:** [SPEC-SHELL-GUARD](SPEC-SHELL-GUARD.md), [SPEC-SANDBOX](SPEC-SANDBOX.md), [SPEC-BINARY-LOCK](SPEC-BINARY-LOCK.md), [SPEC-AUDIT](SPEC-AUDIT.md), [SPEC-CAP-THROTTLE](SPEC-CAP-THROTTLE.md)

---

## 1. Purpose and Posture

The host adopts an **exclusive execution posture**: process execution is
deny-by-default, and only an allowlisted set of executables may run in the
agent's confined session. The posture is **always on** (not a per-workload
sandbox), it is **enforced in the kernel**, and it is **fail-closed**: if the
policy cannot be enforced, the confined session does not run unconfined.

The posture has one enforcement authority and several supporting layers:

| Layer | Role | Mechanism |
| --- | --- | --- |
| **A. Kernel authority** | Every `execve`/`execveat` is mediated | eBPF LSM `security_bprm_check` (`bpf_lsm_bprm_check_security`) |
| **B. Interim authority** | Same decision before/without the eBPF loader | AppArmor enforce-mode profile |
| **C. Session confinement** | Defense-in-depth, survives a missing loader | Landlock (`LANDLOCK_ACCESS_FS_EXECUTE`) + `no_new_privs` |
| **D. Content policy** | Shell-text and behavior contract | [SPEC-SHELL-GUARD](SPEC-SHELL-GUARD.md) raw-text scanner |
| **E. Effects** | Writes, signals, mounts, modules, sockets | eBPF LSM hooks (section 7) |

Layer D is **not** an execution authority. It was never one: any non-bash
parent could always `execve` an arbitrary binary (see
[AUDIT-RESIDUAL-COVERAGE](../AUDIT-RESIDUAL-COVERAGE-2026-09.md) D-04). Layer A
is the authority; layer D is demoted to the content/behavior contract and to
human-readable audit of attempts.

### Key Design Principle

> **Allowlist in kernel, deny-list in text.** The kernel allows only the
> executables the operator has reviewed; everything else is denied regardless
> of shell grammar, quoting, aliasing, renaming, or path. The textual layer is
> retained for the contracts that have no kernel-observable effect (inline
> code, output suppression) and for fast, explanatory block reports.

---

## 2. Host Enforcement Capability

Observed on the reference host (2026-09-28, kernel `7.1.8`):

| Capability | State | Consequence |
| --- | --- | --- |
| `CONFIG_BPF_LSM` | `=y` | BPF LSM programs can be built |
| `CONFIG_LSM` / active LSMs | `landlock,lockdown,yama,integrity,apparmor` (+`capability`) | `bpf` is **not** active; a boot cmdline change is required |
| `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` | `=y` | Exec-permission events possible, but not used as authority |
| AppArmor | active, `apparmor_parser` present | Layer B is available with no reboot |
| Landlock | active | Layer C is available |
| seccomp filter | active | Used by the shell guard's launcher path and later brokers |
| IMA/EVM | active | Optional integrity appraisal (not required by this spec) |
| `unprivileged_bpf_disabled` | `2` | Only root / `CAP_BPF` may load programs (intended) |

Enabling layer A requires the operator to add `bpf` to the kernel command line
LSM list and reboot once:

```
lsm=landlock,lockdown,yama,integrity,apparmor,bpf
```

The exact `lsm=` value must preserve the existing entries in order and append
`bpf`. This is the **only** host change this specification requires, and it is
an operator action, not an agent action.

---

## 3. Enforcement Architecture

```
              agent session start
                      │
        ┌─────────────┼───────────────────────────┐
        ▼             ▼                           ▼
  Landlock+nnp   AppArmor profile          eBPF LSM program
  (layer C)      (layer B, interim)        (layer A, authority)
        │             │                           │
        └─────────────┴──────────────┬────────────┘
                                     ▼
                        any execve/execveat in session
                                     │
                     eBPF security_bprm_check consults
                     pinned allowlist map (path, sha256, uid)
                                     │
                          ┌──────────┴──────────┐
                        allow                 deny
                          │                     │
                    exec proceeds        -EPERM + audit event
```

### 3.1 Loader and boot ordering

- A root-owned loader (`workspace-exec-policyd`) loads the compiled BPF object
  and attaches it to the `bprm_check` hook at boot, before the agent login
  service is started (`REQ-EXEC-103`).
- If the loader fails, the agent session service must **not** start (fail
  closed). Layer B and layer C remain as fallbacks but are not the authority.
- The loader requires `CAP_BPF` and `CAP_SYS_ADMIN`; the agent has neither.

### 3.2 Allowlist map

The loader populates a pinned BPF hash map from
`config/exec_allowlist.yaml`. Each entry keys on the executable identity:

| Field | Meaning |
| --- | --- |
| `path` | Absolute canonical path |
| `sha256` | Content hash; mismatches are denied |
| `allow_uid` | UIDs permitted to exec this binary (default the agent uid) |
| `note` | Human rationale (not used by the kernel) |

Anonymous and `memfd`/`execveat(AT_EMPTY_PATH)` executions present no path;
they are denied by default (`REQ-EXEC-104`).

### 3.3 Fail-closed policy-load gate

A kernel program cannot be relied on when it is absent. Therefore:

1. The loader writes a readiness token only after `BPF_LINK_CREATE` succeeds.
2. The agent session unit `ExecCondition` requires the token and the pinned
   program link; absent either, the session does not start.
3. Layer B (AppArmor) and layer C (Landlock) are applied by the same session
   wrapper, so a loader failure denies, never allows.

---

## 4. eBPF Design

### 4.1 Program

- Type `BPF_PROG_TYPE_LSM`; attach to `bprm_check_security`.
- Reads `bprm->file` → `dentry`/`inode`/`i_ino`, the calling task's
  `bpf_get_current_uid_gid()`, and `bpf_get_current_pid_tgid()` for ancestry.
- Computes/holds the executable hash: the loader pre-hashes allowlisted paths;
  the program compares the inode's device+ino+size+mtime+hash token maintained
  by an LSM `inode_*` companion, or the loader's pinned map keyed by
  `(dev, ino)`. Hash verification is required for allow decisions; a path-only
  positive is insufficient.
- Returns `0` to allow, `-EPERM` to deny.

### 4.2 Hooks beyond exec

| Hook (`bpf_lsm_*`) | Effect denied |
| --- | --- |
| `task_kill` | Signals to processes outside the session's descendant tree |
| `sb_mount`, `sb_umount` | Mount/umount of guard and system paths |
| `file_open`, `inode_permission` | Opens of block devices and guard-owned files for write |
| `inode_setxattr`, file-ioctl path | Immutability / capability / xattr tampering |
| `kernel_read_file`, `kernel_module_request` | Module load, kexec image read |
| `socket_create`, `socket_connect` | `AF_ALG` and unapproved families/endpoints |

These hooks carry the effect-class shell-guard rules (section 6).

### 4.3 Audit

Denials emit a ring-buffer event and, when `auditd` is present, a matching
audit record: timestamp, uid, pid/ppid, path (or `<anon>`), hash, and the
denying policy class. Denial delivery failure never downgrades a denial.

---

## 5. Policy Schema (`config/exec_allowlist.yaml`)

Root-owned, `chattr +i`, edited only through the sudo-gated secure YAML editor
(SPEC-YAML-EDIT). Sketch:

```yaml
version: 1
allow:
  - {path: /usr/bin/workspace-shell-guard, sha256: "<hex>", allow_uid: 1000, note: guarded bash}
  - {path: /bin/bash,                    sha256: "<hex>", allow_uid: 1000, note: guard entry point}
  - {path: /usr/bin/git,                 sha256: "<hex>", allow_uid: 1000, note: git guard}
  - {path: /usr/local/bin/cargo,         sha256: "<hex>", allow_uid: 1000, note: build toolchain}
deny:
  default: true
  patterns:
    - {note: "shells other than the guarded pair", paths: ["/usr/bin/dash", "/usr/bin/zsh", "/bin/sh"]}
    - {note: "interpreters",                        paths: ["/usr/bin/perl", "/usr/bin/awk", "/usr/bin/lua"]}
```

The exact approved set is operator policy. A build-time validator (mirroring
the git/shell policy matrices) checks the schema, that every hash is 64 hex
chars, and that no entry is agent-writable.

---

## 6. Rule Disposition Matrix

Every shell-guard rule in `config/shell_guard_policy.yaml` is assigned a
disposition. Dispositions:

- **kernel-authoritative** (layer A and/or B/C enforce the effect): the textual
  rule becomes advisory and is **retired after eBPF proof**.
- **hybrid** (the kernel enforces the binary/effect): the textual rule is kept
  for the argv/exception cases the kernel cannot see.
- **content-policy** (no kernel-observable effect): stays in
  [SPEC-SHELL-GUARD](SPEC-SHELL-GUARD.md) permanently.
- **session-layer** (environment/session control): not the scanner.

| Rule id | Prevents | Kernel enforcement | Disposition | Retire / keep criterion |
| --- | --- | --- | --- | --- |
| `power-verb` | `systemctl`/`loginctl` power verbs | `bprm_check` deny by hash; polkit/D-Bus rule | kernel-authoritative | Retire after binary-deny + polkit rule are proven |
| `process-by-name` | `pkill`/`killall`/`skill`/`snice` | `bprm_check` deny by hash | kernel-authoritative | Retire after binary-deny proof |
| `power-command` | `shutdown`/`reboot`/`poweroff`/`kexec` | `bprm_check` deny by hash | kernel-authoritative | Retire after binary-deny proof |
| `fs-destroy` | `wipefs`/`fdisk`/`parted`/`mkfs*` | `bprm_check` + `file_open` on block devices | kernel-authoritative | Retire after both proofs |
| `alt-shell` | unguarded shells (`zsh`,`dash`,…) | `bprm_check` allowlist deny (hash defeats rename/copy) | kernel-authoritative | Retire after rename/copy evasion test |
| `busybox-shell` | `busybox sh`/`ash` | `bprm_check` denies `busybox`; the `sh` argument is argv | hybrid | Keep textual rule for the argv case |
| `kill-mass` | `kill -1`, `%`, `kill -NN` | `task_kill` denies signals outside the descendant tree | kernel-authoritative | Retire after `task_kill` proof |
| `chattr-strip` | clearing `+i` | missing `CAP_LINUX_IMMUTABLE` + `inode_setxattr` | kernel-authoritative | Retire after setxattr/ioctl proof |
| `rm-rootfs` | `rm --no-preserve-root` | filesystem permission + `inode_permission` | hybrid | Keep as advisory behavioral guard |
| `dd-device` | writes to block devices | `file_open`/`inode_permission` on device inode | kernel-authoritative | Retire after `file_open` proof |
| `mount-protected` | mount/umount of guard paths | `sb_mount`/`sb_umount` (+ no `CAP_SYS_ADMIN`) | kernel-authoritative | Retire after mount-hook proof |
| `swap-teardown` | `swapoff -a` | `bprm_check` deny by hash | kernel-authoritative | Retire after binary-deny proof |
| `suppress-pipe` | `\| tail`/`head` truncation | none (text/UX contract) | content-policy | Keep permanently |
| `suppress-null` | `>/dev/null` discard | none (text/UX contract) | content-policy | Keep permanently |
| `suppress-swallow` | `\|\| true`, `\|:` masking | none (text/UX contract) | content-policy | Keep permanently |
| `alt-interp` | interpreters as command channel | `bprm_check` denies non-allowlisted interpreter hashes | kernel-authoritative | Retire after interpreter-deny proof |
| `podman-command` | container execution channel | `bprm_check` deny; namespaces/mounts | kernel-authoritative | Retire after binary-deny proof |
| `inline-shell` | nested `bash -c`/`sh -c` | `bprm_check` cannot read the `-c` argument | content-policy | Keep; argv enforcement is a later tracepoint phase |
| `uv-inline-interp` | `uv run <interpreter> -c` | argv-dependent | content-policy | Keep; later argv phase |
| `inline-code-channel` | heredoc/`eval`/`source <()` | shell grammar, not a syscall | content-policy | Keep permanently |

### 6.1 Session-layer items (not rules)

The following shell-guard behaviors are classified **session-layer** and are
delivered by layer B/C and the session wrapper, not by the scanner:
environment sanitisation (§8 of SPEC-SHELL-GUARD), the `AT_SECURE`/capability
gate, and untrusted-script memfd staging. They remain in the guard in this
phase but are explicitly not the kernel authority.

### 6.2 Retirement rule

A rule may move to `retired` only when: (a) the corresponding layer-A hook is
attached on the running host, (b) a matrix case proves the effect is denied for
path, renamed-copy, and syscall forms, and (c) the audit record is produced.
Until then the textual rule stays enabled as defense-in-depth.

---

## 7. Effect Coverage Beyond Exec

The exclusive posture is not only "which binaries". The same program set
enforces the effect classes previously approximated by text: signals
(`task_kill`), mounts (`sb_*`), device and guard-file writes
(`file_open`/`inode_permission`), attribute/capability tampering
(`inode_setxattr`), module/kexec (`kernel_read_file`), and sockets
(`socket_*`). These are the rows marked `kernel-authoritative` in section 6.

---

## 8. Shell-Guard Coexistence

- SPEC-SHELL-GUARD's §1 "Key Design Principle: deny-list on raw text" is
  restated: the **kernel** allows by identity; the **scanner** enforces the
  content/behavior contract and produces explanatory blocks.
- The shell guard continues to cover `bash`/`sh`; `/bin/sh` must resolve to the
  guarded shell or its real target (dash) must be covered, closing D-04.
- The shell guard's rules classified `kernel-authoritative` are retained as
  advisory until their section 6.2 proof, then deleted from the policy file
  (a YAML edit, not a code change).

---

## 9. Install, Reconcile, Recovery

- `make build-exec-policy` builds the loader and BPF object.
- `make install-exec-policy` (root): install root-owned loader + BPF object,
  install the pinned map seed from `config/exec_allowlist.yaml`, install the
  AppArmor profile, install the session wrapper, and enable the boot-time
  service. Idempotent and reconciling.
- `make check-exec-policy`: verify program attached, map pinned, profile
  enforced, session wrapper wired, hashes current. Exit non-zero on drift.
- **Break-glass**: root remains unconfined (selected answer). Recovery uses
  `/bin/bash.real` and `aa-complain`/loader stop from an unconfined root shell.
  The agent has no path to modify policy or stop the loader (`CAP_BPF` absent).

---

## 10. Audit

Denials and enforcement-state transitions are logged: loader readiness, map
reload, hook attach/detach, and every denial with uid/path/hash/ppid. The
destination and mode follow [SPEC-AUDIT](SPEC-AUDIT.md).

---

## 11. Testing

- **Rust/loader unit tests**: policy parse/validate, map seed, hash mismatch
  denial, fail-closed readiness gate.
- **Kernel matrix (root, real host/guest)**: allowlisted exec passes;
  non-listed path denied; renamed copy denied by hash; `dash`/`zsh` denied;
  interpreter denied; `memfd`/`execveat(AT_EMPTY_PATH)` denied; `task_kill`
  outside tree denied; device write denied; module load denied; `AF_ALG`
  denied; loader-absent session refuses to start.
- **Shell suite**: `tests/shell/` covers install/reconcile/check and the
  AppArmor/Landlock secondary layers.
- **MATRIX-DISPOSITION gate**: `scripts/check-exec-dispositions.sh` fails when
  any rule id in `config/shell_guard_policy.yaml` is absent from the section 6
  matrix, so a new rule cannot be added without a disposition. Run from
  `make check`; `tests/shell/25-exec-dispositions.bats` covers it, including
  the fail-closed missing-spec case (REQ-EXEC-151, REQ-EXEC-184).

---

## 12. Residual Risks

- **Pre-loader window**: between boot and loader success, only layer B/C
  protect; the session gate prevents agent processes entirely.
- **Kernel/verifier limits**: complex hashing in-kernel is bounded; the loader
  maintains hash tokens out of band.
- **argv-dependent rules**: `inline-shell`, `uv-inline-interp` remain text-based
  until a tracepoint+map argv phase lands.
- **D-Bus/polkit**: power actions are not fully mediated by LSM; the binary
  deny plus a polkit rule are required.
- **Root adversary**: out of scope by trust model (root is break-glass).

---

## 13. Non-Goals

- No per-workload sandbox requirement (this posture is always on; see
  [SPEC-SANDBOX](SPEC-SANDBOX.md) for workload sandboxes).
- No network egress policy beyond the sockets listed in section 7.
- No replacement of the shell guard's content contract by text-free means in
  this phase.
- No confinement of root.
