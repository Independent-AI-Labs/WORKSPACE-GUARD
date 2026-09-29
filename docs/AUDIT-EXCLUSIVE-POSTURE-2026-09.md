# Audit: Exclusive Execution Posture

**Date:** 2026-09-28
**Type:** Audit
**Scope:** The execution surface of the WORKSPACE-GUARD host: the shell guard
wrapper, the Makefile recipes, every non-shell `execve` path, and the kernel
enforcement mechanisms available to make the posture exclusive.
**Method:** Read-only review of the specifications, requirements, policy files,
and live host state (kernel config, active LSMs, tooling). No deployed file,
policy, or artifact was changed; this report and its companion
[SPEC-EXEC-POLICY](specifications/SPEC-EXEC-POLICY.md) are the only artifacts
written.

## Executive Summary

The repository's execution controls are **not exclusive**. The only
enforcement is a userspace raw-text scanner on `/bin/bash`; every other
`execve` path is unmediated. This audit confirms the gaps named by
[AUDIT-SHELL-EXECUTION-SURFACE-2026-08](AUDIT-SHELL-EXECUTION-SURFACE-2026-08.md)
and [AUDIT-RESIDUAL-COVERAGE-2026-09](AUDIT-RESIDUAL-COVERAGE-2026-09.md), adds
two new findings (unguarded Make recipes; text-interpolation as a
self-inflicted block), and specifies the kernel-authoritative replacement.

The proper solution is not more text rules. It is an **eBPF LSM** program on
`security_bprm_check` that allows only reviewed executables by **path and
content hash**, with AppArmor as the no-reboot interim authority and Landlock as
the session backstop. The rule-by-rule treatment of the existing shell-guard
policy is normative in
[SPEC-EXEC-POLICY §7](specifications/SPEC-EXEC-POLICY.md#7-rule-disposition-matrix);
the requirements are [REQ-EXEC-POLICY](requirements/REQ-EXEC-POLICY.md).

## Host Enforcement Capability (evidence)

| Item | Observed | Impact |
| --- | --- | --- |
| Kernel | `7.1.8` | modern; BPF LSM stable |
| Active LSMs | `lockdown,capability,landlock,yama,apparmor,ima,evm` | `bpf` absent |
| `CONFIG_BPF_LSM` | `=y` | program can be built |
| `CONFIG_LSM` | `landlock,lockdown,yama,integrity,apparmor` | boot change required to enable BPF LSM |
| `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` | `=y` | not adopted as authority (exec-path daemon) |
| AppArmor | active, `apparmor_parser` present | interim authority available now |
| Landlock / seccomp / IMA | active | session backstop / optional appraisal |
| `/etc/shells` | `sh,bash,rbash,dash,zsh` | multiple shells present and executable |
| `/bin/sh` | symlink to `dash` | not wrapped by the shell guard (D-04) |

## Findings

### F-01 HIGH: Make recipes are an unguarded execution channel, and the yaml recipes interpolate data into scanned text

Evidence:

- `Makefile:552-616` runs the yaml mutation recipes as
  `"$(YAML_SH)" -c '<body>'` with `YAML_SH := $(SCRIPT_BASH)` = the guarded
  `/bin/bash`.
- Make executes recipe lines with `/bin/sh` = `dash`, which the shell guard
  does not wrap. Every Makefile recipe therefore executes unguarded.
- The yaml mutation recipes interpolate `$(FIELDS)`, `$(VALUE)`, `$(KEY)` into
  the `-c` body. The guard scans that body in command context, so a payload
  such as `...|awk...` matches `alt-interp` and a payload containing `bash -c`
  matches `inline-shell`. Editing the shell-guard policy or matrix is therefore
  self-blocked; `yaml-remove` (which passes only an id) works, which is the
  observed asymmetry.

Reproduction: a `bash -c` body containing `IFS=... read -ra f <<< 'regex=a|awk'`
is denied by the running guard with rule `alt-interp`.

Impact: the sanctioned policy-edit path is blocked exactly when it is needed,
and the "guarded recipe" claim is not a security boundary.

Required direction: read the payload from the exported environment at runtime
(`$$FIELDS`, `$$VALUE`,…) so the scanned `-c` body is static, and stop treating
Make recipes as a control (they are not). Track the kernel authority in
[REQ-EXEC-110](requirements/REQ-EXEC-POLICY.md).

### F-02 HIGH: `/bin/sh` resolves to `dash`, which is not wrapped

Evidence: `/bin/sh -> dash`; `REQ-SHG-002` covers `/bin/sh` only when it
resolves to bash. `dash` is blocked only as the word `dash` inside scanned bash
text.

Impact: `sh script.sh` (no `-c`) and direct `execve("/bin/dash")` are unscanned.

Required direction: cover the real `/bin/sh` target, or make `/bin/sh` resolve
to the guarded pair; this is layer E1 in
[SPEC-EXEC-POLICY §3](specifications/SPEC-EXEC-POLICY.md). Closes D-04 / C-05.

### F-03 HIGH: No kernel-level execution allowlist

Evidence: the only enforcement is the `/bin/bash` wrapper. `security_bprm_check`
is not mediated by any host policy; the active LSMs do not include `bpf`.

Impact: any process not descended from guarded bash can `execve` any binary:
interpreters, renamed shells, the operator's own tooling. The shell guard
cannot be an authority (see [AUDIT-SHELL-EXECUTION-SURFACE-2026-08](AUDIT-SHELL-EXECUTION-SURFACE-2026-08.md)).

Required direction: attach a BPF LSM program to `bprm_check_security` with a
path+hash allowlist ([REQ-EXEC-110-114](requirements/REQ-EXEC-POLICY.md)).

### F-04 HIGH: Renamed or copied shells bypass basename rules

Evidence: `alt-shell` matches names in text. A copied shell at an unlisted path
(`~/bin/mysh`) is not recognised; the policy acknowledges this as a residual.

Impact: the escape is trivial for an agent with write access to a home
directory.

Required direction: content-hash allowlisting in the kernel defeats rename and
copy ([REQ-EXEC-111](requirements/REQ-EXEC-POLICY.md)); the textual rule is
demoted to `kernel-authoritative` and retired after proof.

### F-05 MEDIUM: Interpreters, memfd, Rust `Command`, and tool writes are outside the scanner

Evidence: `alt-interp` is `scope: command`; the shell guard sees only `-c` text
and untrusted script bodies. `memfd` execution, `std::process::Command`, and
patch-tool writes never enter the scanner.

Impact: an inline interpreter can perform a blocked syscall; an anonymous exec
has no path to match; the tool layer writes files the scanner never sees.

Required direction: kernel allowlist denies non-approved interpreter hashes and
anonymous exec ([REQ-EXEC-112](requirements/REQ-EXEC-POLICY.md)); effect hooks
cover the syscall classes ([REQ-EXEC-130-136](requirements/REQ-EXEC-POLICY.md)).

### F-06 MEDIUM: No rule disposition ledger

Evidence: `config/shell_guard_policy.yaml` defines 20 rules with no mapping to
what is enforced where. Several rules approximate effects the kernel can
enforce directly; others are pure text contracts.

Impact: the ledger cannot show which rules are security boundaries and which
are behavior policy, so retirement is unsafe and duplication persists.

Required direction: the disposition matrix in
[SPEC-EXEC-POLICY §7](specifications/SPEC-EXEC-POLICY.md#7-rule-disposition-matrix)
assigns every rule a disposition; a gate fails on any undisposed rule
([REQ-EXEC-150-151](requirements/REQ-EXEC-POLICY.md)).

### F-07 MEDIUM: BPF LSM is compiled but inactive

Evidence: `CONFIG_BPF_LSM=y`; `bpf` is absent from `CONFIG_LSM` and from
`/sys/kernel/security/lsm`.

Impact: the authority cannot attach until the operator adds `bpf` to the boot
LSM list and reboots.

Required direction: document the exact `lsm=` value and treat the reboot as an
operator step ([REQ-EXEC-115, REQ-EXEC-174](requirements/REQ-EXEC-POLICY.md)).

### F-08 INFO: AppArmor and Landlock are available without a reboot

Evidence: AppArmor is active with `apparmor_parser` and many profiles; Landlock
is active.

Impact: an interim kernel authority and a session backstop can be deployed
immediately, so there is no window before the reboot.

Required direction: install the AppArmor enforce profile and the Landlock
session wrapper as the interim posture
([REQ-EXEC-120-123](requirements/REQ-EXEC-POLICY.md)).

## Required Remediation Sequence

1. Fix the yaml payload interpolation so the sanctioned editor can be used
   (F-01), a prerequisite for the policy files below.
2. Publish the disposition matrix and the `REQ-EXEC-*` requirements (F-06).
3. Cover the real `/bin/sh` target (F-02).
4. Install the AppArmor enforce profile and the Landlock session wrapper as the
   interim authority (F-08).
5. Build and install the loader + BPF object + `config/exec_allowlist.yaml`;
   operator adds `bpf` to `lsm=` and reboots (F-03, F-04, F-07).
6. Attach the effect hooks and migrate `kernel-authoritative` rules out of the
   text policy once proven (F-05, F-06).
7. Update the residual ledgers and re-run the shell, Rust, and kernel matrices.

## References

- [SPEC-EXEC-POLICY](specifications/SPEC-EXEC-POLICY.md)
- [REQ-EXEC-POLICY](requirements/REQ-EXEC-POLICY.md)
- [SPEC-SHELL-GUARD](specifications/SPEC-SHELL-GUARD.md)
- [REQ-SHELL-GUARD](requirements/REQ-SHELL-GUARD.md)
- [AUDIT-SHELL-EXECUTION-SURFACE-2026-08](AUDIT-SHELL-EXECUTION-SURFACE-2026-08.md)
- [AUDIT-RESIDUAL-COVERAGE-2026-09](AUDIT-RESIDUAL-COVERAGE-2026-09.md)
