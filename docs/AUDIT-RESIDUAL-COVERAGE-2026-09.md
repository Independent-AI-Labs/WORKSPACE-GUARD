# Residual Coverage Audit

**Date:** 2026-09-28
**Type:** Audit
**Scope:** The residual-risk ledgers in `docs/specifications/` and
`docs/requirements/`, checked against the WORKSPACE-GUARD control layers
actually installed on this host.
**Method:** Read-only review of the specification residual tables plus live
host inspection (file metadata, capabilities, installed binaries). No
deployed file, policy catalog, or artifact was changed while gathering
evidence; this report is the only artifact written.

## Executive Summary

Each guard specification names the residual risks it accepts and the layer
expected to contain each one. That ledger is part of the security model: it
tells an operator what the guard does not stop and which other control is
supposed to stop it. A residual is only as strong as the layer named as its
backstop.

This audit checks every named residual against the layers actually present on
this host.

- The containment layers for git, the shell, SUID binaries, and home identity
  files are installed and match their specifications.
- Two layers the residual ledgers depend on are **not installed**: the
  audit/inventory layer (auditd, AIDE) and the sandbox (Program II-B). Every
  residual whose declared backstop is "auditd", "AIDE", or "seccomp/sandbox"
  is therefore open here, because the backstop is absent.
- Kernel device permissions and the absence of agent privilege contain several
  residuals that the specifications credit to the missing sandbox.

The result is a split ledger. Residuals contained by the git guard, the shell
guard, the binary lock, the home lock, kernel device permissions, and the lack
of agent privilege are contained. Residuals that name a missing layer are open.
The largest single gap is the complete absence of the detection layer, which
the specifications rely on both to detect after the fact and to deter the
grammar-evasion residuals.

## Legend

| Status | Meaning |
| --- | --- |
| CONTAINED | An installed layer bounds the residual against the agent. |
| PARTIAL | Bounded only by lack of privilege or by kernel permissions, or detection-only where the detector is absent. |
| OPEN | No installed layer bounds the residual. |
| OUT OF SCOPE | The specification declares it a non-requirement or a non-goal. |

## Deployed Control Layers

| Layer | Spec | Observed on host | State |
| --- | --- | --- | --- |
| Git guard (Program I) | [SPEC-GIT-GUARD](specifications/SPEC-GIT-GUARD.md) | `/usr/bin/git` carries `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_setpcap=ep`; `/usr/bin/git.original` is `0700 root:root`; `/usr/lib/git-core/git` is a symlink to `/usr/bin/git`; `deployment-class` is `host-exec` | Installed |
| Shell guard | [SPEC-SHELL-GUARD](specifications/SPEC-SHELL-GUARD.md) | `/bin/bash` is `0755 root:root` with `cap_dac_override=ep`; `/usr/bin/bash.real` is `0700 root:root` | Installed |
| Binary lock (Program II-A) | [SPEC-BINARY-LOCK](specifications/SPEC-BINARY-LOCK.md) | `<path>.real` files at `0700 root:root` exist for `mount`, `umount`, `su`, `passwd`, `chsh`, `chfn`, `newgrp`, `gpasswd`, `ldconfig` | Installed (partial) |
| Home lock (Program III) | [SPEC-HOME-LOCK](specifications/SPEC-HOME-LOCK.md) | `~/.gitconfig` and `~/.ssh/config`, `authorized_keys`, `known_hosts` are root-owned | Installed |
| WORKSPACE-CI contract | [REQ-GIT-GUARD](requirements/REQ-GIT-GUARD.md) | `/opt/workspace-ci` present; the git guard invokes the contract on `commit` and `push` | Installed |
| Host confinement | [README](../README.md) | Agent runs as an unprivileged login user with no passwordless root path | Installed |
| Audit and inventory (Program II-C/D) | [SPEC-AUDIT](specifications/SPEC-AUDIT.md) | No `auditd` or `auditctl` binary, no `/etc/audit`, no AIDE binary, no `/etc/aide` or `/var/lib/aide` | **Absent** |
| Sandbox (Program II-B) | [SPEC-SANDBOX](specifications/SPEC-SANDBOX.md) | No `/usr/local/bin/workspace-sandbox-launcher` | **Absent** |
| Workspace registry | [SPEC-GIT-GUARD](specifications/SPEC-GIT-GUARD.md) section 6.1 | `/etc/workspace-guard` directory does not exist; the implemented registry is `/usr/lib/workspace-guard/workspace-root` | **Divergent** |

## Residual-to-Layer Matrix

Verdicts use the legend above. "Declared backstop" is quoted from the
specification; "Installed backstop" is what this audit found.

### Shell-guard residuals

Source: [SPEC-SHELL-GUARD](specifications/SPEC-SHELL-GUARD.md) section 16 and
[REQ-SHELL-GUARD](requirements/REQ-SHELL-GUARD.md) section 10.

| ID | Residual | Declared backstop | Installed backstop | Verdict |
| --- | --- | --- | --- | --- |
| R-01 | Interpreter indirection (an inline scripting interpreter performing a blocked syscall) | Binary lock + auditd | Inline interpreters are blocked in command text and untrusted scripts; a compiled program is not covered. The interpreter is not SUID or capability-bearing; auditd is absent | PARTIAL |
| R-02 | Dynamic `eval` of an expanded value that spells a blocked idiom | Review + audit | The literal form is caught; the expanded form is not. auditd is absent | OPEN |
| R-03 | Quote-splitting (`pki''ll`, `$'pki'LL`) | Review + audit | Allowed invocations are not logged (only block decisions create records); auditd is absent | OPEN |
| R-04 | Quoted-text false positives block legitimate text | Accepted by design | Behavior is intentional | Not a security residual |
| R-05 | `dd of=` through a symlink to a device | Documented residual | `/dev/sda` and `/dev/nvme0n1` are `brw-rw---- root:disk`; the agent is not in `disk` and has no override capability | CONTAINED by kernel permissions |
| R-06 | Alternative shell renamed or copied to an unlisted path | Operator removes or binary-locks other shells | A compiled, non-privileged shell can be built and run; the binary lock covers only SUID/capability shells | PARTIAL |
| R-07 | `logind` power action over D-Bus (`busctl`) bypassing the `systemctl` verb rule | D-Bus/polkit policy | Not verified on this host | OPEN |
| R-08 | Unreadable script passes through unscanned | File permissions; root-adjacent only | The agent's own files are readable; the case is root-adjacent | PARTIAL |
| R-09 | Root-owned trusted-tier script evaluates caller input | Operator defect + audit | auditd is absent | OPEN |
| R-10 | Suppression performed inside an interpreter | Sandbox + audit | Sandbox absent; auditd absent | OPEN |
| R-11 | `memfd` staging changes the visible `$0`/`BASH_SOURCE` | `SHG_SCRIPT_PATH` contract | Documented and handled | Not a security residual |

**Supersession (2026-09-28).** R-01, R-02, R-06, and R-10 are effect/identity
gaps that the textual scanner cannot close. They are re-assigned to the
always-on exclusive execution posture: the kernel authority of
[SPEC-EXEC-POLICY](specifications/SPEC-EXEC-POLICY.md) (`bprm_check`
path+content-hash allowlist, plus `task_kill`/`file_open`/etc.). The
per-rule mapping is [SPEC-EXEC-POLICY §7](specifications/SPEC-EXEC-POLICY.md#7-rule-disposition-matrix);
the findings are [AUDIT-EXCLUSIVE-POSTURE-2026-09](AUDIT-EXCLUSIVE-POSTURE-2026-09.md).
Until the authority is attached these remain OPEN/PARTIAL as tabled.

### Sandbox-gap residuals

Source: [GAP-ANALYSIS-HARD-NUKE](GAP-ANALYSIS-HARD-NUKE.md) section 11.

| ID | Residual | Declared backstop | Installed backstop | Verdict |
| --- | --- | --- | --- | --- |
| R-12 | Block-device write via a process that does not enter guarded Bash | Program II-B sandbox | The shell guard blocks the common idioms in guarded Bash; direct device opens are denied by `root:disk 0660`; a compiled binary can still cause non-device host harm | PARTIAL |
| R-13 | Page-cache corruption against an unwrapped SUID binary (`AF_ALG`) | Kernel patch + seccomp, auditd for detection | Sandbox absent; auditd absent | OPEN |
| R-14 | Root adversary | Documented as not mitigated | The agent has no root; `sudo` is SUID and not wrapped (see D-04) | OUT OF SCOPE by trust model |
| R-15 | Library git use (libgit2, GitPython) bypassing the git guard | Explicit non-requirement | No layer | OUT OF SCOPE |
| R-16 | Network-level destruction or exfiltration | Out of scope | No layer | OUT OF SCOPE |

### Binary-lock residuals

Source: [SPEC-BINARY-LOCK](specifications/SPEC-BINARY-LOCK.md) section 8.

| ID | Residual | Declared backstop | Installed backstop | Verdict |
| --- | --- | --- | --- | --- |
| R-17 | Guard binary at a contained path is replaced | AIDE | `/usr/bin` is root-owned, `dpkg-divert` is registered, AIDE is absent | CONTAINED against the agent; detection absent |
| R-18 | `.real` page-cache corruption (`AF_ALG`) | seccomp | Sandbox absent | OPEN |
| R-19 | A new SUID binary appears after an apt upgrade | `dpkg-divert` + apt hook | Both apt hooks are present and warn only; they do not contain the new binary | PARTIAL |
| R-20 | SGID binaries are not contained | Drift checker | No drift schedule verified | OPEN |
| R-21 | Kernel or sudo CVE reached through an SUID binary | seccomp + capability drop | Sandbox absent; `sudo` is SUID and not wrapped | OPEN |
| R-22 | Direct write to `~/.gitconfig` bypassing `git config` | Home lock | `~/.gitconfig` is root-owned | CONTAINED |

### Audit-layer residuals

Source: [SPEC-AUDIT](specifications/SPEC-AUDIT.md) section 6. The entire layer
is absent on this host, so every row below is open regardless of its declared
mitigation.

| ID | Residual | Declared backstop | Installed backstop | Verdict |
| --- | --- | --- | --- | --- |
| R-23 | Page-cache corruption stays off disk | AIDE + auditd `AF_ALG` rule + seccomp | None present | OPEN |
| R-24 | Guard binary replaced | AIDE baseline hash | None present | OPEN |
| R-25 | SGID binaries not contained | Drift checker | Not verified | OPEN |
| R-26 | Kernel exploit below the audit layer | Out of scope | None | OUT OF SCOPE |
| R-27 | Audit rules modified (`-e 2` disabled by default) | Partial | auditd absent | OPEN |

### Git-guard residuals

Source: [SPEC-GIT-GUARD-IMPL](specifications/SPEC-GIT-GUARD-IMPL.md) section 9
and [SPEC-GIT-GUARD](specifications/SPEC-GIT-GUARD.md) section 3.5.

| ID | Residual | Declared backstop | Installed backstop | Verdict |
| --- | --- | --- | --- | --- |
| R-28 | Root, kernel, or hardware adversary | Documented as not mitigated | Agent has no root | OUT OF SCOPE by trust model |
| R-29 | Unknown external `git-<name>` helper runs without a capability loan | Contract only on `commit`/`push`; hooks elsewhere | History is forward-only and hooks still run | PARTIAL |
| R-30 | Guard code defect allowing execution with the guard capability set | Blast radius bound to the capability set | Installed posture matches the spec | Accepted |

## Deployment Drift Findings

These are not residual risks. They are differences between the installed state
and the state the specifications describe.

### D-01 HIGH: The detection layer is absent, and most residuals name it

`auditd`, `auditctl`, AIDE, `/etc/audit`, `/etc/aide`, and `/var/lib/aide` are
all absent. The residual rows R-01, R-02, R-03, R-09, R-10, R-13, R-17, R-18,
R-23, and R-24 name auditd or AIDE as the backstop or as the detection control.
On this host those rows have no backstop.

Required direction: install the audit/inventory layer, or mark every residual
that names it as OPEN in the specification ledgers until it is installed.

### D-02 HIGH: The audit directory mode does not match the requirement

`/var/log/workspace-guard` is `drwxrwxrwt` (1777). `REQ-GGUARD-084` and
`REQ-SHG-500` require `root:root` mode `0750`, and the specifications forbid a
user-writable audit destination. The directory is also empty, which is
consistent with only block decisions being logged and no block having occurred
here.

Required direction: correct the directory ownership and mode during guard
install or reconcile, and verify it in `guard-check`.

### D-03 MEDIUM: `sudo` is SUID and not contained

`/usr/bin/sudo` is `rwsr-xr-x root:root` with no `sudo.real`. The binary lock
scopes SUID binaries, and the reference set includes the sudo CVEs this
repository cites. The likely intent is an operator break-glass path. It is
still the largest uncontained SUID binary on the host.

Required direction: either contain `sudo` under the binary lock with an
explicit operator allowance, or record it as an intentional exception with its
rationale.

### D-04 MEDIUM: `/bin/sh` resolves to `dash`, which is not wrapped

`/bin/sh` is a symlink to `dash`. `REQ-SHG-003` wraps only `bash` and
`sh`-resolving-to-bash. `dash` is blocked only as a word inside guarded Bash
(`alt-shell`). A direct `execve` of `/bin/dash` from a non-Bash parent does not
pass the scanner.

Required direction (updated 2026-09-28): cover the actual `/bin/sh` target or
repoint `/bin/sh` to the guarded pair (REQ-SHG-007), and close the direct-exec
class entirely with the kernel authority of
[SPEC-EXEC-POLICY](specifications/SPEC-EXEC-POLICY.md) (`bprm_check`,
path+hash). See
[AUDIT-EXCLUSIVE-POSTURE-2026-09](AUDIT-EXCLUSIVE-POSTURE-2026-09.md) F-02/F-03.

### D-05 MEDIUM: The workspace registry path diverges from the specification

`SPEC-GIT-GUARD` section 6.1 fixes the registry at
`/etc/workspace-guard/workspace-roots` and states that absence blocks a
contract-eligible invocation. That directory does not exist; the installed
implementation records the root at `/usr/lib/workspace-guard/workspace-root`,
and commits succeed. The open item in `../TODO.md` tracks adding the
`/etc/workspace-guard` path.

Required direction: provision the registry path, or reconcile the
specification with the implemented location.

### D-06 LOW: Home lock does not cover every identity file

`~/.ssh/id_ed25519_new` (private key) is agent-owned. The lock covers the
declared globs; this file is outside them. If the key is intentionally
agent-usable, the exclusion should be stated where the lock is specified.

### D-07 LOW: One `.real` binary does not match the declared mode

`/usr/bin/ldconfig.real` is `0755`, while the binary-lock specification gives
`.real` binaries mode `0700 root:root`. `ldconfig` may be a deliberate
exception; it should be recorded.

### D-08 INFO: Kernel device permissions are doing real work

`/dev/sda` and `/dev/nvme0n1` are `brw-rw---- root:disk` and the agent is not
in `disk`. This is an effective containment for device writes (R-05, R-12) that
no specification credits. It should be named in the residual ledger so the
bound is not lost if the device mode changes.

## Recommendations

| ID | Action | Priority | Owner |
| --- | --- | --- | --- |
| C-01 | Install the audit/inventory layer, or mark every residual that names auditd/AIDE as OPEN in the specs | High | Operator |
| C-02 | Add a "backstop installed" column to each residual table so the ledger separates installed controls from roadmap controls | High | WORKSPACE-GUARD |
| C-03 | Correct `/var/log/workspace-guard` to `root:root 0750` and verify it in `guard-check` (D-02) | High | Operator |
| C-04 | Decide and document `sudo` (contain, or record as an intentional exception) (D-03) | Medium | Operator |
| C-05 | Cover the real `/bin/sh` target or record the direct-exec residual (D-04) | Medium | WORKSPACE-GUARD |
| C-06 | Provision `/etc/workspace-guard/workspace-roots` or reconcile the specification (D-05) | Medium | Operator |
| C-07 | Land the Program II-B sandbox launcher, or downgrade every seccomp/sandbox-named residual to OPEN | Medium | WORKSPACE-GUARD |
| C-08 | Record the `ldconfig.real` mode and the kernel device-permission bound in the relevant ledgers (D-07, D-08) | Low | WORKSPACE-GUARD |

## Evidence Appendix

Commands used for live inspection (read-only):

```
cat /usr/lib/workspace-guard/deployment-class
/usr/sbin/getcap /usr/bin/git /bin/bash
ls -l /usr/bin/git /usr/bin/git.original /bin/bash /bin/bash.real
ls -l /usr/lib/git-core/git
find /usr/bin /bin /usr/sbin -maxdepth 1 -name '*.real' -printf '%p %s %u:%g %m\n'
ls -l /usr/bin/sudo /usr/bin/passwd /usr/bin/su /usr/bin/mount /usr/bin/umount
ls -la /var/log/workspace-guard
ls -la /usr/lib/workspace-guard
ls -l /etc/apt/apt.conf.d/99workspace-guard /etc/apt/apt.conf.d/99workspace-guard-shell
ls -l /dev/sda /dev/nvme0n1
find /etc -maxdepth 2 -iname '*workspace*'
command -v aide auditctl auditd
test -x /usr/local/bin/workspace-sandbox-launcher
ls -l ~/.gitconfig ~/.ssh
```

Observed results are summarized in the Deployed Control Layers table and the
Deployment Drift Findings. No mutating command was run.

## References

- [SPEC-SHELL-GUARD](specifications/SPEC-SHELL-GUARD.md)
- [SPEC-BINARY-LOCK](specifications/SPEC-BINARY-LOCK.md)
- [SPEC-AUDIT](specifications/SPEC-AUDIT.md)
- [SPEC-GIT-GUARD](specifications/SPEC-GIT-GUARD.md)
- [SPEC-GIT-GUARD-IMPL](specifications/SPEC-GIT-GUARD-IMPL.md)
- [SPEC-HOME-LOCK](specifications/SPEC-HOME-LOCK.md)
- [SPEC-SANDBOX](specifications/SPEC-SANDBOX.md)
- [REQ-SHELL-GUARD](requirements/REQ-SHELL-GUARD.md)
- [REQ-GIT-GUARD](requirements/REQ-GIT-GUARD.md)
- [REQ-SANDBOX](requirements/REQ-SANDBOX.md)
- [GAP-ANALYSIS-HARD-NUKE](GAP-ANALYSIS-HARD-NUKE.md)
- [README](../README.md)
