# Direct System-Tool Gating Audit

Date: 2026-10-03
Scope: WORKSPACE-GUARD shell-guard policy, and the door it leaves open to
direct system-administration commands.

## Executive Summary

The shell guard gated power verbs (`poweroff`, `reboot`, `halt`,
`suspend`, `kill` on `systemctl`/`loginctl`) and power binaries
(`shutdown`, `reboot`, `poweroff`, `halt`, `kexec`, `telinit`). It did not
gate ordinary mutating service operations. An agent ran
`systemctl --user stop gateway-compose.service` directly; the guard had no
matching rule, so it executed and stopped the live gateway stack.

The gap was not a scanner defect. It was a missing rule. The policy set
named the catastrophic operations and assumed everything else was benign;
service and unit state changes are not benign.

This audit records the incident and the control added to close it: two
command-position rules that treat direct system administration the way the
policy already treats alternate shells and interpreters. Direct invocation
is blocked for all users including root; the operator path is `sudo` (the
launcher words are deliberately omitted from the match), and trusted
maintenance scripts remain exempt from body scanning per REQ-SHG-211.

## Incident

- Command: `systemctl --user stop gateway-compose.service`
- Context: agent command channel (guarded bash), uid 1000, WORKSPACE-GATEWAY
  working tree.
- Effect: the gateway compose unit stopped. The unit was `inactive`; the new
  template that carries `Restart=always` had not been rendered yet, so the
  service did not come back on its own.
- Recovery: operator restored the stack through the sanctioned start path.

## Root Cause

Rule-table gap. `power-verb` matched only the power verb set, and
`power-command` only the standalone power binaries. No rule matched
`systemctl` with a state-changing verb (`stop`, `start`, `restart`,
`reload`, `daemon-reload`, `mask`, `enable`, and the rest), so the command
passed `find_hit` with no match and reached `execve`.

## Control

Two rules were added to `config/shell_guard_policy.yaml`, both
`scope: command` (the inline command text that is the agent's normal command
channel), both command-position only:

- `system-manager-command` (REQ-SHG-317): `systemctl`/`loginctl` with a
  mutating verb, bare `systemd-run`, and `service <name> <action>` with a
  mutating action. Read-only subcommands (`status`, `show`, `list-*`,
  `is-*`, `cat`, `get-*`, `--version`, `help`, `--status-all`) stay allowed
  so inspection does not require an operator.
- `system-admin-command` (REQ-SHG-318): direct system-administration
  binaries (user/group management, kernel modules, storage and crypto,
  audit and MAC policy, network firewalls, hostname/time/clock, and the
  like). `ip` is gated only in its mutating object-verb form and `sysctl`
  only in its write form, so read-only inspection stays allowed.

Both match at command position only and deliberately omit the `sudo`/`doas`
launcher words. The operator's `sudo systemctl ...` path is therefore
permitted, while `env`, `exec`, `nice`, `nohup`, `setsid`, `stdbuf`,
`timeout`, and `xargs` wrappers still match. This is the same command-channel
model already used by `alt-interp` and `podman-command`, with one deliberate
difference: those rules include `sudo` in the launcher set, while these omit
it so the operator retains a direct path.

Rule dispositions are recorded in SPEC-EXEC-POLICY section 7 and
SPEC-SHELL-GUARD section 18: both rules are owned by the exec lane (the
eBPF LSM allowlist denies the binary by content), with the shell guard as
the active command contract until that lane is armed.

## Residual Gaps

- The shell guard only sees bash. A binary invoked directly by another
  process, and a tool launched through `find -exec`/`-execdir` or a
  launcher word not in the set, is outside this rule. The exec lane is the
  owner for those paths.
- Variable-assignment prefixes (`FOO=bar systemctl stop x`) are not part of
  the launcher set, matching the existing `podman-command` behavior; they
  are a documented residual.
- Read-only manager subcommands remain available by design. Tightening them
  to operator-only is a policy choice, not a scanner limitation.
- Script bodies remain a permitted channel for these tools, consistent with
  `alt-interp` and `podman-command`. An agent-authored script can therefore
  still reach them; closing that path is the exec lane's binary-hash deny,
  not the shell scanner. The rule's job is to stop the direct inline command
  that caused this incident.

## Verification

- Unit: the shell-guard matrix asserts the blocked and allowed forms
  (`config/shell_guard_policy_matrix.yaml`), checked by
  `policy_matrix_agrees` and by build-time coverage of every rule.
- Integration: `tests/shell/21-shell-guard.bats` exercises the blocked
  direct forms, the permitted `sudo` form, and the permitted read-only
  forms through the built guard binary.
- The guest QEMU shell-guard battery exercises the same rule inside the
  authoritative Linux guest.
