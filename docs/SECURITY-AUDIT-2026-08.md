# WORKSPACE-GUARD Security Audit

**Date:** 2026-08-03
**Scope:** Repository source, installers, shell guard, YAML editor, test harness,
build container, synchronization scripts, hooks, configuration, and deployment
documentation.
**Method:** Read-only source review, provenance review with `git blame`, and
live host state inspection. No files were changed during the audit.

## Executive Summary

The audit found no evidence of covert telemetry, credential theft, command-and-
control, encoded payloads, or hidden persistence. It did find a critical
architectural bypass: the installer intentionally leaves the original distro
shell executable at `/usr/bin/bash.distrib`, and the test harness intentionally
executes it to bypass the guard. Any non-root user can invoke that path directly.

This defeats the central shell-guard invariant and is classified as a critical
security defect, even though the behavior was documented and intentional.

## Provenance of the Critical Bypass

| Evidence | Date | Effect |
| --- | --- | --- |
| Commit `9ee1e358`, `workspace-agent` | 2026-07-28 | Added the `dpkg-divert` operation that creates the `.distrib` runtime path. |
| Commit `67964839`, `workspace-agent` | 2026-08-01 | Added the test-harness `/usr/bin/bash.distrib` PATH override. |
| Host `/usr/bin/bash.distrib` | 2024-03-31 package timestamp | Original distro bash preserved by the diversion. |
| Host `/bin/bash` and apt hook | 2026-08-02 16:36 | Guard installation/reconciliation timestamp. |

The installer and harness therefore created and relied on an executable,
unguarded shell escape by design.

## Findings

### CRITICAL-001: Executable diverted shell bypasses the guard

**Locations:** `scripts/install-shell-guard:276-280`,
`tests/shell/lib/harness.bash:251-267`, `Makefile:246-254`.

`dpkg-divert` leaves the stock shell at `/usr/bin/bash.distrib` with ordinary
execute permissions. The test harness prepends a wrapper that executes it. A local
non-root user can run the path directly and bypass all guard scanning.

**Required fix:** Do not use `.distrib` as an executable runtime path. Use the
root-only sealed `/bin/bash.real` only for root test orchestration, and make
the diverted package copy non-executable to non-root users.

### HIGH-002: Unreadable scripts fail open

**Locations:** `src/shell_guard.rs:201-223,451-467`.

Metadata/open/read failures are classified as `Unreadable`, then passed to the
real shell. A symlink race or inaccessible script can therefore execute
unscanned content.

**Required fix:** Treat every scan failure as a hard block. Resolve symlinks,
scan the canonical target, and open that target with `O_NOFOLLOW`; never
execute content that was not successfully scanned.

### HIGH-003: Privileged YAML editor resolves tools through `PATH`

**Locations:** `src/yaml_edit_install.rs:17-50`.

Elevated `lsattr` and `chattr` calls use PATH lookup. A controlled PATH could
substitute a malicious helper.

**Required fix:** Use absolute tool paths and fail closed when attribute state
cannot be established.

### HIGH-004: Build container executes unpinned remote code

**Locations:** `Containerfile.test:26-32`.

Bats is downloaded without a checksum and Rust is installed through `curl | sh`.

**Required fix:** Pin immutable artifacts and verify checksums/signatures before
execution; remove the pipe-to-shell bootstrap.

### HIGH-005: Baseline synchronization accepts failed fetches

**Locations:** `scripts/sync-gtfobins:89-101,170-179`.

Fetch failures and partial discovery can return success and feed incomplete or
stale data into security baselines.

**Required fix:** Fail closed unless a validated cache is present, with explicit
operator opt-in for partial diagnostic output.

### MEDIUM-006: APT drift hook uses a hard-coded path

**Locations:** `scripts/install-shell-guard:219-226`.

On usrmerge systems the diversion is `/usr/bin/bash.distrib`, while the hook
checks `/bin/bash.distrib`.

**Required fix:** Generate the hook from the resolved diversion path.

### MEDIUM-007: Audit output can expose command secrets

**Locations:** `src/shell_guard_report.rs:103-155`,
`src/shell_guard.rs:267-297`.

Process ancestry, command strings, URLs, and positional arguments can be written
to terminal and audit logs with incomplete redaction.

**Required fix:** Log executable names and rule IDs by default; redact or omit
arguments and command bodies.

### MEDIUM-008: Installer rollback can leave diversion state inconsistent

**Locations:** `scripts/install-shell-guard:148-163`.

Rollback restores a binary but does not fully reconcile diversion registrations
or `/bin/sh` state.

**Required fix:** Restore and verify all diversion, binary, mode, capability, and
hook state transactionally.

### MEDIUM-009: Trusted script scan has a scan/execute TOCTOU boundary

**Locations:** `src/shell_guard.rs:211-235,468-474`.

Trusted content is scanned from an open descriptor and then executed by pathname.
Root ownership reduces ordinary-agent risk but does not remove replacement races.

**Required fix:** Execute the scanned descriptor or a sealed memfd for every
script class.

### LOW-010: Temporary E2E fixtures are world-writable

**Locations:** `scripts/qemu/e2e-shell-guard-guest.sh:186-201,228-298`.

The fixtures intentionally test unsafe permissions under `/tmp`, but this is
unsafe outside an isolated guest.

**Required fix:** Keep world-writable fixtures confined to the guest and use
private temporary directories elsewhere.

### HIGH-011: Staged installer depended on a scrubbed PATH

**Location:** `scripts/install-shell-guard:46-80,189,293,315`.

The installer is intentionally re-executed through a sanitized shell
environment, but capability tools under `/usr/sbin` were invoked by bare name.
The staged install therefore failed before reconciliation with `setcap: command
not found`.

**Required fix:** Use absolute paths for privileged tools required after guard
environment sanitization. This is now fixed for `setcap`, `getcap`, and the APT
hook's `stat` invocation.

## Review Areas With No Malicious Finding

- No covert network telemetry, suspicious endpoint, credential harvesting, or
  persistence mechanism was found.
- No encoded payload, hidden interpreter loader, unauthorized sudoers, or
  polkit modification was found.
- Rust dependencies and features were consistent with the stated implementation.
- Capability and immutable-file operations are explicit security-product
  behavior rather than hidden code.

## Remediation Order

1. Remove all non-root access to executable `.distrib` shells and remove the
   harness bypass.
2. Make shell script scanning fail closed, including symlink/open/read races.
3. Harden the privileged YAML editor's command resolution and attribute checks.
4. Correct the APT hook path and add installed-state assertions.
5. Pin build and baseline synchronization inputs.
6. Redact audit output and make installer rollback transactional.
7. Re-run all shell, Rust, provision, and QEMU gates.
