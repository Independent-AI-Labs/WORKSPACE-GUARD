# WORKSPACE-GUARD Test Audit

**Date:** 2026-08-04
**Scope:** Bats shell tests, Rust unit/integration tests, Makefile gates,
Podman/QEMU runners, test containers, fixtures, helper programs, and test
documentation.
**Method:** Read-only source audit with file/line review and execution-output
correlation. No test was treated as authoritative merely because it exited 0.

## Executive Summary

The test system contains substantial false assurance. The most serious problems
are destructive host mutation in `21-shell-guard.bats`, test execution through
root-only `/bin/bash.real`, legacy assertions for the prohibited `bash.distrib`
escape, broad skip behavior, and a Linux pre-push gate that does not run the
authoritative shell-guard QEMU suite.

No malicious payload, covert exfiltration, or hidden backdoor was found in test
code. The defects are test-boundary and assurance failures: tests can pass while
the relevant production binary, capability context, immutable state, or runtime
path was never exercised.

## Severity Model

- **Critical:** test code can damage or alter the host, or can certify a false
  security property after destructive production state changes.
- **High:** authoritative security coverage is absent, bypassed, skipped, or
  executed in a materially different privilege/environment context.
- **Medium:** failures are masked, assertions are materially weaker than the
  claimed property, or fixtures can contaminate other tests.
- **Low:** implementation-detail coverage or maintainability gaps that do not
  independently establish a security bypass.

## Critical Findings

### TA-001: Runtime test mutates and can delete production `/bin/bash.real`

**Location:** `tests/shell/21-shell-guard.bats:37-66`.

The suite copies `/bin/bash` to `/bin/bash.real`, changes ownership and mode,
then removes `/bin/bash.real` during teardown based on a shared `/tmp` marker.
The marker is predictable and not exclusively created.

**Impact:** A test run can alter or delete the production sealed shell. Concurrent
runs or a tampered marker can redirect cleanup. This test must never mutate a
live system shell.

### TA-002: Host test execution is root-only and uses the sealed bypass

**Locations:** `Makefile:258-272`, `tests/shell/lib/harness.bash:258-267`.

The current host target runs Bats through `/bin/bash.real` only for root. A
non-root pre-push invocation runs Bats through the installed guard and is blocked
by test-suite constructs such as `>/dev/null`.

**Impact:** The required test suite cannot run as the agent, while root runs use
an unguarded interpreter. This is both an operational regression and a
production-path divergence.

**Required direction:** Run shell tests in the isolated Podman test image when
the host guard is active. Do not restore `bash.distrib` or make `/bin/bash.real`
agent-executable.

## High Findings

### TA-003: Tests retain the prohibited `bash.distrib` contract

**Locations:** `tests/shell/22-shell-guard-install.bats:5-7,68-71,212-213`.

The installer suite models and asserts the executable diverted copy even though
the new security contract requires `.distrib` to be root-only recovery state.

**Impact:** The test suite protects the defect it is supposed to remove.

### TA-004: Capability fixture uses predictable world-writable `/tmp` state

**Locations:** `tests/shell/21-shell-guard.bats:42,54-66`.

`/tmp/.shg-bats-real-marker` and `/tmp/shg-bats-pub` are predictable shared
paths. The public capability fixture is created under a world-writable parent.

**Impact:** Collision, replacement, and cross-run contamination are possible.

### TA-005: Root-owned trusted fixtures are recursively removed without isolation

**Location:** `tests/shell/21-shell-guard.bats:90-110` and related teardown.

Tests create root-owned fixture directories and recursively remove them without
an independent ownership and path-boundary assertion.

### TA-006: Compiled-guard tests skip when the guard is absent

**Locations:** `tests/shell/10-binary-guard-build.bats:18-63`.

The suite skips binary existence, sentinel, and execution tests when artifacts
are missing.

**Impact:** A green shell suite can contain no compiled guard coverage.

### TA-007: Capability and root-only coverage is broadly skipped

**Locations:** `Makefile:223-250`, `tests/integration_test.rs:37-89`,
`tests/shell/21-shell-guard.bats:79-86`.

Root invocations skip capability tests; root-only tests skip capability context;
rootless containers skip AT_SECURE tests; Darwin skips Rust tests.

### TA-008: Linux pre-push omits authoritative QEMU shell-guard coverage

**Locations:** historical pre-push and guest-harness integration.

Linux pre-push runs provisioning E2E but does not require the QEMU shell-guard
suite, which is itself opt-in.

### TA-009: Podman test image and dependencies are unpinned

**Locations:** `Containerfile.test:3,7-32`, `scripts/test-in-podman.sh:9,49`.

The base image, apt packages, Bats archive, and Rust installer are mutable and
not checksum/signature verified. Rust is installed with `curl | sh`.

### TA-010: Podman tests run with broad writable scope and privileged mode

**Locations:** `scripts/podman/run-tier12.sh:34-43`,
`scripts/podman/run-tier3.sh:34-38`.

The whole sibling projects tree is mounted read-write. Tier 3 uses
`--privileged`. Tier 1 and Tier 2 share mutable state.

**Impact:** Test contamination is possible and passing results do not establish
production-equivalent confinement.

### TA-011: E2E cleanup and unsupported capability paths can pass

**Locations:** `scripts/podman/e2e-root-only.sh:22-29`,
`scripts/podman/e2e-yaml-edit.sh:54`,
`scripts/podman/e2e-host-exec.sh:137-170`.

Uninstall failures become warnings, unsupported `chattr` skips immutable tests,
and ownership limitations are reported as skips.

### TA-012: Rust security tests do not cover actual shell execution boundaries

**Locations:** `src/shell_guard_tests.rs`, `src/shell_guard_fd.rs`,
`src/exec_tests.rs`, `src/vendored_tests.rs`.

Missing coverage includes complete script classification, canonical symlink
targets, scan/open/read races, memfd seals and execution, AT_SECURE parsing,
argv preservation, hostile environment values, audit redaction, and capability
state after exec.

### TA-013: YAML tests cover transformations, not the protected mutation boundary

**Locations:** `src/yaml_edit_engine_tests.rs`,
`src/yaml_edit_schema_tests.rs`.

Parser tests do not establish ownership, immutable flags, symlink refusal,
atomic replacement, or failure behavior during filesystem races.

## Medium Findings

### TA-014: Diagnostic commands mask failures

**Locations:** `tests/shell/21-shell-guard.bats:202-208`,
`Makefile:482`, `scripts/podman/e2e-root-only.sh:22-29`.

`&& true`, suppressed hash errors, and warning-only cleanup allow failed
diagnostics or cleanup to produce passing results.

### TA-015: Tests execute subjects outside Bats assertions

**Location:** `tests/shell/21-shell-guard.bats:202-208`.

The same command is run directly several times before the captured assertion,
so failures and side effects are outside the test result.

### TA-016: Permission changes lack guaranteed restoration

**Location:** `tests/shell/21-shell-guard.bats:841-855`.

The test changes `/bin/bash.real` mode and has no unconditional restoration trap.

### TA-017: Assertions are weaker than their security claims

**Locations:** `tests/shell/21-shell-guard.bats:176-187,622-626,729-734,763-767`;
`tests/shell/22-shell-guard-install.bats:81-87,225-232`.

Examples include checking only absence of `BLOCKED`, accepting any `NOFILE` value
below the limit, testing a nonexistent path as “unreadable,” and checking only
idempotency output instead of inode/capability/diversion state.

### TA-018: Fake binaries validate choreography, not behavior

**Locations:** `tests/shell/lib/fake_repo.bash:50-59`,
`tests/shell/10-binary-guard-build.bats:65-91`,
`src/attack_surface_tests.rs:150-235`.

Sentinel binaries, source-string checks, and fake paths do not execute the
production guard or validate its filesystem and capability boundary.

### TA-019: Global test state is unsynchronized

**Location:** `src/binary_guard_tests.rs:288-317`.

Tests mutate process-global environment without a shared lock, allowing parallel
test interference and nondeterministic results.

### TA-020: Toolchain selection differs across gates

**Locations:** `Makefile:239-247`, `scripts/podman/tier1-test.sh:39-67`,
`.pre-commit-config.yaml:57-71`.

Some paths use the CI-owned toolchain, others use bare `cargo`; `cargo test`
removes per-test timeouts when `nextest` is absent.

### TA-021: Quick/special test modes can be mistaken for full success

**Locations:** `Makefile:298-300`, `scripts/test-in-podman.sh:54-59`.

Tier 3 can be skipped while the harness still ends with a generic success banner.

## Low Findings

- `tests/shell/05-binary-lock-yaml.bats:65-68`: hard-coded “live” SUID data and empty capability data.
- `tests/shell/00-harness.bats:41-45`: validates stubbed UID rather than actual privilege.
- `tests/shell/21-shell-guard.bats:827-836`: capability fixture does not assert UID, ownership, or capability state before use.
- `src/log.rs:135-183`: logging tests omit permissions, concurrency, injection, redaction, and failure behavior.
- `src/yaml_edit_schema_tests.rs:78-80`: permissive unknown-basename behavior is not paired with filesystem-security assertions.
- `src/vendored_tests.rs:61-67`: missing enforcement-file cases do not distinguish safe absence from malformed or replaced state.
- `docs/requirements/REQ-PODMAN-TESTING.md:151-156`: test contract does not require post-cleanup host-state verification.

## Remediation Plan

1. Move host `test-shell` execution into the isolated Podman test image when a
   host guard is active; never use `bash.distrib` or expose `/bin/bash.real`.
2. Remove all tests that create, remove, or chmod live `/bin/bash.real`.
3. Replace shared `/tmp` fixtures with private, unique, ownership-checked test
   directories.
4. Turn security-test skips into explicit incomplete/failure states unless the
   test is intentionally platform-specific and reported as such.
5. Remove diagnostic `&& true`, warning-only cleanup, and suppressed security
   probe failures.
6. Require compiled binary presence and execute the binary under test.
7. Add integration coverage for symlinks, memfd seals, AT_SECURE, capabilities,
   argv/env preservation, audit redaction, and YAML filesystem security.
8. Pin test images and fetched dependencies, or use validated local artifacts.
9. Separate Podman tiers into clean containers and verify cleanup state after
   every E2E run.
10. Make the Linux pre-push gate invoke the authoritative shell-guard runtime
    suite, not only provisioning checks.
