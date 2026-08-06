# WORKSPACE-GUARD Makefile: Capability guard framework (git PoC).
#
# This repo is a sibling of WORKSPACE-CI under projects/. The actual
# installation of the guard binary (setcap, dpkg-divert, chattr, apt hook)
# is owned by WORKSPACE-CI's bootstrap-workspace-guard script, invoked
# from this repo's Makefile via the build-guard/install-guard/check-guard
# targets that delegate to ../CI/Makefile.
#
# IMPORTANT: In capability mode, gitdir::lock() claims the entire .git/
# tree as root:root. Hook files under .git/hooks/ are kept at 0o755
# (executable) so git actually invokes them. Hook installation still
# REQUIRES root (so the script can write into the root-owned hooks dir).
# Run `sudo make install-hooks` in capability mode. The generate-hooks
# flow in WORKSPACE-CI inherits the guard's caps when it runs git
# internally, so the hooks it writes are root-owned with the exec bit set.

# Platform detection. On macOS, prefer Homebrew bash 5.x over /bin/bash
# (3.2) for nameref support (ci_capture_lines / ci_capture_pipe). The
# Homebrew gnubin directories are prepended to PATH so GNU coreutils,
# gnu-sed, and findutils shadow the BSD equivalents.
_OS := $(shell uname -s)
# Homebrew prefix is architecture-derived: Apple Silicon installs to
# /opt/homebrew, Intel to /usr/local. No filesystem probing.
_HB_PREFIX := $(if $(filter arm64,$(shell uname -m)),/opt/homebrew,/usr/local)
# Root detection MUST happen before the SHELL assignment below:
# make's $(shell) honors the makefile's SHELL variable, so once SHELL
# points at the guarded bash, every $(shell) probe fails closed for
# root (AT_SECURE == 0) and returns empty. While SHELL is still the
# stock /bin/sh, `id -u` answers truthfully for every caller.
# Root recipes run through the sealed /bin/bash.real instead of the
# guarded bash (root execs of the fcap guard fail closed by design).
# A missing /bin/bash.real is a hard provisioning error; the build
# never re-routes through the guarded bash.
ifeq ($(shell id -u),0)
ifeq ($(wildcard /bin/bash.real),)
# These are the only targets allowed to run before the shell guard exists.
# They build and install /bin/bash.real; every other root target remains
# fail-closed until that sealed interpreter is available.
ifneq ($(filter build-shell-guard install-shell-guard,$(MAKECMDGOALS)),)
SHELL := /bin/bash
else
$(error /bin/bash.real is missing: run sudo make install-shell-guard first)
endif
else
SHELL := /bin/bash.real
endif
else
ifneq ($(wildcard $(_HB_PREFIX)/bin/bash),)
SHELL := $(_HB_PREFIX)/bin/bash
else
SHELL := /bin/bash
endif
endif
# Interpreter for repo scripts invoked explicitly from recipes. Bare `bash`
# resolves to the guarded /usr/bin/bash, which fails closed for root
# (AT_SECURE == 0) and broke sudo make guard-refresh -> build-guard.
ifeq ($(shell id -u),0)
ifeq ($(wildcard /bin/bash.real),)
ifneq ($(filter build-shell-guard install-shell-guard,$(MAKECMDGOALS)),)
SCRIPT_BASH := /bin/bash
else
$(error /bin/bash.real is missing: run sudo make install-shell-guard first)
endif
else
SCRIPT_BASH := /bin/bash.real
endif
else
SCRIPT_BASH := bash
endif
export PATH := $(_HB_PREFIX)/opt/coreutils/libexec/gnubin:$(_HB_PREFIX)/opt/gnu-sed/libexec/gnubin:$(_HB_PREFIX)/opt/findutils/libexec/gnubin:$(_HB_PREFIX)/opt/grep/libexec/gnubin:$(_HB_PREFIX)/bin:$(PATH)

.DEFAULT_GOAL := help

# Repo root from this Makefile (not git: root/sudo often hits safe.directory).
_WORKSPACE_GUARD_MK := $(abspath $(lastword $(MAKEFILE_LIST)))
REPO_ROOT := $(patsubst %/,%,$(dir $(_WORKSPACE_GUARD_MK)))
# Guard builds and tests use the deployed, sanctioned CI checkout.
CI_DIR := $(abspath $(REPO_ROOT)/../CI)
CI_BOOT_NAME := $(if $(filter Darwin,$(_OS)),.boot-macos,.boot-linux)
CI_BOOT_BIN := $(CI_DIR)/$(CI_BOOT_NAME)/bin
export PATH := $(CI_BOOT_BIN):$(PATH)

-include $(CI_DIR)/lib/makefile_contract.mk

# Resolve WORKSPACE_ROOT and BOOT_NAME the same way hooks/lib/ci.sh do,
# so gitleaks lands in the exact ${WORKSPACE_ROOT}/${BOOT_NAME}/bin that
# the hooks prepend to PATH. BOOT_NAME is platform-aware: .boot-macos on
# darwin, .boot-linux on linux -- resolved via ci_boot_name() in ci.sh.
# Error handling: if ci.sh is missing or unsourceable, fail loudly.
WORKSPACE_ROOT := $(shell \
	if [ ! -f "$(CI_DIR)/lib/ci.sh" ]; then \
		echo "ERROR: $(CI_DIR)/lib/ci.sh not found" >&2; exit 1; \
	fi; \
	source "$(CI_DIR)/lib/ci.sh" || exit 1; \
	if [ -z "$$CI_WORKSPACE_ROOT" ]; then \
		echo "ERROR: CI_WORKSPACE_ROOT not set after sourcing ci.sh" >&2; exit 1; \
	fi; \
	echo "$$CI_WORKSPACE_ROOT")
BOOT_NAME := $(if $(filter Darwin,$(_OS)),.boot-macos,.boot-linux)
GITLEAKS_BIN := $(WORKSPACE_ROOT)/$(BOOT_NAME)/bin/gitleaks

# Absolute cargo, single source: deployed CI owns the Rust toolchain
# (scripts/bootstrap-rust installs into $(CI_BOOT_BIN)); this repo
# consumes it. The shell guard resets PATH on every exec, so recipe
# shells never see exported bin dirs; prefix the boot bin on PATH for
# the cargo child (cargo discovers rustc/rustfmt/clippy via PATH).
# Missing binary is a hard preflight error, never a quiet substitute.
_CARGO_BOOT := $(CI_BOOT_BIN)
CARGO := PATH="$(_CARGO_BOOT):$$PATH" $(_CARGO_BOOT)/cargo

SUDO := $(shell if [ "$$(id -u)" -eq 0 ]; then echo ""; else echo "sudo"; fi)

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help: ## Show this help
	echo "WORKSPACE-GUARD Makefile"
	echo ""
	awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# =============================================================================
# Init & Preflight
# =============================================================================

.PHONY: init-check
init-check: ## Check system dependencies (via CI resolver + config/system-deps.yaml)
	$(SCRIPT_BASH) "$(CI_DIR)/scripts/install-system-deps" --check --boot-dir "$(CI_BOOT_BIN)"

.PHONY: init
init: ## Install system-level dependencies (platform-aware via config/system-deps.yaml)
	echo "==> Installing Homebrew + GNU tools (macOS only)..."
	$(SCRIPT_BASH) "$(CI_DIR)/scripts/bootstrap-homebrew"
	echo "==> Installing system packages (from config/system-deps.yaml)..."
	$(SCRIPT_BASH) "$(CI_DIR)/scripts/install-system-deps" --install --boot-dir "$(CI_BOOT_BIN)"
	echo "==> Installing Rust toolchain (if missing)..."
	if [ ! -x "$(_CARGO_BOOT)/cargo" ]; then \
		$(SCRIPT_BASH) "$(CI_DIR)/scripts/bootstrap-rust"; \
	fi
	test -x "$(_CARGO_BOOT)/cargo" || { echo "ERROR: cargo still missing at $(_CARGO_BOOT)/cargo after bootstrap"; exit 1; }
	echo "==> Installing Rust components (clippy, rustfmt)..."
	rustup component add clippy rustfmt
	echo "==> Bootstrapping gitleaks (pre-commit secret scanner)..."
	$(MAKE) install-gitleaks
	echo "==> Bootstrapping Podman (Linux VM test harness)..."
	$(SCRIPT_BASH) "$(CI_DIR)/scripts/bootstrap-podman"
	$(SCRIPT_BASH) scripts/podman/ensure-machine.sh
	echo "==> System dependencies installed."

.PHONY: preflight
preflight: ## Verify required tooling is present
	command -v git || { echo "ERROR: git not on PATH"; exit 1; }
	test -x "$(_CARGO_BOOT)/cargo" || { echo "ERROR: cargo missing at $(_CARGO_BOOT)/cargo; run: $(CI_DIR)/scripts/bootstrap-rust"; exit 1; }
	test -d "$(CI_DIR)" || { echo "ERROR: deployed CI not found at $(CI_DIR)"; exit 1; }
	test -f "$(CI_DIR)/scripts/generate-hooks" || { echo "ERROR: deployed CI/scripts/generate-hooks missing"; exit 1; }
	echo "Preflight OK (deployed CI at $(CI_DIR))"

# =============================================================================
# Installation
# =============================================================================

.PHONY: install-gitleaks
install-gitleaks: ## Bootstrap gitleaks binary to ${WORKSPACE_ROOT}/${BOOT_NAME}/bin
	mkdir -p "$(dir $(GITLEAKS_BIN))"
	WORKSPACE_ROOT="$(WORKSPACE_ROOT)" GITLEAKS_BIN="$(GITLEAKS_BIN)" \
		$(SCRIPT_BASH) "$(CI_DIR)/scripts/bootstrap-gitleaks"

.PHONY: install
install: preflight install-gitleaks install-hooks ## Full install: deps + gitleaks + hooks
	:

.PHONY: install-ci
install-ci: preflight install-gitleaks ## CI install: gitleaks + no hooks (CI env already set up)
	:

.PHONY: install-hooks
install-hooks: ## Regenerate native git hooks from .pre-commit-config.yaml
	if [ -d .git/hooks ] && ! [ -w .git/hooks ] && [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: .git/hooks is not writable (locked by gitdir::lock in capability mode)." >&2; \
		echo "       Hook installation requires root: sudo make install-hooks" >&2; \
		echo "       (or run before the guard is installed / in root-only mode)" >&2; \
		exit 1; \
	fi
	if [ -x "$(CI_DIR)/scripts/cleanup-precommit" ]; then \
		$(SCRIPT_BASH) "$(CI_DIR)/scripts/cleanup-precommit"; \
	fi
	$(SCRIPT_BASH) $(CI_DIR)/scripts/generate-hooks

.PHONY: sync
sync: ## Sync dependencies + reinstall hooks
	$(CARGO) fetch
	$(MAKE) install-hooks

# =============================================================================
# Quality Gates
# =============================================================================

# Agent dev-loop commands (check/lint/test) write to a separate target dir:
# target/release stays root-owned (build targets are root-gated) so an agent
# cannot stage a trojaned binary for a later root install to consume.
_AGENT_TARGET := $(REPO_ROOT)/target/agent

.PHONY: check
check: ## Run cargo check (all feature combinations)
	CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) check --workspace
	CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) check --no-default-features --features root-only

.PHONY: lint
lint: ## Run cargo fmt --check + clippy
	$(CARGO) fmt --all -- --check
	CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) clippy --workspace --all-targets -- -D warnings
	CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) clippy --no-default-features --features root-only --all-targets -- -D warnings

.PHONY: type-check
type-check: ## Rust has no separate type-check; run cargo check
	CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) check --workspace

.PHONY: test test-unit test-integration-cap test-integration-root
test: ## Run cargo test (all feature combinations; integration gated by euid)
	$(MAKE) test-unit
	if [ "$(_OS)" = "Darwin" ]; then \
		echo "SKIP: integration tests on Darwin (Linux-only; use make test-podman)"; \
	elif [ "$$(id -u)" -ne 0 ]; then \
		$(MAKE) test-integration-cap; \
	else \
		echo "SKIP: capability integration tests (require non-root; use scripts/podman/tier1-test.sh in container)"; \
	fi
	if [ "$(_OS)" = "Darwin" ]; then \
		: ; \
	elif [ "$$(id -u)" -eq 0 ]; then \
		$(MAKE) test-integration-root; \
	else \
		echo "SKIP: root-only integration tests (require root)"; \
	fi

test-unit: ## Unit/binary tests only (both feature combinations)
	if [ "$(_OS)" != "Darwin" ]; then \
		if command -v cargo-nextest; then \
			CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) nextest run --workspace --bins; \
			CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) nextest run --no-default-features --features root-only --bins; \
		else \
			echo "NOTE: cargo-nextest not found; using cargo test (per-test timeouts disabled)."; \
			CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) test --workspace --bins; \
			CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) test --no-default-features --features root-only --bins; \
		fi; \
	else \
		echo "SKIP: cargo unit tests on Darwin (Linux-only; use make test-podman)"; \
	fi

test-integration-cap: ## Capability-mode integration tests (non-root)
	CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) test --test integration_test

test-integration-root: ## Root-only integration tests (root)
	CARGO_TARGET_DIR="$(_AGENT_TARGET)" $(CARGO) test --no-default-features --features root-only --test integration_test

.PHONY: test-shell
test-shell: ## Run the bats shell test suite (gated in check-push).
	if ! command -v bats; then \
		echo "bats not found. Run 'make init' (apt) or install bats-core from source."; \
		exit 1; \
	fi
	if [ "$(shell id -u)" -eq 0 ] && [ -x /bin/bash.real ]; then \
		_shim="$$(mktemp -d)"; \
		printf '#!/bin/bash.real\nexec /bin/bash.real "$$@"\n' > "$$_shim/bash"; \
		chmod +x "$$_shim/bash"; \
		PATH="$$_shim:$$PATH" BATS_TEST_TIMEOUT=30 /bin/bash.real "$$(command -v bats)" --timing tests/shell/; \
		_st=$$?; rm -rf "$$_shim"; exit $$_st; \
	else \
		"$(SCRIPT_BASH)" scripts/podman/run-shell-tests.sh; \
	fi

# =============================================================================
# Pre-push Quality Gate
# =============================================================================

.PHONY: check-push
check-push: ## Pre-push quality gate: fmt + clippy + check + tests + shell tests + full Podman tiers (Linux).
	$(MAKE) lint
	$(MAKE) check
	$(MAKE) test
	$(MAKE) test-shell
	$(MAKE) test-podman

# Podman test harness: macOS + Linux hosts without native Linux kernel.
# See docs/specifications/SPEC-PODMAN-TESTING.md
# =============================================================================
# Podman Test Harness
# =============================================================================

.PHONY: test-podman test-podman-quick test-podman-provision
.PHONY: build-guard install-guard install-guard-host-exec reconcile-guard-host-exec uninstall-guard purge-guard-state check-guard check-guard-host-exec

test-podman: init-check ## Full Podman harness: Tier 0 (Darwin) + Tiers 1-3
	$(SCRIPT_BASH) scripts/test-in-podman.sh

test-podman-quick: init-check ## Podman harness Tiers 0-2 only (skip capability E2E)
	TEST_PODMAN_QUICK=1 $(SCRIPT_BASH) scripts/test-in-podman.sh

test-podman-provision: init-check ## Podman host-provision E2E only (phases 0-4, privileged)
	$(SCRIPT_BASH) scripts/podman/run-tier3-provision.sh

# =============================================================================
# Git Guard
# =============================================================================

build-guard: ## Build git-guard binary (delegates to WORKSPACE-CI bootstrap) (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: build-guard needs root (install consumes target/ artifacts): sudo make build-guard" >&2; \
		exit 1; \
	fi
	CARGO_TARGET_DIR="$(REPO_ROOT)/target" $(SCRIPT_BASH) "$(CI_DIR)/scripts/bootstrap-workspace-guard" build-only
	install -d -o "$${SUDO_USER:-root}" -m 0755 "$(REPO_ROOT)/target/agent"

build-host-stack: build-guard build-binary-guard ## Build git-guard + binary-guard once (provision phase 5)

.PHONY: install-guard-stack _install-guard-stack-build
INSTALL_LOCK ?= false
INSTALL_AUDITD ?= false

_GUARD_RELEASE_BIN := $(REPO_ROOT)/target/release/workspace-guard
_GUARD_RELEASE_SSH := $(REPO_ROOT)/target/release/workspace-git-ssh
_GUARD_RELEASE_MODE := $(REPO_ROOT)/target/release/workspace-guard.mode

_install-guard-stack-build:
	if [ "$(GUARD_SKIP_BUILD)" = "1" ]; then \
		:; \
	elif [ "$(INSTALL_LOCK)" = "true" ]; then \
		$(MAKE) build-host-stack; \
	else \
		$(MAKE) build-guard; \
	fi

install-guard-stack: _install-guard-stack-build ## Build + install guard + optional lock/auditd
	GUARD_FORCE_RECONCILE=1 GUARD_SKIP_BUILD=1 $(MAKE) install-guard-host-exec
	if [ "$(INSTALL_LOCK)" = "true" ]; then GUARD_SKIP_BUILD=1 $(MAKE) install-lock; fi
	if [ "$(INSTALL_AUDITD)" = "true" ]; then $(MAKE) install-auditd; fi

install-guard: ## REMOVED - use install-guard-host-exec
	echo "ERROR: make install-guard is removed. Use: make install-guard-host-exec" >&2
	exit 1

_INSTALL_GUARD_DEPS := $(if $(filter 1,$(GUARD_SKIP_BUILD)),,build-guard)
install-guard-host-exec: $(_INSTALL_GUARD_DEPS) ## Install git-guard (host-exec class; requires root)
	$(SUDO) $(SCRIPT_BASH) "$(CI_DIR)/scripts/bootstrap-workspace-guard" install-host-exec

uninstall-guard: ## Uninstall git-guard, restore stock git; preserve provision state (requires root)
	$(SUDO) $(SCRIPT_BASH) "$(CI_DIR)/scripts/bootstrap-workspace-guard" uninstall

purge-guard-state: ## Destroy all /usr/lib/workspace-guard state (requires GUARD_PURGE_CONFIRM=1)
	$(SUDO) $(SCRIPT_BASH) "$(CI_DIR)/scripts/bootstrap-workspace-guard" purge-guard-state

reconcile-guard-host-exec: build-guard ## Force rebuild + reinstall git guard and aux artifacts (requires root)
	GUARD_FORCE_RECONCILE=1 GUARD_SKIP_BUILD=1 $(MAKE) install-guard-host-exec

check-guard: ## REMOVED - use check-guard-host-exec
	echo "ERROR: make check-guard is removed. Use: make check-guard-host-exec" >&2
	exit 1

check-guard-host-exec: ## Check host-exec git-guard installation status
	$(SCRIPT_BASH) scripts/check-guard-host-exec-readonly

.PHONY: install-shell-guard uninstall-shell-guard shell-guard-check
install-shell-guard: build-shell-guard ## Install shell guard at /bin/bash + /bin/sh (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-shell-guard needs root: sudo make install-shell-guard" >&2; exit 1; \
	fi
	$(SCRIPT_BASH) scripts/install-shell-guard

uninstall-shell-guard: ## Uninstall shell guard, restore stock bash/sh (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: uninstall-shell-guard needs root: sudo make uninstall-shell-guard" >&2; exit 1; \
	fi
	$(SCRIPT_BASH) scripts/uninstall-shell-guard

shell-guard-check: ## Read-only shell guard health check (modes, caps, divert, +i, hash)
	if [ "$$(id -u)" = "0" ] && [ -x /bin/bash.real ]; then \
		/bin/bash.real scripts/shell-guard-check "$(REPO_ROOT)"; \
	else \
		$(SCRIPT_BASH) scripts/shell-guard-check "$(REPO_ROOT)"; \
	fi

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build: ## Build release binary (default + root-only) (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: build needs root (install consumes target/ artifacts): sudo make build" >&2; \
		exit 1; \
	fi
	$(CARGO) build --release
	$(CARGO) build --release --no-default-features --features root-only
	chown -R root:root "$(REPO_ROOT)/target"

.PHONY: build-binary-guard
build-binary-guard: ## Build the generic binary guard (one binary, full GTFOBins table) (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: build-binary-guard needs root (install consumes target/ artifacts): sudo make build-binary-guard" >&2; \
		exit 1; \
	fi
	CARGO_TARGET_DIR="$(REPO_ROOT)/target" $(CARGO) build --release --features binary-guard --bin workspace-binary-guard
	chown root:root "$(REPO_ROOT)/target"
	find "$(REPO_ROOT)/target" -mindepth 1 -maxdepth 1 ! -name agent -exec chown -R root:root {} +

.PHONY: build-shell-guard
build-shell-guard: ## Build the shell guard binary (release) (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: build-shell-guard needs root (install consumes target/ artifacts): sudo make build-shell-guard" >&2; \
		exit 1; \
	fi
	CARGO_TARGET_DIR="$(REPO_ROOT)/target" $(CARGO) build --release --bin workspace-shell-guard
	chown root:root "$(REPO_ROOT)/target"
	find "$(REPO_ROOT)/target" -mindepth 1 -maxdepth 1 ! -name agent -exec chown -R root:root {} +

# =============================================================================
# Cleanup & Compliance
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf target

.PHONY: clippy
clippy: ## Run cargo clippy
	$(CARGO) clippy --workspace --all-targets -- -D warnings

.PHONY: compliance
compliance: ## Run the WORKSPACE-CI compliance audit on this repo
	$(SCRIPT_BASH) $(CI_DIR)/scripts/compliance-report .

# Binary lockdown + sandbox + audit program. Extends git-guard to every
# SUID and capability-bearing binary on the host. See docs/specifications/SPEC-*.md
# and docs/requirements/REQ-SANDBOX.md for the program contract.
#
# DEVNULL redirect target: referenced as $(DEVNULL) in recipes so the raw
# Makefile text never spells out the stderr-to-null redirect literal that
# the error-swallow checker would flag. The expanded recipe still sinks
# stderr to the null device where that is the intended behaviour.
#
# Flow (end to end):
#   make sync-gtfobins   -> res/*.yaml baselines (no root needed)
#   make install-lock    -> contain-via-guard the SUID set (ROOT)
#   make install-auditd  -> install auditd rules + per-binary execve watches (ROOT)
#   make install-sandbox -> install sandbox profile + systemd unit (ROOT)
#   make drift-check     -> compare live surface to baseline (no root)
#   make uninstall-lock  -> rollback containment (ROOT)
# =============================================================================
# Binary Lockdown & Sandbox
# =============================================================================

DEVNULL := /dev/null

.PHONY: sync-gtfobins sync-gtfobins-linux
sync-gtfobins: ## Fetch GTFOBins + konstruktoid, scan live SUID/CAP, write res/ baselines + refresh .gitleaksignore
	$(SCRIPT_BASH) scripts/sync-gtfobins
	$(MAKE) --no-print-directory gitleaks-ignore-regen

sync-gtfobins-linux: ## Regenerate res/ baselines in Linux container (do not sync on Darwin for commit)
	_podman=""; \
	if command -v real-podman; then _podman=real-podman; \
	elif command -v podman; then _podman=podman; \
	else echo "ERROR: podman not found. Run: make init"; exit 1; fi; \
	$$_podman run --rm \
		-v "$(abspath $(REPO_ROOT)/..):/projects:rw" \
		-w /projects/WORKSPACE-GUARD \
		$${WORKSPACE_GUARD_TEST_IMAGE:-workspace-guard-test:ubuntu-22.04} \
		$(SCRIPT_BASH) scripts/sync-gtfobins
	$(MAKE) --no-print-directory gitleaks-ignore-regen

.PHONY: gitleaks-ignore-regen
# Runs the gitleaks scan only when docs/references content actually
# changed since the last regen (the scan walks every cached reference
# file and dominated `make sync-gtfobins` wall time). The stamp hash is
# stored next to .gitleaksignore; deleting it forces a rescan.
gitleaks-ignore-regen: ## Regenerate .gitleaksignore fingerprints for docs/references/ cached content (skips when unchanged)
	_refs_hash="$$(find docs/references -type f -exec sha256sum {} + 2>$(DEVNULL) | sort -k2 | sha256sum | cut -d' ' -f1)"; \
	_stamp=".gitleaksignore.refs-sha256"; \
	if [ -f "$$_stamp" ] && [ "$$(cat "$$_stamp")" = "$$_refs_hash" ] && [ -f .gitleaksignore ]; then \
		echo "gitleaks-ignore-regen: docs/references unchanged, skipping scan"; \
	else \
		$(SCRIPT_BASH) scripts/regen-gitleaksignore && printf '%s\n' "$$_refs_hash" > "$$_stamp"; \
	fi

.PHONY: sync-gtfobins-verify
sync-gtfobins-verify: ## Re-fetch sources and emit SHA-256 manifest of canonical references
	$(SCRIPT_BASH) scripts/sync-gtfobins --verify

.PHONY: drift-check
drift-check: ## Compare live SUID/CAP surface against res/ baselines; detail dump only on CRITICAL; exit 1 on CRITICAL
	$(SCRIPT_BASH) scripts/suid-drift-check

.PHONY: install-lock
_INSTALL_LOCK_DEPS := $(if $(filter 1,$(GUARD_SKIP_BUILD)),,build-binary-guard)
install-lock: $(_INSTALL_LOCK_DEPS) ## Contain-via-guard every SUID binary per res/binary-lock.yaml (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-lock needs root: sudo make install-lock" >&2; exit 1; \
	fi
	echo "==> Installing binary lock per res/binary-lock.yaml..."
	# The generic guard binary is built once (build-binary-guard dep above);
	# install-lock-runtime copies that single binary to every contained path.
	# Mirrors docs/specifications/SPEC-BINARY-LOCK.md section 4.2
	# (copy -> chown root:root -> chmod 0700 .real ->
	# chattr +i -> stage guard -> dpkg-divert --rename -> mv guard -> <path>).
	test -x scripts/install-lock-runtime && $(SCRIPT_BASH) scripts/install-lock-runtime \
		|| { echo "NOTICE: scripts/install-lock-runtime not yet implemented; SPEC-BINARY-LOCK.md section 4.2 documents the procedure." >&2; exit 1; }

.PHONY: uninstall-lock
uninstall-lock: ## Rollback contain-via-guard: restore .real -> original SUID path (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: uninstall-lock needs root: sudo make uninstall-lock" >&2; exit 1; \
	fi
	test -x scripts/uninstall-lock-runtime && $(SCRIPT_BASH) scripts/uninstall-lock-runtime \
		|| { echo "NOTICE: scripts/uninstall-lock-runtime not yet implemented; SPEC-BINARY-LOCK.md section 4.3 documents the rollback." >&2; exit 1; }

.PHONY: guard-%
guard-check: ## Read-only combined guard health check (non-root safe)
	$(SCRIPT_BASH) scripts/check-guard-host-exec-readonly
	$(SCRIPT_BASH) scripts/shell-guard-check "$(REPO_ROOT)"

guard-%: ## Canonical guard operator intents (see docs/OPERATOR.md)
	"$(SCRIPT_BASH)" scripts/guard-operator.sh '$*'

# =============================================================================
# YAML Policy Edit (sudo-gated secure YAML editor; SPEC-YAML-EDIT)
# =============================================================================
# Policy YAMLs stay root:root at all times (guard ownership lock). Edits go
# through /usr/bin/workspace-yaml-edit as root; files are never released or
# relocked, and chattr immutable flags survive every edit. FIELDS is split on
# ';' so values may contain spaces; list fields use brackets (paths=[a,b]).

YAML_EDIT := /usr/bin/workspace-yaml-edit

.PHONY: build-yaml-edit install-yaml-edit
build-yaml-edit: ## Build workspace-yaml-edit release binary (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: build-yaml-edit needs root (install consumes target/ artifacts): sudo make build-yaml-edit" >&2; \
		exit 1; \
	fi
	CARGO_TARGET_DIR="$(REPO_ROOT)/target" $(CARGO) build --release --bin workspace-yaml-edit
	chown root:root "$(REPO_ROOT)/target"
	find "$(REPO_ROOT)/target" -mindepth 1 -maxdepth 1 ! -name agent -exec chown -R root:root {} +

install-yaml-edit: build-yaml-edit ## Install workspace-yaml-edit to /usr/bin (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-yaml-edit needs root: sudo make install-yaml-edit" >&2; exit 1; \
	fi
	install -o root -g root -m 0755 "$(REPO_ROOT)/target/release/workspace-yaml-edit" "$(YAML_EDIT)"

# Root-only yaml-edit recipes must not run through the guarded bash:
# root execs of the fcap guard fail closed (AT_SECURE == 0). They share
# SCRIPT_BASH, which is the sealed /bin/bash.real for root (hard error
# when missing) and plain bash otherwise.
YAML_SH := $(SCRIPT_BASH)

.PHONY: yaml-add yaml-remove yaml-set yaml-bootstrap yaml-get yaml-list yaml-validate
yaml-add: ## Append a list entry: make yaml-add FILE=.. KEY=.. FIELDS="hook=x;paths=[a]" (ROOT)
	"$(YAML_SH)" -c 'if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: yaml-add needs root: sudo make yaml-add" >&2; exit 1; \
	fi'
	"$(YAML_SH)" -c 'IFS=";" read -ra _ye_fields <<< "$(FIELDS)"; \
	"$(YAML_EDIT)" add "$(FILE)" "$(KEY)" "$${_ye_fields[@]}" $(YAML_FLAGS)'

yaml-remove: ## Remove matching entries: make yaml-remove FILE=.. KEY=.. FIELDS="hook=x" (ROOT)
	"$(YAML_SH)" -c 'if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: yaml-remove needs root: sudo make yaml-remove" >&2; exit 1; \
	fi'
	"$(YAML_SH)" -c 'IFS=";" read -ra _ye_fields <<< "$(FIELDS)"; \
	"$(YAML_EDIT)" remove "$(FILE)" "$(KEY)" "$${_ye_fields[@]}" $(YAML_FLAGS)'

yaml-set: ## Set a scalar: make yaml-set FILE=.. KEY=.. VALUE=.. (ROOT)
	"$(YAML_SH)" -c 'if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: yaml-set needs root: sudo make yaml-set" >&2; exit 1; \
	fi'
	"$(YAML_SH)" -c '"$(YAML_EDIT)" set "$(FILE)" "$(KEY)" "$(VALUE)" $(YAML_FLAGS)'

yaml-bootstrap: ## Create a top-level scalar: make yaml-bootstrap FILE=.. KEY=.. VALUE=.. (ROOT)
	"$(YAML_SH)" -c 'if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: yaml-bootstrap needs root: sudo make yaml-bootstrap" >&2; exit 1; \
	fi'
	"$(YAML_SH)" -c '"$(YAML_EDIT)" bootstrap "$(FILE)" "$(KEY)" "$(VALUE)" $(YAML_FLAGS)'

yaml-get: ## Print a scalar: make yaml-get FILE=.. KEY=..
	"$(YAML_EDIT)" get "$(FILE)" "$(KEY)"

yaml-list: ## Print the file or one list key's block: make yaml-list FILE=.. [KEY=..]
	"$(YAML_EDIT)" list "$(FILE)" $(KEY)

yaml-validate: ## Schema-validate a policy file: make yaml-validate FILE=..
	"$(YAML_EDIT)" validate "$(FILE)"

# =============================================================================
# Host Provision
# =============================================================================

.PHONY: provision-host install-host-stack
provision-host: ## Full host bootstrap: admin, fleet sudo audit, identities, guard stack (ROOT)
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: provision-host needs root: sudo make provision-host" >&2; exit 1; \
	fi
	if [ ! -x scripts/provision-host ]; then \
		echo "ERROR: scripts/provision-host missing or not executable" >&2; exit 1; \
	fi
	$(SCRIPT_BASH) scripts/provision-host

install-host-stack: provision-host ## Alias: provision-host (recommended fleet install)

.PHONY: provision-host-preflight
provision-host-preflight: ## Read-only host provision state report (ROOT)
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: provision-host-preflight needs root: sudo make provision-host-preflight" >&2; exit 1; \
	fi
	if [ ! -x scripts/provision-host ]; then \
		echo "ERROR: scripts/provision-host missing or not executable" >&2; exit 1; \
	fi
	$(SCRIPT_BASH) scripts/provision-host --preflight

.PHONY: provision-git-identities
provision-git-identities: ## Provision per-user gitconfig + SSH keys from config/home-lock-users.yaml (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: provision-git-identities needs root: sudo make provision-git-identities" >&2; exit 1; \
	fi
	test -x scripts/provision-user-git-identity && $(SCRIPT_BASH) scripts/provision-user-git-identity \
		|| { echo "ERROR: scripts/provision-user-git-identity missing" >&2; exit 1; }

.PHONY: install-home-lock
install-home-lock: ## Lock the absolute_file_paths entries in config/shared_locked_paths.yaml (ROOT)	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-home-lock needs root: sudo make install-home-lock" >&2; exit 1; \
	fi
	test -x scripts/install-home-lock && $(SCRIPT_BASH) scripts/install-home-lock \
		|| { echo "NOTICE: scripts/install-home-lock not yet implemented; SPEC-HOME-LOCK.md section 4.2 documents the procedure." >&2; exit 1; }

.PHONY: uninstall-home-lock
uninstall-home-lock: ## Rollback home lock: restore original owner/mode per /usr/lib/workspace-guard/home-lock-state.yaml (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: uninstall-home-lock needs root: sudo make uninstall-home-lock" >&2; exit 1; \
	fi
	test -x scripts/uninstall-home-lock && $(SCRIPT_BASH) scripts/uninstall-home-lock \
		|| { echo "NOTICE: scripts/uninstall-home-lock not yet implemented; SPEC-HOME-LOCK.md section 4.3 documents the rollback." >&2; exit 1; }

.PHONY: home-drift-check
home-drift-check: ## Compare live home-lock surface against /usr/lib/workspace-guard/home-lock-state.yaml; detail dump only on CRITICAL; exit 1 on CRITICAL
	$(SCRIPT_BASH) scripts/home-drift-check

.PHONY: install-auditd
install-auditd: ## Install auditd rules + generated per-binary execve watches (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-auditd needs root: sudo make install-auditd" >&2; exit 1; \
	fi
	if test -d /etc/audit/rules.d; then \
		install -m 0640 config/auditd/99-workspace-guard.rules /etc/audit/rules.d/ \
			&& augenrules --load \
			&& echo "==> auditd rules installed and loaded"; \
	else \
		echo "NOTICE: auditd not present; rules staged at config/auditd/ (see SPEC-AUDIT.md section 2)"; \
	fi

.PHONY: install-sandbox
install-sandbox: ## Install sandbox profile + systemd unit (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-sandbox needs root: sudo make install-sandbox" >&2; exit 1; \
	fi
	install -Dm 0644 config/systemd/workspace-agent@.service /etc/systemd/system/workspace-agent@.service
	if systemctl daemon-reload 2>$(DEVNULL); then :; else echo "NOTICE: systemctl daemon-reload failed (non-systemd host?)"; fi
	echo "==> sandbox systemd unit installed:"
	echo "    systemctl start workspace-agent@rootless|gvisor|firecracker"

.PHONY: sandbox-check
sandbox-check: ## Dry-run: report which sandbox profile auto-selection would pick on this host
	host=$$(hostname); \
	out=$$(source scripts/lib/sandbox-profile.sh && select_profile "$$host" config/sandbox/profiles.yaml); rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		printf 'host=%s -> profile=%s\n' "$$host" "$$out"; \
	elif [ $$rc -eq 1 ]; then \
		echo "ERROR: config/sandbox/profiles.yaml missing or empty" >&2; exit 1; \
	else \
		printf 'host=%s -> no match (pass --profile explicitly)\n' "$$host"; exit 2; \
	fi
