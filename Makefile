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
_HB_PREFIX := $(if $(wildcard /opt/homebrew),/opt/homebrew,$(if $(wildcard /usr/local),/usr/local))
SHELL := $(if $(wildcard $(_HB_PREFIX)/bin/bash),$(_HB_PREFIX)/bin/bash,/bin/bash)
export PATH := $(_HB_PREFIX)/opt/coreutils/libexec/gnubin:$(_HB_PREFIX)/opt/gnu-sed/libexec/gnubin:$(_HB_PREFIX)/opt/findutils/libexec/gnubin:$(_HB_PREFIX)/opt/grep/libexec/gnubin:$(_HB_PREFIX)/bin:$(PATH)

.DEFAULT_GOAL := help

# Repo root from this Makefile (not git: root/sudo often hits safe.directory).
_WORKSPACE_GUARD_MK := $(abspath $(lastword $(MAKEFILE_LIST)))
REPO_ROOT := $(patsubst %/,%,$(dir $(_WORKSPACE_GUARD_MK)))
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
	bash "$(CI_DIR)/scripts/install-system-deps" --check --boot-dir "$(CI_BOOT_BIN)"

.PHONY: init
init: ## Install system-level dependencies (platform-aware via config/system-deps.yaml)
	echo "==> Installing Homebrew + GNU tools (macOS only)..."
	bash "$(CI_DIR)/scripts/bootstrap-homebrew"
	echo "==> Installing system packages (from config/system-deps.yaml)..."
	bash "$(CI_DIR)/scripts/install-system-deps" --install --boot-dir "$(CI_BOOT_BIN)"
	echo "==> Installing Rust toolchain (if missing)..."
	if ! command -v cargo; then \
		bash "$(CI_DIR)/scripts/bootstrap-rust"; \
	fi
	echo "==> Installing Rust components (clippy, rustfmt)..."
	rustup component add clippy rustfmt
	echo "==> Bootstrapping gitleaks (pre-commit secret scanner)..."
	$(MAKE) install-gitleaks
	echo "==> Bootstrapping Podman (Linux VM test harness)..."
	bash "$(CI_DIR)/scripts/bootstrap-podman"
	bash scripts/podman/ensure-machine.sh
	echo "==> System dependencies installed."

.PHONY: preflight
preflight: ## Verify required tooling is present
	command -v git || { echo "ERROR: git not on PATH"; exit 1; }
	command -v cargo || { echo "ERROR: cargo not on PATH"; exit 1; }
	test -d "$(CI_DIR)" || { echo "ERROR: WORKSPACE-CI not found at $(CI_DIR)"; exit 1; }
	test -f "$(CI_DIR)/scripts/generate-hooks" || { echo "ERROR: WORKSPACE-CI/scripts/generate-hooks missing"; exit 1; }
	echo "Preflight OK (WORKSPACE-CI at $(CI_DIR))"

# =============================================================================
# Installation
# =============================================================================

.PHONY: install-gitleaks
install-gitleaks: ## Bootstrap gitleaks binary to ${WORKSPACE_ROOT}/${BOOT_NAME}/bin
	mkdir -p "$(dir $(GITLEAKS_BIN))"
	WORKSPACE_ROOT="$(WORKSPACE_ROOT)" GITLEAKS_BIN="$(GITLEAKS_BIN)" \
		bash "$(CI_DIR)/scripts/bootstrap-gitleaks"

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
		bash "$(CI_DIR)/scripts/cleanup-precommit"; \
	fi
	bash $(CI_DIR)/scripts/generate-hooks

.PHONY: sync
sync: ## Sync dependencies + reinstall hooks
	cargo fetch
	$(MAKE) install-hooks

# =============================================================================
# Quality Gates
# =============================================================================

.PHONY: check
check: ## Run cargo check (all feature combinations)
	cargo check --workspace
	cargo check --no-default-features --features root-only

.PHONY: lint
lint: ## Run cargo fmt --check + clippy
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo clippy --no-default-features --features root-only --all-targets -- -D warnings

.PHONY: type-check
type-check: ## Rust has no separate type-check; run cargo check
	cargo check --workspace

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
		cargo test --workspace --bins; \
		cargo test --no-default-features --features root-only --bins; \
	else \
		echo "SKIP: cargo unit tests on Darwin (Linux-only; use make test-podman)"; \
	fi

test-integration-cap: ## Capability-mode integration tests (non-root)
	cargo test --test integration_test

test-integration-root: ## Root-only integration tests (root)
	cargo test --no-default-features --features root-only --test integration_test

.PHONY: test-shell
test-shell: ## Run the bats shell test suite (NOT gated in check-push).
	if ! command -v bats; then \
		echo "bats not found. Run 'make init' (apt) or install bats-core from source."; \
		exit 1; \
	fi
	bats tests/shell/

# =============================================================================
# Pre-push Quality Gate
# =============================================================================

.PHONY: check-push
check-push: ## Pre-push quality gate: fmt + clippy + check + tests + host-provision Podman E2E (Linux).
	$(MAKE) lint
	$(MAKE) check
	$(MAKE) test
	$(MAKE) test-podman-provision

# Podman test harness: macOS + Linux hosts without native Linux kernel.
# See docs/specifications/SPEC-PODMAN-TESTING.md
# =============================================================================
# Podman Test Harness
# =============================================================================

.PHONY: test-podman test-podman-quick test-podman-provision test-qemu-guest
.PHONY: build-guard install-guard install-guard-host-exec reconcile-guard-host-exec uninstall-guard purge-guard-state check-guard check-guard-host-exec

test-podman: init-check ## Full Podman harness: Tier 0 (Darwin) + Tiers 1-3
	bash scripts/test-in-podman.sh

test-podman-quick: init-check ## Podman harness Tiers 0-2 only (skip capability E2E)
	TEST_PODMAN_QUICK=1 bash scripts/test-in-podman.sh

test-podman-provision: init-check ## Podman host-provision E2E only (phases 0-4, privileged)
	bash scripts/podman/run-tier3-provision.sh

test-qemu-guest: ## Authoritative E2E inside QEMU guest only (requires root in guest)
	bash scripts/qemu/e2e-guest.sh

# =============================================================================
# Git Guard
# =============================================================================

build-guard: ## Build git-guard binary (delegates to WORKSPACE-CI bootstrap)
	bash "$(CI_DIR)/scripts/bootstrap-workspace-guard" build-only

build-host-stack: build-guard build-binary-guard ## Build git-guard + binary-guard once (provision phase 5)

.PHONY: install-host-stack-phase5 _install-host-stack-phase5-build
INSTALL_LOCK ?= false
INSTALL_AUDITD ?= false

_GUARD_RELEASE_BIN := $(REPO_ROOT)/target/release/workspace-guard
_GUARD_RELEASE_SSH := $(REPO_ROOT)/target/release/workspace-git-ssh
_GUARD_RELEASE_MODE := $(REPO_ROOT)/target/release/workspace-guard.mode

_install-host-stack-phase5-build:
	if [ "$(GUARD_SKIP_BUILD)" = "1" ]; then \
		:; \
	elif [ "$(INSTALL_LOCK)" = "true" ]; then \
		$(MAKE) build-host-stack; \
	else \
		$(MAKE) build-guard; \
	fi

install-host-stack-phase5: _install-host-stack-phase5-build ## Build + install guard + optional lock/auditd
	GUARD_FORCE_RECONCILE=1 GUARD_SKIP_BUILD=1 $(MAKE) install-guard-host-exec
	if [ "$(INSTALL_LOCK)" = "true" ]; then GUARD_SKIP_BUILD=1 $(MAKE) install-lock; fi
	if [ "$(INSTALL_AUDITD)" = "true" ]; then $(MAKE) install-auditd; fi

install-guard: ## REMOVED - use install-guard-host-exec
	echo "ERROR: make install-guard is removed. Use: make install-guard-host-exec" >&2
	exit 1

_INSTALL_GUARD_DEPS := $(if $(filter 1,$(GUARD_SKIP_BUILD)),,build-guard)
install-guard-host-exec: $(_INSTALL_GUARD_DEPS) ## Install git-guard (host-exec class; requires root)
	$(SUDO) bash "$(CI_DIR)/scripts/bootstrap-workspace-guard" install-host-exec

uninstall-guard: ## Uninstall git-guard, restore stock git; preserve provision state (requires root)
	$(SUDO) bash "$(CI_DIR)/scripts/bootstrap-workspace-guard" uninstall

purge-guard-state: ## Destroy all /usr/lib/workspace-guard state (requires GUARD_PURGE_CONFIRM=1)
	$(SUDO) bash "$(CI_DIR)/scripts/bootstrap-workspace-guard" purge-guard-state

reconcile-guard-host-exec: build-guard ## Force rebuild + reinstall git guard and aux artifacts (requires root)
	GUARD_FORCE_RECONCILE=1 GUARD_SKIP_BUILD=1 $(MAKE) install-guard-host-exec

check-guard: ## REMOVED - use check-guard-host-exec
	echo "ERROR: make check-guard is removed. Use: make check-guard-host-exec" >&2
	exit 1

check-guard-host-exec: ## Check host-exec git-guard installation status
	bash "$(CI_DIR)/scripts/bootstrap-workspace-guard" check-host-exec

# =============================================================================
# Build
# =============================================================================

.PHONY: build
build: ## Build release binary (default + root-only)
	cargo build --release
	cargo build --release --no-default-features --features root-only

.PHONY: build-binary-guard
build-binary-guard: ## Build the generic binary guard (one binary, full GTFOBins table)
	cargo build --release --features binary-guard --bin workspace-binary-guard

# =============================================================================
# Cleanup & Compliance
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf target

.PHONY: clippy
clippy: ## Run cargo clippy
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: compliance
compliance: ## Run the WORKSPACE-CI compliance audit on this repo
	bash $(CI_DIR)/scripts/compliance-report .

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
	bash scripts/sync-gtfobins
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
		bash scripts/sync-gtfobins
	$(MAKE) --no-print-directory gitleaks-ignore-regen

.PHONY: gitleaks-ignore-regen
gitleaks-ignore-regen: ## Regenerate .gitleaksignore fingerprints for docs/references/ cached content
	bash scripts/regen-gitleaksignore

.PHONY: sync-gtfobins-verify
sync-gtfobins-verify: ## Re-fetch sources and emit SHA-256 manifest of canonical references
	bash scripts/sync-gtfobins --verify

.PHONY: drift-check
drift-check: ## Compare live SUID/CAP surface against res/ baselines; exit 1 on CRITICAL
	bash scripts/suid-drift-check

.PHONY: drift-check-quiet
drift-check-quiet: ## Same as drift-check but stdout only on CRITICAL; /usr/lib/workspace-binary-guard/drift-report.yaml still written
	bash scripts/suid-drift-check --quiet

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
	test -x scripts/install-lock-runtime && bash scripts/install-lock-runtime \
		|| { echo "NOTICE: scripts/install-lock-runtime not yet implemented; SPEC-BINARY-LOCK.md section 4.2 documents the procedure." >&2; exit 1; }

.PHONY: uninstall-lock
uninstall-lock: ## Rollback contain-via-guard: restore .real -> original SUID path (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: uninstall-lock needs root: sudo make uninstall-lock" >&2; exit 1; \
	fi
	test -x scripts/uninstall-lock-runtime && bash scripts/uninstall-lock-runtime \
		|| { echo "NOTICE: scripts/uninstall-lock-runtime not yet implemented; SPEC-BINARY-LOCK.md section 4.3 documents the rollback." >&2; exit 1; }

.PHONY: guard-%
guard-%: ## Canonical guard operator intents (see docs/OPERATOR.md)
	bash scripts/guard-operator.sh '$*'

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
	bash scripts/provision-host

install-host-stack: provision-host ## Alias: provision-host (recommended fleet install)

.PHONY: provision-host-preflight
provision-host-preflight: ## Read-only host provision state report (ROOT)
	if [ "$$(id -u)" -ne 0 ]; then \
		echo "ERROR: provision-host-preflight needs root: sudo make provision-host-preflight" >&2; exit 1; \
	fi
	if [ ! -x scripts/provision-host ]; then \
		echo "ERROR: scripts/provision-host missing or not executable" >&2; exit 1; \
	fi
	bash scripts/provision-host --preflight

.PHONY: provision-git-identities
provision-git-identities: ## Provision per-user gitconfig + SSH keys from config/home-lock-users.yaml (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: provision-git-identities needs root: sudo make provision-git-identities" >&2; exit 1; \
	fi
	test -x scripts/provision-user-git-identity && bash scripts/provision-user-git-identity \
		|| { echo "ERROR: scripts/provision-user-git-identity missing" >&2; exit 1; }

.PHONY: install-home-lock
install-home-lock: ## Lock the absolute_file_paths entries in config/guard_locked_paths.yaml (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-home-lock needs root: sudo make install-home-lock" >&2; exit 1; \
	fi
	test -x scripts/install-home-lock && bash scripts/install-home-lock \
		|| { echo "NOTICE: scripts/install-home-lock not yet implemented; SPEC-HOME-LOCK.md section 4.2 documents the procedure." >&2; exit 1; }

.PHONY: uninstall-home-lock
uninstall-home-lock: ## Rollback home lock: restore original owner/mode per /usr/lib/workspace-guard/home-lock-state.yaml (ROOT)
	if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: uninstall-home-lock needs root: sudo make uninstall-home-lock" >&2; exit 1; \
	fi
	test -x scripts/uninstall-home-lock && bash scripts/uninstall-home-lock \
		|| { echo "NOTICE: scripts/uninstall-home-lock not yet implemented; SPEC-HOME-LOCK.md section 4.3 documents the rollback." >&2; exit 1; }

.PHONY: home-drift-check
home-drift-check: ## Compare live home-lock surface against /usr/lib/workspace-guard/home-lock-state.yaml; exit 1 on CRITICAL
	bash scripts/home-drift-check

.PHONY: home-drift-check-quiet
home-drift-check-quiet: ## Same as home-drift-check but stdout only on CRITICAL
	bash scripts/home-drift-check --quiet

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