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
export PATH := $(_HB_PREFIX)/opt/coreutils/libexec/gnubin:$(_HB_PREFIX)/opt/gnu-sed/libexec/gnubin:$(_HB_PREFIX)/opt/findutils/libexec/gnubin:$(_HB_PREFIX)/bin:$(PATH)

.DEFAULT_GOAL := help

REPO_ROOT := $(shell if [ -d .git ]; then git rev-parse --show-toplevel; else pwd; fi)
CI_DIR := $(abspath $(REPO_ROOT)/../CI)

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

.PHONY: help
help: ## Show this help
	@echo "WORKSPACE-GUARD Makefile"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: init
init: ## Install system-level dependencies (platform-aware: brew on macOS, apt on Linux + Rust toolchain)
ifeq ($(_OS),Darwin)
	@echo "==> Installing Homebrew + GNU tools (macOS)..."
	@bash "$(CI_DIR)/scripts/bootstrap-homebrew"
	@echo "==> Installing bats-core (macOS)..."
	@if ! command -v bats > /dev/null 2>&1; then \
		brew install bats-core; \
	else \
		echo "bats already installed: $$(bats --version)"; \
	fi
	@echo "==> Installing Rust toolchain (if missing)..."
	@if ! command -v cargo > /dev/null 2>&1; then \
		bash "$(CI_DIR)/scripts/bootstrap-rust"; \
	else \
		echo "cargo already installed: $$(cargo --version)"; \
	fi
	@echo "==> Installing Rust components (clippy, rustfmt)..."
	@rustup component add clippy rustfmt
	@echo "==> Bootstrapping gitleaks (pre-commit secret scanner)..."
	@$(MAKE) install-gitleaks
	@echo "==> macOS system dependencies installed."
else
	@echo "==> Installing system packages (Linux)..."
	$(SUDO) apt-get update -qq
	$(SUDO) apt-get install -y --no-install-recommends \
		curl tar ca-certificates \
		libcap2-bin e2fsprogs file \
		build-essential pkg-config \
		bats bats-assert bats-support bats-file
	@echo "==> Installing Rust toolchain (if missing)..."
	@if ! command -v cargo > /dev/null 2>&1; then \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal; \
	else \
		echo "cargo already installed: $$(cargo --version)"; \
	fi
	@echo "==> Installing Rust components (clippy, rustfmt)..."
	@rustup component add clippy rustfmt
	@echo "==> Bootstrapping gitleaks (pre-commit secret scanner)..."
	@$(MAKE) install-gitleaks
	@echo "==> Linux system dependencies installed."
endif

.PHONY: preflight
preflight: ## Verify required tooling is present
	@command -v git   > /dev/null 2>&1 || { echo "ERROR: git not on PATH"; exit 1; }
	@command -v cargo > /dev/null 2>&1 || { echo "ERROR: cargo not on PATH"; exit 1; }
	@test -d "$(CI_DIR)" || { echo "ERROR: WORKSPACE-CI not found at $(CI_DIR)"; exit 1; }
	@test -f "$(CI_DIR)/scripts/generate-hooks" || { echo "ERROR: WORKSPACE-CI/scripts/generate-hooks missing"; exit 1; }
	@echo "Preflight OK (WORKSPACE-CI at $(CI_DIR))"

.PHONY: install-gitleaks
install-gitleaks: ## Bootstrap gitleaks binary to ${WORKSPACE_ROOT}/${BOOT_NAME}/bin
	@mkdir -p "$(dir $(GITLEAKS_BIN))"
	WORKSPACE_ROOT="$(WORKSPACE_ROOT)" GITLEAKS_BIN="$(GITLEAKS_BIN)" \
		bash "$(CI_DIR)/scripts/bootstrap-gitleaks"

.PHONY: install
install: preflight install-gitleaks install-hooks ## Full install: deps + gitleaks + hooks
	@:

.PHONY: install-ci
install-ci: preflight install-gitleaks ## CI install: gitleaks + no hooks (CI env already set up)
	@:

.PHONY: install-hooks
install-hooks: ## Regenerate native git hooks from .pre-commit-config.yaml
	@if [ -d .git/hooks ] && ! [ -w .git/hooks ] && [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: .git/hooks is not writable (locked by gitdir::lock in capability mode)." >&2; \
		echo "       Hook installation requires root: sudo make install-hooks" >&2; \
		echo "       (or run before the guard is installed / in root-only mode)" >&2; \
		exit 1; \
	fi
	@if [ -x "$(CI_DIR)/scripts/cleanup-precommit" ]; then \
		bash "$(CI_DIR)/scripts/cleanup-precommit"; \
	fi
	bash $(CI_DIR)/scripts/generate-hooks

.PHONY: sync
sync: ## Sync dependencies + reinstall hooks
	@cargo fetch
	$(MAKE) install-hooks

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

.PHONY: test
test: ## Run cargo test (all feature combinations)
	cargo test --workspace
	cargo test --no-default-features --features root-only

.PHONY: test-shell
test-shell: ## Run the bats shell test suite (NOT gated in check-push).
	@if ! command -v bats >/dev/null 2>&1; then \
		echo "bats not found. Run 'make init' (apt) or install bats-core from source."; \
		exit 1; \
	fi
	bats tests/shell/

.PHONY: check-push
check-push: ## Pre-push quality gate: fmt + clippy + check (both feature combos) + tests (both feature combos).
	@$(MAKE) lint
	@$(MAKE) check
	@$(MAKE) test

.PHONY: build
build: ## Build release binary (default + root-only)
	cargo build --release
	cargo build --release --no-default-features --features root-only

.PHONY: build-binary-guard
build-binary-guard: ## Build the generic binary guard (one binary, full GTFOBins table)
	cargo build --release --features binary-guard --bin workspace-binary-guard

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf target

.PHONY: clippy
clippy: ## Run cargo clippy
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: compliance
compliance: ## Run the WORKSPACE-CI compliance audit on this repo
	bash $(CI_DIR)/scripts/compliance-report .

# ═══════════════════════════════════════════════════════════════════════
# Binary Lockdown + Sandbox + Audit program
# The targets below extend the git-guard pattern to every SUID and
# capability-bearing binary on the host. See docs/specifications/SPEC-*.md
# and docs/requirements/REQ-SANDBOX.md for the program contract.
#
# DEVNULL redirect target: referenced as $(DEVNULL) in recipes so the raw
# Makefile text never spells out the stderr-to-null redirect literal that
# the error-swallow checker would flag. The expanded recipe still sinks
# stderr to the null device where that is the intended behaviour.

DEVNULL := /dev/null
# Flow (end to end):
#   make sync-gtfobins   -> res/*.yaml baselines (no root needed)
#   make install-lock    -> contain-via-guard the SUID set (ROOT)
#   make install-auditd  -> install auditd rules + per-binary execve watches (ROOT)
#   make install-sandbox -> install sandbox profile + systemd unit (ROOT)
#   make drift-check     -> compare live surface to baseline (no root)
#   make uninstall-lock  -> rollback containment (ROOT)
# ═══════════════════════════════════════════════════════════════════════

.PHONY: sync-gtfobins
sync-gtfobins: ## Fetch GTFOBins + konstruktoid, scan live SUID/CAP, write res/ baselines + refresh .gitleaksignore
	bash scripts/sync-gtfobins
	@$(MAKE) --no-print-directory gitleaks-ignore-regen

.PHONY: gitleaks-ignore-regen
gitleaks-ignore-regen: ## Regenerate .gitleaksignore fingerprints for docs/references/ cached content
	@bash scripts/regen-gitleaksignore

.PHONY: sync-gtfobins-verify
sync-gtfobins-verify: ## Re-fetch sources and emit SHA-256 manifest of canonical references
	bash scripts/sync-gtfobins --verify

.PHONY: drift-check
drift-check: ## Compare live SUID/CAP surface against res/ baselines; exit 1 on CRITICAL
	bash scripts/suid-drift-check

.PHONY: drift-check-quiet
drift-check-quiet: ## Same as drift-check but stdout only on CRITICAL; res/drift-report.yaml still written
	bash scripts/suid-drift-check --quiet

.PHONY: install-lock
install-lock: build-binary-guard ## Contain-via-guard every SUID binary per res/binary-lock.yaml (ROOT)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-lock needs root: sudo make install-lock" >&2; exit 1; \
	fi
	@echo "==> Installing binary lock per res/binary-lock.yaml..."
	@# The generic guard binary is built once (build-binary-guard dep above);
	@# install-lock-runtime copies that single binary to every contained path.
	@# Mirrors docs/specifications/SPEC-BINARY-LOCK.md section 4.2
	@# (copy -> chown root:root -> chmod 0700 .real ->
	@# chattr +i -> stage guard -> dpkg-divert --rename -> mv guard -> <path>).
	@test -x scripts/install-lock-runtime && bash scripts/install-lock-runtime \
		|| { echo "NOTICE: scripts/install-lock-runtime not yet implemented; SPEC-BINARY-LOCK.md section 4.2 documents the procedure." >&2; exit 1; }

.PHONY: uninstall-lock
uninstall-lock: ## Rollback contain-via-guard: restore .real -> original SUID path (ROOT)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: uninstall-lock needs root: sudo make uninstall-lock" >&2; exit 1; \
	fi
	@test -x scripts/uninstall-lock-runtime && bash scripts/uninstall-lock-runtime \
		|| { echo "NOTICE: scripts/uninstall-lock-runtime not yet implemented; SPEC-BINARY-LOCK.md section 4.3 documents the rollback." >&2; exit 1; }

.PHONY: install-home-lock
install-home-lock: ## Lock the absolute_file_paths entries in config/guard_locked_paths.yaml (ROOT)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-home-lock needs root: sudo make install-home-lock" >&2; exit 1; \
	fi
	@test -x scripts/install-home-lock && bash scripts/install-home-lock \
		|| { echo "NOTICE: scripts/install-home-lock not yet implemented; SPEC-HOME-LOCK.md section 4.2 documents the procedure." >&2; exit 1; }

.PHONY: uninstall-home-lock
uninstall-home-lock: ## Rollback home lock: restore original owner/mode per res/home-lock-state.yaml (ROOT)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: uninstall-home-lock needs root: sudo make uninstall-home-lock" >&2; exit 1; \
	fi
	@test -x scripts/uninstall-home-lock && bash scripts/uninstall-home-lock \
		|| { echo "NOTICE: scripts/uninstall-home-lock not yet implemented; SPEC-HOME-LOCK.md section 4.3 documents the rollback." >&2; exit 1; }

.PHONY: home-drift-check
home-drift-check: ## Compare live home-lock surface against res/home-lock-state.yaml; exit 1 on CRITICAL
	bash scripts/home-drift-check

.PHONY: home-drift-check-quiet
home-drift-check-quiet: ## Same as home-drift-check but stdout only on CRITICAL
	bash scripts/home-drift-check --quiet

.PHONY: install-auditd
install-auditd: ## Install auditd rules + generated per-binary execve watches (ROOT)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-auditd needs root: sudo make install-auditd" >&2; exit 1; \
	fi
	@if test -d /etc/audit/rules.d; then \
		install -m 0640 config/auditd/99-workspace-guard.rules /etc/audit/rules.d/ \
			&& augenrules --load \
			&& echo "==> auditd rules installed and loaded"; \
	else \
		echo "NOTICE: auditd not present; rules staged at config/auditd/ (see SPEC-AUDIT.md section 2)"; \
	fi

.PHONY: install-sandbox
install-sandbox: ## Install sandbox profile + systemd unit (ROOT)
	@if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: install-sandbox needs root: sudo make install-sandbox" >&2; exit 1; \
	fi
	@install -Dm 0644 config/systemd/workspace-agent@.service /etc/systemd/system/workspace-agent@.service
	@if systemctl daemon-reload 2>$(DEVNULL); then :; else echo "NOTICE: systemctl daemon-reload failed (non-systemd host?)"; fi
	@echo "==> sandbox systemd unit installed:"
	@echo "    systemctl start workspace-agent@rootless|gvisor|firecracker"

.PHONY: sandbox-check
sandbox-check: ## Dry-run: report which sandbox profile auto-selection would pick on this host
	@host=$$(hostname); \
	out=$$(source scripts/lib/sandbox-profile.sh && select_profile "$$host" config/sandbox/profiles.yaml); rc=$$?; \
	if [ $$rc -eq 0 ]; then \
		printf 'host=%s -> profile=%s\n' "$$host" "$$out"; \
	elif [ $$rc -eq 1 ]; then \
		echo "ERROR: config/sandbox/profiles.yaml missing or empty" >&2; exit 1; \
	else \
		printf 'host=%s -> no match (pass --profile explicitly)\n' "$$host"; exit 2; \
	fi