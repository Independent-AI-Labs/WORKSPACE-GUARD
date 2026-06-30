# WORKSPACE-GUARD Makefile: SUID guard framework (git PoC).
#
# This repo is a sibling of WORKSPACE-CI under projects/.

SHELL := /bin/bash
.DEFAULT_GOAL := help

REPO_ROOT := $(shell if [ -d .git ]; then git rev-parse --show-toplevel; else pwd; fi)
CI_DIR := $(abspath $(REPO_ROOT)/../CI)

-include $(CI_DIR)/lib/makefile_contract.mk

# Resolve WORKSPACE_ROOT the same way hooks/lib/ci.sh do, so gitleaks lands
# in the exact ${WORKSPACE_ROOT}/.boot-linux/bin that the hooks prepend to PATH.
# Error handling: if ci.sh is missing or unsourceable, fail loudly with a diagnostic.
WORKSPACE_ROOT := $(shell \
	if [ ! -f "$(CI_DIR)/lib/ci.sh" ]; then \
		echo "ERROR: $(CI_DIR)/lib/ci.sh not found" >&2; exit 1; \
	fi; \
	source "$(CI_DIR)/lib/ci.sh" || exit 1; \
	if [ -z "$$CI_WORKSPACE_ROOT" ]; then \
		echo "ERROR: CI_WORKSPACE_ROOT not set after sourcing ci.sh" >&2; exit 1; \
	fi; \
	echo "$$CI_WORKSPACE_ROOT")
GITLEAKS_BIN := $(WORKSPACE_ROOT)/.boot-linux/bin/gitleaks

SUDO := $(shell if [ "$$(id -u)" -eq 0 ]; then echo ""; else echo "sudo"; fi)

.PHONY: help
help: ## Show this help
	@echo "WORKSPACE-GUARD Makefile"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: init
init: ## Install system-level dependencies (apt packages + Rust toolchain)
	@echo "==> Installing system packages..."
	$(SUDO) apt-get update -qq
	$(SUDO) apt-get install -y --no-install-recommends \
		curl tar ca-certificates \
		libcap2-bin e2fsprogs file \
		build-essential pkg-config
	@echo "==> Installing Rust toolchain (if missing)..."
	@if ! command -v cargo > /dev/null; then \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal; \
	else \
		echo "cargo already installed: $$(cargo --version)"; \
	fi
	@echo "==> Installing Rust components (clippy, rustfmt)..."
	@rustup component add clippy rustfmt
	@echo "==> Bootstrapping gitleaks (pre-commit secret scanner)..."
	@$(MAKE) install-gitleaks
	@echo "==> System dependencies installed."

.PHONY: preflight
preflight: ## Verify required tooling is present
	@command -v git   > /dev/null 2>&1 || { echo "ERROR: git not on PATH"; exit 1; }
	@command -v cargo > /dev/null 2>&1 || { echo "ERROR: cargo not on PATH"; exit 1; }
	@test -d "$(CI_DIR)" || { echo "ERROR: WORKSPACE-CI not found at $(CI_DIR)"; exit 1; }
	@test -f "$(CI_DIR)/scripts/generate-hooks" || { echo "ERROR: WORKSPACE-CI/scripts/generate-hooks missing"; exit 1; }
	@echo "Preflight OK (WORKSPACE-CI at $(CI_DIR))"

.PHONY: install-gitleaks
install-gitleaks: ## Bootstrap gitleaks binary to ${WORKSPACE_ROOT}/.boot-linux/bin
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
install-hooks: preflight ## Regenerate native git hooks from .pre-commit-config.yaml
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

.PHONY: build
build: ## Build release binary (default + root-only)
	cargo build --release
	cargo build --release --no-default-features --features root-only

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf target

.PHONY: clippy
clippy: ## Run cargo clippy
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: compliance
compliance: ## Run the WORKSPACE-CI compliance audit on this repo
	bash $(CI_DIR)/scripts/compliance-report .