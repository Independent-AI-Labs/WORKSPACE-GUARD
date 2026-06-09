# RUST-GUARD Makefile — SUID guard framework (git PoC).
#
# This repo is a sibling of AMI-CI under projects/.

SHELL := /bin/bash
.DEFAULT_GOAL := help

REPO_ROOT := $(shell if [ -d .git ]; then git rev-parse --show-toplevel; else pwd; fi)
AMI_CI_DIR := $(abspath $(REPO_ROOT)/../CI)

-include $(AMI_CI_DIR)/lib/makefile_contract.mk

.PHONY: help
help: ## Show this help
	@echo "RUST-GUARD Makefile"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: preflight
preflight: ## Verify required tooling is present
	@command -v git   > /dev/null 2>&1 || { echo "ERROR: git not on PATH"; exit 1; }
	@command -v cargo > /dev/null 2>&1 || { echo "ERROR: cargo not on PATH"; exit 1; }
	@test -d "$(AMI_CI_DIR)" || { echo "ERROR: AMI-CI not found at $(AMI_CI_DIR)"; exit 1; }
	@test -f "$(AMI_CI_DIR)/scripts/generate-hooks" || { echo "ERROR: AMI-CI/scripts/generate-hooks missing"; exit 1; }
	@echo "Preflight OK (AMI-CI at $(AMI_CI_DIR))"

.PHONY: install-hooks
install-hooks: preflight ## Regenerate native git hooks from .pre-commit-config.yaml
	@if [ -x "$(AMI_CI_DIR)/scripts/cleanup-precommit" ]; then \
		bash "$(AMI_CI_DIR)/scripts/cleanup-precommit"; \
	fi
	bash $(AMI_CI_DIR)/scripts/generate-hooks

.PHONY: check
check: ## Run cargo check
	cargo check --workspace

.PHONY: lint
lint: ## Run cargo fmt --check
	cargo fmt --all -- --check

.PHONY: clippy
clippy: ## Run cargo clippy
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: test
test: ## Run cargo test
	cargo test --workspace

.PHONY: build
build: ## Build release binary
	cargo build --release

.PHONY: clean
clean: ## Clean build artifacts
	rm -rf target

.PHONY: compliance
compliance: ## Run the AMI-CI compliance audit on this repo
	bash $(AMI_CI_DIR)/scripts/compliance-report .
