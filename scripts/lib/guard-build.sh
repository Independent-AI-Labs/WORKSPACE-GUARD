# lib/guard-build.sh - build_guard_binary helper
#
# Sourced by scripts/install-git-guard. NOT a standalone script.
# Depends on the parent script's globals: WORKSPACE_ROOT, _CI_ROOT,
# _guard_dir, and the log_info / log_warn / log_error helpers. Inherits
# `set -euo pipefail` from the sourcing shell; do not add a shebang or
# `set` here. Keep this file under the 512-line source-length gate per
# AGENTS.md Rule 4.

_guard_repo_owner() {
    local owner="" _stat_err _stat_rc=0
    _stat_err="$(mktemp)"
    owner="$(stat -c '%U' "$_guard_dir" 2>"$_stat_err")" || _stat_rc=$?
    if [[ $_stat_rc -ne 0 ]]; then
        if [[ -s "$_stat_err" ]]; then
            log_warn "stat owner of $_guard_dir failed: $(head -1 "$_stat_err")"
        fi
        rm -f "$_stat_err"
    else
        rm -f "$_stat_err"
        if [[ -n "$owner" && "$owner" != "root" ]]; then
            printf '%s\n' "$owner"
            return 0
        fi
    fi
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
        printf '%s\n' "$SUDO_USER"
    fi
}

# Release target trees: the top-level tools package builds into
# $_guard_dir/target (workspace-git-ssh), the privileged package into
# $_guard_dir/git-guard/target (workspace-guard).
_guard_target_dirs() {
    printf '%s\n' "$_guard_dir/target" "$_guard_dir/git-guard/target"
}

_guard_rehome_target_tree() {
    local user="${1:-}" _t
    [[ -n "$user" && "$user" != "root" ]] || return 0
    while IFS= read -r _t; do
        [[ -d "$_t" ]] || continue
        chown -R "$user" "$_t" || log_warn "chown $_t -> $user failed (some files may remain root-owned)"
        log_info "Re-homed $_t -> $user"
    done <<< "$(_guard_target_dirs)"
}

_guard_assert_target_ownership() {
    local user="${1:-}" _t
    [[ -n "$user" && "$user" != "root" ]] || return 0
    while IFS= read -r _t; do
        [[ -d "$_t" ]] || continue
        local owner="" _stat_err _stat_rc=0
        _stat_err="$(mktemp)"
        owner="$(stat -c '%U' "$_t" 2>"$_stat_err")" || _stat_rc=$?
        if [[ $_stat_rc -ne 0 ]]; then
            if [[ -s "$_stat_err" ]]; then
                log_warn "stat owner of $_t failed: $(head -1 "$_stat_err")"
            fi
            rm -f "$_stat_err"
            continue
        fi
        rm -f "$_stat_err"
        if [[ "$owner" == "root" ]]; then
            log_error "$_t is root-owned by design (item 17: root-gated release builds)."
            log_error "Run release builds as root: sudo --preserve-env=HOME,SSH_AUTH_SOCK make build-guard"
            log_error "Agent dev loops use CARGO_TARGET_DIR=target/agent (make check/lint/test)."
            return 1
        fi
    done <<< "$(_guard_target_dirs)"
}

_guard_cargo_release_build() {
    local err_file rc=0
    err_file="$(mktemp)"
    if cargo "$@" 2>"$err_file"; then
        rm -f "$err_file"
        return 0
    else
        rc=$?
    fi
    if [[ -s "$err_file" ]] && grep -q 'Cannot emit physreg copy' "$err_file"; then
        log_warn "rustc LLVM error; retrying with CARGO_BUILD_JOBS=1"
        rm -f "$err_file"
        CARGO_BUILD_JOBS=1 cargo "$@"
        return $?
    fi
    cat "$err_file" >&2
    rm -f "$err_file"
    return $rc
}

build_guard_binary() {
    log_info "Building workspace-guard Rust binary..."
    local _boot_name preset_cargo_home preset_rustup_home
    preset_cargo_home="${CARGO_HOME:-}"
    preset_rustup_home="${RUSTUP_HOME:-}"
    case "$(uname -s | tr 'A-Z' 'a-z')" in darwin) _boot_name=".boot-macos" ;; *) _boot_name=".boot-linux" ;; esac
    local ws_boot_rust="${WORKSPACE_ROOT}/$_boot_name/bin"
    local ws_rust_home="${WORKSPACE_ROOT}/$_boot_name/rust"
    local ci_boot_rust="${_CI_ROOT}/$_boot_name/bin"
    local ci_rust_home="${_CI_ROOT}/$_boot_name/rust"
    # Cargo toolchain resolution: explicit precedence, hard failure.
    # 1. workspace-root boot (shared toolchain home)
    # 2. CI boot (bootstrap-rust installs here)
    # 3. bootstrap into the CI boot, then require cargo there
    local boot_rust rust_home
    if [[ -x "$ws_boot_rust/cargo" ]]; then
        boot_rust="$ws_boot_rust"
        rust_home="$ws_rust_home"
    elif [[ -x "$ci_boot_rust/cargo" ]]; then
        boot_rust="$ci_boot_rust"
        rust_home="$ci_rust_home"
    else
        log_info "cargo not in workspace or CI boot: bootstrapping Rust..."
        bash "${_CI_ROOT}/scripts/bootstrap-rust" || {
            log_error "Rust installation failed"
            return 1
        }
        if [[ -x "$ci_boot_rust/cargo" ]]; then
            boot_rust="$ci_boot_rust"
            rust_home="$ci_rust_home"
        elif [[ -x "$ws_boot_rust/cargo" ]]; then
            boot_rust="$ws_boot_rust"
            rust_home="$ws_rust_home"
        else
            log_error "cargo not found after bootstrap: expected $ci_boot_rust/cargo"
            return 1
        fi
    fi
    if [[ $EUID -eq 0 ]]; then
        rust_home="$_guard_dir/target/cargo-home"
        mkdir -p "$rust_home" || {
            log_error "Cannot create root release Cargo home: $rust_home"
            return 1
        }
    elif [[ -n "$preset_cargo_home" ]]; then
        local _mk_err _mk_rc=0
        _mk_err="$(mktemp)"
        mkdir -p "$preset_cargo_home" 2>"$_mk_err" || _mk_rc=$?
        if [[ $_mk_rc -ne 0 ]]; then
            if [[ -s "$_mk_err" ]]; then
                log_warn "mkdir -p $preset_cargo_home failed: $(head -1 "$_mk_err")"
            fi
            rm -f "$_mk_err"
        else
            rm -f "$_mk_err"
            if [[ -d "$preset_cargo_home" && -w "$preset_cargo_home" ]]; then
                rust_home="$preset_cargo_home"
            fi
        fi
    fi
    export PATH="$boot_rust:$PATH"
    export RUSTUP_HOME="${preset_rustup_home:-$rust_home}"
    export CARGO_HOME="$rust_home"

    if [[ ! -x "$boot_rust/cargo" ]]; then
        log_error "cargo missing at resolved toolchain: $boot_rust/cargo"
        return 1
    fi

    if [[ -n "$(command -v rustup)" ]]; then
        # rc-capture: rustup show active-toolchain prints the active
        # toolchain name to stdout (we don't need it). On rc!=0 (rustup
        # broken, or no default toolchain configured), surface stderr
        # and fall through to the install-stable path.
        local _at_out _at_err _at_rc=0
        _at_out="$(mktemp)"; _at_err="$(mktemp)"
        rustup show active-toolchain >"$_at_out" 2>"$_at_err" || _at_rc=$?
        if [[ $_at_rc -ne 0 ]]; then
            if [[ -s "$_at_err" ]]; then
                log_warn "rustup show active-toolchain failed (rc=$_at_rc): $(head -1 "$_at_err")"
            else
                log_warn "rustup show active-toolchain failed (rc=$_at_rc, no stderr)"
            fi
            rm -f "$_at_out" "$_at_err"
            log_warn "rustup found but no default toolchain configured: installing stable"
            rustup default stable || {
                log_error "Failed to set default Rust toolchain"
                return 1
            }
            log_info "Rust stable toolchain installed"
        else
            rm -f "$_at_out" "$_at_err"
        fi
    fi

    local _guard_pkg_dir="$_guard_dir/git-guard"
    if [[ ! -f "$_guard_dir/Cargo.toml" ]]; then
        log_error "WORKSPACE-GUARD project not found at $_guard_dir"
        log_error "Run 'make ensure-repos' or 'make sync-package' first to clone workspace repos"
        return 1
    fi
    if [[ ! -f "$_guard_pkg_dir/Cargo.toml" ]]; then
        log_error "WORKSPACE-GUARD git-guard package not found at $_guard_pkg_dir"
        return 1
    fi

    if [[ $EUID -eq 0 ]]; then
        # Item 17: each release tree is root-built and root-owned so an
        # agent cannot stage a trojaned artifact in target/ for a later
        # root install to consume. Agent dev loops use CARGO_TARGET_DIR
        # target/agent (WORKSPACE-GUARD Makefile check/lint/test).
        local _t
        while IFS= read -r _t; do
            [[ -d "$_t" ]] || continue
            chown root:root "$_t" || {
                log_error "chown $_t -> root failed"
                return 1
            }
            # target/agent is the agent dev-loop CARGO_TARGET_DIR; it must
            # stay agent-owned. Root only claims the release tree.
            find "$_t" -mindepth 1 -maxdepth 1 ! -name agent                 -exec chown -R root:root {} + || {
                log_error "chown release target tree $_t -> root failed"
                return 1
            }
        done <<< "$(_guard_target_dirs)"
    else
        _guard_assert_target_ownership "$(_guard_repo_owner)" || return 1
    fi

    local -a build_features=()
    local build_mode_env="${BUILD_MODE:-}"
    if [[ "$build_mode_env" == "root-only" ]]; then
        log_warn "BUILD_MODE=root-only: building root-only (NON-ROOT USERS CANNOT RUN GIT)"
        build_features=(--no-default-features --features root-only)
    else
        log_info "Building capability-mode binary (default; non-root users supported via filecaps)"
    fi

    local guard_bin=""
    local git_ssh_bin=""
    local has_rustup=0
    if [[ -n "$(command -v rustup)" ]]; then
        has_rustup=1
    fi
    if [[ "$has_rustup" -eq 1 ]]; then
        local installed_targets
        installed_targets=$(rustup target list --installed)
        if echo "$installed_targets" | grep -q musl; then
            log_info "Building statically linked binaries (musl)..."
            (cd "$_guard_pkg_dir" && CARGO_TARGET_DIR="$_guard_pkg_dir/target" \
                _guard_cargo_release_build build --release --target x86_64-unknown-linux-musl "${build_features[@]}")
            (cd "$_guard_dir" && CARGO_TARGET_DIR="$_guard_dir/target" \
                _guard_cargo_release_build build --release --bin workspace-git-ssh --target x86_64-unknown-linux-musl)
            guard_bin="$_guard_pkg_dir/target/x86_64-unknown-linux-musl/release/workspace-guard"
            git_ssh_bin="$_guard_dir/target/x86_64-unknown-linux-musl/release/workspace-git-ssh"
        else
            log_info "Building dynamically linked binaries (gnu)..."
            PATH="/usr/bin:/usr/sbin:/usr/local/bin:$PATH"
            CC=gcc
            export PATH CC
            (cd "$_guard_pkg_dir" && CARGO_TARGET_DIR="$_guard_pkg_dir/target" \
                _guard_cargo_release_build build --release "${build_features[@]}")
            (cd "$_guard_dir" && CARGO_TARGET_DIR="$_guard_dir/target" \
                _guard_cargo_release_build build --release --bin workspace-git-ssh)
            guard_bin="$_guard_pkg_dir/target/release/workspace-guard"
            git_ssh_bin="$_guard_dir/target/release/workspace-git-ssh"
        fi
    else
        log_info "Building dynamically linked binaries (gnu, no rustup)..."
        PATH="/usr/bin:/usr/sbin:/usr/local/bin:$PATH"
        CC=gcc
        export PATH CC
        (cd "$_guard_pkg_dir" && CARGO_TARGET_DIR="$_guard_pkg_dir/target" \
            _guard_cargo_release_build build --release "${build_features[@]}")
        (cd "$_guard_dir" && CARGO_TARGET_DIR="$_guard_dir/target" \
            _guard_cargo_release_build build --release --bin workspace-git-ssh)
        guard_bin="$_guard_pkg_dir/target/release/workspace-guard"
        git_ssh_bin="$_guard_dir/target/release/workspace-git-ssh"
    fi

    if [[ ! -f "$guard_bin" ]]; then
        log_error "Build failed: binary not found at $guard_bin"
        return 1
    fi
    if ! file "$guard_bin" | grep -q ELF; then
        log_error "Build produced invalid ELF binary"
        return 1
    fi
    if [[ ! -s "$guard_bin" ]]; then
        log_error "Build produced empty binary"
        return 1
    fi
    if [[ $EUID -eq 0 ]]; then
        local _t
        while IFS= read -r _t; do
            [[ -d "$_t" ]] || continue
            chown root:root "$_t" || {
                log_error "post-build chown $_t -> root failed"
                return 1
            }
            find "$_t" -mindepth 1 -maxdepth 1 ! -name agent             -exec chown -R root:root {} + || {
                log_error "post-build chown release target tree $_t -> root failed"
                return 1
            }
        done <<< "$(_guard_target_dirs)"
    fi
    log_info "Build successful: $(file "$guard_bin" | cut -d: -f2)"
    if [[ -f "$git_ssh_bin" ]]; then
        log_info "git-ssh wrapper built: $git_ssh_bin"
    else
        log_warn "workspace-git-ssh binary missing after build"
    fi

    GUARD_BIN="$guard_bin"
    GUARD_BUILD_MODE="capability"
    if [[ ${#build_features[@]} -gt 0 ]]; then
        GUARD_BUILD_MODE="root-only"
    fi
    printf '%s\n' "$GUARD_BUILD_MODE" > "${GUARD_BIN}.mode"
    log_info "Wrote build-mode marker: ${GUARD_BIN}.mode ($GUARD_BUILD_MODE)"

    # When invoked under sudo (operator: `sudo --preserve-env=HOME,SSH_AUTH_SOCK
    # make build-guard`), cargo writes target/ as root: and it STAYS
    # root-owned by design (root-gated release builds, item 17). Agent
    # dev loops use CARGO_TARGET_DIR=target/agent and never touch the
    # root-owned release target tree, so there is nothing to re-home.
    return 0
}
