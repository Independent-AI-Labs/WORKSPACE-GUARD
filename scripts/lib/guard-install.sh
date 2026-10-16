# lib/guard-install.sh - install_guard_binary helper
#
# Sourced by scripts/install-git-guard. NOT a standalone script.
# Depends on the parent script's globals: _CI_ROOT, CYAN, BOLD, RED, NC,
# and the log_info / log_warn / log_error helpers. Also calls
# divert_is_active and rollback_guard (defined in the parent script).
# Drift/host-exec helpers live in lib/guard-drift.sh and lib/guard-host-exec.sh.
# Inherits `set -euo pipefail` from the sourcing shell; do not add a
# shebang or `set` here. Keep this file under the 512-line source-length
# gate per AGENTS.md Rule 4.

install_guard_binary() {
    local guard_bin="${1:-$GUARD_BIN}"
    if grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status; then
        log_error "Installer shell has NoNewPrivs=1; sudo cannot gain privileges here."
        log_error "Run from SSH/TTY root session: sudo make install-guard-host-exec"
        return 1
    fi
    if [[ ! -f "$guard_bin" ]]; then
        log_error "Guard binary not found at $guard_bin"
        log_error "Run 'make build-guard' first to build the binary, then: make install-guard-host-exec"
        return 1
    fi
    if ! file "$guard_bin" | grep -q ELF; then
        log_error "Guard binary is not a valid ELF: $guard_bin"
        return 1
    fi

    local install_mode="${GUARD_BUILD_MODE:-}"
    if [[ -z "$install_mode" ]]; then
        local mode_marker="${guard_bin}.mode"
        if [[ -f "$mode_marker" ]]; then
            install_mode="$(cat "$mode_marker")"
        fi
    fi
    if [[ -z "$install_mode" ]]; then
        log_error "No build-mode marker at ${guard_bin}.mode and no in-process build mode."
        log_error "Binary build mode (capability vs root-only) unknown; refusing to guess."
        log_error "Build via 'make build-guard' (records mode), then 'make install-guard-host-exec'."
        return 1
    fi
    if [[ "$install_mode" != "capability" && "$install_mode" != "root-only" ]]; then
        log_error "Invalid build-mode marker '$install_mode' at ${guard_bin}.mode"
        return 1
    fi
    if [[ "$install_mode" == "capability" ]] && [[ ! -x /usr/sbin/setcap ]]; then
        log_error "Binary is capability-mode but setcap is not installed on this host."
        log_error "Capability mode requires setcap (libcap2-bin) to grant non-root git access."
        log_error "Run 'make init', or rebuild root-only: BUILD_MODE=root-only make build-guard"
        return 1
    fi
    if [[ "$install_mode" == "root-only" ]] && [[ -x /usr/sbin/setcap ]]; then
        log_warn "setcap is available here, but the binary was built root-only."
        log_warn "A capability build would allow non-root users to run git; root-only will NOT."
    fi

    local nr_count=0
    nr_count=$(awk -F: '$3>=1000 && $3<65534 && $7 ~ /(bash|sh|zsh|fish)$/{c++} END{print c+0}' /etc/passwd) || nr_count=0

    if [[ "$install_mode" == "root-only" ]]; then
        echo ""
        echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}${BOLD} Git Guard: Root-Only Installation (SOFT BARRIER)${NC}"
        echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
        echo ""
        echo "WARNING: Installing in root-only mode: this is a SOFT BARRIER."
        echo ""
        echo "  • NON-ROOT USERS CANNOT RUN GIT (the guard exits unless euid=0)"
        echo "  • The guard policy engine will still block destructive commands"
        echo "  • Root users can bypass the guard (see threat model docs)"
        echo "  • No chattr +i, no dpkg-divert, no apt hook"
        if [[ "$nr_count" -gt 0 ]]; then
            echo ""
            echo -e "${RED}${BOLD}  !! $nr_count non-root login user(s) detected.${NC}"
            echo -e "${RED}${BOLD}     Their git will be BROKEN by root-only mode.${NC}"
            echo -e "${RED}${BOLD}     For non-root users, use: make build-guard && make install-guard-host-exec${NC}"
        fi
        echo ""
        echo "Root-only is intended ONLY for root/PRoot/container environments."
        echo "See docs/ROOT-ONLY-MODE.md for the full threat model."
        echo ""
        echo "To uninstall: make uninstall-guard"
        echo ""
    else
        echo ""
        echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}${BOLD} Git Guard: host-exec Installation${NC}"
        echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
        echo ""
        echo "The Git Guard is a file-capability binary that wraps /usr/bin/git."
        echo ""
        echo "WHAT IT DOES:"
        echo "  • Relocates real git → /usr/lib/workspace-guard/sealed/git (0700, root-only)"
        echo "  • Installs guard binary → /usr/bin/git (0755, file capabilities)"
        echo "  • Grants workload caps via setcap on /usr/bin/git (host-exec class)"
        echo "  • Removes any prior pam_cap artifacts from earlier installs"
        echo "  • Gives users rights to run git ONLY through the guard"
        echo "  • Blocks: git reset --hard, git checkout --hard, git rebase,"
        echo "            git commit --amend, git push --force, git reset,"
        echo "            git checkout (destructive file restoration)"
        echo "  • Allows: git status, git log, git diff, git add, git commit,"
        echo "            git pull --ff-only, git fetch, git stash"
        echo "  • dpkg-divert protects from apt overwrites"
        echo "  • Immutable attributes (chattr +i) prevent tampering"
        echo "  • Logs every git invocation to /var/log/workspace-guard/"
        echo ""
        echo "To refresh after code changes:"
        echo "  sudo make guard-refresh   (workspace root; alias: refresh-guard)"
        echo "To uninstall git guard (preserves provision state):"
        echo "  sudo make guard-down"
        echo ""
    fi

    if [[ "$install_mode" == "root-only" && "${nr_count:-0}" -gt 0 ]]; then
        if [[ "${FORCE_ROOT_ONLY:-0}" != "1" ]]; then
            log_error "Refusing root-only install: ${nr_count} non-root login user(s) would lose git access."
            log_error "Multi-user host: use capability mode -> make build-guard && make install-guard-host-exec"
            log_error "To override (non-root git WILL break): FORCE_ROOT_ONLY=1 make install-guard-host-exec"
            return 1
        fi
        log_warn "FORCE_ROOT_ONLY=1: proceeding despite ${nr_count} non-root users (their git will break)."
    fi

    if [[ "${GUARD_RECONCILE:-0}" == "1" ]] || [[ -f /usr/lib/workspace-guard/sealed/git ]]; then
        log_info "Reconciling git guard installation..."
    fi

    if [[ -t 0 ]] && [[ "${GUARD_NONINTERACTIVE:-0}" != "1" ]] \
        && [[ "${GUARD_RECONCILE:-0}" != "1" ]] && [[ ! -f /usr/lib/workspace-guard/sealed/git ]]; then
        echo -ne "${CYAN}${BOLD}Proceed with git guard installation? [y/N] ${NC}"
        read -r response
        case "$response" in
            [yY][eE][sS]|[yY]) ;;
            *) log_info "Git guard installation cancelled."; return 0 ;;
        esac
    fi

    local guard_hash
    guard_hash=$(sha256sum "$guard_bin" | awk '{print $1}')

    # The sealed tree is the single home for frozen real binaries and the
    # dpkg-divert package slots (0700 root:root).
    install -d -m 0700 -o root -g root "$GUARD_SEALED_DIR"
    install -d -m 0700 -o root -g root "$GUARD_SEALED_PKG_DIR"
    install -d -m 0700 -o root -g root "$(dirname "$GUARD_GIT_CORE_PKG")"

    # Guard-aware source selection: never copy the guard itself to
    # git.original.  On reinstall, /usr/bin/git IS the old guard, so
    # copying it would create an infinite fork loop (guard execs
    # git.original which IS the guard, execs git.original again ...).
    # We verify each candidate by sha256 against the guard's hash.
    is_real_git() {
        local candidate="$1"
        [[ -x "$candidate" ]] || return 1
        local h
        h=$(sha256sum "$candidate" | awk '{print $1}')
        [[ "$h" != "$guard_hash" ]]
    }

    if [[ -f /usr/lib/workspace-guard/sealed/git && -n "$(command -v chattr)" ]]; then
        rc=0; chattr -i /usr/lib/workspace-guard/sealed/git || rc=$?
        if [ $rc -ne 0 ]; then
            echo "chattr -i /usr/lib/workspace-guard/sealed/git: no-op or failed (rc=$rc)" >&2
        fi
    fi

    # If git.original already exists and is NOT the guard, keep it.
    if [[ -f /usr/lib/workspace-guard/sealed/git ]] && is_real_git /usr/lib/workspace-guard/sealed/git; then
        log_info "Preserving existing real git at /usr/lib/workspace-guard/sealed/git"
        git_src="/usr/lib/workspace-guard/sealed/git"
    else
        # Find real git: prefer dpkg-divert, then /usr/bin/git (only
        # if it is NOT the guard), then the apt package binary.
        git_src=""
        if divert_is_active && is_real_git /usr/lib/workspace-guard/sealed/pkg/git; then
            git_src="/usr/lib/workspace-guard/sealed/pkg/git"
        elif is_real_git /usr/bin/git; then
            git_src="/usr/bin/git"
        elif is_real_git /usr/lib/workspace-guard/sealed/pkg/git-core/git; then
            git_src="/usr/lib/workspace-guard/sealed/pkg/git-core/git"
            log_warn "Using relocated apt package git: /usr/lib/workspace-guard/sealed/pkg/git-core/git"
        elif is_real_git /usr/lib/git-core/git; then
            git_src="/usr/lib/git-core/git"
            log_warn "Using apt package git: /usr/lib/git-core/git"
        fi
        if [[ -z "$git_src" ]]; then
            log_error "Cannot find real git (all candidates are the guard or missing)"
            log_error "Restore: apt install --reinstall git"
            return 1
        fi
        cp "$git_src" /usr/lib/workspace-guard/sealed/git
        chown root:root /usr/lib/workspace-guard/sealed/git
        chmod 0700 /usr/lib/workspace-guard/sealed/git
    fi

    local src_hash copy_hash
    src_hash=$(sha256sum "$git_src" | awk '{print $1}')
    copy_hash=$(sha256sum /usr/lib/workspace-guard/sealed/git | awk '{print $1}')
    if [[ "$src_hash" != "$copy_hash" ]]; then
        log_error "Checksum mismatch: git.original does not match"
        rm -f /usr/lib/workspace-guard/sealed/git
        return 1
    fi

    # Safety net: verify git.original is NOT the guard before proceeding.
    if [[ "$copy_hash" == "$guard_hash" ]]; then
        log_error "git.original has the same sha256 as the guard: refusing to install"
        log_error "This would cause an infinite fork loop. Restore: apt install --reinstall git"
        rm -f /usr/lib/workspace-guard/sealed/git
        return 1
    fi

    if [[ "$install_mode" == "root-only" ]]; then
        # Root-only: simple copy, no dpkg-divert, no setcap, no chattr
        if [[ -f /usr/bin/git && -n "$(command -v chattr)" ]]; then
            rc=0; chattr -i /usr/bin/git || rc=$?
            if [ $rc -ne 0 ]; then
                echo "chattr -i /usr/bin/git: no-op or failed (rc=$rc)" >&2
            fi
        fi
        mkdir -p /usr/lib/workspace-guard
        guard_install_agent_git_identity || return 1
        cp "$guard_bin" /usr/bin/git
        chown root:root /usr/bin/git
        chmod 0755 /usr/bin/git
        log_info "Installed guard in root-only mode (no caps, no chattr, no dpkg-divert)"
    else
        # Capability mode: full installation with dpkg-divert, setcap, chattr.
        #
        # Stage the guard next to the target first, then swap it in with a
        # single atomic rename. `dpkg-divert --rename` below moves the real
        # git out of /usr/bin/git, so without a staged file there is a window
        # (and a non-atomic cp) where /usr/bin/git is missing or partial. In
        # that window callers in a root-locked repo lose the guard's
        # safe.directory injection and fail with "dubious ownership".
        if [[ ! -x /usr/sbin/setcap ]]; then
            log_error "setcap not found: run 'make init' to install system dependencies"
            return 1
        fi

        local guard_stage=/usr/bin/git.guard
        cp "$guard_bin" "$guard_stage"
        chown root:root "$guard_stage"
        chmod 0755 "$guard_stage"

        if divert_is_active; then
            log_warn "dpkg-divert already in place: continuing"
        else
            dpkg-divert --local --divert /usr/lib/workspace-guard/sealed/pkg/git --rename --add /usr/bin/git
        fi
        chmod 0700 /usr/lib/workspace-guard/sealed/pkg/git
        chown root:root /usr/lib/workspace-guard/sealed/pkg/git

        if [[ -n "$(command -v chattr)" && -f /usr/bin/git ]]; then
            rc=0; chattr -i /usr/bin/git || rc=$?
            if [ $rc -ne 0 ]; then
                echo "chattr -i /usr/bin/git: no-op or failed (rc=$rc)" >&2
            fi
        fi
        # Atomic swap: fills the dpkg-divert gap (or replaces a prior guard)
        # in one rename, so no caller ever observes a missing/partial binary.
        mv -f "$guard_stage" /usr/bin/git
        chown root:root /usr/bin/git
        chmod 0755 /usr/bin/git
        _guard_attempt /usr/sbin/setcap -r /usr/bin/git
        if ! install_guard_host_exec; then
            log_error "host-exec capability delivery failed: rolling back"
            rollback_guard
            return 1
        fi

        if [[ -n "$(command -v chattr)" ]]; then
            chattr +i /usr/bin/git || log_warn "Could not set immutable on /usr/bin/git"
            chattr +i /usr/lib/workspace-guard/sealed/git || log_warn "Could not set immutable on /usr/lib/workspace-guard/sealed/git"
        else
            log_warn "chattr not available: skipping immutable attributes"
        fi

        cat > /etc/apt/apt.conf.d/99workspace-guard << 'EOF'
DPkg::Post-Invoke { "/usr/lib/workspace-guard/apt-check.sh"; };
EOF
        mkdir -p /usr/lib/workspace-guard
        guard_install_agent_git_identity || {
            log_error "Failed to install agent git identity"
            rollback_guard
            return 1
        }
        cat > /usr/lib/workspace-guard/apt-check.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
if dpkg -l git | grep -q '^ii' && [[ ! -f /usr/lib/workspace-guard/sealed/git ]]; then
    echo '[WARN] Git package changed but workspace guard not detected. Re-run: make install-guard-host-exec' >&2
fi
if [[ -f /usr/lib/workspace-guard/sealed/pkg/git ]]; then
    chmod 0700 /usr/lib/workspace-guard/sealed/pkg/git
    chown root:root /usr/lib/workspace-guard/sealed/pkg/git
fi
if [[ -f /usr/lib/workspace-guard/sealed/pkg/git-core/git ]]; then
    chmod 0700 /usr/lib/workspace-guard/sealed/pkg/git-core/git
    chown root:root /usr/lib/workspace-guard/sealed/pkg/git-core/git
fi
if [[ -e /usr/lib/git-core/git && ! -L /usr/lib/git-core/git ]]; then
    echo '[WARN] Git exec path /usr/lib/git-core/git is unguarded. Re-run: make install-guard-host-exec' >&2
fi
EOF
        chmod 755 /usr/lib/workspace-guard/apt-check.sh
    fi

    local _cleanup_boot_name
    case "$(uname -s | tr 'A-Z' 'a-z')" in darwin) _cleanup_boot_name=".boot-macos" ;; *) _cleanup_boot_name=".boot-linux" ;; esac
    if [[ -f "$WORKSPACE_ROOT/$_cleanup_boot_name/bin/git" ]]; then
        rm -f "$WORKSPACE_ROOT/$_cleanup_boot_name/bin/git"
        log_info "Removed previous bash wrapper at $_cleanup_boot_name/bin/git"
    fi
    hash -r

    # Alternate git binaries bypass /usr/bin/git guard; lock them down.
    local _alt_git_paths=(
        /snap/bin/git
        /usr/local/bin/git
        /var/lib/flatpak/exports/bin/org.freedesktop.Sdk.Extension.git
    )
    for path in "${_alt_git_paths[@]}"; do
        if [[ -e "$path" ]]; then
            local _chmod_err _chmod_rc=0
            _chmod_err="$(mktemp)"
            chmod 000 "$path" 2>"$_chmod_err" || _chmod_rc=$?
            if [[ $_chmod_rc -ne 0 ]]; then
                if [[ -s "$_chmod_err" ]]; then
                    echo "chmod 000 $path: $(cat "$_chmod_err")" >&2
                fi
                echo "chmod 000 $path: failed (rc=$_chmod_rc)" >&2
            fi
            rm -f "$_chmod_err"
            log_info "Restricted $path (guard bypass vector)"
        fi
    done

    mkdir -p /var/log/workspace-guard
    chmod 1777 /var/log/workspace-guard

    echo ""
    log_info "Running post-installation verification..."
    local structural_errors=0 functional_errors=0

    local guard_mode guard_owner
    guard_mode=$(stat -c '%a' /usr/bin/git)
    guard_owner=$(stat -c '%U:%G' /usr/bin/git)
    if [[ "$guard_mode" != "755" || "$guard_owner" != "root:root" ]]; then
        log_error "Guard binary has wrong permissions: $guard_mode $guard_owner"
        structural_errors=1
    fi

    if [[ "$install_mode" == "capability" ]]; then
        local _cls
        _cls="$(_guard_capture_line guard_read_deployment_class)"
        if [[ "$_cls" != "host-exec" ]]; then
            log_error "deployment-class must be host-exec (got: ${_cls:-missing})"
            structural_errors=1
        fi
        if [[ -x /usr/sbin/getcap ]]; then
            local _gc
            _gc="$(_guard_capture_line /usr/sbin/getcap /usr/bin/git)"
            if guard_git_has_required_file_caps; then
                log_info "Guard binary has host-exec file caps: $_gc"
            else
                log_error "host-exec requires $(guard_workload_file_cap_string) (got: ${_gc:-none})"
                structural_errors=1
            fi
        fi
        if [[ -e /usr/lib/git-core/git ]]; then
            if [[ ! -L /usr/lib/git-core/git || "$(readlink /usr/lib/git-core/git)" != "/usr/bin/git" ]]; then
                log_error "git exec path /usr/lib/git-core/git is not guarded (expected symlink to /usr/bin/git)"
                structural_errors=1
            fi
            if ! guard_git_core_divert_is_active; then
                log_error "dpkg-divert for /usr/lib/git-core/git not active"
                structural_errors=1
            fi
        fi
        if [[ -f /etc/security/capability.conf ]] \
            && grep -q 'workspace-guard ambient caps' /etc/security/capability.conf; then
            log_error "pam_cap artifact still in capability.conf after host-exec install"
            structural_errors=1
        fi
    fi

    local real_mode real_owner
    real_mode=$(stat -c '%a' /usr/lib/workspace-guard/sealed/git)
    real_owner=$(stat -c '%U:%G' /usr/lib/workspace-guard/sealed/git)
    if [[ "$real_mode" != "700" || "$real_owner" != "root:root" ]]; then
        log_error "git.original has wrong permissions: $real_mode $real_owner"
        structural_errors=1
    fi

    local verify_user=""
    if [[ "$install_mode" == "capability" && "$structural_errors" -eq 0 ]]; then
        verify_user="$(guard_verify_login_user)"
        if [[ -z "$verify_user" ]]; then
            log_error "No login user for functional install verification"
            functional_errors=1
        elif ! guard_host_exec_functional_healthy "$verify_user"; then
            log_error "Agent $verify_user cannot run git (host-exec file-cap delivery ineffective)"
            local _gc
            _gc="$(_guard_capture_line guard_git_file_cap_actual)"
            log_warn "  deployment-class: host-exec"
            log_warn "  getcap /usr/bin/git: ${_gc:-<empty>}"
            functional_errors=1
        else
            local _ver_out _ver_rc=0
        _ver_out="$(/usr/sbin/runuser -u "$verify_user" -- git --version 2>&1)" || _ver_rc=$?
            if [[ $_ver_rc -eq 0 ]]; then
                log_info "git --version ($verify_user, host-exec): $_ver_out"
            else
                log_error "git --version failed for $verify_user: $_ver_out"
                functional_errors=1
            fi
        fi
    elif [[ "$install_mode" == "root-only" ]]; then
        if _git_ver="$(git --version 2>&1)"; then
            log_info "git --version: $_git_ver"
        else
            log_error "git --version failed"
            structural_errors=1
        fi
    fi

    if [[ "$install_mode" == "capability" && "$functional_errors" -eq 0 && -n "$verify_user" ]]; then
        verify_guard_blocks() {
            local label="$1"
            shift
            local tmpdir _stderr _rc=0
            tmpdir=$(mktemp -d)
            chmod 755 "$tmpdir"
            _stderr="$(mktemp)"
            local cmd="cd '$tmpdir' && $*"
            guard_verify_user_run "$verify_user" "$cmd" "$_stderr" || _rc=$?
            if grep -q 'missing workload capabilities' "$_stderr"; then
                log_error "Functional verify invalid for $label (workload caps missing)"
                functional_errors=1
            elif [[ $_rc -eq 0 ]]; then
                log_error "Guard did not block: $label"
                functional_errors=1
            else
                log_info "Guard correctly blocked: $label"
            fi
            rm -f "$_stderr"
            rm -rf "$tmpdir"
        }
        verify_guard_blocks "git reset --hard" git reset --hard
        verify_guard_blocks "git update-ref" git update-ref refs/heads/main deadbeefcafe
        verify_guard_blocks "git read-tree --reset" git read-tree -u --reset HEAD
        verify_guard_blocks "git switch --discard-changes" git switch --discard-changes
        verify_guard_blocks "git -- --hard bypass" git -- --hard
    fi

    for alt in "${_alt_git_paths[@]}"; do
        if [[ -e "$alt" ]]; then
            local alt_mode _stat_err _stat_rc=0
            _stat_err="$(mktemp)"
            alt_mode="$(stat -c '%a' "$alt" 2>"$_stat_err")" || _stat_rc=$?
            if [[ $_stat_rc -ne 0 ]]; then
                if [[ -s "$_stat_err" ]]; then
                    log_warn "stat $alt failed: $(cat "$_stat_err")"
                fi
                alt_mode="missing"
            fi
            rm -f "$_stat_err"
            if [[ "$alt_mode" != "0" ]]; then
                log_warn "Alternate git $alt mode is $alt_mode (expected 000)"
            else
                log_info "Alternate git restricted: $alt (mode 000)"
            fi
        fi
    done

    if [[ $structural_errors -ne 0 ]]; then
        log_error "Structural verification failed: rolling back"
        rollback_guard
        return 1
    fi

    if [[ $functional_errors -ne 0 ]]; then
        log_error "Guard installed but agent cannot run git"
        log_error "Fix host-exec delivery, then: sudo make install-guard-host-exec"
        return 1
    fi

    echo ""
    if [[ "$install_mode" == "root-only" ]]; then
        log_info "Git guard installation complete (root-only mode: SOFT BARRIER)."
        log_info "  /usr/bin/git          (0755 root:root, no caps)"
        log_info "  /usr/lib/workspace-guard/sealed/git (0700 root:root)"
        log_info "  audit log: /var/log/workspace-guard/"
        log_warn "  root-only mode: root can bypass (soft barrier, see threat model docs)"
    else
        log_info "Git guard installation complete (host-exec)."
        log_info "  /usr/bin/git          (0755 root:root, file caps, immutable)"
        log_info "  /usr/lib/workspace-guard/sealed/git (0700 root:root, immutable)"
        log_info "  deployment-class: host-exec (see /usr/lib/workspace-guard/deployment-class)"
        log_info "  dpkg-divert configured"
        log_info "  apt hook registered"
        log_info "  audit log: /var/log/workspace-guard/"
    fi
    echo ""
    log_info "To verify: make check-guard-host-exec"

    return 0
}
