# Specification: Git Guard System Hardening

**Date:** 2026-05-18
**Status:** DRAFT
**Type:** Specification
**Parent:** [SPEC-GIT-GUARD-INSTALL](SPEC-GIT-GUARD-INSTALL.md)

---

## 8. Integration into pre-req.sh

The git guard installation logic is added to `pre-req.sh` as a new section that runs **after** all apt/bootstrap dependency installation is complete. The new code path is:

```
pre-req.sh main flow:
  1. Check dependencies → populate MISSING_ENTRIES
  2. Probe apt → resolve package names
  3. Install missing (if --install mode)
     ├── Install apt packages
     └── Bootstrap gcc if needed
  4. Build and install git guard (NEW SECTION)
     ├── Notify user about SUID installation
     ├── Build Rust binary
     ├── Relocate real git
     ├── Install SUID guard
     └── Verify + rollback on failure
```

The git guard section runs unconditionally after dependency installation (not gated on missing packages). If the guard is already installed, it skips without notice (unless `--reinstall-git-guard` is passed).

### 8.1 New Command-Line Flags for pre-req.sh

| Flag | Behaviour |
|------|-----------|
| `--uninstall-git-guard` | Uninstall the SUID guard, restore system git |
| `--reinstall-git-guard` | Force re-install even if already installed |

These flags are mutually exclusive with `--install` and `--ci`.

---

## 9. Makefile Changes

### 9.1 Remove `install-git-guard` from `make install`

The `install-git-guard` target currently copies the bash wrapper to `.boot-linux/bin/git`. This target is **removed** from the `make install` and `make install-ci` flows.

**Before:**
```makefile
install: ... install-git-guard install-hooks ...
install-ci: ... install-git-guard install-hooks ...
```

**After:**
```makefile
install: ... install-hooks ...
install-ci: ... install-hooks ...
```

### 9.2 Keep `install-git-guard` as a No-op for Migration Support

The `install-git-guard` target definition remains in the Makefile (as a no-op with a deprecation warning) to support existing scripts that still invoke it, but it is NOT called by any install flow:

```makefile
.PHONY: install-git-guard
install-git-guard:
	@echo "⚠️  install-git-guard is deprecated — git guard is now installed via sudo make pre-req"
	@echo "    The SUID guard replaces the .boot-linux/bin/git wrapper."
```

---

## 10. Interaction with Existing Bash Guard

During the transition period, the old bash guard at `ami/scripts/utils/git-guard` and the `.boot-linux/bin/git` wrapper remain in place but are **no longer the active guard**. After `sudo make pre-req` installs the SUID guard:

- `/usr/bin/git` → SUID Rust guard (active)
- `/usr/bin/git.original` → real git (restricted)
- `.boot-linux/bin/git` → older bash wrapper (inactive, not in PATH)
- `ami/scripts/utils/git-guard` → source script (kept for reference)

The older wrapper can be removed after all machines have migrated to the SUID guard.

---

## 11. System Hardening During Installation

### 11.1 Restrict Alternate Git Binaries

The installation script restricts access to alternate git binaries that would bypass the guard:

```bash
# Restrict snap git if present
if [[ -x /snap/bin/git ]]; then
    chmod 000 /snap/bin/git 2>/dev/null || true
    echo "[INFO] Restricted /snap/bin/git (bypass vector)"
fi

# Restrict flatpak git if present
if [[ -x /var/lib/flatpak/exports/bin/org.freedesktop.Sdk.Extension.git ]]; then
    chmod 000 /var/lib/flatpak/exports/bin/org.freedesktop.Sdk.Extension.git 2>/dev/null || true
    echo "[INFO] Restricted flatpak git (bypass vector)"
fi

# Remove any user-installed git from /usr/local/bin
if [[ -x /usr/local/bin/git ]]; then
    chmod 000 /usr/local/bin/git 2>/dev/null || true
    echo "[INFO] Restricted /usr/local/bin/git (bypass vector)"
fi
```

This is done during `sudo make pre-req` because only root has the permissions to change these binaries.

### 11.2 PATH Hardening

The installation script verifies that no PATH entries contain alternate git binaries before the system path:

```bash
# Check if any PATH entry contains a git binary before /usr/bin
IFS=':' read -ra PATH_ENTRIES <<< "$PATH"
for entry in "${PATH_ENTRIES[@]}"; do
    if [[ -x "$entry/git" && "$entry" != "/usr/bin" ]]; then
        echo "[WARN] PATH contains alternate git at $entry/git — this bypasses the guard"
        echo "       Remove $entry from PATH or restrict $entry/git"
    fi
done
```

### 11.3 Guard Binary Immutability

The guard binary is protected from modification:

```bash
# Set immutable attribute on guard binary (requires root)
chattr +i /usr/bin/git 2>/dev/null || true

# Set immutable attribute on git.original (prevents tampering)
chattr +i /usr/bin/git.original 2>/dev/null || true
```

Note: `chattr +i` requires the `chattr` utility (part of `e2fsprogs`). If not available, the script warns but continues.

### 11.4 Detect Git Library Bypass Attempts

The installation script checks for git libraries that could bypass the guard:

```bash
# Check for libgit2 installations
if dpkg -l libgit2-dev 2>/dev/null | grep -q '^ii'; then
    echo "[WARN] libgit2-dev is installed — applications can bypass the guard via libgit2"
    echo "       Consider: sudo apt remove libgit2-dev"
fi

# Check for GitPython via pip
if pip3 list 2>/dev/null | grep -q 'GitPython'; then
    echo "[WARN] GitPython is installed — Python scripts can bypass the guard"
    echo "       Consider: pip3 uninstall GitPython"
fi
```

This is informational only — removing libraries may break legitimate applications.

### 11.5 Pre-commit Hook Enforcement

The installation ensures pre-commit hooks are installed in all repos, providing a second layer of defense:

```bash
# Install hooks in workspace root
make install-hooks

# Install hooks in all nested repos
make install-hooks-recursive

# Verify hooks are installed
for repo in $(find . -name ".git" -type d); do
    if [[ ! -x "$repo/hooks/pre-commit" ]]; then
        echo "[WARN] Pre-commit hook missing in $repo"
    fi
done
```

### 11.6 Audit Trail Setup

The installation creates a system-wide audit trail:

```bash
# Create audit log directory (owned by root, writable by all users)
mkdir -p /var/log/workspace-guard
chmod 1777 /var/log/workspace-guard

# Configure rsyslog to forward guard logs
cat > /etc/rsyslog.d/99-workspace-guard.conf << 'EOF'
if $programname == 'workspace-guard' then /var/log/workspace-guard/audit.log
& stop
EOF

systemctl restart rsyslog
```

---

## 12. Requirements Traceability

| Requirement | Spec Section | Status |
|-------------|-------------|--------|
| REQ-GGUARD-140 | §1, §9 | Covered |
| REQ-GGUARD-141 | §2 | Covered |
| REQ-GGUARD-142 | §4.1–4.2 | Covered |
| REQ-GGUARD-143 | §4.3, §5.1 | Covered |
| REQ-GGUARD-144 | §5.2 | Covered |
| REQ-GGUARD-145 | §5.3 | Covered |
| REQ-GGUARD-146 | §5.7 | Covered |
| REQ-GGUARD-147 | §6 | Covered |
| REQ-GGUARD-148 | §5.1 | Covered |
| REQ-GGUARD-149 | §7 | Covered |
| REQ-GGUARD-150 | §5.2 | Covered |
| REQ-GGUARD-151 | §5.5 | Covered |
| REQ-GGUARD-152 | §11.3 | Covered |
| REQ-GGUARD-153 | §5.6 | Covered |
| REQ-GGUARD-154 | §5.0, §11 | Covered |
| REQ-GGUARD-160 | §4.1 | Covered |
| REQ-GGUARD-161 | §4.2 | Covered |
| REQ-GGUARD-162 | §4.2 | Covered |
