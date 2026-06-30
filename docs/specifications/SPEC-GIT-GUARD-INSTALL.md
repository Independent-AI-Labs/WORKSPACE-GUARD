# Specification: Git Guard Installation Procedure

**Date:** 2026-05-18
**Status:** DRAFT
**Type:** Specification
**Parent:** [SPEC-GIT-GUARD](SPEC-GIT-GUARD.md)
**Requirements:** [REQ-GIT-GUARD](../requirements/REQ-GIT-GUARD.md) §15 (REQ-GGUARD-140 through REQ-GGUARD-162)

---

## 1. Overview

The SUID git guard is installed exclusively by `sudo make pre-req`. This is the **only** entry point: `make install` does NOT touch the git binary or git guard.

The installation performs three phases:
1. **Install system dependencies** (apt + bootstrap): existing behaviour
2. **Build the Rust guard binary** from source
3. **Relocate real git** and install the SUID guard at `/usr/bin/git`

The user is informed before any git-related changes occur.

---

## 2. Pre-Installation User Notification

Before any git modification, the script shall display:

```
═══════════════════════════════════════════════
 Git Guard Installation (SUID-root)
═══════════════════════════════════════════════

This will:
  • Build the workspace-guard Rust binary from source
  • Relocate /usr/bin/git → /usr/bin/git.original (mode 0700, root-only)
  • Install the guard as /usr/bin/git (mode 4555, SUID root)

After installation:
  • All git commands are validated by the guard
  • Destructive commands (reset, checkout, clean, etc.) are blocked
  • The real git binary is inaccessible without root privileges
  • Only the SUID guard can invoke real git

To uninstall later: sudo make pre-req --uninstall-git-guard
```

The user must confirm by typing `y` (interactive) or pass `--install` / `--ci` for non-interactive modes.

---

## 3. Phase 1: System Dependencies (Existing)

The existing `pre-req.sh` logic for installing system dependencies via apt and bootstrap scripts runs first. This includes checking for and installing:
- `git` package (the real git binary)
- `gcc` / C compiler
- `curl`, `tar`, `gzip`, `dpkg-deb`
- Playwright browser libraries
- Other system tools

This phase is unchanged from current behaviour.

---

## 4. Phase 2: Build the Rust Guard Binary

### 4.1 Prerequisites Check

The script verifies:
- Rust toolchain is installed (`rustc --version`)
- The source directory exists at `projects/WORKSPACE-GUARD/`
- `Cargo.toml` is present

If Rust is not installed, the script offers to install it via `rustup`:

```
[INFO] Rust toolchain not found. Install via rustup? [y/N]
```

In `--install` mode (non-interactive), the script installs rustup automatically. In `--ci` mode, it fails with a clear error.

### 4.2 Build Process

```bash
cd projects/WORKSPACE-GUARD

# Try musl (static) first, fall back to gnu (dynamic)
if rustup target list --installed | grep -q musl; then
    echo "[INFO] Building statically linked binary (musl)..."
    cargo build --release --target x86_64-unknown-linux-musl
    GUARD_BIN="target/x86_64-unknown-linux-musl/release/workspace-guard"
else
    echo "[INFO] musl target not available: building dynamically linked (gnu)..."
    cargo build --release --target x86_64-unknown-linux-gnu
    GUARD_BIN="target/x86_64-unknown-linux-gnu/release/workspace-guard"
fi
```

### 4.3 Build Verification

After build completes, the script verifies:
- The binary file exists at the expected path
- It is a valid ELF executable (`file $GUARD_BIN | grep -q ELF`)
- It is not empty (`test -s $GUARD_BIN`)

If verification fails, the installation aborts with an error.

---

## 5. Phase 3: Relocate Real Git and Install Guard

### 5.0 Pre-Flight: Detect Alternative Git Installations

Before modifying `/usr/bin/git`, the script scans for alternative git binaries that would bypass the guard:

```bash
for path in /snap/bin/git /usr/local/bin/git ~/.nix-profile/bin/git; do
    if [[ -x "$path" ]]; then
        echo "[WARN] Alternative git found at $path: this bypasses the guard"
        echo "       The guard only protects /usr/bin/git (the canonical path)"
    fi
done
```

This is informational only. The guard does not attempt to disable snap, nix, or user-installed binaries: it protects the system git path.

### 5.1 Pre-Flight Checks

Before modifying `/usr/bin/git`:

1. **Verify system git exists**: `test -x /usr/bin/git`
2. **Check if already installed**: `test -f /usr/bin/git.original`

If already installed (git.original exists with mode 0700):
```
[INFO] Git guard is already installed.
  /usr/bin/git.original exists (mode 0700, root:root)
  /usr/bin/git is SUID (mode 4555, root:root)

To reinstall: sudo make pre-req --reinstall-git-guard
To uninstall: sudo make pre-req --uninstall-git-guard
```

The script exits successfully without re-installing.

### 5.2 Configure dpkg-divert

Before relocating the real git, the script configures a dpkg diversion to prevent the `git` apt package from overwriting `/usr/bin/git` during `apt install git`, `apt upgrade`, or `apt dist-upgrade`:

```bash
# Step 1: Copy real git to git.original (our restricted copy)
cp /usr/bin/git /usr/bin/git.original
chown root:root /usr/bin/git.original
chmod 0700 /usr/bin/git.original

# Step 2: Configure dpkg-divert (prevents future apt overwrites)
dpkg-divert --local --divert /usr/bin/git.distrib --rename --add /usr/bin/git

# Step 3: Verify the diversion is in place
dpkg-divert --list /usr/bin/git | grep -q "git.distrib"
```

After this, any future `apt install git` will place the real git at `/usr/bin/git.distrib` (which is already mode 0700 root:root as a safeguard, though dpkg will try to set its own permissions).

### 5.3 Verify the Copy

```bash
ORIG_HASH=$(sha256sum /usr/bin/git | awk '{print $1}')
COPY_HASH=$(sha256sum /usr/bin/git.original | awk '{print $1}')
if [[ "$ORIG_HASH" != "$COPY_HASH" ]]; then
    echo "[ERROR] Checksum mismatch: git.original does not match system git"
    rm -f /usr/bin/git.original
    dpkg-divert --remove /usr/bin/git 2>/dev/null || true
    exit 1
fi
```

### 5.4 Install the Guard

```bash
# Copy built binary to /usr/bin/git
cp "$GUARD_BIN" /usr/bin/git
chown root:root /usr/bin/git
chmod 4555 /usr/bin/git
```

### 5.5 Remove Older Bash Wrapper (PATH Bypass Mitigation)

The older bash wrapper at `.boot-linux/bin/git` provides a PATH-based bypass of the SUID guard. Since `.boot-linux/bin/` appears in PATH, running `git` would invoke the bash wrapper instead of `/usr/bin/git`.

The script removes this bypass:

```bash
if [[ -f "$PROJECT_ROOT/.boot-linux/bin/git" ]]; then
    rm -f "$PROJECT_ROOT/.boot-linux/bin/git"
    echo "[INFO] Removed older bash wrapper at .boot-linux/bin/git"
    echo "       Use /usr/bin/git (SUID guard) for all git operations"
fi
```

If the user's shell has `.boot-linux/bin/` cached in its hash table, the script also clears it:

```bash
hash -r 2>/dev/null || true
```

### 5.6 Register Apt Post-Invoke Hook

To detect if the git package is reinstalled (which could indicate an attempt to bypass the guard), the script registers an apt hook:

```bash
cat > /etc/apt/apt.conf.d/99git-guard << 'EOF'
DPkg::Post-Invoke { "if dpkg -l git 2>/dev/null | grep -q '^ii' && [ ! -f /usr/bin/git.original ]; then echo '[WARN] Git package changed but git guard not detected. Re-run: sudo make pre-req'; fi"; };
EOF
```

This hook runs after every `dpkg` operation and warns if:
- The `git` package is installed
- But `/usr/bin/git.original` (the guard's marker) does not exist

It does NOT reinstall the guard on its own; it only warns.

### 5.7 Post-Installation Verification

The script runs four checks:

```bash
# Check 1: Guard has correct permissions
GUARD_MODE=$(stat -c '%a' /usr/bin/git)
GUARD_OWNER=$(stat -c '%U:%G' /usr/bin/git)
[[ "$GUARD_MODE" == "4555" && "$GUARD_OWNER" == "root:root" ]]

# Check 2: Real git has correct permissions
REAL_MODE=$(stat -c '%a' /usr/bin/git.original)
REAL_OWNER=$(stat -c '%U:%G' /usr/bin/git.original)
[[ "$REAL_MODE" == "700" && "$REAL_OWNER" == "root:root" ]]

# Check 3: git --version works as current user
sudo -u "$SUDO_USER" git --version >/dev/null 2>&1

# Check 4: git reset --hard is blocked as current user
if sudo -u "$SUDO_USER" git reset --hard >/dev/null 2>&1; then
    echo "[ERROR] Guard did not block git reset --hard"
    exit 1
fi
```

If any check fails, the script attempts rollback (§6).

---

## 6. Rollback on Failure

If any step in Phase 3 fails, the script attempts to restore the original state:

```bash
rollback_git() {
    echo "[WARN] Installation failed: attempting rollback..."

    # Remove the guard binary
    rm -f /usr/bin/git

    # Restore dpkg-divert so /usr/bin/git returns to dpkg control
    dpkg-divert --rename --remove /usr/bin/git 2>/dev/null || true

    # Restore original git if we copied it
    if [[ -f /usr/bin/git.original ]]; then
        mv /usr/bin/git.original /usr/bin/git
        chown root:root /usr/bin/git
        chmod 0755 /usr/bin/git
        echo "[INFO] Restored /usr/bin/git from git.original"
    else
        echo "[ERROR] Cannot rollback: git.original not available"
        echo "[ERROR] You must manually reinstall git: sudo apt install --reinstall git"
    fi
}
```

The rollback is best-effort. If it also fails, a clear error message is displayed with manual recovery instructions.

---

## 7. Uninstall Procedure

Triggered by `sudo make pre-req --uninstall-git-guard`:

```bash
# Step 1: Remove the SUID guard
rm -f /usr/bin/git

# Step 2: Remove dpkg-divert (restores /usr/bin/git to dpkg control)
dpkg-divert --rename --remove /usr/bin/git

# Step 3: Restore real git
if [[ -f /usr/bin/git.original ]]; then
    mv /usr/bin/git.original /usr/bin/git
    chown root:root /usr/bin/git
    chmod 0755 /usr/bin/git
    echo "✅ Git guard uninstalled: /usr/bin/git restored"
else
    # git.distrib was created by dpkg-divert: use that
    if [[ -f /usr/bin/git.distrib ]]; then
        mv /usr/bin/git.distrib /usr/bin/git
        chown root:root /usr/bin/git
        chmod 0755 /usr/bin/git
        echo "✅ Git guard uninstalled: restored from git.distrib"
    else
        echo "[ERROR] No git backup found: cannot restore"
        exit 1
    fi
fi

# Step 4: Remove apt post-invoke hook
rm -f /etc/apt/apt.conf.d/99git-guard

# Step 5: Verify
git --version
echo "✅ git --version: $(git --version)"
```
