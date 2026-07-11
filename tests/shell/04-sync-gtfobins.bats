#!/usr/bin/env bash
# 04-sync-gtfobins.bats: tests for scripts/sync-gtfobins. Exercises the
# full pipeline (fetch -> parse -> discover -> emit) against a fake repo
# with stubbed curl/find/getcap so no network or real root scan is
# needed. The fake repo mirrors the real layout so BASH_SOURCE-based
# REPO_ROOT resolution points at the controlled copy.

load lib/harness

setup()    { guard_setup; load_fake_repo; }
teardown() {
    rm -rf "$GUARD_ROOT/target/.bats-sync-live"
    guard_teardown
}

# Build a fake repo with real scripts + config + fake reference HTML
# + stubbed live SUID/CAP surface. Sets FAKE_REPO in the current shell
# (not a subshell) so exports survive into the bats test body.
_setup_sync_repo() {
    FAKE_REPO="$(make_fake_repo)"
    copy_real_scripts "$FAKE_REPO"
    copy_real_config "$FAKE_REPO"

    # Fake GTFOBins HTML: 3 binaries with SUID, 2 with sudo, 1 with caps.
    fake_gtfobins_html "$FAKE_REPO/docs/references/gtfobins-suid.html" \
        "sudo:Sudo,SUID" \
        "passwd:SUID" \
        "mount:SUID" \
        "git:Sudo" \
        "find:Sudo" \
        "pkexec:Capabilities,SUID"
    # gtfobins-sudo.html and gtfobins-caps.html are byte-identical to
    # the suid capture (URL fragment is client-side only).
    cp "$FAKE_REPO/docs/references/gtfobins-suid.html" "$FAKE_REPO/docs/references/gtfobins-sudo.html"
    cp "$FAKE_REPO/docs/references/gtfobins-suid.html" "$FAKE_REPO/docs/references/gtfobins-caps.html"

    # Fake konstruktoid list with comments + mixed case.
    fake_konstruktoid_list "$FAKE_REPO/docs/references/konstruktoid-suid-list.txt" \
        "# comment line" \
        "Sudo" \
        "passwd" \
        "MOUNT"

    # Readable fake SUID/CAP binaries outside /tmp (decode-caps excludes /tmp).
    # Real host SUID paths are unreadable on Darwin; fixtures must be
    # world-readable so stat/sha256sum exercise real file I/O.
    SYNC_LIVE_ROOT="$GUARD_ROOT/target/.bats-sync-live"
    rm -rf "$SYNC_LIVE_ROOT"
    SYNC_SUDO="$SYNC_LIVE_ROOT/usr/bin/sudo"
    SYNC_PASSWD="$SYNC_LIVE_ROOT/usr/bin/passwd"
    SYNC_GIT="$SYNC_LIVE_ROOT/usr/bin/git"
    make_fake_suid "$SYNC_LIVE_ROOT" "$SYNC_SUDO" "$SYNC_PASSWD"
    mkdir -p "$(dirname "$SYNC_GIT")"
    echo 'fake-git-cap-surface' > "$SYNC_GIT"
    chmod 0644 "$SYNC_GIT"

    printf '%s\n' "$SYNC_SUDO" "$SYNC_PASSWD" > "$TEST_TMPDIR/suid.lst"
    export GUARD_FIND_FIXTURE="$TEST_TMPDIR/suid.lst"

    printf '%s\n' "$SYNC_GIT cap_chown,cap_dac_override=ep" > "$TEST_TMPDIR/caps.lst"
    export GUARD_GETCAP_FIXTURE="$TEST_TMPDIR/caps.lst"
}

# Convenience: run sync-gtfobins against FAKE_REPO.
_run_sync() { run bash "$FAKE_REPO/scripts/sync-gtfobins" "$@"; }

@test "sync-gtfobins: --help prints usage and exits 0" {
    _setup_sync_repo
    _run_sync --help
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "--dry-run"
    assert_output --partial "--verify"
}

@test "sync-gtfobins: --dry-run lists planned actions and writes nothing" {
    _setup_sync_repo
    _run_sync --dry-run
    assert_success
    assert_output --partial "DRY RUN"
    assert_output --partial "$SYNC_SUDO"
    assert_output --partial "$SYNC_PASSWD"
    assert_output --partial "res/binary-lock.yaml"
    # No baseline files should have been written.
    [ ! -f "$FAKE_REPO/res/suid-baseline.yaml" ]
    [ ! -f "$FAKE_REPO/res/fcap-baseline.yaml" ]
}

# Touch every reference file that emit_verify_manifest lists so
# sha256sum has targets (the function uses set -e so a missing file
# aborts the script).
_stage_all_refs() {
    local rdir="$FAKE_REPO/docs/references"
    local f
    for f in \
        gtfobins-suid.html gtfobins-sudo.html gtfobins-caps.html \
        konstruktoid-suid-list.txt capabilities.7.html \
        NVD-CVE-2021-4034.html sudo-Baron-Samedit-CVE-2021-3156.html \
        sudo-chroot-CVE-2025-32463.html NVD-CVE-2025-32463.html \
        systemshardening-cap-hardening.html systemshardening-chattr.html \
        systemshardening-dm-verity.html yunolay-suid-sgid-abuse.html \
        yunolay-caps-abuse.html sandlock-arxiv.html \
        elastic-cap-escalation.html cis-dil-benchmark-suid-rb.html; do
        touch "$rdir/$f"
    done
}

@test "sync-gtfobins: --verify emits canonical-sources.sha256" {
    _setup_sync_repo
    _stage_all_refs
    _run_sync --verify
    assert_success
    assert_output --partial "Verify complete"
    [ -f "$FAKE_REPO/res/canonical-sources.sha256" ]
}

@test "sync-gtfobins: unknown arg exits 1 (usage)" {
    _setup_sync_repo
    _run_sync --bogus
    assert_failure
}

@test "sync-gtfobins: parses GTFOBins SUID tags from HTML" {
    _setup_sync_repo
    _run_sync
    assert_success
    # suid-baseline.yaml should contain sudo and passwd (live SUID).
    [ -f "$FAKE_REPO/res/suid-baseline.yaml" ]
    grep -q "$SYNC_SUDO" "$FAKE_REPO/res/suid-baseline.yaml"
    grep -q "$SYNC_PASSWD" "$FAKE_REPO/res/suid-baseline.yaml"
}

@test "sync-gtfobins: suid-baseline.yaml has correct YAML shape" {
    _setup_sync_repo
    _run_sync
    assert_success
    local bl="$FAKE_REPO/res/suid-baseline.yaml"
    head -n1 "$bl" | grep -q '^# Auto-generated'
    grep -q '^suid_binaries:' "$bl"
    grep -q '  - path:' "$bl"
    grep -q '    owner:' "$bl"
    grep -q '    sha256:' "$bl"
    grep -q '    gtfobins:' "$bl"
    grep -q '    contained:' "$bl"
}

@test "sync-gtfobins: suid-baseline sha256 is real file digest (not fallback)" {
    _setup_sync_repo
    _run_sync
    assert_success
    local bl="$FAKE_REPO/res/suid-baseline.yaml" expected
    expected="$(sha256sum "$SYNC_SUDO" | awk '{print $1}')"
    awk -v p="$SYNC_SUDO" -v want="$expected" \
        '$0 ~ "path: \"" p "\"" {c=1} c && /sha256:/{gsub(/.*sha256: "/, ""); gsub(/".*/, ""); print; exit}' "$bl" \
        | grep -q "$expected"
    refute_line 'sha256: "?"'
}

@test "sync-gtfobins: suid-baseline marks gtfobins=true for GTFOBins-listed binaries" {
    _setup_sync_repo
    _run_sync
    assert_success
    # sudo is in the fake GTFOBins SUID list -> gtfobins: true
    local bl="$FAKE_REPO/res/suid-baseline.yaml"
    # Extract the sudo block and check gtfobins: true.
    awk -v p="$SYNC_SUDO" '$0 ~ "path: \"" p "\"" {c=1} c && /gtfobins:/{print; exit}' "$bl" | grep -q 'true'
}

@test "sync-gtfobins: fcap-baseline.yaml has correct YAML shape" {
    _setup_sync_repo
    _run_sync
    assert_success
    local fb="$FAKE_REPO/res/fcap-baseline.yaml"
    head -n1 "$fb" | grep -q '^# Auto-generated'
    grep -q '^file_capabilities:' "$fb"
    grep -q '  - path:' "$fb"
    grep -q '    caps:' "$fb"
    grep -q '    recommended:' "$fb"
    grep -q '    strip:' "$fb"
}

@test "sync-gtfobins: fcap-baseline recommends throttle for git" {
    _setup_sync_repo
    _run_sync
    assert_success
    local fb="$FAKE_REPO/res/fcap-baseline.yaml"
    # git path should have recommended: "throttle"
    awk -v p="$SYNC_GIT" '$0 ~ "path: \"" p "\"" {c=1} c && /recommended:/{print; exit}' "$fb" | grep -q 'throttle'
}

@test "sync-gtfobins: cve-catalog.yaml is static with expected CVE IDs" {
    _setup_sync_repo
    _run_sync
    assert_success
    local cc="$FAKE_REPO/res/cve-catalog.yaml"
    [ -f "$cc" ]
    grep -q 'CVE-2021-4034' "$cc"
    grep -q 'CVE-2021-3156' "$cc"
    grep -q 'CVE-2025-32463' "$cc"
}

@test "sync-gtfobins: binary-lock.yaml is emitted with version header" {
    _setup_sync_repo
    _run_sync
    assert_success
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    [ -f "$lk" ]
    grep -q '^version: 1' "$lk"
    grep -q '^binaries:' "$lk"
}

@test "sync-gtfobins: binary-lock.yaml contains live-surface paths" {
    _setup_sync_repo
    _run_sync
    assert_success
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    grep -q "path: \"$SYNC_SUDO\"" "$lk"
    grep -q "path: \"$SYNC_PASSWD\"" "$lk"
}

@test "sync-gtfobins: binary-lock.yaml folds live-surface-only binaries" {
    # Binaries on the live surface but NOT in GTFOBins (e.g. a custom
    # SUID binary) should still appear in binary-lock.yaml with a tag
    # matching how they were discovered. The path must be a real file so
    # stat/sha256sum in emit_suid_baseline succeed.
    _setup_sync_repo
    local custom_path="$TEST_TMPDIR/bin/bincustom"
    mkdir -p "$(dirname "$custom_path")"
    echo '#!/usr/bin/env bash' > "$custom_path"
    chmod 4755 "$custom_path"
    printf '%s\n' "$SYNC_SUDO" "$SYNC_PASSWD" "$custom_path" \
        > "$TEST_TMPDIR/suid.lst"
    _run_sync
    assert_success
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    grep -q 'name: "bincustom"' "$lk"
    grep -q "path: \"$custom_path\"" "$lk"
}

@test "sync-gtfobins: konstruktoid list parsed (comments stripped, lowercased)" {
    _setup_sync_repo
    _run_sync
    assert_success
    # The konstruktoid list had Sudo, passwd, MOUNT (with comment).
    # After parsing: sudo, passwd, mount (lowercased, unique).
    # These should show up as konstruktoid: true in suid-baseline.
    local bl="$FAKE_REPO/res/suid-baseline.yaml"
    # passwd is live + in konstruktoid -> konstruktoid: true
    awk -v p="$SYNC_PASSWD" '$0 ~ "path: \"" p "\"" {c=1} c && /konstruktoid:/{print; exit}' "$bl" | grep -q 'true'
}

@test "sync-gtfobins: fetch_url returns 0 even when curl fails" {
    # The curl stub is a no-op success, so fetch_url should return 0
    # and the script should proceed using existing cache files.
    _setup_sync_repo
    # Replace curl stub with a failing one.
    make_stub curl <<'STUB'
#!/usr/bin/env bash
echo "curl: network error (stub)" >&2
exit 7
STUB
    _run_sync
    assert_success
}

@test "sync-gtfobins: full run writes all four baseline files" {
    _setup_sync_repo
    _run_sync
    assert_success
    [ -f "$FAKE_REPO/res/suid-baseline.yaml" ]
    [ -f "$FAKE_REPO/res/fcap-baseline.yaml" ]
    [ -f "$FAKE_REPO/res/cve-catalog.yaml" ]
    [ -f "$FAKE_REPO/res/binary-lock.yaml" ]
}
