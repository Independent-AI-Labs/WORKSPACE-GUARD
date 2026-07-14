#!/usr/bin/env bash
# 05-binary-lock-yaml.bats: tests for scripts/lib/binary-lock-yaml.sh
# (emit_binary_lock). The function joins config/binary-policy-rules.yaml
# against the GTFOBins parse + live SUID/CAP surface and emits
# res/binary-lock.yaml. These tests exercise the join logic: exact name
# wins, tag catch-all, final deny-all, null vs non-null paths, and
# contained flags.

load lib/harness

setup()    { guard_setup; load_fake_repo; }
teardown() { guard_teardown; }

# Set up the globals emit_binary_lock expects from its parent script.
# Creates a minimal fake repo with config + reference HTML + live surface.
_setup_emit() {
    FAKE_REPO="$(make_fake_repo)"
    copy_real_scripts "$FAKE_REPO"
    copy_real_config "$FAKE_REPO"

    # Minimal GTFOBins universe: 3 suid + 1 cap + 1 sudo-only.
    fake_gtfobins_html "$FAKE_REPO/docs/references/gtfobins-suid.html" \
        "sudo:Sudo,SUID" "passwd:SUID" "mount:SUID" \
        "pkexec:Capabilities,SUID" "git:Sudo"
    cp "$FAKE_REPO/docs/references/gtfobins-suid.html" \
       "$FAKE_REPO/docs/references/gtfobins-sudo.html"
    cp "$FAKE_REPO/docs/references/gtfobins-suid.html" \
       "$FAKE_REPO/docs/references/gtfobins-caps.html"

    fake_konstruktoid_list "$FAKE_REPO/docs/references/konstruktoid-suid-list.txt" \
        "sudo" "passwd"

    # Globals emit_binary_lock reads:
    export REPO_ROOT="$FAKE_REPO"
    export RES_DIR="$FAKE_REPO/res"
    export DEVNULL="/dev/null"
    mkdir -p "$RES_DIR"

    # Parse the fake HTML into the temp files emit_binary_lock reads.
    # Mirror what sync-gtfobins does before calling emit_binary_lock.
    GTFOS_SUID_TMP="$(mktemp)"; export GTFOS_SUID_TMP
    GTFOS_SUDO_TMP="$(mktemp)"; export GTFOS_SUDO_TMP
    GTFOS_CAPS_TMP="$(mktemp)"; export GTFOS_CAPS_TMP
    KONS_SUID_TMP="$(mktemp)";  export KONS_SUID_TMP
    SUID_LIVE_TMP="$(mktemp)";  export SUID_LIVE_TMP
    CAPS_LIVE_TMP="$(mktemp)";  export CAPS_LIVE_TMP

    # Parse the fake HTML manually (cannot source sync-gtfobins: it has
    # set -euo pipefail + exit that would kill the bats test shell).
    awk -v so="$GTFOS_SUID_TMP" -v su="$GTFOS_SUDO_TMP" -v co="$GTFOS_CAPS_TMP" '
        BEGIN { RS = "<tr data-gtfobin-name=" }
        NR > 1 {
            name = $0; sub(/^"/, "", name); sub(/".*/, "", name)
            if (name !~ /^[a-z][a-z0-9_-]*$/) next
            if ($0 ~ /function-contexts="[^"]*SUID[^"]*"/)        print name > so
            if ($0 ~ /function-contexts="[^"]*Sudo[^"]*"/)        print name > su
            if ($0 ~ /function-contexts="[^"]*Capabilities[^"]*"/) print name > co
        }
    ' "$FAKE_REPO/docs/references/gtfobins-suid.html"

    awk '/^[[:space:]]*$/ {next} /^[[:space:]]*#/ {next}
         {print tolower($0)}' "$FAKE_REPO/docs/references/konstruktoid-suid-list.txt" \
        | sort -u > "$KONS_SUID_TMP"

    # Live SUID: sudo + passwd (real files on host).
    printf '%s\n' /usr/bin/sudo /usr/bin/passwd > "$SUID_LIVE_TMP"
    # Live caps: none.
    : > "$CAPS_LIVE_TMP"

    # register_temp + cleanup_temps (emit_binary_lock calls them).
    _TEMP_FILES=()
    register_temp() { _TEMP_FILES+=("$1"); }
    cleanup_temps() { local f; for f in "${_TEMP_FILES[@]+"${_TEMP_FILES[@]}"}"; do rm -f "$f" 2>"$DEVNULL"; done; }

    # Source the function we want to test.
    source "$FAKE_REPO/scripts/lib/binary-lock-yaml.sh"
}

@test "binary-lock-yaml: emits version: 1 + binaries: header" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    [ -f "$lk" ]
    grep -q '^version: 1' "$lk"
    grep -q '^binaries:' "$lk"
}

@test "binary-lock-yaml: sudo gets arg-validate (exact name rule wins)" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    # The sudo entry should have policy: arg-validate (exact name rule).
    awk '/^  - name: "sudo"/{c=1} c && /policy:/{print; exit}' "$lk" \
        | grep -q 'arg-validate'
    # And allow_subcommands should be non-empty.
    awk '/^  - name: "sudo"/{c=1} c && /allow_subcommands:/{print; exit}' "$lk" \
        | grep -q 'sudo'
}

@test "binary-lock-yaml: passwd gets arg-validate with allow_self_username" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    awk '/^  - name: "passwd"/{c=1} c && /policy:/{print; exit}' "$lk" \
        | grep -q 'arg-validate'
    awk '/^  - name: "passwd"/{c=1} c && /allow_self_username:/{print; exit}' "$lk" \
        | grep -q 'true'
}

@test "binary-lock-yaml: pkexec gets deny-all-non-root (exact name rule)" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    awk '/^  - name: "pkexec"/{c=1} c && /policy:/{print; exit}' "$lk" \
        | grep -q 'deny-all-non-root'
}

@test "binary-lock-yaml: mount gets deny-non-root (suid tag catch-all)" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    awk '/^  - name: "mount"/{c=1} c && /policy:/{print; exit}' "$lk" \
        | grep -q 'deny-non-root'
}

@test "binary-lock-yaml: git gets deny-all-non-root (git-bypass explicit rule)" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    # git has an explicit name rule in binary-policy-rules.yaml (git-bypass).
    awk '/^  - name: "git"/{c=1} c && /policy:/{print; exit}' "$lk" \
        | grep -q 'deny-all-non-root'
}

@test "binary-lock-yaml: live-surface binaries get non-null path" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    grep -q 'path: "/usr/bin/sudo"' "$lk"
    grep -q 'path: "/usr/bin/passwd"' "$lk"
}

@test "binary-lock-yaml: non-live-surface binaries get null path" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    # mount is in GTFOBins but not on live surface -> path: null
    awk '/^  - name: "mount"/{c=1} c && /path:/{print; exit}' "$lk" \
        | grep -q 'null'
}

@test "binary-lock-yaml: contained false when .real absent" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    awk '/^  - name: "sudo"/{c=1} c && /contained:/{print; exit}' "$lk" \
        | grep -q 'false'
}

@test "binary-lock-yaml: contained true when .real exists" {
    _setup_emit
    # Use a path under TEST_TMPDIR for the live mount binary and create
    # a .real seal alongside it. mount IS in the GTFOBins SUID HTML so
    # the universe entry exists.
    local mpath="$TEST_TMPDIR/bin/mount"
    mkdir -p "$(dirname "$mpath")"
    touch "$mpath"
    touch "${mpath}.real"
    printf '%s\n' /usr/bin/sudo "$mpath" > "$SUID_LIVE_TMP"
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    awk '/^  - name: "mount"/{c=1} c && /contained:/{print; exit}' "$lk" \
        | grep -q 'true'
}

@test "binary-lock-yaml: env_sanitise list emitted for all entries" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    # sudo should have GCONV_PATH in its env_sanitise.
    awk '/^  - name: "sudo"/{c=1} c && /env_sanitise:/{print; exit}' "$lk" \
        | grep -q 'GCONV_PATH'
    # mount should have LD_PRELOAD.
    awk '/^  - name: "mount"/{c=1} c && /env_sanitise:/{print; exit}' "$lk" \
        | grep -q 'LD_PRELOAD'
}

@test "binary-lock-yaml: allow_subcommands empty for non-arg-validate" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    # mount is deny-non-root -> allow_subcommands: []
    awk '/^  - name: "mount"/{c=1} c && /allow_subcommands:/{print; exit}' "$lk" \
        | grep -q '\[\]'
}

@test "binary-lock-yaml: tags array reflects GTFOBins contexts" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    # sudo should have both "suid" and "sudo" in tags.
    awk '/^  - name: "sudo"/{c=1} c && /tags:/{print; exit}' "$lk" \
        | grep -q 'suid'
    awk '/^  - name: "sudo"/{c=1} c && /tags:/{print; exit}' "$lk" \
        | grep -q 'sudo'
}

@test "binary-lock-yaml: reject_patterns emitted as empty list" {
    _setup_emit
    emit_binary_lock
    local lk="$FAKE_REPO/res/binary-lock.yaml"
    # Every entry should have a reject_patterns line.
    grep -q 'reject_patterns: \[\]' "$lk"
}