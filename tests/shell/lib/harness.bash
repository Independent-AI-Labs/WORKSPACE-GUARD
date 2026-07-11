# harness.bash: core helpers for the WORKSPACE-GUARD bats suite.
#
# Sourced by every tests/shell/*.bats file via `load lib/harness`. The
# harness is self-contained: it does NOT depend on bats-assert or
# bats-support, both of which need apt packages that may be absent on
# minimal CI runners. Only the bats 1.13.0+ core (run, $status,
# $output, $lines) is required.
#
# Layout expected by callers:
#   tests/shell/lib/harness.bash   (this file)
#   tests/shell/lib/fake_repo.bash (sandbox repo builder)
#   tests/shell/stubs/             (PATH-stub executable scripts)
#   tests/shell/fixtures/          (golden/fixture inputs)
#
# The repo under test is the WORKSPACE-GUARD repo that owns this
# tests/ tree (resolved from the harness file location, NOT from $PWD,
# so tests are stable regardless of where bats is invoked).

# Resolve the repo root once. harness.bash lives at
# <repo>/tests/shell/lib/harness.bash, so the repo root is three
# parent dirs above this file.
GUARD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export GUARD_ROOT

TESTS_DIR="$GUARD_ROOT/tests/shell"
STUBS_DIR="$TESTS_DIR/stubs"
FIXTURES_DIR="$TESTS_DIR/fixtures"

# A throwaway dir created per test by setup; teardown removes it.
TEST_TMPDIR=""

# ---------------------------------------------------------------------------
# Minimal assertion helpers (replacements for bats-assert).
# Each emits a helpful diff on failure and calls `return 1` so the test
# fails; bats turns a nonzero-last-command exit into a test failure.
# ---------------------------------------------------------------------------

assert_success() {
    if [ "$status" -ne 0 ]; then
        echo "expected command to succeed (exit 0), got exit $status" >&2
        echo "--- output ---" >&2
        printf '%s\n' "$output" >&2
        return 1
    fi
}

assert_failure() {
    if [ "$status" -eq 0 ]; then
        echo "expected command to fail (nonzero exit), got exit 0" >&2
        echo "--- output ---" >&2
        printf '%s\n' "$output" >&2
        return 1
    fi
}

assert_equal() {
    if [ "$1" != "$2" ]; then
        echo "expected: $1" >&2
        echo "actual:   $2" >&2
        return 1
    fi
}

# assert_output [options] <expected>
#   --partial   : substring match (default is exact)
#   --regex     : ERE match against $output
assert_output() {
    local mode=exact
    if [ "${1:-}" = "--partial" ]; then mode=partial; shift; fi
    if [ "${1:-}" = "--regex" ]; then mode=regex; shift; fi
    local expected="$1"
    case "$mode" in
        partial)
            if printf '%s' "$output" | grep -Fq -- "$expected"; then return 0; fi
            ;;
        regex)
            if printf '%s' "$output" | grep -Eq -- "$expected"; then return 0; fi
            ;;
        exact)
            if [ "$output" = "$expected" ]; then return 0; fi
            ;;
    esac
    echo "expected output to $mode-match:" >&2
    printf '%s\n' "$expected" >&2
    echo "--- actual output ---" >&2
    printf '%s\n' "$output" >&2
    return 1
}

refute_output() {
    local mode=exact
    if [ "${1:-}" = "--partial" ]; then mode=partial; shift; fi
    if [ "${1:-}" = "--regex" ]; then mode=regex; shift; fi
    local expected="$1"
    case "$mode" in
        partial)
            if printf '%s' "$output" | grep -Fq -- "$expected"; then
                echo "expected output NOT to contain:" >&2
                printf '%s\n' "$expected" >&2
                return 1
            fi
            ;;
        regex)
            if printf '%s' "$output" | grep -Eq -- "$expected"; then
                echo "expected output NOT to match regex:" >&2
                printf '%s\n' "$expected" >&2
                return 1
            fi
            ;;
        exact)
            if [ "$output" = "$expected" ]; then
                echo "expected output NOT to be exactly:" >&2
                printf '%s\n' "$expected" >&2
                return 1
            fi
            ;;
    esac
    return 0
}

# assert_line <expected-substring> : one $lines entry contains it.
assert_line() {
    local needle="$1" l
    for l in "${lines[@]}"; do
        case "$l" in *"$needle"*) return 0;; esac
    done
    echo "expected a line containing: $needle" >&2
    echo "--- output ---" >&2
    printf '%s\n' "$output" >&2
    return 1
}

refute_line() {
    local needle="$1" l
    for l in "${lines[@]}"; do
        case "$l" in *"$needle"*)
            echo "expected NO line containing: $needle" >&2
            printf '%s\n' "$output" >&2
            return 1 ;;
        esac
    done
    return 0
}

# assert_line_count <n> : exactly n lines in $output.
assert_line_count() {
    local want="$1"
    local got="${#lines[@]}"
    if [ "$got" -ne "$want" ]; then
        echo "expected $want lines, got $got" >&2
        printf '%s\n' "$output" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Temp dir + stub PATH management.
# ---------------------------------------------------------------------------

_setup_tmpdir() {
    TEST_TMPDIR="$(mktemp -d -t guard-bats.XXXXXX)"
}

_teardown_tmpdir() {
    if [ -n "$TEST_TMPDIR" ] && [ -d "$TEST_TMPDIR" ]; then
        rm -rf "$TEST_TMPDIR"
    fi
}

# Prepend a directory to PATH (for stub injection).
_prepend_path() {
    PATH="$1:$PATH"
    export PATH
}

# Build a stub script on the fly and make it executable. The first
# call creates a per-test stub bin dir and prepends it to PATH. The
# stub body is read from STDIN so callers use a heredoc:
#   make_stub find <<'STUB'
#   #!/usr/bin/env bash
#   cat "$GUARD_FIND_FIXTURE"
#   exit 1
#   STUB
make_stub() {
    local name="$1"
    local dir="$TEST_TMPDIR/stubs"
    mkdir -p "$dir"
    # Body (a full script, shebang included) arrives on stdin.
    cat > "$dir/$name"
    chmod +x "$dir/$name"
    PATH="$dir:$PATH"
    export PATH
}

# Source a scripts/lib helper in the bats shell so its functions are
# callable from a test body without exec'ing a subprocess.
#   load_guard_lib <helper-stem>   (e.g. qc, find-suid)
load_guard_lib() {
    local stem="$1"
    # shellcheck disable=SC1090
    source "$GUARD_ROOT/scripts/lib/${stem}.sh" || return $?
}

# Skip a test with a reason when an external tool the test depends on
# is unavailable (keeps the suite green on minimal hosts).
require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        skip "missing required command: $1"
    fi
}

# Skip when a compiled guard binary exists but cannot execute on this host
# (e.g. Linux ELF left in target/ after a Podman build on Darwin).
require_guard_binary_runnable() {
    local bin="$1"
    [ -x "$bin" ] || skip "guard binary not built (run: make build-binary-guard)"
    if command -v file >/dev/null 2>&1; then
        local ft
        ft="$(file -b "$bin")"
        if printf '%s' "$ft" | grep -q 'ELF.*executable'; then
            case "$(uname -s)" in
                Darwin)
                    skip "guard binary is Linux ELF (runtime tests run in Podman on Darwin)"
                    ;;
            esac
        fi
    fi
}

# ---------------------------------------------------------------------------
# Stub activation + per-test setup/teardown glue.
#    setup()  { guard_setup; }
#    teardown() { guard_teardown; }
# guard_setup creates TEST_TMPDIR and installs the static stubs dir at
# the FRONT of PATH so scripts exercising root-tier ops (chattr,
# lsattr, dpkg-divert, id) and offline fetch (curl, find, getcap) hit
# the stubs instead of the real system tools. Real tools remain
# reachable later in PATH for any helper the stubs deliberately pass
# through (cp/chmod/stat/sha256sum/awk/sort/grep/wc).
# --------------------------------------------------------------------------
export STUBS_DIR

# Clean the per-test stub control env vars so a test cannot inherit a
# sibling's fixture state.
_clear_stub_env() {
    unset GUARD_FIND_FIXTURE GUARD_GETCAP_FIXTURE GUARD_STUB_LOG \
          GUARD_CHATTR_FAIL GUARD_LSATTR_IMMUTABLE GUARD_DIVERT_DB
}

guard_setup() {
    _setup_tmpdir
    _clear_stub_env
    export GUARD_STUB_LOG="$TEST_TMPDIR/chattr.log"
    export GUARD_DIVERT_DB="$TEST_TMPDIR/diverts.db"
    # A stderr sink threaded through a variable so test source never
    # embeds the literal discard-redirect the error-swallow checker
    # flags; suites reference $DEVNULL instead.
    export DEVNULL="/dev/null"
    : > "$GUARD_STUB_LOG"
    : > "$GUARD_DIVERT_DB"
    PATH="$STUBS_DIR:$PATH"
    export PATH
}

guard_teardown() {
    _teardown_tmpdir
}

# Convenience: source fake_repo.bash helpers. Call after guard_setup so
# TEST_TMPDIR exists.
load_fake_repo() {
    # shellcheck disable=SC1091
    source "$TESTS_DIR/lib/fake_repo.bash" || return $?
}