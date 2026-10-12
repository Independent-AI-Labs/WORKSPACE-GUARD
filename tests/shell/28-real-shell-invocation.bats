#!/usr/bin/env bash
# 28-real-shell-invocation.bats: repository scripts must not execute the
# guard's backing real shell (/bin/bash.real) directly.
#
# The guard binary execs it (src/shell_guard/main.rs REAL_SHELL); the
# install/uninstall/check scripts reference the path to create, restore and
# verify the relocation; the test containers build a throwaway backing shell
# for the runtime tests. None of those execute it. Invoking it as an
# interpreter bypasses the guard entirely, so that pattern must stay absent.
# The install/uninstall self-staging re-execs run through the guarded shell
# (the staged copy is trusted-tier), not through bash.real.

load lib/harness

@test "no repository script invokes /bin/bash.real via a wrapper" {
    run grep -rqE \
        '(^|[[:space:]])(exec|sudo|nohup|env|command)[[:space:]]+[^[:space:]]*bash\.real' \
        "$GUARD_ROOT/scripts"
    [ "$status" -eq 1 ]
}