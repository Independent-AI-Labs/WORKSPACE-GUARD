#!/usr/bin/env bash
# 28-real-shell-invocation.bats: repository scripts must not execute the
# guard's backing real shell (/usr/lib/workspace-guard/sealed/bash) directly.
#
# The guard binary execs it (src/shell_guard/main.rs SEALED_BASH); the
# install/uninstall/check scripts reference the path to create, restore and
# verify the relocation; the test containers build a throwaway backing shell
# for the runtime tests. None of those execute it. Invoking it as an
# interpreter bypasses the guard entirely, so that pattern must stay absent.

load lib/harness

@test "no repository script invokes the sealed real shell via a wrapper" {
    run grep -rqE \
        '(^|[[:space:]])(exec|sudo|nohup|env|command)[[:space:]]+[^[:space:]]*sealed/bash' \
        "$GUARD_ROOT/scripts"
    [ "$status" -eq 1 ]
}