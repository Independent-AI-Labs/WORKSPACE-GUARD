# AGENTS.md - WORKSPACE-GUARD agent operating rules

## The one git flow

The commit flow is exactly one path: the pre-commit hook auto-stages
everything (`git add -A` via `check-unstaged`) and then `git commit`
runs the gates. There is NO other flow:

- No selective staging (`git add <file>`), no unstaging, no
  `git restore`/`checkout` of paths to dodge the hook, no snapshot
  dances around it.
- A dirty tree rides the next commit as-is. If that is unacceptable,
  STOP and ask the operator - never improvise a side flow.
- Session-start ritual: run `git status` in every repo you will touch
  before making changes.
- Never fight the hook. If a hook gate fails, fix the underlying
  problem and commit again.

## Never run `git stash`

`git stash` is **blocked unconditionally** by the git guard
(`config/git_guard_subcommands.yaml`, REQ-GGUARD-050). Do not attempt
it, do not work around it.

Why: stash is unlink+recreate on the worktree - byte-identical to
exemption-file tampering at the syscall level - and it deadlocks
mid-merge on root-owned `chattr +i` policy files, leaving the tree
half-applied (incident 2026-07-28).

Sanctioned alternatives:

| Need | Do this |
|------|---------|
| Baseline comparison against HEAD | `git worktree add /tmp/wt-baseline HEAD` (remove with `git worktree remove`) |
| Snapshot uncommitted changes | `git diff > /tmp/change.patch` (restore: `git apply /tmp/change.patch`) |
| Staged + unstaged snapshot | `git diff HEAD > /tmp/change.patch` |

## Never hand-edit policy YAMLs

Root-owned policy files (`config/*.yaml`, exemption manifests) are
mutated ONLY through the sudo-gated secure editor:

```bash
sudo make yaml-add    FILE=config/<file>.yaml KEY=<key> FIELDS="<spec>"
sudo make yaml-remove FILE=config/<file>.yaml KEY=<key> FIELDS="<spec>"
sudo make yaml-set    FILE=config/<file>.yaml KEY=<key> VALUE=<value>
```

Field-spec grammar (SPEC-YAML-EDIT): `name=value`, `name=[v1,v2]`,
bare `value` for scalar-list keys. The editor preserves root ownership
and `chattr +i`. Never `rm`+`cp`, `sed -i`, or redirect into a policy
file: root ownership does NOT protect a file whose parent directory is
agent-owned (unlink+recreate), so the editor gate is the only
compliant write path. If the editor rejects the change, stop and ask
the operator.

One-off root operations (renames, relocks) are prepared as scripts in
`/tmp/` and run by the operator with sudo. They are NEVER committed to
the repo and NEVER added as Makefile targets.

## Verify before declaring done

- `make test-shell` - bats suite (gated in `check-push`; must be green)
- `make lint && make check && make test` - Rust gate
- Never suppress, skip, or silence a failing check to make a run green.
