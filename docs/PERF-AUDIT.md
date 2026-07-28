# GUARD Performance Audit

Date: 2026-07-25
Scope: WORKSPACE-GUARD (guard wrapper, build system, scripts) and the
WORKSPACE-CI helpers the wrapper invokes. Hooks are out of scope per
operator instruction: this audit covers the wrapper and its helpers only.
Method: static review of `src/`, `build.rs`, `Makefile`, `scripts/`,
`config/`, plus the sibling CI helper libraries. Every finding cites
file:line.

---

## 1. Root cause: the per-invocation `.git/` ownership sweep

This is the single decision that made every git operation slow. It is
documented, deliberate, and wrong-shaped. The last ~20 commits widened
it (dec253e, e0d36db, 621dca7, fa0e916, ed62a19), which is exactly the
window in which the slowdown appeared.

### 1.1 What it actually does on EVERY guarded git call

`gitdir::lock(argv_os)` (src/gitdir.rs:82) is not a temp-file lock and
not a mutex. It is a recursive ownership and mode sweep:

1. Spawns `/usr/bin/git.original rev-parse --absolute-git-dir` with a
   cleared, hardened environment to find the git dir
   (src/gitdir.rs:346-370). One full git child process.
2. Recursively walks the ENTIRE `.git/` tree (src/gitdir.rs:300-321):
   every object, pack, ref, log, and index file gets `symlink_metadata`,
   and anything not already `root:root` at the right mode gets
   `chown(0,0)` + `chmod`.
3. Walks the full worktree once per filename glob pattern
   (src/gitdir.rs:186-222). `config/shared_locked_paths.yaml:66-73`
   declares 7 glob patterns (`*_exceptions.yaml`, `*_excludes.yaml`,
   `coverage_thresholds.yaml`, `file_length_limits.yaml`,
   `dead_code.yaml`, `.markdown_docs_exceptions.yaml`,
   `exemption_files.yaml`), so the worktree is walked up to 7 more
   times. Each candidate file is checked against the unseal list with a
   linear `Vec::contains` (src/gitdir.rs:203).
4. Walks the worktree again for the `.boot*` directory glob
   (src/gitdir.rs:228-255).
5. Stats and locks `.gitmodules` (src/gitdir.rs:118-124).

### 1.2 It runs TWICE per invocation

- Before the policy engine: src/main.rs:304-305.
- After `git.original` exits, in all three waitpid branches:
  src/exec.rs:255, 262, 269.

The double pass is deliberate (src/gitdir.rs:34-41): pre-exec closes
the planted-payload window, post-exec reclaims files git created.

Tally for one `git status` in a repo with F worktree files and G files
under `.git/`:

- 2 spawned `git rev-parse` processes.
- 2 full `.git/` recursive walks (2G stats, plus chown/chmod per
  drifted file).
- Up to 16 full worktree walks (2 passes x (7 glob patterns + 1 tree
  glob)), each `O(F)` with a `symlink_metadata` per entry.

`git status` itself is one process. The wrapper adds up to 18 tree
traversals around it.

### 1.3 Why it exists, and what the capability model already covers

The intended design (src/gitdir.rs:29-32, src/exec.rs:41-57):

- Policy-bearing paths stay `root:root` so the agent cannot tamper with
  them.
- The guard holds file capabilities (setpcap, chown, dac_override,
  fowner, fsetid). Just before `execve(git.original)`, the forked child
  raises `CAP_DAC_OVERRIDE` into the Ambient set
  (src/exec.rs:48-57), so the real git can write root-owned `.git/`
  files. Parent-side policy sub-calls get NO caps (deliberate,
  src/exec.rs:21-39).

So the delegation half of the model is already in place and works. The
sweep exists for one residual reason: files git CREATES (objects, refs,
index, logs) come out owned by the agent uid, because `git.original`
runs as the agent. Between two git operations the agent could therefore
edit `.git/config`, plant a hook, or rewrite refs with plain file
tools. The post-exec sweep re-chowns everything back to root to close
that window, and the pre-exec sweep re-asserts it before policy reads.

### 1.4 Why the current shape is wrong

The capability model closes the write path; the sweep exists only to
fix ownership of NEW files. But the sweep protects a threat surface of
roughly a dozen policy files by re-owning the entire repository:

- What MUST stay root-owned for enforcement: `.git/config`,
  `.git/hooks/*`, `.git/info/exclude`, `.git/info/attributes`,
  `.gitmodules`, and the exception/exemption YAML files. That is a
  small, enumerable set.
- What the sweep also chowns on every call: every loose object, every
  packfile, the index, every ref, every reflog. None of these are read
  by the guard's policy engine as trusted input in a way that requires
  root ownership to stay safe, and chowning a 2 GB pack directory buys
  nothing.

The correct observation: ambient `CAP_DAC_OVERRIDE` lets git WRITE
root-owned files, but nothing can make agent-created files root-owned
at creation time. Some reclaim step is unavoidable. The defect is that
the reclaim step is a full-tree sweep, twice per call, instead of a
narrow, targeted one.

### 1.5 Fix directions (ordered by impact per unit of risk)

A. Narrow the recursive `.git/` sweep to the security-relevant subset:
   `.git/config`, `.git/hooks/`, `.git/info/`, plus the exception file
   globs. Leave objects/packs/refs/index agent-owned. Cost per call
   drops from O(repo) to O(dozens of stats).
B. If full `.git/` ownership is judged non-negotiable (ref-spoofing
   threat), run git under a dedicated execution uid that owns `.git/`
   so new files are never agent-owned and no sweep is needed. Larger
   redesign; eliminates the sweep entirely.
C. If neither is acceptable, make the post-exec sweep incremental:
   skip files already root-owned with correct mode (the code already
   stats first, so the remaining cost is the walk itself; combine all
   glob patterns into ONE walk with a matcher set instead of one walk
   per pattern, and drop the pre-exec sweep for read-only subcommands).

Option A plus C's single-walk matcher is the recommended combination.

---

## 2. Findings register

Severity: P1 = every git call, P2 = commit/push path, P3 = build,
install, or sync path.

### P1: every git invocation

F1. Double ownership sweep per invocation. src/main.rs:304-305,
    src/exec.rs:255/262/269, src/gitdir.rs:82-136. See section 1.
    Fix: 1.5.A + single-walk matcher.

F2. Up to 8 worktree walks per sweep pass (7 file globs + 1 tree
    glob), each O(worktree). src/gitdir.rs:127-135, 186-255;
    config/shared_locked_paths.yaml:43-73. `unsealed.contains` is a
    linear scan per candidate (src/gitdir.rs:203). Fix: one walk, one
    matcher set, HashSet for unsealed paths.

F3. Two spawned `git rev-parse --absolute-git-dir` per invocation, one
    per sweep pass, with env rebuild each time. src/gitdir.rs:346-370.
    Fix: resolve once, reuse; eliminate entirely with 1.5.B.

F4. `verify_git_original` reads the ENTIRE `/usr/bin/git.original`
    binary into memory and window-scans it for a sentinel string on
    every call, including `git --version`. src/exec.rs:90-122. Fix:
    replace with build-time SHA-256 comparison (hash is 32 bytes of
    work, not a full file scan for a substring), or verify once per
    boot via the installer and keep only the cheap uid/mode stat at
    runtime.

F5. `cmd_str` eagerly allocates and joins the full argv on every call
    although it is only used on block/error paths. src/main.rs:100-105.
    Fix: build it lazily inside the error arms.

F6. Workspace-root detection repeats `Path::exists()` probes for 3
    marker files at every ancestor level, from multiple call sites.
    src/wsroot.rs:3-27; callers src/main.rs (via gitdir scope),
    src/exec.rs:290-311, src/gitdir.rs:146-150. Fix: resolve once per
    invocation, pass the result down.

F7. Agent identity file (`~/.gitconfig` / fleet identity) is
    statted, read, and parsed on every invocation.
    src/agent_identity.rs:162-179. Acceptable alone, but it stacks with
    F3/F6. Fix: single read, reuse for both the lock env and exec env.

F8. Deployment-class file read + 5 capability probes per invocation.
    src/main.rs:180-279. Cheap individually; listed for completeness.
    No change required.

### P2: commit / push path

F9. One `git hash-object` subprocess PER TRACKED FILE in CI deployment
    verification. src/ci_integrity.rs:248-293 (blob_hash_of loop),
    146-160. A 5k-file repo spawns 5k processes per commit/push. Fix:
    `git hash-object --stdin-paths` or `git cat-file --batch-check` in
    one process.

F10. `check_workspace_ci_contract` spawns the full CI quality script
    (`checks_quality.sh`) via bash on every commit/push, with a poll
    loop. src/exec.rs:278-391. Contract flow must stay; the cost lives
    in the helpers below (F12, F13).

F11. Redundant git subprocesses in block checks: `rev-parse
    --abbrev-ref HEAD` (src/block.rs:306-329), `rev-parse --verify` +
    `merge-base --is-ancestor` for revert (src/block.rs:219-253),
    `rev-parse --show-toplevel` (src/exec.rs:279-288), `git config
    --get-regexp` for remotes (src/remote.rs:33-64). Fix: resolve
    branch, toplevel, and remotes once per invocation and share.

F12. CI silent-swallow checker spawns one Python interpreter per
    tracked file. projects/CI/lib/checks_silent.sh:107-166. Fix: batch
    N files per Python invocation; keep the per-file AST semantics.

F13. CI secrets scan invokes `gitleaks` once per file via xargs -P4.
    projects/CI/lib/checks_secrets.sh:52-54. Fix: one `gitleaks dir`
    run per repo (or per top-level directory).

F14. Regex reject rules are recompiled with `regex::Regex::new` on
    every binary-guard invocation, per rule. src/binary_guard.rs:138-193.
    Fix: compile once at build time (build.rs emits a static table) or
    once at runtime via lazy statics. Per instruction: build-time
    compilation is the target.

F15. Binary policy lookup is two linear scans over 511 compiled-in
    entries, per invocation. src/binary_policy_types.rs:62-71. Fix:
    build.rs emits a sorted table + binary search, or a phf map.

F16. `build_sanitized_env` scans the strip list linearly per
    environment variable. src/binary_guard.rs:227-241. Fix: HashSet.

F17. `real_binary_path` probes multiple fixed directories with
    `exists()` per invocation. src/binary_guard.rs:206-225. Fix:
    build.rs bakes the resolved path table; runtime probe only.

F18. Config-key glob matching allocates a fresh DP matrix per pattern
    per `-c` flag. src/config_keys.rs:3-58. Fix: pre-compile patterns
    to one combined matcher at build time.

F19. Subcommand abbreviation resolution builds, sorts, and dedups a
    candidate Vec on every call. src/args.rs:24-58. Fix: static
    match/phf table.

### P3: build, install, sync, drift

F20. build.rs deserializes all YAML configs every build, including the
    ~124 KB / 511-entry binary-lock.yaml, and emits code via repeated
    `format!` in loops. build.rs:163-169, 244-254, 404-481. Fix: single
    buffered writer; parse cost is build-time only, low priority.

F21. Release profile uses `opt-level = "z"` + LTO + codegen-units=1.
    Cargo.toml:7-12. The guard runs per git call; size optimization can
    cost runtime speed. Fix: benchmark `opt-level = 3` for the wrapper
    crate; keep LTO.

F22. (HISTORICAL: `config-lock.sh` has since been deleted and replaced
by the sudo-gated `workspace-yaml-edit` binary; see SPEC-YAML-EDIT.)
`config-lock.sh` runs `lsattr | awk | grep`, `stat`, `chattr`,
    `chown`, and (on unseal verify) `sudo -u <user> test -w` PER FILE,
    in two passes (mutate then verify). scripts/config-lock.sh:54-59,
    112-139, 152-159, 177-198. Fix: one `lsattr` batch, single pass,
    one verification helper per user instead of per file.

F23. `sync-gtfobins` runs per-binary `basename`/`stat`/`sha256sum`/
    `grep -qx` loops against the GTFOBins lists (O(n*m) with process
    spawns), and `binary-lock-yaml.sh:42` greps the live SUID list once
    per capability entry. scripts/sync-gtfobins:193-302,
    scripts/lib/binary-lock-yaml.sh:42. Fix: load lists into bash
    associative arrays once.

F24. Full-filesystem scans on every drift check: `find / -xdev -perm
    -4000` and `getcap -r /`. scripts/lib/find-suid.sh:24,
    scripts/lib/decode-caps.sh:29. These are on-demand, not hot path;
    noted so they are never wired into a hook.

F25. `suid-drift-check` does quadratic awk cross-lookups between live
    and baseline cap sets. scripts/suid-drift-check:142-151, 200-220.
    Fix: associative-array join.

F26. `install-lock-runtime` runs a long serial external-command chain
    per contained binary, including up to 3 warm-exec runs of the
    freshly installed guard. scripts/install-lock-runtime:178-326.
    Fix: batch metadata collection; one warm run per binary.

F27. `make sync-gtfobins` also runs a full gitleaks scan of
    docs/references via gitleaks-ignore-regen. Makefile:355-369,
    scripts/regen-gitleaksignore:46. Fix: decouple regen from baseline
    sync or run it only when docs/references changes.

F28. Tier-1 container test rebuilds both feature sets and runs
    `chown -R target/` twice. scripts/podman/tier1-test.sh:28-55.
    Test-path only; low priority.

---

## 3. Remediation order

Status: F1-F7, F9, F11-F19 implemented (uncommitted, all tests green:
255+203 unit, 27 binary-guard unit, 236/236 bats, clippy clean on
default / root-only / binary-guard feature sets). F13 note: gitleaks multi-path batching was implemented, measured
150x SLOWER than per-file xargs (57 min user time vs 5 s for 200 files;
multi-path argv scans thrash internally), so the final form keeps one
path per process and only hardens the pipeline (NUL-safe ls-files,
temp-file list, no per-file subshell capture). F12 note: the combined
multi-file diff required grouping AddedLines per file in
check_silent_swallow.py so multiline-detector lookahead windows never
cross a file boundary; verified violation-identical against the old
per-file loop on the full WORKSPACE-CI tree.
Details of the implemented changes:

- `.git/` recursive sweep now prunes object stores (`objects/`, `lfs/`):
  the directories themselves are locked root:root 0o755 but not walked.
  All policy-bearing paths (HEAD, config, index, refs/, logs/, hooks/,
  info/, packed-refs, modules/, worktrees/) stay fully locked.
- The 7 file-glob walks + 1 tree-glob walk are collapsed into ONE
  unified worktree walk (`lock_worktree_globs`), with the unseal set
  as a HashSet.
- `rev-parse --absolute-git-dir` is resolved ONCE per invocation in
  main.rs and shared by the pre-exec and post-exec lock passes.
  Invocations without a git subcommand no longer spawn rev-parse or
  run any lock pass at all.
- `is_guard_binary` now compares device+inode against /proc/self/exe
  instead of reading the entire git.original binary into memory.

F14-F19 implementation notes:

- Structural: binary-guard codegen moved from build.rs into
  build_binary_guard.rs (build.rs was 624 lines, over the 512-line
  file-length gate; now 420 + 222).

- F14: reject regexes compile once per process via a OnceLock+Mutex
  cache keyed by the baked &'static pattern (Box::leak for a truly
  'static Regex ref; bounded by the number of baked patterns). True
  build-time compilation is impossible: regex::Regex has no const
  constructor and the crate has no build-script codegen path, so
  once-per-process is the floor without swapping the regex engine.
- F15: BINARY_POLICIES is now emitted sorted by name; find_policy is
  two binary searches (name table + new BINARY_POLICY_ALIASES index).
  build.rs panics on duplicate names or alias collisions (fail-closed
  at build). allow_subcommands stays in the table as the alias source
  but is no longer scanned at runtime.
- F16: build_sanitized_env uses a HashSet for the strip list.
- F17: real_binary_path is unchanged on the hot path -- the diverted
  layout resolves on the first candidate (`current_exe + ".real"`,
  one stat). The directory probe loop only runs when the divert
  layout is absent, and binary-lock.yaml has path: null for almost
  all entries, so there is no table to bake. Resolved by analysis.
- F18: build.rs emits DANGEROUS_/SUDO_GATED_CONFIG_KEY_SEGMENTS
  (pre-split, pre-lowercased &[&[&str]]) and rejects patterns with
  more than one `**` at build time. The matcher is now a recursive
  segment walk with zero allocation (no DP matrix, no per-call
  lowercase/split of patterns).
- F19: build.rs emits ABBREV_CANDIDATES (sorted+deduped union) and
  ABBREV_PREFERRED (sorted partial+sudo_gated). The resolver is a
  partition_point + range scan + binary_search -- no Vec build, no
  sort, no dedup per call.

F22/F23/F25 implementation notes:

- F22: (superseded -- config-lock.sh was later deleted in favor of
  workspace-yaml-edit) config-lock.sh now snapshots file state via
  collect_file_state
  (one lsattr + one stat spawn per phase instead of per-file
  lsattr|awk|grep and stat pipelines), and not_writable_by does one
  sudo/su privilege-drop spawn for the whole set. Flows unchanged;
  status output identical (verified on a fixture repo).
- F23: sync-gtfobins loads GTFOBins/konstruktoid lists into bash assoc
  arrays once (load_bin_set), batches stat and sha256sum across the
  whole SUID/caps path list (batch_stat, batch_sha256), and uses
  ${path##*/} instead of basename. binary-lock-yaml.sh tracks live
  basenames in an assoc array instead of a grep spawn per caps entry.
  The original `grep -qxP "^$bname\t"` skip probe could never match
  (whole-line -x against multi-field lines), so duplicate basenames in
  the caps list were appended, not skipped; the assoc-array version
  replicates the exact old output by only seeding the skip set from
  the SUID loop. Verified: regenerated suid-baseline.yaml,
  fcap-baseline.yaml and binary-lock.yaml are byte-identical (modulo
  the timestamp header) to the pre-change script on the same live
  surface.
- F25: suid-drift-check joins known/live file-cap sets in bash assoc
  arrays (was a per-entry awk respawn + full rescan, quadratic). The
  three drift-class temp files are sorted after the join so the report
  keeps its deterministic order. Verified: drift-report.yaml identical
  (modulo timestamps) to the pre-change script on the same surface.

F20/F21/F26/F27/F28 implementation notes:

- F20: resolved by analysis. The codegen already accumulates into one
  String buffer per generated file and does a single fs::write per
  file; the per-emit format! temporaries are build-time-only
  allocations and the audit itself ranks this low priority. No change.
- F21: release profile switched from opt-level = "z" to opt-level = 3
  (LTO kept). Measured: 321 ms vs 342 ms for 500 guard invocations
  (~6% faster per call), binary grows 505 KB -> 558 KB.
- F26: install-lock-runtime batches lock-surface metadata (one stat /
  grep -l / sha256sum / lsattr / dpkg-divert --list spawn each for the
  whole surface instead of per-binary probes) and runs ONE warm exec
  per binary, using the invocation form (--version / --help / bare) a
  one-time preflight probe of the guard binary proved works. The
  dpkg-divert test double learned the real tool's bare `--list` form
  (lists all diversions).
- F27: `make gitleaks-ignore-regen` now skips the gitleaks scan when a
  sha256 stamp of docs/references matches the last regen; the stamp
  (.gitleaksignore.refs-sha256) is per-host and gitignored. sync-gtfobins
  still invokes the regen target; it is just usually a no-op now.
- F28: tier1-test.sh's second `chown -R target/` is skipped when a
  full-tree find shows no non-testagent-owned files (early-exit on
  first match), so the chown only re-runs after a build step actually
  dirties ownership.

All 28 findings are now either implemented or resolved by analysis
(F8/F10/F17/F20/F24).

Constraints honored: no hook changes, no feature or flow removal, no
state carried between invocations (all caching is within one process
lifetime or baked at build time).
