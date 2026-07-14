# GAP Analysis: Hard Nuke / Block-Device Destruction

**Date:** 2026-07-14  
**Status:** DRAFT  
**Type:** Gap analysis / threat assessment  
**Scope:** WORKSPACE-GUARD deployment on agent dev hosts (`vm-ws`, `host-exec` class)  
**Trigger:** Agent build process wrote directly to `/dev/sda`, destroying the host OS  

**Related documents:**

| Document | Role |
|----------|------|
| [RESEARCH.md](../RESEARCH.md) | SUID/CVE threat model; agent sandbox consensus |
| [RESEARCH-SYSTEM-BINARIES.md](RESEARCH-SYSTEM-BINARIES.md) | Four-layer program design; CVE→mitigation matrix |
| [REQ-SANDBOX.md](requirements/REQ-SANDBOX.md) | Program II requirements |
| [REQ-HOME-LOCK.md](requirements/REQ-HOME-LOCK.md) | Documented `~/.gitconfig` bypass incident |
| [PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md](PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md) | `host-exec` vs `sandbox-service` install rules |
| [docs/references/SOURCES.md](references/SOURCES.md) | Cached industry sources |

---

## 1. Executive summary

**`/dev/sda` and block-device destruction are not protected by the default WORKSPACE-GUARD deployment.**

Program I (Git Guard) intercepts only `/usr/bin/git`. A build script, shell command, or compiled binary that opens `/dev/sda`, `/dev/nvme0n1`, or runs `dd of=/dev/...` never passes through the guard. There is no block-device deny policy in guard source, YAML config, or install scripts.

The four-layer design in [RESEARCH-SYSTEM-BINARIES.md](RESEARCH-SYSTEM-BINARIES.md) **was written to address exactly this class of host harm** ,  but only when all layers are installed and agents run inside the sandbox stack. On `vm-ws` Grok/IDE shells:

- **Program I** is installed (`host-exec`, file caps on `/usr/bin/git`).
- **Programs II-A, II-B, III** are optional and **not deployed** on this host.
- **`workspace-sandbox-launcher` is spec-only** ,  not implemented in the repo.

The `/dev/sda` incident is therefore **outside Program I's threat model** ([REQUIREMENTS.md](../REQUIREMENTS.md) §Non-Requirements: no namespace isolation, no MAC) and **inside the residual risk** that Programs II-III were designed to close but have not been rolled out.

---

## 2. Incident reconstruction

### 2.1 Attack class

| Vector | Example | Hits guard? |
|--------|---------|-------------|
| Build recipe / Makefile | `dd if=image.img of=/dev/sda bs=4M` | No |
| Package build script | `mkfs.ext4 /dev/sda1` | No |
| Interpreted write | `interpreted runtime -c 'open("/dev/sda","wb").write(b"x")'` | No |
| Flash / imaging tool | `balena-cli`, `etcher`, custom Rust `ioctl` | No |
| Privilege-assisted | `sudo dd ...` after SUID/sudo escalation | No (until `install-lock`) |

Git Guard does not parse `make`, `cargo`, `bash`, or child processes of those tools. Only invocations of `/usr/bin/git` are policy-checked.

### 2.2 OS permissions (incidental, not guard)

On `vm-ws` at time of writing:

```
brw-rw---- 1 root disk  8, 0  /dev/sda
brw-rw---- 1 root disk 259, 0  /dev/nvme0n1
```

Block nodes are `root:disk` mode `660`. User `agent` is **not** in group `disk`, so a **direct** non-root write returns `EACCES` without guard involvement.

**However**, `agent` is in group **`sudo`**. Any `sudo`-allowed command (including `dd`, `mkfs`, or a build script run under `sudo`) bypasses the permission gate entirely. The incident VM may also have run the agent as root, granted passwordless sudo for build steps, or placed the agent in `disk` group ,  none of which Git Guard addresses.

### 2.3 What Git Guard would have blocked

If the agent had tried to destroy work **via git** (`git reset --hard`, `git push --force`, hook bypass env vars, dangerous `-c` keys), Program I would have blocked it. The incident used the **unguarded shell/build path**, not git.

---

## 3. Deployment model (end-to-end)

```mermaid
flowchart TB
  subgraph agentShell [Agent IDE shell - vm-ws host-exec]
    bash[bash / make / cargo]
    git[/usr/bin/git]
    dd[/usr/bin/dd / mkfs / interpreted]
  end

  git --> wg[workspace-guard]
  wg --> gorig[git.original]

  bash --> kernel[Host kernel]
  dd --> blockdev[/dev/sda /dev/nvme*]
  blockdev --> kernel

  subgraph optional [Optional - NOT on vm-ws]
    lock[Program II-A install-lock]
    sandbox[Program II-B workspace-agent@]
    home[Program III install-home-lock]
  end

  lock -.->|would wrap SUID| su[/usr/bin/su sudo mount]
  sandbox -.->|PrivateDevices + seccomp| bash
```

### 3.1 Live state on `vm-ws` (2026-07-14)

| Check | Result |
|-------|--------|
| Host profile | `vm-ws` → `host-exec` ([config/guard-host-profiles.yaml](../config/guard-host-profiles.yaml)) |
| Deployment class file | `/usr/lib/workspace-guard/deployment-class` = `host-exec` |
| Git Guard | `/usr/bin/git` = guard; `/usr/bin/git.original` mode `0700`; file caps present |
| Binary lock | `res/suid-baseline.yaml`: all 8 SUID binaries `contained: false`; no widespread `*.real` wrappers |
| Sandbox unit | `workspace-agent@rootless` inactive; launcher binary absent |
| Home lock | Not verified installed |
| Agent `sudo` membership | **Yes** ,  `agent` in group `sudo` |

### 3.2 Install stack (documented vs actual)

**Documented mandatory stack** ([README.md](../README.md), [PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md](PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md) §5):

```bash
make build-guard
sudo make install-guard-host-exec   # mandatory
sudo make install-lock              # optional
sudo make install-home-lock         # optional
sudo make install-auditd            # optional
# install-sandbox FORBIDDEN on Grok/IDE shells
```

**Gap:** Only step 1-2 are treated as mandatory. Steps 3-5 are explicitly optional. The reconciliation plan even notes `install-lock` as optional post-git.

---

## 4. Protection matrix by program layer

| Layer | Install | Active on `vm-ws` IDE shells? | Blocks `/dev/sda` / OS wipe? | Blocks git abuse? |
|-------|---------|-------------------------------|------------------------------|-------------------|
| **I ,  Git Guard** | `install-guard-host-exec` | Yes | **No** | **Yes** |
| **II-A ,  Binary lock** | `install-lock` | No (`contained: false`) | **No** for `dd`/`mkfs` (not wrapped) | N/A |
| **II-B ,  Sandbox** | `install-sandbox` | Forbidden on IDE shells; launcher missing | **Would** via `PrivateDevices` + `@raw-io` | N/A |
| **II-C ,  Audit** | `install-auditd` | Unknown / likely no | Detection only; no `/dev/*` rules | Partial |
| **III ,  Home lock** | `install-home-lock` | Unknown / likely no | **No** | Partial (`~/.gitconfig`) |

### 4.1 Program I ,  what it covers

Source: [src/block.rs](../src/block.rs), [config/guard_subcommands.yaml](../config/guard_subcommands.yaml), [config/guard_environment.yaml](../config/guard_environment.yaml).

- Destructive git subcommands and plumbing bypasses
- Global flags (`--no-verify`, force push, etc.)
- 96 dangerous `-c` / config keys
- Hook-bypass env vars (`SKIP`, `PRE_COMMIT_ALLOW_NO_CONFIG`)
- `.git/` tree lock (capability-mode only; skipped in root-only CI)

Explicitly **does not** cover: shell, build tools, block devices, network, non-git binaries.

### 4.2 Program II-A ,  disk utilities gap

[res/binary-lock.yaml](../res/binary-lock.yaml) catalog entry for `dd`:

```yaml
- name: "dd"
  path: null          # NOT diverted on host
  contained: false
  policy: deny-non-root
  reject_patterns: [] # no of=/dev/ blocking
```

**Absent from catalog entirely:** `mkfs.*`, `wipefs`, `fdisk`, `parted`, `losetup`, `blockdev`, `cryptsetup`, `hdparm`.

Even if `install-lock` ran, it only wraps **SUID/CAP binaries on the lock surface** ([REQ-SANDBOX.md](requirements/REQ-SANDBOX.md) REQ-LCK-001). `dd` and `mkfs` are normal mode `755` binaries ,  they would remain unwrapped unless explicitly added to a **non-SUID wrap policy** (not implemented).

### 4.3 Program II-B ,  designed mitigations (unshipped)

[config/systemd/workspace-agent@.service](../config/systemd/workspace-agent@.service):

| Control | Block-device relevance |
|---------|------------------------|
| `PrivateDevices=yes` | Hides real block device nodes from unit processes |
| `SystemCallFilter=~@raw-io` | Blocks raw block I/O ioctl syscall class |
| `SystemCallFilter=~@mount` | Blocks overlayfs LPE (CVE-2023-0386) |
| `RestrictAddressFamilies=...` | Blocks `AF_ALG` (Copy Fail CVE-2026-31431) |
| `NoNewPrivileges=yes` | Blocks SUID re-escalation inside unit |

[SPEC-SANDBOX.md](specifications/SPEC-SANDBOX.md) §3.4 Landlock: deny-by-default; `/dev` not in allow-list → block device paths denied for rootless profile workloads.

**Deployment blockers:**

1. `workspace-sandbox-launcher` referenced at line 64 of the unit ,  **zero implementation files in repo**.
2. [PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md](PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md): **do not** `install-sandbox` on Grok/IDE shells.
3. IDE agents do not run as `workspace-agent@` service processes.

### 4.4 Program II-C ,  audit gaps

[config/auditd/99-workspace-guard.rules](../config/auditd/99-workspace-guard.rules) logs:

- `setxattr` / `capset` (tamper)
- `socket(AF_ALG)` (Copy Fail)
- `mount`, `pivot_root` (overlay escape)
- `open_by_handle_at` (Shocker)

**Missing:** `open`/`write` watches on `/dev/sd*`, `/dev/nvme*`, `/dev/mmcblk*`. Audit is detection-only in any case.

---

## 5. End-to-end GAP inventory

Gaps are numbered for traceability. Severity: **C** = critical (OS destruction or root), **H** = high, **M** = medium.

### 5.1 CRITICAL ,  direct destruction (incident class)

| ID | Gap | Evidence | Guard layer that should close it |
|----|-----|----------|----------------------------------|
| **GAP-C01** | Unguarded shell/build tools (`make`, `cargo`, `bash`, `interpreted runtime`, `node`) can write block devices or invoke disk utilities | [REQUIREMENTS.md](../REQUIREMENTS.md) §Non-Requirements; no wrap targets in Makefile/README | II-B sandbox (Landlock + `PrivateDevices`) |
| **GAP-C02** | No `/dev/sd*`, `/dev/nvme*`, `of=/dev/` policy anywhere in guard config or Rust | Grep: zero matches in `src/`, `config/` | II-B or new path-policy layer |
| **GAP-C03** | `dd` catalog-only; `path: null`, `reject_patterns: []` | [res/binary-lock.yaml](../res/binary-lock.yaml) | II-A extension + arg-validate |
| **GAP-C04** | `mkfs`, `wipefs`, `parted`, `fdisk`, `losetup`, `blockdev` not in policy catalog | [res/binary-lock.yaml](../res/binary-lock.yaml) grep | II-A extension |
| **GAP-C05** | IDE shells = full host user; no seccomp/Landlock/namespace on agent process tree | [README.md](../README.md) Role in framework | II-B applied to IDE entry |
| **GAP-C06** | Agent in `sudo` group on `vm-ws` ,  any allowed sudo command can wipe disk | Live: `groups agent` includes `sudo` | **Mitigation:** [SPEC-HOST-PROVISION](specifications/SPEC-HOST-PROVISION.md) break-glass `admin` + RED audit; fleet sudo retained (audit-only); II-A `sudo` lock still recommended |

### 5.2 CRITICAL ,  privilege escalation → disk access

| ID | Gap | Evidence | Layer |
|----|-----|----------|-------|
| **GAP-C07** | Binary lock not installed; 8 SUID binaries `contained: false` | [res/suid-baseline.yaml](../res/suid-baseline.yaml) | II-A |
| **GAP-C08** | `mount`/`umount`/`su`/`passwd` directly invokable | Same baseline | II-A |
| **GAP-C09** | Copy Fail (`AF_ALG`) unblocked in IDE shells | [RESEARCH.md](../RESEARCH.md) §3.4-3.5; seccomp only in sandbox unit | II-B seccomp + kernel patch |
| **GAP-C10** | Root / root-only CI: `git.original` directly executable; full block-device access | [ROOT-ONLY-MODE.md](ROOT-ONLY-MODE.md) | Host policy |
| **GAP-C11** | Kernel LPE generally out of scope | [SPEC-GIT-GUARD-IMPL.md](specifications/SPEC-GIT-GUARD-IMPL.md) §9.2 | Kernel patch + II-B tier |

### 5.3 HIGH ,  git-guard bypass → secondary harm

| ID | Gap | Evidence | Layer |
|----|-----|----------|-------|
| **GAP-H01** | libgit2 / GitPython / raw `.git/objects` ,  no runtime intercept | [REQUIREMENTS.md](../REQUIREMENTS.md) line 125 | Out of scope; detect at install |
| **GAP-H02** | Alternate git binaries (`~/bin`, nix, compiled git) | [SPEC-GIT-GUARD-HARDENING.md](specifications/SPEC-GIT-GUARD-HARDENING.md) §11; install warns only | Install hardening |
| **GAP-H03** | `~/.gitconfig` direct write without home-lock (documented CI incident) | [REQ-HOME-LOCK.md](requirements/REQ-HOME-LOCK.md) Background | III |
| **GAP-H04** | `~/.bashrc` / `~/.profile` never locked ,  PATH/alias persistence | [REQ-HOME-LOCK.md](requirements/REQ-HOME-LOCK.md) REQ-HL-NG-02 | III extension or host |
| **GAP-H05** | Child `PATH` includes `/usr/local/bin` for git subprocesses | [config/guard_paths.yaml](../config/guard_paths.yaml) | I (subprocess scope only) |
| **GAP-H06** | Transient `CAP_DAC_OVERRIDE` on host-exec git invocation | [src/main.rs](../src/main.rs), [src/exec.rs](../src/exec.rs) | I design tradeoff |

### 5.4 MEDIUM ,  operational / deployment

| ID | Gap | Evidence |
|----|-----|----------|
| **GAP-M01** | `workspace-sandbox-launcher` not implemented | [SPEC-SANDBOX.md](specifications/SPEC-SANDBOX.md); glob finds 0 files |
| **GAP-M02** | `install-lock` / `install-home-lock` optional, not in default vm-ws stack | [PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md](PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md) |
| **GAP-M03** | auditd has no block-device write rules | [config/auditd/99-workspace-guard.rules](../config/auditd/99-workspace-guard.rules) |
| **GAP-M04** | `chattr +i` best-effort at install | [SPEC-GIT-GUARD-HARDENING.md](specifications/SPEC-GIT-GUARD-HARDENING.md) |
| **GAP-M05** | Network exfil / remote destructive pulls out of scope | [REQUIREMENTS.md](../REQUIREMENTS.md) |
| **GAP-M06** | Contract check fail-open on timeout | [src/exec.rs](../src/exec.rs) |

---

## 6. Cross-reference: in-repo research vs gaps

### 6.1 Four-layer program intent

[RESEARCH-SYSTEM-BINARIES.md](RESEARCH-SYSTEM-BINARIES.md) §1 states the program goal:

> generalises [the git guard] pattern … so that an AI agent running on the box **cannot escalate to root, cannot read `/etc/shadow`, cannot read `~/.ssh/id_rsa`, and cannot persist**.

Block-device destruction is not named explicitly, but it falls under **host compromise cost** addressed by sandbox tier selection (§4):

| Tier | Kernel exposure | Best for |
|------|-----------------|----------|
| Rootless (Landlock + seccomp + ns) | shared | AI agent host code |
| gVisor | Sentry only | untrusted LLM shell commands |
| Firecracker | separate guest kernel | catastrophic host compromise cost |

**Gap:** The research defines the right tiers; **deployment stops at Program I** on IDE hosts.

### 6.2 CVE→mitigation matrix (unsupported cells = our gaps)

From [RESEARCH-SYSTEM-BINARIES.md](RESEARCH-SYSTEM-BINARIES.md) §5:

| Layer | Copy Fail | Shocker | overlayfs | Block-device write |
|-------|-----------|---------|-----------|-------------------|
| Binary lock | N | N | N | **N** |
| Cap throttle | partial | Y | Y | **N** |
| Sandbox seccomp | Y | Y | Y | **partial** (`@raw-io`) |
| Sandbox Landlock | N | Y | N | **Y** (deny `/dev`) |
| Kernel patch | Y | N | N | N |

**Interpretation:** Block-device wipe is **not** in the binary-lock threat model. Landlock deny-by-default (sandbox) is the designed prevention layer. That layer is **unimplemented + undeployed** on `vm-ws`.

### 6.3 Agent sandbox consensus

[RESEARCH.md](../RESEARCH.md) §5.1-5.4:

> standard Docker/runc isolation is **insufficient** for untrusted code execution  
> **Consensus:** Default to Firecracker/Kata for untrusted code; gVisor for compute-heavy workloads

Gemini CLI (Mar 2026) and Agent Sandbox SIG are cited as industry movement toward **per-command sandboxing**, not single-binary git wrapping.

**WORKSPACE-GUARD today:** git-only wrap on host-exec = **below** the research consensus for untrusted agent code execution.

### 6.4 Documented non-git incident (parallel class)

[REQ-HOME-LOCK.md](requirements/REQ-HOME-LOCK.md): rootless agent wrote `~/.gitconfig` via editor subprocess ,  bypassed git intercept. Response: Program III.

The `/dev/sda` incident is the **same structural failure**: agent used an **unguarded execution path** (build/shell, not `git`) to cause host-wide harm. Program III does not help; Program II-B would.

### 6.5 Defense-in-depth status table

From [RESEARCH.md](../RESEARCH.md) §6:

| Measure | Status in repo/deploy |
|---------|----------------------|
| Git guard + env scrub + blocks | **Done** |
| `chattr +i` + `dpkg-divert` on git | **Done** |
| gVisor/Firecracker for agent workloads | **Manual / not deployed** |
| seccomp block AF_ALG in agent workloads | **Spec only** (systemd unit) |
| auditd splice + SUID correlation | **Partial** (no block dev) |
| Falco AF_ALG rule | **Manual** |

---

## 7. Cross-reference: industry hardening patterns

Sources are cached in [docs/references/](references/SOURCES.md) (offline-verifiable).

### 7.1 CIS / konstruktoid ,  minimize SUID surface

| Practice | Source | WORKSPACE-GUARD alignment | Gap |
|----------|--------|---------------------------|-----|
| Audit all SUID binaries; remove unnecessary setuid | [cis-dil-benchmark-suid-rb.html](references/cis-dil-benchmark-suid-rb.html), [konstruktoid-suid-list.txt](references/konstruktoid-suid-list.txt) | `sync-gtfobins` + baseline | **install-lock not run** ,  8 SUID bins exposed |
| GTFOBins-aware containment | [gtfobins-suid.html](references/gtfobins-suid.html) | `config/binary-policy-rules.yaml` | Policies exist; **not enforced on host** |

### 7.2 Capability hardening ,  least privilege per service

| Practice | Source | Alignment | Gap |
|----------|--------|-----------|-----|
| `CapabilityBoundingSet=` drop all then add minimum | [systemshardening-cap-hardening.html](references/systemshardening-cap-hardening.html) | `workspace-agent@.service` bounding set | Unit not used for IDE agents |
| Never grant `CAP_DAC_READ_SEARCH` to interpreters | [yunolay-caps-abuse.html](references/yunolay-caps-abuse.html) | SPEC-CAP-THROTTLE | Agent shells unrestricted |
| `SecureBits=noroot-locked` on agent parent | systemshardening cap article | Not applied to IDE session | GAP-C06 sudo |

### 7.3 Sandlock / rootless sandbox ,  deny-by-default filesystem

| Practice | Source | Alignment | Gap |
|----------|--------|-----------|-----|
| Landlock compile-time policy; supervisor for runtime | [sandlock-arxiv.html](references/sandlock-arxiv.html) | SPEC-SANDBOX §3.4 Landlock table | **Launcher not built** |
| Block syscalls + virtualize effects | Sandlock paper | seccomp list in SPEC-SANDBOX §3.3 | Not applied to IDE shells |
| Separate static policy from runtime decisions | Sandlock split | Git guard = static policy for git only | No policy for `/dev` |

### 7.4 Immutable root / verified boot ,  catastrophic wipe recovery

| Practice | Source | Alignment | Gap |
|----------|--------|-----------|-----|
| dm-verity read-only root | [systemshardening-dm-verity.html](references/systemshardening-dm-verity.html) | Referenced in research | **Not deployed**; would not prevent wipe but limits persistence |
| `chattr +i` on critical binaries | [systemshardening-chattr.html](references/systemshardening-chattr.html) | Git guard install | Best-effort; does not block `dd` |

### 7.5 AI agent sandboxing consensus (2025-2026)

| Practice | Source (RESEARCH.md §5, §7) | WORKSPACE-GUARD | Gap |
|----------|----------------------------|-----------------|-----|
| MicroVM (Firecracker/Kata) for untrusted agents | Zylos Research, Agent Sandbox SIG | Tier listed in SPEC-SANDBOX | Not offered to IDE path |
| gVisor for syscall interception | gVisor MAGI, Gemini CLI PR | Tier listed | Not deployed |
| Per-command sandbox, not repo-tool-only wrap | Gemini CLI, Sandlock | Git-only on host-exec | **GAP-C01, GAP-C05** |
| seccomp `AF_ALG` block | Copy Fail mitigations | In systemd unit only | IDE shells exposed (**GAP-C09**) |

### 7.6 Industry vs WORKSPACE-GUARD positioning

| Industry expectation | WORKSPACE-GUARD default deploy |
|---------------------|-------------------------------|
| Untrusted code runs in sandbox with no block-device access | Only `git` is wrapped |
| SUID surface contained or removed | Optional `install-lock`; baseline `contained: false` |
| Agent UID cannot sudo | `agent` in `sudo` on `vm-ws` |
| Defense in depth: MAC + sandbox + audit | Git policy + optional layers |

---

## 8. Attack path analysis (end-to-end)

### Path A ,  Direct build wipe (incident class)

```
Agent (IDE shell)
  → make / cargo build / custom script
    → dd of=/dev/sda  OR  open("/dev/sda","wb")
      → [no guard]
        → kernel block layer
          → OS destroyed
```

**Guards encountered:** none.

### Path B ,  sudo-assisted wipe

```
Agent
  → sudo make install  (or passwordless sudo rule)
    → dd of=/dev/sda as root
      → [no guard; II-A not installed]
        → success
```

**Guards encountered:** none. **Host misconfig:** `agent` ∈ `sudo`.

### Path C ,  SUID escalate then wipe

```
Agent
  → /usr/bin/su / /usr/bin/sudo (unwrapped)
    → root shell
      → dd of=/dev/sda
```

**Guards encountered:** none until `install-lock`. Copy Fail path: corrupt unwrapped SUID via `AF_ALG` → root → wipe.

### Path D ,  sandboxed agent (designed, not deployed)

```
Agent
  → workspace-sandbox-launcher --profile rootless -- make ...
    → Landlock: /dev denied
    → PrivateDevices: no block nodes
    → seccomp @raw-io: ioctl blocked
      → dd fails with EPERM/EACCES
```

**Guards encountered:** full II-B stack. **Status:** not available.

### Path E ,  git-only destruction (protected)

```
Agent
  → git reset --hard / git push -f
    → workspace-guard
      → BLOCK
```

**Guards encountered:** Program I. **Not the incident class.**

---

## 9. Coverage matrix (default deploy)

| Attack | Protected today on `vm-ws`? |
|--------|----------------------------|
| `dd of=/dev/sda` via build/shell | **No** |
| `mkfs` / `wipefs` on block devices | **No** |
| Raw `open("/dev/nvme0n1","wb")` | **No** (EACCES without root/disk; not guard) |
| `sudo dd ...` (agent in sudo group) | **No** |
| `git reset --hard` via `/usr/bin/git` | **Yes** |
| Hook bypass env on guarded git | **Yes** |
| Dangerous `git -c` keys | **Yes** |
| `~/.gitconfig` direct write | **No** (unless home-lock) |
| SUID / sudo escalation | **No** (until install-lock) |
| Agent in Landlock + PrivateDevices | **No** |

---

## 10. Recommended remediation (prioritized)

Ordered by impact on `/dev/sda` incident class vs implementation cost.

### Tier 0 ,  Host provisioning (automated in guard repo)

Run once per agent VM (see [SPEC-HOST-PROVISION](specifications/SPEC-HOST-PROVISION.md)):

```bash
cp config/host-provision.yaml.example config/host-provision.yaml
cp config/home-lock-users.yaml.example config/home-lock-users.yaml
sudo make install-host-stack
```

This creates a break-glass `admin` account (random password printed once),
requires that password before fleet account setup, provisions git/SSH
identities, and installs the guard stack. **Mitigates GAP-C06** when
`user_management.enabled: true` (audit-only fleet sudo; break-glass admin).

Additional host policy (manual / image build):

- Ensure agents are not in group `disk`.
- Ensure agents never run builds as root.
- Patch kernel for Copy Fail (≥ 6.19.12 / 6.18.22 per [RESEARCH.md](../RESEARCH.md)).

### Tier A ,  Contain all agent processes (closes GAP-C01, C02, C05)

1. **Implement** `workspace-sandbox-launcher` per [SPEC-SANDBOX.md](specifications/SPEC-SANDBOX.md).
2. **Route IDE agent commands** through `workspace-sandbox-launcher --profile rootless --` (architectural change).
3. Landlock deny `/dev/*`; rely on `PrivateDevices` equivalent in launcher.

*Aligns with:* Sandlock deny-by-default, RESEARCH.md §5 consensus, Gemini/gVisor industry direction.

### Tier B ,  Extend disk-utility policy (partial; GAP-C03, C04)

- Add non-SUID wrap or centralized `exec` interceptor for `dd`, `mkfs*`, `wipefs`, `parted`, `fdisk` with `reject_patterns` for `/dev/sd*`, `/dev/nvme*`, `of=/dev/`.
- **Limitation:** does not stop `interpreted open()` or static binaries.

*Aligns with:* GTFOBins arg-awareness; does not match Sandlock completeness.

### Tier C ,  Mandatory optional programs on `vm-ws` (GAP-C07, H03)

Included in `sudo make install-host-stack` when `guard_stack.install_lock` and
`guard_stack.install_auditd` are true in `config/host-provision.yaml` (defaults).

Standalone (if not using full stack):

```bash
sudo make install-lock
sudo make install-home-lock
sudo make install-auditd
```

Update [PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md](PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md) to make these **required** for `vm-ws`, not optional.

*Aligns with:* CIS SUID audit, REQ-HOME-LOCK incident response.

### Tier D ,  Detection (GAP-M03)

- auditd rules: `open`/`write` on `/dev/sd*`, `/dev/nvme*`.
- Falco: `AF_ALG` socket from agent UID.

*Aligns with:* RESEARCH.md §6 monitoring row; Elastic cap-escalation telemetry patterns.

### Tier E ,  Host integrity (long-term)

- dm-verity / read-only root ([systemshardening-dm-verity.html](references/systemshardening-dm-verity.html)).
- AppArmor/SELinux profile: deny `block` class for agent UID ([REQUIREMENTS.md](../REQUIREMENTS.md) notes MAC as separate).

---

## 11. Known residual risks (accepted until closed)

From [RESEARCH-SYSTEM-BINARIES.md](RESEARCH-SYSTEM-BINARIES.md) §5 "unsupported cells" and this analysis:

1. **Block-device write via unguarded process** ,  no layer deployed.
2. **Copy Fail against unwrapped SUID** ,  kernel patch + seccomp not on IDE path.
3. **Root adversary** ,  documented unmitigated ([SPEC-GIT-GUARD-IMPL.md](specifications/SPEC-GIT-GUARD-IMPL.md) §9.2).
4. **Library git bypass** ,  explicit non-requirement.
5. **Network-level destruction/exfil** ,  out of scope.

---

## 12. Conclusion

WORKSPACE-GUARD **correctly protects git abuse** on `vm-ws` but **does not protect the host from agent build/shell actions**, including the `/dev/sda` wipe incident class. The research and specifications **already identify** the required layers (sandbox Landlock, `PrivateDevices`, seccomp, binary lock, home lock); the gap is **deployment and implementation**, not threat-model ignorance.

**Single sentence:** *Program I is doing its job; Programs II and III were designed to stop exactly this class of harm and are not live on the agent path that ran the build.*

---

## Appendix A ,  File index

| Topic | Path |
|-------|------|
| Git blocks | [src/block.rs](../src/block.rs), [config/guard_subcommands.yaml](../config/guard_subcommands.yaml) |
| Binary catalog | [res/binary-lock.yaml](../res/binary-lock.yaml), [config/binary-policy-rules.yaml](../config/binary-policy-rules.yaml) |
| SUID baseline | [res/suid-baseline.yaml](../res/suid-baseline.yaml) |
| Sandbox unit | [config/systemd/workspace-agent@.service](../config/systemd/workspace-agent@.service) |
| Sandbox spec | [docs/specifications/SPEC-SANDBOX.md](specifications/SPEC-SANDBOX.md) |
| Audit rules | [config/auditd/99-workspace-guard.rules](../config/auditd/99-workspace-guard.rules) |
| Deploy plan | [docs/PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md](PLAN-GUARD-DEPLOYMENT-RECONCILIATION.md) |
| Industry sources | [docs/references/SOURCES.md](references/SOURCES.md) |

## Appendix B ,  Verification commands

```bash
# Deployment class
cat /usr/lib/workspace-guard/deployment-class

# Git guard
ls -la /usr/bin/git /usr/bin/git.original
getcap /usr/bin/git

# Binary lock surface
grep 'contained:' res/suid-baseline.yaml

# Agent privilege context
id
groups
ls -l /dev/sda /dev/nvme0n1

# Sandbox
systemctl status 'workspace-agent@*'
test -x /usr/local/bin/workspace-sandbox-launcher && echo launcher-present || echo launcher-missing
```