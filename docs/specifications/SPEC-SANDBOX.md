# Specification: Sandbox Stack (Per-Workload Profile Picker)

**Date:** 2026-07-08
**Status:** DRAFT
**Type:** Specification
**Requirements:** [REQ-SANDBOX](../requirements/REQ-SANDBOX.md)
**Threat Model:** [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md)

---

## 1. Architecture Overview

```
  User invokes:
    workspace-sandbox-launcher --profile <name> -- <command> [args...]
                         |
                         v
               Read config/sandbox/profiles.yaml
                         |
         +---------------+---------------+
         |               |               |
         v               v               v
    rootless         gvisor         firecracker
    (Landlock +      (runsc          (microVM,
     seccomp +       Sentry            KVM, guest
     namespaces +    intercepts       kernel)
     cgroups)        syscalls)
         |               |               |
         v               v               v
    PR_SET_NO_NEW_PRIVS  --no-new-privs  (guest kernel
    seccomp BPF filter   on runsc         enforces)
    Landlock rules
    user+mount+net ns
    cgroup limits
         |
         v
    execve(command)
    (inside the sandbox)
```

The sandbox launcher picks an isolation tier per workload. The three tiers
are listed in [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md)
section 4. The user selects via `--profile`; there is no default profile.

---

## 2. Profile Selection

### 2.1 Command-line interface

```
Usage: workspace-sandbox-launcher --profile <name> -- <command> [args...]
       workspace-sandbox-launcher --profile auto -- <command> [args...]

Profiles:
  rootless     Landlock + seccomp + namespaces + cgroups (~5ms cold start)
  gvisor       gVisor runsc Sentry (~200ms cold start, no host kernel syscall)
  firecracker  Firecracker microVM with separate guest kernel (~125ms cold start)
```

### 2.2 Auto-selection (--profile auto)

If `--profile auto` is passed, the launcher reads
`config/sandbox/profiles.yaml` and matches the current hostname:

```yaml
# config/sandbox/profiles.yaml
# Maps hostname patterns to sandbox profiles.
# First match wins.

profiles:
  - pattern: ".*-agent"
    profile: rootless

  - pattern: ".*-untrusted"
    profile: gvisor

  - pattern: ".*-critical"
    profile: firecracker

  - pattern: ".*"
    profile: rootless    # catch-all default for auto mode
```

If no pattern matches, the launcher exits 2 with an error. The user must
pass an explicit `--profile` for hosts that do not match any pattern.

---

## 3. Rootless Profile (Landlock + seccomp + namespaces)

### 3.1 Startup sequence

```
1. fork()
2. Child: unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID)
3. Child: set PR_SET_NO_NEW_PRIVS
4. Child: install seccomp-bpf filter (section 3.3)
5. Child: apply Landlock rules (section 3.4)
6. Child: set cgroup limits (section 3.5)
7. Child: set rlimits (section 3.6)
8. Child: execve(command)
9. Parent: waitpid() and report exit code
```

### 3.2 Namespace setup

- **User namespace**: new user namespace. The child maps its UID to 0 inside
  the namespace but has no host privileges. This is the isolation boundary.
- **Mount namespace**: new mount namespace with a private root. `/proc` is
  mounted fresh. Host filesystem is not visible unless explicitly bind-mounted.
- **Network namespace**: new network namespace with loopback only. No
  external interfaces unless `--net-host` is passed.
- **PID namespace**: new PID namespace. The child is PID 1.

### 3.3 Seccomp-bpf filter

The seccomp filter uses `SCMP_ACT_ERRNO(EPERM)` for blocked syscalls. The
filter is applied after `PR_SET_NO_NEW_PRIVS` so SUID binaries inside the
sandbox cannot re-escalate.

Blocked syscalls:

| Syscall | Blocked because |
|---------|----------------|
| `open_by_handle_at` | Shocker CVE-2014-0038 |
| `mount`, `mount_setattr`, `umount2`, `pivot_root`, `move_mount`, `open_tree` | overlayfs CVE-2023-0386, mount injection |
| `ptrace`, `process_vm_readv`, `process_vm_writev` | Process inspection/injection |
| `bpf`, `perf_event_open`, `fanotify_init`, `userfaultfd` | Kernel observability / write primitives |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | io_uring attack surface |
| `personality` | Personality flags can disable ASLR |
| `kexec_load`, `kexec_file_load` | Kernel replacement |
| `init_module`, `finit_module`, `delete_module`, `create_module` | Kernel modules |
| `settimeofday`, `clock_settime` | Time manipulation |

**AF_ALG socket block** (Copy Fail CVE-2026-31431):

The `socket` syscall is filtered with an argument check: if `domain ==
AF_ALG` (38), return `EPERM`. This is implemented as a seccomp argument
filter:

```c
SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket),
  SCMP_A0(SCMP_CMP_EQ, AF_ALG)
```

All other `socket()` domains are allowed (subject to the namespace having
no interfaces, so most network operations fail naturally).

### 3.4 Landlock rules

Landlock restricts file access paths. The rules are:

| Path | Read | Write | Reason |
|------|------|-------|--------|
| `/etc` | Y | N | Resolver, nsswitch, config files |
| `/etc/shadow` | N | N | Password hashes |
| `/etc/gshadow` | N | N | Group hashes |
| `/root` | N | N | Root home |
| `/root/.ssh` | N | N | Root SSH keys |
| `/usr` | Y | N | System binaries and libraries |
| `/bin`, `/sbin`, `/lib`, `/lib64` | Y | N | System dirs |
| `/boot` | N | N | Kernel and boot files |
| `~/.ssh` | N | N | User SSH keys |
| Working directory | Y | Y | Agent needs read/write to its workspace |
| `/tmp` | Y | Y | Temporary files (private tmpfs) |

Landlock is a deny-by-default model: any path not explicitly allowed is
denied. The rules above are the allow-list; everything else is denied.

### 3.5 Cgroup limits

```ini
[Service]
# cgroup v2 unified hierarchy
MemoryMax=536870912        # 512 MiB
CPUQuota=200%              # 2 cores (200000/100000)
TasksMax=256               # max 256 processes
IOWeight=50               # low block I/O priority
```

Values are configurable in `config/sandbox/rootless.yaml`:

```yaml
# config/sandbox/rootless.yaml
memory_max: 536870912     # bytes
cpu_quota: 200000          # microseconds per 100000 period (2 cores)
pids_max: 256
io_weight: 50
net_host: false           # allow host network namespace?
```

### 3.6 Rlimits

```c
setrlimit(RLIMIT_CORE, 0);       // no core dumps
setrlimit(RLIMIT_NOFILE, 256);    // max 256 file descriptors
setrlimit(RLIMIT_NPROC, 256);     // max 256 processes
setrlimit(RLIMIT_FSIZE, 1073741824);  // max 1 GiB file size
```

---

## 4. gVisor Profile (runsc)

### 4.1 Startup sequence

```
1. Pre-check: runsc binary is installed and version matches config
2. runsc --platform=systrap --network=none run <command>
   (or --network=host if config/sandbox/gvisor.yaml has net_host: true)
3. runsc boots the Sentry process which intercepts all syscalls
4. The workload runs with no direct host kernel syscalls
```

### 4.2 runsc flags

```yaml
# config/sandbox/gvisor.yaml
platform: systrap          # or "ptrace" if systrap is unavailable
network: none              # or "host"
debug: false
strace: false
profile: false             # CPU profiling
```

### 4.3 Security properties

- The Sentry intercepts every syscall the workload makes. The host kernel
  only sees the Sentry's syscalls (read, write, epoll, etc.), not the
  workload's syscalls.
- `--no-new-privs` is passed to runsc so `NoNewPrivileges` is enforced.
- No file capabilities are granted to the workload.
- The network is isolated (none) or bridged (host) per config.

### 4.4 Limitations

- I/O overhead: 10-30% on syscall-heavy workloads.
- Not all syscalls are supported (some require platform-specific patches).
- Does not protect against vulnerabilities in the Sentry itself (but the
  Sentry surface is much smaller than the full host kernel).

---

## 5. Firecracker Profile (microVM)

### 5.1 Startup sequence

```
1. Pre-check: firecracker binary, vmlinux, and rootfs.ext4 exist
2. Create a TAP device (or use --net=none)
3. firecracker --no-api --config-file config/sandbox/firecracker.json
4. Firecracker boots the guest kernel
5. The workload runs inside the guest with a separate kernel
6. On exit, the microVM is torn down
```

### 5.2 Configuration

```json
{
  "boot-source": {
    "kernel_image_path": "config/sandbox/vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off nomodules ro"
  },
  "drives": [{
    "drive_id": "rootfs",
    "path_on_host": "config/sandbox/rootfs.ext4",
    "is_root_device": true,
    "is_read_only": true
  }],
  "machine-config": {
    "vcpu_count": 2,
    "mem_size_mib": 512
  },
  "network-interfaces": []
}
```

### 5.3 Security properties

- Separate guest kernel: kernel exploits in the host kernel are not
  reachable from the workload.
- Read-only root filesystem: the workload cannot modify its own OS image.
- No network interfaces by default: the workload has no network access
  unless a TAP device is configured.
- CPU and memory limits are enforced by the Firecracker VMM.

### 5.4 Limitations

- Cold start: ~125ms (faster than gVisor's 200ms because it is a direct
  KVM boot, not a syscall interceptor).
- Requires KVM (hardware virtualization). Not available in nested
  virtualization or some containers.
- The guest kernel must be maintained and patched separately.

---

## 6. Sandbox Audit

### 6.1 Launch log

Every sandbox launch is logged to `/var/log/workspace-sandbox.log`:

```
2026-07-08T14:32:01Z|rootless|hostname-agent|pid=12345|cmd=cargo test|exit=0
2026-07-08T14:33:15Z|gvisor|hostname-untrusted|pid=12367|cmd=bash -c run.sh|exit=1
```

### 6.2 Failure handling

If the sandbox launcher fails to apply seccomp, Landlock, or namespace
setup, it exits code 3 and does NOT exec the workload. The workload never
runs unconfined. This is a hard failure.

```
FATAL: sandbox setup failed: seccomp filter install returned ENOMEM
       workload NOT started. Fix the sandbox and re-run.
```

---

## 7. Systemd Integration

The systemd unit template at `config/systemd/workspace-agent@.service`
codifies the capability and namespace settings for systemd-managed agent
workloads:

```ini
# config/systemd/workspace-agent@.service
[Unit]
Description=WORKSPACE Agent (%i)
After=network.target

[Service]
Type=exec

# Capability throttle (SPEC-CAP-THROTTLE section 6)
CapabilityBoundingSet=
NoNewPrivileges=yes

# Address family restriction (AF_ALG block for Copy Fail)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

# Filesystem protection
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

# Namespace isolation
PrivateDevices=yes
PrivateNetwork=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RemoveIPC=yes

# Resource limits
MemoryMax=512M
CPUQuota=200%
TasksMax=256
LimitCORE=0
LimitNOFILE=256

# Seccomp ( capaz / systemd seccomp filter )
SystemCallFilter=~@mount @module @raw-io @debug @chroot @swap @clock @cpu-emulation
SystemCallFilter=~open_by_handle_at io_uring_setup io_uring_enter io_uring_register
SystemCallFilter=~personality kexec_load kexec_file_load init_module finit_module delete_module
SystemCallFilter=~bpf perf_event_open fanotify_init userfaultfd ptrace process_vm_readv process_vm_writev

# The %i instance name maps to the profile
# (the wrapper script at /usr/local/bin/workspace-agent-wrapper
# handles the profile selection and calls workspace-sandbox-launcher)
ExecStart=/usr/local/bin/workspace-sandbox-launcher --profile %i -- 

[Install]
WantedBy=multi-user.target
```

---

## 8. Defense-in-Depth Map

This spec implements the sandbox row of the defense-in-depth map from
[RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md) section 5:

| Vector | Rootless | gVisor | Firecracker |
|--------|----------|--------|-------------|
| Copy Fail (AF_ALG) | seccomp blocks `socket(AF_ALG)` | Sentry (no host syscall) | separate kernel |
| Shocker (open_by_handle_at) | seccomp blocks syscall + cap drop | Sentry | separate kernel |
| nftables (CAP_NET_ADMIN) | cap drop (bounding set empty) | no net_admin in runsc | no net in guest |
| overlayfs (mount) | seccomp blocks `mount` + `mount_setattr` | Sentry | separate kernel |
| Page-cache corruption (splice) | seccomp blocks `AF_ALG` | no host syscall | separate kernel |
| ptrace re-entry | seccomp blocks `ptrace` + `NoNewPrivileges` | Sentry | separate kernel |
| SUID re-escalation | `PR_SET_NO_NEW_PRIVS` | `--no-new-privs` | guest kernel |
| ESP6 (CAP_NET_RAW) | cap drop (bounding set empty) | no net_raw in runsc | no raw in guest |

---

## 9. References

1. [references/sandlock-arxiv.html](../references/sandlock-arxiv.html): Sandlock rootless sandbox design
2. [RESEARCH-SYSTEM-BINARIES](../RESEARCH-SYSTEM-BINARIES.md) section 4: sandbox isolation tiers
3. [REQ-SANDBOX](../requirements/REQ-SANDBOX.md) section 3: REQ-SBX-* requirements
4. [SPEC-CAP-THROTTLE](SPEC-CAP-THROTTLE.md) section 6: systemd CapabilityBoundingSet
5. [SPEC-AUDIT](SPEC-AUDIT.md): auditd and drift detection
6. [SPEC-HOME-LOCK](SPEC-HOME-LOCK.md): home-dir chown lock (closes the
   direct-file-write vector that bypasses the `git config` command
   intercept)