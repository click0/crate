# FreeBSD Porting Ideas Inspired by Sandboxie

This document maps isolation features from SandboxieCrack (Windows) to their FreeBSD equivalents, proposing concrete enhancements for the Crate project.

---

## 1. Encrypted Containers — GELI / ZFS Native Encryption

### Sandboxie approach
SandboxieCrack implements ImBox encrypted sandbox volumes (`core/dll/crypt.c`, `core/svc/MountManager.cpp`). Each sandbox directory can be stored in an AES-encrypted container file, mounted transparently at sandbox start and unmounted at exit. The service layer handles key management and volume mounting with elevated privileges.

### FreeBSD equivalent
- **`geli(8)`** — Full-disk encryption for block devices. Can encrypt a zvol or memory-backed device.
- **ZFS native encryption** — Per-dataset encryption with `zfs create -o encryption=aes-256-gcm -o keyformat=passphrase`. Supports key rotation and per-dataset keys.

### Proposed integration
```
# In +CRATE.SPEC:
options:
  encrypted:
    method: zfs        # or geli
    keyformat: passphrase
```

Implementation path:
1. Create an encrypted ZFS dataset per container: `zfs create -o encryption=aes-256-gcm pool/crate/<name>`
2. Prompt for passphrase (or read from keyfile) at `crate run` time
3. Load key via `zfs load-key`, mount dataset, proceed with normal jail setup
4. On exit, `zfs unload-key` to lock the dataset

Benefits over Sandboxie: ZFS encryption is kernel-native, supports snapshots of encrypted datasets, and doesn't require a custom encrypted container format.

---

## 2. Snapshot Management — ZFS Snapshots

### Sandboxie approach
SandboxieCrack implements file-level snapshots (`core/drv/file_snapshots.c`). Snapshots capture the state of a sandbox's modified files using name scrambling to store multiple versions. Supports parent-child snapshot chains and selective restore. Snapshot metadata is stored in `Snapshot.ini` files within the sandbox directory.

### FreeBSD equivalent
- **`zfs snapshot`** — Atomic, zero-cost snapshots of entire datasets
- **`zfs rollback`** — Restore dataset to a previous snapshot
- **`zfs clone`** — Create writable copy from snapshot (instant, COW)
- **`zfs diff`** — Show changes between snapshots

### Proposed integration
New `crate snapshot` subcommand:

```bash
crate snapshot create <container> [name]    # zfs snapshot pool/crate/<container>@<name>
crate snapshot list <container>             # zfs list -t snapshot pool/crate/<container>
crate snapshot restore <container> <name>   # zfs rollback pool/crate/<container>@<name>
crate snapshot delete <container> <name>    # zfs destroy pool/crate/<container>@<name>
crate snapshot diff <container> <s1> [s2]   # zfs diff pool/crate/<container>@<s1> [<s2>]
```

Implementation: Add `snapshot.cpp` with ZFS command wrappers. Requires container rootfs to live on a ZFS dataset (add `--zfs-pool` flag to `crate create`).

Benefits over Sandboxie: Filesystem-level snapshots are atomic, zero-copy, and capture the complete container state (not just modified files). No custom name-scrambling logic needed.

---

## 3. Per-Container Firewall Rules — pf Anchors + VNET

### Sandboxie approach
SandboxieCrack uses the Windows Filtering Platform (`core/drv/wfp.c`) to apply per-sandbox network rules. Each sandbox can have independent allow/block rules for TCP/UDP traffic based on IP ranges, ports, and protocols. Rules are applied at the kernel level using WFP callout filters registered per-sandbox.

### FreeBSD equivalent
- **`pf(4)`** — BSD packet filter with anchor support for hierarchical rulesets
- **VNET** — Already used by Crate; provides per-jail network stack
- **`ipfw(8)`** — Already used by Crate for NAT

### Proposed integration
Replace or supplement current `ipfw` rules with `pf` anchors for more flexible per-container policies:

```
# In +CRATE.SPEC:
options:
  net:
    outbound: [wan]
    firewall:
      block-ip: [10.0.0.0/8, 172.16.0.0/12]
      allow-tcp: [80, 443]
      allow-udp: [53]
      default: block
```

Implementation:
1. Create a pf anchor per jail: `anchor "crate/<jail-name>"`
2. Load per-jail rules into the anchor at jail start
3. Flush anchor rules at jail stop
4. Since VNET gives each jail its own stack, rules can also run inside the jail's own pf instance

This approach scales better than the current flat ipfw rule numbering (which has TODO about rule conflicts in `run.cpp:51`).

---

## 4. DNS Filtering — Per-Jail DNS Proxy

### Sandboxie approach
SandboxieCrack hooks DNS resolution in user mode (`core/dll/dns_filter.c`). Intercepts `WSALookupServiceBeginW` and `getaddrinfo` to apply per-sandbox domain allow/block lists with wildcard pattern matching. Can redirect blocked domains to localhost or return NXDOMAIN.

### FreeBSD equivalent
- **Per-jail `resolv.conf`** — Already possible; jail gets its own `/etc/resolv.conf`
- **`unbound(8)`** — Lightweight recursive DNS resolver, available in FreeBSD base since 10.0
- **Response Policy Zones (RPZ)** — Standard DNS filtering mechanism supported by unbound

### Proposed integration
```yaml
# In +CRATE.SPEC:
dns_filter:
  allow:
    - "*.example.com"
    - "cdn.provider.net"
  block:
    - "*.ads.example.com"
    - "telemetry.*"
  redirect_blocked: "127.0.0.1"  # or "nxdomain"
```

Implementation:
1. If `dns_filter` is specified, start a local `unbound` instance inside the jail listening on 127.0.0.1:53
2. Generate `unbound.conf` with local-zone entries for blocked domains (`local-zone: "ads.example.com" redirect`, `local-data: "ads.example.com A 127.0.0.1"`)
3. Set jail's `resolv.conf` to point to `127.0.0.1`
4. Forward allowed queries to the host's upstream DNS

Benefits over Sandboxie: Uses standard DNS infrastructure (unbound + RPZ) instead of API hooking. Works for all applications regardless of DNS library used.

---

## 5. Resource Limits — RCTL Framework

### Sandboxie approach
SandboxieCrack limits the number of processes per sandbox and can restrict CPU/memory through Windows Job Objects. Process limits are configured in `Sandboxie.ini` and enforced by the kernel driver.

### FreeBSD equivalent
- **`rctl(8)`** — Resource limits framework for jails, users, processes
- Supports: CPU time, CPU percentage, RSS, virtual memory, swap, number of processes, open files, pseudo-terminals, socket buffers, disk quota (with ZFS)

### Proposed integration
```yaml
# In +CRATE.SPEC:
limits:
  maxproc: 64              # max processes in jail
  memorylocked: 256M       # max locked memory
  vmemoryuse: 2G           # max virtual memory
  cputime: 3600            # max CPU seconds
  openfiles: 1024          # max open file descriptors
  pcpu: 50                 # max CPU % (throttle)
```

Implementation in `run.cpp`:
1. Parse `limits` section in `spec.cpp`
2. Before jail start, apply rctl rules: `rctl -a jail:<name>:maxproc:deny=64`
3. On jail cleanup, remove rules: `rctl -r jail:<name>`

Requires `kern.racct.enable=1` in `/boot/loader.conf`.

Benefits over Sandboxie: RCTL provides much richer resource controls (CPU %, memory, disk, files) compared to Sandboxie's basic process count limit.

---

## 6. Copy-on-Write Filesystem — ZFS Clones / unionfs

### Sandboxie approach
SandboxieCrack implements transparent copy-on-write at the file level (`core/drv/file.c`, `core/drv/file_xlat.c`). Files are categorized as TRUE_PATH (host original) or COPY_PATH (sandbox copy). On first write, the file is copied from TRUE_PATH to COPY_PATH, and subsequent accesses use the copy. This avoids duplicating the entire filesystem.

### FreeBSD equivalent
- **ZFS clones** — `zfs clone pool/base@snap pool/crate/<name>` creates an instant writable copy sharing all blocks with the original via COW
- **`unionfs(5)`** — Layer a writable filesystem over a read-only base

### Proposed integration

**Option A: ZFS clones (recommended)**
```bash
# One-time: create base snapshot
zfs snapshot pool/crate/base@v1

# Per run: clone base for this container instance
zfs clone pool/crate/base@v1 pool/crate/run-<name>-<pid>

# After run: destroy (ephemeral) or keep (persistent)
zfs destroy pool/crate/run-<name>-<pid>
```

**Option B: unionfs overlay**
```bash
mount -t unionfs -o below /path/to/writable /path/to/base /path/to/merged
```

Add to `+CRATE.SPEC`:
```yaml
options:
  cow:
    mode: ephemeral   # discard changes on exit
    # or
    mode: persistent  # keep changes across runs
    backend: zfs      # or unionfs
```

Benefits over Sandboxie: Filesystem-level COW (ZFS) is transparent, atomic, and requires no file-by-file tracking. Works for all file types including hard links, symlinks, and special files.

---

## 7. IPC Namespace Controls — Jail SysV IPC

### Sandboxie approach
SandboxieCrack filters IPC at multiple levels (`core/drv/ipc.c`, `core/drv/ipc_port.c`): named pipes, ALPC ports, RPC endpoints, COM objects, and clipboard operations. The driver intercepts NtCreatePort, NtConnectPort, and related syscalls, applying per-sandbox allow/block policies. Dynamic RPC ports are tracked and filtered.

### FreeBSD equivalent
- **Jail `allow.sysvipc`** — Controls access to System V IPC (shared memory, semaphores, message queues)
- **`allow.raw_sockets`** — Controls raw socket access
- **Jail children** — Nested jails for further isolation
- FreeBSD jails natively isolate IPC namespaces; no hooking needed

### Proposed integration
```yaml
# In +CRATE.SPEC:
ipc:
  sysvipc: false     # default: deny SysV IPC (shared mem, semaphores, msg queues)
  raw_sockets: false # default: deny raw sockets
  mqueue: false      # POSIX message queues
```

Implementation: Map these to `jail_setv()` parameters. Currently Crate doesn't expose these knobs — adding them allows fine-tuning for applications that need shared memory (e.g., PostgreSQL requires `sysvipc=true`).

---

## 8. Process Privilege Dropping — Capsicum + MAC

### Sandboxie approach
SandboxieCrack manipulates process security tokens (`core/drv/token.c`): drops privileges via `SeFilterToken`, removes SID groups, lowers integrity levels, and applies restricted tokens. This prevents sandboxed processes from accessing high-privilege resources even if they exploit a vulnerability.

### FreeBSD equivalent
- **Capsicum** — Capability mode: once entered, a process can only use pre-opened file descriptors. Irrevocable.
- **MAC framework** — Mandatory Access Control policies:
  - `mac_bsdextended(4)` — File system firewall rules
  - `mac_portacl(4)` — Port binding restrictions
  - `mac_seeotheruids(4)` — Hide processes from other users
- **`security.jail.enforce_statfs`** — Control visibility of mount points

### Proposed integration
```yaml
# In +CRATE.SPEC:
security:
  capsicum: false       # enable Capsicum capability mode for main process
  mac_bsdextended: []   # file access rules
  mac_portacl:
    allow_ports: [80, 443]  # allowed bind ports
  hide_other_jails: true    # prevent seeing other jails
```

Implementation:
1. For Capsicum: after jail setup and before executing the user command, optionally enter capability mode via `cap_enter()`. Note: this is very restrictive and only useful for specific workloads.
2. For MAC: generate `mac.conf` rules and load them via `mac(4)` framework.
3. `security.jail.enforce_statfs=2` — already prevents jails from seeing host mounts.

Benefits over Sandboxie: Capsicum is irrevocable (even root can't escape once entered). MAC policies are kernel-enforced, not based on token manipulation which can be more fragile.

---

## 9. Configuration Validation — YAML Schema + `crate validate`

### Sandboxie approach
SandboxieCrack provides an INI configuration editor with validation, auto-completion, contextual tooltips, and color-coded settings. The GUI validates settings in real-time and warns about invalid combinations.

### FreeBSD/Crate equivalent
Crate currently has basic `Spec::validate()` in `spec.cpp` that checks for:
- Presence of executable, services, or tor option
- Absolute paths
- No duplicate package overrides
- Matching port range spans
- Recognized script sections

### Proposed enhancement
Add a standalone validation command and richer diagnostics:

```bash
crate validate spec.yml
```

Implementation:
1. Define a JSON Schema or programmatic schema for `+CRATE.SPEC` format
2. Validate all fields: types, ranges, enum values, cross-field constraints
3. Produce human-readable error messages with line numbers
4. Add warnings for common misconfigurations:
   - Network options without `net` enabled
   - Services that need `sysvipc` but don't enable it
   - Missing packages for specified services
5. Optional: `crate validate --fix` to auto-correct common issues

Also enhance existing parsing in `spec.cpp`:
- Better error messages (currently some paths call `abort()`)
- Suggest corrections for typos in option names
- Warn about deprecated or unknown fields

---

## 10. Container Templates / Presets — Jail Profiles

### Sandboxie approach
SandboxieCrack provides predefined box types with different security levels:
- **Standard** — Basic isolation, full network access
- **Enhanced Privacy** — Blocks access to personal data, restricts network
- **Data Protection** — Prevents data exfiltration, blocks clipboard, limits network
- **Application Compartment** — Minimal isolation, just prevents modification of host system

### Proposed integration
Create a `templates/` directory in Crate with predefined `+CRATE.SPEC` profiles:

```
templates/
├── minimal.yml          # Bare jail, no network, no X11
├── standard.yml         # Network access, shared Downloads dir
├── privacy.yml          # Network via Tor, no shared dirs, encrypted, ephemeral COW
├── network-isolated.yml # No network, X11 for GUI apps
└── development.yml      # Full network, shared home dir, all dev tools
```

Usage:
```bash
crate create --template privacy --name my-browser firefox
crate create --template development --name devbox
```

Implementation:
1. Add `--template` flag to `crate create`
2. Load template YAML, then overlay user-specified options
3. Ship templates in `/usr/local/share/crate/templates/`
4. Allow user templates in `~/.config/crate/templates/`

Example `templates/privacy.yml`:
```yaml
base:
  keep: []
options:
  tor: {}
  encrypted:
    method: zfs
  cow:
    mode: ephemeral
    backend: zfs
dns_filter:
  block:
    - "*.telemetry.*"
    - "*.tracking.*"
limits:
  maxproc: 32
  vmemoryuse: 2G
```

---

## Summary: Priority Roadmap

| Priority | Feature | FreeBSD API | Complexity | Impact |
|----------|---------|-------------|------------|--------|
| **High** | Resource limits (RCTL) | `rctl(8)` | Low | Prevents resource abuse |
| **High** | ZFS snapshots | `zfs snapshot/clone` | Medium | State management, rollback |
| **High** | DNS filtering | `unbound(8)` | Medium | Privacy, security |
| **Medium** | pf firewall anchors | `pf(4)` | Medium | Replaces fragile ipfw numbering |
| **Medium** | Container templates | N/A (YAML) | Low | Usability |
| **Medium** | Config validation | N/A (code) | Low | Developer experience |
| **Medium** | COW filesystem | ZFS clones | Medium | Disk efficiency |
| **Low** | Encryption | GELI / ZFS encryption | Medium | Data protection |
| **Low** | IPC controls | Jail params | Low | Fine-grained isolation |
| **Low** | Capsicum / MAC | `cap_enter()`, `mac(4)` | High | Defense in depth |
