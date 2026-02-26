# FreeBSD Porting Ideas Inspired by Sandboxie

This document maps isolation features from SandboxieCrack (Windows) to their FreeBSD equivalents, proposing concrete enhancements for the Crate project.

---

## 1. Encrypted Containers — GELI / ZFS Native Encryption

### Sandboxie approach
SandboxieCrack provides encrypted sandbox volumes via the `MountManager` service (`core/svc/MountManager.cpp`, 1455 lines). The `MountManager` class handles the full lifecycle: `AcquireBoxRoot()` locks and prepares a sandbox root directory, `MountImDisk()` creates ImDisk-backed encrypted virtual disks with AES cipher and password protection, `CreateJunction()` sets up NTFS junction points to redirect the sandbox file path to the encrypted volume, and `ReleaseBoxRoot()` cleans up on exit. The system supports two distinct volume types: **image files** (`ImBox type=img`) — persistent encrypted container files on disk, and **RAM disks** (`ImBox type=ram`) — memory-backed volatile sandboxes that are destroyed on exit. New volumes are automatically formatted with NTFS and assigned drive letters. Passwords are stored in memory-resident structures to prevent key exposure to disk. The cryptographic API hooks in `core/dll/crypt.c` (separate from ImBox encryption) intercept Windows DPAPI calls (`CryptProtectData`/`CryptUnprotectData`/`CertGetCertificateChain`) to ensure credential protection operations stay within sandbox boundaries.

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
SandboxieCrack implements file-level snapshots (`core/dll/file_snapshots.c`). Each snapshot is assigned a short ID (max 17 characters) with scramble keys used to obfuscate file names within the snapshot directory for privacy. Snapshots form hierarchical parent-child chains: when resolving a file, the system performs lazy resolution across snapshot layers — walking from the newest snapshot back through parents until the file is found or the base layer is reached. Snapshot metadata is stored in `Snapshot.ini` files within the sandbox directory, tracking snapshot IDs, parent references, and creation timestamps.

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
SandboxieCrack uses the Windows Filtering Platform (`core/drv/wfp.c`) to apply per-sandbox network rules. The driver registers a WFP sublayer (GUID `e1d364e9-cd84-4a48-aba4-608ce83e31ee`) and installs callout filters for both send and receive operations across IPv4 and IPv6. Each sandbox can have independent allow/block rules for TCP/UDP traffic based on IP ranges, ports, and protocols. The WFP integration includes flow tracking (associating network connections with specific sandboxed processes) and flow deletion callbacks for cleanup when connections terminate.

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

This approach would complement the current dynamic ipfw rule allocation (via `FwSlots` in `run.cpp`) with more flexible per-container policies.

---

## 4. DNS Filtering — Per-Jail DNS Proxy

### Sandboxie approach
SandboxieCrack hooks DNS resolution in user mode (`core/dll/dns_filter.c`). Intercepts `WSALookupServiceBeginW`/`WSALookupServiceNextW` and `WSALookupServiceEnd` to apply per-sandbox domain allow/block lists with wildcard pattern matching. The filter maintains a static IP entry table populated at initialization to match resolution results against configured patterns. Filtering is enabled or disabled based on global driver configuration (certificate status and network options), and rules support both domain-based patterns (e.g., `*.ads.example.com`) and IP-based filtering of resolution results. Blocked domains can be redirected to localhost or suppressed entirely.

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
SandboxieCrack limits the number of processes per sandbox and can restrict CPU/memory through Windows Job Objects. Process limits are configured in `Sandboxie.ini` and enforced by the kernel driver (`core/drv/process.c`). The driver tracks all processes via `PsSetCreateProcessNotifyRoutineEx` callbacks, maintaining a `PROCESS` structure per sandboxed process that includes process ID, starter ID, integrity level, primary token references, and per-process thread maps.

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
SandboxieCrack implements transparent copy-on-write at the file level via both kernel driver (`core/drv/file.c`, `core/drv/file_xlat.c`) and user-mode DLL (`core/dll/file.c` — the largest module at 258KB). Files are categorized as TRUE_PATH (host original) or COPY_PATH (sandbox copy). On first write, the file is copied from TRUE_PATH to COPY_PATH, and subsequent accesses use the copy. File deletions are tracked in a delete tree rather than physically removing files, allowing undelete. The implementation spans multiple supporting modules: `file_copy.c` (copy operations), `file_del.c` (deletion tracking), `file_link.c` (hardlink/symlink handling), `file_pipe.c` (named pipe redirection), `file_dir.c` (directory operations), and `file_init.c` (path initialization).

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
SandboxieCrack filters IPC at multiple levels (`core/drv/ipc.c`, `core/drv/ipc_port.c`): LPC/ALPC ports, events, EventPairs, KeyedEvents, mutexes, semaphores, job objects, and named pipes. The driver intercepts port-related syscalls in `core/drv/ipc.c` (`NtCreatePort`, `NtConnectPort`, `NtAlpcConnectPort`, etc.), while `core/drv/ipc_port.c` applies message-level filtering on established connections with per-sandbox allow/block policies. Dynamic RPC ports are tracked via `IPC_DYNAMIC_PORT`/`IPC_DYNAMIC_PORTS` structures, which maintain a port registry with locks for thread safety. The driver also handles spooler port forwarding and RPC endpoint mapper filtering to prevent cross-sandbox service access.

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

**Note on named pipes:** Sandboxie's IPC layer also includes dedicated named pipe proxying (`core/dll/file_pipe.c`, `core/svc/namedpipeserver.cpp` — 853 lines) for controlled cross-sandbox pipe communication. The FreeBSD equivalent is Unix domain socket proxying — see §15 for a proposed implementation.

---

## 8. Process Privilege Dropping — Capsicum + MAC

### Sandboxie approach
SandboxieCrack manipulates process security tokens (`core/drv/token.c`) through four key kernel functions: `Token_Filter` (drops specified privileges from a token), `Token_Restrict` (applies additional SID restrictions and integrity level lowering), `Token_ReplacePrimary` (swaps a process's primary token for a restricted copy), and `Token_DuplicateToken` (creates restricted token copies for child processes). The driver also modifies DACLs on kernel object handles to prevent sandboxed processes from accessing high-privilege resources even if they exploit a vulnerability.

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

## 11. GUI / Desktop Isolation — Nested X11 / Wayland

### Sandboxie approach
SandboxieCrack provides extensive GUI isolation (`core/dll/gui.c`, 87KB). The DLL hooks window management functions (`CreateWindowEx`, `SetWindowPos`, `ShowWindow`, `EnumWindows`, etc.) to filter window class enumeration, isolate desktop/window station access, intercept clipboard operations, and filter inter-process window messages. The `GuiServer` service (`core/svc/GuiServer.cpp`) acts as a privileged proxy using a slave process architecture — helper processes mediate GUI operations between sandboxed applications and the host desktop. The `Gui_UseProxyService` flag controls whether the proxy is active.

### FreeBSD equivalent
- **Xpra** — Persistent remote X11 sessions; can act as a nested X server
- **Xephyr** — Nested X11 server running inside an existing X session
- **Wayland** — Protocol-level isolation; each compositor is a security boundary
- **X11 `SECURITY` extension** — Allows creating untrusted X11 connections with restricted capabilities

### Proposed integration
```yaml
# In +CRATE.SPEC:
options:
  x11:
    mode: nested      # nested (Xephyr/Xpra), shared (current nullfs), none
    resolution: 1280x720
    clipboard: false  # see §12
```

Implementation:
1. **`mode: nested`** — Start Xephyr or Xpra inside the jail, set `DISPLAY` to the nested server. The host X11 socket is NOT shared. Applications see a completely isolated display.
2. **`mode: shared`** — Current behavior: nullfs mount of `/tmp/.X11-unix`. Fast but no isolation.
3. **`mode: none`** — No X11 access at all.
4. For Wayland: mount only the Wayland socket if available; Wayland's protocol design already provides better isolation than X11.

Benefits over Sandboxie: Nested X servers provide stronger isolation than API hooking — the sandboxed application has no access to the host window list, clipboard, or input events at the protocol level.

---

## 12. Clipboard Isolation — X11 Selection Filtering

### Sandboxie approach
SandboxieCrack intercepts clipboard operations as part of the GUI layer (`core/dll/gui.c`). The `GuiServer` mediates clipboard data between sandboxes — when a sandboxed application copies data, it goes to a per-sandbox clipboard buffer. Cross-sandbox paste operations are filtered and optionally blocked (configurable in Data Protection box types).

### FreeBSD equivalent
- **X11 selections** — X11 uses three selection buffers (PRIMARY, SECONDARY, CLIPBOARD) mediated by the X server
- **`xclip`/`xsel`** — Command-line clipboard utilities
- **Wayland clipboard** — Per-surface clipboard, compositor-controlled

### Proposed integration
```yaml
# In +CRATE.SPEC:
options:
  clipboard:
    mode: isolated    # isolated (per-jail), shared (host), none
    direction: both   # in, out, both, none — for shared mode
```

Implementation:
1. **`mode: isolated`** — With nested X11 (§11), clipboard isolation is automatic — each Xephyr instance has its own selection buffers.
2. **`mode: shared`** with `direction` control — Run an `xsel` proxy that forwards clipboard in the allowed direction(s). Block the reverse direction.
3. **`mode: none`** — No clipboard access.

---

## 13. COM/D-Bus Service Isolation — Per-Jail D-Bus

### Sandboxie approach
SandboxieCrack provides extensive COM/DCOM isolation (`core/dll/com.c`, 101KB). The DLL hooks `CoCreateInstance`, `CoGetClassObject`, and related COM activation functions. COM objects requested by sandboxed applications are either instantiated within the sandbox (in-process servers) or proxied through the service layer via `ComWire.h` protocol (out-of-process servers). DCOM server launches are redirected to sandbox-local instances. The `COM_IUNKNOWN` wrapper structure tracks reference counts and object indices for proxied objects. Type library loading is restricted to prevent sandbox escape via COM object registration.

### FreeBSD equivalent
- **D-Bus** — The UNIX equivalent of COM for inter-process service activation. Used by desktop environments (GNOME, KDE) for service discovery and method calls.
- **Per-user D-Bus sessions** — Each user gets a `dbus-daemon --session` instance
- **D-Bus policy files** — XML-based access control for method calls, signals, and name ownership

### Proposed integration
```yaml
# In +CRATE.SPEC:
options:
  dbus:
    system: false      # provide system bus inside jail
    session: true      # start session bus for GUI apps
    policy:
      allow_own: ["org.freedesktop.Notifications"]
      deny_send: ["org.freedesktop.*"]
```

Implementation:
1. If `dbus.session: true`, start a `dbus-daemon --session` inside the jail at jail creation time
2. Generate a jail-local D-Bus policy file restricting name ownership and method calls
3. If `dbus.system: false` (default), do NOT mount the host's `/var/run/dbus/system_bus_socket` — the jail has no system bus access
4. Set `DBUS_SESSION_BUS_ADDRESS` environment variable to the jail-local socket

Benefits over Sandboxie: D-Bus policy files are declarative and auditable. Per-jail D-Bus daemon provides true service namespace isolation without API-level hooking.

---

## 14. Service Manager Isolation — Per-Jail rc.d

### Sandboxie approach
SandboxieCrack hooks the Windows Service Control Manager via multiple components (`core/dll/scm.c`, `scm_create.c`, `scm_notify.c`, `scm_query.c`; `core/svc/serviceserver.cpp`, `serviceserver2.cpp`). Sandboxed applications can enumerate, start, stop, and configure services — but only within the sandbox context. Access to real host services is blocked. The service server maintains a per-sandbox service database, handling service creation, status queries, and change notifications in an isolated namespace.

### FreeBSD equivalent
- **Per-jail `rc.d`** — Each jail can have its own set of `rc.d` scripts for service management
- **`daemon(8)`** — FreeBSD's native service supervision utility
- **`service(8)`** — Service management interface that respects jail boundaries

### Proposed integration
```yaml
# In +CRATE.SPEC:
services:
  managed:
    - name: nginx
      enable: true
      rcvar: nginx_enable
    - name: postgresql
      enable: true
      rcvar: postgresql_enable
  auto_start: true  # start services at jail boot via rc.d
```

Implementation:
1. Parse `services` section in `spec.cpp`
2. Generate jail-local `/etc/rc.conf` entries for specified services
3. At jail start, run `service <name> start` for each enabled service
4. At jail stop, run `service <name> stop` in reverse order
5. Service enumeration is naturally isolated — jails only see their own `rc.d` scripts

Benefits over Sandboxie: No API hooking needed — FreeBSD jails natively restrict service visibility to the jail's own service set.

---

## 15. Named Pipe / Unix Socket Proxying

### Sandboxie approach
SandboxieCrack provides dedicated named pipe proxying (`core/dll/file_pipe.c` for user-mode interception, `core/svc/namedpipeserver.cpp` — 853 lines — for the privileged proxy server). The pipe server creates controlled channels between sandboxed processes and the host, allowing specific named pipes to cross the sandbox boundary while blocking others. Pipe access policies are applied per sandbox based on pipe name patterns.

### FreeBSD equivalent
- **Unix domain sockets** — The POSIX equivalent of named pipes for local IPC
- **`AF_UNIX` with `socketpair(2)`** — Creates connected socket pairs for parent-child IPC
- **`nullfs` socket mounts** — Mount individual socket files into the jail for controlled sharing

### Proposed integration
```yaml
# In +CRATE.SPEC:
options:
  socket_proxy:
    # Share specific host sockets with the jail
    share:
      - /var/run/dbus/system_bus_socket
      - /tmp/.X11-unix/X0
    # Create proxy sockets for controlled cross-jail communication
    proxy:
      - host: /var/run/myapp.sock
        jail: /var/run/myapp.sock
        direction: bidirectional  # or in, out
```

Implementation:
1. For `share`: use `nullfs` to mount specific socket files into the jail (already done for X11)
2. For `proxy`: create a `socat`-based or custom proxy daemon that relays data between host and jail sockets with optional filtering
3. Default: no host sockets shared unless explicitly configured

Benefits over Sandboxie: Unix domain sockets with `nullfs` mounts are simpler than API hooking. The proxy approach provides explicit, auditable socket sharing.

---

## 16. Terminal/Console Isolation

### Sandboxie approach
SandboxieCrack hooks Windows Terminal Services (RDP) session APIs (`core/dll/terminal.c` for user-mode hooks, `core/svc/terminalserver.cpp` for the privileged RDP session proxy). The DLL intercepts WinStation and WTS APIs (`WinStationEnumerateW`, `WTSEnumerateSessionsW`, `WTSEnumerateProcessesW`, `WTSQueryUserToken`, etc.) to prevent sandboxed applications from enumerating or interacting with Remote Desktop sessions outside their sandbox. The `terminalserver.cpp` service dynamically loads `winsta.dll` and provides session query, remoteability checks, name resolution, property retrieval, and disconnect operations via a pipe-based communication protocol.

### FreeBSD equivalent
- **Per-jail PTY allocation** — Each jail gets its own pseudo-terminal devices
- **`devfs` rules** — Control which `/dev/pts/*` devices are visible inside the jail
- **`jexec(8)` / `jls(8)`** — Already provide per-jail terminal sessions

### Proposed integration
Terminal/console isolation is largely **automatic** in FreeBSD jails:

1. Each jail gets its own PTY namespace via `devfs` rules — processes inside the jail cannot see or attach to PTYs belonging to other jails or the host
2. `jexec` creates new terminal sessions when entering a jail
3. The existing `devfs_ruleset` mechanism (already used by Crate) controls device visibility

```yaml
# In +CRATE.SPEC (optional fine-tuning):
options:
  terminal:
    devfs_ruleset: 4    # restrict /dev visibility
    allow_raw_tty: false  # prevent raw TTY access
```

Benefits over Sandboxie: No hooking needed — jail PTY isolation is kernel-enforced. This is one of the few areas where the jail model provides stronger isolation with zero implementation effort.

---

## Summary: Priority Roadmap

| Priority | Feature | FreeBSD API | Complexity | Impact |
|----------|---------|-------------|------------|--------|
| **High** | Resource limits (RCTL) | `rctl(8)` | Low | Prevents resource abuse |
| **High** | ZFS snapshots | `zfs snapshot/clone` | Medium | State management, rollback |
| **High** | DNS filtering | `unbound(8)` | Medium | Privacy, security |
| **High** | GUI isolation (nested X11) | Xephyr / Xpra | Medium | Prevents X11 escape |
| **Medium** | pf firewall anchors | `pf(4)` | Medium | Complements dynamic ipfw allocation |
| **Medium** | Container templates | N/A (YAML) | Low | Usability |
| **Medium** | Config validation | N/A (code) | Low | Developer experience |
| **Medium** | COW filesystem | ZFS clones | Medium | Disk efficiency |
| **Medium** | Clipboard isolation | X11 selections / Xephyr | Low | Prevents data leakage |
| **Medium** | D-Bus isolation | `dbus-daemon` per jail | Medium | Service namespace isolation |
| **Low** | Encryption | GELI / ZFS encryption | Medium | Data protection |
| **Low** | IPC controls | Jail params | Low | Fine-grained isolation |
| **Low** | Capsicum / MAC | `cap_enter()`, `mac(4)` | High | Defense in depth |
| **Low** | Service manager isolation | Per-jail `rc.d` | Low | Service namespace isolation |
| **Low** | Unix socket proxying | `nullfs` + `socat` | Medium | Controlled cross-jail IPC |
| **Low** | Terminal isolation | `devfs` rules | None (automatic) | Already provided by jails |
