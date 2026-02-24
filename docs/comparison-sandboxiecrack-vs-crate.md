# SandboxieCrack vs Crate: Architectural Comparison

## Overview

| | SandboxieCrack (Windows) | Crate (FreeBSD) |
|---|---|---|
| **Platform** | Windows (NT kernel) | FreeBSD |
| **Language** | C (driver/dll), C++ (services/UI) | C++17 |
| **Maturity** | Production, 20+ years of development | Alpha |
| **License** | GPL-3.0 | GPL-3.0 |
| **Upstream** | sandboxie-plus/Sandboxie | yurivict/crate |
| **Architecture** | 4-layer: kernel driver → DLL hooks → services → GUI | Single setuid binary orchestrating FreeBSD jails |

## Architectural Models

### SandboxieCrack — Hook-Based Isolation

SandboxieCrack uses a layered interception approach on Windows:

1. **Kernel driver** (`core/drv/`) — Intercepts 50+ NT system calls via SSDT hooking and minifilter callbacks. Implements file path translation (`file.c`, `file_xlat.c`), registry hive isolation (`key.c`, `key_flt.c`), process token manipulation via `Token_Filter`/`Token_Restrict`/`Token_ReplacePrimary` (`token.c`), IPC filtering with dynamic port tracking via `IPC_DYNAMIC_PORT` structures (`ipc.c`, `ipc_port.c`), and WFP-based network filtering with per-sandbox sublayer and flow tracking (`wfp.c`). The driver maintains per-sandbox state through the `BOX` structure (`box.h`) which defines four namespace paths: file (`\??\C:\Sandbox\%SID%\BoxName`), registry (`HKCU\Sandbox\BoxName`), IPC (`\Sandbox\%SID%\Session_%SESSION%\BoxName`), and pipe (IPC path with backslashes as underscores).

2. **User-mode DLL** (`core/dll/`) — Injected into every sandboxed process via low-level `LdrInitializeThunk` hooking. The largest components: `file.c` (258KB — COW file operations with delete tree tracking), `key.c` (144KB — registry hooking with value merging via `key_merge.c`), `com.c` (101KB — COM/DCOM activation hooking with `COM_IUNKNOWN` proxy wrappers), `proc.c` (100KB — `CreateProcessW`/`ShellExecuteEx` hooking for process creation redirection), `gui.c` (87KB — window/desktop/clipboard isolation), `net.c` (72KB — socket and network API hooking), and `dns_filter.c` (25KB — DNS resolution filtering with IP entry caching). Hook management via `MODULE_HOOK` structures in `dllhook.c` with detour-style trampolines.

3. **Service layer** (`core/svc/`) — A privileged Windows service with specialized servers: `ProcessServer` (process creation, token DACL management, RunSandboxed requests), `MountManager` (encrypted ImDisk volumes via `MountImDisk`/`UnmountImDisk`, RAM disk support via `GetRamDisk`, NTFS junction management via `CreateJunction`/`RemoveJunction`, box root locking via `AcquireBoxRoot`/`ReleaseBoxRoot`), `GuiServer` (window proxy with slave process architecture for cross-sandbox GUI mediation), and `NamedPipeServer` (pipe proxying). Communication via wire protocol headers (`*Wire.h`).

4. **GUI** (`SandboxiePlus/`) — Qt-based management interface with sandbox configuration, monitoring, and snapshot management.

### Crate — OS-Level Jail Isolation

Crate delegates isolation entirely to the FreeBSD kernel:

1. **Single binary** — A setuid C++ program that orchestrates jail lifecycle: create container images from FreeBSD base + packages, run them as jails with VNET networking.

2. **Jail isolation** — Uses `jail_setv()` to create jails with process, filesystem, and network namespace isolation. No API hooking required — the kernel enforces boundaries.

3. **VNET networking** — Creates `epair` virtual interfaces, assigns IP addresses (10.x.y.z scheme), and configures `ipfw` NAT rules for outbound connectivity and optional inbound port forwarding.

4. **Filesystem** — Uses `nullfs` bind mounts for shared directories/files and `devfs` for device access inside the jail. Container images are compressed tarballs (xz).

## Feature Comparison

| Aspect | SandboxieCrack (Windows) | Crate (FreeBSD) |
|--------|--------------------------|------------------|
| **Core isolation** | Kernel driver (`drv/`) + DLL hooks (`dll/`) — syscall interception | FreeBSD jails via `jail_setv()` — kernel-enforced namespaces |
| **File virtualization** | Path translation + copy-on-write (`file.c`, `file_xlat.c`) with TRUE_PATH/COPY_PATH semantics | Full separate rootfs (tarball) + `nullfs` bind mounts for sharing |
| **Registry/Config isolation** | Registry hive redirection (`key.c`, `key_flt.c`) with key filtering | N/A — FreeBSD has no registry; per-jail `/etc` suffices |
| **Network isolation** | WFP per-process filtering (`wfp.c`) + DNS hooking (`dns_filter.c`) | VNET + `epair` virtual interfaces + `ipfw` NAT (`net.cpp`, `run.cpp`) |
| **Process control** | Token manipulation + privilege dropping (`token.c`, `process.c`), integrity levels | Jail-level process isolation; `jexec` for in-jail execution |
| **IPC isolation** | Named pipe/ALPC filtering (`ipc.c`, `ipc_port.c`), dynamic port blocking | Jail IPC namespace isolation (`allow.sysvipc` control) |
| **GUI isolation** | Window class filtering, clipboard hooks (`gui.c`, `guihook.c`) | X11 socket sharing via `nullfs` mount (no isolation) |
| **API interception** | DLL injection + IAT/inline hooking (`dllhook.c`, `hook_tramp.c`) | Not needed — jail model doesn't require API-level hooks |
| **Encrypted sandboxes** | ImBox encrypted volumes, AES (`crypt.c`, `MountManager.cpp`) | Not implemented |
| **Snapshots** | File snapshots with name scrambling (`file_snapshots.c`) | Not implemented |
| **Resource limits** | Per-sandbox process count limits | Not implemented (FreeBSD RCTL framework available) |
| **Service layer** | C++ wire-protocol services (`svc/`) — process brokering, COM proxy, GUI server | None — single binary handles everything |
| **Templates/Presets** | Box types: Standard, Enhanced Privacy, Data Protection, Application Compartment | None — manual YAML per container |
| **Configuration** | INI-based (`Sandboxie.ini`) with GUI editor and validation | YAML-based (`+CRATE.SPEC`) with programmatic parsing |
| **Package management** | N/A (runs host applications) | FreeBSD `pkg` integration — installs packages into container image |
| **COM/D-Bus services** | COM/DCOM hooking (`com.c`, 101KB) — `CoCreateInstance` interception, DCOM redirection, `COM_IUNKNOWN` proxying | Not implemented (D-Bus per-jail possible) |
| **Clipboard isolation** | Clipboard interception via GUI hooks + `GuiServer` cross-sandbox mediation | Not isolated — shared via X11 socket |
| **Process creation control** | Hooks `CreateProcessW`/`ShellExecuteEx` (`proc.c`, 100KB) — redirects child processes into sandbox | Jail-native — `jexec` for entry, jail boundary enforced by kernel |
| **Syscall interception** | SSDT hooking of 50+ NT syscalls at kernel level | Not needed — FreeBSD jails enforce isolation at kernel level without syscall interception |
| **Container portability** | Sandboxes tied to host installation | Compressed tarballs (`.crate` files) — distributable images |

## Feature Gap Analysis: What Crate Is Missing

Features present in SandboxieCrack but absent from Crate:

1. **Encrypted containers** — SandboxieCrack provides ImBox encrypted volumes with AES; Crate has no encryption support.

2. **Snapshot management** — SandboxieCrack supports file-level snapshots with parent-child chains; Crate has no snapshot mechanism.

3. **Per-container resource limits** — SandboxieCrack limits process counts per sandbox; Crate doesn't enforce resource constraints (though FreeBSD's RCTL framework could provide this).

4. **DNS filtering** — SandboxieCrack hooks DNS resolution per-sandbox with domain pattern matching; Crate only configures basic NAT networking.

5. **Configuration templates** — SandboxieCrack offers predefined security profiles (Privacy, Data Protection, etc.); Crate requires manual YAML authoring.

6. **GUI management** — SandboxieCrack has a full Qt GUI for sandbox management; Crate is CLI-only.

7. **Configuration validation** — SandboxieCrack validates settings with contextual tooltips; Crate has basic spec validation only.

8. **Copy-on-write filesystem** — SandboxieCrack transparently redirects file writes to sandbox copies; Crate uses full rootfs copies without COW.

9. **GUI/Desktop isolation** — SandboxieCrack filters window operations, isolates desktops, and mediates cross-sandbox GUI access via GuiServer; Crate shares the host X11 socket without any isolation.

10. **Clipboard isolation** — SandboxieCrack provides per-sandbox clipboard buffers with configurable cross-sandbox paste policies; Crate has no clipboard isolation.

11. **COM/D-Bus service isolation** — SandboxieCrack intercepts COM activation and proxies DCOM objects; Crate has no D-Bus or service bus isolation.

## Strengths of Each Approach

### SandboxieCrack Strengths

- **Application transparency** — Sandboxed applications run unmodified; API hooking makes the sandbox invisible to apps.
- **Fine-grained control** — Per-process, per-file, per-registry-key policies. Can allow/deny individual API calls.
- **No rootfs duplication** — Shares the host OS; only modified files are copied (copy-on-write). Lightweight on disk.
- **Mature feature set** — 20+ years of development. Encryption, snapshots, resource limits, DNS filtering, COM proxying.
- **Integration depth** — Deep Windows integration: shell context menus, "Run Sandboxed" option, auto-start programs.

### Crate Strengths

- **Kernel-enforced isolation** — Jails are a kernel primitive. No userspace hooks to bypass — stronger security boundary.
- **Full network stack isolation** — VNET gives each container its own network stack, routing table, and firewall. SandboxieCrack only filters at the WFP level.
- **Portability** — Container images (`.crate` files) are self-contained tarballs. Easy to distribute and reproduce.
- **Simplicity** — Single binary, ~2000 lines of C++. Easy to audit and reason about security properties.
- **Native packaging** — Leverages FreeBSD `pkg` ecosystem for building container images with specific software.
- **Script hooks** — YAML spec supports shell scripts at 10 lifecycle points (before/after jail creation, user setup, service start, etc.).
- **No kernel module required** — Uses only standard FreeBSD jail/VNET/ipfw facilities. No custom kernel code.
- **ZFS-ready ecosystem** — FreeBSD's ZFS support enables potential COW, snapshots, and encryption without application changes.
