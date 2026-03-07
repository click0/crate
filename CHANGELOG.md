# Changelog

All notable changes to **crate** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.2.5] — 2026-03-07

### Added
- **Native FreeBSD API wrappers** — replace fork+exec shell commands with
  direct library calls where available:
  - `lib/jail_query.{cpp,h}` — libjail `jailparam_*` API replaces `jls(8)` parsing
  - `lib/zfs_ops.{cpp,h}` — libzfs/libzfs_core replaces `zfs(8)` commands
  - `lib/ifconfig_ops.{cpp,h}` — libifconfig replaces `ifconfig(8)` commands
  - `lib/pfctl_ops.{cpp,h}` — libpfctl replaces `pfctl(8)` commands
  - `lib/mac_ops.{cpp,h}` — ugidfw ioctl + `sysctlbyname()` replaces `ugidfw(8)`
  - `lib/ipfw_ops.{cpp,h}` — ipfw wrapper (native `IP_FW3` planned)
  - `lib/capsicum_ops.{cpp,h}` — libcasper for `cap_enter()`, `cap_dns`, `cap_syslog`
  - `lib/netgraph_ops.{cpp,h}` — `PF_NETGRAPH` socket replaces `ngctl(8)`
  - `lib/nv_protocol.{cpp,h}` — libnv nvlist IPC over Unix socket
  - `lib/vm_spec.{cpp,h}` — YAML parsing for `type: vm` (bhyve) spec
  - `lib/vm_run.{cpp,h}` — libvirt bhyve driver for VM lifecycle
  - `lib/vnc_server.{cpp,h}` — libvncserver embedded VNC (replaces x11vnc fork)
  - `lib/x11_ops.{cpp,h}` — libX11/XRandR for display management
  - `lib/drm_session.{cpp,h}` — libseat for DRM session without suid
- `JailExec` namespace — `jail_attach()` with automatic `jexec(8)` fallback
- Compile-time feature flags: `HAVE_LIBZFS`, `HAVE_LIBIFCONFIG`,
  `HAVE_LIBPFCTL`, `HAVE_CAPSICUM`, `WITH_LIBVIRT`, `WITH_LIBVNCSERVER`,
  `WITH_X11`, `WITH_LIBSEAT`
- All wrappers fall back to shell commands when compiled without optional flags

### Changed
- `list.cpp` — use `JailQuery::getAllJails()` instead of `jls -N` parsing
- `info.cpp` — use `JailQuery` for jail lookup + `JailExec` for in-jail commands
- `console.cpp` — use `JailQuery` for container resolution
- `clean.cpp` — use `JailQuery::getAllJails()` for running jail enumeration
- `export.cpp` — use `JailQuery` for container resolution
- `run.cpp` — use `JailQuery`, `JailExec`, `ZfsOps`, `MacOps` throughout
- `run_jail.cpp` — use `ZfsOps::jailDataset()`/`unjailDataset()`
- `run_net.cpp` — use `IfconfigOps`, `NetgraphOps`, `PfctlOps`
- `snapshot.cpp` — use `ZfsOps` for all ZFS snapshot operations
- `util.cpp` — delegate `isZfsEncrypted()`/`isZfsKeyLoaded()` to `ZfsOps`
- Makefile updated with optional library flags and P2-P4 source files

---

## [0.2.4] — 2026-03-07

### Fixed
- `spec.cpp` — remove dead `listOrScalarOnly()` call before `ERR` in pkg/add handler
- `run_gui.cpp` — X11 shared mode security warning now respects `logProgress` flag
  and no longer produces double output
- `config.cpp` — silent `catch(...)` blocks now emit `WARN()` messages for
  config parsing errors (system config, drop-in fragments, user config)

### Added
- `snmpd/mib.cpp` — AgentX stub warning at startup

---

## [0.2.3] — 2026-03-06

### Added
- `--var KEY=VALUE` command-line substitution for spec variables
- Healthcheck support (`healthcheck:` spec section) with configurable
  retries, interval, timeout, and start period
- `depends:` spec section for container dependency ordering
- `crate stack` command for multi-container orchestration
- Healthcheck runtime — background monitoring, retry reporting, service-only
  crate health loop
- Enhanced `crate list` with ports, mounts, and healthcheck columns
- URL fetch support for remote crate archives
- `base_container:` spec section for ZFS-clone-based container templates
- jailrun (hyphatech) comparison analysis in `docs/research/`

### Fixed
- Healthcheck retry counter off-by-one
- Timeout enforcement missing on healthcheck commands
- SIGINT handler typo in service-only crate run loop

### Changed
- Comparison docs moved to `docs/research/`

---

## [0.2.2] — 2026-03-05

### Added
- **Networking expansion** (7 phases):
  - Bridge mode with DHCP and static IP (Phase 1)
  - Static MAC address generation and VLAN support (Phase 2)
  - Passthrough mode for direct NIC assignment (Phase 3)
  - Netgraph mode with ng_bridge + eiface (Phase 4)
  - IPv6 SLAAC and static IPv6 support (Phase 5)
  - Multiple interfaces via `extra[]` config (Phase 6)
  - System config defaults and network mode templates (Phase 7)
- Named networks in system config `/usr/local/etc/crate.conf`
- `/usr/local/etc/crate.d/` drop-in config fragment support
- `loader.conf` tunable comment for VNET/VIMAGE sysctl
- Comprehensive `TODO-IMPROVEMENTS.md`

### Changed
- README.md and README_UK.md fully rewritten
- crate.5 manpage updated with new networking modes
- Docs: compatibility section — FreeBSD 13.0+ supported

---

## [0.2.1] — 2026-03-04

### Added
- **crate-snmpd** — AgentX SNMP subagent with CRATE-MIB (F3)
- **crate-hub** — multi-host aggregator dashboard skeleton (F4)
- **crated** — REST API daemon skeleton (F1)
- **libcrate.a** — extracted shared library from monolithic binary (F0)
- GUI session manager for multi-container display switching
  - GPU headless mode, 7 GUI mode example configs
- `gui` command (11th subcommand)

### Fixed
- 9 bugs in GUI manager — security, correctness, reliability
- 6 issues in GPU headless mode
- Duplicated jail/networking code removed, uses RunNet/RunJail modules
- Export/import commands wired into build and dispatch
- License corrected: ISC → BSD 3-Clause in docs

---

## [0.2.0] — 2026-03-03

### Added
- **Phase 1**: IPC controls, RCTL resource limits, `crate validate` command
- **Phase 2**: ZFS snapshots, encrypted containers, DNS filtering,
  security hardening
- **Phase 3**: COW filesystem (ZFS + unionfs), templates, X11 isolation
  (shared/nested/headless/gpu), D-Bus isolation, managed services, socket proxy
- **Phase 4**: PF firewall anchors, Capsicum/MAC stubs, template merging,
  clipboard proxy, terminal isolation
- **Phase 5**: FreeBSD 15.0 compatibility — version-mismatch detection
- **Phase 6**: Code cleanup, pkgbase support, dynamic ipfw rule allocation
- `list`, `info`, `clean`, `console`, `export`, `import` commands
- IPv6 pass-through networking
- Security hardening — securelevel, children.max, cpuset
- UX improvements — `NO_COLOR`, `--version`, shell completions
- Modularized `run.cpp` into `run_net.cpp`, `run_jail.cpp`, `run_gui.cpp`,
  `run_services.cpp`
- 3-tier config: system → drop-in → user YAML

---

## [0.1.x] — 2024–2025 (pre-fork history)

### Added
- Core jail containerization with `jail_setv()` / `jail_remove()`
- VNET networking with epair + ipfw NAT
- Crate archive format (tar.xz with `+CRATE.SPEC`)
- Variable substitution in scripts (`$HOME`, `$USER`)
- Examples: qbittorrent, qbittorrent+tor
- GitHub Actions CI for FreeBSD build testing
- FreeBSD 15.0 jail descriptor API (`JAIL_OWN_DESC`)

### Security
- Command injection hardening — exec-based process execution
- USER env spoofing prevention — `getpwuid(getuid())`
- Directory traversal validation for shared dirs/files
- RAII resource cleanup (`RunAtEnd`, `UniqueFd`)
- SIGINT/SIGTERM signal handling for clean jail shutdown
- Unpredictable jail directory names (random hex)

### Fixed
- Build fix for FreeBSD 11.3 (`_WITH_GETLINE`)
- `sys/jail.h` C++ safety with `extern "C"` wrapper
- Resource leaks — RAII popen, strdup in mount, pointer in ctx
- Base.txz URL for releases vs snapshots
