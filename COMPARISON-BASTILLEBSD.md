# Crate vs BastilleBSD — Detailed Comparison

> Updated version (March 2026). Previous versions: [20250228](COMPARISON-BASTILLEBSD_20250228.md), [v1-pre-2025](COMPARISON-BASTILLEBSD-v1-pre-2025.md).

## General Overview

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **Purpose** | FreeBSD containerizer — packages applications and services into isolated, self-contained "crates" | Automation system for deploying and managing containerized applications on FreeBSD |
| **Language** | C++17 (~4,000 lines) | Shell scripts (POSIX sh) |
| **License** | ISC | BSD |
| **Status** | Alpha (since 2019, active development) | Stable (v1.4.0, active development since 2018) |
| **Philosophy** | Minimalist disposable application containers; focus on desktop applications and GUI with deep isolation | Full-featured jail manager for servers and infrastructure; DevOps-oriented |
| **Dependencies** | yaml-cpp, libjail, librang | Only the base FreeBSD system (sh, jail, zfs, pkg) |

---

## Architecture and Operating Model

### Crate — "Package and Run"
```
spec.yml → [crate create] → myapp.crate (XZ archive)
                                  ↓
                            [crate run]
                                  ↓
                    Temporary jail + ZFS COW + network + firewall
                                  ↓
                          Application execution
                                  ↓
              RAII cleanup (jail, mount, firewall, epair, ZFS)
```
- **Ephemeral model**: jail is created at launch and destroyed after completion
- 11 commands: `create`, `run`, `validate`, `snapshot`, `list`, `info`, `console`, `clean`, `export`, `import`, `gui`
- Aggressive optimization: ELF dependency analysis via ldd, removal of unnecessary files
- Container is a self-contained XZ archive (`.crate`)
- RAII patterns (RunAtEnd) guarantee cleanup even on errors and signals

### BastilleBSD — "Create and Manage"
```
bastille bootstrap 14.2-RELEASE → base release
bastille create myjail 14.2-RELEASE 10.0.0.1 → persistent jail
bastille start/stop/restart myjail → lifecycle management
bastille template myjail user/template → configuration automation
```
- **Persistent model**: jails are long-lived, managed as services
- 39 subcommands for full lifecycle management
- Jails are stored on disk (ZFS or UFS)
- Support for thin and thick jails

---

## CLI Commands

### Crate (11 commands)
| Command | Description |
|---|---|
| `crate create -s spec.yml -o app.crate` | Create a container from a specification |
| `crate create -s spec.yml --template base.yml` | Create with template inheritance |
| `crate create -s spec.yml --use-pkgbase` | Create via pkgbase (FreeBSD 16+) |
| `crate run -f app.crate [-- args]` | Run a container |
| `crate validate -s spec.yml` | Validate a specification |
| `crate snapshot create\|list\|restore\|delete\|diff` | Manage ZFS snapshots |
| `crate list [-j]` | List running containers (table or JSON) |
| `crate info TARGET` | Information about a running container |
| `crate console TARGET [--user USER]` | Interactive shell in a container |
| `crate clean` | Clean up temporary files and jails |
| `crate export TARGET [-o FILE]` | Export a running container to .crate (with SHA256) |
| `crate import FILE [-o FILE] [--force]` | Import .crate with validation (SHA256, traversal, OS version) |
| `crate gui list\|focus\|attach\|url\|tile\|screenshot\|resize` | GUI session manager (switching, tiling, screenshots) |

### BastilleBSD (39 subcommands)
| Command | Description |
|---|---|
| `bastille bootstrap` | Download a FreeBSD/HardenedBSD/MidnightBSD/Linux release or template |
| `bastille create` | Create a jail (thin/thick/clone/empty/linux) |
| `bastille start/stop/restart` | Startup management |
| `bastille destroy` | Delete a jail or release |
| `bastille console` | Enter a jail (interactive session) |
| `bastille cmd` | Execute a command inside a jail |
| `bastille clone` | Clone a jail (including live via ZFS, `-l`) |
| `bastille rename` | Rename a jail |
| `bastille migrate` | Migrate a jail to a remote server (live for ZFS, `-l`) |
| `bastille export/import` | Export/import jails (7 formats: txz/tgz/tzst/raw/gz/xz/zst; compatible with iocage, ezjail) |
| `bastille template` | Apply a template (Bastillefile) to a jail |
| `bastille pkg` | Package management (pkg/apt for Linux) |
| `bastille service` | Service management |
| `bastille mount/umount` | Volume mounting (including ZFS mount) |
| `bastille network` | Add/remove network interfaces (since v0.14) |
| `bastille rdr` | Port redirection via pf (with IPv6, v1.4) |
| `bastille limits` | Resource limits (rctl + cpuset) |
| `bastille list` | List jails, releases, templates (JSON, priorities) |
| `bastille config` | Get/set jail properties |
| `bastille update/upgrade` | Update a jail |
| `bastille tags` | Labels for jails (tags as TARGET) |
| `bastille zfs` | ZFS management (snapshot/rollback/jail/unjail/df) |
| `bastille top/htop` | Process monitoring |
| `bastille monitor` | Service watchdog with auto-restart (cron-based, since v1.0) |
| `bastille cp/jcp/rcp` | File copying (host↔jail, jail↔jail) |
| `bastille convert` | Conversion thin↔thick |
| `bastille etcupdate` | Update /etc |
| `bastille verify` | Verify a release |
| `bastille setup` | Host auto-configuration (loopback, bridge, vnet, netgraph, firewall, storage, linux) |
| `bastille edit` | Edit jail configuration |
| `bastille sysrc` | Safely edit rc files |

**Conclusion**: BastilleBSD provides a significantly broader set of commands (39) for managing the full jail lifecycle. Crate has 11 commands covering build, run, validation, snapshot management, listing, inspection, interactive console, export/import, cleanup, and GUI session management.

---

## Jail Types

| Type | **Crate** | **BastilleBSD** |
|---|---|---|
| Thin (shared base) | No — each .crate is fully self-contained | **Yes** (default) — shared base system via nullfs |
| Thick (independent) | Effectively yes — each .crate contains a full copy | **Yes** (`-T` flag) |
| Clone | **Yes** (ZFS COW clone at runtime) | **Yes** (`-C` flag, ZFS clone; `-l` for live clone) |
| Empty | No | **Yes** (`-E` flag) — for custom builds |
| Linux jails | No | **Yes** (`-L`, Ubuntu Noble/Focal/Bionic, Debian; without VNET) |
| Multi-OS | FreeBSD only | **Yes** (FreeBSD, HardenedBSD, MidnightBSD, Linux) |

---

## Data Storage and ZFS

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Native ZFS integration** | **Yes** | **Yes** (`zfs` subcommand) |
| **ZFS snapshots** | **Yes** (`crate snapshot create/list/restore/delete/diff`) | **Yes** |
| **ZFS clone (COW)** | **Yes** (automatic with `cow/backend: zfs`) | **Yes** (for thin jails; live clone via `-l`) |
| **ZFS encryption** | **Yes** (`encrypted: true` in spec, verified at runtime) | No (encryption at pool level) |
| **ZFS datasets in jail** | **Yes** (`zfs-datasets:` in YAML, `allow.mount.zfs`) | **Yes** (`bastille zfs jail`, v1.0+) |
| **ZFS send/recv** | No | **Yes** (live export without stopping jail, migrate) |
| **Copy-on-Write (COW)** | **Yes** (ZFS clone or unionfs, ephemeral/persistent modes) | Via ZFS clone |
| **UFS** | Yes (default) | **Yes** |
| **Shared dirs** | Yes (nullfs in YAML) | Yes (`bastille mount`) |
| **Shared files** | Yes (hardlink + fallback mount) | Via mount |
| **Container format** | `.crate` (XZ archive) | Directory on the filesystem |
| **Export formats** | `.crate` (XZ) | 7 formats: `.txz`, `.tgz`, `.tzst`, `.raw`, `.gz`, `.xz`, `.zst` |
| **Size optimization** | **Yes** (ELF analysis, stripping unnecessary files) | No (full system) |
| **ZFS options on creation** | No | Yes (`-Z "compression=lz4,atime=off"`, v0.14+) |
| **pkgbase (FreeBSD 16+)** | **Yes** (`--use-pkgbase` flag) | **Yes** (`bootstrap --pkgbase`) |

**Conclusion**: Crate has full-featured ZFS integration, including snapshots, COW clones, encryption, and dataset attachment to jails. BastilleBSD leads in ZFS send/recv for migration and export format variety (7 formats).

---

## Networking

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **VNET** | Yes (epair, automatic configuration) | Yes (5 modes: -V, -B, -P, alias, inherit) |
| **Physical interface** | No | Yes (`-V` — auto-create bridge + epair) |
| **Bridge** | No | Yes (`-B` — connect to existing bridge) |
| **Passthrough** | No | Yes (`-P` — direct interface passthrough, v1.1+) |
| **Netgraph** | No | Yes (`bastille setup netgraph`, alternative VNET backend to if_bridge, v1.0+) |
| **NAT** | Yes (ipfw NAT, automatic rules) | Via pf loopback NAT (`bastille rdr`) |
| **Port forwarding** | Yes (inbound-tcp/udp in YAML) | Yes (`bastille rdr`, +IPv6 in v1.4) |
| **IP addressing** | Automatic (10.0.0.0/8, up to ~8M containers) | Manual or DHCP (SYNCDHCP/SLAAC for VNET) |
| **DNS** | **Optional forwarding + DNS filtering** | Via `bastille edit resolv.conf` |
| **Outbound control** | **Yes** (wan/lan/host/dns granularity) | Via firewall rules (pf/ipfw) |
| **VLAN** | No | Yes (`--vlan ID`, v0.14+) |
| **Static MAC** | No | Yes (`-M` flag) |
| **IPv6** | **Yes** (epair IPv6 fd00:crate::/64, ipfw ip6, pf inet6, routing) | **Yes** (dual-stack `-D`, SLAAC, IPv6 rdr in v1.4) |
| **Dynamic epair** | **Yes** (`ifconfig epair create`, auto-numbered) | **Yes** (`e0a_jailname`/`e0b_jailname`, v1.0+) |
| **DHCP/SYNCDHCP** | No | **Yes** (for VNET jails, including SYNCDHCP) |
| **Multiple interfaces** | No | Yes (`bastille network add/remove`, v0.14+) |
| **Checksum offload workaround** | **Yes** (FreeBSD 15.0 epair bug) | No data |

**Conclusion**: Crate provides convenient automatic network management with full IPv6 support (epair IPv6, ipfw ip6, pf inet6), granular outbound traffic control, and DNS filtering. BastilleBSD offers significantly more networking modes (5 types + netgraph), DHCP, VLAN, static MAC, and enterprise-level configurations.

---

## Firewall

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **ipfw** | **Yes** (automatic NAT rules, IPv4 + IPv6) | Yes (manual configuration) |
| **pf** | **Yes** (per-container pf anchor, §3, with inet6) | **Yes** (native integration) |
| **Per-container policy** | **Yes** (`firewall:` section in YAML: block_ip, allow_tcp/udp, default_policy) | Via pf rules |
| **Dynamic slots** | **Yes** (FwSlots: unique rule numbers, no conflicts, §18) | pf rdr-anchor with tables |
| **Port forwarding** | In YAML: `inbound-tcp: {3100: 3000}` | `bastille rdr TARGET tcp 80 8080` |
| **Automatic rule cleanup** | **Yes** (RAII, ref-counting for shared rules) | `bastille rdr TARGET list/clear` |
| **ip.forwarding** | Auto-save/restore of original value (IPv4 + IPv6) | Manual configuration |

**Conclusion**: Crate supports both firewalls (ipfw and pf) with IPv4 and IPv6, per-container firewall policy via pf anchors, and automatic ipfw management through dynamic slots. BastilleBSD is oriented toward pf with full anchor and table control.

---

## Graphics and Desktop

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **X11 (shared)** | **Yes** (X11 socket + Xauthority passthrough) | No (not a target use case) |
| **X11 (nested/Xephyr)** | **Yes** (isolated nested X server, §11) | No |
| **X11 (headless/Xvfb)** | **Yes** (virtual framebuffer without physical display) | No |
| **X11 (GPU headless)** | **Yes** (DRM leasing, Xorg with real GPU without monitor) | No |
| **X11 (disabled)** | **Yes** (`mode: none`) | — |
| **VNC** | **Yes** (x11vnc with password, auto-port, §gui) | No |
| **noVNC/WebSocket** | **Yes** (websockify + noVNC for browser access) | No |
| **GUI session manager** | **Yes** (`crate gui`: list/focus/attach/url/tile/screenshot/resize) | No |
| **Clipboard isolation** | **Yes** (modes: isolated/shared/none, direction: in/out/both, §12) | No |
| **D-Bus isolation** | **Yes** (system/session bus control, allow_own/deny_send, §13) | No |
| **OpenGL/GPU** | **Yes** (hardware acceleration) | No |
| **Video devices** | **Yes** (/dev/videoN passthrough) | No |
| **GUI applications** | **Yes** (Firefox, Chromium, Kodi, etc.) | No (server-oriented) |

**Conclusion**: Crate is uniquely positioned for running desktop GUI applications in jails: 5 X11 modes (shared, nested, headless, gpu, none), VNC with password, noVNC via browser, GUI session manager with tiling and screenshots, clipboard filtering, D-Bus control. BastilleBSD is oriented exclusively toward server workloads.

---

## Security

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **securelevel** | **Configurable** (-1 auto/0-3, default=2 in config) | **securelevel = 2** by default |
| **enforce_statfs** | **Configurable** (auto/0/1/2, auto-detection for ZFS) | **2** (fixed) |
| **devfs_ruleset** | **Configurable** (§16, terminal isolation) | Ruleset 4 by default; 13 for VNET |
| **RCTL resources** | **Yes** (any RCTL resources via `limits:` in YAML) | **Yes** (via `bastille limits`) |
| **MAC bsdextended** | **Yes** (ugidfw rules via `security:` in YAML, §8) | No |
| **MAC portacl** | **Yes** (mac_portacl via `security:`, §8) | No |
| **Capsicum** | **Yes** (option in `security:`, §8) | No |
| **raw_sockets** | Configurable (via ipc: section) | **Denied** by default |
| **SysV IPC** | Configurable (`ipc: sysvipc: true`) | No data |
| **allow.mlock** | Configurable | No data |
| **allow.chflags** | Configurable | No data |
| **allow.set_hostname** | Configurable | No data |
| **allow.quotas** | Configurable | No data |
| **children.max** | **Configurable** (default=0, same as BastilleBSD) | 0 (nested jails prohibited) |
| **CPU pinning** | **Yes** (cpuset via `security:` in YAML, `/usr/bin/cpuset -l`) | **Yes** (cpuset via `bastille limits`) |
| **pathnames.h** | **Yes** (absolute paths to all commands, CWE-426, §pathnames) | Bare names (PATH-relative) |
| **Environment sanitization** | **Yes** (environ=empty, restoring only TERM/DISPLAY/LANG) | No |
| **execv vs execvp** | **Yes** (execv — no PATH search) | execvp/system (via shell) |
| **lstat for symlinks** | **Yes** (CWE-59 protection) | No data |
| **Jail descriptor** | **Yes** (JAIL_OWN_DESC for race-free removal, FreeBSD 15+) | No |
| **Archive traversal** | **Yes** (checking `..` in archives before extraction) | No data |
| **Signal-safe cleanup** | **Yes** (SIGINT/SIGTERM → RAII destructors) | Via shell trap |
| **setuid check** | Yes (requires setuid, prohibits running from inside a jail) | Yes (root) |
| **DNS filtering** | **Yes** (per-jail unbound, domain blocking, §4) | No |
| **Socket proxying** | **Yes** (socat-based, share/proxy, §15) | No |
| **Terminal isolation** | **Yes** (devfs ruleset, TTY control, §16) | No data |
| **Directory traversal protection** | **Yes** (Util::safePath check for shared dirs) | No data |

**Conclusion**: Crate offers a significantly deeper multi-layered security model: securelevel (configurable, default=2), children.max (default=0), CPU pinning via cpuset, MAC bsdextended/portacl, Capsicum, DNS filtering, clipboard and D-Bus isolation, pathnames.h for CWE-426, environment sanitization, execv, lstat for symlink attacks, JAIL_OWN_DESC for race-free cleanup. BastilleBSD has good security defaults (securelevel=2) and resource limits.

---

## Templating and Automation

### Crate — YAML Specification with Template Inheritance

```yaml
# spec.yml (§10: templates via --template)
pkg:
    install: [firefox, git]
run:
    command: /usr/local/bin/firefox
options: [net, x11, gl, video]

# ZFS encryption (§1)
encrypted: true

# COW filesystem (§6)
cow:
    backend: zfs        # or unionfs
    mode: ephemeral     # or persistent

# Resource limits (§5)
limits:
    memoryuse: 512M
    pcpu: 50
    maxproc: 100

# DNS filtering (§4)
dns:
    block: ["*.ads.example.com", "tracker.example.net"]
    redirect_blocked: nxdomain

# Per-container firewall (§3)
firewall:
    block_ip: ["192.168.0.0/16"]
    allow_tcp: [80, 443]
    default_policy: block

# X11 isolation (§11)
x11:
    mode: nested        # Xephyr
    resolution: 1920x1080

# Clipboard (§12)
clipboard:
    mode: isolated
    direction: out      # jail → host only

# D-Bus (§13)
dbus:
    session_bus: true
    system_bus: false
    deny_send: ["org.freedesktop.secrets"]

# IPC control (§7)
ipc:
    sysvipc: false
    raw_sockets: false

# Socket proxying (§15)
sockets:
    share: ["/var/run/dbus/system_bus_socket"]
    proxy:
        - host: /tmp/.X11-unix/X0
          jail: /tmp/.X11-unix/X0

# Advanced security (§8)
security:
    capsicum: true
    cpuset: "0-3"
    securelevel: 2
    children_max: 0
    mac_rules: ["subject uid 1001 object not uid 1001 mode rsx"]

# ZFS datasets
zfs-datasets: ["zpool/data/myapp"]

# Lifecycle hooks
scripts:
    run:begin: ["echo 'Starting...'"]
    run:after-create-jail: ["setup.sh"]
    run:before-start-services: ["pre-start.sh"]
    run:after-execute: ["cleanup.sh"]
    run:end: ["echo 'Done'"]

dirs:
    share:
        - [/var/db/myapp, $HOME/myapp/db]
```

Template inheritance (`--template`): the template specification is merged with the user specification via `mergeSpecs()`.

### BastilleBSD — Bastillefile (17 hooks)

```
# Bastillefile
ARG DB_NAME=mydb
ARG+ ADMIN_EMAIL
PKG nginx postgresql15-server
SYSRC nginx_enable=YES
SYSRC postgresql_enable=YES
SERVICE postgresql initdb
SERVICE postgresql start
CMD psql -U postgres -c "CREATE DATABASE ${DB_NAME}"
TEMPLATE /usr/local/etc/nginx/nginx.conf
RENDER /usr/local/etc/nginx/nginx.conf
CP usr/ etc/
LIMITS memoryuse 1G
RDR tcp 8080 80
TAGS web db
```
- Docker-like syntax with 17 hooks: ARG, ARG+, CMD, CONFIG, CP, INCLUDE, LIMITS, LINE_IN_FILE, MOUNT, PKG, RDR, RENDER, RESTART, SERVICE, SYSRC, TAGS, TEMPLATE
- Required arguments (`ARG+`, v1.4+) — abort if missing
- Built-in variables: `${JAIL_NAME}`, `${JAIL_IP}`, `${JAIL_IP6}`
- Templates in Git repositories with subdirectory support (v1.0+)
- Applied to already created jails
- Legacy multi-file format removed (since v1.2.2)

**Conclusion**: Crate describes everything in a single YAML file with deep configuration for security (securelevel, cpuset, children.max, MAC, Capsicum), networking, ZFS, GUI, DNS, and IPC. Supports template inheritance. BastilleBSD uses a Docker-like Bastillefile, more familiar to DevOps practitioners.

---

## Lifecycle Management

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Creation** | Yes (create, +templates, +pkgbase) | Yes (create, with numerous options) |
| **Start** | Yes (run, ephemeral) | Yes (start) |
| **Stop** | Automatic on exit (RAII) | Yes (stop) |
| **Restart** | No (re-creation) | Yes (restart) |
| **ZFS snapshots** | **Yes** (create/list/restore/delete/diff) | **Yes** |
| **Cloning** | **Yes** (COW at runtime) | **Yes** (clone, including live `-l`) |
| **Renaming** | No | Yes (rename) |
| **Migration** | No | **Yes** (migrate, including live via ZFS send/recv + SSH) |
| **OS update** | Rebuild .crate | Yes (update, upgrade, etcupdate) |
| **Export/Import** | **Yes** (`crate export/import` with SHA256, traversal validation, OS version check) | **Yes** (7 formats, compatible with iocage/ezjail) |
| **Listing** | **Yes** (`crate list`, table + JSON output) | **Yes** (list, with priority sorting) |
| **Inspection** | **Yes** (`crate info TARGET`) | Yes (`bastille list`, `bastille config`) |
| **Console** | **Yes** (`crate console TARGET`, jexec-based) | **Yes** (`bastille console`) |
| **Monitoring** | No | **Yes** (top, htop, monitor with auto-restart, cron-based, v1.0+) |
| **Validation** | **Yes** (`crate validate`) | Yes (`bastille verify` for releases) |
| **Cleanup** | **Yes** (`crate clean`) | Via `bastille destroy` |
| **Tags** | No | Yes (tags) |
| **Conversion** | No | Yes (thin↔thick, convert) |
| **File copying** | Via shared dirs/files | **Yes** (cp/jcp/rcp: host↔jail, jail↔jail) |
| **Version mismatch detect** | **Yes** (host vs container FreeBSD version) | No |

**Conclusion**: Crate has a full-featured command set: list, info, console, export/import, clean, validate. BastilleBSD provides a complete jail management lifecycle, including live migration, live cloning, monitoring with auto-restart, and file copying between jails.

---

## Packages and Services

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Package installation** | Yes (in YAML: pkg.install) | Yes (`bastille pkg`) |
| **Local packages** | Yes (pkg.add, pkg.override) | Via cp + pkg |
| **pkgbase** | **Yes** (`--use-pkgbase`) | **Yes** (`--pkgbase`) |
| **Service management** | **Yes** (run.service + managed services §14) | Yes (`bastille service`) |
| **Managed services** | **Yes** (auto-start, auto-stop in reverse order, rc.conf generation) | Via sysrc + service |
| **Multiple services** | Yes | Yes |
| **sysrc** | Via managed services rc.conf | **Yes** (`bastille sysrc`) |
| **Automatic package cleanup** | **Yes** (removal of unused dependencies) | No |
| **Optimization (strip)** | **Yes** (ELF analysis, documentation removal) | No |

---

## DNS Filtering (Unique Crate Feature)

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Per-jail DNS resolver** | **Yes** (unbound, §4) | No |
| **Domain blocking** | **Yes** (wildcard patterns) | No |
| **Redirect blocked** | **Yes** (nxdomain or specific IP) | No |
| **Upstream forwarding** | **Yes** (automatically from host resolv.conf) | — |

---

## IPC and Process Isolation

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **SysV IPC** | **Configurable** (§7) | No data |
| **POSIX mqueue** | **Configurable** (§7) | No data |
| **raw_sockets** | **Configurable** (override via ipc:) | Denied by default |
| **Socket proxying** | **Yes** (socat, share/proxy, §15) | No |
| **D-Bus isolation** | **Yes** (session/system bus, policy, §13) | No |
| **Clipboard control** | **Yes** (isolated/shared, direction, §12) | No |

---

## Batch Operations and Targeting

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Multiple targets** | No (single container) | **Yes** — `ALL`, tags, space-separated lists |
| **Tags** | No | Yes (`bastille tags TARGET tag1 tag2`) |
| **Boot priorities** | No | Yes (`-p` — start/stop ordering) |
| **Dependencies** | No | Yes (beta: dependent jail auto-starts) |
| **JSON output** | **Yes** (`crate list -j`) | **Yes** (`bastille list -j`) |
| **Parallel startup** | No | Yes (`bastille_parallel_limit` in config) |
| **Startup delay** | No | Yes (`bastille_startup_delay`) |

---

## Host Auto-Configuration

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Auto-configuration** | No (manual) | **Yes** (`bastille setup`: loopback, bridge, vnet, netgraph, firewall, storage, linux) |
| **Loopback setup** | No | Yes (`bastille setup loopback`) |
| **Bridge setup** | No | Yes (`bastille setup bridge`) |
| **Netgraph setup** | No | Yes (`bastille setup netgraph`) |
| **Firewall setup** | No | Yes (`bastille setup firewall`) |
| **Linux setup** | No | Yes (`bastille setup linux`) |

**Conclusion**: BastilleBSD has a unique `setup` command that auto-configures the host system for working with jails. Crate requires manual host configuration.

---

## OCI/Docker Compatibility

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **OCI images** | No | **No** |
| **Docker Hub** | No | No |
| **Dockerfile/Containerfile** | No | No (Bastillefile — proprietary system) |
| **Export format** | `.crate` (XZ) | 7 formats (txz/tgz/tzst/raw/gz/xz/zst) |

Both systems operate exclusively within the FreeBSD jail ecosystem. For OCI containers on FreeBSD, **Podman + ocijail** is recommended.

---

## API and Web Interface

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **REST API** | No | **Yes** (bastille-api, JSON payloads, since v1.0) |
| **Web interface** | No | **Yes** (bastille-ui — Go + HTML, with ttyd terminal) |
| **Companion tools** | No | **Rocinante** — applies Bastillefile to the host |
| **Nomad Driver** | No | Planned (roadmap 2.0.x) |

---

## FreeBSD 15.0+ Compatibility

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **JAIL_OWN_DESC** | **Yes** (race-free jail removal via owning descriptor) | No data |
| **epair checksum fix** | **Yes** (disable txcsum/txcsum6 workaround) | No data |
| **Version mismatch warning** | **Yes** (warning when host ≠ container FreeBSD version) | No data |
| **ipfw compat warning** | **Yes** (FreeBSD 15.0 removed old ipfw compat code) | No data |
| **getgroups(2) change** | **Yes** (adjusted for setgroups behavior change) | No data |

---

## Summary Table

| Criterion | **Crate** | **BastilleBSD** |
|---|---|---|
| Maturity | Alpha (active development) | Stable (v1.4.0, February 2026) |
| Jail model | Ephemeral (+ COW persistent) | Persistent |
| GUI/Desktop | **Superior** (5 X11 modes, VNC, noVNC, GUI manager, clipboard, D-Bus) | Not supported |
| Server management | Minimal | **Superior** |
| ZFS integration | **Full** (snapshots, COW, encryption, datasets) | **Full** (+ send/recv, migrate, 7 formats) |
| Security (depth) | **Superior** (securelevel, cpuset, children.max, pathnames.h, env, MAC, Capsicum, DNS, execv) | Good defaults (securelevel=2) |
| Network modes | 1 (epair+NAT) + IPv6 + pf anchors | 5+ (VNET, bridge, passthrough, alias, inherit + netgraph) |
| IPv6 | **Yes** (epair IPv6, ipfw ip6, pf inet6) | **Yes** (dual-stack, SLAAC, rdr) |
| Container size | **Optimized** (ELF analysis) | Full system |
| Migration | No | **Yes (including live)** |
| Templates | YAML specification with inheritance | Bastillefile (Docker-like) |
| Number of commands | 11 (+snapshot, gui subcommands) | 39 |
| Linux jails | No | Yes (Ubuntu Noble/Focal/Bionic, Debian) |
| Multi-OS | No | Yes (FreeBSD, HardenedBSD, MidnightBSD, Linux) |
| Monitoring | No | Yes (monitor with auto-restart, cron-based) |
| Resource limits (RCTL) | **Yes** | **Yes** |
| CPU pinning (cpuset) | **Yes** | **Yes** |
| DNS filtering | **Yes** | No |
| Clipboard/D-Bus/Socket | **Yes** | No |
| Tor | Yes | Via templates |
| API/Web UI | No | **Yes** (bastille-api + bastille-ui) |
| JSON output | **Yes** (`crate list -j`) | **Yes** (`bastille list -j`) |
| Host auto-config | No | **Yes** (`bastille setup`) |
| Ecosystem | Examples (Firefox, Kodi...) | Template repository + bastille-ui |
| FreeBSD 15.0+ ready | **Yes** (JAIL_OWN_DESC, epair fix) | No data |
| pkgbase (FreeBSD 16+) | **Yes** | **Yes** |

---

## When to Use Which?

### Crate is better suited for:
- Running **desktop GUI applications** in an isolated environment (Firefox, Chromium, Kodi)
- **Sandboxing** with deep isolation (clipboard, D-Bus, DNS, MAC, Capsicum)
- **Disposable** isolated execution environments
- Minimizing container size (ELF dependency optimization)
- Scenarios requiring **X11/OpenGL/video** with isolation (5 modes: shared, nested, headless, gpu, none)
- **Remote access** to GUI via VNC/noVNC (browser-based access)
- Managing **multiple GUI sessions** (tiling, focus, screenshots)
- Applications with **ZFS encryption** at-rest requirements
- Per-container **DNS filtering** (blocking ad/tracking domains)
- Scenarios with high **security** requirements (securelevel, cpuset, CWE-426, CWE-59, MAC)
- **Inspecting and exporting** running containers (`list`, `info`, `console`, `export`)

### BastilleBSD is better suited for:
- **Server infrastructure** and DevOps
- Managing **multiple** long-lived jails (tags, priorities, dependencies)
- **Migrating** jails between servers (including live)
- Automation via **templates** (CI/CD)
- Granular **resource** control (CPU pinning, rctl)
- Compatibility with other jail managers (iocage, ezjail import)
- Working with **Linux jails** and multiple operating systems
- Scenarios requiring a **REST API** and programmatic management
- Multiple **networking modes** (bridge, passthrough, VLAN, DHCP, netgraph)
- **Host auto-configuration** (`bastille setup`)
- **Monitoring** with automatic service restart

---

## What Crate Could Borrow from BastilleBSD

1. ~~**ZFS integration**~~ ✅ Implemented (snapshots, COW, encryption, datasets)
2. ~~**Resource limits**~~ ✅ Implemented (RCTL via `limits:` in YAML)
3. ~~**Container listing**~~ ✅ Implemented (`crate list` with table/JSON output)
4. ~~**Export/Import**~~ ✅ Implemented (`crate export/import` with SHA256, traversal validation)
5. ~~**IPv6**~~ ✅ Implemented (epair IPv6, ipfw ip6, pf inet6)
6. ~~**CPU pinning**~~ ✅ Implemented (cpuset via `security:` in YAML)
7. **Persistent mode** — option to preserve a jail between runs (COW persistent is a step in this direction)
8. **Thin jails** — saving space through a shared base system
9. **Bridge/Passthrough/Netgraph** — additional networking modes
10. **VLAN support** — `--vlan ID` for network segmentation
11. **Static MAC** — fixed MAC addresses for DHCP stability
12. **Multiple network interfaces** — `network add/remove`
13. **DHCP/SYNCDHCP** — automatic IP addressing for VNET jails
14. **Live migration** — transferring a running container to another host (ZFS send/recv + SSH)
15. **Tags/labels** — grouping containers by tags
16. **Batch operations** — `ALL`, tags as TARGET, multiple targets
17. **Boot priorities** — start/stop ordering for jails
18. **Monitoring with auto-restart** — service watchdog with cron
19. **Host auto-configuration** — `setup`-like command
20. **REST API** — programmatic interface for integration
21. **File copying** — cp/jcp/rcp for runtime file transfer

## What BastilleBSD Could Borrow from Crate

1. **pathnames.h** — absolute paths to commands (CWE-426 protection)
2. **Environment sanitization** — protection against LD_PRELOAD/PATH injection
3. **execv instead of execvp** — eliminating PATH search in setuid context
4. **DNS filtering** — per-jail blocking of unwanted domains
5. **GUI/Desktop isolation** — nested X11, clipboard control, D-Bus isolation
6. **MAC bsdextended** — granular access rules via ugidfw
7. **Capsicum** — capability-based security for additional isolation
8. **COW filesystem** — transparent COW for ephemeral operations
9. **ZFS encryption** — support for encrypted datasets out of the box
10. **Archive traversal validation** — checking `..` before extraction
11. **JAIL_OWN_DESC** — race-free jail removal via owning descriptor
12. **ELF optimization** — aggressive container size reduction
13. **Signal-safe RAII cleanup** — guaranteed cleanup on SIGINT/SIGTERM
14. **Automatic IPv6 configuration** — fully automatic IPv6 epair setup
