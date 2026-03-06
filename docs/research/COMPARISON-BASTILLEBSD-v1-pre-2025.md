# Crate vs BastilleBSD — Detailed Comparison

## General Overview

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **Purpose** | FreeBSD containerizer — packages applications and services into isolated self-contained "crates" | System for automating deployment and management of containerized applications on FreeBSD |
| **Language** | C++17 (~3,066 lines) | Shell scripts (POSIX sh) |
| **License** | BSD 3-Clause | BSD |
| **Status** | Alpha (since June 2019) | Stable (v1.3.x, active development since 2018) |
| **Philosophy** | Minimalist disposable application containers; focus on desktop applications and GUI | Full-featured jail manager for servers and infrastructure; DevOps-oriented |
| **Dependencies** | yaml-cpp, libjail, librang | Only the FreeBSD base system (sh, jail, zfs, pkg) |

---

## Architecture and Operating Model

### Crate — "Package and Run"
```
spec.yml → [crate create] → myapp.crate (XZ archive)
                                  ↓
                            [crate run]
                                  ↓
                    Temporary jail + network + mounts
                                  ↓
                          Application execution
                                  ↓
                    Full cleanup (jail is destroyed)
```
- **Ephemeral model**: jail is created at launch and destroyed after completion
- Two commands: `create` and `run`
- Aggressive optimization: ELF dependency analysis via ldd, removal of unnecessary files
- Container is a self-contained XZ archive (`.crate`)

### BastilleBSD — "Create and Manage"
```
bastille bootstrap 14.2-RELEASE → base release
bastille create myjail 14.2-RELEASE 10.0.0.1 → persistent jail
bastille start/stop/restart myjail → lifecycle management
bastille template myjail user/template → configuration automation
```
- **Persistent model**: jails are long-lived, managed as services
- 35+ subcommands for complete lifecycle management
- Jails are stored on disk (ZFS or UFS)
- Support for thin and thick jails

---

## CLI Commands

### Crate (2 commands)
| Command | Description |
|---|---|
| `crate create -s spec.yml -o app.crate` | Create a container from a specification |
| `crate run -f app.crate [-- args]` | Run a container |
| `crate spec.yml` | Shorthand for create |
| `crate app.crate` | Shorthand for run |

### BastilleBSD (35+ subcommands)
| Command | Description |
|---|---|
| `bastille bootstrap` | Download a FreeBSD release or template |
| `bastille create` | Create a jail (thin/thick/clone/empty/linux) |
| `bastille start/stop/restart` | Startup management |
| `bastille destroy` | Delete a jail or release |
| `bastille console` | Enter a jail (interactive session) |
| `bastille cmd` | Execute a command inside a jail |
| `bastille clone` | Clone a jail |
| `bastille rename` | Rename a jail |
| `bastille migrate` | Migrate a jail to a remote server |
| `bastille export/import` | Export/import jails (compatible with iocage, ezjail) |
| `bastille template` | Apply a template to a jail |
| `bastille pkg` | Package management inside a jail |
| `bastille service` | Service management |
| `bastille mount/umount` | Volume mounting |
| `bastille network` | Network interface management |
| `bastille rdr` | Port forwarding (host → jail) |
| `bastille limits` | Resource limits (rctl/cpuset) |
| `bastille list` | List jails, releases, templates |
| `bastille config` | Get/set jail properties |
| `bastille update/upgrade` | Jail updates |
| `bastille tags` | Labels for jails |
| `bastille zfs` | ZFS management for jails |
| `bastille top/htop` | Process monitoring |
| `bastille cp/jcp/rcp` | File copying (host↔jail, jail↔jail) |
| `bastille convert` | Conversion between thin↔thick |
| `bastille etcupdate` | Update /etc |
| `bastille verify` | Release verification |
| `bastille setup` | Auto-configure network, firewall, storage |
| `bastille edit` | Edit jail configuration |
| `bastille sysrc` | Safe editing of rc files |

**Conclusion**: BastilleBSD provides a significantly broader set of commands for managing the complete jail lifecycle. Crate focuses on two operations — build and run.

---

## Jail Types

| Type | **Crate** | **BastilleBSD** |
|---|---|---|
| Thin (thin/shared base) | No — each .crate is fully self-contained | **Yes** (default) — shared base system via nullfs |
| Thick (thick/independent) | Effectively yes — each .crate contains a full copy | **Yes** (`-T` flag) |
| Clones (clone) | No | **Yes** (`-C` flag, ZFS clone) |
| Empty (empty) | No | **Yes** (`-E` flag) — for custom builds |
| Linux jails | No | **Yes** (`-L`, experimental, via debootstrap) |

---

## Networking

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **VNET** | Yes (epair) | Yes (3 modes: -V, -B, -P) |
| **Physical interface** | No | Yes (`-V` — bind to physical interface) |
| **Bridge** | No | Yes (`-B` — connect to existing bridge) |
| **Passthrough** | No | Yes (`-P` — pass interface into jail) |
| **NAT** | Yes (ipfw NAT, automatic rules) | Via pf/ipfw (manual configuration or rdr) |
| **Port forwarding** | Yes (inbound-tcp/udp in YAML) | Yes (`bastille rdr`) |
| **IP addressing** | Auto (10.0.0.0/8 based on container ID) | Manual (specified at creation) |
| **DNS** | Optional forwarding | Configuration via `-n` flag |
| **Outbound control** | Yes (wan/lan/host/dns granularity) | Via firewall rules (pf/ipfw) |
| **VLAN** | No | Yes (`-v` flag) |
| **Static MAC** | No | Yes (`-M` flag) |
| **IPv6** | No | Yes (improved in v1.0+) |
| **Dynamic epair** | No (static) | Yes (since v1.0, both VNET forms simultaneously) |

**Conclusion**: Crate provides convenient automatic network management with granular outbound traffic control. BastilleBSD offers significantly more networking modes and enterprise-grade configurations.

---

## Data Storage

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **ZFS** | No | **Yes** (native integration, `zfs` subcommand) |
| **ZFS snapshots** | No | **Yes** |
| **ZFS clone** | No | **Yes** (for thin jails) |
| **ZFS send/recv** | No | **Yes** (used in migrate) |
| **UFS** | Yes (default) | **Yes** |
| **Shared dirs** | Yes (nullfs in YAML) | Yes (`bastille mount`) |
| **Shared files** | Yes (hardlink + fallback mount) | Via mount |
| **Container format** | `.crate` (XZ archive) | Directory on the filesystem |
| **Size optimization** | Yes (ELF analysis, removal of extras) | No (full system) |
| **ZFS options at creation** | No | Yes (`-Z` flag) |

**Conclusion**: BastilleBSD has deep ZFS integration (snapshots, clones, send). Crate does not use ZFS but compensates with aggressive container size optimization.

---

## Graphics and Desktop

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **X11** | **Yes** (X11 socket + Xauthority forwarding) | No (not a target use case) |
| **OpenGL/GPU** | **Yes** (hardware acceleration) | No |
| **Video devices** | **Yes** (/dev/videoN passthrough) | No |
| **GUI applications** | **Yes** (Firefox, Chromium, Kodi, etc.) | No (server-oriented) |

**Conclusion**: Crate is uniquely positioned for running desktop GUI applications inside jails. BastilleBSD is oriented exclusively toward server workloads.

---

## Templating and Automation

### Crate — YAML Specification
```yaml
pkg:
    install: [firefox, git]
run:
    command: /usr/local/bin/firefox
options: [net, x11, gl, video]
dirs:
    share:
        - [/var/db/myapp, $HOME/myapp/db]
scripts:
    run:begin: ["echo 'Starting...'"]
    run:after-execute: ["cleanup.sh"]
```
- A single YAML file describes everything
- 10+ lifecycle hooks (run:begin, run:after-create-jail, run:before-start-services, etc.)
- Variable substitution ($HOME, $USER, ${VAR})

### BastilleBSD — Bastillefile
```
# Bastillefile
CMD echo "Hello"
PKG nginx
SYSRC nginx_enable=YES
SERVICE nginx start
TEMPLATE /usr/local/etc/nginx/nginx.conf
OVERLAY /usr/local/www
```
- Docker-like syntax
- Commands: CMD, PKG, SYSRC, SERVICE, TEMPLATE, OVERLAY, CP, RDR, MOUNT, CONFIG, etc.
- Templates are stored in Git repositories
- Applied to already created jails
- Consolidated template repository on GitLab

**Conclusion**: Both approaches are effective but differ in philosophy. Crate describes "what should be inside the container," while BastilleBSD describes "how to configure an existing jail."

---

## Lifecycle Management

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Creation** | Yes (create) | Yes (create, with numerous options) |
| **Launch** | Yes (run, ephemeral) | Yes (start) |
| **Stop** | Automatic on exit | Yes (stop) |
| **Restart** | No (recreation) | Yes (restart) |
| **Cloning** | No | Yes (clone) |
| **Renaming** | No | Yes (rename) |
| **Migration** | No | **Yes** (migrate, including live migration via ZFS) |
| **OS update** | No (rebuild) | Yes (update, upgrade, etcupdate) |
| **Export/Import** | .crate files | Yes (compatibility with iocage/ezjail) |
| **Listing** | No | Yes (list, with priority sorting) |
| **Monitoring** | No | Yes (top, htop, monitor) |
| **Tags** | No | Yes (tags) |
| **Conversion** | No | Yes (thin↔thick, convert) |

**Conclusion**: BastilleBSD provides a complete jail management cycle, including unique live migration. Crate uses an ephemeral model where the jail is recreated on every launch.

---

## Security

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Resource limits** | No | **Yes** (rctl, cpuset via `limits`) |
| **setuid check** | Yes (requires root) | Yes (root) |
| **Network isolation** | Yes (VNET + ipfw) | Yes (VNET + pf/ipfw) |
| **Jail context check** | Yes (prevents running inside a jail) | No data |
| **Tor integration** | **Yes** (native support) | Via templates |
| **SSL certificates** | Yes (host CA bundle forwarding) | Via file templates |
| **Ktrace/debugging** | **Yes** (dbg-ktrace option) | Via `cmd`/`console` |

---

## Packages and Services

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Package installation** | Yes (in YAML: pkg.install) | Yes (`bastille pkg`) |
| **Local packages** | Yes (pkg.add, pkg.override) | Via cp + pkg |
| **Service management** | Yes (run.service in YAML) | Yes (`bastille service`) |
| **Multiple services** | Yes | Yes |
| **sysrc** | No | **Yes** (`bastille sysrc`) |
| **Auto package cleanup** | **Yes** (removal of unused dependencies) | No |
| **Optimization (strip)** | **Yes** (ELF analysis, documentation removal) | No |

---

## Summary Table

| Criterion | **Crate** | **BastilleBSD** |
|---|---|---|
| Maturity | Alpha | Stable (v1.3+) |
| Jail model | Ephemeral | Persistent |
| GUI/Desktop | **Superior** | Not supported |
| Server management | Minimal | **Superior** |
| ZFS integration | No | **Superior** |
| Network modes | 1 (epair+NAT) | 4+ (VNET, bridge, passthrough, shared IP) |
| Container size | **Optimized** | Full system |
| Migration | No | **Yes (including live)** |
| Templates | YAML specification | Bastillefile (Docker-like) |
| Number of commands | 2 | 35+ |
| Linux jails | No | Yes (experimental) |
| Monitoring | No | Yes |
| Resource limits | No | Yes |
| Tor | Yes | Via templates |
| Ecosystem | Examples (Firefox, Kodi...) | Template repository on GitLab |

---

## Firewall

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Firewall** | ipfw (automatic NAT rules) | **pf** (native integration) |
| **Configuration** | Automatic via code (net.cpp) | `bastille setup` auto-configuration of pf |
| **Port forwarding** | In YAML: `inbound-tcp: {3100: 3000}` | `bastille rdr TARGET tcp 80 8080` |
| **Dynamic rules** | Ref-counting for shared rules | pf rdr-anchor with dynamic `<jails>` table |
| **Rule management** | Auto-cleanup on termination | `bastille rdr TARGET list/clear` |

**Conclusion**: Crate uses ipfw with automatic management. BastilleBSD is oriented toward pf with full control over anchors and tables.

---

## Batch Operations and Targeting

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Multiple targets** | No (single container) | **Yes** — `ALL`, tags, space-separated lists |
| **Tags** | No | Yes (`bastille tags TARGET tag1 tag2`) |
| **Boot priorities** | No | Yes (`-p` — start/stop order) |
| **Dependencies** | No | Yes (beta: dependent jail auto-starts) |
| **JSON output** | No | Yes (`bastille list -j`) |

---

## OCI/Docker Compatibility

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **OCI images** | No | **No** |
| **Docker Hub** | No | No |
| **Dockerfile/Containerfile** | No | No (Bastillefile — its own system) |
| **Export format** | `.crate` (XZ) | `.txz` / ZFS snapshot (proprietary) |

Both systems work exclusively within the FreeBSD jail ecosystem. For OCI containers on FreeBSD, a separate project **Podman + ocijail** is recommended.

---

## API and Web Interface

| | **Crate** | **BastilleBSD** |
|---|---|---|
| **API** | No | **Yes** (bastille-api — basic REST API) |
| **Web interface** | No | No (CLI-only, API as foundation) |
| **Companion tools** | No | **Rocinante** — applies Bastillefile to the host (not jail) |

---

## Security (Extended Comparison)

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **securelevel** | Not set | **securelevel = 2** by default (Highly secure) |
| **raw_sockets** | Not restricted | **Denied** by default (`allow.raw_sockets=0`) |
| **enforce_statfs** | Not set | **2** (limits mount visibility) |
| **devfs_ruleset** | Custom (for /dev/videoN, X11) | Ruleset 4 by default; 13 for VNET |
| **Resources (rctl)** | No | **Full set**: memoryuse, vmemoryuse, pcpu, maxproc, openfiles, cputime, wallclock, readbps, writebps, readiops, writeiops, swapuse, nthr |
| **CPU pinning** | No | Yes (via cpuset) |
| **children.max** | Not set | 0 by default (nested jails prohibited) |

---

## Bastillefile — Complete Hook Reference

| Hook | Syntax | Purpose |
|------|--------|---------|
| `ARG` | `ARG_NAME=default` | Define a variable with a default |
| `ARG+` | `ARG_NAME+=value` | Required argument |
| `CMD` | `/bin/sh command` | Execute commands inside a jail |
| `CONFIG` | `set property value` | Set jail.conf properties |
| `CP` | `usr etc` | Copy overlay directories |
| `INCLUDE` | `user/template` or URL | Include another template |
| `LIMITS` | `resource value` | Resource limits (rctl) |
| `LINE_IN_FILE` | `word /path/file` | Conditionally add lines to a file |
| `MOUNT` | `hostpath jailpath nullfs rw 0 0` | Volume mounting |
| `PKG` | `pkg1 pkg2` | Package installation |
| `RDR` | `tcp 80 8080` | Port forwarding |
| `RENDER` | `/path/to/file` | Substitute `${ARG}` variables |
| `RESTART` | (no arguments or service) | Restart jail/service |
| `SERVICE` | `servicename start` | Service management |
| `SYSRC` | `key=value` | Set rc.conf values |
| `TAGS` | `tag1 tag2` | Assign tags |

Built-in variables: `${JAIL_NAME}`, `${JAIL_IP}`, `${JAIL_IP6}`

---

## Release Management

| Feature | **Crate** | **BastilleBSD** |
|---|---|---|
| **Base download** | FTP (base.txz) | `bootstrap` (freebsd-update or pkgbase) |
| **Patch updates** | Rebuild .crate | `bastille update` (freebsd-update) |
| **Release upgrade** | Rebuild .crate | `bastille upgrade` (thin and thick) |
| **/etc update** | Rebuild .crate | `bastille etcupdate` |
| **Verification** | No | `bastille verify` |
| **pkgbase (FreeBSD 15+)** | No | **Yes** (`bootstrap --pkgbase`) |

---

## When to Use What?

### Crate is better suited for:
- Running **desktop GUI applications** in an isolated environment (Firefox, Chromium, Kodi)
- **Disposable** isolated execution environments
- Minimizing container size (ELF dependency optimization)
- Rapid prototyping of isolated applications
- Scenarios requiring X11/OpenGL/video

### BastilleBSD is better suited for:
- **Server infrastructure** and DevOps
- Managing **multiple** long-lived jails
- Environments with **ZFS** (snapshots, clones, migration)
- **Migrating** jails between servers (including live)
- Automation via **templates** (CI/CD)
- Granular **resource** control (CPU, RAM, I/O)
- Compatibility with other jail managers (iocage, ezjail import)
- Working with **Linux jails**

---

## What Crate Could Borrow from BastilleBSD

1. **ZFS integration** — snapshots, clones, fast jail creation
2. **Persistent mode** — option to preserve a jail between runs
3. **Listing/monitoring** — command to view running containers
4. **Resource limits** — rctl/cpuset for CPU/RAM restrictions
5. **Cloning** — creating copies of existing .crate files
6. **Thin jails** — saving space through a shared base system
7. **IPv6** — IPv6 support in the networking stack
8. **Bridge/Passthrough** — additional networking modes
9. **List command** — viewing available .crate files and running containers
10. **Live migration** — transferring a running container to another host
