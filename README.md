# crate

Crate is a containerizer for FreeBSD. It packages applications and services into isolated, self-contained containers (`.crate` files) and runs them in dedicated FreeBSD jails with automatic networking, firewall, and resource cleanup.

Crate containers contain everything needed to run the containerized software — only the `crate` executable and the FreeBSD kernel are required at runtime.

**Language:** C++17 | **License:** BSD 3-Clause | **Status:** Alpha (active development since 2019)

[Українська версія](README_UK.md) | [Порівняння з BastilleBSD](COMPARISON-BASTILLEBSD.md)

## Features

### Container Management
* **11 commands**: `create`, `run`, `validate`, `snapshot`, `list`, `info`, `console`, `clean`, `export`, `import`, `gui`
* **YAML specification** with template inheritance (`--template`)
* **ZFS integration**: snapshots (create/list/restore/delete/diff), COW clones, encryption (AES-256-GCM/CCM, AES-128), dataset attachment
* **Copy-on-Write**: ephemeral or persistent modes via ZFS clone or unionfs
* **Export/Import**: running containers to `.crate` archives with SHA256 validation, directory traversal protection, OS version checking
* **Container listing** in table or JSON format (`crate list -j`)
* **Interactive console** access (`crate console TARGET`)
* **pkgbase** support for FreeBSD 16+ (`--use-pkgbase`)

### Graphics & Desktop
* **5 X11 modes**: shared (host Xorg), nested (Xephyr), headless (Xvfb), GPU (DRM leasing with nvidia/amdgpu/intel), none
* **VNC**: x11vnc with optional password, automatic port allocation
* **noVNC/WebSocket**: browser-based access via websockify
* **GUI session manager** (`crate gui`): list, focus, attach, url, tile, screenshot, resize
* **Clipboard isolation**: isolated/shared/none modes with directional control (in/out/both)
* **D-Bus isolation**: per-container system/session bus policy (allow_own, deny_send)
* **OpenGL/GPU acceleration**: hardware rendering with driver auto-detection
* **Video devices**: V4L `/dev/videoN` passthrough

### Networking
* **4 network modes**: NAT (default), bridge (`if_bridge`), passthrough (direct NIC), netgraph (`ng_bridge`)
* **NAT mode**: ipfw-based with automatic 10.0.0.0/8 addressing, outbound control (wan/lan/host/dns), inbound port forwarding (TCP/UDP)
* **Bridge mode**: container on physical network via `if_bridge` with DHCP or static IP
* **Passthrough mode**: dedicated physical NIC assigned directly to container via VNET
* **Netgraph mode**: `ng_bridge` + `eiface` alternative to `if_bridge`
* **DHCP**: synchronous lease acquisition (`SYNCDHCP` semantics)
* **Static IP**: CIDR notation (e.g. `192.168.1.50/24`) with gateway
* **IPv6**: NAT ULA (fd00:cra7:e::/48), SLAAC for bridge/passthrough/netgraph, static IPv6 addresses
* **Static MAC**: deterministic MAC address generation (SHA-256, vendor OUI `58:9c:fc`)
* **VLAN**: 802.1Q tagging (ID 1-4094) for bridge/passthrough/netgraph modes
* **Multiple interfaces**: primary + extra interfaces per container, each with independent mode/IP/VLAN
* **Named networks**: define reusable network profiles in system config, reference by name in container specs
* **pf anchors**: per-container firewall policy (block_ip, allow_tcp/udp, default_policy)
* **DNS filtering**: per-jail unbound with domain blocking (wildcard patterns, nxdomain/redirect)
* **Dynamic firewall slots**: unique rule numbers, no conflicts, RAII cleanup

### Security
* **securelevel**: configurable (-1 auto / 0-3, default=2)
* **children.max**: configurable (default=0 — no nested jails)
* **CPU pinning**: cpuset via `security:` in YAML
* **RCTL resource limits**: memoryuse, pcpu, maxproc, openfiles, and 20+ other resources
* **MAC bsdextended**: ugidfw rules for granular access control
* **MAC portacl**: port binding restrictions
* **Capsicum**: capability-based sandboxing
* **pathnames.h**: absolute paths to all external commands (CWE-426 protection)
* **Environment sanitization**: clean environ, restore only TERM/DISPLAY/LANG
* **execv** (no PATH search) instead of execvp in setuid context
* **lstat** for symlink validation (CWE-59 protection)
* **JAIL_OWN_DESC**: race-free jail removal (FreeBSD 15+)
* **Archive traversal protection**: validates paths before extraction
* **Signal-safe RAII cleanup**: guaranteed resource cleanup on SIGINT/SIGTERM
* **Terminal isolation**: configurable devfs ruleset, TTY control

### Services & IPC
* **Managed services**: auto-start/stop in order, rc.conf generation
* **Socket proxying**: socat-based host<->jail socket forwarding
* **SysV IPC / POSIX mqueue**: configurable per container
* **Tor integration**: built-in tor proxy option with optional control port

### Lifecycle Hooks
* `run:begin`, `run:after-create-jail`, `run:before-start-services`, `run:before-execute`, `run:after-execute`, `run:end`
* `create:begin`, `create:end`

## Commands

| Command | Description |
|---|---|
| `crate create -s spec.yml -o app.crate` | Create a container from specification |
| `crate create -s spec.yml --template base.yml` | Create with template inheritance |
| `crate run -f app.crate [-- args]` | Run a container |
| `crate validate -s spec.yml` | Validate a specification |
| `crate snapshot create\|list\|restore\|delete\|diff` | Manage ZFS snapshots |
| `crate list [-j]` | List running containers (table or JSON) |
| `crate info TARGET` | Detailed container information |
| `crate console TARGET [-u USER]` | Interactive shell in a container |
| `crate clean [-n]` | Clean up orphaned resources (dry-run supported) |
| `crate export TARGET [-o FILE]` | Export running container to .crate |
| `crate import FILE [-o FILE] [--force]` | Import .crate with validation |
| `crate gui list\|focus\|attach\|url\|tile\|screenshot\|resize` | GUI session manager |

## Quick Start

```sh
# Create a container from a spec
crate create -s examples/firefox.yml -o firefox.crate

# Run it
crate run -f firefox.crate

# List running containers
crate list

# Open a shell in a running container
crate console firefox

# Export a running container
crate export firefox -o backup.crate
```

### Headless GUI with browser access

```yaml
# spec.yml
pkg:
    install: [firefox]
run:
    command: /usr/local/bin/firefox
options: [net]
gui:
    mode: headless
    vnc: true
    novnc: true
    vnc_password: secret
```

```sh
crate create -s spec.yml -o firefox-headless.crate
crate run -f firefox-headless.crate &
crate gui url firefox    # prints noVNC URL for browser access
```

### Network Modes

```yaml
# NAT (default) — automatic IP, ipfw NAT, outbound control
options:
    net:
        outbound: [wan, dns]
        inbound-tcp:
            8080: 80

# Bridge — container on physical network via if_bridge
options:
    net:
        mode: bridge
        bridge: bridge0
        ip: dhcp
        static-mac: true

# Bridge with static IP and VLAN
options:
    net:
        mode: bridge
        bridge: bridge0
        ip: 192.168.1.100/24
        gateway: 192.168.1.1
        vlan: 100
        ip6: slaac

# Passthrough — dedicated NIC directly to container
options:
    net:
        mode: passthrough
        interface: vtnet1
        ip: dhcp
        ip6: slaac

# Netgraph — ng_bridge alternative to if_bridge
options:
    net:
        mode: netgraph
        interface: em0
        ip: 192.168.1.100/24
        gateway: 192.168.1.1
        static-mac: true

# Multiple interfaces
options:
    net:
        mode: bridge
        bridge: bridge0
        ip: dhcp
        extra:
            - mode: bridge
              bridge: bridge1
              ip: 10.0.0.50/24
              gateway: 10.0.0.1
              vlan: 100

# Using named networks (defined in crate.yml)
options:
    net:
        network: external
        ip: 192.168.1.50/24
        extra:
            - network: internal
              ip: 10.0.0.50/24
```

## Configuration

Configuration files (YAML, higher priority wins):

| File | Scope |
|---|---|
| `/usr/local/etc/crate.yml` | System-wide |
| `/usr/local/etc/crate.d/*.yml` | Drop-in fragments (alphabetical order) |
| `~/.config/crate/crate.yml` | Per-user |

Key options: `prefix`, `cache`, `logs`, `zfs_enable`, `zfs_zpool`, `network_interface`, `default_bridge`, `static_mac_default`, `bootstrap_method`, `securelevel`, `children_max`, `search_path`, `compress_xz_options`, `networks`.

### Named Networks

Define reusable network profiles in the system config and reference them by name in container specs:

```yaml
# /usr/local/etc/crate.yml
networks:
    external:
        mode: bridge
        bridge: bridge0
        gateway: 192.168.1.1
        static-mac: true
    internal:
        mode: bridge
        bridge: bridge1
        gateway: 10.0.0.1
        vlan: 100
    dmz:
        mode: netgraph
        interface: em1
        gateway: 172.16.0.1
```

```yaml
# container spec (.crate)
options:
    net:
        network: external
        ip: 192.168.1.50/24
        extra:
            - network: internal
              ip: 10.0.0.50/24
```

Named network fields serve as defaults — explicit values in the container spec always override.

## Templates

The `templates/` directory provides ready-made base configurations:

| Template | Description |
|---|---|
| `standard.yml` | NAT with WAN+DNS, shared Downloads directory |
| `development.yml` | NAT with full outbound access, shared home, SysV IPC |
| `minimal.yml` | Bare jail, no network, no X11 |
| `privacy.yml` | Tor proxy, ZFS encryption, ephemeral COW, DNS filtering |
| `network-isolated.yml` | No network, nested X11 (1280x720) |
| `bridge-dhcp.yml` | Bridge mode with DHCP and static MAC |
| `bridge-static.yml` | Bridge mode with static IP and gateway |
| `passthrough.yml` | Passthrough with DHCP and IPv6 SLAAC |
| `netgraph.yml` | Netgraph mode with DHCP and static MAC |

## Examples

The `examples/` directory contains ready-to-use specifications:

**Desktop applications:**
firefox, chromium, gimp, thunderbird, meld, mpv, vlc, qbittorrent, qtox, telegram-desktop, xfce-desktop

**Headless/GPU modes:**
firefox-headless, firefox-gpu, chromium-headless, chromium-gpu, gimp-headless, blender-gpu, glxgears-gpu

**Network services:**
gogs, nginx, syncthing, tor, i2pd

**Privacy (Tor/I2P):**
chromium+tor, firefox+i2pd, chromium+i2pd, qbittorrent+i2pd

**Utilities:**
nmap, amass, wget, aria2, fetch, gzip, yt-dlp, xeyes

## YAML Specification Reference

Top-level keys supported in `.crate` / `.yml` spec files:

| Key | Description |
|---|---|
| `base` | `keep`, `keep-wildcard`, `remove` — control base system files |
| `pkg` | `install`, `local-override`, `nuke` — package management |
| `run` | `command`, `service` — what to execute in the container |
| `dirs` | `share` — shared directories (host<->jail) |
| `files` | `share` — shared files (host<->jail) |
| `options` | `net`, `x11`, `ssl-certs`, `tor`, `video`, `gl`, `no-rm-static-libs`, `dbg-ktrace` |
| `scripts` | Lifecycle hooks (run:begin, run:after-create-jail, etc.) |
| `security` | `securelevel`, `children_max`, `cpuset`, `enforce_statfs`, `allow_*` |
| `limits` | RCTL resource limits (memoryuse, pcpu, maxproc, etc.) |
| `ipc` | `sysvipc`, `mqueue`, `raw_sockets` |
| `zfs` | `datasets` — additional ZFS datasets to attach |
| `encrypted` | ZFS encryption (method, keyformat, cipher) |
| `cow` | Copy-on-Write (mode: ephemeral/persistent, backend: zfs/unionfs) |
| `dns_filter` | DNS filtering (allow, block, redirect_blocked) |
| `firewall` | Per-container pf policy (block_ip, allow_tcp/udp, default) |
| `x11` | X11 display (mode: nested/shared/none, resolution, clipboard) |
| `gui` | GUI session (mode: nested/headless/gpu/auto, vnc, novnc, resolution) |
| `clipboard` | Clipboard isolation (mode: isolated/shared/none, direction) |
| `dbus` | D-Bus policy (system, session, policy/allow_own/deny_send) |
| `services` | Managed services (managed list, auto_start) |
| `socket_proxy` | Socket forwarding (share, proxy with host/jail/direction) |
| `terminal` | Terminal isolation (devfs_ruleset, allow_raw_tty) |
| `security_advanced` | Capsicum, MAC bsdextended/portacl, hide_other_jails |

## Installation

Via FreeBSD ports:
```sh
cd /usr/ports/sysutils/crate && make install clean
```

Or build from source:
```sh
make && sudo make install
```

**Dependencies:** yaml-cpp, libjail

### Additional Components

```sh
make install-daemon       # crated — container lifecycle daemon
make install-examples     # example spec files to /usr/local/share/examples/crate
make install-completions  # shell completions
```

## FreeBSD 15.0+ Compatibility

* JAIL_OWN_DESC — race-free jail removal via owning descriptor
* epair checksum offload fix (txcsum/txcsum6 disable)
* OS version mismatch warning (host != container)
* ipfw compatibility warning (removed legacy compat code)
* getgroups(2) behavior change adjustment

## Caveats

* Inbound network ports can't be accessed from the host running the crate because of [this bug](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=239590), currently they can only be accessed from other hosts.

## Project Status

`crate` is in its alpha stage. Active development since June 2019.

## TODO

See the TODO file in the project.
