# crate

Crate is a containerizer for FreeBSD. It packages applications and services into isolated, self-contained containers (`.crate` files) and runs them in dedicated FreeBSD jails with automatic networking, firewall, and resource cleanup.

Crate containers contain everything needed to run the containerized software — only the `crate` executable and the FreeBSD kernel are required at runtime.

**Language:** C++17 | **License:** ISC | **Status:** Alpha (active development since 2019)

[Українська версія](README_UK.md) | [Порівняння з BastilleBSD](COMPARISON-BASTILLEBSD.md)

## Features

### Container Management
* **11 commands**: `create`, `run`, `validate`, `snapshot`, `list`, `info`, `console`, `clean`, `export`, `import`, `gui`
* **YAML specification** with template inheritance (`--template`)
* **ZFS integration**: snapshots (create/list/restore/delete/diff), COW clones, encryption, dataset attachment
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
* **VNET**: automatic epair creation with IPv4 and IPv6
* **NAT**: ipfw-based with automatic rule management
* **IPv6**: full support (fd00:cra7:e::/48 ULA, ipfw ip6, pf inet6, routing)
* **Port forwarding**: inbound TCP/UDP mapping via YAML
* **pf anchors**: per-container firewall policy (block_ip, allow_tcp/udp, default_policy)
* **Outbound control**: granular access — wan/lan/host/dns
* **DNS filtering**: per-jail unbound with domain blocking (wildcard patterns, nxdomain/redirect)
* **Dynamic firewall slots**: unique rule numbers, no conflicts, RAII cleanup

### Security
* **securelevel**: configurable (-1 auto / 0–3, default=2)
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
* **Socket proxying**: socat-based host↔jail socket forwarding
* **SysV IPC / POSIX mqueue**: configurable per container
* **Tor integration**: built-in tor proxy option

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

## Configuration

Configuration files (YAML, higher priority wins):

| File | Scope |
|---|---|
| `/usr/local/etc/crate.yml` | System-wide |
| `/usr/local/etc/crate.d/*.yml` | Drop-in fragments (alphabetical order) |
| `~/.config/crate/crate.yml` | Per-user |

Key options: `prefix`, `cache`, `logs`, `zfs_enable`, `zfs_zpool`, `network_interface`, `securelevel`, `children_max`, `search_path`, `compress_xz_options`.

## Examples

The `examples/` directory contains ready-to-use specifications:

**Desktop applications:**
firefox, chromium, gimp, thunderbird, libreoffice, telegram-desktop, vlc, mpv, meld, qbittorrent, qtox, xfce-desktop

**Headless/GPU modes:**
firefox-headless, firefox-gpu, chromium-headless, chromium-gpu, gimp-headless, libreoffice-headless, blender-gpu, glxgears-gpu

**Network services:**
gogs, nginx, syncthing, tor, i2pd

**Privacy (Tor/I2P):**
chromium+tor, firefox+i2pd, chromium+i2pd, qbittorrent+i2pd

**Utilities:**
nmap, amass, wget, aria2, fetch, gzip, xeyes

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

## FreeBSD 15.0+ Compatibility

* JAIL_OWN_DESC — race-free jail removal via owning descriptor
* epair checksum offload fix (txcsum/txcsum6 disable)
* OS version mismatch warning (host ≠ container)
* ipfw compatibility warning (removed legacy compat code)
* getgroups(2) behavior change adjustment

## Caveats

* Inbound network ports can't be accessed from the host running the crate because of [this bug](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=239590), currently they can only be accessed from other hosts.

## Project Status

`crate` is in its alpha stage. Active development since June 2019.

## TODO

See the TODO file in the project.
