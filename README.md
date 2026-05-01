# crate

Crate is a containerizer for FreeBSD. It packages applications and services into isolated, self-contained containers (`.crate` files) and runs them in dedicated FreeBSD jails with automatic networking, firewall, and resource cleanup.

Crate containers contain everything needed to run the containerized software — only the `crate` executable and the FreeBSD kernel are required at runtime.

**Language:** C++17 | **License:** BSD 3-Clause | **Status:** Alpha (active development since 2019)

[Українська версія](README_UK.md) | [Comparison with BastilleBSD](docs/research/COMPARISON-BASTILLEBSD.md)

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
| `crate export TARGET [-o FILE] [-P PASSFILE] [-K SIGNKEY]` | Export running container to .crate (optional encryption + ed25519 signature) |
| `crate import FILE [-o FILE] [--force] [-P PASSFILE] [-V PUBKEY]` | Import .crate with validation (auto-decrypts, verifies signature) |
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

### Encrypted export/import

`.crate` artefacts are portable — unlike Bastille's place-bound jails — and
since 0.5.4 they can also be **private**. Exports are wrapped in
`AES-256-CBC + PBKDF2` via `openssl enc(1)` so the same image can travel
between hosts without leaking its filesystem to anyone with network or
backup-storage access.

```sh
# 1. Write a passphrase to a file (must be mode 0600 — owner-only)
printf 'cRatE2026craTE#UKR' > /etc/crate/secret
chmod 0600 /etc/crate/secret

# 2. Export, encrypted
crate export firefox -P /etc/crate/secret -o firefox.crate
# -> firefox.crate         (AES-256-CBC ciphertext)
# -> firefox.crate.sha256  (over the encrypted bytes)

# 3. scp/rsync to the target host …

# 4. Import — encryption is auto-detected from magic bytes
crate import firefox.crate -P /etc/crate/secret
# Without -P on an encrypted archive, the import fails fast with a clear message.
```

Notes:
- The example passphrase `cRatE2026craTE#UKR` is illustrative — pick your own.
  PBKDF2 makes brute force expensive but a strong passphrase is still your job.
- The passphrase file goes in via `-kfile <path>` to `openssl`, so the secret
  never appears on the command line and is not visible via `ps`.
- `crate` refuses any passphrase file that isn't `0600`, regular, and non-empty.
- The `.sha256` sidecar covers the **ciphertext**: verify it out-of-band
  before decrypting if you want detection of bit-flips on transport.
- The `.sha256` sidecar covers the **ciphertext**: verify it out-of-band
  before decrypting if you want detection of bit-flips on transport.
- For authenticated provenance ("this archive really came from me"),
  pair `-P` with `-K`/`-V` (ed25519 signing — see below).

### Signed export/import (ed25519)

Encryption (the `-P` flag above) gives you confidentiality. Signing
gives you **authenticity** — a recipient can verify a `.crate` archive
really came from the holder of the matching secret key, even if it
travelled through untrusted intermediaries. The two are independent
and can be combined.

```sh
# 1. One-time: generate an ed25519 keypair
openssl genpkey -algorithm ED25519 -out crate-sign.key
openssl pkey -in crate-sign.key -pubout -out crate-sign.pub
chmod 0600 crate-sign.key
# (publish crate-sign.pub anywhere; keep crate-sign.key secret)

# 2. Sign on export. Combine with -P for confidentiality + authenticity.
crate export firefox -K crate-sign.key -P /etc/crate/secret -o firefox.crate
# -> firefox.crate         (AES-256-CBC ciphertext)
# -> firefox.crate.sha256  (over the encrypted bytes)
# -> firefox.crate.sig     (ed25519 signature over the encrypted bytes)

# 3. On the recipient: verify with the public key.
crate import firefox.crate -V crate-sign.pub -P /etc/crate/secret
# Refuses to import if firefox.crate.sig is missing/mismatched —
# unless --force.
```

What gets signed: the **on-disk archive bytes** (including any
encryption layer). So:
- A tampered ciphertext is detected by the signature, even before
  the recipient enters the passphrase.
- The public key can verify provenance without holding the
  passphrase.
- An unsigned archive imports normally; a *signed* archive without
  `-V` refuses to import (intentionally — opt-in to the looser
  unsigned mode with `--force`).

Notes:
- Implementation: `openssl pkeyutl -sign -rawin -inkey ed25519-key`.
  ed25519 produces a fixed 64-byte signature; `.sig` is binary.
- Secret-key file rejected unless mode `0600`, regular, non-empty.
- The signature path is `<archive>.sig`. Verifier exit codes ≠ 0
  abort the import unless `--force`.

### Audit log

Every state-changing crate command (`create`, `run`, `stop`, `restart`,
`snapshot`, `export`, `import`, `clean`, `console`, `gui`, `stack`)
appends a one-line JSON record to `/var/log/crate/audit.log`. Read-only
commands (`list`, `info`, `stats`, `logs`, `validate`) are skipped to
keep the log lean.

```sh
$ crate create -s spec.yml -o myapp.crate
...
$ tail -1 /var/log/crate/audit.log | jq .
{
  "ts":      "2026-05-01T20:55:01Z",
  "pid":     12345,
  "uid":     1000,                          // real uid (the user)
  "euid":    0,                             // effective uid (setuid root)
  "gid":     1000,
  "egid":    0,
  "user":    "alice",
  "host":    "build-server",
  "cmd":     "create",
  "target":  "spec.yml",
  "argv":    "'crate' 'create' '-s' 'spec.yml' '-o' 'myapp.crate'",
  "outcome": "ok"
}
```

Notes:
- The file lives under `Config::Settings::logs` (default
  `/var/log/crate`); change it via `crate.yml`.
- Mode 0640, append-only writes — fits the `auditd(8)` /
  `syslogd(8)` model. Rotate with `newsyslog(8)`.
- Captures **both** real and effective uid/gid so reviewers see
  "user X (uid=1000) acted via euid=0" — important for setuid binaries.
- Pair `outcome: "started"` and `outcome: "ok"` records by `pid` to
  measure command duration; `failed: <msg>` records contain the
  exception message for post-mortem.

### Cross-device file shares

`files:` shares no longer require the host source and the jail-side
mount point to live on the same filesystem. When `crate run` detects
a cross-device path pair (host on tmpfs, jail dataset on a different
ZFS pool, external disk, etc.), it automatically falls back to a
single-file `nullfs` bind-mount instead of the hard-link path that
returns `EXDEV`. The semantics inside the jail are identical:
read/write, in-place edits, ownership and mode all reflect the
underlying host file.

```yaml
# This now works regardless of whether /etc/resolv.conf and the
# jail dataset share a device. crate decides per-file whether to
# hard-link (same device) or nullfs-bind (cross device).
files:
  /etc/resolv.conf: /etc/resolv.conf
  /var/log/myapp.log: /home/me/logs/myapp.log
```

The strategy table is published in `CHANGELOG.md` (0.6.0); the pure
decision logic lives in `lib/share_pure.{h,cpp}` with a 9-case ATF
test covering every cell of the (host_exists × jail_exists ×
same_device) matrix.

### X11 mode security

`crate` supports five X11 display modes — they are **not equivalent
from a security standpoint**. `crate validate` and `crate run` both
emit warnings when an isolation-weak mode is selected.

| Mode | Isolation | Use when |
|---|---|---|
| `nested` (Xephyr) | Strong: containers get a private X server | desktop apps, default for production |
| `headless` (Xvfb) + VNC/noVNC | Strong: no host X access at all | server/automation/screenshot |
| `gpu` (DRM leasing) | Strong: dedicated GPU, no host X | accelerated workloads |
| `shared` | **None** — full read/write access to the host X server | only inside fully trusted jails |
| `none` | n/a | no GUI |

**Why `shared` is dangerous.** Mounting the host's `/tmp/.X11-unix`
into a jail means any process inside that jail can:
- Read every keystroke typed into any application on the host (X is
  global, not per-window).
- Move/raise/iconify/destroy any host window.
- Take screenshots of the entire desktop.

`crate` warns about this both at validate time (`crate validate spec.yml`)
and at run time. Operators who deliberately accept the risk can suppress
the runtime warning with `CRATE_X11_SHARED_ACK=1`.

```yaml
# DON'T (default behaviour for legacy specs)
options: [x11]               # ⚠️ implicit mode=shared

# DO
options: [x11]
x11:
    mode: nested             # private Xephyr server per jail
    resolution: 1920x1080
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

### Via FreeBSD ports

```sh
cd /usr/ports/sysutils/crate && make install clean
```

The port supports build OPTIONS (enabled by default unless noted):

| Option | Description |
|---|---|
| `DAEMON` | Container lifecycle daemon (crated) |
| `SNMPD` | SNMP monitoring agent (crate-snmpd) |
| `EXAMPLES` | Example container specifications |
| `COMPLETIONS` | Bash/ZSH shell completions (off by default) |
| `ZFS` | Native ZFS API (libzfs) |
| `IFCONFIG` | Native interface configuration (libifconfig) |
| `PFCTL` | Native PF firewall control (libpfctl) |
| `CAPSICUM` | Capsicum sandbox support (libcasper) |
| `LIBVIRT` | Virtual machine support (bhyve via libvirt) |
| `X11` | X11 display forwarding |
| `VNCSERVER` | Embedded VNC server (libvncserver) (off by default) |
| `LIBSEAT` | DRM/GPU session management (libseat) |

```sh
# Configure options interactively
cd /usr/ports/sysutils/crate && make config && make install clean
```

### From source

```sh
make && sudo make install
```

**Dependencies:** yaml-cpp, libjail

**Compile-time feature flags** (set `=0` to disable):

```sh
make HAVE_LIBZFS=1 HAVE_LIBIFCONFIG=1 HAVE_LIBPFCTL=1 HAVE_CAPSICUM=1 \
     WITH_LIBVIRT=1 WITH_X11=1 WITH_LIBSEAT=1 WITH_LIBVNCSERVER=0
```

All native API wrappers fall back to shell commands when compiled without the corresponding flag.

### Make targets

| Target | Description |
|---|---|
| `make` | Build `crate` CLI |
| `make all-daemon` | Build `crate` + `crated` daemon |
| `make all-snmpd` | Build `crate` + `crate-snmpd` agent |
| `make install` | Install crate CLI + man pages |
| `make install-daemon` | Install crated, RC script, config |
| `make install-snmpd` | Install crate-snmpd + MIB file |
| `make install-examples` | Install example specs to `/usr/local/share/examples/crate/` |
| `make install-completions` | Install shell completions |
| `make test` | Compile unit tests and run via kyua |

## crated — REST API Daemon

`crated` is a container lifecycle daemon providing a REST API for remote management.

### Features

* Listens on **Unix socket** (local) and **TCP/TLS** (remote)
* **Token-based authentication** (SHA-256 hashes, roles: `viewer`/`admin`)
* **Rate limiting** (100 req/s read, 10 req/s write)
* **Prometheus metrics** at `/metrics`
* FreeBSD **RC service** integration

### API Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `GET /healthz` | — | Health check |
| `GET /api/v1/containers` | — | List running containers |
| `GET /api/v1/containers/:name/gui` | — | GUI session info (display, VNC/WS ports) |
| `GET /api/v1/containers/:name/stats` | yes | Resource usage (RCTL) |
| `GET /api/v1/containers/:name/logs` | yes | Logs (`?follow=true`, `?tail=N`) |
| `POST /api/v1/containers/:name/start` | yes | Start container from .crate |
| `POST /api/v1/containers/:name/stop` | yes | Stop container (SIGTERM → SIGKILL) |
| `DELETE /api/v1/containers/:name` | yes | Destroy container |
| `GET /api/v1/host` | — | Host system info |
| `GET /metrics` | — | Prometheus metrics |

### Configuration

```yaml
# /usr/local/etc/crated.conf
listen:
    unix: /var/run/crate/crated.sock
    tcp_port: 9800
    tcp_bind: 0.0.0.0

tls:
    cert: /usr/local/etc/crate/tls/server.pem
    key: /usr/local/etc/crate/tls/server.key
    ca: /usr/local/etc/crate/tls/ca.pem
    require_client_cert: true

auth:
    tokens:
        - name: ansible
          token_hash: "sha256:..."
          role: admin
        - name: grafana
          token_hash: "sha256:..."
          role: viewer

log:
    file: /var/log/crated.log
    level: info
```

### RC service

```sh
# /etc/rc.conf
crated_enable="YES"

# Control
service crated start
service crated stop
service crated status
```

## crate-snmpd — SNMP Monitoring Agent

`crate-snmpd` is an AgentX subagent that exposes container metrics via SNMP. It collects data from `jls`/`rctl` and registers a `CRATE-MIB` (installed to `/usr/local/share/snmp/mibs/`).

```sh
make all-snmpd && sudo make install-snmpd
```

## Testing

The project uses **Kyua** and **ATF** (FreeBSD's standard test framework).

```sh
make test                     # Build and run all tests
cd tests && kyua test         # Run from tests directory
kyua test unit/               # Unit tests only
kyua test functional/         # Functional tests only
kyua report -v                # Verbose report
```

**Unit tests** (C++17, libatf-c++): spec parsing, network options, IPv6, jail lifecycle, error handling.

**Functional tests** (shell-based ATF): CLI commands (`help`, `version`, `validate`, `list`).

## Compatibility

**Supported:** FreeBSD 13.0 and later (13.x, 14.x, 15.x). All version-specific features have safe fallbacks.

FreeBSD 15.0 adaptations (automatic, no user action needed):
* JAIL_OWN_DESC — race-free jail removal via owning descriptor (falls back to `jail_remove()` on older kernels)
* epair checksum offload fix — `txcsum`/`txcsum6` disabled unconditionally (harmless on 13.x/14.x)
* OS version mismatch warning — detects host vs container FreeBSD major version difference
* ipfw compatibility warning — alerts when FreeBSD 15 host runs a container built with older base

## Caveats

* Inbound network ports can't be accessed from the host running the crate because of [this bug](https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=239590), currently they can only be accessed from other hosts.

## Project Status

`crate` is in its alpha stage. Active development since June 2019.

## TODO

See the TODO file in the project.
