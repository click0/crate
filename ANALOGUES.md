# Closest Analogues to Crate on FreeBSD

## Key Characteristics of Crate (for comparison)

1. **Ephemeral jails** — a jail is created at launch and destroyed after termination
2. **Self-contained archives** — application + dependencies are packed into `.crate` (XZ)
3. **Desktop/GUI isolation** — X11, OpenGL, video devices
4. **Minimal container** — ELF analysis via ldd, stripping unnecessary files
5. **Declarative specification** — YAML
6. **Simple CLI** — two commands: `create` and `run`
7. **Automatic networking** — VNET + ipfw NAT with no manual configuration
8. **Written in C++17** (~3,000 lines)

---

## Similarity Matrix

| Tool | Ephemeral | Archives | GUI | Minimal | Declarative | Simple CLI | Auto-net | C/C++ | **Total /40** |
|---|---|---|---|---|---|---|---|---|---|
| **Crate** (reference) | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 5 | **40** |
| **AppJail** | 4 | 2 | 1 | 3 | 4 | 2 | 4 | 2 | **22** |
| **Podman + ocijail** | 4 | 4 | 1 | 1 | 2 | 3 | 3 | 1 | **19** |
| **Kleene** | 4 | 2 | 1 | 1 | 3 | 3 | 4 | 1 | **19** |
| **pot** | 3 | 3 | 1 | 1 | 2 | 3 | 3 | 1 | **17** |
| **xc** | 3 | 3 | 1 | 1 | 3 | 2 | 3 | 1 | **17** |
| **Vessel** | 2 | 2 | 1 | 1 | 3 | 3 | 2 | 3 | **17** |
| **Blackship** | 2 | 1 | 1 | 1 | 4 | 3 | 3 | 1 | **16** |
| **Focker** | 2 | 2 | 1 | 1 | 4 | 3 | 2 | 1 | **16** |
| **BastilleBSD** | 1 | 2 | 1 | 1 | 4 | 2 | 3 | 1 | **15** |
| **CBSD** | 1 | 2 | 3 | 1 | 2 | 1 | 3 | 2 | **15** |
| **Capsicumizer** | 1 | 1 | 4 | 1 | 3 | 3 | 1 | 1 | **15** |
| **runj** | 3 | 3 | 1 | 1 | 2 | 2 | 2 | 1 | **15** |
| **exec.prepare** | 5 | 1 | 1 | 1 | 2 | 2 | 1 | 1 | **14** |
| **Curtain** | 1 | 1 | 3 | 1 | 3 | 3 | 1 | 1 | **14** |
| **iocage** | 2 | 1 | 1 | 1 | 2 | 3 | 3 | 1 | **14** |
| **Service Jails** | 2 | 1 | 1 | 1 | 2 | 5 | 1 | 1 | **14** |
| **MicroJails** | 1 | 1 | 1 | 5 | 1 | 1 | 1 | 1 | **12** |

---

## Detailed Descriptions (by decreasing similarity)

### 1. AppJail — the closest analogue (22/40)

| | |
|---|---|
| **URL** | https://github.com/DtxdF/AppJail |
| **Language** | POSIX sh + C |
| **Version** | 4.9.0 (February 2026) |
| **Status** | Actively developed, the most feature-rich jail manager |
| **Port** | `sysutils/appjail` |

**Why it is close to Crate:**
- Explicit **"ephemeral concept"** (appjail-ephemeral(7)) — jails as "cattle, not pets"
- **Makejail** — a declarative format analogous to Dockerfile: `FROM`, `RUN`, `PKG`, `ENTRYPOINT`, `COPY`, `ENV`, `INCLUDE`
- **`.appjail` archives** — XZ-compressed images with AJSPEC metadata
- **TinyJails** — an experimental feature for minimal jails (analogous to Crate's ELF optimization)
- **Director** — a companion tool for YAML-based multi-jail environment descriptions
- **X11 support** — mounting `/tmp/.X11-unix` into the jail (documented in the handbook)
- **NAT** — via pf, automatic virtual network management
- 101+ ready-made Makejail files in the repository

**How it differs:**
- Jails are persistent by default (ephemeral behavior is a philosophy, not the default)
- No automatic GPU/OpenGL/video passthrough
- No Xauthority management (manual `xhost +` required)
- 35+ subcommands vs. 2 in Crate
- Shell, not C++

---

### 2. Podman + ocijail (19/40)

| | |
|---|---|
| **URL** | https://github.com/dfr/ocijail |
| **Language** | Go (ocijail), Go (podman) |
| **Status** | Experimental on FreeBSD, active development by the FreeBSD Foundation |
| **Port** | `sysutils/podman`, `sysutils/ocijail` |

**Why it is close to Crate:**
- `podman run --rm` — an ephemeral container, destroyed after exit (like `crate run`)
- OCI images — self-contained archives (layer tarballs)
- Docker Hub / image registries
- CNI networking

**How it differs:**
- OCI ecosystem (not FreeBSD-native packaging)
- No ELF analysis (full OS images)
- No desktop/GUI support
- Requires root (no rootless on FreeBSD)
- Large dependency stack
- Limited selection of FreeBSD images

---

### 3. Kleene (19/40)

| | |
|---|---|
| **URL** | https://github.com/kleene-project/kleened |
| **Language** | Elixir (kleened), Python (klee CLI) |
| **Version** | v0.1.0-rc.1 (pre-release) |
| **Status** | Early stage, not production-ready |
| **Port** | `sysutils/kleened`, `sysutils/klee` |

**Why it is close to Crate:**
- `klee run` — creates an ephemeral container from an image, destroys it on exit (Docker semantics)
- Dockerfile-like build system
- PF networking with automatic configuration

**How it differs:**
- Client-server architecture (requires the kleened daemon)
- Images are ZFS datasets, not portable archives
- No desktop/GUI support
- No ELF analysis
- Requires ZFS

---

### 4. pot (17/40)

| | |
|---|---|
| **URL** | https://github.com/bsdpot/pot |
| **Language** | Shell |
| **Version** | 0.16.1 (March 2025) |
| **Status** | Active, used in production with Nomad |
| **Port** | `sysutils/pot` |

**Why it is close to Crate:**
- XZ-compressed export archives (ZFS snapshots)
- VNET + pf NAT
- **Nomad integration** — `nomad-pot-driver` provides ephemeral behavior (pull -> create -> run -> destroy)
- **Potluck** — a registry of ready-made images (50+)
- Thin and thick jails, flavours (templates)

**How it differs:**
- **Requires ZFS** (does not work on UFS)
- No native ephemeral mode (ephemeral behavior is achieved through Nomad)
- No desktop/GUI support
- No YAML (CLI flags + flavour scripts)
- Archives depend on ZFS (not self-contained rootfs)
- Infrastructure/DevOps tool

---

### 5. xc (17/40)

| | |
|---|---|
| **URL** | https://github.com/michael-yuji/xc |
| **Language** | Rust |
| **Status** | WIP, presented at BSDCan |

A FreeBSD-oriented container engine. Supports OCI images and native Jailfile. Can run Linux containers via Linuxulator. Daemon architecture (xcd). Integration with PF, ZFS, DTrace.

**How it differs from Crate:** daemon architecture, no desktop focus, no ELF analysis, not in ports.

---

### 6. Vessel (17/40)

| | |
|---|---|
| **URL** | https://github.com/ssteidl/vessel |
| **Language** | C + Tcl |
| **Status** | Author's side project |

Application containers on FreeBSD. Unique feature: a `vessel` process runs alongside each jail, listening for events via kqueue. VesselFile (Tcl syntax) for declarative descriptions. Partially written in C — the only tool besides Crate that uses a compiled language.

**How it differs from Crate:** not ephemeral by default, Tcl (not YAML), no GUI, no archives, no ELF analysis.

---

## Non-jail Approaches to Desktop Isolation

### 7. Capsicumizer (15/40)

| | |
|---|---|
| **URL** | https://github.com/myfreeweb/capsicumizer |
| **Status** | Abandoned (public domain) |

**"Super Capsicumizer 9000"** — a Capsicum-based sandbox. Runs programs in capability mode via LD_PRELOAD (libpreopen). Profiles in UCL syntax (similar to AppArmor). **Can isolate GUI applications** (GTK, X11, Wayland).

The only tool besides Crate specifically designed for sandboxing desktop applications on FreeBSD. However, it uses Capsicum (process level) rather than jails (OS level). Does not work with Go programs (LD_PRELOAD).

### 8. Curtain / freebsd-pledge (14/40)

| | |
|---|---|
| **URL** | https://github.com/Math2/freebsd-pledge |
| **Status** | WIP, requires a kernel rebuild |

A kernel module `mac_curtain` — a port of OpenBSD's `pledge(3)` and `unveil(3)` to FreeBSD. The `curtain(1)` utility runs programs in a sandbox with filesystem restrictions. Can isolate Firefox. However, it requires a custom kernel build.

---

## Patterns (not tools)

### 9. exec.prepare / exec.release (native jail.conf)

A mechanism built into FreeBSD (12.2+) via `jail.conf(5)` hooks:
- `exec.prepare` — runs before jail creation (e.g., ZFS clone from a template)
- `exec.release` — runs after destruction (clone removal)

**The closest match to the create-run-destroy model** at the kernel level. However, it requires manual configuration of everything else.

### 10. MicroJails (a pattern from the FreeBSD Wiki)

| | |
|---|---|
| **URL** | https://wiki.freebsd.org/VladimirKrstulja/Guides/MicroJails |

A shell script by Vladimir Krstulja: creates a bare jail root, copies `ld-elf.so.1` and only the required `.so` libraries (found via `ldd`), plus minimal `/etc` files. **This is exactly the same technique** that Crate automates in `create.cpp`. A manual version of Crate's main technical feature.

---

## Server-oriented Jail Managers (low similarity)

| Tool | Description | Status |
|---|---|---|
| **BastilleBSD** | Full-featured jail manager, Bastillefile templates, pf, 35+ commands | Stable v1.3+ |
| **CBSD** | All-in-one: jails + bhyve + QEMU, SQLite, web UI, clustering. The only jail manager with X11-in-jail documentation | Stable, since 2013 |
| **iocage** | ZFS-first, UUID identification, templates, plugins | Revived under freebsd/iocage, v1.10 |
| **Blackship** | New (December 2025), Rust, TOML, dependency graph, state machines | Early stage |
| **Focker** | Docker clone in Python, Fockerfile, ZFS layers | In ports, sporadic development |
| **Jailer** | Minimalist, VNET-only, ZFS-only | Active, not in ports |
| **ezjail** | Classic, nullfs shared base | Effectively abandoned |
| **Service Jails** | FreeBSD 15+, jail any rc.d service via 1-2 lines in rc.conf | Coming in FreeBSD 15 |

---

## Closest Analogues by Individual Characteristic

| Crate Characteristic | Closest Analogue |
|---|---|
| **Ephemeral model** (create -> run -> destroy) | `exec.prepare`/`exec.release` (native jail.conf), Kleene (`klee run`), Podman (`--rm`) |
| **Self-contained archives** | Podman (OCI image tarballs), pot (ZFS -> XZ), AppJail (`.appjail`) |
| **Desktop/GUI isolation** | Capsicumizer (Capsicum + UCL profiles), CBSD (X11 in jail), Curtain (pledge) |
| **ELF analysis / minimal container** | MicroJails (wiki pattern, manual ldd), AppJail TinyJails (experimental) |
| **Declarative specification** | AppJail Makejail, Focker Fockerfile, Blackship TOML, BastilleBSD Bastillefile |
| **Simplicity (2 commands)** | Service Jails (1-2 lines in rc.conf), Capsicumizer (one command) |
| **Automatic networking** | AppJail (pf + virtual networks), BastilleBSD (pf + rdr-anchor) |

---

## Conclusion

**No single tool reproduces Crate's unique combination.** Crate occupies its own niche by combining:
- Ephemeral jails
- Self-contained XZ archives with ELF optimization
- First-class X11/OpenGL/video support
- YAML specifications
- A two-command CLI
- Automatic VNET+NAT networking

The closest analogue is **AppJail** (22/40), which shares the ephemeral philosophy, has an archive format, TinyJails, and X11 support, but remains a full-featured jail manager with 35+ commands.

To reproduce Crate's functionality using other tools would require a combination of:
**AppJail** (ephemeral concept + Makejail) + **MicroJails** (ldd technique) + manual X11 setup + **exec.prepare/exec.release** (jail.conf hooks)
