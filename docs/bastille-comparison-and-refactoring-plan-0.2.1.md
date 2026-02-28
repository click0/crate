# Crate vs Bastille: Comparison & Refactoring Plan for Crate 0.2.1

## 1. Comparison Overview

### Architecture

| Aspect | Crate | Bastille (fork) |
|--------|-------|-----------------|
| Language | C++17 (~4000 LOC) | POSIX sh (~40 scripts) |
| Execution model | setuid binary, exec-based (no shell) | root/sudo, shell scripts |
| Jail lifecycle | Ephemeral (create→run→destroy) | Persistent (create, start/stop, destroy) |
| Jail creation | `jail_setv()` C API directly | `jail.conf` file + `jail -c` |
| Networking | epair + ipfw NAT (automatic) | loopback/shared/VNET bridge (manual IP) |
| Config format | Per-crate YAML spec | Global `bastille.conf` + per-jail `jail.conf` |
| Security | CWE-426 hardened paths, env sanitization, JAIL_OWN_DESC | Basic root check, permissions check |
| Storage | base.txz cache + pkgbase bootstrap | Thin (nullfs shared base) / Thick (full copy) / Clone (ZFS) |
| Commands | 4 (create, run, validate, snapshot) | 30+ (full lifecycle) |

### Feature Matrix

| Feature | Crate | Bastille | Gap |
|---------|-------|----------|-----|
| Create container | create (archive) | create (thin/thick/clone/vnet/linux) | Crate lacks thin/thick modes |
| Run container | run (ephemeral) | start/stop/restart (persistent) | Different philosophies |
| List containers | **Missing** | list -a (JID, State, IP, Ports, etc.) | **Critical gap** |
| Destroy/clean | **Missing** | destroy (ZFS-aware, force stop) | **Critical gap** |
| Config file | **Missing** (in TODO) | bastille.conf (paths, ZFS, network, templates) | **Important gap** |
| Export/Import | **Missing** | export (xz/gz/tgz/raw ZFS), import | **Important gap** |
| Clone | **Missing** | clone (ZFS clone + new IP) | Nice to have |
| IPv6 | **Missing** | validate_ip() dual-stack, ip6.addr | **Important gap** |
| VNET bridge | epair only | epair + jib bridge + custom bridge (-B) | **Important gap** |
| Port rdr (dynamic) | ipfw NAT (per-spec) | pf rdr anchors (dynamic add/remove/list) | Partial |
| Console access | **Missing** | console (jexec login shell) | **Useful gap** |
| Rename | **Missing** | rename (jail + ZFS dataset) | Nice to have |
| securelevel | **Missing** | securelevel=2 by default | **Security gap** |
| children.max | **Missing** | Not in bastille either | Enhancement |
| CPU pinning | **Missing** | Not in bastille either | Enhancement |
| JSON output | **Missing** | `jls --libxo json` | **UX gap** |
| Logging | stderr only (LOG macro) | exec.consolelog per jail | **Important gap** |
| Templates (base) | templates/ dir (YAML merge) | templates/ dir (shell-based) | Crate's is cleaner |
| DNS filtering | unbound-based per-jail | Not in bastille | Crate advantage |
| Firewall policy | pf anchors per-jail | pf anchors per-jail (rdr) | Both have it |
| X11 isolation | Shared + Nested (Xephyr) | Not in bastille | Crate advantage |
| Clipboard proxy | xclip-based proxy | Not in bastille | Crate advantage |
| D-Bus isolation | Per-jail session bus | Not in bastille | Crate advantage |
| Socket proxy | socat-based | Not in bastille | Crate advantage |
| COW filesystem | ZFS clone + unionfs | Not in bastille | Crate advantage |
| Encryption check | ZFS encryption verification | Not in bastille | Crate advantage |
| MAC bsdextended | ugidfw rules | Not in bastille | Crate advantage |
| Capsicum | Planned (§8) | Not in bastille | Crate advantage |
| RCTL limits | Per-jail (deny) | rctl command wrapper | Both have it |
| ZFS snapshots | snapshot (create/list/restore/delete/diff) | zfs (set/get/snap/df) | Crate has diff |
| Signal handling | SIGINT/SIGTERM → RAII cleanup | Basic trap | Crate is better |
| Batch operations | **Missing** | TARGET=ALL for most commands | Nice to have |
| validate command | Cross-check warnings | verify (base checksum) | Different scopes |
| pkgbase bootstrap | FreeBSD 16+ ready | Traditional base.txz only | Crate advantage |

### Key Bastille Concepts Worth Porting

1. **Global config file** — bastille.conf defines paths, ZFS pool, network settings, compression
   options, templates, timezone. Crate has nothing — all is hardcoded in `locs.cpp`.

2. **`list` command with formatted table** — bastille shows JID, State, IP, Ports, Hostname,
   Release, Path for all containers (running and stopped). Critical for operational visibility.

3. **`securelevel = 2`** — bastille sets this by default in jail.conf. Crate never sets it.
   This is a significant security hardening that prevents:
   - Modification of immutable file flags
   - Writing to kernel memory
   - Loading kernel modules inside jail

4. **IPv6 dual-stack** — bastille validates IPv6 addresses and sets `ip6.addr` / `ip6 = new`.
   Crate's `net.cpp` only handles AF_INET. The epair setup in `run.cpp` only assigns IPv4.

5. **VNET bridge modes** — bastille supports three modes:
   - Default: `jib addm` (automatic bridge)
   - `-B`: custom external bridge (user-specified)
   - `-V`: unique per-jail bridge
   Crate only has direct epair (no bridge, no shared L2 segment).

6. **Export/Import** — bastille supports ZFS send/recv (raw, gz, xz) and tar-based (tgz, txz).
   Crate has `.crate` archives but no migration between hosts.

7. **Console access** — `bastille console TARGET` gives interactive shell access.
   Crate has no way to attach to a running container.

---

## 2. Refactoring Plan for Crate 0.2.1

### Phase 0: Prerequisites (no code changes)

**Goal:** Establish baseline, ensure CI passes, tag current state.

- [ ] Verify `tests/ci-verify.sh` passes on FreeBSD 14.2 and 15.0
- [ ] Tag current code as `v0.2.0` release point
- [ ] Create tracking issue for 0.2.1 milestone

---

### Phase 1: Architecture — Split `run.cpp` and Add Config File

**Goal:** Break the monolithic 1179-line `run.cpp` into focused modules.
Make the codebase extensible for new commands.

**Rationale:** `run.cpp` contains networking setup (~200 lines), jail creation (~150 lines),
firewall rules (~150 lines), X11/clipboard/D-Bus setup (~150 lines), services management
(~50 lines), DNS filtering (~50 lines), and the main execution loop. Each of these is an
independent concern that should live in its own module.

#### 1a. Extract networking into `run_net.cpp/h`

New files: `run_net.h`, `run_net.cpp`

Extract from `run.cpp`:
- Gateway detection (lines 566-584): `detectGateway()` → returns `{gwIface, hostIP, hostLAN}`
- Epair creation (lines 591-632): `createEpair()` → returns epair info struct
- IP allocation (lines 597-609): `allocateEpairIps()` — the `numToIp` lambda
- Firewall rule setup (lines 634-748): `setupFirewallRules()` → returns cleanup callback
- PF anchor setup (lines 750-780): `setupPfAnchor()` → returns cleanup callback
- Resolv.conf copy (lines 588-589)

Interface:
```cpp
namespace RunNet {
  struct GatewayInfo { std::string iface, hostIP, hostLAN; };
  struct EpairInfo { std::string ifaceA, ifaceB, ipA, ipB; unsigned num; };

  GatewayInfo detectGateway();
  EpairInfo createEpair(int jid);
  void destroyEpair(const std::string &ifaceA);
  RunAtEnd setupFirewallRules(const Spec &spec, const EpairInfo &epair,
                              const GatewayInfo &gw, int origIpForwarding);
  RunAtEnd setupPfAnchor(const Spec &spec, const EpairInfo &epair,
                         const std::string &jailXname);
}
```

**Risk:** Medium. Firewall rules are tightly coupled to epair state. Must preserve
exact rule numbers and cleanup order. Tests should verify multi-crate concurrent scenarios.

#### 1b. Extract jail lifecycle into `run_jail.cpp/h`

New files: `run_jail.h`, `run_jail.cpp`

Extract:
- Jail creation (lines 413-508): `createJail()` → returns `{jid, jailFd}`
- Jail destroy (lines 486-505): `destroyJail()` callback
- RCTL limits (lines 510-524): `applyRctlLimits()`
- ZFS dataset attach (lines 527-543): `attachZfsDatasets()`
- User creation (lines 797+): `createUserInJail()`

#### 1c. Extract GUI/isolation into `run_gui.cpp/h`

New files: `run_gui.h`, `run_gui.cpp`

Extract:
- X11 setup (lines 348-397): all three modes (none/shared/nested)
- Clipboard proxy (lines 1037-1075)
- D-Bus isolation (lines 964-993)

#### 1d. Extract services/DNS into `run_services.cpp/h`

New files: `run_services.h`, `run_services.cpp`

Extract:
- DNS filtering (lines 921-962)
- Managed services (lines 996-1013)
- Service start/stop (lines 1016-1019, 1127-1140)
- Socket proxy (lines 880-919)

#### 1e. Add global config file `config.cpp/h`

New files: `config.h`, `config.cpp`

**Config file locations** (bastille-inspired, in priority order):
1. `~/.config/crate/crate.yml` (user override)
2. `/usr/local/etc/crate.yml` (system-wide)

**Config keys** (derived from bastille.conf + crate's hardcoded values):
```yaml
# Paths
prefix: /var/run/crate          # was Locations::jailDirectoryPath
cache: /var/cache/crate          # was Locations::cacheDirectoryPath
logs: /var/log/crate             # NEW: structured logging

# ZFS
zfs_enable: false                # NEW
zfs_zpool: ""                    # NEW: default pool for COW/snapshots
zfs_options: "-o compress=lz4 -o atime=off"  # NEW

# Networking
network_interface: ""            # NEW: override gateway auto-detection
ipv6_enable: false               # NEW: Phase 3

# Base system
base_url: "https://download.freebsd.org/..."  # was Locations::baseArchiveUrl
bootstrap_method: "base_txz"     # "base_txz" or "pkgbase"

# Security defaults
securelevel: 2                   # NEW: from bastille
children_max: 0                  # NEW: prevent jail-in-jail

# Search path for .crate files
search_path:                     # was in TODO
  - "."
  - "~/.local/share/crate"
  - "/usr/local/share/crate"

# Compression
compress_xz_options: "-T0"       # was Cmd::xzThreadsArg
```

Modify `locs.cpp` to read from config instead of hardcoding.
Modify `args.cpp` to respect search_path for `crate run <name>`.

**Risk:** Low. Config is additive — all values have defaults matching current behavior.

#### 1f. Structured logging

New file: `log.h`, `log.cpp`

Replace the ad-hoc `LOG(...)` macros in `run.cpp` and `create.cpp` with a unified logger:

```cpp
namespace Log {
  enum Level { Debug, Info, Warn, Error };
  void init(const std::string &logFile, Level minLevel);
  void log(Level level, const std::string &component, const std::string &msg);
}
// Macro: CLOG(level, component, msg...)
```

Log to file (from config `logs` path) and optionally to stderr (when `-v` flag is given).

**Dependency:** Requires 1e (config file) for log path.

---

### Phase 2: New Commands — `list`, `info`, `clean`, `console`

**Goal:** Add essential operational commands inspired by bastille.

**Dependency:** Phase 1e (config file) for paths. Phase 1f (logging) optional.

#### 2a. `crate list` command

New file: `list.cpp`

Modify: `args.cpp/h` (add `CmdList`), `main.cpp` (dispatch), `commands.h`

**Output format** (inspired by bastille `list -a`):
```
JID   State   IP Address     Spec            PID    Started
12    Up      10.0.0.101     firefox.crate   4521   2025-01-15 10:23
-     Down    -              nginx.crate     -      -
```

**Implementation:**
- Scan `/var/run/crate/jail-*` directories for active crates
- Parse `/var/run/crate/jail-*/+CRATE.SPEC` for spec metadata
- Use `jls` (via `jail_getv()` C API, not shell) to get JID, IP, state
- PID tracking: write `getpid()` to `/var/run/crate/jail-*/+CRATE.PID` in run.cpp

**JSON output** (`-j` flag): serialize to JSON using simple manual formatting
(no external library needed — crate avoids dependencies).

**Risk:** Low. Read-only operation. Main risk is stale jail directories.

#### 2b. `crate info <name>` command

New file: `info.cpp`

Shows detailed information about a specific running/stopped crate:
- Spec contents (parsed YAML summary)
- Jail parameters (JID, path, hostname, vnet)
- Network info (epair, IPs, firewall rules, ports)
- Resource limits (RCTL)
- ZFS datasets
- Uptime/PID

Uses `jail_getv()` C API + `rctl` + `ifconfig` + `zfs list`.

#### 2c. `crate clean` command

New file: `clean.cpp`

Cleans up orphaned resources from crashed crate instances:
- Stale jail directories in `/var/run/crate/jail-*` (check PID liveness)
- Orphaned epair interfaces (`ifconfig -l | grep epair`)
- Stale ipfw rules (check FwSlots for dead PIDs — already has `garbageCollect()`)
- Stale pf anchors (list `crate/*` anchors, check matching jails)
- Stale RCTL rules

This is the counterpart to bastille's `destroy --force`.

**Risk:** Medium. Must be careful not to clean up resources belonging to running crates.
Use PID liveness checks and FwSlots file locking.

#### 2d. `crate console <jail>` command

New file: `console.cpp`

Opens interactive shell in a running crate (like bastille's `console`):
```
crate console jail-firefox-a1b2
```

Implementation: `jexec -l -U <user> <jid> /bin/sh` via `execvp` (replaces current process).

**Risk:** Low. Straightforward `jexec` wrapper.

#### 2e. Update `args.cpp` for new commands

Add to argument parser:
- `CmdList` — `crate list [-j]`
- `CmdInfo` — `crate info <jail-name>`
- `CmdClean` — `crate clean [-n|--dry-run]`
- `CmdConsole` — `crate console <jail-name> [command...]`

---

### Phase 3: Networking Improvements

**Goal:** IPv6 support, bridge networking modes.

**Dependency:** Phase 1a (run_net.cpp extraction).

#### 3a. IPv6 support in `net.cpp`

Modify `net.cpp`:
- Add `getIfaceIp6Addresses()` — same pattern as IPv4 but with `AF_INET6`
- Add `getIfaceIp6LinkLocal()` for VNET
- Modify `getNameserverIp()` to return both IPv4 and IPv6 nameservers

Modify `spec.h/cpp`:
- Add `NetOptDetails::outboundWan6`, `outboundLan6`, `outboundDns6`
- Add `inboundPortsTcp6`, `inboundPortsUdp6`
- IPv6 address ranges for jail-side epair

Modify `run_net.cpp`:
- IPv6 address allocation (fd00:crate::/48 ULA prefix)
- `ifconfig epairNb inet6 fd00:crate::N/127`
- IPv6 NAT (ipfw nat64 or ip6fw)
- IPv6 firewall rules
- IPv6 default route in jail

**Risk:** High. IPv6 NAT on FreeBSD is significantly different from IPv4. Options:
- ipfw nat64lsn/nat64stl (stateful/stateless NAT64)
- pf nat66 (NPTv6)
- Or simpler: just route IPv6 natively (no NAT, give jail real IPv6)

Recommended approach for 0.2.1: **IPv6 pass-through only** (no NAT).
Assign jail a real IPv6 address from the host's /64, route directly.
Full IPv6 NAT deferred to 0.3.0.

#### 3b. Bridge networking mode

Add to `spec.h`:
```cpp
struct NetOptDetails {
  // ... existing ...
  std::string mode = "epair";  // "epair" (default), "bridge", "passthrough"
  std::string bridgeInterface; // for "bridge" mode
};
```

In `run_net.cpp`, add bridge mode (inspired by bastille's VNET):
- Create `if_bridge` interface
- Add epair-a to bridge
- Add host's external interface to bridge
- Jail gets L2 connectivity to the physical network

**Risk:** High. Bridge mode changes the security model — jail is on the same L2 segment
as the host network. Must be opt-in only. Also requires `if_bridge` kernel module.

---

### Phase 4: Security Enhancements

**Goal:** Harden default jail parameters, add CPU isolation.

**Dependency:** Phase 1e (config file) for defaults.

#### 4a. `securelevel` support

Modify `run_jail.cpp`:
- Add `"securelevel"` parameter to `jail_setv()` call
- Default: `"2"` (from config, bastille's default)
- Overridable in spec YAML: `security/securelevel: 0|1|2|3`

Modify `spec.h`:
```cpp
int securelevel = -1;  // -1 = use config default (2)
```

**Risk:** Low. Securelevel is a standard jail parameter. Level 2 is widely used.
May break crates that need to modify file flags — add a warning in validate.cpp.

#### 4b. `children.max` support

Modify `run_jail.cpp`:
- Add `"children.max"` parameter to `jail_setv()` call
- Default: `"0"` (prevent jail-in-jail attacks)
- Overridable in spec YAML: `security/children_max: N`

**Risk:** Low. Standard jail parameter.

#### 4c. CPU pinning via `cpuset`

Modify `spec.h`:
```cpp
std::string cpuset;  // e.g., "0-3", "0,2,4"
```

In `run_jail.cpp`, after jail creation:
```cpp
if (!spec.cpuset.empty())
  Util::execCommand({CRATE_PATH_CPUSET, "-j", jidStr, "-l", spec.cpuset}, "apply cpuset");
```

Add `CRATE_PATH_CPUSET` to `pathnames.h`.

**Risk:** Low. `cpuset -j` is a standard FreeBSD tool.

#### 4d. Validate command enhancements

Modify `validate.cpp`:
- Add warning for `securelevel < 2` in spec
- Add warning for `children_max > 0`
- Add warning for bridge networking mode (L2 exposure)
- Cross-check cpuset against available CPUs

---

### Phase 5: Export/Import

**Goal:** Enable crate migration between hosts.

**Dependency:** Phase 2a (list command) for listing exportable crates.

#### 5a. `crate export` command

New file: `export.cpp`

**Two modes** (inspired by bastille):
1. **Archive mode** (for any filesystem): tar+xz of jail root
2. **ZFS mode** (ZFS only): `zfs send` stream (raw, compressed, or incremental)

```
crate export firefox.crate [-o /path/to/output] [--format xz|gz|zfs-raw|zfs-xz]
crate export --zfs-dataset tank/crate/jails/firefox [-o /path/to/output]
```

Implementation:
- Stop running crate (or `--safe` mode: snapshot first)
- Archive: `tar cf - -C <jailpath> . | xz -T0 > output.crate.export.xz`
- ZFS: `zfs send [-R] <dataset>[@snap] | xz > output.zfs.xz`
- Generate SHA256 checksum file alongside

#### 5b. `crate import` command

New file: `import.cpp`

```
crate import /path/to/export.crate.export.xz
crate import --zfs /path/to/export.zfs.xz --dataset tank/crate/jails/imported
```

Implementation:
- Verify SHA256 checksum
- Archive: extract to new jail directory
- ZFS: `xz -d | zfs recv <dataset>`
- Validate extracted +CRATE.SPEC

**Risk:** Medium. Must handle cross-version FreeBSD imports carefully.
SHA256 verification is essential for integrity.

---

### Phase 6: UX Improvements

**Goal:** Better user experience, machine-readable output.

**Dependency:** Phases 1-2 complete.

#### 6a. JSON output for all commands

Add `-j`/`--json` flag to `args.cpp`.

Modify list, info, snapshot commands to output JSON when requested.
Simple JSON serialization (no library dependency):

```cpp
namespace Json {
  std::string object(const std::vector<std::pair<std::string,std::string>> &kv);
  std::string array(const std::vector<std::string> &items);
  std::string string(const std::string &s);
}
```

#### 6b. Colored output improvements

Currently uses `rang.hpp`. Add `NO_COLOR` env var support (like bastille's `colors.pre.sh`):
```cpp
if (::getenv("NO_COLOR") != nullptr)
  rang::setControlMode(rang::control::Off);
```

#### 6c. Shell completion

New file: `completions/crate.bash`, `completions/crate.zsh`

Generate from command structure in args.cpp.

#### 6d. Man page

New file: `crate.1` (mdoc format)

---

## 3. Implementation Order & Dependencies

```
Phase 0 (tag v0.2.0)
  │
  ├── Phase 1a (run_net.cpp)
  ├── Phase 1b (run_jail.cpp)
  ├── Phase 1c (run_gui.cpp)
  ├── Phase 1d (run_services.cpp)
  ├── Phase 1e (config.cpp) ←── independent of 1a-1d
  └── Phase 1f (log.cpp) ←── depends on 1e
        │
        ├── Phase 2a (list) ←── needs 1e for paths
        ├── Phase 2b (info)
        ├── Phase 2c (clean)
        └── Phase 2d (console)
              │
              ├── Phase 3a (IPv6) ←── needs 1a
              ├── Phase 3b (bridge) ←── needs 1a
              │
              ├── Phase 4a (securelevel) ←── needs 1b, 1e
              ├── Phase 4b (children.max) ←── needs 1b
              ├── Phase 4c (cpuset) ←── needs 1b
              └── Phase 4d (validate++) ←── needs 4a-4c
                    │
                    ├── Phase 5a (export) ←── needs 2a
                    └── Phase 5b (import)
                          │
                          ├── Phase 6a (JSON output) ←── needs 2a, 2b
                          ├── Phase 6b (NO_COLOR)
                          ├── Phase 6c (completions)
                          └── Phase 6d (man page)
```

**Recommended sprint grouping for 0.2.1:**

| Sprint | Phases | Deliverable |
|--------|--------|-------------|
| Sprint 1 | 1a, 1b, 1e | Modular run.cpp + config file |
| Sprint 2 | 1c, 1d, 1f | Complete run.cpp extraction + logging |
| Sprint 3 | 2a, 2b, 2c, 2d | New commands (list/info/clean/console) |
| Sprint 4 | 4a, 4b, 4c, 4d | Security hardening |
| Sprint 5 | 3a (IPv6 pass-through only) | Basic IPv6 |
| Sprint 6 | 5a, 5b | Export/Import |
| Sprint 7 | 6a, 6b, 6c | UX polish |

**What to defer to 0.3.0:**
- Full IPv6 NAT (Phase 3a full)
- Bridge networking (Phase 3b) — security implications need more design
- Linux jail support (bastille has it, but crate's philosophy is FreeBSD-native)
- Thin/thick jail modes (bastille concept, doesn't fit crate's archive model)
- Batch operations (TARGET=ALL) — less relevant for ephemeral containers

---

## 4. Risk Summary

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| run.cpp split breaks cleanup order | High | Medium | Keep RunAtEnd chain intact, integration tests |
| IPv6 NAT complexity | Medium | High | Defer full NAT to 0.3.0, do pass-through only |
| Config file breaks existing usage | Low | Low | All defaults match current behavior |
| Bridge mode security exposure | High | Low | Opt-in only, warnings in validate |
| Cross-version export/import | Medium | Medium | SHA256 checksums, version metadata |
| FwSlots race conditions | High | Low | Already uses file locking |

---

## 5. Crate Advantages to Preserve

The following crate features are **superior** to bastille and must NOT be regressed:

1. **exec-based execution** — no shell injection, no command substitution
2. **CWE-426 hardened paths** — all external commands via absolute paths in pathnames.h
3. **Environment sanitization** — cleared and rebuilt for setuid safety
4. **JAIL_OWN_DESC** — race-free jail removal, auto-cleanup on crash (FreeBSD 15.0+)
5. **FwSlots dynamic allocation** — eliminates firewall rule conflicts between concurrent crates
6. **RAII cleanup chain** — RunAtEnd ensures resources are freed even on exceptions/signals
7. **DNS filtering** — per-jail unbound config, not available in bastille
8. **X11/clipboard/D-Bus isolation** — desktop containerization features
9. **COW filesystem** — ephemeral/persistent modes with ZFS/unionfs
10. **pkgbase bootstrap** — forward-looking FreeBSD 16+ support
11. **Spec validation** — cross-check warnings for misconfigurations
12. **Template merging** — composable YAML specs via mergeSpecs()
