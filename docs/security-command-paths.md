# Security: External Command Paths

## Why absolute paths?

Crate is a **setuid root** binary. When a setuid program executes external commands
by name (e.g., `zfs`, `ipfw`), the shell searches for them using the `PATH`
environment variable. An attacker can set `PATH=/tmp/evil:$PATH` and place a
malicious script named `zfs` in `/tmp/evil/` — it would execute as root.

This is [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html).

## How crate handles this

Crate uses a three-layer defense against untrusted search path attacks:

### 1. Centralized path definitions (`pathnames.h`)

All external command paths are defined as compile-time constants in `pathnames.h`:

```cpp
#define CRATE_PATH_ZFS        "/sbin/zfs"
#define CRATE_PATH_IPFW       "/sbin/ipfw"
#define CRATE_PATH_IFCONFIG   "/sbin/ifconfig"
// ... ~30 commands total
```

This follows the same pattern as FreeBSD's system `<paths.h>` which defines
`_PATH_IFCONFIG`, `_PATH_MOUNT`, etc. for base system utilities.

### 2. Environment sanitization (`main.cpp`)

On startup, before any other operations, crate:

1. Saves `TERM`, `DISPLAY`, `WAYLAND_DISPLAY`, `LANG`, `XAUTHORITY`
2. Clears the entire environment (`environ = empty_env`)
3. Sets a safe `PATH` from `_PATH_DEFPATH` (`/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin`)
4. Restores only the saved safe variables

This prevents `LD_PRELOAD`, `LD_LIBRARY_PATH`, and other dangerous variables from
being inherited by child processes.

### 3. `execv` instead of `execvp`

All command execution uses `execv()` (which requires an absolute path) instead of
`execvp()` (which searches `PATH`). Similarly, `execl()` is used instead of `execlp()`.

## Overriding command paths

For non-standard FreeBSD installations where commands are in different locations,
paths can be overridden at **compile time** via Makefile:

```sh
# Example: ZFS installed from ports instead of base
make CXXFLAGS+='-DCRATE_PATH_ZFS="/usr/local/sbin/zfs"'

# Multiple overrides
make CXXFLAGS+='-DCRATE_PATH_ZFS="/usr/local/sbin/zfs" -DCRATE_PATH_XEPHYR="/usr/local/bin/Xephyr"'
```

The `#ifndef` guards in `pathnames.h` allow any path to be overridden without editing
the header file.

### Why not a runtime config file?

For a setuid binary, a runtime configuration file (`paths.conf`) would be an additional
attack vector — if an attacker can modify the config, they can redirect command execution.
CWE-426 explicitly warns: *"Do not allow these settings to be modified by an external party."*

Compile-time configuration has no runtime attack surface.

## Comparison with other FreeBSD tools

| Tool | Approach | setuid? |
|------|----------|---------|
| **FreeBSD `<paths.h>`** | `#define _PATH_*` compile-time constants | Yes (login, su) |
| **sudo** | `secure_path` in sudoers config | No (uses suid helper) |
| **iocage** | Hardcoded safe PATH + absolute paths for critical commands | No |
| **cbsd** | `cmdboot` auto-generates `cmd.subr` with `which` at init time | No |
| **BastilleBSD** | PATH-relative bare names | No |
| **crate** | `pathnames.h` compile-time + env sanitization + `execv` | **Yes** |

## Default paths

See `pathnames.h` for the complete list. All defaults match standard FreeBSD base
system locations (`/sbin/`, `/usr/sbin/`, `/usr/bin/`, `/bin/`). Ports/packages
commands default to `/usr/local/bin/` or `/usr/local/sbin/`.

### FreeBSD base system commands

| Define | Default path | Used for |
|--------|-------------|----------|
| `CRATE_PATH_ZFS` | `/sbin/zfs` | ZFS snapshots, clones, datasets, encryption |
| `CRATE_PATH_IPFW` | `/sbin/ipfw` | Firewall rules for NAT and jail networking |
| `CRATE_PATH_PFCTL` | `/sbin/pfctl` | pf anchor rules (alternative to ipfw) |
| `CRATE_PATH_IFCONFIG` | `/sbin/ifconfig` | epair interface setup |
| `CRATE_PATH_ROUTE` | `/sbin/route` | Default route in jails |
| `CRATE_PATH_DEVFS` | `/sbin/devfs` | Device filesystem rules |
| `CRATE_PATH_JEXEC` | `/usr/sbin/jexec` | Command execution inside jails |
| `CRATE_PATH_PKG` | `/usr/sbin/pkg` | Package installation during crate creation |
| `CRATE_PATH_RCTL` | `/usr/bin/rctl` | Resource limits (RCTL) |
| `CRATE_PATH_UGIDFW` | `/usr/sbin/ugidfw` | MAC bsdextended rules |

### Ports/packages commands

| Define | Default path | Used for |
|--------|-------------|----------|
| `CRATE_PATH_XEPHYR` | `/usr/local/bin/Xephyr` | Nested X11 server for GUI isolation |
| `CRATE_PATH_SOCAT` | `/usr/local/bin/socat` | Unix socket proxying |
| `CRATE_PATH_UNBOUND` | `/usr/local/sbin/unbound` | Per-jail DNS filtering |
