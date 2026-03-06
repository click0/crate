# Compatibility Analysis of the `crate` Project with FreeBSD 15.0

**Date of analysis:** 2026-02-19
**FreeBSD version:** 15.0-RELEASE (released December 2, 2025)
**Project:** crate — a containerization tool for FreeBSD (C++17)

---

## Overall Assessment

**Compatibility level: MODERATE (changes required)**

The `crate` project is a native FreeBSD application written in C++17 and is generally
well-compatible with FreeBSD 15.0. However, there are a number of issues of varying
severity that require attention.

---

## 1. Critical Issues (CRITICAL)

### 1.1. base.txz Download URL — FTP Deprecated

**File:** `locs.cpp:15-17`

```cpp
const std::string baseArchiveUrl = STRg("ftp://ftp1.freebsd.org/pub/FreeBSD/snapshots/"
                                        << Util::getSysctlString("hw.machine") << "/"
                                        << Util::getSysctlString("kern.osrelease")
                                        << "/base.txz");
```

**Issue:** The project uses `ftp://ftp1.freebsd.org/pub/FreeBSD/snapshots/` for downloading
base.txz. In FreeBSD 15.0:

- `ftpd(8)` has been removed from the base system
- The canonical URL has been changed to `https://download.freebsd.org/`
- FreeBSD FTP servers are being gradually decommissioned

The `fetch` command (used in `create.cpp:282`) supports HTTPS, but the URL itself points
to a potentially unavailable FTP server.

Additionally, with the transition to **pkgbase** in FreeBSD 15.0, the structure of distribution
sets is changing. In FreeBSD 16, a complete transition away from distribution sets (base.txz,
kernel.txz) in favor of pkgbase is planned. To create jails via pkgbase, use:
`pkg -r /jails/myjail install FreeBSD-set-base`.

**Action:** Replace the URL with `https://download.freebsd.org/releases/` or
`https://download.freebsd.org/snapshots/`, and in the long term, implement pkgbase support.

### 1.2. ipfw Binary Incompatibility in Jails

**Files:** `run.cpp:264-338`, `create.cpp:212-216`

**Issue:** The compatibility code for `ipfw` binaries from FreeBSD 7/8 has been removed
from the FreeBSD 15.0 kernel (commit `4a77657cbc01`). When running containers created
on FreeBSD 14.x on a FreeBSD 15.0 host, `ipfw` inside the jail will not work:

```
ipfw: setsockopt(IP_FW_XDEL): Invalid argument
ipfw: getsockopt(IP_FW_XADD): Invalid argument
```

This directly affects the `crate` networking stack, as the project actively uses `ipfw`
for NAT and traffic filtering inside and outside the jail.

**Action:** Containers created on FreeBSD <15.0 must be recreated with base.txz
from FreeBSD 15.0. Adding a version check at startup is recommended.

### 1.3. TCP Checksum Offload Bug in epair Interfaces

**File:** `run.cpp:230-248`

```cpp
std::string epipeIfaceA = Util::stripTrailingSpace(
    Util::runCommandGetOutput("ifconfig epair create", "create the jail epipe"));
std::string epipeIfaceB = STR(epipeIfaceA.substr(0, epipeIfaceA.size()-1) << "b");
```

**Issue:** After upgrading to FreeBSD 15.0, users are widely reporting network access
problems from VNET jails via epair interfaces
([Forum](https://forums.freebsd.org/threads/no-access-to-external-network-from-vnet-jails-in-15-0-release.100669/)).

Root cause: epair supports `TXCSUM`/`TXCSUM6` (checksum offloading) and delegates checksum
computation to the physical interface. If packets do not leave the host (jail->host or
jail->jail), the checksum is never computed and packets are dropped.

**Action:** After creating epair interfaces, add:
```
ifconfig epairXa -txcsum -txcsum6
ifconfig epairXb -txcsum -txcsum6
```

There are also reported issues with interface naming when moving into a jail — `vnet0.X`
may appear instead of the expected `epairXb`
([Forum](https://forums.freebsd.org/threads/epair0-behaves-like-schrodingers-cat-and-is-not-working-anymore-after-upgrading-to-15-0.101110/)).
Testing of interface name parsing is required.

---

## 2. High Priority (HIGH)

### 2.1. Jail API — New File Descriptors

**File:** `run.cpp:158-169`

```cpp
res = ::jail_setv(JAIL_CREATE,
  "path", jailPath.c_str(),
  "host.hostname", Util::gethostname().c_str(),
  "persist", nullptr,
  "allow.raw_sockets", optNet,
  "allow.socket_af", optNet,
  "vnet", nullptr,
  nullptr);
```

**Changes in FreeBSD 15.0:**
- New syscalls added: `jail_set(2)`, `jail_get(2)`, `jail_attach_jd(2)`,
  `jail_remove_jd(2)` for working via file descriptors
- Race conditions associated with using jail IDs have been eliminated
- `meta` and `env` parameters added for metadata and environment variables
- `zfs.dataset` support for attaching ZFS datasets

**Status:** The existing code using `jail_setv()` and `jail_remove()` continues to work
(backward compatibility is preserved), but migration to the new API is recommended
to eliminate race conditions.

**Action:** Consider migrating to the jail descriptor API for reliability.

### 2.2. `sys/jail.h` Is Not C++-Safe

**File:** `run.cpp:21-23`

```cpp
extern "C" { // sys/jail.h isn't C++-safe: https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=238928
#include <sys/jail.h>
}
```

**Status:** Based on available information, bug #238928 remains unfixed in FreeBSD 15.0.
The `extern "C"` wrapper is still necessary. Verification during build is required.

### 2.3. Changed Behavior of `setgroups(2)` / `getgroups(2)`

**Files:** `run.cpp:364-367` (usage of `pw useradd`, `pw groupadd`, `pw usermod`)

**Change in FreeBSD 15.0:** `setgroups(2)`, `getgroups(2)`, and `initgroups(3)` have been
modified — the effective group ID is no longer included in the array. This may affect
user configuration inside jails via `pw`.

**Action:** Test user and group creation inside the jail with FreeBSD 15.0 base,
ensure that group membership (wheel, videoops) is correct.

---

## 3. Medium Priority (MEDIUM)

### 3.1. `_WITH_GETLINE` — Likely No Longer Required

**File:** `util.cpp:20`

```cpp
#define _WITH_GETLINE // it breaks on 11.3 w/out this, but the manpage getline(3) doesn't mention _WITH_GETLINE
```

**Change:** In FreeBSD 15.0, `getline()` is exported by default without requiring the
definition of `_WITH_GETLINE` or `_POSIX_C_SOURCE`. Defining `_WITH_GETLINE` does not
cause an error, but constitutes dead code.

**Action:** `#define _WITH_GETLINE` can be safely removed. If backward compatibility
with FreeBSD <15.0 is needed, it can be kept with a comment.

### 3.2. LLVM/Clang Updated to Version 19.1.7

**File:** `Makefile:10`

```makefile
CXXFLAGS+= -Wall -std=c++17
```

**Change:** FreeBSD 15.0 ships with Clang 19.1.7 (FreeBSD 14.0 had Clang 16.0.6).
Clang 19 introduces new warnings and tightens checks.

**Potential issues:**
- New warnings under `-Wall` (particularly for C-style casts, implicit conversions)
- Stricter C++17 conformance checking
- GoogleTest (if used) now requires C++14 as a minimum

**Action:** Perform a test build and check for new warnings/errors.

### 3.3. Changed Behavior of Bridge Interfaces

**File:** `run.cpp:230-248` (epair interfaces)

**Change:** In FreeBSD 15.0, bridge now resolves IP only on the bridge itself, not on
member interfaces. This may affect the VNET jail network configuration if bridge interfaces
are used.

**Status:** `crate` uses epair directly (without bridge), so this change most likely
does not affect the project directly, but requires attention when expanding network
capabilities.

### 3.4. VNET sysctl as Loader Tunables

**File:** `run.cpp:109-115`

```cpp
if (Util::getSysctlInt("kern.features.vimage") == 0)
    ERR(...)
if (Util::getSysctlInt("net.inet.ip.forwarding") == 0)
    Util::setSysctlInt("net.inet.ip.forwarding", 1);
```

**Change:** VNET sysctl variables can now be loader tunables (`CTLFLAG_TUN` extension).
This means that `net.inet.ip.forwarding` and similar variables can be set via loader.conf
before the kernel is loaded.

**Action:** Functionality is not broken, but documentation should be updated.

---

## 4. Low Priority (LOW)

### 4.1. `nmount()` Compatibility — OK (Improved)

**File:** `mount.cpp:28-59`

`nmount()` is a stable FreeBSD syscall. In FreeBSD 15.0, handling of the `MNT_IGNORE` flag
for devfs, fdescfs, and nullfs has been fixed — the flag is now correctly preserved through
`nmount(2)`, which reduces noise from `df(1)` and `mount(8)` for containerized workloads.
The API and call signature have not changed.

### 4.2. `O_EXLOCK` — OK

**File:** `ctx.cpp:34`

```cpp
ctx->fd = ::open(file().c_str(), O_RDWR|O_CREAT|O_EXLOCK, 0600);
```

`O_EXLOCK` is a standard BSD flag; no changes detected. Works correctly.

### 4.3. `sysctlbyname()` — OK

**Files:** `util.cpp:151-170`

The `sysctlbyname()` syscall has not undergone changes. The `sysctl(8)` utility gained
additional features (jail attachment, vnet/prison variable filtering), but the programmatic
access API is stable.

### 4.4. `kldload()` — OK

**File:** `util.cpp:172-174`

The `kldload()` API is stable; no changes detected.

### 4.5. `chflags()` — OK

**File:** `util.cpp:331-353`

The `chflags()` system call is stable; no changes detected.

### 4.6. `fdclose()` — OK

**File:** `util.cpp:276`

```cpp
if (::fdclose(file, nullptr) != 0)
```

`fdclose()` (introduced in FreeBSD 11.0) remains available in FreeBSD 15.0.

### 4.7. `readdir_r(3)` — Deprecated

The project does not use `readdir_r()` directly (using `std::filesystem::directory_iterator`
instead), but if any dependency uses `readdir_r()`, it will trigger warnings during
compilation/linking.

---

## 5. Informational Notes

### 5.1. Removed 32-bit Platforms

FreeBSD 15.0 discontinued support for i386, armv6, and 32-bit powerpc as standalone
platforms. `crate` is built on 64-bit platforms — this does not affect the project.

### 5.2. New Jail inotify

FreeBSD 15.0 added native `inotify(2)` support (Linux-compatible). This may be useful
for future expansion of `crate` functionality (e.g., monitoring changes within a jail).

### 5.3. mac_do(4) for Jails

`mac_do(4)` became production-ready in FreeBSD 15.0 and supports modifying rules
inside jails via `security.mac.do.rules`. This may be useful for managing privileges
within containers.

### 5.4. Service Jails — A New Type of Jail

FreeBSD 15.0 introduces Service Jails — a new type of jail with `path=/` (shared
filesystem with the host), configurable via one or two lines in `/etc/rc.conf`
(`<service>_svcj=YES`). This is a simplified alternative for isolating system services
that does not directly compete with `crate`, but demonstrates the direction of development
of the FreeBSD jail ecosystem.

### 5.5. OCI-Compatible Containers

FreeBSD now publishes OCI-compatible container images. This is a competing approach
to containerization that may affect the strategic development of the project.

### 5.6. pf(4) Supports OpenBSD NAT Syntax

`pf(4)` now supports OpenBSD-style NAT syntax. This does not affect `crate`
(which uses `ipfw`), but may be considered as an alternative.

---

## 6. Summary Table

| Component | File(s) | Compatible? | Priority |
|-----------|---------|-------------|----------|
| base.txz URL (FTP) | `locs.cpp:15-17` | NO | CRITICAL |
| ipfw binary compat. | `run.cpp`, `create.cpp` | PARTIAL | CRITICAL |
| epair checksum bug | `run.cpp:230-248` | PARTIAL | CRITICAL |
| jail_setv() API | `run.cpp:158-169` | YES (deprecated approach) | HIGH |
| sys/jail.h C++ | `run.cpp:21-23` | YES (workaround) | HIGH |
| setgroups/getgroups | `run.cpp:364-367` | NEEDS TESTING | HIGH |
| _WITH_GETLINE | `util.cpp:20` | YES (dead code) | MEDIUM |
| Clang 19 build | `Makefile` | NEEDS TESTING | MEDIUM |
| Bridge behavior | `run.cpp:230-248` | YES (epair OK) | MEDIUM |
| VNET sysctl | `run.cpp:109-115` | YES | MEDIUM |
| nmount() | `mount.cpp:28-59` | YES | LOW |
| O_EXLOCK | `ctx.cpp:34` | YES | LOW |
| sysctlbyname() | `util.cpp:151-170` | YES | LOW |
| kldload() | `util.cpp:172-174` | YES | LOW |
| chflags() | `util.cpp:331-353` | YES | LOW |
| fdclose() | `util.cpp:276` | YES | LOW |
| nullfs/devfs | `mount.cpp`, `run.cpp` | YES | LOW |
| epair interfaces | `run.cpp:230-232` | YES | LOW |
| pkg manager | `create.cpp:69-114` | YES | LOW |
| pw/service commands | `run.cpp:356-399` | YES | LOW |
| rc.conf system | `run.cpp:250-255` | YES | LOW |

---

## 7. Recommended Action Plan

1. **Immediately:**
   - Replace FTP URL in `locs.cpp` with HTTPS (`download.freebsd.org`)
   - Add checksum offload disabling on epair: `ifconfig epairXa -txcsum -txcsum6`
   - Perform a test build with Clang 19.1.7 on FreeBSD 15.0

2. **Short-term:**
   - Add FreeBSD version check when starting containers
   - Test ipfw NAT in the context of FreeBSD 15.0 jails
   - Verify epair interface naming when moving into a jail (vnet0.X vs epairXb)
   - Verify user/group creation via `pw` inside the jail

3. **Medium-term:**
   - Migrate to jail descriptor API (jail_set/jail_get via fd)
   - Add pkgbase support as an alternative to base.txz
   - Remove `_WITH_GETLINE` (or keep with conditional compilation)

4. **Long-term:**
   - Prepare for the complete elimination of distribution sets in FreeBSD 16
   - Consider OCI compatibility for the container format

---

## 8. Phase 6: Code Cleanup & Forward-Looking Features (2026-02-26)

All critical issues from Phase 5 have been resolved. Phase 6 focuses on eliminating
technical debt (all TODO/FIXME/XXX markers in the code) and preparing for FreeBSD 16.

### 8.1. §17: pkgbase support — **IMPLEMENTED**

- **Files:** `args.h`, `args.cpp`, `create.cpp`
- `--use-pkgbase` flag for `crate create`
- Bootstrapping jail root via `pkg -r <jailpath> install FreeBSD-runtime`, etc.
- Writes `+CRATE.BOOTSTRAP` (pkgbase|base.txz) to the container
- Preparation for FreeBSD 16, where base.txz will be replaced by pkgbase

### 8.2. §18: Dynamic ipfw rule allocation — **IMPLEMENTED**

- **Files:** `ctx.h`, `ctx.cpp`, `run.cpp`
- `FwSlots` class: file-based allocator of unique rule numbers
- Each crate receives its own slot, preventing rule conflicts
- Garbage collection removes dead PIDs during allocation
- Replaces hardcoded bases (19000/59000) with dynamic ranges (10000-29999, 50000-64999)

### 8.3. §19: IP address space documentation & overflow detection — **IMPLEMENTED**

- **File:** `run.cpp`
- Documentation of the IP allocation algorithm in 10.0.0.0/8
- Overflow detection: ERR on epairNum > 2^24
- Bitwise ops instead of division for clarity

### 8.4. §20: Jail directory permission check — **IMPLEMENTED**

- **File:** `misc.cpp`
- Checks owner (uid 0) and permissions (0700) when creating the jail directory
- Automatically corrects permissions on mismatch

### 8.5. §21: Exception handling cleanup — **IMPLEMENTED**

- **File:** `main.cpp`
- FIXME/XXX markers replaced with clean "internal error:" messages

### 8.6. §22: GL GPU vendor detection — **IMPLEMENTED**

- **File:** `spec.cpp`
- Auto-detection of GPU vendor via `pciconf -l`
- NVIDIA (0x10de) → nvidia-driver
- AMD (0x1002) / Intel (0x8086) → drm-kmod
- Fallback: nvidia-driver (legacy)

### TODO/FIXME/XXX Status

After Phase 6, there are **no remaining** TODO, FIXME, or XXX markers in the codebase.

---

## Sources

- [FreeBSD 15.0-RELEASE Release Notes](https://www.freebsd.org/releases/15.0R/relnotes/)
- [FreeBSD 15.0-RELEASE Announcement](https://www.freebsd.org/releases/15.0R/announce/)
- [FreeBSD 15 — The Register](https://www.theregister.com/2025/12/05/freebsd_15/)
- [FreeBSD 15.0 Updates — vermaden](https://vermaden.wordpress.com/2025/11/30/valuable-freebsd-15-0-release-updates/)
- [Jails and upgrades to 15.0 — Forums](https://forums.freebsd.org/threads/jails-and-upgrades-to-15-0.100558/)
- [VNET jail in FreeBSD 15 — Forums](https://forums.freebsd.org/threads/problem-about-vnet-jail-in-freebsd15.101193/)
- [FreeBSD Foundation: Fixes and Features](https://freebsdfoundation.org/our-work/journal/browser-based-edition/freebsd-15-0/freebsd-15-0-fixes-and-features/)
- [Brave New PKGBASE World — vermaden](https://vermaden.wordpress.com/2025/10/20/brave-new-pkgbase-world/)
- [Epair checksum/naming issues in 15.0 — Forums](https://forums.freebsd.org/threads/epair0-behaves-like-schrodingers-cat-and-is-not-working-anymore-after-upgrading-to-15-0.101110/)
- [VNET jail networking issues in 15.0 — Forums](https://forums.freebsd.org/threads/no-access-to-external-network-from-vnet-jails-in-15-0-release.100669/)
- [ipfw_ctl3 invalid option after upgrade — Forums](https://forums.freebsd.org/threads/upgrading-from-14-3-p6-to-15-0-ipfw_ctl3-invalid-option-98v0-97v0.100606/)
- [FreeBSD 15 Bridges, VLANs and Jails — Forums](https://forums.freebsd.org/threads/freebsd-15-bridges-vlans-and-jails-nice.101719/)
- [setgroups/getgroups changes — FreeBSD Status Report](https://www.freebsd.org/status/report-2025-04-2025-06/group-changes/)
- [MNT_IGNORE fix for devfs/nullfs](https://www.mail-archive.com/dev-commits-src-all@freebsd.org/msg53388.html)
