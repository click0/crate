# Changelog

All notable changes to **crate** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.4.3] — 2026-04-27

CLI input-validation hardening: 36 new test cases for `Args::validate`.

### Changed

- **`Args::validate()`** moved from `cli/args.cpp` into `cli/args_pure.cpp`
  so it can be linked into unit tests without dragging in
  `cli/args.cpp`'s rang/usage()/exit() dependencies.
- The default `CmdNone` branch now throws `Exception` (via `ERR(...)`)
  instead of calling the static `err()` helper that printed `usage()`
  and `exit(1)`. Net behaviour is the same — `cli/main.cpp`'s catch
  chain prints `e.what()` in red and returns 1 — except that the
  bare `crate` (no args) path no longer prints the usage hint.
- `Util::Fs::fileExists`, `Util::Fs::dirExists`, `Util::Fs::getUserHomeDir`
  moved from `lib/util.cpp` to `lib/util_pure.cpp`. All three are
  POSIX (`stat`, `getpwuid`) so they compile and link on Linux too.

### Added — tests

`tests/unit/args_validate_test.cpp` (+36 cases) exercises every branch
of `Args::validate()`:
- `Create`: empty, spec-only, template-not-found
- `Run`: empty, missing file, existing file
- `Validate`: empty, with spec
- `Snapshot`: each subcommand's required-arg combinations
- `List` / `Clean`: no-arg paths
- Target-only commands (`Info`, `Console`, `Stats`, `Logs`, `Stop`,
  `Restart`): empty + set
- `Gui`: subcommand variations (focus/attach/url/screenshot/resize
  require target; resize requires resolution)
- `Stack`: `up`/`exec` argument requirements
- `CmdNone`: bare-crate path

### Verification

- `make build-unit-tests` → 14 binaries built
- `cd tests && kyua test unit` → **200/200 pass** (was 164, +36)

---

## [0.4.2] — 2026-04-27

Test methodology rollout: every unit test now links against the real
production code. The old "duplicate the function under test into the
test source" pattern is gone. A regression in any extracted helper
will now actually fail the suite.

### Changed — extraction of pure helpers into `*_pure.cpp` modules

| New module | Function(s) extracted from |
|---|---|
| `cli/args_pure.cpp`        | `cli/args.cpp`        — `strEq`, `isShort`, `isLong`, `isCommand` |
| `snmpd/mib_pure.cpp`       | `snmpd/mib.cpp`       — `encodeUint32`, `encodeOid`, `encodeOctetString` |
| `daemon/metrics_pure.cpp`  | `daemon/metrics.cpp`  — `parseRctlUsage` |
| `lib/stack_pure.cpp`       | `lib/stack.cpp`       — `parseCidr`, `ipToString`, `ipFromCidr`, `buildHostsEntries`; templated `topoSort<T>`. Also hosts `isIpv6Address` from `lib/net.cpp`. |
| `lib/spec_pure.cpp`        | `lib/spec.cpp`        — `parsePortRange`; pure methods of `Spec::NetOptDetails` (`allowOutbound`, `allowInbound`, `isNatMode`, `needsIpfw`, `needsDhcp`); `Spec::optionExists`; ctors/dtors for `OptDetails` and `NetOptDetails` |
| `lib/lifecycle_pure.cpp`   | `lib/lifecycle.cpp`   — `humanBytes` |
| `lib/import_pure.cpp`      | `lib/import.cpp`      — `parseSha256File`, `archiveHasTraversal`, `normalizeArchiveEntry` |

Every original `.cpp` keeps a thin forwarder (or `using` declaration)
so existing call sites are unchanged.

### Changed — tests

All 13 unit-test files no longer duplicate the function under test.
They `#include` the appropriate `*_pure.h` and link against the
matching `*_pure.cpp`. Result: every test now exercises the real
production symbol.

### Build

`Makefile` `tests/unit/%` rule links every test against the full set
of pure modules:
```
TEST_LINK_SRCS = lib/util_pure.cpp lib/err.cpp lib/spec_pure.cpp \
                 lib/stack_pure.cpp lib/lifecycle_pure.cpp \
                 lib/import_pure.cpp cli/args_pure.cpp \
                 daemon/metrics_pure.cpp snmpd/mib_pure.cpp
```

`-Icli`/`-Idaemon`/`-Isnmpd` added to test include path so the
respective `*_pure.h` files resolve.

`topoSort` is now a header-only template (`StackPure::topoSort<T>`)
so production and test code share one implementation.

### Notes

- 164/164 kyua unit tests pass on Linux.
- Test-count dropped from 166 (0.4.1) to 164 because two duplicated
  `toUInt` cases that used to live in both `util_test` and `spec_test`
  now live only in `spec_test` (against the real `Util::toUInt`).

---

## [0.4.1] — 2026-04-27

Unit-test methodology fix: tests can now link against the production
code instead of embedding frozen copies of the functions under test.

### Changed

- **Pure helpers extracted from `lib/util.cpp` into `lib/util_pure.cpp`**.
  The platform-independent subset (`filePathToBareName`,
  `filePathToFileName`, `splitString`, `stripTrailingSpace`, `toUInt`,
  `reverseVector`, `shellQuote`, `safePath`, `isUrl`, `Fs::hasExtension`)
  now lives in a separate translation unit with no FreeBSD-specific
  dependencies. Production `crate`/`crated`/`crate-snmpd` still pull
  these in via `LIB_SRCS` (Makefile updated), so behaviour is identical.
- **`lib/util.h`** no longer `#include <rang.hpp>` — the include was
  unused inside the header and blocked unit-test inclusion on Linux
  (no `librang-dev`). Files that use `rang::fg` / `rang::style` now
  include `<rang.hpp>` explicitly (`lib/capsicum_ops.cpp`).
- **`lib/err.h`** no longer `#include <rang.hpp>`. The `WARN(...)` macro
  still uses rang colours; callers that use `WARN` and didn't already
  include `<rang.hpp>` had it added (`lib/{ctx,config,mount,pfctl_ops,
  gui_registry,ipfw_ops,vm_run,vm_stack}.cpp`).
- **Test build rule** now links every test against
  `lib/util_pure.cpp + lib/err.cpp`. Tests can `#include "util.h"` /
  `#include "err.h"` and call the real `Util::shellQuote` etc. instead
  of duplicating the implementation.
- **`tests/unit/util_security_test.cpp`** rewritten to use the real
  `Util::safePath` and `Util::shellQuote` from `lib/util_pure.cpp`.
  This is the proof-of-concept: a regression introduced into
  `safePath` will now fail the suite (versus the previous pattern,
  which only checked a frozen copy in the test source).
- **`tests/unit/err_test.cpp`** rewritten to use the real `Exception`
  class. Adds one new case (`err2_macro_throws_with_message`) that
  exercises the `ERR2` macro directly.

### Notes

- 165/165 kyua unit tests pass on Linux.
- The remaining test files still use the duplicate-the-function
  pattern — they will be migrated incrementally as their target code
  joins `lib/util_pure.cpp` or new pure modules.

---

## [0.4.0] — 2026-04-26

Test-coverage and CLI argument parser hardening release. Two real
bugs were caught by new unit tests during this cycle (one CLI parser,
one path-validation) and fixed in the same commit.

### Security

- **`Util::safePath()`** (lib/util.cpp) — the canonical-path prefix
  guard used a raw string-prefix comparison without requiring a path
  separator after the prefix. With `requiredPrefix = "/var/run/crate"`,
  the path `"/var/run/crate_attacker/payload"` was wrongly accepted as
  inside the prefix. One-line fix: also require
  `canonical[prefix.size()] == '/'`. `crate` is installed setuid root,
  so the impact is real if any caller relies on `safePath()` to scope
  filesystem access.

### Fixed

- **`isLong()`** (cli/args.cpp) — long-option parser had a logically
  impossible loop condition (`!islower || !isdigit`, which always
  evaluates true since no character is *both* lowercase AND a digit).
  Result: every long option (`--help`, `--log-progress`, command-level
  `--help`, etc.) returned `nullptr` from `isLong()` and silently fell
  through to "unknown argument". The CLI worked only for the few options
  with explicit `strEq` checks before `isLong` (`--no-color`,
  `--version`, `--use-pkgbase`, `--var`). Fix accepts `[a-z0-9-]+`,
  matching the documented surface.

### Added — tests

Added 6 new unit-test files, **83 new ATF cases**, all passing.
Total kyua suite: **165/165** (was 82).

| File | Cases | Covers |
|---|---|---|
| `snmpd_mib_test`      | 14 | AgentX wire encoders byte-exact vs RFC 2741 |
| `daemon_metrics_test` |  9 | `parseRctlUsage` parser |
| `stack_test`          | 17 | `ipFromCidr`, `buildHostsEntries`, `topoSort` (cycles, duplicates, missing deps, diamond, disconnected) |
| `util_security_test`  | 11 | `safePath` traversal guard + `shellQuote` injection escaping (with `/bin/sh` round-trip) |
| `import_test`         | 14 | `.sha256` parsing (BSD/GNU formats), tar-listing `..` detection, archive entry normalisation |
| `cli_args_test`       | 18 | `strEq`, `isShort`, `isLong`, `isCommand` |

### Added — build

- `make build-unit-tests` — builds every unit-test binary without
  running anything (handy when CI builds as user but runs kyua as root).
- `make coverage` — gcov/lcov instrumented build + HTML report at
  `coverage-html/index.html`. Note: tests embed local copies of the
  functions under test, so the report measures coverage of the test-
  local copies — useful for spotting un-exercised branches in test
  logic, less useful as production-code coverage.
- `.github/workflows/{linux-unit,freebsd-build-lite}.yml` now drive
  the test build through the Makefile (`make test-unit` /
  `gmake build-unit-tests`) so adding a new test takes a single edit
  (`UNIT_TESTS` in `Makefile`) instead of three (Makefile + Kyuafile +
  workflow).

---

## [0.3.15] — 2026-04-22

Full FreeBSD build restoration. After the 0.3.0 firewall rewrite,
the new CI matrix (14.2 + 15.0, full `gmake crate`) surfaced a
large backlog of latent compile/link issues that had been hidden
by the old CI (which only built a subset of files). This patch
release fixes every one of them so `gmake crate`, `gmake crated`,
and `gmake crate-snmpd` succeed cleanly on both FreeBSD versions.

### Added
- `.github/workflows/release.yml` — on tag push, builds on FreeBSD
  14.2 + 15.0 and attaches `crate-<ver>-freebsd-<rel>-amd64.tar.xz`
  (with SHA256) as GitHub Release assets. Previously the Release
  page only had auto-generated source tarballs.
- Release tarball layout: `bin/crate`, `sbin/crated`,
  `sbin/crate-snmpd`, `man/man5/crate.5.gz`,
  `share/snmp/mibs/CRATE-MIB.txt`, `crated.conf.sample`,
  `crated.rc`, `README.md`, `LICENSE`, `CHANGELOG.md`.
- `cpp-httplib` added to CI `pkg install` for the `crated` daemon.

### Fixed — missing system headers (FreeBSD 14.2 / 15.0 clang)
- `run_jail.cpp` — add `<sys/param.h>` before `<sys/jail.h>` (for
  `MAXPATHLEN`, `MAXHOSTNAMELEN`); add `<sys/wait.h>` for
  `WIFSIGNALED`/`WIFEXITED`/`WEXITSTATUS`; add `<signal.h>` for
  `SIGKILL`.
- `jail_query.cpp` — add `<sys/param.h>` before `<sys/jail.h>`.
- `zfs_ops.cpp` — add `<sys/wait.h>` for `waitpid`.
- `capsicum_ops.cpp` — add `<sys/socket.h>`, `<netinet/in.h>`,
  `<arpa/inet.h>`, `<syslog.h>`.
- `ifconfig_ops.cpp`, `stack.cpp` — add `<netinet/in.h>` for
  `struct in_addr`/`sockaddr_in`.
- `stack.cpp` — add `<sys/socket.h>` for `AF_INET`.
- `mac_ops.cpp` — add `<sys/param.h>` + `<sys/mount.h>` for
  `fsid_t` / `struct statfs`.
- `netgraph_ops.cpp` — add `<sys/socket.h>` before netgraph
  headers (for `sa_family_t`).
- `daemon/main.cpp` — add `<fcntl.h>` for `::open()`.
- `import.cpp` — add `<iomanip>` for `std::setprecision`.
- `snmpd/collector.h`, `snmpd/mib.cpp` — add `<cstdint>` for
  `uint8_t`/`uint16_t`/`uint32_t`/`uint64_t`.

### Fixed — language / standards issues
- `cli/args.cpp`, `lib/stack.cpp` — wrap raw `std::stoul` /
  `std::stoi` to throw `Exception` via `ERR2` instead of leaking
  `std::invalid_argument`/`std::out_of_range` (continuation of
  0.3.0 Util::toUInt fix).
- `run_net.h`, `run_jail.h`, `run_gui.h`, `run_services.h`,
  `pfctl_ops.h` — replace `const class Spec &spec` in-namespace
  forward declarations with proper `#include "spec.h"`. The
  in-namespace form silently created `RunNet::Spec` etc. instead
  of referencing the global `::Spec`.
- `lib/spec.h` + `lib/spec.cpp` — add `Spec` copy constructor
  and copy-assignment with deep-copy of 13 `unique_ptr` members.
  Required by `preprocess()` and `mergeSpecs()`. Previously
  silently relied on compiler-specific copy-elision behaviour.
- `lib/spec.h` — add missing `RestartPolicy` struct + `unique_ptr`
  member that were referenced in the parser but never declared.
- `lib/spec.cpp` — include `servicesAutoStart` field in copy
  constructor (was silently defaulted to `true` on copy).
- `ctx.h`, `gui_registry.h` — move `FwUsers` / `FwSlots` /
  `GuiRegistry` default constructors from `private` to `public`.
  FreeBSD 15.0 libc++ (clang 19) enforces that `std::make_unique`
  requires a public constructor.
- `lib/stack.cpp`, `lib/vm_spec.cpp` — fix yaml-cpp temp-ref
  binding (`auto &x = node["key"]`) → `auto x = ...`.
- `ipfw_ops.cpp` — remove explicit `op->ctxid = 0`. The `ctxid`
  field only exists in FreeBSD 15.0+ `ip_fw3_opheader`; callers
  already zero the struct with `memset`.
- `daemon/auth.cpp`, `daemon/routes.cpp`, `daemon/server.cpp` —
  define `CPPHTTPLIB_OPENSSL_SUPPORT` before `#include <httplib.h>`
  in every translation unit that uses httplib (ODR violation
  otherwise — different `httplib::Server` layout).
- `daemon/auth.h` — change forward declaration of `httplib::Request`
  from `class` to `struct` (`-Wmismatched-tags`).
- `run_gui.cpp` — guard `X11Ops::getResolution()` call with
  `#ifdef HAVE_X11` (was unconditional but `x11_ops.cpp` only
  compiles with `WITH_X11`).
- `cli/args.cpp` — remove `const` from scalar return type
  (`-Wignored-qualifiers`).
- `lib/spec.cpp` — add braces around ambiguous `if ... ERR ...` /
  `for` block (`-Wmisleading-indentation`).

### Fixed — linker
- `Makefile` — add `-lnetgraph` (NgMkSockNode etc.), `-lmd`
  (SHA256_Data), `-lpthread` (std::thread) to base `LIBS`. These
  are transitively required by always-compiled lib/ files.

### Fixed — tests
- `tests/functional/crate_info_test` — change shebang from
  `#!/bin/sh` to `#!/usr/bin/env atf-sh`. ATF shell functions
  (`atf_test_case`, `atf_check`) require the atf-sh interpreter;
  plain `sh` produced no ATF protocol output and kyua reported
  "broken: Invalid header for test case list".

### Removed — dead / non-functional code
- `RunNet::setupPfAnchor()` — never called; superseded by
  `PfctlOps::loadContainerPolicy()` introduced in 0.3.0.
- `PfctlOps::addNatRule()`, `PfctlOps::addRdrRule()`,
  `IpfwOps::addNatForJail()`, `IpfwOps::addPortForward()` — never
  called.
- `MacOps::nativeAddRule()` / `nativeRemoveRule()` ioctl path (79
  lines): `MAC_BSDEXTENDED_ADD_RULE` / `_REMOVE_RULE` are not
  defined in any public FreeBSD header, and `/dev/ugidfw` does
  not exist on stock FreeBSD. The `ugidfw(8)` command fallback
  is preserved and is the correct interface.
- `lib/stack.cpp::updateStackDns()` — defined but never called.
- `lib/clean.cpp::getRunningJailJids()`, `pidAlive()` — defined
  but never called.
- Duplicate `fwSlotSize` / `fwRuleRangeOutBase` statics in
  `lib/run.cpp` — single source of truth is `run_net.cpp`.

### Verification
- 39/39 non-FreeBSD files pass `-Wall -Wextra -Werror=reorder
  -Werror=return-type -Werror=mismatched-tags`.
- 16 FreeBSD-only files compile on FreeBSD CI (require
  `<sys/jail.h>`, `<libzfs.h>`, `<libpfctl.h>`, etc.).
- 82/82 kyua unit tests pass on both Linux (libatf) and FreeBSD.

---

## [0.3.1] — 2026-04-19

### Fixed
- **Build error in full `gmake crate`**: `const class Spec &spec`
  forward declarations inside `RunNet`, `RunJail`, `RunGui`,
  `RunServices` namespaces created `RunNet::Spec` (etc.) instead of
  referencing the global `::Spec`, causing "member access into
  incomplete type" errors. Replaced with proper `#include "spec.h"`
  in all five headers (`run_net.h`, `run_jail.h`, `run_gui.h`,
  `run_services.h`, `pfctl_ops.h`). This bug was hidden by the old
  CI (which compiled only 5 files) and surfaced once the new
  `freebsd-build.yml` ran the full `gmake crate`.

---

## [0.3.0] — 2026-04-19

### Added
- **Per-container firewall policy** — full IPv4+IPv6 support:
  - IPv6 outbound rules consolidated into `RunNet::setupFirewallRules()`
    (previously inline in `run.cpp`).
  - IPv6 inbound port forwarding via `ipfw fwd` (global IPv6 addresses,
    no NAT needed).
  - Unified cleanup lambda handles both IPv4 and IPv6 rule deletion.
- **`PfctlOps::loadContainerPolicy()`** — single authoritative place to
  build per-container pf rules from `spec.firewallPolicy`, with dual
  IPv4/IPv6 output.
- **Neighbor-safe firewall operations**:
  - `pfctl -s Anchors` probe on first use — `WARN` if
    `anchor "crate/*"` is missing from `/etc/pf.conf`.
  - `ipfw nat N show` probe before `configureNat()` — `WARN` on
    collision with other jail managers.
  - `CRATE_IPFW_RULE_BASE_IN`, `CRATE_IPFW_RULE_BASE_OUT`,
    `CRATE_IPFW_SLOT_SIZE` environment variables override the default
    ipfw rule ranges (10000 / 50000 / 10) so operators can avoid
    collisions with bastille/appjail/custom rulesets.
  - `PfLock` RAII (`O_EXLOCK` on `/var/run/crate/pfctl.lock`) serializes
    concurrent pfctl operations from parallel `crate run` processes.
- **CI workflows**:
  - `linux-unit.yml` — ~30 s unit-test job on `ubuntu-latest` using
    `kyua` + `libatf-dev` from Ubuntu universe.
  - `freebsd-build-lite.yml` — fast smoke check on feature branches.
  - `freebsd-build.yml` — full gated build (matrix 14.2 + 15.0) on
    master / PRs / weekly cron, with artifact upload.
- `make test-unit` target — runs `kyua test unit` (skips FreeBSD-only
  `functional/crate_info_test`), enabling local Linux development.

### Changed
- **`Util::toUInt()`** now wraps `std::stoul` and converts
  `std::invalid_argument` / `std::out_of_range` into the project's
  `Exception` via `ERR2`. No more raw stdlib exceptions leaking from
  YAML config parsing.
- Applied the same wrapping idiom across **9 additional call sites**:
  `cli/args.cpp` (logs/stop/restart timeout args), `lib/stack.cpp`
  `parseCidr()`, `lib/net.cpp` netmask, `lib/run_net.cpp` epair+CIDR,
  `lib/run_gui.cpp` resolution, `lib/lifecycle.cpp` rctl output,
  `snmpd/main.cpp` `-i interval`, `lib/spec.cpp` `children_max`,
  `lib/ctx.cpp` pid-file reader.
- `PfctlOps::flushRules()` and `IpfwOps::deleteNat()` now emit `WARN`
  on failure instead of silently swallowing exceptions.

### Removed
- Dead code: `RunNet::setupPfAnchor()` (never called, superseded by
  inline code in `run.cpp` which is now in `PfctlOps::loadContainerPolicy`).
- Dead code: `PfctlOps::addNatRule()`, `PfctlOps::addRdrRule()` — never
  called from anywhere in the tree.
- Dead code: `IpfwOps::addNatForJail()`, `IpfwOps::addPortForward()` —
  never called from anywhere in the tree.
- Duplicate `fwSlotSize` / `fwRuleRangeOutBase` statics in `run.cpp`
  (single source of truth is now `run_net.cpp`, configurable via env).

### Fixed
- Failing ATF tests `parsePortRange_invalid_throws`,
  `toUInt_empty_throws`, `toUInt_negative_throws`,
  `toUInt_trailing_chars_throws` (expected `std::runtime_error` but
  received `std::invalid_argument` from unwrapped `stoul`).

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
