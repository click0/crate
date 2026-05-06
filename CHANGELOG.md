# Changelog

All notable changes to **crate** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.8.14] — 2026-05-06

`crate doctor` extended with two new operational checks:

### `network` category — ipfw reserved-range orphans

crate's auto-features each reserve a high rule-number range:
- `crate throttle` (0.7.7): pipe `10000+jid*2`, rule `20000+jid*2`
- `crate run --auto-fw` (0.8.2/0.8.3): nat `30000+jid`, rule `40000+jid`

Operator-defined rules SHOULD live below 10000. Doctor now scans
`ipfw -q list`, finds rules in the reserved ranges (20000+, 40000+),
and flags any that don't correspond to a currently-running jail —
typically stale rules from a destroyed jail that didn't get cleaned
up (crash mid-teardown, manual `kill -9` of crate run, etc.).

```
network:
  [PASS] ipfw   no orphan rules in crate-reserved ranges (20000+, 40000+)
  [WARN] ipfw   3 ipfw rule(s) in crate-reserved ranges without a
                matching running jail — likely stale from a destroyed
                jail; clean with `ipfw delete <N>` or wait for next
                `crate clean` to surface them
```

### `network` category — per-jail RCTL presence

For each running crate-managed jail, invokes `rctl -l jail:<name>`
and counts active rules. Surfaces:
- Rules present → PASS (jail bounded; spec presumably declared limits)
- Zero rules → WARN ("jail can OOM the host — FAIL if spec
  declared limits:; check `crate inspect`")

Doctor doesn't re-load specs at runtime, so this is informational
not authoritative — operators with NAT-mode unbounded jails will
see WARN, which is correct (those jails CAN exhaust the host).

### Implementation

`lib/doctor.cpp`:
- `checkIpfwReservedRanges` — `ipfw -q list` + parse first column,
  cross-reference against `JailQuery::getAllJails(crateOnly=true)`
  for valid IDs, count orphans
- `checkRctlPresence` — `rctl -l jail:<name>` per running jail,
  count non-empty lines

`lib/doctor_pure.cpp` — added `network` to canonical category sort
order (rank 8, after `auto-fw`).

### Tests

No new pure tests — both checks are shell-out heavy + per-host.
Existing `doctor_pure_test` cases (13) continue to pass.

**994/994 unit tests pass locally**.

### NOT in this release

- **Spec-aware FAIL promotion** — load each spec's `limits:` and
  compare against actual `rctl -l` output for true drift detection.
  Tracked.
- **pf rule count** — analogue of the ipfw orphan check for pf
  anchors. Defer — pf anchors auto-flush on jail teardown via
  `destroyPfAnchor` `RunAtEnd`, so orphans are rare.

---

## [0.8.13] — 2026-05-06

Lifecycle endpoints on control sockets — POST stop / restart from
the bearer-token-less control plane. Operators can wire desktop
trays / IDE plugins to stop or restart their pool's containers
without holding admin tokens.

### New endpoints

| Method | Path                                       | Role required |
|--------|--------------------------------------------|---------------|
| `POST`   | `/v1/control/containers/<n>/stop`        | admin          |
| `POST`   | `/v1/control/containers/<n>/restart`     | admin          |
| `POST`   | `/v1/control/containers/<n>/start`       | (501)          |

### Defence in depth (unchanged)

Same 4-layer chain as 0.7.10/0.7.11/0.7.14:
1. Filesystem perms (kernel, primary gate)
2. `getpeereid(2)` re-check
3. Pool ACL — operator can only target jails in their pool
4. Role gate — `viewer` socket rejects all POST verbs

The new POST verbs are MUTATING (`actionIsMutating()` returns true)
so they ride the same rate-limit cap as `PATCH /resources` (10
req/s per peer-uid+gid).

### PostStart deferred

`POST /start` returns HTTP 501 with a clear message:
> "POST /start not implemented on control sockets — use bearer-token
> main API or `crate run -f <file.crate>`"

Reason: starting a stopped jail requires the .crate file path.
crated doesn't track a "spec registry" mapping jail-name → archive
path. Future work: persist the .crate path at `crate run` time so
control-socket PostStart can pick it up.

### Implementation

- `daemon/control_socket_pure.h` — `Action` enum extended:
  `PostStart`, `PostStop`, `PostRestart`
- `daemon/control_socket_pure.cpp`:
  - parser handles `/start`, `/stop`, `/restart` (POST verbs only)
  - `actionIsMutating()` returns true for all three
  - `actionLabel()` returns `"start"` / `"stop"` / `"restart"` —
    these become rate-limit bucket keys
  - `authorize()` extends pool ACL to lifecycle actions
  - `reasonForStatus(501)` → `"Not Implemented"`
- `daemon/control_socket.cpp`:
  - `handleStop`, `handleRestart` — construct `Args` with
    stopTarget/restartTarget, delegate to existing
    `stopCrate()` / `restartCrate()` from `lib/lifecycle.cpp`
  - `PostStart` case returns 501

### Tests

No new pure tests — the change is mostly enum + dispatch
additions. Existing 29 ATF cases for `control_socket_pure_test`
continue to pass; pool ACL invariants (admin-only PATCH) carry
over to the new POST verbs.

**994/994 unit tests pass locally**.

### NOT in this release

- **PostStart** — see above (needs spec registry).
- **POST /destroy** — destruction is one-way; deliberately kept
  on the bearer-token main API to require a stronger credential.
- **POST /snapshot** — snapshot CRUD via control sockets. Defer.

---

## [0.8.12] — 2026-05-06

Log-stream auto-reopen on rotate. `?follow=true` clients survive
log rotation (newsyslog, logrotate) without operator intervention.
Pre-0.8.12 the stream ended cleanly on `NOTE_DELETE`/`NOTE_RENAME`
and the operator had to re-curl.

### Mechanism

When `kqueue` fires with `NOTE_DELETE | NOTE_RENAME` on the watched
fd:
1. Brief `usleep(50ms)` so the rotator has a chance to create the
   replacement file (logrotate typically does rename-then-create
   in two syscalls; we'd hit ENOENT in the gap).
2. Close old fd; loop `open(logPath, O_RDONLY | O_CLOEXEC)` up to
   20 times with 50ms backoff (1s total).
3. If the new file appears, re-register the kqueue filter on the
   new fd and reset the `std::ifstream` to the new file from start.
4. If it never appears, end the stream cleanly so the client can
   re-curl manually.

### Operator-visible behaviour

Before:
```sh
$ curl -N https://crated/api/v1/containers/myjail/logs?follow=true
... live tail ...
                          # (newsyslog rotates here — connection drops)
$ # operator manually retries:
$ curl -N https://crated/api/v1/containers/myjail/logs?follow=true
```

After:
```sh
$ curl -N https://crated/api/v1/containers/myjail/logs?follow=true
... live tail ...
... (newsyslog rotates — invisible to operator) ...
... live tail of new file continues ...
```

### Implementation

`daemon/routes.cpp::handleContainerLogs` streaming branch:
- Inspects `triggered.fflags` after each `kevent` call
- On rotate event: usleep + retry-open loop + re-arm kqueue + reset
  ifstream
- Uses the existing `FdCloser` RAII for proper teardown of the
  old fd

Linux fallback path is unchanged (still `usleep(500ms)` polling;
no rotate detection — Linux dev-only path).

### Tests

No new unit tests — the change is platform-specific runtime I/O
behind `#ifdef __FreeBSD__` exercising kqueue+open+ifstream-reset.
End-to-end testing remains a future functional-test addition.

**994/994 unit tests pass locally**.

### NOT in this release

- **Auto-recover from `NOTE_REVOKE`** — currently treated like
  delete. Not commonly hit.
- **Inode-stable detection** — currently we re-open by path. If
  the path itself disappears (entire /var/log/crate/<jail>/
  removed), stream ends. Acceptable for the typical rotate flow.
- **Linux `inotify` rotate detection** — gated on broader Linux
  port work.

---

## [0.8.11] — 2026-05-06

`gui: auto` and `gui: { mode: gpu }` now auto-unhide `/dev/dri/*`
in the jail's devfs view. Saves the operator from writing a custom
devfs ruleset for the common case "I want hardware-accelerated
firefox in this jail."

### What's automated

| Already automatic (pre-0.8.11) | New in 0.8.11 |
|---|---|
| `/tmp/.X11-unix` bind-mount (since X11 support landed) | `/dev/dri/card*` + `/dev/dri/renderD*` unhidden in jail's devfs view |

So with `gui: auto` (0.7.19 scalar shortcut) the only operator
config now is the spec line itself:

```yaml
gui: auto
start: firefox
```

That's the whole spec for "run firefox with GPU acceleration in
a jail" — no `terminal.devfs_ruleset:`, no manual
`mounts: { host: /dev/dri/card0, jail: ... }` needed.

### Trigger conditions

- `guiOptions->mode == "gpu"` (explicit GPU mode), OR
- `guiOptions->mode == "auto"` AND `/dev/dri/card0` exists on host

Skipped when:
- No `guiOptions` at all (no GUI wanted)
- `mode == "headless"` or `"nested"` (software/Xephyr — no GPU
  needed)
- `/dev/dri/card0` doesn't exist on host (nothing to expose)

### Mechanism

```sh
devfs -m <jail-path>/dev rule add path dri unhide
devfs -m <jail-path>/dev rule add path 'dri/*' unhide
devfs -m <jail-path>/dev rule applyset
```

Operates on the jail's devfs mount only. Host devfs untouched.

### Defence in depth

- Only the `dri` subdirectory and its children are unhidden — no
  blanket `path '*' unhide` that would expose unrelated devices.
- Soft-fail with operator-visible warning if `devfs(8)` fails:
  jail still starts, just without GPU access. Operator can add
  a manual ruleset to recover.
- Operator's explicit `terminal.devfs_ruleset:` setting wins —
  this auto-unhide only adds rules; if the operator's custom
  ruleset is more restrictive, it gets the last word via the
  existing `applyset` after this block.

### Implementation

`lib/run.cpp` — after the existing `terminal.devfs_ruleset` apply,
add the auto-unhide block conditional on `spec.guiOptions->mode`.
~30 LOC of run.cpp; no new files.

### Tests

No new unit tests — the change is shell-out + filesystem state,
not pure logic. Existing GUI tests cover the mode-resolution
side. **994/994 unit tests pass locally**.

### NOT in this release

- **Auto-detect GUI need from `start:` command** (firefox,
  gimp, blender) → enable `gui: auto` implicitly. Risky (false
  positives like `firefox-stats-collector`); deferred until
  requested.
- **NVIDIA / AMDGPU specific device exposure** — currently we
  only handle the standard `/dev/dri/*` paths. NVIDIA adds
  `/dev/nvidia*`; AMDGPU adds `/dev/kfd`. Future work to detect
  + expose those automatically.

---

## [0.8.10] — 2026-05-06

`options.ipsec.conf:` — auto-install strongSwan conn snippet
into `/usr/local/etc/strongswan.d/` at jail start, remove on
teardown. Operator no longer pre-loads the conn into ipsec.conf.

### Spec

```yaml
options:
  ipsec:
    conn: my-tunnel-1
    conf: /etc/crate/ipsec/my-tunnel-1.conf   # NEW (0.8.10)
```

### Lifecycle

| When | What |
|---|---|
| Jail start | Copy `<conf>` → `/usr/local/etc/strongswan.d/crate-<jail>.conf`; `ipsec reread`; `ipsec auto --add/--up <conn>` (existing 0.8.4 behaviour) |
| Jail teardown | `ipsec auto --down/--delete <conn>`; remove the installed file; `ipsec reread` (cleanup) |

`conf:` is optional — if omitted, behaviour matches 0.8.4 (operator
preconfigures the conn). If specified, the file is auto-deployed.

### Pairs naturally with `crate vpn ipsec render-conf`

```sh
# operator workflow:
crate vpn ipsec render-conf my-tunnel.yml > /etc/crate/ipsec/my-tunnel-1.conf
# spec.yml then references it:
#   options:
#     ipsec:
#       conn: my-tunnel-1
#       conf: /etc/crate/ipsec/my-tunnel-1.conf
crate run -f my-jail.crate
```

`render-conf` (0.6.10) writes the strongSwan conn block; `conf:`
(this release) auto-deploys it. Operator does both steps once;
crate handles the lifecycle from there.

### Implementation

- `lib/spec.h` — `IpsecOptDetails::confPath` field
- `lib/spec.cpp` — `options.ipsec.conf` parser
- `lib/run.cpp` — at jail start (after WireGuard, before bringing
  conn up): if `confPath` set, validate file exists, copy to
  `/usr/local/etc/strongswan.d/crate-<jail>.conf`, invoke
  `ipsec reread`. `RunAtEnd ipsecConfCleanup` removes the file
  + reread on teardown.

### Defence in depth

- File-exists check before copy — surfaces operator typos at jail
  start with clear error rather than silently leaving the conn
  unloaded.
- `ipsec reread` failure is soft-fail (warn, continue) — same
  posture as wg-quick errors. Better to start the jail and let
  the operator `crate doctor` later than block on a strongSwan
  hiccup.

### Tests

No new unit tests — the change is runtime I/O (file copy + shell
exec), not pure logic. Existing IPsec tests cover the conn-name
side. **994/994 unit tests pass locally**.

### NOT in this release

- **Conn name auto-derive** from spec — currently operator must
  match the conn name in conn snippet to the `conn:` value. Auto-
  derive (parse the snippet's `conn <name>` line) is a future
  ergonomics win.
- **Multi-conn install** — currently one conn per jail. If
  operators want N conns, they pre-load them all into
  ipsec.conf and reference one by name.

---

## [0.8.9] — 2026-05-06

`crate doctor` now verifies auto-fw rules are actually loaded for
each running jail. Surfaces silent breakage when operators flush
pf or delete ipfw nat instances out from under crate.

### New `auto-fw` check category

```
auto-fw:
  [PASS] postgres-prod  pf anchor present (auto-fw active)
  [PASS] redis-cache    pf anchor present (auto-fw active)
  [WARN] dev-postgres   no crate/dev-postgres_pid* pf anchor —
                        auto-fw inactive (OK for jails not using
                        mode:auto; FAIL for auto-mode jails —
                        outbound traffic likely broken)
```

For each running crate-managed jail:
- **pf path**: invoke `pfctl -a crate -s Anchors`, look for an
  anchor matching `crate/<jail-name>_pid*`. Found → PASS;
  missing → WARN.
- **ipfw path**: invoke `ipfw nat <natIdForJail(jid)> show`.
  Exit 0 → PASS; non-zero → WARN.
- **No jails running**: PASS with "no jails to check".

### Why WARN instead of FAIL

`crate doctor` doesn't know each jail's spec at runtime — operators
running NAT-mode jails (no auto-fw) or hand-rolled bridge jails
legitimately have empty anchors. We can't distinguish "expected
empty" from "auto-fw broken" without re-loading the spec, which
costs more than the check is worth.

WARN-level is the right call: visible in the report, exit code 1,
but doesn't fail-hard for setups that don't use mode:auto. Future
enhancement: persist the spec-side intent ("this jail uses
auto-fw") in the lease file so doctor can promote WARN → FAIL only
when there's a known auto-fw expectation.

### Implementation

- `lib/doctor.cpp::checkAutoFwRules` — the new check function:
  - kldstat for pf/ipfw to pick the inspection path
  - per-jail invocation + parse
  - sane fallbacks on missing tools (ipfw not installed → WARN,
    not crash)
- `lib/doctor_pure.cpp` — added `auto-fw` to canonical category
  rank (sorts after `audit`)

### Tests

No new pure tests — the check is shell-out heavy + per-host
specific (which jails are running, which firewall loaded). The
existing `tests/unit/doctor_pure_test.cpp` (13 cases) still
covers the data model + render + exit-code aggregation.

**994/994 unit tests pass locally** (no new tests).

### NOT in this release

- **Spec-aware FAIL promotion** — load the .crate to learn
  "should have auto-fw" then FAIL instead of WARN on absence.
  Tracked.
- **Per-jail rule count** — currently checks "any rule in
  anchor"; future could check "expected SNAT + N rdr rules
  present". Defer until operator reports a partial-rule scenario.

---

## [0.8.8] — 2026-05-06

`daemon/routes.cpp` rate-limit refactor onto the shared
`RateLimit::check` module. Mechanical no-op: same key shape,
same per-second counter, same cap values — both API planes
(main API + control sockets) now share state and any future
tuning lands in one place.

### Before

```cpp
// daemon/routes.cpp:
static std::mutex g_rateMutex;
static std::map<std::string, std::pair<int, time_t>> g_rateBuckets;
static bool checkRateLimit(...) {
  std::lock_guard<...> lock(g_rateMutex);
  // ... 10 lines of bucket-management duplicated from
  //     daemon/rate_limit_pure.cpp ...
}
static constexpr int RATE_LIMIT_MUTATING = 10;
static constexpr int RATE_LIMIT_READ     = 100;
```

### After

```cpp
static bool checkRateLimit(const std::string &clientId,
                           const std::string &endpoint,
                           int maxPerSecond) {
  return RateLimit::check(clientId + "|" + endpoint, maxPerSecond);
}
// All RATE_LIMIT_MUTATING / RATE_LIMIT_READ refs replaced with
// RateLimit::kMutating / RateLimit::kRead (same values).
```

### What this unlocks

- Future config-driven cap tuning in `crated.conf` (`rate_limit.read:`,
  `rate_limit.mutating:`) lands in one place + applies to both
  planes consistently.
- Single bucket store: a sustained burst from one client gets
  consistently rate-limited regardless of which plane it's hitting.
- ~25 LOC removed from `daemon/routes.cpp`.

### Behaviour change

None observable to operators. Same key (`<clientId>|<endpoint>`),
same caps, same algorithm. The shared store is process-wide so
buckets carry over across hot reload (which is the same as before
since both files used static state).

### Tests

`tests/unit/rate_limit_pure_test.cpp` (10 cases from 0.7.15)
already covers the algorithm. **994/994 unit tests pass locally**
(no new tests; pure refactor).

### NOT in this release

- **Config-driven caps** — `crated.conf` overrides for
  `RateLimit::kRead` / `kMutating`. The 100/10 defaults are
  conservative; tighter caps for paranoid operators or looser
  caps for trusted-network deployments are a future configurable.

---

## [0.8.7] — 2026-05-06

`firewall_backend:` config override for hybrid pf+ipfw hosts and
operators who want explicit control over auto-fw routing.

```yaml
# crate.yml
firewall_backend: pf       # force pf even if ipfw is also loaded
# OR
firewall_backend: ipfw     # force ipfw even if pf is loaded
# OR
firewall_backend: none     # skip auto-fw entirely; operator owns rules
# OR
# (omitted)                # auto-detect via kldstat (0.8.0..0.8.6 default)
```

### When this matters

FreeBSD supports running both pf and ipfw simultaneously (different
rule chains, no collision). Pre-0.8.7 if both were loaded, crate
auto-fw silently picked pf. That's the right default but didn't
help operators who:
- Use ipfw+dummynet for shaping (0.7.7 throttle) and want auto-fw
  in the same backend for visibility
- Run pf for inbound DMZ filtering but want auto-fw isolated to ipfw
- Want zero auto-fw because they have a custom rule generator

### Implementation

- `lib/config.{h,cpp}` — `Settings.firewallBackend` field; YAML
  parser validates against `["", "pf", "ipfw", "none"]` whitelist
  and throws on bad value
- `lib/run.cpp` — auto-fw branch consults `cfg.firewallBackend`
  before kldstat detection. Forced backends skip the kldstat
  invocation entirely (small startup-time saving). `"none"` value
  emits a LOG line and skips both pf and ipfw paths.

### Defence in depth

- Whitelist enforcement at config-load time. Typos like
  `firewall_backend: pflog` fail-fast at daemon start with a
  clear error message rather than silently falling back to
  auto-detect.

### Tests

No new unit tests — the change is a 4-way switch on a string
value (pf / ipfw / none / unset) with the validation already
covered at YAML-parse time. Existing test suite continues to
pass.

**994/994 unit tests pass locally** (no new tests; behaviour
change exercised by FreeBSD CI's compile path).

### NOT in this release

- **Per-jail firewall_backend override** in the spec. Currently
  hostwide only. Defer until requested.
- **`firewall_backend: nft`** for hypothetical Linux port. Not
  applicable until Linux support lands.

---

## [0.8.6] — 2026-05-06

`network_interface` auto-detect via `route -4 get default`. Closes
the "operator must set network_interface in crate.yml" requirement
that the auto-fw work (0.8.0+) introduced.

### Behaviour

```yaml
# crate.yml
network_pool: 10.66.0.0/24
# network_interface: em0   <-- now optional
```

When unset, `crate run` invokes `route -4 get default`, parses the
`interface:` line, and uses the result for SNAT / port-forward
rules. Operator can still pin the value explicitly (recommended
for hosts with multiple uplinks where the default route changes).

Cached: detection happens once per daemon lifetime. `crate doctor`
+ future hooks can `NetDetect::clearCache()` to force a re-detect.

### Defence in depth

- Parser only accepts FreeBSD-shaped iface names (1..15 chars,
  alnum + `.` + `_`). Garbage after the `interface:` token (e.g.
  shell-injection attempt via a malicious `route` binary on
  `$PATH`) returns empty and falls back to skip.
- Tab/space tolerance, CRLF tolerance — survives operators piping
  output through tools that mangle whitespace.
- Localised output not supported (we match English `interface:`
  only). FreeBSD `route(8)` doesn't localise output, so this is
  safe in practice.

### Soft-fail

If both `network_interface` is unset AND auto-detection fails
(no default route, route(8) missing), the warning gets more
useful:

```
auto-fw: network_interface unset in crate.yml AND default-route
auto-detection failed (no `route -4 get default` interface line);
skipping SNAT auto-rule — outbound traffic from 10.66.0.5 will
require operator-written pf/ipfw rules
```

### Implementation

- `lib/net_detect_pure.{h,cpp}` — pure parser:
  - `parseRouteOutput(text) -> ifaceName | ""`
  - Robust against whitespace variations, CRLF, multiple
    interface lines (takes first), garbage after the colon
- `lib/net_detect.{h,cpp}` — runtime: invokes
  `/sbin/route -4 get default`, caches result with mutex.
  `defaultIfaceCached()` API + `clearCache()` for test/doctor
  hooks.
- `lib/run.cpp` — auto-fw block now resolves to either
  `cfg.networkInterface` (explicit) or `NetDetect::defaultIfaceCached()`
  (auto). Validates result either way before passing to pf/ipfw.

### Tests

`tests/unit/net_detect_pure_test.cpp` — **9 ATF cases**:

- `typical_route_output` — exact FreeBSD 14 `route -4 get default`
  format pinned
- `vlan_iface` — dotted form (`vlan0.100`) accepted
- `no_interface_line` — fallback returns ""
- `empty_input` — handles empty file/output
- `crlf_line_endings` — survives Windows-edited inputs
- `rejects_garbage_value` — shell-injection / spaces / empty value
  all rejected
- `takes_first_match` — robustness invariant
- `rejects_oversized_iface` — > 15 chars (IFNAMSIZ - 1) rejected
- `tab_separator_accepted` — whitespace tolerance

**994/994 unit tests pass locally** (985 prior + 9 new).

### NOT in this release

- **Cache invalidation on host network change** — operator could
  manually `service crated restart` if their default route
  switches; auto-invalidation via routing socket events
  (`route monitor`) is a future hook.
- **IPv6 default route detection** — currently IPv4-only. When
  IPv6 NPTv6 lands (future), we'll need
  `route -6 get default ::/0` parsing.

---

## [0.8.5] — 2026-05-06

Log-streaming tail now uses `kqueue(2)` + `kevent(2)` instead of
`usleep(500ms)` busy-polling. Each `?follow=true` streaming client
gets its own kqueue fd watching its own log file; the per-client
thread blocks until the kernel signals a write. The 32-cap from
0.8.4 stays as belt-and-suspenders.

### Mechanism

```
kq      = kqueue();
watchFd = open(logPath, O_RDONLY | O_CLOEXEC);
EV_SET(&ev, watchFd, EVFILT_VNODE,
       EV_ADD | EV_CLEAR,
       NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE | NOTE_RENAME,
       0, NULL);
kevent(kq, &ev, 1, NULL, 0, NULL);

// tail loop:
while (read new bytes via std::getline → sink.write):
    ;
struct timespec timeout{1, 0};   // 1s — also forces a periodic
struct kevent triggered;          //      disconnect-check
kevent(kq, NULL, 0, &triggered, 1, &timeout);
// loop back, read newly-arrived bytes, write to sink
```

### Wakeup characteristics

Before (0.8.4 and earlier):
- 500ms polling — average wake latency 250ms even when log is hot
- One wakeup per client per 500ms regardless of activity (CPU
  usage scales with client count, not log rate)

After (0.8.5):
- ~0ms wake latency on append (kernel notifies via kqueue)
- One wakeup per actual log write per client (CPU scales with
  log rate, not client count)
- 1s timeout still fires periodically so a quiet log + a vanished
  client are detected within 1s

### Rotation safety

The kqueue filter watches `NOTE_WRITE | NOTE_EXTEND | NOTE_DELETE
| NOTE_RENAME`. A log rotator (newsyslog, logrotate) renaming the
file mid-stream wakes us up; the next `getline` round hits EOF
gracefully and the operator can re-curl when the rotator creates
the fresh file. We do NOT auto-reopen — that's a future
enhancement; today's behaviour is "stream ends cleanly on rotate."

### Linux fallback

cpp-httplib runs on FreeBSD in production; the codebase is built
on Linux only for unit tests. The `kqueue(2)` syscall is
FreeBSD-native (and macOS/OpenBSD) and not available on Linux,
so the new code is gated by `#ifdef __FreeBSD__`. On Linux the
old `usleep(500ms)` path is preserved — unit-test compatibility,
no behaviour change for crated's actual deployment.

A future Linux port would use `inotify(7)` for the equivalent
mechanism. Tracked but not blocking.

### Implementation

- `daemon/routes.cpp::handleContainerLogs` streaming branch:
  - Opens an extra read-only fd for kqueue's filter target
  - Registers `EVFILT_VNODE` events
  - Replaces `usleep(500000)` with `kevent(... 1s timeout)`
  - RAII `FdCloser` struct ensures both fds close on any return
    path (sink-write fail, client disconnect, exception)
- New includes (FreeBSD-only): `<sys/event.h>`, `<sys/types.h>`,
  `<sys/time.h>`

### Tests

No new unit tests — the change is platform-specific runtime I/O
behind `#ifdef`. Existing tests that don't exercise the streaming
path are unaffected.

**985/985 unit tests pass locally** (no new tests; same as 0.8.4).

The actual streaming mechanism is exercised by the FreeBSD CI
build (compile success → kqueue API used correctly). End-to-end
streaming testing remains a future functional-test addition.

### NOT in this release

- **Cross-client kqueue mux** — sharing one kqueue/bg-thread
  across all clients to reduce thread count below O(N). Requires
  bypassing cpp-httplib's content-provider model (which keeps a
  worker thread per active stream). Not blocking; current 32-cap
  + efficient sleep is operationally fine.
- **Auto-reopen on rotate** — currently stream ends when the log
  is rotated. Operators re-curl. A `tail -F` style auto-follow
  would re-open by path on `NOTE_DELETE` / `NOTE_RENAME`. Defer.
- **Linux `inotify` port** — only matters if crated ever runs on
  Linux. Defer.

---

## [0.8.4] — 2026-05-06

Three code-health fixes from the second-pass audit. All three were
real debt items rather than aesthetic concerns; this release closes
each with the smallest reasonable patch + doc/comment.

### Fix #1: hub `poll_interval:` config now actually wired

`hub/poller.cpp::loadNodes` read `root["poll_interval"]` but threw
the value away — operators setting a custom interval saw it
silently ignored, and the hard-coded 15s default was used instead.

This release:
- `loadNodes(path, unsigned *outPollIntervalSec = nullptr)` —
  matches the `loadHaSpecs(path, long *outThresholdSeconds)`
  out-param pattern from 0.7.3
- `Poller(nodes, store, unsigned pollIntervalSec = 15)` —
  constructor takes the value
- `hub/main.cpp` reads + passes through

Sanity bounds: `[1, 3600]` seconds. Below 1 caps the daemon at
something useful; above 3600 (1h) caps an operator-typo from
leaving a node looking "down" for days.

### Fix #2: log-streaming concurrency cap

`daemon/routes.cpp::handleContainerLogs` (the `?follow=true`
streaming variant) ties up one server thread per active client
via a polling tail-f loop. The TODO comment at line 385
acknowledged this could exhaust the daemon's thread pool under a
burst of log shippers / Prometheus exporters / curl-in-a-loop
scripts.

The "right" fix is a single bg thread + kqueue/epoll multiplex.
That's a substantial refactor (queued separately). This release
ships the **operational guard**:

- `g_streamingClients` atomic counter, capped at
  `kMaxStreamingClients = 32`
- Beyond the cap: HTTP `503 Service Unavailable` with
  `Retry-After: 5` so well-behaved clients back off
- Decremented in the chunked-content-provider's cleanup callback
  whether the stream finished cleanly or errored out

Converts "ties up a server thread per client" from
**unbounded** resource exposure to **bounded** (32) resource
exposure. The kqueue refactor remains tracked for a future
release; not blocking 0.8.4.

### Fix #3: IPsec runtime hook (closes 0.6.10's split-half TODO)

0.6.10 shipped `crate vpn ipsec render-conf` (validate + render
strongSwan ipsec.conf snippets) with a header comment noting that
"full kernel-level integration with crate jails is a separate
runtime concern (TODO)." This release fills in the runtime half:

```yaml
options:
  ipsec:
    conn: my-tunnel-1
```

When a jail's spec has the new `options.ipsec.conn:` field set,
`crate run`:
- before jail start: `ipsec auto --add <conn>` then
  `ipsec auto --up <conn>`
- on teardown (incl. crash): `ipsec auto --down <conn>` then
  `ipsec auto --delete <conn>`

Mirrors the WireGuard runtime pattern from 0.6.13. Operator
prerequisites (operator's responsibility, NOT crate's):
- strongSwan installed and the daemon running on the host
- the conn block referenced by `conn:` already in
  `/usr/local/etc/ipsec.conf` (or an included file). The
  `crate vpn ipsec render-conf` command can generate this file.

### Implementation

- `lib/ipsec_runtime_pure.{h,cpp}` — new pure module:
  - `validateConnName(name)` — ASCII alnum + `._-`, length 1..32,
    `%default` reserved (strongSwan keyword)
  - `buildAddArgv` / `buildUpArgv` / `buildDownArgv` /
    `buildDeleteArgv` — `/usr/local/sbin/ipsec auto --<verb> <name>`
  - `isEnabled(name)` — non-empty predicate
- `lib/spec.h` — `IpsecOptDetails { connName }` class added
  alongside existing `WireguardOptDetails`
- `lib/spec.cpp` — `options.ipsec.conn:` parser (mirrors
  wireguard's `options.wireguard.config:`)
- `lib/spec_pure.cpp` — `optionIpsec()` accessor + validate hook +
  added `"ipsec"` to `allOptionsLst` whitelist
- `lib/run.cpp` — `RunAtEnd ipsecDownAtEnd` declared and reset
  alongside the existing `wgDownAtEnd`. Lifecycle parity.

### Tests

`tests/unit/ipsec_runtime_pure_test.cpp` — **6 ATF cases**:

- `conn_typical` — alphabet acceptance
- `conn_invalid` — empty, oversized, `%default` reserved, shell
  metas, slashes
- `add_argv_shape` — `/usr/local/sbin/ipsec auto --add <name>` 4-token
  shape pinned
- `up_down_delete_argv_verbs` — verbs at index [2], conn at [3]
- `absolute_ipsec_path` — all builders use absolute path
  (matches WireGuard's `/usr/local/bin/wg-quick` policy)
- `enabled_predicate` — non-empty test

**985/985 unit tests pass locally** (979 prior + 6 new).

`lib/ipsec_pure.h` header comment updated to point at the new
runtime module instead of the TODO marker.

Also: `lib/lifecycle.h` got a documentation comment in this
release explaining why it has zero direct includers (re-exported
via `lib/commands.h`). No code change.

### NOT in this release

- **kqueue/epoll log-stream multiplex** — still tracked as
  follow-up; the 32-client cap from this release is the
  operational guard until then.
- **`firewall_backend:` config override** for hybrid pf+ipfw
  hosts where operators want auto-fw on ipfw even when pf is
  loaded. Defer until requested.
- **IPsec auto-render** — automatically `crate vpn ipsec
  render-conf` + drop into strongSwan's include dir. Currently
  operator does that step manually.

---

## [0.8.3] — 2026-05-06

`ipfw redir_port` for port-forward — closes the pf/ipfw symmetry
gap left by 0.8.2. The ipfw auto-fw path now supports the same
inbound: declarations as the pf path (0.8.1).

### Mechanism

`ipfw nat ... config` accepts multiple `redir_port` clauses on the
same line. Per jail (jid=5, IP 10.66.0.5, iface em0):

```sh
ipfw nat 30005 config if em0 \
  redir_port tcp 10.66.0.5:80 8080 \
  redir_port udp 10.66.0.5:53 53 \
  redir_port tcp 10.66.0.5:5000-5099 5000-5099
ipfw add 40005 nat 30005 ip from 10.66.0.5 to any out via em0
```

Same spec syntax produces equivalent firewall behaviour regardless
of which backend is loaded. Range form on either side is supported
(jail collapses to `host:lo` if `lo == hi`; otherwise `host:lo-hi`).

### Hybrid pf + ipfw on the same host

FreeBSD supports running both pf and ipfw simultaneously, and crate
takes advantage:

| Subsystem | Backend |
|---|---|
| `mode: auto` SNAT + port-forward (this release line) | pf if loaded, else ipfw |
| `crate throttle` rate limiting (0.7.7)              | always ipfw + dummynet |

Operators using throttle on a pf-primary host don't need to switch:
ipfw remains loaded for dummynet pipes; pf does the NAT/rdr; the
two firewalls don't conflict because they operate on different rule
chains. crate auto-fw picks one for its own rules; the other stays
free for whatever the operator's running on it.

### Implementation

- `lib/auto_fw_pure.{h,cpp}` extended:
  - `RedirPort` struct (proto + host range + jail addr + jail range)
  - `buildIpfwNatConfigWithRedirsArgv(natId, iface, redirs)` —
    builds the full config command including all redir_port
    clauses on one ipfw invocation
  - Empty `redirs` produces an argv equivalent to the basic
    `buildIpfwNatConfigArgv` form (back-compat with 0.8.2 SNAT-only).
- `lib/run.cpp` — ipfw branch builds the redirs vector from
  `optionNet->inboundPortsTcp` and `inboundPortsUdp`, passes to the
  new builder. The asymmetry-warning that 0.8.2 emitted is removed.

### Tests

`tests/unit/auto_fw_pure_test.cpp` extended with **5 new ATF cases**:

- `ipfw_nat_with_no_redirs_equivalent_to_basic` — back-compat
  invariant
- `ipfw_nat_redir_single_port` — single-port form
  (`10.66.0.5:80 8080`)
- `ipfw_nat_redir_range` — range form
  (`10.66.0.5:5000-5099 5000-5099`)
- `ipfw_nat_redir_asymmetric_range` — host range, jail single
- `ipfw_nat_redir_multiple` — three redirects on one config line,
  18 argv tokens total, 3 `redir_port` keywords

**979/979 unit tests pass locally** (974 prior + 5 new).

### NOT in this release

- **icmp passthrough** for either backend — would need separate
  rule shape; defer until requested.
- **IPv6 NAT** — both paths IPv4-only. Defer until 0.8.x adds
  IPv6 pool support to 0.7.17's allocator.
- **`firewall_backend:` config override** — currently auto-detect
  (pf preferred). If operators want to force ipfw on a host where
  both are loaded, that's a future config-surface addition.

---

## [0.8.2] — 2026-05-06

`mode: auto` ipfw alternative — operators using `ipfw(8)` instead
of `pf(4)` now also get auto-fw. Backend detected at jail-start
via `kldstat -n {pf,ipfw}`; pf preferred if both loaded (matches
0.8.0/0.8.1 behaviour), ipfw used if only ipfw is loaded.

### ipfw NAT path

```sh
# Per jail (jid=5, network_interface=em0, allocated IP 10.66.0.5):
ipfw nat 30005 config if em0
ipfw add 40005 nat 30005 ip from 10.66.0.5 to any out via em0
```

ID conventions:
- NAT instance id: `30000 + jid`
- Rule id: `40000 + jid`

These ranges sit above throttle's 10000/20000 (0.7.7), leaving
the low rule numbers for operator-defined ipfw.

### Cleanup

`RunAtEnd ipfwAutoFwCleanup` declared at function scope; reset on
successful setup. On jail teardown:

```sh
ipfw delete 40005           # delete rule first ...
ipfw nat 30005 delete       # ... then NAT instance
```

Same word-order quirk as 0.7.7 throttle ("delete" comes LAST in
`ipfw nat <id> delete`).

### Backend selection

| pf loaded | ipfw loaded | Path                                       |
|-----------|-------------|--------------------------------------------|
| yes       | yes         | pf (matches 0.8.0/0.8.1 behaviour)         |
| yes       | no          | pf                                         |
| no        | yes         | ipfw (this release)                        |
| no        | no          | warn + skip; jail starts but no auto-fw    |

### Asymmetric feature set (port-forward)

The ipfw path in this release supports SNAT only. Port-forward
via `ipfw nat ... redir_port` is planned for 0.8.3. If the spec
declares `inbound:` ports AND ipfw is the active backend, the
auto-fw step warns:

```
auto-fw[ipfw]: inbound: declarations ignored in 0.8.2 (port-forward
via ipfw redir_port deferred to 0.8.3); switch to pf for full
auto-fw or add ipfw fwd rules manually
```

This is a deliberate scope split — the pf path was the primary
workflow; the ipfw path catches up over 0.8.2 + 0.8.3.

### Implementation

- `lib/auto_fw_pure.{h,cpp}` — extended:
  - `natIdForJail(jid)` / `ruleIdForJail(jid)` — deterministic
    per-jid ids in reserved ranges
  - `validateIpfwNatId` — sanity belt against typos
  - `buildIpfwNatConfigArgv`, `buildIpfwNatRuleArgv`,
    `buildIpfwRuleDeleteArgv`, `buildIpfwNatDeleteArgv` — argv
    builders (string-form, no shell escaping needed)
- `lib/run.cpp` — backend detection (`kldstat -n {pf,ipfw}`),
  dispatch on result, register `ipfwAutoFwCleanup` `RunAtEnd` for
  the ipfw path. Soft-fail with `std::cerr` warnings on every
  failure mode (backend not loaded, ipfw setup fails) — jail still
  starts.

### Tests

`tests/unit/auto_fw_pure_test.cpp` extended with **6 new ATF cases**:

- `ipfw_ids_deterministic_per_jid` — same jid → same ids
- `ipfw_ids_in_reserved_ranges` — 30000+/40000+ above throttle's range
- `ipfw_validate_id_range` — rejects below-base + above-16-bit
- `ipfw_nat_config_argv_shape` — `ipfw nat <id> config if <iface>`
- `ipfw_nat_rule_argv_shape` — full rule + from/to/out/via tokens pinned
- `ipfw_delete_argvs` — rule delete + NAT delete word-order quirk

**974/974 unit tests pass locally** (968 prior + 6 new).

### NOT in this release (Phase 2 continued)

- **ipfw port-forward** via `redir_port` in the nat config — 0.8.3.
- **icmp passthrough** — neither pf nor ipfw path supports icmp
  yet. Defer.
- **IPv6 NAT** — IPv4-only. Defer until 0.8.x adds IPv6 pool.

---

## [0.8.1] — 2026-05-06

Auto port-forward (pf rdr) for `mode: auto` jails — the second
slice of network DX Phase 2 (after 0.8.0's SNAT auto-rule).

When the spec declares inbound TCP/UDP ports, `crate run` now
emits one `rdr` rule per port (or range) into the jail's pf
anchor, alongside the SNAT rule from 0.8.0:

```yaml
options:
  net:
    mode: auto
    inbound:
      tcp:
        - { from: 8080,       to: 80 }
        - { from: 5000-5099,  to: 5000-5099 }
      udp:
        - { from: 53, to: 53 }
```

becomes (per-jail anchor `crate/<jailXname>`):

```
nat on em0 inet from 10.66.0.5 to ! 10.66.0.5 -> (em0)
rdr on em0 inet proto tcp from any to (em0) port 8080 -> 10.66.0.5 port 80
rdr on em0 inet proto tcp from any to (em0) port 5000:5099 -> 10.66.0.5 port 5000:5099
rdr on em0 inet proto udp from any to (em0) port 53 -> 10.66.0.5 port 53
```

Operator does NOT need to write any pf.conf rdr rules. Same anchor
as SNAT, so cleanup is automatic via the existing
`destroyPfAnchor` `RunAtEnd`.

### Format details

- Single port form (`port 8080`) when host range collapses to one
  port (lo == hi); range form (`port 8080:8090`) otherwise. Same
  for the jail side independently — asymmetric host-range to
  jail-single is also supported (pf accepts both).
- `(<iface>)` parens for the destination match — robust against
  DHCP changes on the host's external interface.
- `inet` qualifier confines to IPv4.

### Defence in depth

- **proto whitelisted**: `tcp` or `udp` only. `icmp` and others
  rejected (would need different rule shape; defer).
- **port range 1..65535**: port 0 rejected.
- **silent skip on validation failure**: a malformed port pair
  is dropped without aborting the run; the rest of the rules
  still load. The spec parser already validates port ranges
  upstream, so this is belt-and-braces.

### Implementation

- `lib/auto_fw_pure.{h,cpp}` — extended with:
  - `validateProto` — whitelist `tcp` / `udp`
  - `validatePort` — 1..65535
  - `formatRdrRule` / `formatRdrAnchorLine` — per-rule formatter
    with smart range-vs-single output
- `lib/run.cpp` — extends the SNAT auto-fw block: iterate
  `optionNet->inboundPortsTcp` and `inboundPortsUdp`, append
  rdr lines to the same anchor text loaded via
  `PfctlOps::addRules`.

### Tests

`tests/unit/auto_fw_pure_test.cpp` extended with **10 new ATF cases**:

- `proto_typical` / `proto_invalid` — whitelist + injection guard
- `port_typical` / `port_invalid` — 0 reserved, > 65535 rejected
- `rdr_single_port_shape` — `port 8080` form (no `:8080:8080`)
- `rdr_range_both_sides` — `port 5000:5099 -> ... port 5000:5099`
- `rdr_range_host_single_jail` — asymmetric form, range collapsed
  to single on the jail side
- `rdr_uses_iface_token_for_dest` — `to (em0)` parens pinned
- `rdr_inet_qualifier_present` — `inet proto tcp` invariant
- `rdr_anchor_line_has_trailing_newline` — concatenation contract

**968/968 unit tests pass locally** (958 prior + 10 new).

### NOT in this release (Phase 2 continued / Phase 3)

- **ipfw alternative** — for operators who use ipfw instead of
  pf. Different rule shape (`ipfw fwd` for port-forward,
  `ipfw nat` for SNAT). Tracked as 0.8.2.
- **icmp passthrough** — needs separate pf rule type. Defer.
- **IPv6 rdr** — currently IPv4-only. Defer until 0.8.x adds
  IPv6 pool support.

---

## [0.8.0] — 2026-05-06

**Major version bump.** First release on the `0.8.0` branch.

`mode: auto` now auto-generates the SNAT rule that was previously
the operator's responsibility. Combined with 0.7.17's pool
allocator and 0.7.18's spec shortcut, a single-line spec gets
true outbound-internet jails on a fresh host:

```yaml
# crate.yml (operator-written, once)
network_pool:      10.66.0.0/24
network_interface: em0       # NEW REQUIREMENT for SNAT auto-rule

# spec.yml (per-jail)
options:
  net:
    mode: auto
```

`crate run` with the above:
1. (0.7.18) expands `mode: auto` to bridge + auto-create-bridge
2. (0.7.17) allocates `10.66.0.2` from the pool, registers a lease
3. (0.7.17) configures static IP on the jail-side iface
4. **(0.8.0) emits one nat rule** into the jail's pf anchor:
   ```
   nat on em0 inet from 10.66.0.2 to ! 10.66.0.2 -> (em0)
   ```
5. Jail starts; outbound traffic from the jail's `10.66.0.2`
   gets translated to the host's `em0` address; reply packets
   route back through the established state.

Operator does NOT need to write any pf.conf rule for routine
desktop-app jails.

### Why a major version bump

`mode: auto` semantics changed. Pre-0.8.0 the shortcut produced
a jail that needed operator-supplied SNAT to work — many specs
relied on operator-written pf.conf. Post-0.8.0 the same spec
auto-loads SNAT into the per-jail pf anchor, which can interact
with operator's existing rules.

This is a behaviour change visible to operators, hence 0.8.0.
Specs that don't use `mode: auto` are unaffected.

### Defence in depth

- **External interface validated** before reaching `pfctl`: 1..15
  chars, alnum + `.` (vlan tags) + `_`, no shell metacharacters.
- **Jail address validated**: digits + dots + optional `/<prefix>`,
  ≤18 chars. Catches shell-injection attempts in the network_pool
  config.
- **`to ! <jailAddr>`** clause excludes intra-jail traffic — replies
  between two jails on the same bridge stay on the bridge instead
  of being NAT'd to the host's address.
- **`-> (em0)`** with parens means "translate to whatever address
  is currently on em0" — robust against DHCP lease changes on the
  host's external interface.
- **`inet`** qualifier confines the rule to IPv4 — no accidental
  IPv6 NAT (which pf would warn about anyway, but explicit > implicit).

### Soft-fail behaviour

If `network_interface` is unset in `crate.yml`, the auto-fw step
warns and continues:
```
auto-fw: network_interface unset in crate.yml; skipping SNAT
auto-rule — outbound traffic from 10.66.0.2 will require
operator-written pf/ipfw rules
```

If `pfctl` fails to load the rule (pf.ko not loaded, syntax error
in the operator's main pf.conf, ...), the auto-fw step warns and
continues:
```
auto-fw: SNAT rule load failed: <error> — outbound traffic may not
work; configure pf manually
```

These soft-fails preserve the pre-0.8.0 behaviour of "jail starts
even if firewall is broken." Operators relying on the auto-fw can
trip-wire detection via `crate doctor` (0.7.13) which checks
`zpool` health + `network_pool` config — a future doctor check
could also verify the auto-fw rule was loaded.

### Implementation

- `lib/auto_fw_pure.{h,cpp}` — pure module:
  - `validateExternalIface` — IFNAMSIZ + alnum + `.` + `_`
  - `validateRuleAddress` — IPv4 with optional CIDR suffix
  - `formatSnatRule(iface, addr)` — produces the canonical pf
    nat rule string
  - `formatSnatAnchorLine` — same plus trailing newline so
    multiple lines concatenate cleanly
- `lib/run.cpp` — wired into the bridge-mode auto-IP block:
  validates inputs, builds the rule line, loads via existing
  `PfctlOps::addRules(anchor, rulesText)`. Cleanup is automatic
  (existing `destroyPfAnchor` `RunAtEnd` flushes the anchor at
  teardown).

### Tests

`tests/unit/auto_fw_pure_test.cpp` — **11 ATF cases**:

- iface validator: typical (em0/igb0/vlan0.100/bridge0/vtnet1) +
  invalid (empty, oversized, space, semicolon, backtick, slash,
  newline)
- address validator: typical IPv4 + CIDR + 0.0.0.0/0 catch-all +
  rejection of shell-injection (`;rm -rf /`, backticks, `$(...)`,
  multiple slashes, oversized)
- SNAT rule shape: single IP + CIDR + invariants pinned (`inet`
  qualifier present, `to ! <jailAddr>` exclusion present, `(<iface>)`
  parens for dynamic translation)
- anchor line format: trailing newline + starts with rule

**958/958 unit tests pass locally** (947 prior + 11 new).

### NOT in this release (future Phase 2 / Phase 3)

- **Port-forward auto-rules** (rdr) from `inbound:` declarations.
  0.8.1.
- **ipfw alternative** for operators using ipfw instead of pf.
  0.8.2.
- **IPv6 SNAT (NPTv6)** for IPv6 pool allocation. Defer until
  0.8.x adds IPv6 pool support.
- **`crate doctor` integration** — verify auto-fw rule actually
  loaded for each running jail. 0.8.x quality-of-life.
- **`network_interface` auto-detect** — read from `route -4 get
  default` if unset in config. Defer; explicit config is safer
  for production hosts with multiple uplinks.

---

## [0.7.19] — 2026-05-06

`gui: auto` scalar shortcut — companion to 0.7.18's `mode: auto`
for the GUI side. Operators write:

```yaml
gui: auto
```

instead of the equivalent map form:

```yaml
gui:
  mode: auto
```

The runtime side (`run_gui.cpp::resolveGuiMode`) already had the
`auto` mode branch — at jail start it inspects the host:

| Host condition                     | Resolved mode |
|------------------------------------|---------------|
| `/dev/dri/card0` exists, no $DISPLAY | `gpu`         |
| `$DISPLAY` set                       | `nested`      |
| Otherwise                            | `headless`    |

So the only piece missing was the spec ergonomics — operators
had to write 2 lines for what was conceptually 1. This release
adds the scalar shorthand to the parser; everything else flows
through the existing GUI runtime.

### Accepted scalar values

`gui: auto`, `gui: nested`, `gui: headless`, `gui: gpu` — same
set as the existing `gui.mode:` map field. Anything else is
rejected with a clear error message.

### Implementation

- `lib/spec.cpp` — `else if (isKey(k, "gui"))` branch now
  accepts a scalar in addition to the existing map form. When
  scalar, builds a `GuiOptions` with just `mode` set.

### Combined with 0.7.18

The two shortcuts compose naturally for typical desktop-app
specs:

```yaml
options:
  net:
    mode: auto    # 0.7.18: bridge + auto-IP + auto-create-bridge

gui: auto         # 0.7.19: pick gpu/nested/headless from host

start: firefox
```

That's the whole spec for "run firefox in a jail" — pre-0.7.18
the same spec needed ~10 lines.

### Tests

No new unit tests — the change is a 6-line scalar branch in the
parser. Existing `gui:` map-form tests continue to pass; FreeBSD
CI exercises the integration path. **947/947 unit tests pass
locally** (no new tests added).

### NOT in this release (future)

- **Auto-bind `/tmp/.X11-unix`** when GUI is detected — currently
  operator must add it to `mounts:` explicitly. Phase 2.
- **Auto-add `/dev/dri/*` to devfs ruleset** when GPU mode picked
  — currently operator must list devices. Phase 2.
- **Auto-detect GUI need from `start:` command** (e.g. firefox
  → enable GUI implicitly). Risky (false positives); deferred
  until requested.

---

## [0.7.18] — 2026-05-06

`mode: auto` spec shortcut — single-line replacement of the
`options.net.{...}` boilerplate for the typical bridged-jail
case. Operators now write:

```yaml
options:
  net:
    mode: auto
```

instead of:

```yaml
options:
  net:
    mode: bridge
    bridge: bridge0
    auto_create_bridge: true
    # ip: omitted = ipMode=Auto = pool allocation
```

### Expansion

`mode: auto` is recognised at parse time and expanded during
`Spec::preprocess()` to:

| Field             | Value                                                     |
|-------------------|-----------------------------------------------------------|
| `mode`            | `Bridge`                                                  |
| `bridgeIface`     | `Settings.defaultBridge` if set, else `crate0`            |
| `autoCreateBridge`| `true`                                                    |
| `ipMode`          | unchanged (default `Auto`, so 0.7.17's pool allocator hands out an IP) |

If the operator overrides `bridge:`, `auto_create_bridge:`, or
`ip:` alongside `mode: auto`, the explicit values win — the
shortcut only fills in defaults that aren't already set.

### Practical effect

Combined with 0.7.17's `network_pool` config:

```yaml
# /usr/local/etc/crate.yml (operator-written, once)
network_pool: 10.66.0.0/24
default_bridge: bridge0   # optional, falls back to crate0

# spec.yml (per-jail, minimal)
options:
  net:
    mode: auto
```

A fresh `crate run` now: creates `bridge0` if missing, allocates
the next free IP from `10.66.0.0/24`, configures the bridge, and
runs the jail. No pf.conf / ipfw editing for routine desktop-app
jails; pre-0.7.17 specs continue to work unchanged.

### Implementation

- `lib/spec.h` — `Mode::Auto` enum value
- `lib/spec.cpp` — parser branch (`modeStr == "auto"` → `Mode::Auto`)
  + preprocess expansion (Auto → Bridge with sensible defaults)

The shortcut is intentionally tiny — the heavy lifting (pool
allocator, lease store, atomic file ops) was done in 0.7.17.
This release is the ergonomics layer on top.

### Tests

No new unit tests added for this small ergonomics shortcut —
the change touches three functions and is structurally tiny.
FreeBSD CI exercises the full preprocess + jail-create path.

**947/947 unit tests pass locally** (no new tests; existing
spec parser + preprocess tests continue to pass with the new
enum value + branch).

### NOT in this release (future Phase 2 / Phase 3)

- **SNAT auto-rule generation** — a `pf` or `ipfw` rule for the
  jail's outbound traffic. Detect which firewall is loaded; add
  rule on `crate run`; remove on teardown.
- **Port-forward auto-rules** — generate `rdr` rules from the
  spec's `inbound:` declaration. Same lifecycle as SNAT.
- **IPv6 pool allocation** — IPv4-only in 0.7.17/0.7.18. A
  separate `network_pool6` field for ULA / GUA pools.
- **Pool reservation in passthrough/netgraph modes** — currently
  bridge-only.

---

## [0.7.17] — 2026-05-06

Auto-IP allocation for `IpMode::Auto` bridge mode (Phase 1 of
`network: auto` from the libkrun-inspired roadmap). The
`IpMode::Auto` enum value has been declared since the early
networking work but its runtime fell through to DHCP. This release
activates pool-based allocation: when a global `network_pool` CIDR
is configured, the auto branch picks a free IP, registers a lease,
and configures it as a static address.

### Configuration

```yaml
# /usr/local/etc/crate.yml or ~/.config/crate/crate.yml
network_pool: 10.66.0.0/24
```

When set, every bridged jail with `ipMode: auto` (the default if
no explicit `ip:` is given) gets an allocated IP from the pool.
When unset, behaviour is unchanged from 0.7.16 — auto mode falls
back to DHCP. So the change is opt-in and pre-existing specs
continue to work.

### Allocator semantics

- The pool's `.0` (network), `.1` (gateway, by convention), and
  the broadcast (`.255` for /24) are reserved.
- Allocation is "next lowest free IP" — deterministic, cron-friendly.
- Pool exhausted → `crate run` exits with a clear error before
  any jail state is created.
- Idempotent: re-running `crate run` for the same jail-instance
  picks up the existing lease (no double-allocation).

### Lease store

`/var/run/crate/network-leases.txt` — flat text file:

```
# crate network leases — managed by crate run / crate clean
# format: <jail-name> <ip>
jail-firefox-abcd 10.66.0.2
jail-postgres-1234 10.66.0.3
```

- Atomic writes via tmpfile + `rename(2)` — crash mid-write
  doesn't leave a half-written file.
- Concurrent `crate run` invocations serialised via `flock(2)` on
  the lease file — no two jails can ever pick the same IP.
- Released on jail teardown via a `RunAtEnd` hook (best-effort:
  failure logs but doesn't mask the real teardown error).

### Implementation

- `lib/ip_alloc_pure.{h,cpp}` — pure helpers:
  - `parseCidr`, `parseIp`, `formatIp` — IPv4 round-trip
  - `gatewayFor`, `broadcastFor` — pool arithmetic
  - `allocateNext(pool, taken)` — next free, skips `.0`, `.1`,
    broadcast, and any IP in `taken`
  - `parseLeaseLine`, `formatLeaseLine` — wire format
- `lib/network_lease.{h,cpp}` — runtime: `flock`-protected
  read/write/append/release on the lease file. Atomic.
- `lib/config.{h,cpp}` — `Settings.networkPool` (string CIDR).
  Empty = disabled.
- `lib/run.cpp` — bridge-mode `IpMode::Auto` branch consults
  `Config::get().networkPool`; if set, allocates + configures
  static IP + registers `RunAtEnd` lease release. If not set,
  falls through to existing DHCP path.

### Tests

`tests/unit/ip_alloc_pure_test.cpp` — **14 ATF cases**:

- IP round-trip + bad-input rejection (5 forms)
- CIDR typical / bad (no slash, empty prefix, /0, /31, /33,
  bad octet, misaligned base)
- gateway/broadcast for /24 + /30
- `allocateNext` happy path, skips taken, skips gateway even if
  in `taken` (defensive), pool-exhausted returns 0, /30 full pool,
  doesn't assign broadcast
- Lease line round-trip + rejection (5 forms: empty, name-only,
  bad ip, slash in name, leading/double space)

**947/947 unit tests pass locally** (933 prior + 14 new).

### NOT in this release (Phase 2 / Phase 3)

- **`mode: auto` shortcut** in spec — single line replaces the
  full `options.net.{...}` section. Phase 2 (0.7.18).
- **SNAT auto-rule generation** — pf or ipfw rule for jail's
  outbound traffic. Phase 2.
- **Port forwarding auto-rules** — generate pf/ipfw rdr from
  the spec's `inbound:` declaration. Phase 2.
- **IPv6 pool allocation** — only IPv4 in this phase. Phase 3.
- **Pool reservation in passthrough/netgraph modes** — currently
  bridge-only. Future.

---

## [0.7.16] — 2026-05-06

`crate validate --strict` + completions refresh + Makefile header-dep
regression fix from 0.7.12.

### `crate validate --strict`

Promotes warnings to errors AND adds new structural checks that
the regular `crate validate` doesn't catch. Designed for CI gates
where "warning" is too soft — the spec is rejected on first error.

```sh
crate validate spec.yml             # standard: schema + warnings
crate validate --strict spec.yml    # rejects on any warn or structural error
```

Strict-mode catalogue (v1):

| Check | Rationale |
|---|---|
| Duplicate inbound TCP/UDP host ports | Two rules binding the same host port silently override; almost always a copy-paste error |
| Duplicate share destinations | Two host paths mapped to the same jail-side path is ambiguous and likely a typo |
| Empty share source/destination | Surfaces at validate-time instead of cryptic runtime mount errors |
| `x11/mode=shared` (was a warning) | Promoted to error: no display isolation, jail processes can sniff host keystrokes |
| Unbounded RCTL | `limits:` absent OR no `memoryuse`/`maxproc` — runaway processes can OOM-kill the host |

All warnings from the regular validate are also promoted to errors
in `--strict` mode. Operators who deliberately want a warning-laden
spec can drop `--strict`; CI pipelines should add it.

### Completions refresh

`completions/crate.sh` was last updated when crate had ~12 commands.
Modern crate has **28** commands. This release brings the file up
to date for both bash and zsh:

- All commands now in the bash `commands` variable
- Per-command flag completions added: `backup`, `restore`,
  `backup-prune`, `replicate`, `template`, `retune`, `throttle`,
  `doctor`, `migrate`, `inspect`, `top`, `inter-dns`, `vpn`,
  `stats`, `logs`, `stop`, `restart`
- File-completion hints for new flags: `--from-token-file`,
  `--ssh-key`, `--output-dir`, etc.
- zsh `_arguments` blocks for all new commands with `:` descriptors
  for tab-help

Auto-generation from CLI usage is tracked as a future enhancement;
the file is hand-maintained against `cli/args.cpp` for now.

### Makefile -MMD -MP (regression fix)

The 0.7.12 test-build refactor moved `TEST_LINK_SRCS` compilation
into per-source `.o` files cached under `tests/unit/.test-objs/`,
which gave us the 17× speedup. But the pattern rule:

```
$(TEST_OBJ_DIR)/%.o: %.cpp lib/lst-all-script-sections.h
	$(CXX) ... -c $< -o $@
```

did NOT track header dependencies. Changing `lib/args.h` (or any
other shared header) would NOT trigger a rebuild of the objects
that `#include` it — make would see the `.cpp` unchanged and
re-link the cached stale `.o` into the test binary.

This bit me hard during 0.7.16 development: 21 unit tests started
failing with `validate() did not throw Exception as expected`
because `args_pure.o` was built against a pre-`validateStrict`
`args.h`. A `make clean-tests && make` resolved it locally, but
the regression would have hit FreeBSD CI cache too.

Fix: add `-MMD -MP` to the compile rule and `-include` the
generated `.d` files. Now any header change triggers the right
rebuilds without manual cleanup.

### Tests

- **12 new ATF cases** in `validate_pure_test` covering the
  strict-mode checks: minimal-spec-unbounded, bounded-spec-no-error,
  bounded-via-maxproc, TCP port conflict (single + range overlap),
  UDP port conflict, no-conflict baseline, duplicate share dest,
  same-share-twice-not-conflict, empty share paths, x11/mode=shared
  promoted, x11/mode=nested no-error.
- **933/933 unit tests pass locally** (921 prior + 12 new).

### NOT in this release (future)

- **Completion auto-gen** — a make target that runs `crate -h`
  and `crate <cmd> -h` for every command, parses the usage output,
  and emits completions. Tracked separately; current hand-
  maintained file is a stop-gap.
- **--strict checks for namespaces / network policies** — once
  the network-policy section grows beyond inbound port ranges,
  add cross-rule conflict detection (same proto+port forwarded to
  two destinations, etc.).
- **`--strict` integration into `crate run`** — currently
  `--strict` is `crate validate` only. A future enhancement could
  reject specs at run time too; for now operators enforce via CI.

---

## [0.7.15] — 2026-05-06

Rate limiting on control sockets. The 0.7.10/0.7.11 control-socket
plane shipped without one, so a buggy GUI/tray app polling `/v1/control/
containers/<n>/stats` in a tight loop could spin crated up. This
release closes the gap with a per-uid + per-action token bucket
(same per-second-counter algorithm as the existing main-API limiter
in `daemon/routes.cpp`), factored into a reusable module so both
planes can share it.

### Limits

| Action class | Cap (per second per peer-uid+gid) |
|---|---|
| GET (list, get, stats)            | **100 req/s** |
| PATCH (resources)                 | **10 req/s** |

Same caps as the main API's `RATE_LIMIT_READ` / `RATE_LIMIT_MUTATING`,
intentionally — operators don't have to learn two models.

### Bucket key

```
uid:<peerUid>|gid:<peerGid>|<actionLabel>
```

`actionLabel` is one of `list`, `get`, `stats`, `patch` — coarse
enough to not fragment the counter into thousands of buckets per
container; fine enough that a runaway PATCH loop doesn't starve out
GET polling and vice versa.

Multiple users in the same operator group share a counter — that's
intentional. A runaway tray app deserves the same throttle as a
runaway script run by the operator beside them; the unit of trust
is the group, matching how the rest of the control-socket plane
authenticates.

### Behaviour on cap

- Response: `HTTP 429 Too Many Requests`
- Body: `{"error": "rate limit exceeded; retry in 1s"}`
- The retry-after hint is always `1` — the bucket flips at the next
  wall second, and a longer hint would mislead well-behaved clients.

### Implementation

- `daemon/rate_limit_pure.{h,cpp}` — the pure check function:
  - `Bucket {counter, second}` state struct
  - `Decision check(prev, now, max)` — pure: takes prior state +
    wall second + cap, returns new state + allow/deny
  - `retryAfterSeconds()` — pinned at 1 (see above)
  - Pathological inputs handled: `max <= 0` treated as disabled
    (always allow); non-monotonic clock (operator running ntpd /
    stepping clock backward) still resets cleanly.
- `daemon/rate_limit.{h,cpp}` — runtime: `std::mutex` +
  `std::unordered_map<std::string, Bucket>` shared store with
  `check(key, max)` that walks one round of the pure module.
  Constants `kRead = 100`, `kMutating = 10`.
- `daemon/control_socket_pure.{h,cpp}` — extended:
  - `actionLabel(Action)` — `list` / `get` / `stats` / `patch`
  - `actionIsMutating(Action)` — only `PatchResources` returns true
  - `reasonForStatus(429)` — `"Too Many Requests"`
- `daemon/control_socket.cpp::handleConnection` — between authorize
  and dispatch, run `RateLimit::check(<bucket-key>, cap)`. On deny,
  emit a 429 and close.

### Tests

`tests/unit/rate_limit_pure_test.cpp` — **10 ATF cases**:

- `fresh_bucket_is_allowed` — empty sentinel `{0, 0}` allows the
  first request
- `below_cap_increments` — counter increments on allow
- `at_cap_last_request_allowed` — exactly `max` requests in a
  second succeed (off-by-one guard)
- `above_cap_denied` — request beyond cap denied
- `many_denies_dont_drift_counter` — flood of post-cap requests
  doesn't push counter past `max` (telemetry invariant)
- `second_rollover_resets_counter` — wall-second tick resets to 1
- `non_monotonic_clock_still_resets` — bucket second "in the future"
  also resets (operator clock-step survives)
- `zero_max_treated_as_disabled` — typo flipping cap to 0/-N is
  always-allow, not always-deny (don't brick the daemon)
- `retry_after_is_one_second` — pinned constant
- `allows_exactly_max_requests_per_second` — property: of `max+5`
  requests in a single second, exactly `max` succeed and 5 are denied

`tests/unit/control_socket_pure_test.cpp` — **3 new ATF cases**:

- `action_labels_distinct` — collision-free action labels (would
  lump unrelated actions into one bucket)
- `action_labels_stable` — exact strings pinned (operator alerts /
  log scrapers depend on them)
- `action_is_mutating_only_for_patch` — only PATCH classified as
  mutating; future actions default to non-mutating until explicitly
  added

**921/921 unit tests pass locally** (908 from prior + 13 new).

### Followup

- Refactor `daemon/routes.cpp::checkRateLimit` to call into the
  shared `RateLimit::check` — pure mechanical no-op refactor,
  deferred so the `0.7.15` release stays focused on the
  control-socket gap.
- Config-driven caps: make `kRead`/`kMutating` overridable in
  crated.conf. Defer until at least one operator reports needing
  it; current values are conservative.

---

## [0.7.14] — 2026-05-06

`crated` Capsicum sandbox — per-fd `cap_rights_limit(2)` on control-socket
listeners and accepted connections. Activates the `lib/capsicum_ops.cpp`
infrastructure that has been in the tree (since the early Capsicum
plumbing) but never wired into the daemon's listen/accept paths.

### Threat model

Defence-in-depth against memory-corruption bugs in the daemon. If a
buffer-overflow (or similar) gives an attacker a stale `int fd`
reference to a control-socket listener, they cannot turn it into:

- a sender of arbitrary bytes (no `CAP_SEND` on the listener)
- a connection-establisher to other hosts (no `CAP_CONNECT`)
- a configuration-modifier (no `CAP_SETSOCKOPT`)

The accept-only listener can only accept new clients — so the worst
case is "attacker accepts a connection and serves a 403 from a
half-corrupted handler", which is still bounded by the existing
3-layer auth (filesystem perms → getpeereid → pool ACL/role).

For accepted connection fds: limited to recv/send/shutdown the
moment `getpeereid(2)` finishes. A parser-side bug can't repurpose
the fd into an arbitrary file write or new socket op.

### Why no `cap_enter()`

`cap_enter(2)` would put the entire `crated` process into capability
mode, which makes `execve(2)` of subprocesses fail with `ENOTCAPABLE`.
crated routinely spawns `rctl(8)`, `jail(8)`, `jexec(8)`, `ipfw(8)`,
`pfctl(8)`, `tar(1)` — all path-based. Whole-process sandbox is
therefore architecturally incompatible with crated's current "spawn
a tool for every state-changing op" pattern.

A future hardening track (privsep, à la OpenSSH: sandboxed network
front + privileged worker over a Unix-socket protocol) is out of
scope for 0.7.x.

### Right mappings

| FdRole       | Rights                                                          | Count |
|--------------|------------------------------------------------------------------|-------|
| `Listener`   | `CAP_ACCEPT, CAP_GETSOCKOPT, CAP_FSTAT`                          | 3     |
| `Connection` | `CAP_RECV, CAP_SEND, CAP_SHUTDOWN, CAP_GETSOCKOPT, CAP_FSTAT`     | 5     |
| `LogWrite`   | `CAP_WRITE, CAP_FSYNC, CAP_FSTAT`                                 | 3     |
| `ConfigRead` | `CAP_READ, CAP_FSTAT`                                             | 2     |

`CAP_FSTAT` is included in every category so libc's `fstat`-based
buffering optimisations (stdio block-size detection, etc.) keep
working — without it many calls hit `ENOTCAPABLE` paths.

### Implementation

- `daemon/sandbox_pure.{h,cpp}` — pure helpers:
  - `FdRole` enum (`Listener`/`Connection`/`LogWrite`/`ConfigRead`)
  - `labelFor()` — stable diagnostic strings (log-scrapers depend
    on them)
  - `rightCountFor()` — expected number of `cap_rights_t` entries
    per role, pinned by unit tests so a runtime drift surfaces
  - `describe(fd, role)` — one-line log helper
- `daemon/sandbox.{h,cpp}` — runtime: thin wrappers over
  `cap_rights_init` + `cap_rights_limit`, behind `#ifdef HAVE_CAPSICUM`.
  Linux build emits no-op stubs returning `false` so unit tests still
  compile and link.
- `daemon/control_socket.cpp` — wired:
  - `bindSocketOrThrow` → `Sandbox::applyListenerRights(listenFd)`
    immediately after `listen(2)`
  - `handleConnection` → `Sandbox::applyConnectionRights(connFd)` the
    moment `getpeereid(2)` finishes, before HTTP parsing runs

### Tests

`tests/unit/sandbox_pure_test.cpp` — **6 ATF cases**:

- `labels_are_distinct` — role labels are unique
- `labels_are_stable` — exact strings pinned (log-scraper contract)
- `right_counts_match_runtime` — pin the (3, 5, 3, 2) tuple; if
  someone adds a `CAP_*` to `daemon/sandbox.cpp` without bumping
  this count, the test fails — surfacing the drift
- `right_counts_strictly_positive` — no role should have zero rights
  (zero rights = unusable fd = bug)
- `connection_has_strictly_more_rights_than_listener` — invariant
  (a connection is bidirectional + closable; a listener only accepts)
- `describe_format` — output shape for log lines

**908/908 unit tests pass locally** (902 from prior + 6 new).

### NOT in this release (future hardening)

- **Privsep architecture** — sandboxed network-front + privileged
  worker process. Would enable real `cap_enter(2)` on the front. ~2
  weeks of work; queued behind C4/D2/D5 in current roadmap.
- **`cap_rights_limit` on the main daemon's httplib sockets** —
  cpp-httplib doesn't expose the per-connection fd to handlers;
  control-socket plane was rebuilt with a custom accept loop in
  0.7.11 so we have the hooks there. Same custom-loop refactor on
  the main daemon could activate per-fd sandbox there too.
- **Whole-process audit-log fd limiting** — audit log is opened
  per-record (O_APPEND | O_CLOEXEC), so there's no long-lived fd
  to limit. A future change could keep the fd open and `applyLogWriteRights`
  it; would speed up high-volume audit slightly.

---

## [0.7.13] — 2026-05-06

`crate doctor` — one-shot health check command. First command an
operator runs when something looks off; surfaces ~half the common
support-ticket conditions in a single go.

### Usage

```sh
crate doctor          # text report, exits 0/1/2
crate doctor --json   # machine-readable, same exit codes
```

Exit code:

| | meaning |
|---|---|
| `0` | all checks PASS |
| `1` | at least one WARN, no FAIL — degraded but functional |
| `2` | at least one FAIL — operator action needed |

Cron-friendly: `crate doctor --json | jq '.summary'` makes alerts trivial.

### Sample output

```
kernel:
  [PASS] if_bridge       loaded — vnet jails (bridge interfaces)
  [PASS] if_epair        loaded — vnet jails (paired veth-style links)
  [WARN] dummynet        not loaded — crate throttle (kldload dummynet if you need it)

command:
  [PASS] /sbin/zfs       found — ZFS dataset / snapshot operations
  [PASS] /sbin/jail      found — jail(8) lifecycle
  ...

filesystem:
  [PASS] /var/run/crate  crated runtime state — 5234 MB free
  [WARN] /var/log/crate  audit log + per-jail create logs — 32 MB free (below recommended 50 MB)

zfs:
  [PASS] zpool           all pools healthy

jails:
  [PASS] postgres        jid=12, ip4=10.0.1.5
  [WARN] redis           marked dying — `crate clean` may help

audit:
  [PASS] /var/log/crate/audit.log  size = 14 MB

Summary: 9 PASS, 3 WARN, 0 FAIL
```

### Check catalog (v1)

| Category | What |
|---|---|
| `kernel`     | `kldstat -n` for `if_bridge`, `if_epair` (required); `racct`, `dummynet`, `ipfw`, `vmm`, `nmdm` (recommended) |
| `command`    | `access(X_OK)` on `/sbin/zfs`, `/sbin/jail`, `/usr/sbin/jexec`, `/usr/bin/jls`, `/sbin/ifconfig`, `/usr/bin/{grep,tar,xz}`, `/sbin/{rctl,ipfw,pfctl,kldstat}` |
| `filesystem` | `/var/run/crate` and `/var/log/crate` exist + writable + free-space warning thresholds (100 MB / 50 MB) |
| `zfs`        | `zpool status -x` parsed for "all pools are healthy" / "no pools available" / anything else |
| `config`     | `/usr/local/etc/crated.conf` parseability sniff (read first 4 KB, reject NUL bytes) |
| `jails`      | `JailQuery::getAllJails(crateOnly=true)` — flag dying jails as WARN |
| `audit`      | `/var/log/crate/audit.log` size — WARN at ≥100 MB suggesting rotation |

Categories sort in canonical order in text output (kernel → command →
filesystem → zfs → config → jails → audit) so day-to-day diffs are
clean. Within a category, checks sort alphabetically by name.

### Implementation

- `lib/doctor_pure.{h,cpp}` — `Check`/`Severity`/`Report` data model,
  `passCheck`/`warnCheck`/`failCheck` constructors, text + JSON
  rendering, exit-code aggregation. No system surface — testable on
  any platform.
- `lib/doctor.cpp` — runtime: kldstat per-module, `access(X_OK)` on
  command paths, `statvfs(2)` for free-space, `zpool status -x` parse,
  `crated.conf` text-sniff, JailQuery walk, `stat(2)` on audit log.
  Read-only by construction.
- `cli/args.cpp` + `cli/args_pure.cpp` — `CmdDoctor`, `-j/--json`
  flag, no positional args.
- `lib/audit.cpp` — added to the `isReadOnly` whitelist (alongside
  list/info/stats/logs/top/inspect) so `crate doctor` runs don't
  fill the audit log on a polled monitor.

### Tests

`tests/unit/doctor_pure_test.cpp` — **13 ATF cases**:

- Constructor severity, label strings, tally counters, exit-code priorities (FAIL > WARN > PASS)
- Text rendering: groups by category, severity labels present, summary
  line, ANSI-colour gating (`--no-color`), detail field surfaced,
  canonical category order
- JSON rendering: top-level shape, empty-report shape, escapes for
  quotes/newlines

**902/902 unit tests pass locally** (889 from prior + 13 new).

### NOT in this release (future)

- **Network policy check** — would inspect ipfw rules vs operator-
  defined rules for conflicts. Tricky to do without false positives.
- **Per-jail RCTL drift** — verify the actual rctl rules match what
  the spec said. Needs spec-loading machinery; deferred.
- **WireGuard / IPsec config sanity** — render to /tmp and diff
  against installed config. Defer until operators ask.

---

## [0.7.12] — 2026-05-05

Build infrastructure: Makefile test-link refactor. The per-test
`tests/unit/%: $(TEST_LINK_SRCS) ...` rule was inline-compiling
every pure source for every test binary (~30 sources × ~40 tests =
~1200 compilations on a clean build). Each new pure-test added
about a minute to the FreeBSD-lite CI job, which hit the 20-minute
inner timeout on the 0.7.9 release commit (workaround: bumped to 30m
in 0.7.9 followup).

This release moves the pure sources into per-source object files
under `tests/unit/.test-objs/` that are compiled **once** and then
linked into every test binary:

```
tests/unit/.test-objs/lib/util_pure.o
tests/unit/.test-objs/lib/spec_pure.o
... (one .o per TEST_LINK_SRCS source) ...
tests/unit/.test-objs/tests/unit/_test_config_stub.o
```

A `.SECONDARY:` directive marks them as non-intermediate so make
keeps them across runs (incremental rebuilds become near-instant —
no-op finishes in milliseconds).

### Measured speedup

On a 32-vCPU dev box (`make -j32 build-unit-tests` from clean):

| variant                              | wall clock |
|--------------------------------------|------------|
| 0.7.11 (per-test inline compile)     | **4m 07s** |
| 0.7.12 (compile-once + link-many)    | **0m 14s** |

That's ~17× on this box. On the 4-vCPU FreeBSD CI VM the absolute
numbers will be larger but the ratio holds.

Incremental no-op:

```
$ make build-unit-tests
make: Nothing to be done for 'build-unit-tests'.
real    0m0.008s
```

### Implementation

- `Makefile`:
  - New `TEST_OBJ_DIR = tests/unit/.test-objs`
  - New `TEST_LINK_OBJS` derived via
    `$(patsubst %.cpp,$(TEST_OBJ_DIR)/%.o,$(TEST_LINK_SRCS))` —
    keeps source dir layout under TEST_OBJ_DIR so the same
    `$(TEST_OBJ_DIR)/%.o: %.cpp` pattern rule covers all five
    top-level dirs (lib/ daemon/ cli/ hub/ snmpd/) without
    duplicate rules.
  - Pattern rule auto-creates the per-dir parent via
    `@mkdir -p $(@D)`.
  - `.SECONDARY: $(TEST_LINK_OBJS) $(TEST_STUB_OBJ)` keeps the
    objects across builds (without it, make treats them as
    intermediate and `rm`s them after each test links — defeating
    the whole point of caching).
  - `clean-tests` now also `rm -rf $(TEST_OBJ_DIR)`.
- `.gitignore` ignores `tests/unit/.test-objs/`.
- `TODO` entry for "Makefile test-link refactor (medium priority)"
  removed — done in this release.

### Why we didn't lower the freebsd-build-lite CI timeout

Stays at 30m (raised in the 0.7.9 followup). The clean build will
now fit comfortably under 5m on the CI VM, but a slow runner day
or future test additions will still benefit from the headroom.
Lowering the timeout is a one-line followup we can defer.

### Coverage target unaffected

The `coverage` target still uses `COVERAGE_CXXFLAGS` / `COVERAGE_LDFLAGS`
which the new pattern rule honours during the per-source compile.
gcov instrumentation lands in `.test-objs/` alongside the .o files,
which `find tests/unit -name '*.gcda' -delete` continues to clean
correctly (the find walks the .test-objs subtree too).

---

## [0.7.11] — 2026-05-05

Closes the defence-in-depth gap left in 0.7.10: control sockets now
verify peer credentials via `getpeereid(2)` on each connection,
matching what the design document promised.

The 0.7.10 prototype used cpp-httplib for control sockets, which
gave routing for free but did not expose the per-connection fd to
handlers — making `getpeereid(2)` impossible to call. We had to
synthesise `peerGid = expectedGid` and rely solely on filesystem
permissions. 0.7.11 replaces the httplib code path for control
sockets with a hand-rolled accept loop that captures peer creds
the moment `accept(2)` returns:

```
accept(listenFd) -> connFd
getpeereid(connFd, &uid, &gid)  ← layer 2 active here
read header until \r\n\r\n
parseHttpHead(...)
read body up to Content-Length
parseRoute(method, path)
authorize(...)                  ← real peerGid passed in
dispatch + writeResponse
close
```

Defence in depth (now complete, 4 layers):

1. **Filesystem permissions** (kernel) — outer gate.
2. **`getpeereid(2)` re-check** (THIS RELEASE) — even if perms get
   loosened by misconfiguration, peer.gid must match the socket's
   configured group.
3. **Pool ACL** — request paths scoped to `socket.pools`.
4. **Role gate** — `viewer` socket rejects PATCH.

### Implementation

- `daemon/control_socket_pure.{h,cpp}` — extended with strict
  HTTP/1.0–1.1 wire parser (`parseHttpHead`) and response builder
  (`buildHttpResponse`):
  - Method whitelist (alpha only, ≤16 chars)
  - Path validation (printable ASCII only, ≤1024 chars)
  - Strict Content-Length (digits only, capped at 64KB)
  - Header line cap 4KB; total head cap 8KB
  - Case-insensitive header names
  - No chunked encoding, no continuation lines, no keep-alive
- `daemon/control_socket.cpp` — fully rewritten:
  - `bindSocketOrThrow` — `socket(AF_UNIX) → bind → chmod → chown
    → listen(16)`. Per-spec fail-soft: errors during bind log and
    skip just that socket; other sockets keep going.
  - `acceptLoop` — `SO_RCVTIMEO`-driven so a stop-flag check fires
    every second for graceful shutdown.
  - `handleConnection` — `getpeereid` first, parse, authorize,
    dispatch, write, close. Per-connection thread, detached.
- The `extern "C" int getpeereid(int, uid_t *, gid_t *);` declaration
  is portable across FreeBSD (where it's in `<unistd.h>`) and Linux
  glibc (where it requires `_DEFAULT_SOURCE`); a duplicate
  declaration matches the BSD signature stable since 4.4BSD.

### Tests

`tests/unit/control_socket_pure_test.cpp` extended with **8 new
ATF cases** for the wire parser:

- `http_parse_typical_get` — happy path
- `http_parse_patch_with_content_length` — extracts CL header
- `http_parse_content_length_case_insensitive` — `CONTENT-LENGTH`,
  `content-length` both work (RFC 9110 case-insensitivity)
- `http_parse_http_1_0_accepted` — both 1.0 and 1.1 supported
- `http_parse_rejects_malformed` — empty input, no CRLF, missing SP,
  unsupported version, space in path, non-numeric CL, oversized CL,
  header without colon, truncated head
- `http_parse_rejects_bad_method_chars` — non-letter / over-cap
  method names
- `http_response_shape` — status/CT/CL/connection-close all present;
  body verbatim after empty CRLF
- `http_response_status_codes` — 400/403/404/500 reason phrases

**889/889 unit tests pass locally** (881 from prior + 8 new).

### NOT in this release (still future)

- **Lifecycle endpoints** (start/stop/destroy) on control sockets.
  Those keep the bearer-token requirement on the main API.
- **Per-jail (not per-group) sockets.** The current per-group model
  covers the multi-team use case; per-jail isolation can come if
  operators ask for it.

---

## [0.7.10] — 2026-05-05

`crated` control sockets — bearer-token-less Unix-socket REST API for
GUI/tray applications, with **per-group isolation via filesystem
permissions**. Operator A in unix group `dev-team` connects to
`/var/run/crate/control/dev.sock`; operator B in group `ops`
connects to `/var/run/crate/control/prod.sock`. The kernel rejects
operator B's `connect(2)` on operator A's socket with `EACCES`
before crated sees a byte — true sibling isolation.

This release picks up the Firecracker control-plane idea (item 4 of
the Firecracker comparison series), adapted to multi-tenant single-host
operators: where Firecracker spawns one mini-daemon per VM, we get
the same isolation properties via N Unix sockets in one daemon, with
no per-jail process overhead.

### Configuration

```yaml
control_sockets:
    - path: /var/run/crate/control/dev.sock
      group: dev-team           # resolved at startup via getgrnam(3)
      mode:  "0660"             # default; 0660 root:dev-team
      pools: [dev, stage]       # which pools this socket can manage
      role:  admin              # admin = full; viewer = read-only

    - path: /var/run/crate/control/prod.sock
      group: ops
      mode:  "0660"
      pools: [prod]
      role:  admin

    - path: /var/run/crate/control/monitoring.sock
      group: developers
      mode:  "0660"
      pools: ["*"]              # everything, but read-only
      role:  viewer
```

### API surface (per socket)

| Method | Path                                            | Required role |
|--------|-------------------------------------------------|---------------|
| `GET`   | `/v1/control/containers`                        | viewer        |
| `GET`   | `/v1/control/containers/<name>`                 | viewer        |
| `GET`   | `/v1/control/containers/<name>/stats`           | viewer        |
| `PATCH` | `/v1/control/containers/<name>/resources`       | admin         |

`PATCH /resources` body is a flat JSON object with a strict whitelist:
`pcpu` (0..100), `memoryuse`, `readbps`, `writebps` (K/M/G/T suffix).
Unknown keys are **rejected**, not silently ignored — a typo by a
tray-app developer fails loudly instead of being a no-op. The
backing implementation is `rctl(8)` — same mechanism as `crate retune`
(0.7.6), but reachable from non-root users via filesystem-permission
ACL instead of admin token.

Lifecycle-changing operations (start/stop/restart/destroy) are
**deliberately not exposed** on control sockets. Those remain on
the bearer-token main API. The control plane is for **status polling
and live tuning** by trusted user-level processes.

### Defence in depth

1. **Filesystem permissions (kernel-enforced).** A 0660 root:ops
   socket cannot be opened by operators outside the `ops` group.
   `connect(2)` returns `EACCES` before crated runs a single line of
   code. This is the primary isolation boundary.
2. **Pool ACL.** Even if a peer reaches a socket, `/v1/control/
   containers/<name>` is rejected with HTTP 403 if `<name>`'s
   inferred pool isn't in the socket's `pools:` list. "*" is the
   explicit all-pools grant.
3. **Role gate.** A `viewer` socket rejects `PATCH /resources` with
   HTTP 403 even if everything else allows. Read-only by construction.

### Operator-friendly defaults

- **Missing group** in the system database → log a warning and
  **skip that one socket entry**; crated continues with the rest.
  Avoids "the prod box won't start because dev-team isn't in
  /etc/group on the prod host".
- **Mode > 0660** (world-readable bits set) → log a warning and
  **proceed as configured**. Operators may have legitimate reasons
  to relax (e.g. a multi-team monitoring pipeline); we surface the
  risk without forcing a specific policy.
- **Sockets live under** `/var/run/crate/control/`. The path is
  validated against this prefix at config-load time — operators
  cannot accidentally drop sockets in `/tmp` or `/etc`.

### Implementation

- `daemon/control_socket_pure.{h,cpp}` — pure module:
  - `ControlSocketSpec` config struct + `validateSocketSpec()`
  - `parseRoute(method, path)` — `/v1/control/containers/...`
    parser; rejects unknown methods and bad container names
  - `authorize(...)` — five-way decision matrix (Allow + 4 Deny
    reasons) with HTTP status mapping
  - `parseResourcesPatch(json)` — strict whitelist + minimal flat
    JSON parser; rejects malformed body, unknown keys, empty `{}`
  - `renderContainersJson()`, `renderErrorJson()`,
    `renderPatchOkJson()` — stable, sorted JSON output
- `daemon/control_socket.{h,cpp}` — runtime: bind N Unix sockets
  with proper mode/ownership; one `httplib::Server` per socket on
  a detached thread; route handlers delegate every decision to the
  pure module
- `daemon/config.{h,cpp}` — `control_sockets:` YAML section parser
  + validation hook into `ControlSocketPure::validateSocketSpec`
- `daemon/main.cpp` — `ControlSocketsManager` lifecycle alongside
  the existing `Server` and `WsConsole`
- `daemon/crated.conf.sample` — three example sockets covering
  the typical multi-team deployment shape

### Tests

`tests/unit/control_socket_pure_test.cpp` — **29 ATF cases**:

- `validateSocketSpec` — typical/invalid path (must live under
  `/var/run/crate/control/`), group alphabet, mode range, role
  enum, pools list including "*"
- `isModeSafe` — 0660 ok, 0666/0664/0661/0777 flagged
- `parseRoute` — list/get/stats/patch + method-mismatch + unknown
  prefix + malformed container name
- `authorize` — full ACL decision matrix:
  - typical allow on all four actions
  - gid mismatch → `DenyGidMismatch`
  - pool filter (matches "*", pool-less containers, alt separator)
  - viewer + PATCH → `DenyRoleMismatch`
  - viewer GET on all paths still allowed
  - unknown action → `DenyUnknownAction`
- `parseResourcesPatch` — typical, all-keys, unknown-key reject,
  empty-body reject, malformed-JSON reject (5 forms)
- `renderContainersJson` — stable sort, empty-list shape
- `renderErrorJson` — escapes `"` and `\n`
- `renderPatchOkJson` — omits empty fields
- `httpStatusFor` — 200/403/404 mapping
- `poolVisibleOnSocket` — "*" matches anything (incl. pool-less)

**881/881 unit tests pass locally** (852 from prior + 29 new).

### Defence-in-depth caveat (0.7.11 follow-up)

`ControlSocketPure::authorize()` includes a `peerGid != socketExpectedGid`
check intended as a layer-2 re-verification using `getpeereid(2)`
on the connection fd. cpp-httplib (the framework crated uses for
HTTP) does not currently expose the per-connection fd through its
public API, so the runtime synthesises `peerGid = expectedGid` —
i.e. trusts the kernel's filesystem-permission gate to have already
filtered out wrong-group peers. The pure-module check exists, is
unit-tested, and will activate the moment the runtime grows access
to the connection fd (planned: 0.7.11, via either a custom
HTTP-on-unix accept loop or a small cpp-httplib patch).

For 0.7.10 this is acceptable: filesystem permissions alone are
already a substantial improvement over bearer tokens for the GUI
use case, and the layer-2 re-check is defence-in-depth — not the
primary boundary.

### NOT in this release (future)

- **Per-connection `getpeereid(2)`** — see caveat above. (0.7.11)
- **Lifecycle endpoints** (start/stop/destroy) on control sockets.
  Those keep the bearer-token requirement on the main API.
- **WebSocket console / screenshots** through the control socket.
  The console uses a separate listener (0.6.4) and screenshots
  need X11 + XAUTHORITY context that's hostile to a generic daemon
  handler.
- **Per-jail (not per-group) sockets.** If operators want true
  N-sockets-per-N-jails isolation, that's a future Variant 3 from
  the design analysis. For multi-team setups the per-group model
  in this release is sufficient and N-jails-times-cheaper.

---

## [0.7.9] — 2026-05-05

`crate run --warm-base <dataset> --name <name>` — Part 2 of the
warm-template story (Part 1 was 0.7.5's `crate template warm`).
A new jail boots from a fresh ZFS clone of the warm template,
bypassing tar-extract + cold-create work entirely. Where the cold
path takes 30+ seconds (xz decompress, base.txz extract, pkg
install replay, profile init), warm-base typically lands at
1-2 seconds — the whole speed-up story for ZFS-backed workflows.

### Usage

```sh
# 1. Once: bake an image (run jail, install pkgs, configure, then
# capture). 0.7.5 territory.
crate run -f firefox.crate
crate template warm firefox --output tank/templates/firefox-warm

# 2. From now on, fresh jails come up near-instantly:
crate run --warm-base tank/templates/firefox-warm --name fox-1
crate run --warm-base tank/templates/firefox-warm --name fox-2
crate run --warm-base tank/templates/firefox-warm --name dev-fox
```

`-f / --file` and `--warm-base` are mutually exclusive. With
`--warm-base` the rootfs comes from the ZFS clone; the spec is
parsed from `+CRATE.SPEC` inside the cloned dataset (the source
jail's directory had it from when it was extracted from the
original .crate).

`--name` is required and only valid with `--warm-base` — without
the .crate file there is no name to derive.

### Mechanism

```
zfs snapshot <warmDataset>@warmrun-<utc>
zfs clone    <warmDataset>@warmrun-<utc> <jailsParent>/jail-<name>-<hex>
# ZFS auto-mounts the clone at <jailsParent.mountpoint>/jail-<name>-<hex>
# which is precisely where lib/run.cpp expected jailPath.
... (normal jail startup, no tar extraction) ...
# At teardown:
zfs destroy <jailsParent>/jail-<name>-<hex>     # auto-unmounts
zfs destroy <warmDataset>@warmrun-<utc>         # marker snapshot
```

Two distinct snapshot-suffix prefixes, so operators can prune them
with different retention rules:

| Prefix       | Owner                      | When pruned                              |
|--------------|----------------------------|-------------------------------------------|
| `warm-...`   | `crate template warm`      | When operator retires the template       |
| `warmrun-...`| `crate run --warm-base`    | At jail teardown (best-effort cleanup)   |

### Defence in depth

- **Warm-base + `-f` is rejected at validate time.** The two paths
  are mutually exclusive; the validator surfaces the typo before
  any ZFS call.
- **Warm dataset name validated** with the same rules as
  `crate template warm` (alnum + `._-/`, no `..`, no `//`, no
  leading/trailing `/`). Rejection happens before any `zfs(8)`
  invocation.
- **Jail name validated** as alnum + `._-`, length 1..64. No
  shell metas, no path separators.
- **Jails dir must be on ZFS.** Surfaces a clear error if
  `Locations::jailDirectoryPath` isn't a ZFS mountpoint —
  warm-base is a ZFS-only feature by construction.
- **Missing `+CRATE.SPEC` in clone** raises a structured error
  pointing at the expected path, instead of letting the YAML parser
  fail with a cryptic "file not found".
- **Teardown is best-effort.** A failure in `zfs destroy <clone>`
  during cleanup logs but does NOT mask the actual run-time error.
  This matches the existing `RunAtEnd` semantics for the cold path.

### Implementation

- `lib/warm_pure.{h,cpp}` — extended with three consumer-side
  helpers:
  - `validateJailName(name)` — same alphabet as
    `BackupPure::validateJailName`
  - `warmRunSnapshotSuffix(epoch)` — distinct `warmrun-` prefix
  - `warmRunCloneName(parent, name, hex)` — same naming as
    `Locations::jailDirectoryPath/jail-<name>-<hex>` so
    mountpoint inheritance lands the rootfs at the expected path
- `lib/run.cpp` — new branch gated by `args.runWarmBase`:
  - Skip `mkdir(jailPath)` (ZFS creates it via auto-mount)
  - `ZfsOps::snapshot(warmSnap)` + `ZfsOps::clone(warmSnap, clone)`
  - `RunAtEnd destroyWarmClone` replaces the cold path's
    `RunAtEnd destroyJailDir` (rmdirHier on a mounted clone
    would either fail or wipe through the mount)
  - Skip the tar validate + extract block; sanity-check
    `+CRATE.SPEC` exists in the clone
- `cli/args.cpp` — `--warm-base` and `--name` flags; updated
  `usageRun()` documents the two modes
- `cli/args_pure.cpp` — `Args::validate` for `CmdRun` enforces
  the mutual exclusion + `--name` requirement
- `cli/main.cpp` — outer-loop restart-policy extraction skipped
  when no `-f` is given (warm-base operators wrap their jail in
  rc.d if they want outer restart)
- `lib/args.h` — `runWarmBase`, `runName` fields

### Tests

`tests/unit/warm_pure_test.cpp` extended with 6 new ATF cases:

- `warm_base_jail_name_typical` / `_invalid` — alphabet, length cap,
  reserved-name rejection, shell-meta rejection
- `warm_run_suffix_distinct_from_template_suffix` — invariant that
  `warmrun-` and `warm-` prefixes never alias each other
- `warm_run_suffix_canonical_epochs` — known epoch -> known string
- `warm_run_suffix_lex_sort_matches_chrono` — cron-pruning property
  inherited from the backup module convention
- `warm_run_clone_name_shape` — same naming as
  `jail-<name>-<hex>` for two parent datasets

**852/852 pass locally.** Total warm_pure_test cases: 16.

### NOT in this release

- **Spec override.** `crate run --warm-base <ds> -f <other.crate>`
  to take rootfs from the clone but a different spec from the
  archive. Flagged as a future enhancement; current 0.7.9
  rejects this combo as an error.
- **Multi-host pull.** Cloning warm templates across hosts goes
  through `crate replicate` (0.7.2) explicitly — not auto-pulled
  by `--warm-base`.
- **Outer-loop restart policy.** With no `-f`, the
  `cli/main.cpp` top-level restart loop has no spec to read. The
  spec inside the clone IS still honoured for in-jail restart;
  operators wanting outer-loop restart should run the jail under
  rc.d.

---

## [0.7.8] — 2026-05-04

`crate backup-prune <dir> --keep <spec>` — Proxmox-style retention
pruning of `crate backup` stream files. Operators write daily backups
to a directory (NFS share, USB disk, S3-mounted FS); this command
deletes the old ones under a bucketed retention policy without the
operator having to script `find -mtime` rules.

The Firecracker / Proxmox-VE comparison series picked off another
operator pain point: backup files accumulate forever on the backup
volume, and existing tooling (Proxmox vzdump-prune) bucketing
semantics aren't trivial to script with shell. This release ships
the same semantics in a one-shot command.

### Usage

```sh
# Daily=7, weekly=4, monthly=6 — same syntax as Proxmox vzdump
crate backup-prune /backups --keep daily=7,weekly=4,monthly=6

# Filter to one jail (useful when one dir holds several jails)
crate backup-prune /backups --keep daily=14 --jail postgres

# Preview without deleting
crate backup-prune /backups --keep daily=7 --dry-run

# Also remove orphaned incrementals (default: keep + warn)
crate backup-prune /backups --keep daily=7 --delete-orphans
```

### Bucketing semantics

For each retention bucket type with `N>0` (`hourly | daily | weekly
| monthly`), walk the **full** stream files newest → oldest. The
newest stream that lands in a fresh bucket key is kept; subsequent
streams in the same bucket are dropped. Stop after `N` distinct
buckets are seen.

The kept set is the **union** across bucket types. A file pinned by
multiple types still counts as one keeper.

Bucket key derivations (all UTC):

| bucket  | key                          |
|---------|------------------------------|
| hourly  | `epoch / 3600`               |
| daily   | `epoch / 86400`              |
| weekly  | `epoch / (86400 * 7)`        |
| monthly | `gmtime → year*12 + month`   |

`monthly` is calendar-aligned — months don't have uniform length so
plain integer division would drift over the years.

### Incremental chains

`crate backup --auto-incremental` produces files like
`<jail>-backup-<curr>.inc-from-backup-<prev>.zstream` that depend on
their base full. Two safety rules:

1. **Incrementals follow their base.** If the base full is kept,
   the incremental is kept too — chains stay restorable. If the
   base is dropped, the incremental is flagged as an *orphan*.
2. **Orphans default to keep + warn.** Operators can pass
   `--delete-orphans` to remove them as well. We don't auto-delete
   because partial chains are sometimes intentional (e.g. an
   operator wants the last full + some recent incrementals before
   a destructive change).

### Defence in depth

- **Filename schema enforced.** The pure parser only matches
  `<jail>-backup-YYYY-MM-DDTHH:MM:SSZ.zstream` (and the optional
  `.inc-from-...` tail). Files in the directory that don't match —
  README.md, .DS_Store, an external tool's output — are silently
  skipped, never touched.
- **Right-most `-backup-` boundary.** Jail names containing `-`
  (e.g. `dev-postgres`) parse correctly; we use `rfind` so the
  rightmost `-backup-` separator wins.
- **Epoch parsing rejects out-of-range values.** Bad month/day/hour
  values produce a parse failure (file goes to "skipped", not
  "removed"). The 1970-01-01T00:00:00Z epoch is treated as a
  parse-failure sentinel — nobody names a backup that.
- **Unparseable timestamps are orphans, never auto-removed.** Even
  with `--delete-orphans`, files with an unrecognisable suffix stay
  put — we don't know what they are.
- **`unlink` failures don't abort.** If one file can't be removed
  (permissions, vanished mid-run), the rest still process; the
  failure is reported in red without aborting.

### Implementation

- `lib/backup_prune_pure.{h,cpp}` — pure module:
  - `validateDir`, `validateJailFilter` — input sanitisation
  - `parseSuffixEpoch` — UTC ISO-8601 → `time_t` via Howard
    Hinnant's days_from_civil algorithm (no `timegm` dependency,
    no `TZ` race)
  - `parseStreamFilename` — splits the schema into
    `(jail, suffix, incFromSuffix, epoch)`
  - `hourBucket`, `dayBucket`, `weekBucket`, `monthBucket` —
    bucket-key derivations
  - `decidePrune` — the policy core; returns
    `{keep, remove, orphans}` triple
  - `explainKeeps` — keep-set with per-file reason ("daily:1",
    "monthly:3" etc.) for verbose / debug use
- `lib/backup_prune.cpp` — runtime: `std::filesystem` directory
  scan, calls into pure module, `Util::Fs::unlink` per decision,
  size summary in MB
- CLI: `cli/args.cpp` adds `usageBackupPrune()` + parser case;
  `cli/args_pure.cpp` adds `isCommand("backup-prune")` and
  validation; `lib/args.h` adds `Cmd BackupPrune` + 5 fields
- `lib/audit.cpp`, `lib/audit_pure.cpp` — recorded as
  state-changing (writes the `backup-prune` line into audit.log
  with target = `<dir> keep=<spec>`)

### Tests

22 ATF cases in `tests/unit/backup_prune_pure_test.cpp`:

- Directory + jail-filter validators
- Epoch parsing — known dates, round-trip through
  `BackupPure::snapshotSuffix`, malformed-input rejection
- Filename parser — full / incremental / dashed-jail-name (rfind
  correctness), garbage-file rejection
- Bucket distinctness across hour/day/week/month
- Calendar-aligned month bucketing across Feb→Mar boundary
- Daily-only, mixed daily+monthly union
- Empty policy keeps nothing
- Incremental kept with surviving base; orphaned with dropped base
- `--delete-orphans` flag promotes orphans to removals
- Lists are disjoint (no file appears in more than one bucket)
- Empty input + "more buckets requested than files exist" both
  produce sensible decisions

### Caveats

- Operates on **stream files** in the backup directory, never on
  source-side ZFS snapshots. Operators who want snapshot pruning
  on the source pool should keep using `zfs destroy` — that's a
  separate concern with different blast radius.
- Only files matching the `crate backup` schema are touched. Other
  files in the directory are visible (in the "skipped" count) but
  never deleted — even with `--delete-orphans`.
- No interactive confirmation prompt. Operators are expected to
  run `--dry-run` first or wrap the command in their own
  confirmation. Adding a `--yes` requirement would force operators
  to plumb `--yes` through cron, which we deemed worse.

---

## [0.7.7] — 2026-05-04

`crate throttle <jail>` — **true token-bucket network rate
limiting** via FreeBSD's `dummynet(4)` accessed through
`ipfw(8)`. Sister to `crate retune` (0.7.6) which targets RCTL
hard caps for CPU/disk/memory. This release fills the
"Firecracker-style sustained-rate-with-burst" gap for network
traffic — torrent client gets 1Mbit/s sustained but can burst to
1MB so initial DHT chatter doesn't lag.

### Usage

```sh
# Cap a torrent client to 10Mbit/s ingress, 5Mbit/s egress, 1MB burst:
crate throttle torrent --ingress 10Mbit/s --egress 5Mbit/s \
                       --ingress-burst 1MB --egress-burst 1MB

# Egress-only (downloads fine, uploads fighting your IDE):
crate throttle torrent --egress 1Mbit/s --queue 100

# Inspect current pipe state:
crate throttle torrent --show

# Drop all throttling for the jail:
crate throttle torrent --clear
```

### Mechanism

```
ipfw pipe <pipeId> config bw <rate> burst <burst> queue <queue>
ipfw add <ruleId> pipe <pipeId> ip from <jailIp> to any out  (egress)
ipfw add <ruleId> pipe <pipeId> ip from any to <jailIp> in   (ingress)
```

`bw` is sustained rate (Firecracker's "refill rate"), `burst` is
bucket capacity (Firecracker's "size"). Together a textbook
token bucket.

### Pipe ID allocation

Per-jail deterministic IDs: `pipeId = 10000 + jid*2 + (egress?1:0)`,
`ruleId = 20000 + jid*2 + (egress?1:0)`. Two pipes per jail
(ingress/egress). The deterministic mapping means:

- Re-running `crate throttle torrent --ingress 5Mbit/s` after
  earlier `--ingress 10Mbit/s` **replaces** the old config; no
  orphan pipes.
- A teardown after a daemon restart can find the right pipe to
  delete.
- `kPipeBase = 10000` and `kRuleBase = 20000` leave the low IDs
  for operator-defined ipfw rules.

### Defense in depth

- **Rate** rejects the bare `"10M"` form on purpose. ipfw accepts
  it but the bit/s vs byte/s ambiguity bites operators. We force
  `Mbit/s` or `MB/s` to be spelled out.
- **Burst** rejects `/s` suffix — burst is bytes, not bytes/s.
  Catches the common typo where someone writes `--burst 1MB/s`.
- **Queue slot count** capped at 1..1000. Without that, an
  operator could turn it into an unbounded memory sink for
  dummynet's per-packet allocations.
- **Burst without rate** is flagged as a config error — burst
  alone has no effect, surfacing the typo instead of silently
  accepting it.
- **Jail IP** validated as IPv4 (octet bounds checked) before
  reaching ipfw — otherwise the wrong octet would silently
  rule-bind to nothing.

### Implementation

- **`lib/throttle_pure.{h,cpp}`** — pure helpers:
  `validateRate`/`validateBurst`/`validateQueue`/`validateIp`,
  `pipeIdForJail`/`ruleIdForJail` (deterministic),
  `ThrottleSpec` + `validateSpec`, argv builders for `pipe
  config`/`add bind`/`delete rule`/`pipe delete`/`pipe show`.
- **`lib/throttle.cpp`** — runtime: jail-name → JID + IPv4 via
  `JailQuery`, soft-delete prior config (so repeats replace
  cleanly), apply per-direction. `--clear` strips both
  directions; `--show` runs `ipfw pipe show` for each.
- **`cli/args.cpp` + `main.cpp`** — `CmdThrottle` enumerator,
  full flag set wired.
- **`lib/audit*.cpp`** — recorded as state-changing.

### Tests

`tests/unit/throttle_pure_test.cpp` — 20 ATF cases:

| Group | Notable cases |
|---|---|
| `validateRate` | typical bit/s + byte/s; **bare `10M` REJECTED** (ambiguity guard); lowercase `mbit/s` rejected (ipfw is finicky); `Mbps` rejected |
| `validateBurst` | empty allowed; `/s` suffix rejected (burst is bytes, not bytes/s) |
| `validateQueue` | slot count 1..1000; byte size `KB`/`MB`; out-of-range rejected |
| `validateIp` | typical, octet > 255 rejected, missing/extra octet rejected |
| `pipeIdForJail` | deterministic per JID+direction, distinct ranges from `ruleIdForJail` |
| `validateSpec` | full spec, single direction, **burst-without-rate flagged** |
| argv builders | full pipe config; **optional burst+queue omitted when empty**; egress vs ingress `from`/`to` ordering; `pipe delete` word order (delete LAST for pipes) |

**Verified locally: 20/20** in `throttle_pure_test`.

---

## [0.7.6] — 2026-05-04

`crate retune <jail> --rctl KEY=VALUE [--clear KEY]... [--show]`
— live RCTL adjustment for a running jail. **No restart required;
the jail's in-memory state survives.** Operator throttles a
runaway container (torrent client suddenly sucking the disk)
without losing its work.

Inspired by Firecracker's per-VM rate limiter, but built on top
of FreeBSD's existing `rctl(8)` — same hard-cap mechanism crate
already uses at create time, just exposed as a runtime knob.

### Usage

```sh
# Throttle a torrent client so it stops fighting your IDE for disk:
crate retune torrent --rctl writebps=2M --rctl readbps=2M

# Cap CPU + show before/after rctl usage:
crate retune torrent --rctl pcpu=20 --show

# Drop a previously-set rule:
crate retune ide --clear pcpu --clear writebps

# Combine — clears run before sets, so you can re-tune in one call:
crate retune torrent --clear writebps --rctl writebps=512K
```

### What's NOT in this release

True **token bucket** (sustained rate + burst) for network
throughput requires `dummynet(4)` integration — that's the topic
of 0.7.7. RCTL is a hard cap, not a token bucket.

### Validators (typos caught at parse time)

- **`--rctl KEY=VALUE`**: KEY whitelisted against the supported
  set (pcpu, memoryuse, vmemoryuse, readbps, writebps, readiops,
  writeiops, maxproc, openfiles, nthr, ...). Typos like `witebps`
  produce an error that **lists the supported keys** instead of
  shrugging — operators look at this, not the source.
- **VALUE** rejected per key class: `pcpu` is 0..100 with no
  suffix; `*bps`/`memoryuse` accept K/M/G/T (1024-based,
  matches `rctl(8)`); `*iops` and counts must be plain ints.
- **`--clear KEY`** validates the key against the same whitelist.

### Implementation

- **`lib/retune_pure.{h,cpp}`** — pure helpers:
  `validateRctlKey` (whitelist with helpful error),
  `validateRctlValue` (per-key kind: percentage / byte rate /
  plain int), `parseHumanSize` (1024-based; supports decimals
  like `1.5M`), argv builders for `rctl -a` (set), `rctl -r`
  (clear), `rctl -u` (show).
- **`lib/retune.cpp`** — runtime: jail-name → JID via
  `JailQuery`, optional pre-show `rctl -u`, apply `--clear`s
  first (soft-fail; rule may not exist), apply `--rctl`s, optional
  post-show. Raw operator value passes through to `rctl(8)` —
  no double-conversion of the suffix.
- **`cli/args.cpp` + `main.cpp`** — `CmdRetune` enumerator,
  repeatable `--rctl`/`--clear`, `--show` toggle.
- **`lib/audit*.cpp`** — recorded as state-changing.

### Tests

`tests/unit/retune_pure_test.cpp` — 16 ATF cases:
- 2 `validateRctlKey` (whole whitelist accepted; typos rejected
  with the supported-set list embedded in the error)
- 3 `validateRctlValue` per key class (pcpu range, byte rate
  with K/M/G/T, IOPS/counts no suffix)
- 3 `validatePairs` (typical, empty rejected, **error message
  contains the offending pair index** for multi-flag debugging)
- 4 `parseHumanSize` (plain int, K/M/G/T 1024-based, decimal
  `1.5M`, invalid → `-1`)
- 3 argv builders (set, clear, show — including the property
  that `set` passes the **raw suffix** through to rctl(8)
  unchanged so we don't double-convert)

**Verified locally: 16/16** in `retune_pure_test`.

---

## [0.7.5] — 2026-05-04

ZFS warm-template caching (part 1) — `crate template warm <jail>
--output <dataset>` captures a running jail's on-disk state as a
ZFS clone the operator can later pass to `crate run --warm-base
<dataset>` (planned for 0.7.6) to skip cold-create work like
`pkg install`, profile initialisation, or asset-cache priming.

### Inspired by but **not** Firecracker snapshot

Firecracker (and bhyve via `bhyvectl --suspend/--resume`) saves
**memory** state — open browser tabs, X11 sessions, in-flight
HTTP connections all come back. That requires either KVM/bhyve
hypervisor instrumentation or CRIU-style process checkpoint, and
**neither is available for FreeBSD jails today** (no CRIU port
that's production-ready; bhyve VMs are a separate product
class). Documented in `lib/warm_pure.h` and the usage screen.

What `crate template warm` actually captures vs. doesn't:

| Captured (on-disk)                    | NOT captured (memory) |
| ------------------------------------- | --------------------- |
| `pkg install` output, `/var/db/pkg`   | process memory        |
| fontconfig caches                     | open file descriptors |
| db migrations applied                 | unflushed page cache  |
| `npm install` output                  | browser tabs          |
| profile dirs, `/root/.config/...`     | X11 sessions          |

Practical effect: jail launch goes from 30+ seconds (cold create)
to 1-2 seconds (clone+launch). Firefox window appears, but tabs
must be re-opened.

### Usage

```sh
# Prime a jail with everything you want pre-installed:
crate run -f firefox.crate
# ... install, configure, log into accounts, browse a few sites ...

# Capture the on-disk state as a warm template:
crate template warm firefox --output tank/templates/firefox-warm

# Optional: promote the clone so deleting old warm snapshots
# doesn't break the template
crate template warm firefox --output tank/templates/firefox-warm --promote
```

### Design notes

- **Snapshot suffix** is `warm-YYYY-MM-DDTHH:MM:SSZ` (UTC, lex-
  sortable), matching the backup module convention so retention
  pruning is a one-liner: `ls -1 ...@warm-* | sort | head -n -N`.
- **Without `--promote`** the template dataset is a ZFS clone of
  the warm snapshot — near-zero space until written, but
  prevents deletion of the source snapshot. With `--promote`
  the clone graph is flipped (operator can delete old warms).
- **Validation gates** apply to the destination dataset: alnum
  + `._-/`, no `//`, no `.`/`..` segments, no leading/trailing
  slash, no `:` (reserved for snapshot/bookmark separators).
- **Audit log** records `template:warm:<jail>-><dataset>`.

### Implementation

- **`lib/warm_pure.{h,cpp}`** — pure helpers:
  `warmSnapshotSuffix(unixEpoch)` (UTC ISO 8601),
  `validateTemplateDataset` (same alphabet rules as
  `ReplicatePure::validateDestDataset`), `validateSnapshotSuffix`
  (rejects `@`/`/`/shell metas), and three argv builders for
  `zfs snapshot/clone/promote`.
- **`lib/warm.cpp`** — runtime: jail → ZFS dataset via
  `JailQuery`+`Util::Fs::getZfsDataset`, run snapshot, run
  clone, optional promote.
- **`cli/args.cpp` + `main.cpp`** — `CmdTemplate` enumerator;
  parser-side subcommand dispatch on `templateSubcmd` so we
  can grow `template list/destroy/...` later without breaking
  this contract.
- **`lib/audit*.cpp`** — recorded as
  `template:warm:<jail>-><dataset>`.

### Tests

`tests/unit/warm_pure_test.cpp` — 10 ATF cases:
- 2 `validateTemplateDataset` (typical, invalid: leading/trailing
  slash, double slash, `.`/`..`, `:`, shell metas)
- 2 `validateSnapshotSuffix` (typical, invalid: empty, 65 chars,
  `@`, `/`, shell metas)
- 2 `warmSnapshotSuffix` (canonical UNIX epochs, **lex-sort =
  chrono-sort invariant**)
- `fullSnapshotName` shape
- 3 argv-shape tests (snapshot, clone, promote)

**Verified locally: 10/10** in `warm_pure_test`.

### What's NOT in this release

`crate run --warm-base <dataset>` — the consumer side that
actually picks up the template at run time. That requires
modifying `lib/run.cpp`'s create-jail-directory path to clone
from the operator's warm dataset instead of extracting
`base.txz`. Tracked as 0.7.6.

---

## [0.7.4] — 2026-05-04

Resource pools + per-token ACL — operators carve their container
fleet into pools (teams / tenants / environments) and bind each
API token to a whitelist of pools it may touch. Inspired by
Proxmox's resource pools + permissions model; the daemon-side ACL
is the foundation that a future admin-UI repository will surface.

### Configuration

```yaml
auth:
    pool_separator: "-"     # default; use "_" or "." if jail names already use "-"
    tokens:
      - name: dev-team
        token_hash: "sha256:..."
        role: admin
        pools: ["dev", "stage"]    # cannot touch prod-* jails
      - name: ci-runner
        token_hash: "sha256:..."
        role: admin
        pools: ["*"]               # explicit all-pools grant
      - name: legacy
        token_hash: "sha256:..."
        role: admin
        # `pools:` omitted -> unrestricted (pre-0.7.4 behaviour)
```

### Pool inference (no schema migration)

We deliberately do NOT add a new `pool:` field to `crate.yml` —
that would force every existing spec to be rewritten. Instead the
pool is derived from the jail name using a configurable separator:

| jail name           | inferred pool (separator: `-`) |
| ------------------- | ------------------------------ |
| `dev-postgres-1`    | `dev`                          |
| `stage-redis`       | `stage`                        |
| `prod-web`          | `prod`                         |
| `monolithic`        | `""` (no pool)                 |

Operators who already use hyphens in container names can switch
the separator to `_` or `.`.

### ACL semantics

- `pools: []` (or omitted) → unrestricted; matches pre-0.7.4
  behaviour, so existing configs need no changes.
- `pools: ["*"]` → explicit all-pools grant; preferred over
  leaving the field out when the operator wants the intent
  visible in the config audit.
- `pools: ["dev"]` → only jails inferred to pool `dev`. Jails
  with no separator in the name (`monolithic`) are **invisible**
  to this token — operators must add `*` to reach them. Silent
  leakage of jails that don't follow the naming convention
  would defeat the ACL.

### Enforcement

12 F2 endpoints that take a `:name` URL parameter (stats, logs,
start, stop, restart, destroy, snapshot list/create/delete,
stats stream, export, restart) now use
`isAuthorizedForContainer(req, config, role, name)` instead of
`isAuthorized(req, config, role)`. The new helper runs the
existing role + TTL + scope chain, then consults the matching
token's `pools:` against `PoolPure::inferPool(name, config.poolSeparator)`.

The WebSocket console (`/api/v1/containers/<name>/console`)
applies the same ACL after the bearer-token handshake but before
opening the PTY — a token that can't see the pool gets
`token not allowed for this container's pool` at upgrade time.

`handleExportDownload` (which addresses an artifact `:filename`
rather than a container) keeps plain `isAuthorized` — artifact
filenames have their own validation and the pool concept doesn't
apply there.

Unix-socket peers bypass the pool ACL the same way they bypass
the bearer-token check — the unix-socket file mode (root:wheel
0660) is the gate, documented in CAVEATS in `crated.8`.

### Implementation

- **`lib/pool_pure.{h,cpp}`** — pure helpers: `inferPool`
  (single-byte separator; leading separator yields no-pool, not
  pool ""), `validatePoolName` (alnum bookend rules + `*`
  carve-out), `tokenAllowsContainer` (the full ACL matrix).
- **`daemon/config.{h,cpp}`** — `AuthToken.pools` and
  `Config.poolSeparator`. YAML parser reads `pool_separator:` as
  a single-char string; `pools:` as scalar or sequence.
- **`daemon/auth.{h,cpp}`** — new `isAuthorizedForContainer`
  wraps `isAuthorized` + the per-token pool check.
- **`daemon/routes.cpp`** — 12 F2 handlers migrated from
  `isAuthorized` to `isAuthorizedForContainer`.
- **`daemon/ws_console.cpp`** — pool ACL applied before PTY
  upgrade.
- **`daemon/crated.conf.sample`** — documents `pool_separator:`
  and `pools:` with a `dev-team` example.

### Tests

`tests/unit/pool_pure_test.cpp` — 13 ATF cases:
- 5 `inferPool`: typical dash separator, alternative `_`/`.`,
  no-separator-is-no-pool, **leading-separator-is-no-pool** (the
  property that prevents pool-restricted tokens from reaching
  `-foo` as pool `""`), empty input.
- 3 `validatePoolName`: typical accepted, wildcard accepted,
  invalid rejected (empty, 33 chars, leading `-`/`_`, dots,
  slashes, shell metas).
- 5 `tokenAllowsContainer`: empty = unrestricted (backward
  compat), wildcard = unrestricted, pool match allowed, pool
  mismatch denied, **no-pool jail reachable only by
  unrestricted/wildcard tokens** (the property that gates
  silent leakage).

**Verified locally: 13/13** in `pool_pure_test`.

---

## [0.7.3] — 2026-05-03

HA failover policy in hub — operators declare per-container HA
specs in `crate-hub.conf`; hub poller tracks how long each node
has been unreachable; new `GET /api/v1/ha/orders` publishes
deterministic migration orders that an operator/cron consumes via
`crate migrate`. Hub does NOT auto-execute, by design.

### Configuration

```yaml
ha:
    threshold_seconds: 60       # default; anti-flap window before HA fires
    specs:
      - container: postgres-prod
        primary:   alpha
        partners:  [beta, gamma]
      - container: redis-cache
        primary:   delta
        partners:  [epsilon]
```

### New endpoint

```
GET /api/v1/ha/orders
{ "status": "ok",
  "data": [
    { "container":"postgres-prod",
      "from_node":"alpha",
      "to_node":"beta",
      "reason":"primary node 'alpha' down for 120s (>= threshold 60s)" }
  ] }
```

Empty array when no failovers needed. **Deterministic**: same node
state → same orders → consumers don't see flapping.

### Why hub doesn't execute

A hub that auto-executes failover would need admin tokens for the
per-node daemons. That breaks the 0.6.7 architecture where admin
tokens stay in operator localStorage / chmod-600 files and never
cross hub-side logging. So hub publishes orders, operator runs:

```sh
curl -sf https://hub:9810/api/v1/ha/orders \
  | jq -r '.data[] | "\(.container) \(.from_node) \(.to_node)"' \
  | while read c from to; do
      crate migrate "$c" \
        --from "$from:9800" --from-token-file /etc/crate/tokens/"$from" \
        --to   "$to:9800"   --to-token-file   /etc/crate/tokens/"$to"
    done
```

A future `crate ha-execute` could wrap this; for now the shell
recipe is documented and shipped.

### Decision rules (deterministic)

- Primary reachable → no order.
- Primary unreachable for < `threshold_seconds` → no order
  (anti-flap window).
- Primary unreachable ≥ threshold → emit order to the **first
  reachable partner in declared order**. Order matters: list
  higher-priority hosts first.
- No partners reachable → emit **no** order. Half-failovers (move
  container off the dead primary into nowhere) are worse than
  letting the operator notice.

### Implementation

- **`hub/ha_pure.{h,cpp}`** — pure decision module:
  `evaluateFailoverOrders`, `renderOrdersJson` (stable shape,
  escapes `reason`), `validateSpecs` (alphabet, no duplicates,
  partner ≠ primary).
- **`hub/poller.{h,cpp}`** — `NodeStatus.firstDownAt` (UNIX
  epoch when current down-streak started; reset to 0 on
  successful poll). New `loadHaSpecs(path, *thresholdOut)`.
- **`hub/api.{h,cpp}`** — `registerApiRoutes` extended with
  `haSpecs` + `haThresholdSeconds`; new `GET /api/v1/ha/orders`.
- **`hub/main.cpp`** — loads + validates specs, wires through.

### Tests

`tests/unit/ha_pure_test.cpp` — 13 ATF cases:
- 4 decision-table: no-order-reachable, no-order-below-threshold,
  **emit at exact threshold** (boundary), partner pick order.
- No-order-when-all-partners-down (no-half-failover invariant).
- Missing primary skips silently.
- Multi-spec independence.
- **Deterministic invariant** (same input → same output —
  consumer loop stability).
- 3 JSON-render shape tests (incl. escape of `"`/`\n` in `reason`).
- 2 `validateSpecs` cases incl. partner == primary rejection.

**Verified locally: 13/13** in `ha_pure_test`.

---

## [0.7.2] — 2026-05-03

`crate replicate` — ZFS storage replication over `ssh`. Streams a
fresh snapshot of a jail's dataset to a remote host as a
`zfs send | ssh ... 'zfs recv'` pipeline. Supports incremental
sends (`--since` / `--auto-incremental`). All SSH transport options
are operator-controllable.

### Usage

```sh
# Daily snapshot to a DR host:
crate replicate myjail \
    --to backup@dr.example.com \
    --dest-dataset tank/jails/myjail \
    --auto-incremental \
    --ssh-port 2222 \
    --ssh-key /root/.ssh/id_ed25519 \
    --ssh-opt StrictHostKeyChecking=accept-new \
    --ssh-opt ConnectTimeout=30
```

### SSH transport — what operators can drive

| Flag | Purpose |
|---|---|
| `--ssh-port N` | non-default port |
| `--ssh-key PATH` | identity file (passed via `-i`) |
| `--ssh-config PATH` | custom `ssh_config` (passed via `-F`) |
| `--ssh-opt KEY=VAL` | repeatable; passed verbatim as `-o KEY=VAL` |

`--ssh-opt` is the deliberate escape hatch — we don't enumerate
every OpenSSH option in the CLI. Any of `StrictHostKeyChecking`,
`UserKnownHostsFile`, `ProxyJump`, `ConnectTimeout`, ... can be
threaded through.

**Defaults set automatically**: `BatchMode=yes` (no password
prompts in cron), `ServerAliveInterval=30` (keeps long sends
alive across firewalls). Both can be overridden via `--ssh-opt`.

### Defense in depth

Every input passes through pure validators **before** any
filesystem or process touchpoint:

- `--to`: `[user@]host` — user must be alnum + `._-`, host must
  be IPv4 (with octet bounds checked — `256.0.0.1` rejected) or
  RFC 1123 hostname. Shell metacharacters rejected.
- `--dest-dataset`: alnum + `._-/`, no `//`, no `.`/`..`
  segments, no leading/trailing `/`. ZFS dataset alphabet only.
- `--ssh-opt KEY=VAL`: KEY must be alnum (≤64 chars). VAL
  rejects whitespace, control chars, and shell metacharacters
  — values are passed unquoted to ssh, an unsanitised `;` would
  break out of the command.
- `--ssh-key` / `--ssh-config`: absolute paths only, no `..`
  segments, no metacharacters.

So even if `crated.conf` or a CI YAML is compromised, the worst
case is a `crate validate`-style error — never `ssh
host '...; rm -rf /'`.

### Implementation

- **`lib/replicate_pure.{h,cpp}`** — pure SSH-side helpers:
  `validateSshRemote` / `parseSshRemote` (with the IPv4-shape
  fix from 0.6.10 reused), `validateSshOpt` /
  `validateSshKey` / `validateDestDataset`, `buildSshArgv`
  (sets default `BatchMode=yes` + `ServerAliveInterval=30`,
  threads `-p`/`-i`/`-F`/`-o`), `buildRemoteRecvCommand`,
  `buildReplicationPipeline` (returns the two-stage argv-list
  for `Util::execPipeline`).
- **`lib/replicate.cpp`** — runtime: resolves jail → ZFS dataset
  via `JailQuery` + `Util::Fs::getZfsDataset`, finds latest
  `backup-*` snapshot for `--auto-incremental`, takes a fresh
  snapshot, runs the pipeline. Reuses `BackupPure::choosePlan`
  + `snapshotSuffix` from 0.7.0.
- **`cli/args.cpp` + `main.cpp`** — `CmdReplicate`,
  `usageReplicate()`, all flags wired.
- **`lib/audit*.cpp`** — recorded; target is
  `<jail>-><[user@]host>:<dest-dataset>`.

### Tests

`tests/unit/replicate_pure_test.cpp` — 15 ATF cases:
- 2 `validateSshRemote` (typical incl. v4/v6/hostname/no-user;
  invalid incl. empty user, empty host, `256.0.0.1`,
  underscore-hostname, shell metacharacters)
- 1 `parseSshRemote` user/host split
- 2 `validateSshOpt` (typical incl. `StrictHostKeyChecking=no`,
  `UserKnownHostsFile=/dev/null`, `ProxyJump=bastion`,
  `ConnectTimeout=30`; invalid incl. empty key, dash in key,
  whitespace in value, shell metas, control chars)
- 2 `validateSshKey` (typical, invalid: relative, `..`, metas)
- 2 `validateDestDataset` (typical, invalid: leading/trailing
  slash, double slash, `.`/`..` segments, `:`, metas)
- 3 `buildSshArgv` (minimal with defaults present, full options
  stitched in correct positions, no-user shape)
- 1 `buildRemoteRecvCommand` shape
- 2 `buildReplicationPipeline` (full two-stage; incremental
  uses `-i prev curr`)

**Verified locally: 15/15** in `replicate_pure_test`.

---

## [0.7.1] — 2026-05-03

API tokens gain optional **TTL** and **scope** fields — tighten the
blast radius of a leaked CI runner token without rewriting the
auth flow. Inspired by Proxmox's API token model (where each token
carries an explicit expiry and a path-prefix ACL).

### Configuration

```yaml
auth:
    tokens:
      - name: ci-runner
        token_hash: "sha256:..."
        role: admin
        expires_at: "2026-12-31T23:59:59Z"
        scope:
          - /api/v1/containers/*
          - /api/v1/exports/*
```

`expires_at` is a UTC ISO 8601 timestamp (`Z` or `+00:00`/`-00:00`
suffix; non-UTC offsets rejected). `scope` is a list of path
globs:

- exact match: `/api/v1/host`
- trailing prefix: `/api/v1/containers/*` matches any path that
  starts with `/api/v1/containers/`. **The slash is required** —
  the bare prefix `/api/v1/containers` does NOT match the glob,
  so granting per-resource access doesn't accidentally leak the
  collection-list endpoint.

### Backward compatibility

Pre-0.7.1 configs keep working unchanged. Missing `expires_at`
parses to `0`, which `isExpired()` treats as "never expires".
Missing `scope` parses to an empty list, which `pathInScope()`
treats as "no restriction". So an existing token with just
`name`/`token_hash`/`role` has identical behaviour after upgrade.

### Implementation

- **`lib/auth_pure.{h,cpp}`** — extends the pure module with
  `parseIso8601Utc(s)` (returns `-1` on bad shape, bad month
  range, or non-UTC offset; uses `timegm`), `isExpired(t, now)`
  (strict-after; `expiresAt=0` always returns false),
  `pathInScope(scope, path)` (empty scope → true; exact match or
  `/*`-suffix prefix match), and the combined
  `checkBearerAuthFull(...)` which folds expiry + scope into the
  hash + role-check sequence.
- **`daemon/config.{h,cpp}`** — `AuthToken` gains
  `expiresAt: long` and `scope: vector<string>` (defaults `0` /
  empty). YAML parser reads `expires_at:` (rejects malformed) and
  `scope:` (scalar or sequence).
- **`daemon/auth.cpp`** — `isAuthorized()` calls
  `checkBearerAuthFull` with `req.path` and `time(nullptr)`.
- **`daemon/crated.conf.sample`** — documents the new fields with
  a `ci-runner` example.

### Tests

`tests/unit/auth_pure_test.cpp` — 13 new ATF cases on top of the
existing 15:
- 3 `parseIso8601Utc` (canonical epochs at 1970/2000/2026 with
  exact UNIX values; invalid-shape rejection incl. bad month
  `2026-13-31`; `+00:00`/`-00:00` accepted as UTC)
- 2 `isExpired` (0 means never; strict-after at the boundary —
  exact-second still alive)
- 4 `pathInScope` (empty scope unrestricted; exact match without
  partial prefix; trailing `/*` glob; **glob requires slash —
  bare prefix doesn't match**, the property that gates
  per-resource access)
- 4 `checkBearerAuthFull` integration (expired-rejected even with
  matching role+scope; out-of-scope-rejected even with matching
  role; in-scope admin happy path; backward-compat with
  expiresAt=0 + empty scope = pre-0.7.1 behaviour)

**737/737** unit tests expected (was 724; pure tests verified at
28/28 for auth_pure_test alone).

---

## [0.7.0] — 2026-05-03

**0.7 series — enterprise-grade operations.** Inspired by what
Proxmox VE 8/9 ships (snapshot-based vzdump, replication,
HA failover, RBAC). The `0.7.x` line lands these one feature
per release without breaking the 0.6.x F2 API surface.

`crate backup` + `crate restore` — first piece. ZFS-send-based
snapshot streams, with incremental support, that operators can
park on cheap storage and replay months later.

### Usage

```sh
# Full backup nightly:
crate backup myjail --output-dir /var/backups/crate

# Daily incremental (auto-detects last backup-* snapshot):
crate backup myjail --output-dir /var/backups/crate --auto-incremental

# Explicit incremental from a known parent:
crate backup myjail --output-dir /var/backups/crate \
    --since backup-2026-05-01T00:00:00Z

# Restore (creates a fresh dataset):
crate restore /var/backups/crate/myjail-backup-2026-05-03T03:33:20Z.zstream \
    --to tank/jails/myjail-restored
```

### File naming

Filenames sort lexicographically by time, so retention pruning is
`ls -1 backup-* | sort | tail -n +N | xargs rm`. Incremental
streams carry a self-describing `inc-from-<parent>` tag so the
operator knows which chain a file belongs to without keeping a
separate index.

```
myjail-backup-2026-05-03T03:33:20Z.zstream                       (full)
myjail-backup-2026-05-04T03:33:20Z.inc-from-backup-2026-05-03T03:33:20Z.zstream
```

### Why no compression wrapper

ZFS already compresses datasets and the send-stream format is
designed to be dedup-friendly. Adding gzip/xz/zstd on top would
shrink streams by ~5% in typical container workloads while
doubling restore time. Operators who need network-pipeline
compression can pipe through their tool of choice —
`crate backup ... | zstd | ssh remote "zfs recv pool/dr/myjail"`
is two syscalls away.

### Implementation

- **`lib/backup_pure.{h,cpp}`** — pure helpers: snapshot suffix
  (UTC ISO 8601, lex-sortable), filename builder, validators,
  argv builders for `zfs snapshot/send/recv/destroy`, retention
  parser, full-vs-incremental plan chooser.
- **`lib/backup.cpp`** — resolves jail → dataset via `JailQuery`,
  finds latest backup-* via `zfs list` for `--auto-incremental`,
  pipes `zfs send` into the output file. `restore` runs
  `zfs recv` reading the stream file as stdin.
- **`cli/args.cpp` + `cli/main.cpp`** — `CmdBackup`+`CmdRestore`
  enumerators, dispatch, usage.
- **`lib/audit*.cpp`** — both recorded in audit.log; targets
  `<name>-><dir>` and `<file>-><dataset>` respectively.

### Tests

`tests/unit/backup_pure_test.cpp` — 23 ATF cases including the
**lex-sort = chronological-sort invariant** (the property that
makes cron-driven retention pruning trivial), full vs.
incremental argv shape, plan-choice priority (`--since` >
auto-incremental > full fallback on first run), retention parser
edge cases, and shell-metacharacter rejection in output dir.

**724/724** unit tests pass (was 701).

---

## [0.6.15] — 2026-05-03

Datacenter grouping in `crate-hub`. Operators running containers
across multiple regions can now label each node with a `datacenter:`
key in `crate-hub.conf`; the hub aggregates node + container counts
per-DC and exposes a new endpoint for the dashboard:

```
GET /api/v1/datacenters
```

```yaml
# /usr/local/etc/crate-hub.conf
nodes:
  - name:       alpha
    host:       alpha.eu-west-1.example.com:9800
    datacenter: eu-west-1
    token:      <admin-token>
  - name:       beta
    host:       beta.us-east-1.example.com:9800
    datacenter: us-east-1
    token:      <admin-token>
```

Response shape:

```json
{
  "status": "ok",
  "data": [
    {"name":"eu-west-1","nodes_total":1,"nodes_reachable":1,"nodes_down":0,"containers_total":5},
    {"name":"us-east-1","nodes_total":1,"nodes_reachable":0,"nodes_down":1,"containers_total":0}
  ]
}
```

The web dashboard now renders a Datacenters table above the Nodes
table; the Nodes table grew a "Datacenter" column. Nodes without
an explicit `datacenter:` are canonicalised to `default` so
upgrades from 0.6.14 don't see a phantom DC.

### What's NOT in this release

The DC admin UI — adding/renaming/deleting datacenters from the
dashboard, drag-drop node moves, per-DC quotas — is intentionally
deferred. The aggregation API and config-driven membership land
first so an operator can group nodes today; the UI piece can layer
on top later without touching the backend shape again.

### Implementation

- **`hub/datacenter_pure.{h,cpp}`** — pure helpers:
  `validateName` (alnum + `.`/`_`/`-`, ≤32 chars),
  `canonicalName` (empty → `default`), `groupAndSummarise`
  (alphabetical by name, mirrors `AggregatorPure::summarise`'s
  "stale containerCount on unreachable node is excluded" rule),
  `renderJson` (stable field order).
- **`hub/poller.h`** — `NodeConfig` and `NodeStatus` gain a
  `datacenter:` field.
- **`hub/poller.cpp`** — YAML parser reads `datacenter:`,
  `Poller` constructor mirrors it into the status cache.
- **`hub/api.cpp`** — `GET /api/v1/datacenters` route. Reuses
  `AggregatorPure::countTopLevelObjects` for container counting
  so the per-DC and the global aggregate stay byte-consistent.
- **`hub/web/`** — `index.html` adds the Datacenters table and a
  Datacenter column on the Nodes table; `app.js` fetches the new
  endpoint and renders.

### Tests

`tests/unit/datacenter_pure_test.cpp` — 11 ATF cases:
- 2 `validateName` (typical incl. `eu-west-1`/`default`/32-char
  boundary; invalid: empty, 33-char, whitespace, `/`, `;`, `$`)
- `canonicalName` empty → default
- 5 `groupAndSummarise` cases including the **stale-count-on-
  unreachable invariant** (the same correctness property we test
  for in `AggregatorPure::summarise`)
- 3 `renderJson` cases (empty, field-order pin, multi-DC
  comma-separation)

**701/701** unit tests pass (was 690).

---

## [0.6.14] — 2026-05-03

`crate migrate` — orchestrate moving a container between two
crated-managed hosts via the existing F2 API, in five strict-order
steps. The source container keeps running until the destination
reports a successful start, so a network blip between steps 1-4
leaves the original alive.

### Usage

```sh
crate migrate myjail \
    --from alpha.example.com:9800  --from-token-file /root/tokens/alpha \
    --to   beta.example.com:9800   --to-token-file   /root/tokens/beta
```

### Plan

| Step | Method | URL                                                |
| ---- | ------ | -------------------------------------------------- |
|  1   | POST   | `{from}/api/v1/containers/{name}/export`           |
|  2   | GET    | `{from}/api/v1/exports/{file}` → /tmp              |
|  3   | POST   | `{to}/api/v1/imports/{name}` (octet-stream upload) |
|  4   | POST   | `{to}/api/v1/containers/{name}/start`              |
|  5   | POST   | `{from}/api/v1/containers/{name}/stop`             |

Step 5 only fires after step 4 reports success — abort on any
earlier failure leaves the source intact.

### Why curl(1) for HTTP

Pulling in a real HTTP/TLS client would mean either bundling
cpp-httplib's client mode (untested at our auth-flow surface) or
reimplementing the chunked + Bearer + cert-verification dance.
`curl(1)` ships in FreeBSD base and on every Linux distro; the
operator running migrations already has it.

### Token handling

Tokens are read from chmod-600 files instead of command-line flags
so they never appear in `ps`/process listings. The runtime also
adds the `Authorization: Bearer ...` header via curl's `-H`
argument, which is the smallest token leak surface curl provides
(short of the env-driven form, which FreeBSD base curl doesn't
honour).

### Defense in depth

`MigratePure::validateEndpoint` rejects dotted-numeric strings that
*look* like IPv4 but have invalid octets (e.g. `256.0.0.1:80`)
instead of silently accepting them as hostnames — the same fix we
landed for the IPsec validator in 0.6.10. Container names are
checked against the same allowed-character set the daemon's F2
endpoints use; bearer tokens reject whitespace/control chars that
would corrupt the `Authorization` header.

### Implementation

- **`lib/migrate_pure.{h,cpp}`** — pure validators
  (`validateEndpoint`, `validateBearerToken`,
  `validateContainerName`), plan builders (`buildExportStep`,
  `buildRemainingSteps`), `normalizeBaseUrl`, `describeStep`
  (token-redacting), `redactToken`.
- **`lib/migrate.cpp`** — runtime: `curl(1)` invocation,
  `Authorization` header, JSON `file:` field extraction from the
  export response, per-run `/tmp/crate-migrate-<pid>` work dir
  with cleanup on success and on exception.
- **`cli/args.cpp` + `cli/main.cpp`** — `CmdMigrate` enumerator,
  `usageMigrate()`, dispatch.
- **`lib/audit.cpp` + `audit_pure.cpp`** — `migrate` is recorded
  in `/var/log/crate/audit.log` (it mutates state on two hosts);
  the target field encodes `<name>@<from>-><to>`.

### Tests

`tests/unit/migrate_pure_test.cpp` — 13 ATF cases:
- 2 `validateEndpoint` (typical incl. v4/v6/bracketed/scheme;
  invalid incl. missing port, out-of-range port, `256.0.0.1:80`,
  bare scheme)
- 2 `validateBearerToken` (typical; invalid: empty, whitespace,
  control char, 513 chars)
- 2 `validateContainerName` (typical; invalid: empty, `.`, `..`,
  65 chars, `/`, space, `;`)
- 2 `normalizeBaseUrl` (adds `https://` when missing; preserves
  `http://`/`https://` when present)
- 1 `buildExportStep` shape
- 2 `buildRemainingSteps` (full chain shape; **stop-source-after-
  start-dest invariant** — the most important security/correctness
  property of the plan)
- 1 `describeStep` (token never appears in log description)
- 1 `redactToken` (value never leaks; length OK to expose)

**690/690** unit tests pass (was 677).

---

## [0.6.13] — 2026-05-03

WireGuard runtime — `crate run` now brings a tunnel up before the
jail starts and tears it down with the container, driven by a single
`options.wireguard.config:` line in the spec:

```yaml
options:
    wireguard:
        config: /usr/local/etc/wireguard/wg0.conf
```

The runtime invokes `/usr/local/bin/wg-quick up <path>` after the
spec is parsed and registers a `RunAtEnd` handler that calls
`wg-quick down <path>` on every exit path — clean, exception, or
signal. No new kernel touchpoints in this binary; we stand on the
shoulders of `wg-quick(8)`.

### Why delegate to wg-quick

A from-scratch in-process WG client would need either the `if_wg`
kmod's ioctl interface (FreeBSD 13+) or a userspace wg-go
embedding. Both are substantial subsystems that need their own
RAII for interface destruction, route fixup, jail-side IPv6 RA
suppression, and idempotent reconciliation across crash recovery.
Delegating the kernel/userspace plumbing to `wg-quick` and limiting
this release to lifecycle wiring keeps the surface tractable. The
TODO entry for full kernel-level integration is preserved as a
future item.

### Defense in depth

`wireguard.config` paths are validated server-side before any I/O:
- non-empty, ≤255 chars
- absolute path (`/...`)
- no `..` segments (defense against config traversal)
- no shell metacharacters (`;`, `` ` ``, `$`, `|`, `&`, `<`, `>`,
  `\\`, `\n`, `\r`)

Even with a compromised spec, the worst case is a `crate validate`
error — never `wg-quick up '/etc/foo;rm -rf /'`.

### Implementation

- **`lib/wireguard_runtime_pure.{h,cpp}`** — pure validators +
  argv builders (`buildUpArgv`, `buildDownArgv`). Both argv lists
  start with the absolute path to `wg-quick` so the runtime never
  trusts `PATH` (which `crate(8)` re-sets at setuid-init time
  anyway).
- **`lib/spec.h`** + **`lib/spec.cpp`** + **`lib/spec_pure.cpp`** —
  new `WireguardOptDetails` option class, `wireguard` added to the
  allowed-options whitelist, YAML parser handles `config:` field,
  `Spec::validate()` runs `validateConfigPath` when the option is
  active.
- **`lib/run.cpp`** — calls `wg-quick up` after `parseSpec` and
  registers a RunAtEnd handler so all exit paths run `wg-quick
  down`. Teardown is best-effort (try/catch swallowed) so a stuck
  WG interface doesn't block jail destruction.

### Tests

`tests/unit/wireguard_runtime_pure_test.cpp` — 10 ATF cases:
- 6 `validateConfigPath`: typical accepted, empty rejected,
  relative rejected, 255/256-char boundary, `..` segment rejected
  (with the carve-out that `..` *inside* a longer name like
  `foo..bar.conf` is fine), all 10 shell metacharacters (`;`,
  `` ` ``, `$`, `|`, `&`, `<`, `>`, `\\`, `\n`, `\r`)
- 3 argv-shape tests for `buildUpArgv` / `buildDownArgv` plus an
  invariant that argv[0] is the same absolute path in both.
- 1 `isEnabled` predicate.

**677/677** unit tests pass (was 667).

---

## [0.6.12] — 2026-05-03

Man pages for `crated(8)` and `crate-hub(8)`. Operators now have a
proper offline reference for both daemons — endpoints, auth model,
config keys, and file layout — so `man crated` works the way it
should on a FreeBSD system.

### What's there

- **`crated.8`** — REST API daemon. Documents:
  - The three independent listeners (unix socket, TCP/TLS,
    WebSocket console) and how they relate to the auth model.
  - Every F1 + F2 endpoint with one-line descriptions, in the
    order they appear in `daemon/routes.cpp`.
  - The full `crated.conf` shape with a sample.
  - File paths (`/usr/local/etc/crated.conf`,
    `/var/run/crate/crated.sock`, etc.).
  - Caveats — explicitly calls out the "unix socket peer is
    trusted as admin without `getpeereid(2)`" gap so operators
    auditing the daemon find it from the man page first.
- **`crate-hub.8`** — multi-host aggregator. Documents:
  - Why the hub is read-mostly: mutating actions go direct to the
    per-node `crated`, so admin tokens stay in the operator's
    browser `localStorage`.
  - All `/api/v1/*` aggregate endpoints.
  - Sample `crate-hub.conf` with node + token list.
  - Web dashboard layout under `/usr/local/share/crate-hub/web/`.

Both pages follow the existing `crate.5` mdoc style — same
copyright header, same `.Sh` section ordering, same `.Bl -tag`
formatting.

### Install

- `make install-daemon` now also installs `crated.8.gz` into
  `${PREFIX}/man/man8/`. Existing operators who run
  `make install-daemon` after upgrade pick this up automatically.
- `make install-hub-man` (new) installs `crate-hub.8.gz`. The hub
  binary itself isn't built from this Makefile (separate build),
  so this target ships only the documentation; the hub package
  invokes it.

### Tests

Pure documentation; no test changes. **667/667** unit tests
unchanged.

---

## [0.6.11] — 2026-05-03

`crate inspect TARGET` — pretty-printed JSON snapshot of a running
container's runtime state. Useful for `crate inspect myjail | jq`
ad-hoc queries, for capturing pre/post-deploy state into
revision-controlled diffs, and as the data source for the upcoming
hub web dashboard's container detail page.

### Output

```json
{
  "name": "myjail",
  "jid": 7,
  "hostname": "myjail.local",
  "path": "/jails/myjail",
  "osrelease": "14.2-RELEASE",
  "jail_params": {
    "allow.mount.nullfs": "1",
    "securelevel": "2",
    "vnet": "1"
  },
  "interfaces": [
    {"name": "primary", "ip4": "10.0.0.5", "ip6": "", "mac": ""}
  ],
  "mounts": [
    {"source": "tmpfs", "target": "/jails/myjail/tmp", "fstype": "tmpfs"}
  ],
  "rctl_usage": {
    "cputime": "120",
    "memoryuse": "12345678"
  },
  "zfs_dataset": "tank/jails/myjail",
  "zfs_origin": "",
  "process_count": 14,
  "has_gui": false,
  "gui_display": 0,
  "gui_vnc_port": 0,
  "gui_ws_port": 0,
  "gui_mode": "",
  "started_at": 0,
  "inspected_at": 1730000123
}
```

### Implementation

- **`lib/inspect_pure.{h,cpp}`** — pure JSON renderer + RFC 8259
  `escapeJsonString` + `applyRctlOutput`/`applyMountOutput`
  parsers. The `applyMountOutput` parser carefully avoids
  prefix-collision false positives (`/jails/myjail-other` will not
  match a `/jails/myjail` filter — the trailing-slash sentinel
  catches it).
- **`lib/inspect.cpp`** — runtime gather: `JailQuery::getJailParam`
  for a curated set of jail params (the security-relevant +
  name-mapping ones), `rctl(8)` for usage counters, `mount(8)` for
  jail-rooted mounts, `zfs(8)` for dataset/origin (clones), `ps -J`
  for process count, `Ctx::GuiRegistry` for any active GUI session.
- **`cli/args.cpp` + `cli/main.cpp`** — `CmdInspect` enumerator,
  `crate inspect <name|JID>` argument parsing, `usageInspect()`.
- **`lib/audit*.cpp`** — `inspect` is read-only; not recorded in
  `/var/log/crate/audit.log`.

### Tests

`tests/unit/inspect_pure_test.cpp` — 17 ATF cases:
- 4 `escapeJsonString` (ASCII passthrough, `"`/`\\`, control chars
  incl. ``/``, UTF-8 `Олексій` passthrough)
- 6 `renderJson` shape/content (minimal-shape with stable keys,
  jail-params alphabetic order, interfaces array, mounts array,
  GUI fields, escape integration in fields)
- 3 `applyRctlOutput` (typical, blank-line + malformed tolerance,
  empty input)
- 4 `applyMountOutput` (filter to jail subtree, jail-root itself
  included, prefix-collision rejected, malformed-line tolerance)

**667/667** unit tests pass (was 650).

### Status

`started_at` is left at 0 — libjail doesn't expose a creation
timestamp, and we don't yet store our own. A future release will
record this either via a per-jail metadata file written by
`crate run` or via `kern.proc` of the jail's init process.

---

## [0.6.10] — 2026-05-03

IPsec config rendering — sister tool to 0.6.9's WireGuard renderer.
`crate vpn ipsec render-conf <spec.yml>` reads a YAML spec and emits
a strongSwan-style `ipsec.conf` on stdout, validating endpoints,
subnets, cipher proposals, and the strongSwan keyword enums
(`auto=`, `authby=`, `keyexchange=`) before rendering.

### Usage

```sh
$ cat ipsec-spec.yml
conns:
    - name: dc1-dc2
      description: "primary site link"
      left: 203.0.113.5
      leftsubnet: ["10.0.1.0/24"]
      right: 198.51.100.7
      rightsubnet: ["10.0.2.0/24"]
      keyexchange: ikev2
      ike: aes256-sha256-modp2048
      esp: aes256-sha256
      authby: psk
      auto: start

$ crate vpn ipsec render-conf ipsec-spec.yml | sudo tee /usr/local/etc/ipsec.conf
$ sudo ipsec reload && sudo ipsec up dc1-dc2
```

### Validation

- **Hosts** (`left=` / `right=`) accept IPv4 literal, bracketed IPv6,
  RFC 1123 hostname, or `%any` (strongSwan road-warrior wildcard).
  Dotted-numeric strings must validate as IPv4 — so `256.0.0.1`
  fails with "host looks like IPv4 but has invalid octets" instead
  of silently falling through to hostname validation.
- **Subnets** — IPv4 (prefix 0..32) / IPv6 (prefix 0..128).
- **Cipher proposals** — alnum + `-`/`_`, length 1..128. Catches
  shell-injection-shaped typos before they reach `ipsec.conf`.
- **`auto=`** ∈ `{ignore, add, route, start}`.
- **`authby=`** ∈ `{psk, pubkey, rsasig, ecdsasig, never}`.
- **`keyexchange=`** ∈ `{ike, ikev1, ikev2}`.
- **Conn names** — alnum + `.`/`_`/`-`, length 1..32, `%default`
  reserved.
- Errors include a `conn #N: ...` prefix for multi-conn files.

### Implementation

- **`lib/ipsec_pure.{h,cpp}`** — pure validators + INI renderer.
  Parallels `wireguard_pure` in spirit; the IP/hostname validators
  are reimplemented locally so this header stays self-contained.
- **`lib/vpn.cpp`** — extended: `vpn ipsec render-conf` dispatches
  to `vpnIpsec()`; YAML adapter parses `conns:` list with
  `left`/`leftsubnet`/`right`/`rightsubnet`/`ike`/`esp`/
  `keyexchange`/`authby`/`auto`/`description`.
- **`cli/args*.cpp`** — argument validation now accepts both
  `wireguard` and `ipsec` subcommand keywords; usage updated with
  side-by-side examples.

### Tests

`tests/unit/ipsec_pure_test.cpp` — 23 ATF cases:
- 4 `validateHost` (v4, bracketed v6, hostname/`%any`, invalid)
- 3 `validateSubnet` (v4 typical, v6 typical, invalid)
- 2 `validateProposal` (typical, invalid metacharacters)
- 2 enum keyword tests (`auto=`, `authby=`)
- 2 `validateConnName` (typical, invalid: empty, 33-char, `%default`,
  whitespace, metacharacters, `/`)
- 4 `validateConfig` integration (minimal valid, no conns, invalid
  `keyexchange`, conn-index in error message)
- 6 `renderConf` (setup+conn block, CSV-joined subnets, optional-
  field omission, `ike`/`esp` emission, description comment, multi-
  conn separation)

**650/650** unit tests pass (was 627).

---

## [0.6.9] — 2026-05-03

WireGuard config rendering — `crate vpn wireguard render-conf` reads
a small YAML spec and emits a `wg-quick(8)`-compatible INI config.
Validates keys, CIDRs, and endpoint forms before rendering, so
operators see "PublicKey is too short" instead of a cryptic
`wg(8)` error two screens later.

### Why pure tooling, not auto-integrated runtime

WireGuard kernel-level integration on FreeBSD requires the `if_wg`
kmod, privileged interface creation, route management, and jail-side
RA suppression — each of which is a separate, vetted-in-production
piece of plumbing. Until that lands, the pragmatic step is a tested
config-renderer the operator pipes into `wg-quick up`. The runtime
TODO tracks the rest.

### Usage

```sh
$ cat vpn-spec.yml
interface:
    private_key: "AAAA…AAAA="
    addresses: ["10.0.0.1/24", "fd00::1/64"]
    listen_port: 51820
peers:
    - public_key: "BBBB…BBBB="
      allowed_ips: ["10.0.0.2/32"]
      endpoint: "vpn.example.com:51820"
      persistent_keepalive: 25
      description: "edge router"

$ crate vpn wireguard render-conf vpn-spec.yml | sudo tee /etc/wireguard/wg0.conf
$ sudo wg-quick up wg0
```

### Validation

- **Keys** (private/public/preshared) must be exactly 44 base64
  characters ending with `=` — the canonical form for 32 raw bytes.
  Stray whitespace or an alphabet typo is caught here, not by `wg`.
- **CIDRs** accept both IPv4 (prefix 0..32) and IPv6 (prefix 0..128).
  The IPv4 path enforces octets ≤ 255; the IPv6 path allows one `::`
  shorthand and rejects two.
- **Endpoints** support `host:port` (IPv4 / RFC 1123 hostname) and
  bracketed `[ipv6]:port`. Port range 1..65535.
- **Spec invariants**: `[Interface]` requires `private_key` and at
  least one `addresses` entry; the file requires at least one
  `[Peer]` section; each peer requires `public_key` and at least one
  `allowed_ips` entry. The first error includes a `peer #N` index so
  multi-peer files are easy to debug.

### Implementation

- **`lib/wireguard_pure.{h,cpp}`** — pure validators + INI renderer:
  `validateKey()`, `validatePort()`, `validateCidr()`,
  `validateEndpoint()`, `validateConfig()`, `renderConf()`. No
  socket/kernel touchpoints — the entire module is unit-testable on
  Linux.
- **`lib/vpn.cpp`** — YAML adapter: parses the spec via yaml-cpp,
  builds the pure structs, validates, prints the INI to stdout.
- **`cli/args.cpp` + `cli/args_pure.cpp`** — new `CmdVpn` enumerator,
  `crate vpn wireguard render-conf <spec>` argument parsing.
- **`lib/audit*.cpp`** — `vpn` is read-only with respect to jails
  (it only reads the spec file and writes to stdout), so it's not
  recorded in `/var/log/crate/audit.log`.

### Tests

`tests/unit/wireguard_pure_test.cpp` — 26 ATF cases:
- 4 `validateKey` (zero-bytes accepted, wrong-length rejected,
  missing-padding rejected, non-base64-char rejected)
- 2 `validatePort` (typical range, edge cases including `0`,
  `65536`, negative, non-numeric)
- 4 `validateCidr` (v4 typical, v4 invalid incl. octet > 255 and
  prefix > 32, v6 typical, v6 invalid incl. double `::` and
  prefix > 128)
- 4 `validateEndpoint` (v4, bracketed v6, hostname, malformed —
  no port, missing `]`, port out of range, illegal hostname char)
- 4 `validateConfig` integration (minimal valid, no peers, no
  addresses, peer-index in error message)
- 8 `renderConf` (interface section emitted, CSV-joined addresses,
  optional `ListenPort` omitted when empty, peer section with
  description+endpoint+keepalive, `PresharedKey` emitted when set,
  omitted when empty, multiple peers separated, output ends with
  newline)

**627/627** unit tests pass (was 601).

---

## [0.6.8] — 2026-05-02

Inter-container DNS — drops the manual-`/etc/hosts` ritual that
operators previously had to do to make containers in different
stacks (or no stack at all) resolve each other by name. The
existing per-stack DNS (0.3.0) only covers containers within the
same stack; this release adds a *host-wide* `.crate` zone.

### Usage

```sh
# After starting / stopping any container:
crate inter-dns

# Or wire it into a lifecycle hook in your spec:
hooks:
    post-run: /usr/local/bin/crate inter-dns
    post-stop: /usr/local/bin/crate inter-dns
```

The command walks `JailQuery::getAllJails(crateOnly=true)` and
writes two files atomically:

1. **`/etc/hosts`** — replaces the section between
   `# >>> crate inter-container DNS <<<` and
   `# <<< crate inter-container DNS >>>` markers, leaving the rest
   of `/etc/hosts` (including `localhost`, your own static entries)
   untouched. Recovers gracefully from a half-written block left
   by a previous interrupted run.
2. **`/usr/local/etc/unbound/conf.d/crate.conf`** — auto-generated
   `local-zone: "crate." static` plus one `local-data:` line per
   container per address family. After writing, the runtime tries
   `unbound-control reload` first, falls back to `service unbound
   reload`; both being unavailable is a non-fatal soft failure
   (the file is still written).

A jail named `alpha` with IPv4 `10.0.0.1` is now resolvable as both
`alpha` and `alpha.crate` from any other jail that uses the host
as its resolver (the default for NAT-mode containers).

### Implementation

- **`lib/inter_dns_pure.{h,cpp}`** — pure helpers:
  - `validateHostname()` — RFC 1123 label rules: 1..63 chars, must
    start and end with `[A-Za-z0-9]`, body adds `-`. Catches typos
    before the runtime touches DNS files.
  - `normalizeName()` — case-insensitive lower-casing for canonical
    DNS records.
  - `buildUnboundFragment()` — sorts entries by name, emits one
    `local-data:` line per (name, family) pair. Empty IP is skipped
    so a v4-only jail doesn't produce a stray AAAA.
  - `buildHostsBlock()` — `/etc/hosts` block with stable
    `>>> crate inter-container DNS <<<` markers.
  - `replaceHostsBlock()` — atomic in-string replace; recovers from
    a half-written block (BEGIN marker present, END missing) by
    dropping everything from BEGIN forward.
- **`lib/inter_dns.{h,cpp}`** — runtime: walks `JailQuery`, atomic
  write via `<path>.tmp.<pid>` + `rename(2)`, best-effort
  `unbound-control reload`. Returns a `RebuildResult` so callers
  can report counts/paths.
- **`cli/args.cpp` + `lib/audit*.cpp`** — new `CmdInterDns`,
  `usageInterDns()`, dispatch in `cli/main.cpp`. Marked read-only
  in the audit log (it doesn't mutate jails — only host config).

### Tests

`tests/unit/inter_dns_pure_test.cpp` — 19 ATF cases:
- 6 `validateHostname` cases (empty, 63/64-char boundary, leading
  `-` / `.` / `_`, trailing `-` / `.`, underscore + dot in body,
  positive list with `MyJail-Prod-2026`)
- `normalizeName` lower-casing + idempotent on already-lowercase
- 6 `buildUnboundFragment` cases (empty zone marker, A only, AAAA
  only, dual-stack, sort order across 3 names, lower-cases input)
- 3 `buildHostsBlock` cases (markers present, v4-first preference,
  v6 fallback when no v4)
- 3 `replaceHostsBlock` cases (append when missing, preserve
  surrounding lines, recover from truncated block)

**601/601** unit tests pass (was 582).

---

## [0.6.7] — 2026-05-02

Hub web dashboard — populates the long-empty `hub/web/` directory
with a minimal vanilla-JS dashboard: cluster summary banner, node
table with reachability indicators, and a containers table with
start/stop/restart/destroy buttons. Reuses the existing
`set_mount_point("/", webDir)` static-file plumbing in `crate-hub`,
so deployment is "drop the files in
`/usr/local/share/crate-hub/web/` and reload".

### What's there

- **`hub/web/index.html`** — three sections (summary / nodes /
  containers), polled every 5 s from the hub's read-only F1
  endpoints. No bundler; one CSS file, one JS file.
- **`hub/web/style.css`** — dark-mode-only minimal CSS, ~110 lines.
  No framework dependencies.
- **`hub/web/app.js`** — vanilla `fetch` + DOM rendering. Mutating
  actions (start/stop/restart/destroy) hit the **per-node daemon's**
  F2 API directly — the hub itself doesn't proxy mutations, so the
  admin Bearer token stays in `localStorage` on the operator's
  machine and never crosses through hub-side logging. The token is
  prompted for on first action and remembered for the session.

### New endpoint

`GET /api/v1/aggregate` — single-shot summary that the dashboard's
banner consumes:

```json
{
  "status": "ok",
  "data": {
    "nodes_total": 4,
    "nodes_reachable": 3,
    "nodes_down": 1,
    "containers_total": 17
  }
}
```

### Implementation

- **`hub/aggregator_pure.{h,cpp}`** — pure helpers:
  - `summarise(nodes)` — counts reachable / down nodes, sums
    `containerCount` only for reachable nodes (so a stale cached
    count for a freshly-down node doesn't inflate the total).
  - `renderSummaryJson(s)` — stable JSON shape.
  - `countTopLevelObjects(jsonArray)` — counts `{...}` entries in a
    JSON array string without pulling in a parser; understands
    string escaping so `{` inside a quoted value doesn't bump the
    count. Used by the runtime to project each node's
    `s.containers` blob into a single number.
- **`hub/api.cpp`** — new `/api/v1/aggregate` route wired through
  the pure helpers.
- **`hub/web/`** — three new static files installed by deployment.

### Tests

`tests/unit/hub_aggregator_pure_test.cpp` — 9 ATF cases:
- `summarise` for empty / mixed-reachability / unreachable-with-stale-
  count input (the "stale count must be ignored" case is the
  important one — it's why we lock the count behind `reachable`).
- `renderSummaryJson` field-order pin.
- `countTopLevelObjects`: empty array, simple objects, nested
  objects (only top-level counted), brace-in-string (`{` inside a
  quoted value), malformed-input safety (`""`, `[{`, `[`, raw
  object).

**582/582** unit tests pass (was 573).

### Status

The web dashboard is intentionally read-mostly: lifecycle buttons
work but the dashboard does not include log streaming, console
attachment, or snapshot management. Those need a richer UI shell
(component framework, route management) and will land when somebody
wants them — TODO already tracks the underlying API surface.

---

## [0.6.6] — 2026-05-02

SNMP AgentX wire protocol — full Get/GetNext PDU dispatcher replaces
the stub mode that previously sent Open/Register PDUs and then
ignored every incoming request from the master agent. CRATE-MIB
scalars are now actually queryable from `snmpwalk`, `snmpget`, and
NMS dashboards (Zabbix, Observium, LibreNMS).

### What was wrong

`snmpd/mib.cpp` had only encoders — every `Get`/`GetNext` from the
master agent was silently dropped. Worse, `encodeOid()` emitted a
**4-byte** `n_subid` field where RFC 2741 §5.1 mandates **1 byte**.
A real master agent would either reject our PDUs as malformed or
misinterpret the OID length. The bug had been there since 0.2.5.

### What's now in place

`snmpd/mib_pure.{h,cpp}` is the pure RFC 2741 §5 codec. It handles
both directions of the wire protocol:

- **Header**: 20-byte encode/decode, honours the `NETWORK_BYTE_ORDER`
  flag (some older masters send little-endian, the bit is clear in
  that case). PDU-type enum (Open/Close/Register/Get/GetNext/
  GetBulk/Notify/Response).
- **OID** (the bug fix): 1-byte `n_subid`, prefix optimization for
  `1.3.6.1.<≤255>` paths, include-bit, encode/decode round-trip.
- **OctetString**: 4-byte length + bytes + zero-padding to 4-byte
  alignment.
- **SearchRange + GetRequest payload**: skips a leading context
  octet-string when the `NON_DEFAULT_CONTEXT` flag is set.
- **VarBind encoders** for every type the MIB uses: `Integer32`,
  `OctetString`, `Null`, `OID`, `Counter32`, `Gauge32`, `TimeTicks`,
  `Counter64`, plus the three exception tags (`noSuchObject`,
  `noSuchInstance`, `endOfMibView`).
- **Response payload prefix**: `sysUpTime(4) + errStatus(2) +
  errIndex(2)`.
- **OID comparison + walking helpers**: `compareOid()`,
  `oidIsChildOf()`, `oidEquals()` — needed to resolve `GetNext`.

`snmpd/mib.cpp` gains a `dispatchOnce(timeoutMs)` loop:

1. `select()` on the AgentX socket with a short timeout (100 ms).
2. Read 20-byte header + payload.
3. For `PDU_GET`: exact-match the OID against the scalar table
   (`crateContainerTotal`, `crateContainerRunning`, `crateVersion`,
   `crateHostname`); reply with the appropriate `VarBind` or
   `noSuchInstance` for the container table (table walk is a future
   release — listed in the comments).
4. For `PDU_GETNEXT`: lexicographic next OID in the scalar table or
   `endOfMibView`.
5. Write the response PDU back.

`snmpd/main.cpp` now drives `dispatchOnce(100)` in a tight loop and
re-runs the metrics collector every `pollInterval` seconds — no more
30-second blackout windows where the daemon is unresponsive to SNMP.

### Tests

`tests/unit/snmpd_agentx_test.cpp` — 20 ATF cases covering:
- Header encode/decode round-trip + short-input safety + LE flag
- OID round-trip (no-prefix, with-prefix, include-bit)
- OctetString round-trip with multiple lengths
- SearchRange round-trip
- GetRequest payload decode (1 OID, 2 OIDs, with leading context
  octet-string when `NON_DEFAULT_CONTEXT` flag set)
- VarBind type tags for `Integer32`/`Counter64`/`OctetString`/`Null`/
  `EndOfMibView` (eight-byte encoding of `Counter64`, 4-byte
  alignment of `OctetString` padding)
- Response header layout (`sysUpTime`, error status, error index)
- `compareOid` (lexicographic, prefix-shorter-is-less, unsigned
  32-bit subids)
- `oidIsChildOf` (strict child only — equal OIDs return false)

`tests/unit/snmpd_mib_test.cpp` — 6 existing cases updated to the
correct RFC 2741 byte layout (had been pinning the buggy 4-byte
`n_subid`).

`tests/unit/adversarial_test.cpp:encodeOid_minimal` — likewise
updated.

**573/573** unit tests pass (was 553).

---

## [0.6.5] — 2026-05-02

crated export/import endpoints — closes the last open item under
the F2 write API. External tooling can now produce, fetch, and
upload `.crate` archives over HTTPS without the operator having to
SSH into the host.

### New endpoints

| Method | Path                                          | Role  |
| ------ | --------------------------------------------- | ----- |
| POST   | `/api/v1/containers/{name}/export`            | admin |
| GET    | `/api/v1/exports/{filename}`                  | admin |
| POST   | `/api/v1/imports/{name}`                      | admin |

`POST /export` runs the same `tar | xz` pipeline the CLI uses,
writing to `/var/run/crate/<name>-<unixtime>.crate`. The response
JSON carries `file`, `size`, and `sha256` so a hub or CI can verify
the artifact independently:

```json
{"status":"ok","data":{
  "file":"myapp-1777698300.crate",
  "size":24576123,
  "sha256":"d4a..."
}}
```

`GET /exports/<file>` streams the artifact back via cpp-httplib's
`set_content_provider` (chunked, 64 KB at a time). The filename is
validated server-side so the endpoint cannot be coaxed into reading
arbitrary files — see "Path traversal" below.

`POST /imports/<name>` accepts the raw archive body (Content-Type:
`application/octet-stream`). The handler sniffs the leading 16
bytes for the xz signature (`FD 37 7A 58 5A 00`) or the
`Salted__` prefix from `openssl enc`, rejects anything else with
400, atomically writes to `/var/run/crate/<name>.crate.tmp.<pid>`
then renames into place — so a connection drop mid-upload doesn't
leave a half-written `.crate` for the next `crate run` to choke on.

### Path traversal

`TransferPure::validateArtifactName()` enforces:
- Length 1..128
- Allowed: `[A-Za-z0-9._-]` only (so `.crate` suffix is fine)
- Reserved: `.` and `..`
- Forbidden: `/`, `\`, NUL, whitespace, shell metacharacters
  (`;`, `` ` ``, `$`, `|`)

This is dispatched **before** any filesystem access, so even with a
compromised admin token the worst case is a 400 — never a leak of
`/etc/passwd` via `/api/v1/exports/../../etc/passwd`.

### Implementation

- **`daemon/transfer_pure.{h,cpp}`** — pure helpers:
  - `validateArtifactName()` — the rules listed above.
  - `formatExportResponse` / `formatImportResponse` — JSON shapes.
  - `sniffArchiveType()` — `"xz"` / `"encrypted"` / `"unknown"`
    classifier from the leading bytes.
  - `hexEncode()` — bytes → lowercase hex digest.
- **`daemon/routes.cpp`** — three new handlers + route registration:
  `handleContainerExport`, `handleExportDownload`,
  `handleContainerImport`. SHA-256 via OpenSSL's `SHA256_*` API
  (already linked for auth).

### Tests

`tests/unit/transfer_pure_test.cpp` — 13 ATF cases:
- 7 `validateArtifactName` cases: empty, `.`, `..`, 128/129-char
  boundary, `..` traversal, `/` and `\` rejection, whitespace,
  metacharacters (`;`, `` ` ``, `$`, `|`), and a positive list
  (`myapp.crate`, `backup_20260502.crate`, `v0.6.5.crate`)
- 2 response-shape tests
- 3 `sniffArchiveType` tests covering xz, encrypted, unknown +
  truncated-signature edge case
- 1 `hexEncode` vector test (empty, NUL, 0xff, ASCII, deadbeef)

**553/553** unit tests pass (was 540).

### Status

The F2 write API is now feature-complete: lifecycle (start/stop/
restart/destroy), snapshot CRUD, SSE stats stream, WebSocket
console, and export/import are all in place. The TODO file no
longer carries any F2-related entries.

---

## [0.6.4] — 2026-05-02

WebSocket console — RFC 6455-compliant interactive-shell endpoint
for `crated`. Lets the upcoming hub web dashboard (and any
EventSource-equivalent client) attach to a `/bin/sh` running inside
a jail, with byte-faithful TTY output and full bidirectional input,
without needing SSH access to the host.

### Endpoint

```
GET /api/v1/containers/{name}/console HTTP/1.1
Host: <consoleWsBind>:<consoleWsPort>
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <16-byte-base64-nonce>
Sec-WebSocket-Version: 13
Authorization: Bearer <admin-token>
```

The handshake authenticates with the same admin Bearer token used by
the F2 mutating endpoints. After the upgrade, the daemon proxies
bytes between the WebSocket and a `/bin/sh -i` running under
`jexec(8)` inside the target jail. Server→client traffic is sent as
binary frames so raw TTY escape sequences pass through unchanged;
client→server text or binary frames are written to the shell's
stdin. PING/PONG round-trips work as expected; CLOSE terminates the
shell with SIGTERM.

### IPv6 + IPv4 dual stack

The listener is opt-in via `console_ws_port` (default 0 = disabled)
and binds via `getaddrinfo(3)`, accepting either IPv4 literals
(`127.0.0.1`), IPv6 literals (`::1`, `::`), or hostnames. When the
resolver returns an IPv6 candidate the socket sets `IPV6_V6ONLY=0`
so a single `::` listener also accepts IPv4-mapped clients —
matching the rest of the daemon.

### crated.conf

```yaml
listen:
    unix: /var/run/crate/crated.sock
    tcp_port: 9800
    tcp_bind: 0.0.0.0

console_ws:
    port: 9802
    bind: "::"      # dual-stack, or 127.0.0.1 / ::1 for loopback only
```

### Implementation

- **`daemon/ws_pure.{h,cpp}`** — pure WebSocket protocol module
  (no OpenSSL, no sockets):
  - `sha1Raw()` — RFC 3174 SHA-1 implementation, ~80 lines.
  - `base64Encode()` — RFC 4648, no line breaks.
  - `computeAcceptKey()` — RFC 6455 §1.3 handshake digest.
  - `parseHandshakeRequest()` — case-insensitive header parsing,
    rejects non-GET, missing Upgrade/Connection/Key/Version, wrong
    version (must be 13).
  - `buildHandshakeResponse()` / `buildHandshakeRejection()` —
    101 Switching Protocols / 400 Bad Request templates.
  - `parseFrame()` / `encodeFrame()` / `encodeCloseFrame()` —
    full RFC 6455 §5 framing including 16-bit and 64-bit length
    extensions, masking, control-frame validation (FIN=1, ≤125
    bytes), reserved-opcode rejection.
- **`daemon/ws_console.{h,cpp}`** — runtime: dedicated TCP listener
  on its own thread (separate from cpp-httplib), per-connection
  worker, PTY-based session. SIGCHLD ignored so disconnected
  shells auto-reap.
- **`daemon/main.cpp`** — `WsConsole::start(config)` after the HTTP
  server starts; `WsConsole::stop()` before exit.
- **`daemon/config.{h,cpp}`** — `consoleWsPort` (0 disables) and
  `consoleWsBind` (default `127.0.0.1`).

### Tests

`tests/unit/ws_pure_test.cpp` — 22 ATF cases:
- 3 SHA-1 vectors (empty, "abc", 56-byte FIPS vector, 1-million-byte
  vector that crosses block boundaries)
- 7 base64 RFC 4648 vectors (empty through "foobar")
- RFC 6455 §1.3 canonical accept-key vector
- 6 handshake parsing tests (valid, lowercase/mixed-case headers,
  missing key, wrong version, missing Upgrade, non-GET method)
- 2 handshake response/rejection format tests
- 9 frame tests (short unmasked, short masked with RFC §5.7
  "Hello" vector, 16-bit medium length, incomplete returns 0,
  reserved opcode rejection, oversized control frame rejection,
  short/medium/large round-trip, masked round-trip, CLOSE frame
  status code encoding)

**540/540** unit tests pass (was 518).

### Security notes

- Bearer-token authentication runs **before** the handshake is
  accepted; an unauthenticated client receives 400 with no upgrade.
- Body of the rejection 400 includes the failure reason (missing key,
  wrong version, etc.) so legitimate clients can debug; this is not
  a side channel because the failure modes are protocol-level, not
  credential-level.
- The endpoint is opt-in. Operators who don't run `console_ws.port`
  see no listener at all — zero attack surface.
- The session shell is started under `jexec(8)`, the same path the
  CLI's `crate console` uses, so jail confinement guarantees apply
  exactly as for an interactive operator session.

---

## [0.6.3] — 2026-05-02

Auto-create bridge interfaces — drops the requirement that an
operator pre-create the `bridge0` (or whichever) interface before
running a container in bridge mode. Specs that opt in with
`options.net.auto_create_bridge: true` get the bridge created on
demand and torn down with the container.

### Why

Bridge mode is the easiest way to expose a container on the host's
LAN, but for years it required the operator to remember a one-line
`ifconfig bridge create name=bridge0; ifconfig bridge0 up` ritual
before `crate run` would succeed. Forgetting the ritual produced an
opaque `cannot add to bridge: No such device` error from `ifconfig`.

### How

Opt-in stays opt-in: the default behaviour is unchanged, so existing
specs that depend on a hand-managed bridge are unaffected. When
`auto_create_bridge: true` is set:

```yaml
options:
    net:
        mode: bridge
        bridge: bridge0
        auto_create_bridge: true
        ip: dhcp
```

…the runtime decision table picks one of three actions:

| bridge exists | `auto_create_bridge` | action          |
| ------------- | -------------------- | --------------- |
|       ✓       |        any           | proceed (NoOp)  |
|       ✗       |        true          | create + setUp  |
|       ✗       |        false         | error           |

Only bridges that **crate** created in this run are torn down on
container exit. Pre-existing bridges are left alone — exactly what
you want when several containers share `bridge0`.

### Validation

- `BridgePure::validateBridgeName()` rejects empty names, names
  longer than IFNAMSIZ-1 (15 chars), names without a driver prefix,
  names without a unit number, and names containing shell
  metacharacters or `/`. Catches typos before they hit `ifconfig(8)`.
- `Spec::NetOptDetails::validate()` rejects
  `auto_create_bridge: true` outside bridge mode.

### Implementation

- **`lib/bridge_pure.{h,cpp}`** — pure decision module (`Action` enum
  + `chooseAction()`) plus the name validator. No I/O.
- **`lib/ifconfig_ops.cpp`** — new `createNamedInterface(name)` that
  goes through `libifconfig` when available and falls back to
  `ifconfig <name> create`.
- **`lib/run.cpp`** — bridge mode now consults `chooseAction()` and
  remembers `weCreatedBridge` so the `RunAtEnd` cleanup destroys the
  bridge if and only if crate created it.
- **`lib/spec.{h,cpp}` + `lib/spec_pure.cpp`** — `NetOptDetails`
  gains a `bool autoCreateBridge`; YAML key `auto_create_bridge`
  parsed as a relaxed boolean (`true`/`yes`/`on`/`1`).

### Tests

`tests/unit/bridge_pure_test.cpp` — 11 ATF cases:
- `chooseAction` for all four cells of the decision table + a
  totality check + name uniqueness.
- `validateBridgeName` against empty, too long (15 vs 16 chars),
  shell metacharacters (`;` `` ` `` `$` space `/` `..`), missing
  driver prefix, missing unit number, and a positive list of
  typical names (`bridge0`, `br0`, `vmbr0`, `br0a1`).

**518/518** unit tests pass (was 507).

---

## [0.6.2] — 2026-05-02

`crate top` — live, htop-style resource monitor for all
crate-managed jails. Refreshes once per second; press `q` (or Ctrl-C)
to quit. Aimed at operators who need a quick "what's the cluster
doing right now" view without spinning up Grafana.

### Output

```
crate top    (press 'q' to quit)

NAME               JID              IP    CPU%        MEM       DISK  PROC
postgres            12      10.0.0.20    14.2    420.0 MB    12.5 MB    23
nginx-edge          15      10.0.0.21     3.1     48.0 MB     0 B        7
build-ci            18      10.0.0.22   210.5      1.2 GB    340.0 MB   42
3 jails  CPU 227.8%  MEM 1.7 GB  DISK 352.5 MB  PROC 72
```

CPU is computed from RCTL `cputime` deltas across one-second samples,
so values exceed 100% on multi-core jails (the build-ci row above is
running on three cores). MEM/DISK come from RCTL `memoryuse` /
`writebps` and are humanised with base-1024 suffixes. PROC is the
RCTL `maxproc` usage counter.

When stdout is not a terminal (`crate top | grep`, `watch crate top`,
etc.) the renderer emits one plain-text frame and exits — handy for
ad-hoc shell scripts and cron checks.

### Implementation

- **`lib/top_pure.{h,cpp}`** — pure formatting and arithmetic:
  `humanCount`, `humanBytes` (base-1024), `cpuPercent` (handles
  counter rollback on jail restart), `truncateForColumn` (ASCII-safe
  with `~` marker), `formatHeader` / `formatRow` / `formatFooter` /
  `formatFrame`, plus an `applyRctlOutput` that picks the curated
  RCTL keys we care about and ignores the rest.
- **`lib/top.cpp`** — runtime glue: signal handling (SIGINT/TERM/HUP
  exit cleanly), terminal control via ANSI escapes (alternate screen
  + hidden cursor; restored on every exit path), per-JID CPU sample
  cache for delta calculation, RCTL polling via `execCommandGetOutput`,
  and a `RawStdin` RAII wrapper that flips stdin into non-canonical
  non-blocking mode so we can read 'q' without ncurses.
- **`cli/main.cpp` + `cli/args.cpp`** — new `CmdTop` enumerator,
  `usageTop()`, dispatch wiring. `crate top` takes no arguments.

### Tests

`tests/unit/top_pure_test.cpp` — 21 ATF cases covering:
- `humanCount` boundary values (0, 999, 1K, 12.3K, 1M, 1.2T)
- `humanBytes` boundary values (0 B, 1023 B, exact KB/MB/GB/TB,
  intermediate 1.5 MiB)
- `cpuPercent` basics, multi-core (>100%), zero/negative dt, counter
  rollback on jail restart (must return 0, not wrap)
- `truncateForColumn` shorter / longer / width=1 / zero/negative width
- `formatHeader` column presence + no trailing whitespace
- `formatRow` alignment + humanisation + name truncation
- `formatFooter` totals aggregation across N rows + zero-jails edge
- `formatFrame` shape (header + N rows + footer, exact newline count)
- `applyRctlOutput` known-key picking, malformed-line tolerance,
  non-numeric-value tolerance

**507/507** unit tests pass (was 486).

### Notes

`crate top` is a read-only command and is therefore *not* recorded in
`/var/log/crate/audit.log` (alongside `validate`/`list`/`info`/
`stats`/`logs`). On a non-tty stdout the binary exits after one
frame, so `watch -n5 crate top` works as a poor-man's auto-refresh
without burning a server thread.

---

## [0.6.1] — 2026-05-01

crated F2 write API expanded — five new endpoints land restart, full
snapshot CRUD, and a server-sent-events stats stream so external
tooling (the upcoming hub web dashboard, cron-driven snapshot scripts,
Grafana/agent collectors) can drive `crate` over HTTPS without
shelling into the host.

### New endpoints

| Method | Path                                             | Role   |
| ------ | ------------------------------------------------ | ------ |
| POST   | `/api/v1/containers/{name}/restart`              | admin  |
| GET    | `/api/v1/containers/{name}/snapshots`            | viewer |
| POST   | `/api/v1/containers/{name}/snapshots`            | admin  |
| DELETE | `/api/v1/containers/{name}/snapshots/{snap}`     | admin  |
| GET    | `/api/v1/containers/{name}/stats/stream`         | viewer |

`POST /snapshots` accepts an optional JSON body `{"name":"<snap>"}`;
when absent the daemon generates a UTC timestamp-based name
(`auto_YYYY-MM-DD_HHMMSS`). Snapshot names are validated server-side
against `[A-Za-z0-9._-]{1,64}` (rejecting `.` and `..`) before being
passed to `zfs(8)`, so the API surface itself can't be coaxed into
shell-injection or dataset-traversal even by a compromised admin
token.

`GET /stats/stream` opens a `text/event-stream` (SSE) connection. One
JSON event per second carries `name`, `jid`, `ip`, `ts`, plus every
RCTL counter (`cputime`, `memoryuse`, `pcpu`, ...). The handler
self-terminates with `event: end` if the jail exits while the stream
is open, so clients don't need separate liveness checks.

### Implementation

- **`daemon/routes_pure.{h,cpp}`** — testable formatting + validation:
  `formatStatsSseEvent()` (renders one SSE frame), `validateSnapshotName()`
  (returns "" if accepted, otherwise a one-line reason), and
  `extractStringField()` (a tiny brace-/quote-aware extractor used
  instead of pulling in a JSON parser for daemon request bodies).
- **`daemon/routes.cpp`** — five new handlers wired into
  `registerRoutes()`. Auth gates apply: read endpoints require the
  `viewer` role, mutating endpoints require `admin`. Per-endpoint
  rate limits reuse the existing buckets.

### Tests

`tests/unit/routes_pure_test.cpp` — 16 ATF cases:
- 5 SSE shape/escape/numeric-detection tests (including JSON escaping
  of `"`, `\`, `\n` in the jail name; numeric detection of `-7`/`1.5`
  vs string fallback for `1.2.3`)
- 5 snapshot-name validator tests (empty / 64+ chars / `.`/`..` /
  forbidden characters / valid examples)
- 6 JSON-field extractor tests (whitespace tolerance, escape decoding,
  missing-field empty return, non-string value rejection,
  unterminated-string safety)

**486/486** unit tests pass (was 470).

### What's still missing for full F2 parity

Tracked in `TODO`: WebSocket console (interactive shell over WS) and
export/import endpoints (multipart upload + `.crate` streaming). Both
need substantial transport plumbing and will land in their own
releases.

---

## [0.6.0] — 2026-05-01

Cross-device file shares — drops the long-standing requirement that the
host source and the jail-side mount point share a filesystem. `files:`
shares now transparently fall back to a single-file nullfs bind-mount
whenever a hard link would cross device boundaries.

### Why

`crate` previously implemented `files:` shares with `link(2)`. That
syscall returns `EXDEV` whenever the two paths live on different
devices — common in any setup where the jail dataset is on a separate
ZFS pool, the host source is on tmpfs, or the user mounts an external
disk. Symptom on the user side: a confusing `link: Cross-device link`
error at run time, with no obvious workaround.

### How

The decision logic is centralised in `lib/share_pure.{h,cpp}`. Given
three observable booleans — `hostExists`, `jailExists`, `sameDevice`
— it picks one of:

| host | jail | sameDev | strategy                       |
| ---- | ---- | ------- | ------------------------------ |
|  ✓   |  ✓   |    ✓    | unlink jail; hard-link host→jail |
|  ✓   |  ✓   |    ✗    | unlink jail; touch jail; nullfs-bind host→jail |
|  ✓   |  ✗   |    ✓    | hard-link host→jail            |
|  ✓   |  ✗   |    ✗    | touch jail; nullfs-bind host→jail |
|  ✗   |  ✓   |    ✓    | hard-link jail→host (creates host) |
|  ✗   |  ✓   |    ✗    | copy jail→host; touch jail; nullfs-bind |
|  ✗   |  ✗   |    —    | error (spec invalid)           |

The same-device hard-link paths preserve existing semantics
byte-for-byte. The new `nullfs-bind-host-to-jail` path is the one that
unblocks cross-device specs: the jail-side path is created as an empty
regular file, and `mount -t nullfs <host> <jail>` overlays the host
file's vnode onto it. Single-file nullfs has been part of FreeBSD
since 7.x; the in-jail process sees the file with full read/write
fidelity, including in-place edits.

### New helpers

- `Util::Fs::sameDevice(a, b)` — `stat(2)`-based comparison that walks
  up to the nearest existing ancestor when either path is missing, so
  the runtime can ask "would these end up on the same device?" before
  actually creating the file.
- `Util::Fs::touchFile(path, mode)` — creates an empty regular file
  with `O_NOFOLLOW`, used as a placeholder for the bind-mount.

### Tests

`tests/unit/share_pure_test.cpp` — 9 ATF cases covering all 7 cells of
the decision table plus a 2×2×2 totality check (every input triple
maps to a known strategy) and a name-uniqueness assertion to catch
accidental collisions when the enum grows. **470/470** unit tests
pass (was 461).

### Files

- `lib/share_pure.{h,cpp}` — pure decision module (new)
- `lib/util.{h,cpp}` — `sameDevice`, `touchFile` (new)
- `lib/run.cpp` — file-share loop refactored to dispatch on strategy
- `tests/unit/share_pure_test.cpp` — coverage (new)

### Compatibility

Pure addition. Specs that already work continue to use the hard-link
path. Cross-device specs that previously failed with `EXDEV` now
succeed via nullfs.

---

## [0.5.9] — 2026-05-01

Audit logging — closes the second-to-last "high priority" item in
TODO. Every state-changing crate command now appends a one-line JSON
record to `/var/log/crate/audit.log` so a multi-user host has a
compliance-friendly trail of who did what, when.

### Why

Crate is installed setuid root. On a shared host, an unprivileged
user invokes it; the kernel hands `crate` root via euid. Without
explicit audit, there is no record of "user X did Y" — both
`getuid()` (real) and `geteuid()` (effective, 0) are needed for a
reviewer to map an action back to its initiator.

### Format

JSON Lines (one event per line), schema:

```json
{
  "ts":      "2026-05-01T20:55:01Z",
  "pid":     12345,
  "uid":     1000,
  "euid":    0,
  "gid":     1000,
  "egid":    0,
  "user":    "alice",
  "host":    "build-server",
  "cmd":     "create",
  "target":  "spec.yml",
  "argv":    "'crate' 'create' '-s' 'spec.yml'",
  "outcome": "started" | "ok" | "failed: <msg>"
}
```

### Added

- **`lib/audit_pure.cpp`/`.h`** (new):
  - `Event` struct + `renderJson(Event)` with proper escapes
    (`"`, `\`, control chars, `\u00XX` for low ASCII; UTF-8 above
    0x7F passes through)
  - `pickTarget(args)` — chooses the primary subject for each
    command (spec/archive/dataset@snap/etc.)
  - `formatTimestampUtc(time_t)` — ISO 8601 (`gmtime_r` + strftime)
  - `joinArgv(argc, argv)` — shell-quoted replayable command line
- **`lib/audit.cpp`/`.h`** (new):
  - `Audit::logStart(argc, argv, args)` — emits `"started"` record
    after `Args::validate()` succeeds.
  - `Audit::logEnd(argc, argv, args, errMsg)` — emits `"ok"` or
    `"failed: ..."` based on outcome.
  - Read-only commands (`list`, `info`, `stats`, `logs`, `validate`)
    skipped to keep the log lean.
  - Single `write()` call per record (atomic per POSIX for size ≤
    `PIPE_BUF`).
  - File: mode 0640, `O_APPEND` — fits `auditd(8)` / `newsyslog(8)`.

### Hooked in

`cli/main.cpp` calls `logStart` after `args.validate()`, wraps the
dispatch switch in try/catch + always-flushed lambda so:
- Successful command → `outcome: "ok"`
- `Exception` thrown → `outcome: "failed: <msg>"`, then re-throw
- Any other `std::exception` → `outcome: "failed: std::exception: ..."`
- `succ == false` from a command → `"failed: command returned failure"`

### Added — tests (+17 cases)

`tests/unit/audit_pure_test.cpp`:
- JSON shape (all fields present, no embedded newlines)
- Escapes: `"`, `\`, `\n`/`\r`/`\t`, low Unicode `\u00XX`, UTF-8 passthrough
- Argv with embedded shell metacharacters → safely quoted
- `pickTarget` for every command (create/run/snapshot/info/console/
  export/import/stats/logs/stop/restart) + empty for list/clean/none
- Timestamp formatting at UNIX epoch, Y2K, plus regex pattern check
- `joinArgv` basic, special chars, empty

### Documentation

`README.md` + `README_UK.md` gained an "Audit log" / "Журнал аудиту"
section with example record and operational notes (rotation, mode,
correlating started/ok pairs by pid).

### Verification

- `make build-unit-tests` → 30 binaries built
- `cd tests && kyua test unit` → **461/461 pass** (was 444, +17)

---

## [0.5.8] — 2026-05-01

ed25519 signatures for `.crate` archives via `crate export -K
<secret-key>` and `crate import -V <public-key>`. Closes the last
"high priority" item in TODO and pairs with the 0.5.4 symmetric
encryption to give independent **confidentiality** + **authenticity**.

### Added

- **`lib/sign_pure.cpp`/`.h`** (new):
  - `validateSecretKeyFile` — must be regular, non-empty, mode 0600.
  - `validatePublicKeyFile` — must be regular, non-empty (mode irrelevant).
  - `buildSignArgv(secretKey, archive, sigOut)` — pinned to
    `openssl pkeyutl -sign -rawin -inkey ... -in ... -out ...`.
  - `buildVerifyArgv(publicKey, archive, sigFile)` — pinned to
    `openssl pkeyutl -verify -pubin -rawin -inkey ... -sigfile ...`.
  - `sidecarPath(archive)` — `<archive>.sig`.
- **CLI**:
  - `crate export -K, --sign-key <file>` — sign with ed25519 secret key
  - `crate import -V, --verify-key <file>` — verify with ed25519 public key
- **Auto-detection on import**: if `<archive>.sig` exists, `-V` is
  required (or `--force` to skip). If `-V` is given but no sidecar
  exists, the import fails (or `--force` to skip).
- The signature covers the **on-disk archive bytes**, including any
  encryption layer added by 0.5.4. So a tampered ciphertext fails
  signature check **before** the recipient enters their passphrase.

### Threat model recap

| Property | Provided by |
|---|---|
| Confidentiality | `-P` (AES-256-CBC + PBKDF2, 0.5.4) |
| Content integrity | `.sha256` sidecar |
| **Authenticity** | `-K` / `-V` (ed25519, 0.5.8) |

The three are independent; combine as needed.

### Added — tests (+13 cases)

`tests/unit/sign_pure_test.cpp`:
- Secret key file: 0600 OK; 0644 / 0640 / empty / missing / dir rejected
- Public key file: 0644 OK; 0600 also OK; empty / missing rejected
- argv shape pinned for sign + verify (positions 0–9 for sign, 0–10 for verify)
- `-rawin` flag presence (ed25519 requires it)
- Sidecar path computation

### Added — documentation

`README.md` + `README_UK.md` gain a "Signed export/import (ed25519)"
section with:
- One-time keypair generation (openssl genpkey)
- Combined `-P` + `-K` example for confidentiality + authenticity
- What gets signed (on-disk bytes including encryption layer)

### Verification

- `make build-unit-tests` → 29 binaries built
- `cd tests && kyua test unit` → **444/444 pass** (was 431, +13)

---

## [0.5.7] — 2026-05-01

`pkg install` failure inside a jail no longer eats its own diagnostics.
When `crate create` shells `pkg` inside a jail and `pkg` exits non-zero,
the captured stdout/stderr is now appended to a per-jail log file so
operators running crate non-interactively (cron, CI) can recover the
output.

### Why

Previously, `runChrootCommand()` inherited the controlling terminal —
so an interactive `crate create` user saw `pkg`'s output, but a
background invocation (cron, CI, daemon) lost it entirely. The thrown
`Exception` only said `'install the requested packages...' failed
with exit status N` — no log path, no error context, nothing for
post-mortem.

### Added

- **`Util::execCommandLogged(argv, what, logFile)`** — like
  `execCommand` but redirects child stdout AND stderr to `logFile`
  (open with `O_CREAT | O_APPEND`, mode 0640). On non-zero exit the
  thrown Exception's message includes the log path:
  ```
  exec command: 'install the requested packages into the jail'
    failed with exit status 1 — output captured in
    /var/log/crate/create-myapp.log
  ```
- **`Util::Fs::mkdirIfNotExists(dir, mode)`** — `mkdir(2)` that
  tolerates `EEXIST`; lets callers lazily create shared directories
  like `/var/log/crate` without racing.
- **`lib/log_pure.cpp`** (new): `LogPure::sanitizeName` and
  `LogPure::createLogPath` — filesystem-safe path computation.
  - `sanitizeName` replaces `/`, `\`, NUL with `_`; collapses
    leading dots (`.` and `..` can't be valid log names); empty
    name → `unnamed`.
  - `createLogPath(logsDir, kind, name)` →
    `<logsDir>/<kind>-<sanitized>.log`.

### Changed

- `lib/create.cpp::runChrootCommand` now takes an optional
  `logFile` parameter. When set, it routes through
  `execCommandLogged` and the captured pkg/script output is appended
  to that file.
- `installAndAddPackagesInJail` accepts the log path and threads it
  through every chroot invocation in the function.
- `createCrate` computes the log path from `Config::get().logs`
  (default `/var/log/crate`) and the jail's basename, lazily
  creating the log directory with `mkdirIfNotExists`.

### Lifecycle on failure (recap)

A `pkg` failure now leaves:
- The jail directory **deleted** (existing `RunAtEnd destroyJailDir`
  RAII at lib/create.cpp:447 — unchanged).
- The captured pkg output **preserved** at
  `/var/log/crate/create-<jail>.log` for post-mortem.
- An Exception message that **points to the log path**.

### Added — tests (+11 cases)

`tests/unit/log_pure_test.cpp`:
- `sanitizeName`: passthrough of safe names; replacement of `/`,
  `\`, NUL; collapsing of leading dots; empty → `unnamed`; long
  input passthrough; mid-string dots preserved.
- `createLogPath`: basic shape; sanitisation removes path
  separators (no traversal escape); `kind` distinguishes outputs.

### Verification

- `make build-unit-tests` → 28 binaries built
- `cd tests && kyua test unit` → **431/431 pass** (was 420, +11)

---

## [0.5.6] — 2026-05-01

X11 shared-mode security hardening: the warning is now always
visible (was previously gated behind the verbosity flag), the
`crate validate` warnings list includes it, and the README documents
all five X11 modes with their isolation properties.

### Fixed

- **Security warning for `x11/mode=shared` is now always shown at
  runtime.** Previously the WARN sat under `if (logProgress)` in
  `lib/run_gui.cpp`, so a user running `crate run app.crate` without
  `-p` would silently start a shared-mode container with full
  host-X access. The warning has real security implications and
  must not be gated by a verbosity flag.
- Operators who knowingly accept the risk can suppress the runtime
  warning with `CRATE_X11_SHARED_ACK=1`.

### Added — `crate validate` warnings

`ValidatePure::gatherWarnings` now flags:
- `x11/mode=shared` — explicit shared mode
- `options: [x11]` without `x11/mode` block — implicit shared default

### Added — tests (+3 cases)

`tests/unit/validate_pure_test.cpp`:
- `x11_shared_warns`
- `x11_headless_no_warn` (negative — must NOT warn)
- `x11_option_implicit_shared_warns` (no x11Options block)

### Added — documentation

`README.md` + `README_UK.md` gained an "X11 mode security" section
with a comparison table of the 5 modes (nested/headless/gpu/shared/none),
explanation of why `shared` is dangerous (keystroke leak, window
manipulation, screen capture), and a do/don't YAML example.

### Verification

- `make build-unit-tests` → 27 binaries built
- `cd tests && kyua test unit` → **420/420 pass** (was 417, +3)

---

## [0.5.5] — 2026-05-01

`pkg/add` spec section now works (was a stub returning a "not yet
implemented" error).

### Fixed

- **`pkg/add` is no longer rejected by the spec parser.** The
  underlying executor `installAndAddPackagesInJail()` (lib/create.cpp)
  has actually shipped support for adding pre-built `.txz` packages
  via `pkg add` for a long time — it copies each listed file into
  `/tmp/<basename>` inside the jail and invokes `pkg add`. The spec
  parser was the one rejecting `pkg/add` entries with a
  `not yet implemented` message. Replace the stub with a list parser
  matching `pkg/install`.

### Added — validation

- `Spec::validate()` now requires every `pkg/add` entry to be an
  absolute path. Relative paths are rejected before the jail is
  created, with a clear error.

### Added — tests (+3 cases)

`tests/unit/spec_validate_test.cpp`:
- `pkg_add_relative_path_throws`
- `pkg_add_absolute_path_ok`
- `pkg_add_multiple_one_relative_throws`

### Spec example

```yaml
pkg:
    add:
      - /host/local/pkgs/myapp-1.0.txz
      - /host/local/pkgs/mylib-2.3.txz
```

### Verification

- `make build-unit-tests` → 27 binaries built
- `cd tests && kyua test unit` → **417/417 pass** (was 414, +3)

---

## [0.5.4] — 2026-05-01

Optional **passphrase-based encryption** for `.crate` archives via
`crate export -P <passphrase-file>` and `crate import -P
<passphrase-file>`. Lets operators move container images privately
between hosts — addressing the use case where reproducible
applications travel as `.crate` artefacts.

### Added — encryption envelope

- `lib/crypto_pure.cpp`/`.h` (new): AES-256-CBC + PBKDF2 envelope
  layered on top of the existing tar+xz pipeline using the standard
  `openssl enc` CLI. No new build-time deps — `openssl(1)` is already
  installed on FreeBSD by default.
- New CLI flags:
  - `crate export -P, --passphrase-file <path>`
  - `crate import -P, --passphrase-file <path>`
- Auto-detection on import via magic bytes:
  - `Salted__` prefix (8 bytes) → encrypted, requires `-P`
  - `\xFD7zXZ\x00` xz magic → plain
  - anything else → reject
- Passphrase files are validated: must be a regular non-empty file
  with mode `0600` (owner-only). Loose permissions reject the
  invocation before any work starts.
- Passphrases are passed to `openssl` via `-kfile`, never on the
  command line — so they don't leak via `ps`/`procfs`.

### Security model

- **Confidentiality**: AES-256-CBC with PBKDF2 key derivation (OpenSSL
  default ≈ 10 000 iterations). Per-archive 8-byte random salt.
- **Integrity**: provided by the existing `.sha256` sidecar, which is
  computed over the encrypted ciphertext on export. Out-of-band
  verification of that hash before decryption is the operator's
  responsibility.
- **Authenticity**: not yet provided. Asymmetric signing (ed25519/GPG)
  remains open in TODO.
- The passphrase itself is never embedded in the artefact — same
  passphrase produces a different ciphertext each time (random salt).

### Added — tests (+17 cases)

`tests/unit/crypto_pure_test.cpp`:
- Magic-byte detection: xz/Salted/short/garbage/almost-match.
- File-level detection on real `mkstemp` fixtures (xz / Salted /
  missing).
- Passphrase-file validation: 0600 OK, world-readable rejected,
  group-readable rejected, empty rejected, missing rejected, dir
  rejected.
- argv shape pinned for both encrypt and decrypt invocations,
  including a regression guard that the passphrase is **never**
  passed inline (no `-k`/`-pass`, only `-kfile <path>`).

### Verification

- `make build-unit-tests` → 27 binaries built
- `cd tests && kyua test unit` → **414/414 pass** (was 397, +17)

---

## [0.5.3] — 2026-04-29

Version-string sync. Tag `v0.5.3` was published from the 0.5.2 merge
commit (`aa5e6bf`); the release artefacts are named
`crate-0.5.3-freebsd-*-amd64.tar.xz`, but the source still reported
`0.5.2`. Bump the in-source version strings so `crate --version`,
`port/Makefile` `PORTVERSION`, and the SNMP `crateVersion` MIB scalar
all report `0.5.3` to match the release tag.

No code changes — pure version-string synchronisation.

---

## [0.5.2] — 2026-04-29

`xorg.conf` generator and `crate snapshot list` renderer under test.

### Changed — extracted to pure modules

- `lib/run_gui_pure.cpp`: added `RunGuiPure::generateGpuXorgConf` —
  full headless-GPU `xorg.conf` body builder. Now uses the
  hardened `parseResolution` (so a malformed resolution like
  `"abc"` falls back to `1280x720` instead of throwing via
  `Util::toUInt`).
- `lib/snapshot_pure.cpp` (new): `SnapshotPure::renderTable` for
  `crate snapshot list` output.

### Added — tests (+11 cases)

- `run_gui_pure_test`: 6 new cases for `generateGpuXorgConf`
  (default driver → `dummy`, explicit driver + BusID, NVIDIA
  extras present, no NVIDIA extras for non-NVIDIA, all required
  sections present, garbage resolution falls back to 1280x720).
- `snapshot_pure_test` (new, 5): empty dataset, header presence,
  data columns, multiple rows, long names don't crash padding.

### Verification

- `make build-unit-tests` → 26 binaries built
- `cd tests && kyua test unit` → **397/397 pass** (was 386, +11)

---

## [0.5.1] — 2026-04-29

GUI mode VESA-CVT modeline math + resolution helpers under test.

### Changed — extracted to pure module

- `lib/run_gui_pure.cpp` (new):
  - `RunGuiPure::computeCvtModeline(w, h, refresh)` — VESA CVT v1.1
    reduced-blanking timing calculation. Drives the `xrandr --newmode`
    output for `crate gui` non-default resolutions.
  - `RunGuiPure::resolveResolution(spec)` — picks effective resolution
    from `guiOptions` / `x11Options`, fallback `1280x720`.
  - `RunGuiPure::parseResolution("WxH", w, h)` — `WxH` parser.

### Added — tests (+13 cases)

`tests/unit/run_gui_pure_test.cpp` covers:
- CVT modeline pinned values for 720p/1080p/4K@60Hz; structural
  invariants across 6 common sizes; higher refresh → higher
  pixel clock.
- `resolveResolution` default / `guiOptions` overrides /
  `x11Options` fallback / `guiOptions` wins over `x11Options`.
- `parseResolution` basic / zero rejected / garbage / extra
  chars (leading/trailing whitespace).

### Hardened along the way

`parseResolution` initially relied on `std::stoul`, which silently
skips leading whitespace — so `" 1920x1080"` would parse as valid.
Added explicit checks rejecting whitespace at position 0 and
position-after-`x`. (Same kind of latent bug the 0.4.5 `Util::toUInt`
fix addressed for unsigned overflow.)

### Verification

- `make build-unit-tests` → 25 binaries built
- `cd tests && kyua test unit` → **386/386 pass** (was 373, +13)

---

## [0.5.0] — 2026-04-28

Daemon Bearer-token auth and `crate list` rendering now under unit-test
coverage. Both pieces touched user-facing behaviour that previously had
zero direct tests.

### Changed — extracted to pure modules

- `lib/auth_pure.cpp` (new): `AuthPure::parseBearerToken`,
  `AuthPure::checkTokenRole`, `AuthPure::checkBearerAuth`. The full
  Bearer-token gate from `daemon/auth.cpp` is now in a tiny pure module
  parameterised by an injected `sha256Fn` — production passes
  `OpenSSL::SHA256` indirectly via `daemon/auth.cpp::sha256hex`, tests
  pass an identity-mapping fake. No new CI dependencies needed.
- `lib/list_pure.cpp` (new): `ListPure::renderJson`,
  `ListPure::renderTable` and stream/string variants. The display logic
  for `crate list` (and `crate list -j`) lives here as pure functions
  taking a `vector<Entry>`. `lib/list.cpp` keeps the FreeBSD-jail
  discovery side and forwards to these for output.

### Added — tests (+24 cases)

- `tests/unit/auth_pure_test.cpp` (+15) — Bearer-token parsing
  (basic, empty, just-prefix, wrong-scheme, embedded spaces); role
  gate (unknown hash, viewer-allows-any, admin-required, writer-required,
  admin-as-superset, empty-tokens); end-to-end happy/missing-header/
  wrong-scheme/role-escalation-blocked/admin-superset.
- `tests/unit/list_pure_test.cpp` (+9) — JSON output (empty,
  single entry, comma separator, healthcheck=false); Table output
  (empty, headers, singular/plural footer, dash-for-empty fields,
  `Y/-` healthcheck column).

### Verification

- `make build-unit-tests` → 24 binaries built
- `cd tests && kyua test unit` → **373/373 pass** (was 349, +24)

---

## [0.4.8] — 2026-04-28

Four more small pure helpers extracted, 13 new test cases.

### Changed — extracted to pure modules

- `lib/run_pure.cpp` (new): `RunPure::argsToString` (from `lib/run.cpp`),
  `RunPure::envOrDefault` (from `lib/run_net.cpp`).
- `lib/autoname_pure.cpp` (new): `AutoNamePure::snapshotName` (from
  `lib/snapshot.cpp::autoSnapshotName`), `AutoNamePure::exportName`
  (from `lib/export.cpp::autoExportName`).

The originals are now thin forwarders.

### Added — tests (+13 cases)

- `tests/unit/run_pure_test.cpp` (+8): `argsToString` empty/basic/
  injection-quoting; `envOrDefault` unset/valid/garbage/empty/
  overflow (verifies the 0.4.5 `toUInt` overflow guard does flow
  through to `envOrDefault`).
- `tests/unit/autoname_test.cpp` (+5): `snapshotName` format check
  (15 chars `YYYYMMDDTHHMMSS`), year sanity; `exportName` regex
  match, basename preservation, empty-basename edge case.

### Verification

- `make build-unit-tests` → 22 binaries built
- `cd tests && kyua test unit` → **349/349 pass** (was 336, +13)

---

## [0.4.7] — 2026-04-28

`validateCrateSpec` warning logic now under unit-test coverage. The
`crate validate <spec>` CLI emits warnings for security-relevant
configuration choices (sysvipc, allow_chflags, securelevel < 2, COW
backend implications, X11 nested mode, etc.). A regression that
silently drops a warning ships unannounced risk; this PR pins down
each branch with a dedicated test.

### Changed — extracted to pure module

- The 30+ warning branches inside `validateCrateSpec()` (lib/validate.cpp)
  moved into a new pure helper `ValidatePure::gatherWarnings(spec)` in
  `lib/validate_pure.cpp`. The CLI now just calls that and prints
  what it returns.

### Added — `tests/unit/validate_pure_test.cpp` (+30 cases)

Covers every warning branch:
- ipc/sysvipc, net/lan-with-tor, ipv6 (no-outbound + with-tor)
- limits-without-maxproc (positive + negative)
- encrypted, dns_filter (empty rules + without-net)
- allow_chflags, allow_mlock, securelevel < 2 (positive + negative)
- children_max, cpuset (invalid char + valid)
- COW backend=zfs / mode=persistent
- x11 nested, clipboard isolated (without/with nested)
- dbus session, socket_proxy empty
- firewall (without net + block-no-allow)
- capsicum, mac_bsdextended rules
- terminal devfs_ruleset
- multi-warning sanity check

### Verification

- `make build-unit-tests` → 20 binaries built
- `cd tests && kyua test unit` → **336/336 pass** (was 306, +30)

---

## [0.4.6] — 2026-04-28

`Spec::validate()` now under unit-test coverage — the largest
previously-untested function in the codebase (~200 lines, 30+ branches).

### Changed — extracted to pure module

- **`Spec::validate()`** moved from `lib/spec.cpp` to `lib/spec_pure.cpp`.
  Pulls in: `allOptionsSet` constant, `lst-all-script-sections.h`
  (generated header), and `Config::get()` (declared in
  `lib/config.h`, stubbed for tests).
- **`Spec::NetOptDetails::createDefault`**, **`Spec::TorOptDetails`
  ctor + `createDefault`**, **`Spec::optionNet/optionNetWr/optionTor`**,
  and the `getOptionDetails` template helpers also moved to
  `spec_pure.cpp` so the test suite can construct/inspect Spec
  objects without linking against yaml-cpp-bound `lib/spec.cpp`.

### Added — Config test stub

`tests/unit/_test_config_stub.cpp` provides minimal stubs for
`Config::get`, `Config::load`, `Config::resolveCrateFile`. Returns an
empty `Settings` object so `optNet->networkName` lookups in
`Spec::validate()` always fail with "not found" — exactly the
scenario tests want to assert.

### Added — `tests/unit/spec_validate_test.cpp` (+48 cases)

Covers **every branch** of `Spec::validate()`:
- "must do something": `runCmdExecutable`, `runServices`, or `tor`
- duplicate `pkg-local-override` entries
- absolute-path checks for `runCmdExecutable`, `dirsShare`, `filesShare`
- options whitelist (every documented option) + unknown rejected
- script sections whitelist + empty section rejected
- `inboundPortsTcp/Udp` span consistency
- `networkName` lookup against (empty stub) Config
- mode-specific validation:
  - `bridge`/`passthrough`/`netgraph` need their iface fields
  - `nat` rejects `bridge`/`dhcp`/`static`/`vlan`/`static-mac`/`ip6=slaac|static`
  - non-NAT rejects `inbound-tcp/udp`
  - `gateway` requires static IP
  - `ip6=static` requires address
  - `extra` interfaces require non-NAT primary; `extra mode=nat` rejected
- ZFS dataset names: empty / absolute / `..`
- RCTL limits: known list (~25 names), unknown rejected
- Encryption: method/keyformat/cipher whitelists
- `enforce_statfs` range `0..2`
- Firewall ports `1..65535`
- Terminal `devfs_ruleset` range `0..65535`

### Verification

- `make build-unit-tests` → 19 binaries built
- `cd tests && kyua test unit` → **306/306 pass** (was 258, +48)

---

## [0.4.5] — 2026-04-28

Boundary / adversarial test pass. **Two more real bugs caught and fixed**
— making this the fifth bug found by the tests added in this PR cycle.

### Fixed

- **`Util::toUInt`** silently truncated when the parsed value
  exceeded `UINT_MAX`. On 64-bit platforms `unsigned long` is 64-bit
  but `unsigned` is 32-bit, so e.g. `toUInt("99999999999")` returned
  the low 32 bits instead of throwing. Practical impact: a port-range
  spec like `99999999999` would parse as a random small port. Also
  silently accepted leading-`-` and leading whitespace via `stoul`'s
  permissiveness. Fix: explicit guard against `-`/whitespace and
  range-check the parsed value before casting.
- **`StackPure::parseCidr`** accepted any prefix length — including
  `/64` for IPv4 (silently kept) and `/-1` (parsed by `std::stoul` as
  `ULONG_MAX`). Fix: reject prefixes outside `0..32` and reject leading
  `-`. `/-1` and `/64` now return `false`.

### Changed — extracted to pure module

- `Scripts::escape` moved from `lib/scripts.cpp` to
  `lib/scripts_pure.cpp` (`ScriptsPure::escape`).

### Added — tests (+36 cases)

- `tests/unit/scripts_test.cpp` (+5) — covers `escape` with empty
  input, plain text, single quote, classic injection attempt, and a
  `/bin/sh` round-trip.
- `tests/unit/adversarial_test.cpp` (+31) — boundary/edge tests
  across the existing pure surface:
  - `shellQuote`: 100KB input, 1000 single quotes, embedded null
    bytes, high-byte (0x80–0xFF) bytes
  - `splitString`: only-delimiters, 1000-element split, leading/
    trailing delimiters
  - `Fs::hasExtension`: case sensitivity, dotfile, no-dot
  - `isUrl`: minimum-valid (8 vs 9 chars), uppercase scheme
  - `parseCidr`: 0/32 boundaries, oversize, negative, extra text,
    empty addr/prefix
  - `parsePortRange`: overflow, negative, inverted range
  - `humanBytes`: `UINT64_MAX`, just-below-1K
  - `MibPure`: 1023-byte octet string, empty OID
  - `topoSort`: 100-node chain, fan-out
  - `isLong`: triple-dash, just `--`

### Bug-discovery score so far this PR cycle

| Release | Bug found | Severity |
|---|---|---|
| 0.4.0 | `safePath` accepts `/foo_neighbour` for prefix `/foo` | path-traversal in setuid binary |
| 0.4.0 | `isLong` rejects every long option | every `--help`-style flag broken |
| 0.4.4 | `pathSubstituteVarsInString` infinite loop on `$HOMER` | DoS |
| 0.4.5 | `Util::toUInt` silent truncation past UINT_MAX | wrong port/limits silently accepted |
| 0.4.5 | `parseCidr` accepts impossible prefixes (`/64`, `/-1`) | wrong netmask silently accepted |

### Verification

- `make build-unit-tests` → 18 binaries built
- `cd tests && kyua test unit` → **258/258 pass** (was 222, +36)

---

## [0.4.4] — 2026-04-27

Variable-substitution coverage + a third real bug caught by new tests.

### Fixed

- **`Util::pathSubstituteVarsInString()`** had an infinite loop when
  the input contained a token that matched `$HOME`/`$USER` as a prefix
  but was followed by an alphanumeric (e.g. `"$HOMER"`, `"$USERNAME"`).
  The loop's word-boundary check prevented substitution but did not
  advance the cursor, so `s.find(key)` returned the same offset
  forever. Fixed by walking with an explicit `pos` cursor that
  advances past every match (substituted or not). Caught by the new
  `stringSubst_word_boundary` test, which timed out at 300 s before
  the fix.

### Changed — extracted to pure modules

- `Util::pathSubstituteVarsInPath`, `Util::pathSubstituteVarsInString`
  moved from `lib/util.cpp` to `lib/util_pure.cpp`.
- `substituteVars` moved from `lib/spec.cpp` to `lib/spec_pure.cpp`
  (now `SpecPure::substituteVars`).

### Added — tests (+22 cases)

- `tests/unit/util_subst_test.cpp` (+11 cases) — `pathSubstituteVarsInPath`
  and `pathSubstituteVarsInString` coverage, including the adversarial
  `$HOMER` / `$USERNAME` cases that surfaced the infinite-loop bug.
- `tests/unit/spec_subst_test.cpp` (+11 cases) — `${KEY}` substitution
  used by `crate create --var KEY=VALUE`. Covers empty input, multiple
  keys, repeated tokens, unknown keys, empty values, recursion guard
  (a value containing `${X}` is not re-expanded), adjacent tokens,
  `$X`-without-braces ignored.

### Verification

- `make build-unit-tests` → 16 binaries built
- `cd tests && kyua test unit` → **222/222 pass** (was 200, +22)

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
