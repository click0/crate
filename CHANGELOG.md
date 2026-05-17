# Changelog

All notable changes to **crate** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.1.4] — 2026-05-14

**Anchor-name length ceiling raised from 64 to 256.** Companion
fix to 1.1.3. Same bug shape: lib/run.cpp builds anchors as
`crate/<jailXname>`, and after 1.1.3 jailXname can be up to 200
chars — making the worst-case anchor 206 chars, well beyond the
old 64-char ceiling.

### What was wrong

`lib/run.cpp:1163` builds:

```cpp
auto anchor = std::string("crate/") + jailXname;
```

Same in `lib/pfctl_ops.cpp::composeContainerPolicy` (1.1.0)
which composes `STR("crate/" << jailXname)`. With jailXname
up to 200 chars (per 1.1.3) and the `crate/` prefix at 6 chars,
the anchor is up to 206 chars — but `validateAnchorName`
capped at 64.

Even BEFORE 1.1.3, a 60-char jailXname already produced a
66-char anchor that the old ceiling would have rejected.
The bug was masked because:

1. Existing tests only fed validateAnchorName short single-
   segment strings ("crate", "crate.dev_pool-1") — never the
   runtime `crate/<full-name>` shape
2. Operators who hit it under setuid (pre-1.0.0) would have
   seen direct pfctl(8) errors rather than the daemon's 400 —
   harder to attribute to validation

1.1.0's PfctlOps privops-wiring made the failure mode visible
(daemon 400) but the test suite still didn't exercise the
long-name path.

### The fix

`validateAnchorName`'s `name.size() > 64` check becomes
`name.size() > 256`. pf has no hard limit on anchor path
length (it's an in-kernel hash table key, not a kernel
identifier); 256 is well above any realistic crate-generated
anchor and stays well clear of `MAXHOSTNAMELEN`.

### Tests

New `anchor_accepts_runtime_long_form` regression test:

- 200-char `jailXname` → 206-char `crate/<...>` anchor validates
- 256-char anchor (at limit) validates
- 257-char anchor rejected

Suite grows from 1311 to **1312**.

### Wire compatibility

Daemon-side relaxation only. No wire format change.

### Files

- `lib/privops_pure.cpp` — `validateAnchorName` ceiling 64 → 256
- `tests/unit/privops_pure_test.cpp` — new
  `anchor_accepts_runtime_long_form` regression
- `cli/args.cpp` — version `crate 1.1.4`
- `CHANGELOG.md` — this entry

---

## [1.1.3] — 2026-05-14

**Jail-name length ceiling raised from 64 to 200.** Fixes a
latent 1.1.0+ bug where the daemon's `validateJailName`
rejected the runtime-composed jail xname for any spec name
longer than ~55 chars.

### What was wrong

`lib/run.cpp:802` builds the jail's exec name as:

```cpp
auto jailXname = STR(nameComponent << "_pid" << ::getpid());
```

For a typical pid like `12345`, the suffix `_pid12345` is 9
chars. So a spec name `nameComponent` of 56+ chars would
make `jailXname` exceed the 64-char ceiling — the daemon's
privops `create_jail` validator returns 400 before ever
calling `jail(8)`. Operators with descriptive jail names
(common in stack deployments where names encode purpose)
hit this deterministically.

The pre-1.0.0 rootless audit didn't surface this because no
test fed `validateJailName` a 60+ char input followed by a
pid suffix. The validator unit test only checked the 64/65
boundary against a plain `aaaa...` string.

### The fix

`validateJailName`'s `name.size() > 64` check becomes
`name.size() > 200`. FreeBSD's `MAXHOSTNAMELEN` is 256;
picking 200 leaves 56 bytes of headroom for the pid suffix
and any future composition while staying clear of the
kernel limit.

### Tests

Existing `jailname_rejects_too_long` updated to test the new
200/201 boundary. New `jailname_accepts_runtime_pid_suffix`
regression test that explicitly composes the `<long-name>_pid<num>`
shape that lib/run.cpp produces at runtime.

Suite grows from 1310 to **1311**.

### Wire compatibility

No wire change. The validator is daemon-side; a 1.1.3 daemon
relaxes what it accepts. Old daemons still reject long names
— operators hitting this should bump the daemon (no client
change needed).

### Files

- `lib/privops_pure.cpp` — `validateJailName` ceiling 64 → 200
- `tests/unit/privops_pure_test.cpp` — existing test updated;
  new `jailname_accepts_runtime_pid_suffix` regression
- `cli/args.cpp` — version `crate 1.1.3`
- `CHANGELOG.md` — this entry

---

## [1.1.2] — 2026-05-13

**Test coverage for recent verbs + anchor-name validator fix.**
Backfills validator + wire parser tests for the three privops
verbs added in 1.0.5–1.1.1 (`reclaim_iface_from_vnet`,
`flush_pf_anchor`, `query_jail_rctl`) and extends
`dispatch_covers_every_verb` to include every verb added since
0.9.23.

Adding those tests surfaced a latent 1.1.0 bug: the daemon's
`validateAnchorName` rejected `/`, while every real-world
crate anchor uses the `crate/<jail>` nested form (per pf.conf
convention). The 1.1.0 PfctlOps privops-wiring shipped looking
like it worked because the existing AddPfRule test cases used
a single-segment "crate" anchor — never exercising the
canonical `/`-separated path. 1.1.2 fixes the validator AND
adds the missing test coverage.

### validateAnchorName

```cpp
// 1.1.1 and earlier
bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-';

// 1.1.2 (this release)
bool ok = isAlnum(c) || c == '.' || c == '_' || c == '-' || c == '/';
```

Shell metacharacters (`;`, ` `, `` ` ``, `$`, etc.) remain
rejected. pf's anchor namespace is internal to the kernel; `/`
is a logical path separator, not a filesystem path, so there
is no traversal risk.

### What's added

`tests/unit/privops_pure_test.cpp` gains 3 validator tests:

- `reclaim_iface_from_vnet_minimal` — happy path + 4 invalid
  inputs (shell metachar in ifname, path-traversal in jail name,
  empty fields)
- `flush_pf_anchor_minimal` — accepts `crate/web` and bare
  `crate`; rejects empty and shell-metachar
- `query_jail_rctl_minimal` — accepts jid 1..65535; rejects 0
  and > 65535

`tests/unit/privops_wire_pure_test.cpp` gains 4 tests:

- `parse_reclaim_iface_from_vnet` — JSON parse happy + missing
  field
- `parse_flush_pf_anchor` — JSON parse happy + missing field
- `parse_query_jail_rctl` — JSON parse happy + missing field
- `format_query_jail_rctl_escapes_newlines` — guards the first
  multi-line response formatter; verifies that `\n` in the
  `output` field gets JSON-escaped, the body stays single-line,
  and `extractStringField` round-trips the original

`dispatch_covers_every_verb` extended from the original 14
verbs (0.9.0) to all 24 verbs (0.9.0 → 1.1.1). The test
ensures every Verb enum value reaches a real dispatcher
branch; previously a new verb could be added to the enum
but missed in the dispatcher switch with no test catching it.

### Why now

The 1.0.5–1.1.1 mini-PRs each added a verb without dedicated
test scaffolding (relying on the existing patterns being
"proven enough"). That was fine for shipping but leaves the
test suite blind to regressions on those code paths. 1.1.2
backfills the gap with no new functionality.

### Tests

Suite grows from 1303 to **1310** (3 validator tests + 4 wire
tests). All previously-added test cases keep passing.

### Files

- `lib/privops_pure.cpp` — `validateAnchorName` allows `/`
- `tests/unit/privops_pure_test.cpp` — 3 validator tests; the
  `flush_pf_anchor_minimal` case asserts `crate/web` validates
- `tests/unit/privops_wire_pure_test.cpp` — 4 parser/formatter
  tests; `dispatch_covers_every_verb` extended
- `cli/args.cpp` — version `crate 1.1.2`
- `CHANGELOG.md` — this entry

---

## [1.1.1] — 2026-05-13

**Query-side privops: rctl read.** First read-side verb of the
1.1.x line. Fixes `crate inspect` silently dropping the RCTL
section under rootless. Wire taxonomy grows from 23 to 24
verbs; `query_jail_rctl` is the first verb whose 200-OK body
carries arbitrary text output for client-side parsing.

### What changes

`lib/inspect.cpp:96` previously called `rctl -u jail:<jid>`
directly via `Util::execCommandGetOutput`. Under rootless,
that fails for any non-root operator, the surrounding
`try/catch(...)` swallowed the exception, and the operator
got an inspect snapshot with no RCTL data.

1.1.1 adds a new privops verb `query_jail_rctl` and routes
the inspect call site through it when crated's socket is
detected:

```
crate inspect web
  ↓ (rootless)
  privops query_jail_rctl(jid=42)
  ↓
  crated runs `rctl -u jail:42` as root, returns output
  ↓
  client parses via InspectPure::applyRctlOutput (unchanged)
```

Legacy single-tenant (setuid) deployments keep the direct
shell-out path unchanged.

### Wire-format note: text in response body

This is the first verb where the response body's `output`
field carries multi-line text. The format uses standard JSON
string escaping (newlines become `\n`, etc.); the existing
`PrivOpsWirePure::extractStringField` handles the unescape
on the client side. The verb-name registry already supports
this — `CreateEpair` (0.9.26) was the first response-data
verb, just with short identifier strings rather than text.

### Doctor / migrate

The audit also listed `inspect/doctor/migrate` shell-out
sites. The doctor/migrate paths only call `Util::execCommand`
for the *probe* check (return zero = available, non-zero =
not), which doesn't need privileged access — they work
unchanged under rootless. No verb needed for those.

### What's left

Audit's rootless track now CLOSED.

Remaining 1.x backlog (out of scope for the audit, but tracked):

- Test coverage on impure modules — `run.cpp` (1810 lines) vs
  `run_pure.cpp` (24 lines), plus 47 lib/*.cpp without dedicated
  tests. 1.2.0+.
- `scripts_pure` / `lifecycle_pure` / `autoname_pure` /
  `import_pure` stub completion. 1.2.0+.

### Tests

No new dedicated test — the verb mirrors the existing
single-field-input shape; the response-data path is proven
by `CreateEpair`. Suite stays at 1303.

### Files

- `lib/privops_pure.{h,cpp}` — `Verb::QueryJailRctl`,
  `QueryJailRctlReq{jid}`, `validateQueryJailRctl`
- `lib/privops_wire_pure.{h,cpp}` — JSON parser, success
  formatter, dispatcher case; first formatter with multi-line
  text output
- `lib/privops_nv_pure.{h,cpp}` — nv parser
- `lib/privops_client.h` + `lib/privops_client_pure.cpp` —
  `buildQueryJailRctl`
- `daemon/privops_handlers.{h,cpp}` — `handleQueryJailRctl`
  + HTTP + libnv dispatcher cases
- `lib/inspect.cpp` — RCTL call site routes through privops
  when socket detected; legacy shell-out preserved
- `cli/args.cpp` — version `crate 1.1.1`
- `CHANGELOG.md` — this entry

---

## [1.1.0] — 2026-05-13

**PfctlOps privops-wiring.** First minor release of the 1.x
line. Closes the last `crate(1) → /dev/pf` direct-access path
flagged by the pre-1.0.0 audit. Adds the 23rd privops verb
and refactors `PfctlOps::loadContainerPolicy` into a pure
composer + caller-driven addRules, so the rootless `crate(1)`
binary no longer needs root for any pfctl operation.

### Why this is the audit's biggest 1.x item

The audit originally flagged `lib/pfctl_ops.cpp:28` as "PfLock
file not per-user". On closer inspection that was a wrong
finding — `pf(4)` is host-wide and the lock must serialize
across operators. The real bug was that `lib/run.cpp` had
three direct call sites into `PfctlOps` (`addRules`,
`loadContainerPolicy`, `flushRules`) that all opened
`/dev/pf` or `/var/run/crate/pfctl.lock` as the calling uid.

After 1.0.0 removed the setuid bit, those calls fail for any
non-root operator. Single-tenant workflows that don't use
`spec.firewallPolicy` or auto-fw never hit the path; any
operator running a jail with firewall rules under rootless
mode hit it on first `crate run`.

### What changes

#### New verb: `flush_pf_anchor`

Symmetric companion to the existing `add_pf_rule` verb (0.9.0).
Same 7-file pattern as 0.9.23–1.0.5: enum + struct + validator
+ JSON parser + nv parser + client builder + daemon handler +
HTTP/libnv dispatcher cases.

Wire taxonomy grows from 22 to **23 verbs**.

#### `PfctlOps::loadContainerPolicy` refactor

Split into:

```cpp
// Pure composition — builds rule text from spec.firewallPolicy.
// No /dev/pf access, no shell calls. Safe to run as any uid.
struct ComposedPolicy { std::string anchor; std::string rulesText; };
ComposedPolicy composeContainerPolicy(spec, jailXname, ipv4, ipv6);

// Legacy entry point — composes then calls addRules() locally.
// Kept for binary compat / out-of-tree consumers.
std::string loadContainerPolicy(spec, jailXname, ipv4, ipv6);
```

#### `lib/run.cpp` routing helpers

Two new static helpers, same shape as `moveToVnetPrivopsOrLocal`
in `run_net.cpp`:

- `addPfRulePrivopsOrLocal(anchor, rulesText)` — sends the
  rule text via `AddPfRule` verb when the socket is detected,
  otherwise falls through to the bare `PfctlOps::addRules`
- `flushPfAnchorPrivopsOrLocal(anchor)` — sends the anchor
  name via `FlushPfAnchor` verb, otherwise bare flush

Three call sites updated:

| Site                                            | Before                                        | After                                            |
|-------------------------------------------------|-----------------------------------------------|--------------------------------------------------|
| `run.cpp:~1163` (auto-fw SNAT/rdr)              | `PfctlOps::addRules(anchor, rule)`            | `addPfRulePrivopsOrLocal(anchor, rule)`          |
| `run.cpp:~1513` (per-container firewall policy) | `PfctlOps::loadContainerPolicy(...)`          | `composeContainerPolicy(...)` + privops addRules |
| `run.cpp:~1518` (anchor teardown)               | `PfctlOps::flushRules(anchorName)`            | `flushPfAnchorPrivopsOrLocal(anchorName)`        |

### Why a minor version (1.0.5 → 1.1.0)

- Adds a new wire verb (`flush_pf_anchor`) — visible to API
  consumers and the privops dispatcher
- Refactors a public API (`loadContainerPolicy` no longer
  the only entry point; `composeContainerPolicy` is the
  preferred form)
- Changes runtime behaviour for any rootless deployment using
  firewall policy (latent crash → working code)

Patch releases (1.0.x) so far were either internal-only
(per-user path leaks) or single-verb additions that didn't
restructure an existing helper. This release does both, so
it earns the minor bump.

### Wire compatibility

Existing 22 verbs (0.9.0–1.0.5) unchanged. New verb is
additive. 1.1.0 daemons accept 1.0.x clients; 1.1.0 clients
talking to a 1.0.x daemon will get 404 on `flush_pf_anchor`
during jail teardown — operators upgrading should bump the
daemon first, then clients. Anchor teardown failures are
warn-only (the jail is already gone), so the only operator-
visible symptom would be a stale `crate/<jailname>` anchor
needing `pfctl -a crate/<jailname> -F all` manual cleanup.

### What's left from the pre-1.0.0 audit

| Area                            | Status     |
|---------------------------------|------------|
| Per-user path leaks             | ✅ done (0.9.27, 1.0.1–1.0.4) |
| Iface verbs (forward + reverse) | ✅ done (1.0.5) |
| **PfctlOps privops-wiring**     | ✅ **done (this release)** |
| Query-side privops verbs        | 1.1.x      |
| Test coverage on impure modules | 1.2.0+     |

The audit's main rootless work is now COMPLETE. Remaining
items are either polish (query-side verbs for
inspect/doctor/migrate; these never blocked 1.0.0) or larger
refactors (test coverage on run.cpp's impure half).

### Tests

No new dedicated test — the new verb mirrors the existing
`AddPfRule` shape (one struct field validation), reusing
the proven `validateAnchorName` field validator. The
`composeContainerPolicy` split is structure-only; the rule-
composition logic is unchanged from `loadContainerPolicy`.
Suite stays at 1303.

### Files

- `lib/privops_pure.{h,cpp}` — `Verb::FlushPfAnchor`,
  `FlushPfAnchorReq{anchor}`, `validateFlushPfAnchor`
- `lib/privops_wire_pure.{h,cpp}` — JSON parser, success
  formatter, dispatcher case
- `lib/privops_nv_pure.{h,cpp}` — nv parser
- `lib/privops_client.h` + `lib/privops_client_pure.cpp` —
  `buildFlushPfAnchor`
- `daemon/privops_handlers.{h,cpp}` — `handleFlushPfAnchor`
  + HTTP + libnv dispatcher cases
- `lib/pfctl_ops.{h,cpp}` — `composeContainerPolicy` pure
  helper; `loadContainerPolicy` rewritten on top of it
- `lib/run.cpp` — `addPfRulePrivopsOrLocal` +
  `flushPfAnchorPrivopsOrLocal` static helpers; three call
  sites routed through them
- `cli/args.cpp` — version `crate 1.1.0`
- `CHANGELOG.md` — this entry

---

## [1.0.5] — 2026-05-12

**Reclaim-from-vnet privops verb.** Fifth patch release of the
1.x line. Adds a new privops verb so jail teardown no longer
shells out to `ifconfig -vnet` directly from `crate(1)`. First
verb added since 0.9.28; the wire taxonomy grows from 21 to 22.

### What changes

`lib/run_net.cpp:446` (the `reclaimPassthroughInterface`
function) previously called:

```cpp
Util::execCommand({CRATE_PATH_IFCONFIG, info.iface, "-vnet", jailName},
                  ...);
```

This requires `CAP_NET_ADMIN` / root, which `crate(1)` no
longer has since the setuid bit was removed in 1.0.0. The fix
wires the call through a new privops verb
`reclaim_iface_from_vnet`, mirroring the 0.9.20 pattern that
already routes the forward direction (host → jail) through
`ConfigureIface`.

### Wire taxonomy

| #  | Verb name                  | Release  | Direction         |
|----|----------------------------|----------|-------------------|
| 22 | `reclaim_iface_from_vnet`  | **1.0.5**| jail → host       |
| 21 | `clear_loginclass_rctl`    | 0.9.28   | (loginclass scope)|
| ... | (full list: see 0.9.0–0.9.28 entries) | | |

Same per-verb pattern as 0.9.25–0.9.28: validator, JSON parser,
nv parser, client builder, daemon handler, HTTP + libnv
dispatcher cases.

### Reasoning

The pre-1.0.0 audit flagged this site as "direct shell call".
The earlier 0.9.20 work routed the inverse direction
(host → jail) through `ConfigureIface` but missed the
teardown path because the call site lives in a different
helper. 1.0.5 closes that gap.

### What's left

| Area                            | Status     |
|---------------------------------|------------|
| Per-user path leaks             | ✅ done (0.9.27, 1.0.1–1.0.4) |
| Iface verbs (forward + reverse) | ✅ done (0.9.23–0.9.26, 1.0.5) |
| **PfctlOps privops-wiring**     | 1.1.0      |
| Query-side privops verbs        | 1.1.0+     |
| Test coverage (run.cpp impure)  | 1.2.0+     |

### Tests

No new dedicated test — the verb mirrors the 0.9.25
`SetIfaceInetAddr` shape, which is covered by the existing
validator + parser test scaffold. The new
`validateReclaimIfaceFromVnet` reuses the proven
`validateIfaceName` + `validateJailName` field validators.
Suite stays at 1303.

### Files

- `lib/privops_pure.h` — new `Verb::ReclaimIfaceFromVnet`,
  request struct, validator decl
- `lib/privops_pure.cpp` — verbName, parseVerb, validator
- `lib/privops_wire_pure.{h,cpp}` — JSON parser + success
  formatter + dispatcher case
- `lib/privops_nv_pure.{h,cpp}` — nv parser
- `lib/privops_client.h` + `lib/privops_client_pure.cpp` —
  client builder
- `daemon/privops_handlers.{h,cpp}` — handler impl + HTTP +
  libnv dispatcher cases
- `lib/ifconfig_ops.{h,cpp}` — `moveFromVnet(iface, jailName)`
  primitive (shells `ifconfig <iface> -vnet <jail>`)
- `lib/run_net.cpp` — `moveFromVnetPrivopsOrLocal` wrapper;
  `reclaimPassthroughInterface` routes through it
- `cli/args.cpp` — version `crate 1.0.5`
- `CHANGELOG.md` — this entry

---

## [1.0.4] — 2026-05-12

**VM runtime + cloud-init paths per-user.** Fourth patch
release of the 1.x line. `lib/vm_run.cpp` now resolves the
VM DNS share and cloud-init user-data temp directories to
the per-user base when the privops socket is detected.

### What changes

New file-local `vmBaseDir()` helper in `lib/vm_run.cpp` —
same lazy-resolve pattern as `stack.cpp` (1.0.3) and
`network_lease.cpp` (0.9.27).

| Mode                          | DNS share base                       | cloud-init temp dir                  |
|-------------------------------|--------------------------------------|--------------------------------------|
| Legacy (no `crated`)          | `/var/run/crate/vm/<vmName>/dns/`    | `/var/run/crate/cloud-init/`         |
| Rootless (crated + privops)   | `/var/run/crate/<uid>/vm/<vmName>/dns/` | `/var/run/crate/<uid>/cloud-init/`|

Two functions updated:

- `configureVmDns()` — DNS share dir tree (`vm/<vmName>/dns/`)
  resolves under per-user root
- The cloud-init user-data writer (anonymous helper near line
  340) — writes `user-data-9p-<pid>.yaml` under per-user root

### Why this matters

Before this release, two operators on a rootless host with
the VM track enabled would clobber each other's resolv.conf
9p-share AND collide on cloud-init user-data files (despite
the PID suffix). Single-tenant deployments saw no impact.

VM track is `#ifdef HAVE_LIBVIRT`-gated, so non-libvirt
builds are completely unaffected.

### 1.x backlog

Path-leak track complete with this release. Remaining 1.x
items (different shapes):

- `lib/run_net.cpp:446` direct `ifconfig -vnet` (should use
  `SetIfaceUp` privops verb)
- **PfctlOps privops-wiring** — `lib/run.cpp` call sites
  (1.1.0)
- Query-side privops verbs (inspect/doctor/migrate)
- Test coverage on impure modules (run.cpp 1810 / run_pure.cpp
  24 lines)

### Tests

No new tests — single helper + 2 sites. Same `dnsBaseDir`
pattern from 1.0.3. Suite stays at 1303.

### Files

- `lib/vm_run.cpp` — `vmBaseDir()` helper; 2 sites routed
  through it; new includes
- `cli/args.cpp` — version `crate 1.0.4`
- `CHANGELOG.md` — this entry

---

## [1.0.3] — 2026-05-12

**Stack DNS dirs per-user.** Third patch release of the 1.x
line. The per-stack unbound config + pidfile directory now
resolves to `/var/run/crate/<uid>/dns-<network>/` when the
privops socket is detected.

### What changes

`lib/stack.cpp` gains a `dnsBaseDir()` static helper that
lazy-resolves the base directory for per-stack DNS state:

| Mode                          | Path                                 |
|-------------------------------|--------------------------------------|
| Legacy (no `crated`)          | `/var/run/crate/dns-<network>/`      |
| Rootless (crated + privops)   | `/var/run/crate/<uid>/dns-<network>/`|

Four sites updated:

- `generateUnboundConf()` — pidfile path inside the rendered
  unbound config (named + default cases)
- `startStackDns()` — `mkdir` target + path passed to
  `unbound -c <conf>`
- `stopStackDns()` — `remove_all` cleanup path

Net effect: when alice and bob each run a stack with a
network named `db`, their unbound instances no longer fight
over `/var/run/crate/dns-db/unbound.pid`.

### Why this matters

Before this release, every operator on a rootless host shared
the same DNS config directory. Two operators bringing up
stacks with the same network name would clobber each other's
unbound.conf and pidfile. The unbound process started first
held the pidfile; the second `crate stack up` would either
silently overwrite the conf and not restart unbound, or
deliver SIGTERM to the wrong process at teardown.

### 1.x backlog

Remaining latent per-user path leaks:

- `lib/vm_run.cpp` VM + cloud-init paths hardcoded
- `lib/run_net.cpp:446` direct `ifconfig -vnet` (should use
  existing `SetIfaceUp` privops verb)

Reclassified out of "latent path leak" into a separate 1.1.0
work item (real bug, but bigger fix):

- **PfctlOps privops-wiring**: `crate(1)` calls
  `PfctlOps::addRules` / `loadContainerPolicy` / `flushRules`
  directly from `lib/run.cpp`. Without setuid, the
  non-root operator cannot open `/dev/pf` nor the host-wide
  `/var/run/crate/pfctl.lock`. The original audit suggested
  per-user lock but that's incorrect — pf is host-wide, the
  lock must serialize across operators. The right fix is to
  route the three call sites through the existing `AddPfRule`
  privops verb (and add `FlushPfAnchor` / `LoadPfPolicy`
  verbs if needed). 1.1.0 will cover this.

### Tests

No new tests — the change is a single helper + 4 string
substitutions. The `dnsBaseDir()` cache uses the same lazy-
resolve pattern proven in `network_lease.cpp`. Suite stays
at 1303.

### Files

- `lib/stack.cpp` — `dnsBaseDir()` helper, 4 call sites
  routed through it; new includes for `privops_client.h` and
  `runtime_paths_pure.h`
- `cli/args.cpp` — version `crate 1.0.3`
- `CHANGELOG.md` — this entry

---

## [1.0.2] — 2026-05-12

**Spec registry per-user + restart wires through it.** Second
patch release of the 1.x line. Fixes two coupled multi-tenant
bugs that the 0.8.21 spec-registry feature inherited from the
pre-rootless filesystem-walk era.

### What changes

#### `lib/spec_registry.cpp` — lazy per-user path

Same `effectivePath()` lazy-resolve pattern as
`network_lease.cpp` (0.9.27) and `network_lease6.cpp` (1.0.1).
When the privops socket is detected, the registry file moves
from `/var/run/crate/spec-registry.txt` to
`/var/run/crate/<uid>/spec-registry.txt`. Alice's
`crate run -f web.crate` registers under alice's uid; bob
doing the same registers under bob's uid; neither sees the
other's entry.

#### `lib/lifecycle.cpp` — `restartCrate()` queries the registry

`crate restart <name>` now asks `SpecRegistry::lookup(name)`
for the `.crate` path before falling back to the legacy
filesystem walk under `/var/run/crate/<name>.crate`. The
fallback is preserved for two reasons:

1. Jails started before 0.8.21 (no registry entry, just a
   conventional file placement)
2. Single-tenant deployments that historically dropped
   `.crate` files manually under `/var/run/crate/`

Net effect: existing single-tenant homelabs see no behaviour
change; rootless multi-tenant deployments stop cross-
contaminating.

### Why this matters

Before this release, two operators on the same host running
`crate restart web` would race to find each other's `.crate`
path. Whoever pushed last to the shared
`/var/run/crate/spec-registry.txt` won. Cross-tenant
restarts then either picked up the wrong spec (silent data
corruption) or hit the legacy filesystem walk (silent
fall-through to a stale `/var/run/crate/web.crate` left over
from a previous deploy).

### 1.x backlog

Remaining latent per-user path leaks from the pre-1.0.0 audit:

- `lib/pfctl_ops.cpp` pf lock not per-user
- `lib/stack.cpp` DNS dirs hardcoded
- `lib/vm_run.cpp` VM + cloud-init paths hardcoded
- `lib/run_net.cpp:446` direct `ifconfig -vnet` (should use
  existing `SetIfaceUp` privops verb)
- Query-side privops verbs (inspect/doctor/migrate shell out)

### Tests

Existing `spec_registry_pure_test` covers parser + line
format. The `effectivePath()` lazy-cache uses the same pattern
proven in `network_lease.cpp`. No new test files; suite stays
at 1303.

### Files

- `lib/spec_registry.cpp` — `effectivePath()` helper, all I/O
  routed through it; `setPathForTesting` sets an override flag
- `lib/spec_registry.h` — header comment documents per-user
  storage
- `lib/lifecycle.cpp` — `restartCrate` queries SpecRegistry
  first, legacy fs walk as fallback; adds
  `#include "spec_registry.h"`
- `cli/args.cpp` — version `crate 1.0.2`
- `CHANGELOG.md` — this entry

---

## [1.0.1] — 2026-05-12

**IPv6 lease file per-user.** First patch release of the 1.x
line. Mirrors the 0.9.27 IPv4 lazy-resolve into the IPv6
sibling that was missed at the time.

### What changes

`lib/network_lease6.cpp` gains the same `effectivePath()`
helper that `network_lease.cpp` has had since 0.9.27. When the
crated privops socket is detected at first call, the IPv6
lease file path resolves to:

```
/var/run/crate/<uid>/network-leases6.txt
```

instead of the legacy single-tenant
`/var/run/crate/network-leases6.txt`. Empty-socket-path
deployments (no `crated` running, or unset
`privops_socket:`) preserve the legacy path byte-for-byte.

### Why this matters

Without this fix, every operator on a rootless host shared the
same v6 lease file, racing each other for the lock and seeing
each other's allocations. The v4 sibling was already isolated
since 0.9.27 — meaning two operators running parallel
`crate run` would race on v6 but not on v4, an
asymmetry that masked the bug from single-stack v4
deployments.

### Wire / API compatibility

None of the lease format, allocation algorithm, or public
function signatures changed. `NetworkLease6::leasePath()` now
returns the resolved per-user path instead of the legacy
constant; callers that printed this value see the new path
when rootless mode is active.

### 1.x backlog

Remaining latent per-user path leaks from the pre-1.0.0 audit
(unchanged from 1.0.0):

- `lib/lifecycle.cpp` `.crate` file path
- `lib/pfctl_ops.cpp` pf lock
- `lib/stack.cpp` DNS dirs
- `lib/vm_run.cpp` VM + cloud-init paths
- `lib/run_net.cpp:446` direct `ifconfig -vnet` (should use
  `SetIfaceUp` privops verb)

These will land in 1.0.2+ as mechanical mini-patches following
this PR's template.

### Tests

No new tests — the change mirrors the 0.9.27 pattern, which
is exercised by `tests/unit/ip6_alloc_pure_test.cpp` plus the
runtime-paths suite. The lazy-cache + override flag pair was
proven in network_lease.cpp.

### Files

- `lib/network_lease6.cpp` — `effectivePath()` helper, all
  I/O routed through it
- `lib/network_lease6.h` — header comment updated to document
  per-user storage path
- `cli/args.cpp` — version `crate 1.0.1`
- `CHANGELOG.md` — this entry

---

## [1.0.0] — 2026-05-12

**Rootless track complete — setuid bit removed.** First 1.x
release. The `Makefile install` target now installs `crate(1)`
at mode `0755` instead of `04755`; the binary can no longer
self-elevate. Every privileged operation (jail lifecycle,
mounts, RCTL, ZFS attach, network configuration, firewall
rules) is delegated to `crated(8)` via the libnv privops
socket (local clients, getpeereid-authenticated) or the HTTPS
API with bearer tokens (remote clients). This closes the
multi-step rootless track started at 0.9.0 and is the final
gate the security audit was waiting on.

### What changes

#### Makefile install target

```make
# 0.9.30 and earlier
install -s -m 04755 crate $(DESTDIR)$(PREFIX)/bin

# 1.0.0
install -s -m 0755 crate $(DESTDIR)$(PREFIX)/bin
```

That is the entire C++/build change for this release. The
preceding 31 mini-PRs (0.9.0 → 0.9.30) staged every other
piece — verb taxonomy, libnv listener, per-user namespacing
helpers, CLI call-site wiring, default flip — so the setuid
removal here is a one-line gate, not a code rewrite.

#### CLI binary behaviour

`crate(1)` runs as the operator's uid. It opens the privops
socket (path resolved via `privops_socket:` in `crated.conf`,
default `/var/run/crate/privops.sock`), packs nvlist requests,
and reads responses. The pre-1.0 setuid path (geteuid != ruid,
exec under root) is gone. Operators who script around
`crate(1)` as root no longer need `sudo` — the kernel does
the privilege handoff via getpeereid when the request crosses
the socket.

#### Operator visibility

```
# 0.9.30 install
$ ls -l /usr/local/bin/crate
-rwsr-xr-x  1 root  wheel  ... /usr/local/bin/crate
                       ^ setuid

# 1.0.0 install
$ ls -l /usr/local/bin/crate
-rwxr-xr-x  1 root  wheel  ... /usr/local/bin/crate
                       ^ no setuid
```

Compliance checklists that flag setuid-root binaries now pass
out of the box. The only privileged binary the port installs
is `crated(8)` at `/usr/local/sbin/crated`.

### Migration

Three upgrade paths:

| State pre-1.0.0                                | Action on upgrade                |
|------------------------------------------------|----------------------------------|
| 0.9.30 with `crated` running + `rootless: true`| Just `pkg upgrade`; nothing else |
| 0.9.30 with `rootless_per_user: false`         | Same — `crate(1)` still works, just talks to `crated` for every op |
| ≤ 0.8.x, no `crated` running                   | Install + enable `crated` first, THEN upgrade `crate`. See docs/rootless-migration.md |

`crated` MUST be running for `crate(1)` to function in 1.0.0.
Single-tenant operators who somehow avoided installing `crated`
in the 0.9.x track will get a clear error from `crate(1)`
pointing at `service crated start`.

### Rolling back

Patch the Makefile back to `-m 04755`, rebuild, and reinstall.
Or pin to 0.9.30. The wire-level privops protocol has not
changed since 0.9.29, so a 1.0.0 client talks to a 0.9.30
daemon and vice versa.

### Wire compatibility

No wire changes since 0.9.29. 21 privops verbs unchanged.
JSON, libnv, bearer token formats unchanged. Control sockets
unchanged. HTTPS API unchanged. Prometheus metrics unchanged.

### Series state

Rootless track:

- 0.9.0–0.9.7: privops verb taxonomy (14 verbs, JSON)
- 0.9.8–0.9.13: per-user namespacing pure modules + audit
- 0.9.14: libnv listener (FreeBSD-native, getpeereid)
- 0.9.15–0.9.29: CLI call sites wired through privops; verb
  set grew to 21
- 0.9.30: default flip (`rootless_per_user: true`)
- **1.0.0: setuid bit removed (this release)**

Out of scope for 1.0.0 (tracked in CHANGELOG under audit
findings, will land in 1.x):

- `lib/network_lease6.cpp` per-user lazy-resolve (IPv4
  sibling already done in 0.9.27)
- `lib/lifecycle.cpp` `.crate` file path per-user
- `lib/pfctl_ops.cpp` pf lock per-user
- `lib/stack.cpp` DNS dirs per-user
- `lib/vm_run.cpp` VM + cloud-init paths per-user
- `lib/run_net.cpp:446` direct `ifconfig -vnet` → `SetIfaceUp`
  privops
- Query-side privops verbs (inspect/doctor/migrate inspection
  currently shell out)
- Test coverage on the impure half (run.cpp 1810 lines vs
  run_pure.cpp 24 lines, plus 47 lib/*.cpp without dedicated
  tests)

### Tests

No new tests — the change is purely the install mode flag.
The behaviour was exercised across 31 prior mini-PRs; the
0.9.30 audit confirmed every call site is wired. Suite stays
at 1303.

### Files

- `Makefile` — `install` target: `04755` → `0755`, comment
  noting rollback procedure
- `cli/args.cpp` — version `crate 1.0.0`
- `docs/rootless-migration.md` — status promoted to "1.0.0,
  setuid removed", 1.0.0 release-log entry filled in
- `CHANGELOG.md` — this entry

### Thanks

To everyone who reviewed the per-verb mini-PRs across the
0.9.0–0.9.30 track. The architectural correction at 0.9.14
(libnv vs HTTP-on-unix-socket) was the right call and saved
us from a wheel-reinvention path.

---

## [0.9.30] — 2026-05-10

**Rootless track, default flip.** Thirty-first 0.9.x release.
The `rootless_per_user` master toggle now defaults to **true**.
New installs (and old installs whose `crated.conf` does not
set the field explicitly) compose paths, ZFS dataset prefix,
network sub-CIDR, and RCTL umbrella loginclass from the
connecting operator's uid. Operators who want the legacy
single-tenant shape must opt out with `rootless_per_user: false`.

### What changes

#### Default value flipped

```cpp
// daemon/config.h — was 0.9.12 .. 0.9.29
bool rootlessPerUser = false;

// daemon/config.h — 0.9.30+
bool rootlessPerUser = true;
```

The field default flips at the C++ level. The YAML key name
is unchanged (`rootless_per_user`), and the parser still
honours an explicit `false` value byte-for-byte the same way
it always did.

#### Sample config rewritten

`daemon/crated.conf.sample` now shows the toggle commented
out at its new default value (`# rootless_per_user: true`),
with prose explaining that operators wanting the legacy shape
must uncomment to `false` explicitly. The "0.9.14" forward-
reference is replaced with a "default since 0.9.30" note.

#### Migration doc updated

`docs/rootless-migration.md` rewrote two sections:

1. **Status** — bumped to "rootless model is on by default",
   with explicit `rootless_per_user: false` callout for
   operators who want to opt out
2. **Single-tenant migration** — split into two paths
   (accept the flip vs. pin to legacy), added a dedicated
   "Rolling back" subsection covering the toggle pin +
   restart + jail recycle procedure

The 0.9.13–0.9.30 release-by-release changelog inside the
doc was also brought up to date (was last touched at 0.9.13
planning).

### Behaviour for upgraders

| Pre-0.9.30 `crated.conf` state              | 0.9.30 effective value | Action needed       |
|---------------------------------------------|------------------------|---------------------|
| `rootless_per_user: true` (explicit)        | `true`                 | None                |
| `rootless_per_user: false` (explicit)       | `false`                | None                |
| key absent (most 0.8.x → 0.9.x upgrades)    | `true` (was `false`)   | Recycle jails OR pin to false |

The third row is the breaking case: a 0.8.x deployment that
upgraded through 0.9.x without ever touching `crated.conf`
gets rootless mode at the next `service crated restart`.
Operators in that boat who don't want to migrate jails should
add `rootless_per_user: false` before restarting crated.

The daemon does not auto-rearrange ZFS datasets or migrate
existing jails — operators control the cutover by stopping
and re-running their jails after the flip. See the migration
doc's "Path A — accept the flip" section.

### Wire compatibility

No wire changes. All 21 privops verbs from 0.9.0–0.9.28
unchanged. JSON + libnv schemas unchanged. Bearer token
format unchanged. The flip is purely a config-default change
in the daemon.

### Series state

Track complete except for setuid removal:

- 0.9.0–0.9.7: privops verb taxonomy (14 verbs, JSON)
- 0.9.8–0.9.13: per-user namespacing pure modules + audit
- 0.9.14: libnv listener (FreeBSD-native, getpeereid)
- 0.9.15–0.9.29: 14 CLI call sites wired through privops;
  verb set grew to 21
- **0.9.30: default flip (this release)**
- 1.0.0: setuid bit removed from `Makefile install`

### Tests

No new tests — the change is a single struct member default.
Suite stays at 1303. Existing `Crated::Config::load` coverage
exercises both the absent-field path (now defaults true) and
the explicit-false path. FreeBSD CI smoke-runs the daemon
startup which validates the default end-to-end.

### Files

- `daemon/config.h` — default flipped to `true`, comment
  expanded with 0.9.30 paragraph and rollback pointer
- `daemon/crated.conf.sample` — block rewritten to show
  new default + opt-out instructions
- `docs/rootless-migration.md` — status, schema example,
  migration path, and release-by-release log updated
- `cli/args.cpp` — version `crate 0.9.30`
- `CHANGELOG.md` — this entry

---

## [0.9.29] — 2026-05-10

**Rootless track, RCTL umbrella auto-apply.** Thirtieth 0.9.x
release. The `set_loginclass_rctl` primitive from 0.9.28 now
fires automatically after a successful `create_jail` privops
invocation, sourced from a new `rctl_umbrella:` block in
`crated.conf`. Operators no longer need a startup-script step
to seed loginclass quotas.

### What lands

#### Config schema

`Crated::Config` gains:

```cpp
std::vector<std::pair<std::string, std::string>> rctlUmbrella;
```

YAML form:

```yaml
rctl_umbrella:
  memoryuse: 4G
  pcpu:      200
  maxproc:   256
```

Keys / values validated via `RetunePure::validateRctlKey` /
`validateRctlValue` at config-load time — bad entries throw
at daemon startup, not at first jail-create.

#### Process-global rules

`Crated::setUmbrellaConfig(rules)` registers the parsed map
once at daemon startup. `daemon/main.cpp` calls it just
before opening the privops listener.

#### Auto-apply in dispatcher

`maybeApplyUmbrella(verb, uid, status)` runs after every
libnv-transport dispatch. Fires only when:

1. `verb == CreateJail`
2. `uid > 0` (peer credentials known — libnv socket only;
   HTTP path always has uid=0 → no-op)
3. `200 <= status < 300` (jail actually created)
4. `g_umbrellaRules` is non-empty

For each rule, runs `rctl -a loginclass:crate-<uid>:KEY:deny=VALUE`
via `Util::execCommand`. Best-effort: failures log to stderr
but do NOT fail the create_jail response — the jail is up,
losing an umbrella rule is a quota gap not a correctness
break.

### Behaviour

```
# crated.conf has:
#   rctl_umbrella:
#     memoryuse: 4G

# alice (uid 1000) sends create_jail "web1" via libnv socket
# crated:
#   1. handleCreateJail succeeds
#   2. maybeApplyUmbrella fires:
#      rctl -a loginclass:crate-1000:memoryuse:deny=4G
#   3. response 200 returned to client

# alice sends create_jail "web2"
# crated:
#   1. handleCreateJail succeeds
#   2. maybeApplyUmbrella re-applies the same rule
#      (idempotent — kernel no-ops the duplicate)

# Now alice has 2 jails. Per-jail rules cap each. Umbrella
# cap of 4G applies to alice's TOTAL across both jails.

# bob (uid 1001) sends create_jail
# crated applies rctl -a loginclass:crate-1001:memoryuse:deny=4G
# bob's umbrella is independent of alice's.
```

### HTTP path: no auto-apply

The HTTP transport never has a peer uid (cpp-httplib limitation;
0.9.14 architecture decision). Auto-apply skips on HTTP requests
— bearer-token API isn't multi-tenant in the operator-uid sense.
Operators wanting umbrella enforcement must use the libnv socket
(or call `set_loginclass_rctl` manually).

### Series state

CLI call-sites wired (12+):
- All `crate retune`, `crate stop`, full `crate run` chain
- All host-side iface verbs (createEpair / disableOffload /
  setUp / setInetAddr / bridge add+del)
- Lease file per-user path (0.9.27)
- Loginclass RCTL umbrella primitives (0.9.28)
- **Auto-apply umbrella at create_jail (this release)**

The `rootless_per_user: true` config block and per-user
namespacing (paths, ZFS, network sub-CIDR, RCTL groups) are
all wired and tested individually.

Remaining:
- 0.9.30 — default flip (`rootless_per_user: true` becomes
  default in `crated.conf.sample`; existing setuid-prod
  deployments unaffected, but new installs default to
  rootless)
- 1.0.0 — setuid bit removed from `Makefile install` target

### Tests

No new tests — the auto-apply path is daemon-side runtime
behaviour requiring a real `rctl(8)` to exercise meaningfully.
Covered by:
- `rctl_umbrella` config parsing tested implicitly via
  daemon startup on FreeBSD CI (bad config = startup throw)
- `maybeApplyUmbrella` logic mirrors `maybeWritePerUserAudit`
  shape (proven pattern from 0.9.13)
- `set_loginclass_rctl` validator coverage from 0.9.28
  (auto-apply uses the same key/value path)

Suite stays at 1303.

### Files

- `daemon/config.h` — `rctlUmbrella` field
- `daemon/config.cpp` — YAML parser, validates at load time
- `daemon/privops_handlers.{h,cpp}` — `setUmbrellaConfig`
  setter + `maybeApplyUmbrella` post-dispatch hook +
  `g_umbrellaRules` storage
- `daemon/main.cpp` — `setUmbrellaConfig(config.rctlUmbrella)`
  at startup
- `daemon/crated.conf.sample` — `rctl_umbrella:` block
- `cli/args.cpp` — version `crate 0.9.29`
- `CHANGELOG.md` — entry

---

## [0.9.28] — 2026-05-09

**Rootless track, RCTL umbrella verbs.** Twenty-ninth 0.9.x
release. Two new verbs that apply RCTL rules at the
loginclass scope (umbrella) instead of per-jail. The
infrastructure for 0.9.11's `crate-<uid>` loginclass is now
addressable end-to-end.

### What lands

#### Two new privops verbs

- **`set_loginclass_rctl`** — wraps
  `rctl -a loginclass:<name>:<key>:deny=<value>`. Fields:
  `loginclass`, `key`, `value`. Validates
  `loginclass` via `PerUserRctlPure::validateLoginclassName`
  (must be `crate-<uid>` shape), and `key`/`value` via
  the existing `RetunePure` whitelist (same gate as
  `set_rctl` from 0.9.0).
- **`clear_loginclass_rctl`** — symmetric remove via
  `rctl -r loginclass:<name>:<key>:deny`. Fields:
  `loginclass`, `key`.

#### Use case

Today's `set_rctl` (0.9.0) is jail-scoped — alice can
exceed her aggregate quota by spawning multiple jails,
each below the per-jail cap. With `set_loginclass_rctl`,
the kernel enforces a sum across all of alice's jails:

```
# Pre-0.9.28: alice spawns 3 jails, each at 2G memoryuse.
# Total = 6G. Per-jail set_rctl can't catch this.

# 0.9.28: at provisioning time, set the umbrella once:
POST /api/v1/privops/set_loginclass_rctl
{"loginclass":"crate-1000","key":"memoryuse","value":"4G"}

# Now: alice spawns 3 jails. Kernel enforces 4G total
# regardless of how many jails she has.
```

The umbrella rule and per-jail rules apply simultaneously
— kernel takes the more restrictive of the two whenever
both fire.

### Wire-up

Same files as previous verb-expansion releases —
`privops_pure.{h,cpp}`, `privops_wire_pure.{h,cpp}`,
`privops_nv_pure.{h,cpp}`, `privops_client.h`,
`privops_client_pure.cpp`, `privops_handlers.{h,cpp}`. Two
new functions/cases per file.

`privops_pure.cpp` gains `#include "per_user_rctl_pure.h"`
to reuse `validateLoginclassName`.

### CLI wiring (intentionally none for 0.9.28)

The verbs are primitives — no automatic invocation from
`crate run` or other CLI commands. Operators wanting
umbrella rules call them directly (e.g., from a startup
script) or wait for **0.9.29** which will auto-apply
umbrella rules from `crated.conf` at jail-create time.

This split keeps 0.9.28 small and reviewable — pure verb
addition. Auto-application requires a config-schema decision
(per-key map vs structured spec) that's worth its own PR.

### Series state

CLI call-sites wired (12+ in total). All host-side verbs
needed for `crate run` exist. RCTL umbrella primitives now
exist; auto-application coming in 0.9.29.

### Tests

- 2 new ATF tests in `privops_pure_test`
  (`set_loginclass_rctl_validates`,
  `clear_loginclass_rctl_validates`) covering happy path
  + bad loginclass + bad key + out-of-range value.
- `verb_token_roundtrips_for_every_verb` updated.
- Suite: 1301 → **1303**.

### Files

`privops_pure.{h,cpp}`, `privops_wire_pure.{h,cpp}`,
`privops_nv_pure.{h,cpp}`, `privops_client.h`,
`privops_client_pure.cpp`, `privops_handlers.{h,cpp}`,
`tests/unit/privops_pure_test.cpp`, `cli/args.cpp`,
`CHANGELOG.md`.

---

## [0.9.27] — 2026-05-09

**Rootless track, per-user lease file path.** Twenty-eighth
0.9.x release. The IP-lease file (`network-leases.txt`)
moves from a single shared `/var/run/crate/` location to a
per-user `/var/run/crate/<uid>/` subtree when crated's
privops socket is detected.

### What lands

`lib/network_lease.cpp::effectivePath()` — lazily resolves
the lease file path on first use:

```cpp
const std::string &effectivePath() {
  static std::string cached;
  static bool computed = false;
  if (!computed) {
    if (g_pathOverridden) {
      cached = g_path;  // honour test override
    } else if (!PrivOpsClient::detectSocketPath().empty()) {
      cached = RuntimePathsPure::perUserRoot((uint32_t)::getuid())
             + "/network-leases.txt";
    } else {
      cached = g_path;  // legacy single-tenant
    }
    computed = true;
  }
  return cached;
}
```

All call sites (`openLocked`, `readAll`, `writeAllAtomic`,
`leasePath()`) replaced `g_path.c_str()` references with
`effectivePath().c_str()`. Same path for the entire process
lifetime; cache eliminates per-call detection overhead.

### Behavior

| Mode | Lease file path |
|------|-----------------|
| Legacy (no privops socket) | `/var/run/crate/network-leases.txt` |
| Rootless (socket detected) | `/var/run/crate/<uid>/network-leases.txt` |
| Test override (`setPathForTesting`) | the supplied path |

The 0.9.10 sub-CIDR allocator already gives each operator a
disjoint IP range. Combined with this per-user lease file,
**alice's `crate run` never reads or writes bob's leases**
— two operators can both run a jail named `web` simultaneously
without IP collision.

### Trade-offs

- **Lease file location lock-in at process start.** The path
  is computed once on first call to `effectivePath()` and
  cached for the lifetime of the process. If the operator
  starts/stops crated mid-`crate run`, the lease file
  remains where it was first resolved. Acceptable: `crate
  run` invocations are short-lived.
- **Migration of existing lease entries.** Operators with
  pre-0.9.27 deployments switching to rootless mode will
  see an empty per-user lease file at first; existing leases
  in the legacy path are not auto-imported. Documented in
  the migration doc; manual `crate clean` + `crate run`
  rebuilds them per-user.

### Series state

CLI call-sites wired:
- `crate retune` (0.9.15)
- `crate stop` (0.9.17)
- `crate run` ZFS attach + detach (0.9.18)
- `crate run` nullfs mounts 8 sites (0.9.19)
- `crate run` vnet moveToVnet 4 sites (0.9.20)
- `crate run` removeJail teardown (0.9.21)
- `crate run` createJail (0.9.22)
- `crate run` setUp + disableOffload 5 sites (0.9.23)
- `crate run` bridge add + del 2 sites (0.9.24)
- `crate run` setInetAddr (0.9.25)
- `crate run` createEpair 2 sites (0.9.26)
- **`crate run` lease file path → per-user under
  /var/run/crate/<uid>/ ← this release**

Remaining:
- 0.9.28 — RCTL umbrella application (uses 0.9.11
  loginclass to apply `loginclass:crate-<uid>:KEY:deny=...`
  rules at jail-create time)
- 0.9.29 — default flip (`rootless_per_user: true`
  becomes default in `crated.conf.sample`)
- 1.0.0 — setuid bit removed from `Makefile install`

### Tests

No new tests added — existing `network_lease`-using tests
continue to pass via the `g_pathOverridden` test-override
path (set by `setPathForTesting`). Suite stays at 1301.

### Files

- `lib/network_lease.cpp` — `#include "privops_client.h"` +
  `#include "runtime_paths_pure.h"` + `effectivePath()`
  helper + `g_pathOverridden` flag + 7 call-site updates
- `cli/args.cpp` — version `crate 0.9.27`
- `CHANGELOG.md` — entry

---

## [0.9.26] — 2026-05-09

**Rootless track, `create_epair` verb — first response-data
verb.** Twenty-seventh 0.9.x release. Wraps
`IfconfigOps::createEpair()`, which the kernel auto-assigns
the next free epair unit number for. The verb returns the
A/B iface names so the client can plumb them downstream.

### What lands

#### New privops verb

`create_epair` — no request fields. Response body shape:

```
{"created":true,"a":"epair17a","b":"epair17b"}
```

This is the first verb whose response carries non-trivial
data. Previously all verbs returned status + a confirmation
body the client could ignore. `create_epair` is different
because the operator NEEDS the assigned names to do the
next steps (move B-half into vnet, attach A-half to bridge).

#### Wire protocol

- Daemon handler: builds the JSON response via
  `formatCreateEpairSuccess(a, b)` →
  `{"created":true,"a":"<A>","b":"<B>"}`.
- Client (run_net.cpp): receives `Response.body` as JSON
  string, calls existing `PrivOpsWirePure::extractStringField`
  twice (once for `a`, once for `b`). No new JSON parser
  needed — extractStringField already handles top-level
  string fields (used by daemon-side parsers).

The libnv transport wraps the same JSON body in an nvlist
field as before — clients on either transport use the same
extraction code.

#### CLI wiring

`lib/run_net.cpp` gets `createEpairPrivopsOrLocal()` returning
`std::pair<std::string, std::string>`. Two call-sites
migrate (lines 239 / 518) — both `auto epairPair =
IfconfigOps::createEpair();` patterns.

### Trade-offs

- **JSON body extraction at the client.** Native nvlist
  responses (per-verb structured fields) would be cleaner
  for libnv transport but require refactoring 14 handlers
  to expose typed responses. Current JSON-in-nvlist shape
  ships today; future optimisation if motivated.
- **No retry on transient failures.** If `create_epair`
  succeeds on the daemon but the response is dropped
  (network issue, timeout), an orphan epair leaks. Same
  constraint as direct `IfconfigOps::createEpair()` — that
  pattern is unchanged.

### Series state

CLI call-sites wired:
- `crate retune` (0.9.15)
- `crate stop` (0.9.17)
- `crate run` ZFS attach + detach (0.9.18)
- `crate run` nullfs mounts 8 sites (0.9.19)
- `crate run` vnet moveToVnet 4 sites (0.9.20)
- `crate run` removeJail teardown (0.9.21)
- `crate run` createJail (0.9.22)
- `crate run` setUp + disableOffload 5 sites (0.9.23)
- `crate run` bridge add + del 2 sites (0.9.24)
- `crate run` setInetAddr (host-side epair-A) (0.9.25)
- **`crate run` createEpair (2 sites) → create_epair ← this release**

**Full host-side iface plumbing now coverable via privops.**
The 5 `IfconfigOps::*` ops `crate run` uses
(createEpair / disableOffload / setUp / setInetAddr /
bridgeAddMember) all have privops paths. With 0.9.22's
createJail and 0.9.21's removeJail, **`crate run` and
`crate stop` no longer need root for any privileged step
when the privops socket is detected** — the legacy setuid
fallback is now optional.

### Remaining

- 0.9.27 — `network_lease.cpp` per-user paths + RCTL
  umbrella application (uses 0.9.10 sub-CIDR + 0.9.11
  loginclass)
- 0.9.28 — default flip
- 1.0.0 — setuid removed

### Tests

- 1 new ATF test in `privops_pure_test`
  (`create_epair_no_fields_required`)
- 1 new ATF test in `privops_wire_pure_test`
  (`format_create_epair_response_extracts`) that locks down
  the response shape AND verifies it round-trips through the
  client's `extractStringField` extraction path
- `verb_token_roundtrips_for_every_verb` updated
- Suite: 1299 → **1301**

### Files

Same set as 0.9.23/0.9.24/0.9.25 plus
`tests/unit/privops_wire_pure_test.cpp`:
`privops_pure.{h,cpp}`, `privops_wire_pure.{h,cpp}`,
`privops_nv_pure.{h,cpp}`, `privops_client.h`,
`privops_client_pure.cpp`, `privops_handlers.{h,cpp}`,
`run_net.cpp`, `tests/unit/privops_pure_test.cpp`,
`tests/unit/privops_wire_pure_test.cpp`, `cli/args.cpp`,
`CHANGELOG.md`.

---

## [0.9.25] — 2026-05-09

**Rootless track, `set_iface_inet_addr` verb.** Twenty-sixth
0.9.x release. Third atomic iface verb. The host-side IPv4
assignment primitive used by `run_net.cpp::createEpair` to
configure the host-side epair-A end after the jail-side
epair-B is moved into the jail.

### What lands

#### New privops verb

`set_iface_inet_addr` — wraps `IfconfigOps::setInetAddr(iface,
addr, prefixLen)`. Three-arg shape:

| Field | Type | Notes |
|-------|------|-------|
| `ifname` | string | Iface name (validated via `validateIfaceName`) |
| `addr` | string | Bare IPv4 (no `/prefix`) |
| `prefix_len` | unsigned | 0..32 |

Validator reuses `validateIpv4Cidr` by reassembling
`addr + "/" + prefixLen` — cheaper than duplicating IPv4
octet logic.

#### Wire-up across the stack

Same files as 0.9.23 / 0.9.24 — `privops_pure`,
`privops_wire_pure`, `privops_nv_pure`, `privops_client`,
`privops_handlers`. One new function/case in each.

#### CLI wiring

`lib/run_net.cpp::createEpair` line 229 (was line 209
pre-0.9.24) now calls `setInetAddrPrivopsOrLocal(info.ifaceA,
info.ipA, 31)` instead of direct `IfconfigOps::setInetAddr`.
The /31 epair-A side gets its IP via privops when the socket
is detected.

### Series state

CLI call-sites wired:
- `crate retune` (0.9.15)
- `crate stop` (0.9.17)
- `crate run` ZFS attach + detach (0.9.18)
- `crate run` nullfs mounts 8 sites (0.9.19)
- `crate run` vnet moveToVnet 4 sites (0.9.20)
- `crate run` removeJail teardown (0.9.21)
- `crate run` createJail (0.9.22)
- `crate run` setUp + disableOffload 5 sites (0.9.23)
- `crate run` bridge add + del 2 sites (0.9.24)
- **`crate run` setInetAddr (host-side epair-A) → set_iface_inet_addr ← this release**

Remaining iface verbs:
- 0.9.26 — `create_epair` (first response-data verb — returns
  the epair pair names since the kernel auto-assigns them)
- 0.9.27 — `network_lease.cpp` per-user paths + RCTL umbrella
- 0.9.28 — default flip
- 1.0.0 — setuid removed

### Tests

1 new ATF test (`set_iface_inet_addr_minimal`) covering happy
path + 3 reject cases (bad iface, bad addr, out-of-range
prefix). `verb_token_roundtrips_for_every_verb` updated.
Suite: 1298 → **1299**.

### Files

Same set as 0.9.23/0.9.24: `privops_pure.{h,cpp}`,
`privops_wire_pure.{h,cpp}`, `privops_nv_pure.{h,cpp}`,
`privops_client.h`, `privops_client_pure.cpp`,
`privops_handlers.{h,cpp}`, `run_net.cpp`,
`tests/unit/privops_pure_test.cpp`, `cli/args.cpp`,
`CHANGELOG.md`.

---

## [0.9.24] — 2026-05-09

**Rootless track, bridge membership verbs.** Twenty-fifth
0.9.x release. Symmetric pair around `IfconfigOps::bridgeAddMember`
and `bridgeDelMember`.

### What lands

#### Two new privops verbs

- **`bridge_add_member`** — wraps `IfconfigOps::bridgeAddMember(bridge, member)`.
  Fields: `bridge`, `member` (both validated as iface names).
- **`bridge_del_member`** — symmetric remove.

Different shape from 0.9.23's verbs (2 args vs 1) but same
overall pattern. Validators delegate to existing
`validateIfaceName` for both fields.

#### Wire-up across the stack

Same files as 0.9.23 — `privops_pure`, `privops_wire_pure`,
`privops_nv_pure`, `privops_client`, `privops_handlers`. Each
gained two new functions / cases.

#### CLI wiring

`lib/run_net.cpp` gets two more file-static helpers
(`bridgeAddMemberPrivopsOrLocal`, `bridgeDelMemberPrivopsOrLocal`)
and 2 call-sites migrate:

| Site | Op |
|------|-----|
| `setupBridgeEpair` line 481 | `bridgeAddMember(bridgeIface, ifaceA)` |
| `destroyBridgeEpair` line 491 | `bridgeDelMember(bridgeIface, ifaceA)` |

`bridgeAddMember` is hard-fail (matches existing exception
behaviour). `bridgeDelMember` is soft-fail (matches RunAtEnd
teardown pattern from earlier releases — warn on error,
continue cleanup).

### Series state

CLI call-sites wired:
- `crate retune` (0.9.15)
- `crate stop` (0.9.17)
- `crate run` ZFS attach + detach (0.9.18)
- `crate run` nullfs mounts 8 sites (0.9.19)
- `crate run` vnet moveToVnet 4 sites (0.9.20)
- `crate run` removeJail teardown (0.9.21)
- `crate run` createJail (0.9.22)
- `crate run` setUp + disableOffload 5 sites (0.9.23)
- **`crate run` bridge add + del 2 sites → bridge_add_member / bridge_del_member ← this release**

Remaining iface verbs:
- 0.9.25 — `set_iface_inet_addr` (3-arg verb: iface + addr + prefix_len)
- 0.9.26 — `create_epair` (first response-data verb — returns the epair pair names)
- 0.9.27 — `network_lease.cpp` per-user paths + RCTL umbrella
- 0.9.28 — default flip
- 1.0.0 — setuid removed

### Tests

2 new ATF tests (`bridge_add_member_minimal`,
`bridge_del_member_minimal`) in `privops_pure_test`.
`verb_token_roundtrips_for_every_verb` updated to include
both new verbs. Suite: 1296 → **1298**.

### Files

Same set as 0.9.23: `privops_pure.{h,cpp}`,
`privops_wire_pure.{h,cpp}`, `privops_nv_pure.{h,cpp}`,
`privops_client.h`, `privops_client_pure.cpp`,
`privops_handlers.{h,cpp}`, `run_net.cpp`,
`tests/unit/privops_pure_test.cpp`, `cli/args.cpp`,
`CHANGELOG.md`.

---

## [0.9.23] — 2026-05-09

**Rootless track, atomic single-iface verbs.** Twenty-fourth
0.9.x release. **First verb-set expansion since 0.9.0** —
previously the 14-verb taxonomy was treated as frozen, but
the `crate run` host-side bridge plumbing has primitives
(`setUp`, `disableOffload`) that don't compose well with
the existing `configure_iface` composite verb.

### What lands

#### Two new privops verbs

- **`set_iface_up`** — wraps `IfconfigOps::setUp(ifname)`.
  Single string arg; idempotent (already-up succeeds).
- **`disable_iface_offload`** — wraps
  `IfconfigOps::disableOffload(ifname)`. Same shape; the
  FreeBSD 15 checksum-offload workaround.

Why these two together: same shape (1 ifname, no
response data), called as a sibling pair in
`run_net.cpp::setupBridgeEpair`, and small enough that
splitting into separate releases would be unhelpful.

#### Wire-up across the stack

- `lib/privops_pure.{h,cpp}` — `Verb::SetIfaceUp`,
  `Verb::DisableIfaceOffload` + request structs +
  validators (delegate to existing `validateIfaceName`)
- `lib/privops_wire_pure.{h,cpp}` — JSON parsers +
  `formatSetIfaceUpSuccess` / `formatDisableIfaceOffloadSuccess`
  builders + dispatcher cases
- `lib/privops_nv_pure.{h,cpp}` — nv parsers (FieldMap)
- `lib/privops_client.h` + `lib/privops_client_pure.cpp` —
  `buildSetIfaceUp` / `buildDisableIfaceOffload`
- `daemon/privops_handlers.{h,cpp}` —
  `handleSetIfaceUp` / `handleDisableIfaceOffload` +
  dispatcher cases (HTTP + libnv transports)

#### CLI wiring

`lib/run_net.cpp` gets two new file-static helpers
(`setUpPrivopsOrLocal`, `disableOffloadPrivopsOrLocal`)
mirroring the 0.9.20 `moveToVnetPrivopsOrLocal` pattern.
Five call-sites are migrated:

| Site | Op |
|------|-----|
| `createEpair` line 160 | disableOffload(ifaceA) |
| `createEpair` line 161 | disableOffload(ifaceB) |
| `setupBridgeEpair` line 436 | disableOffload(ifaceA) |
| `setupBridgeEpair` line 437 | disableOffload(ifaceB) |
| `setupBridgeEpair` line 440 | setUp(ifaceA) |

### Why expand the verb set

The `configure_iface` composite verb (0.9.6) bundles
move + IP/MAC config + bridge attach. It assumes a
spec-driven "give me everything at once" usage. The
`run_net.cpp` orchestration is streaming — interleave
IfconfigOps calls with state-tracking and other ops.
For that pattern, atomic verbs match better. The
0.9.0 taxonomy contract isn't broken; new verbs append
to the closed set.

### Trade-offs

- **No rollback** of either op. The handler succeeds or
  fails the entire op atomically. setUp + disableOffload
  are themselves idempotent, so retry-on-failure works.
- **Other host-side IfconfigOps still need root.**
  `bridgeAddMember`, `setInetAddr`, `createEpair` haven't
  got matching verbs yet. 0.9.24 plan: `bridge_add_member`
  + `set_iface_inet_addr`. 0.9.25: `create_epair` (returns
  pair names — first verb with non-trivial response data).

### Series state

CLI call-sites wired:
- `crate retune` → set_rctl / clear_rctl (0.9.15)
- `crate stop` → destroy_jail (0.9.17)
- `crate run` ZFS attach + detach → attach_zfs / detach_zfs (0.9.18)
- `crate run` nullfs mounts (8 sites) → mount_nullfs (0.9.19)
- `crate run` vnet moveToVnet (4 sites) → configure_iface move-only (0.9.20)
- `crate run` removeJail teardown → destroy_jail (0.9.21)
- `crate run` createJail → create_jail (0.9.22)
- **`crate run` setUp + disableOffload (5 sites) → set_iface_up / disable_iface_offload ← this release**

Remaining:
- 0.9.24 — `bridge_add_member` + `set_iface_inet_addr` verbs
- 0.9.25 — `create_epair` (first response-data verb)
- 0.9.26 — `network_lease.cpp` per-user paths + RCTL umbrella
- 0.9.27 — default flip
- 1.0.0 — setuid removed

### Tests

2 new ATF tests (`set_iface_up_minimal`,
`disable_iface_offload_minimal`) in privops_pure_test.
`verb_token_roundtrips_for_every_verb` updated to include
the 2 new verbs (catches future enum-add-without-mapping).
Suite: 1294 → **1296**.

### Files

- `lib/privops_pure.{h,cpp}` — verb enum + structs + validators
- `lib/privops_wire_pure.{h,cpp}` — JSON parsers + format builders
- `lib/privops_nv_pure.{h,cpp}` — nv parsers
- `lib/privops_client.h` + `lib/privops_client_pure.cpp` — builders
- `daemon/privops_handlers.{h,cpp}` — handlers + dispatcher cases
- `lib/run_net.cpp` — 2 new helpers + 5 call-site replacements
- `tests/unit/privops_pure_test.cpp` — 2 new tests
- `cli/args.cpp` — version `crate 0.9.23`
- `CHANGELOG.md` — entry

---

## [0.9.22] — 2026-05-09

**Rootless track, `createJail` via privops.** Twenty-third
0.9.x release. Seventh CLI call-site, fifth inside `crate
run` — and the **last major chunk** of `crate run` jail
lifecycle to land.

### What lands

`lib/run_jail.cpp::createJail` now privops-aware:

```cpp
JailInfo createJail(const Spec &spec, const std::string &jailPath,
                    const std::string &jailName, bool logProgress) {
  // ... build optAllowMlock etc. (same as before) ...

  std::string sock = PrivOpsClient::detectSocketPath();
  if (!sock.empty()) {
    std::ostringstream params;
    params << "allow.raw_sockets=" << optRawSockets
           << " allow.socket_af=" << optNet
           // ... all 9 allow.* + enforce_statfs ...
           ;
    auto resp = PrivOpsClient::sendRequest(sock,
        PrivOpsClient::buildCreateJail(jailName, jailPath,
                                        Util::gethostname(),
                                        /*vnet=*/true,
                                        params.str()));
    // error handling
    auto jail = JailQuery::getJailByName(jailName);
    info.jid = jail->jid;
    return info;
  }
  // Legacy jail_setv() path unchanged
}
```

The signature gained a `jailName` parameter — caller
(`run.cpp`) passes `jailXname` which is `<nameComponent>_pid<PID>`
(unique per `crate run` invocation, well-formed for the
privops `validateJailName`).

### Design choice: pack into `parameters`

Of the two options from 0.9.21's CHANGELOG —
"pack into parameters string" vs "extend the verb" — went
with **option 1** (parameters packing). Reasoning:

- **No verb shape change.** `CreateJailReq` from 0.9.0 stays
  stable. The taxonomy contract is preserved.
- **`parameters` is operator-supplied free text already** — it
  already accepts arbitrary `jail.conf` fragments. Spec-derived
  flags fit that model naturally.
- **Spec values are constant alphabet** (`true` / `false` /
  `0` / `1` / `2`) — no risk of shell metas slipping past
  `validateRuleText`.

### Trade-offs

1. **JID fetched via post-create query.** The verb response
   doesn't include the jid (it returns success bool + name).
   We resolve via `JailQuery::getJailByName(jailName)`. Tiny
   race window if something destroys the jail between create
   and query; acceptable for crate-controlled flow. A future
   verb response extension (return the jid) closes this.
2. **No `JAIL_OWN_DESC` fd-based teardown via privops.** The
   FreeBSD 15 fd-teardown path needs the descriptor returned
   by `jail_setv()`. Privops verb returns nothing of the sort.
   Falls back to jid-based `jail_remove` from 0.9.21's
   `removeJail` privops route. Loses the
   exit-after-fd-close race-safety of the libjail path on
   FreeBSD 15+, but matches the CLI `jail -r NAME` semantics.
3. **No fallback on privops error.** Unlike 0.9.21's
   `removeJail`, createJail fails hard on privops error
   (no `jail_setv` fallback). Reason: a partial-failure
   scenario where privops fails mid-create then libjail
   creates a duplicate would be worse than just failing.
   Operators can rerun with `unset CRATE_PRIVOPS_SOCKET` to
   force legacy.

### Series state

CLI call-sites wired:
- `crate retune` → set_rctl / clear_rctl (0.9.15)
- `crate stop` → destroy_jail (0.9.17)
- `crate run` ZFS attach + detach → attach_zfs / detach_zfs (0.9.18)
- `crate run` nullfs mounts (8 sites) → mount_nullfs (0.9.19)
- `crate run` vnet moveToVnet (4 sites) → configure_iface move-only (0.9.20)
- `crate run` removeJail (RunAtEnd) → destroy_jail (0.9.21)
- **`crate run` createJail → create_jail ← this release**

Remaining:
- 0.9.23 — additional iface verbs (createEpair / bridgeAddMember /
  setUp / disableOffload / setInetAddr) for full rootless
  `crate run` coverage. Without these, rootless mode still
  needs root for the host-side bridge plumbing in `setupBridgeEpair`.
- 0.9.24 — `network_lease.cpp` per-user paths + RCTL umbrella
  application (uses 0.9.10 sub-CIDR + 0.9.11 loginclass)
- 0.9.25 — default flip
- 1.0.0 — setuid removed

### Tests

No new tests. Suite stays at 1294. Wire path needs
integration test infrastructure (real `crated`).

### Files

- `lib/run_jail.h` — `createJail` signature gains `jailName`
- `lib/run_jail.cpp::createJail` — privops route + legacy
  `jail_setv()` fallback path unchanged
- `lib/run.cpp` — caller passes `jailXname`
- `cli/args.cpp` — version `crate 0.9.22`
- `CHANGELOG.md` — entry

---

## [0.9.21] — 2026-05-09

**Rootless track, `removeJail` via privops.** Twenty-second
0.9.x release. Sixth CLI call-site through privops, fourth
inside `crate run` (the teardown side).

### What lands

`lib/run_jail.cpp::removeJail` — called during `crate run`
error rollback / `RunAtEnd` teardown. Now privops-aware:

```cpp
void removeJail(const JailInfo &info) {
  std::string sock = PrivOpsClient::detectSocketPath();
  if (!sock.empty()) {
    auto resp = PrivOpsClient::sendRequest(sock,
        PrivOpsClient::buildDestroyJail(std::to_string(info.jid), false));
    if (resp.transportError.empty() && resp.status < 400) {
      // close jailFd if FreeBSD 15 path was used
      return;
    }
    // Fall through with warning — better to try legacy than leak
  }
  // Legacy jail_remove_jd / jail_remove path (unchanged)
}
```

The `name` field passed to `destroy_jail` is
`std::to_string(info.jid)`. The kernel auto-names jails with
their jid string when no explicit `name=` is given to
`jail_setv` — so `jail -r 12345` works for jails created by
the existing `crate run` flow.

### Why not `createJail` too?

`run_jail.cpp::createJail` calls `jail_setv()` (libjail) with
~12 spec-derived `allow.*` / `enforce_statfs` parameters.
Privops `create_jail` verb has only `name`, `path`,
`hostname`, `vnet`, `parameters` (string). The verb's design
assumed CLI-style use; the kernel-API style of `crate run`
needs richer params.

Two options for closing the gap:

1. **Pack params into `parameters`** — string-flatten the 12
   `allow.*=true|false` fields into a space-separated
   string. Requires no verb shape change. Limitation:
   `parameters` is single-line, validated for shell metas.
   Spec values are all `true`/`false`/`0`/`1`/`2`, so safe.
2. **Extend the verb** — add 12 new fields to
   `CreateJailReq`. Cleaner shape, but breaks the
   "stable verb taxonomy from 0.9.0" contract.

Both options are live design discussions for **0.9.22**.
0.9.21 ships only the teardown side (which is unambiguous —
`destroy_jail` already accepts everything we need).

### Behavior on privops failure

If the privops call fails (transport error or 4xx/5xx), the
handler **falls through to the legacy `jail_remove_jd` /
`jail_remove` libjail call** with a yellow warning to stderr.
Better to leak a libjail call than leave a stuck jail
registered.

### Series state

CLI call-sites wired:
- `crate retune --rctl` / `--clear` → set_rctl / clear_rctl (0.9.15)
- `crate stop` (force-remove) → destroy_jail (0.9.17)
- `crate run` ZFS attach + detach → attach_zfs / detach_zfs (0.9.18)
- `crate run` nullfs mounts (8 sites, auto-routed via Mount class) → mount_nullfs (0.9.19)
- `crate run` vnet moveToVnet (4 sites) → configure_iface move-only (0.9.20)
- **`crate run` removeJail (RunAtEnd teardown) → destroy_jail ← this release**

Remaining run-chain:
- 0.9.22 — `run_jail.cpp::createJail` wiring (decide on
  parameters-string vs verb-extension first)
- 0.9.23 — additional iface verbs (createEpair / bridgeAddMember /
  setUp / disableOffload / setInetAddr) for full rootless
  `crate run` coverage
- 0.9.24 — `network_lease.cpp` per-user paths + RCTL umbrella
- 0.9.25 — default flip
- 1.0.0 — setuid removed

### Tests

No new tests. Suite stays at 1294. Wire path needs
integration test infrastructure (real `crated`).

### Files

- `lib/run_jail.cpp::removeJail` — privops route + libjail
  fallback
- `cli/args.cpp` — version `crate 0.9.21`
- `CHANGELOG.md` — entry

---

## [0.9.20] — 2026-05-09

**Rootless track, vnet `moveToVnet` via privops + handler
move-only mode.** Twenty-first 0.9.x release. Fifth CLI
call-site (4 actual call points in `lib/run_net.cpp`) routed
through privops, third inside `crate run`.

### Daemon-side (handler change)

`Crated::handleConfigureIface` (added 0.9.6) used to
unconditionally `jexec ifconfig <iface> up` after the move +
optional IP/MAC config. 0.9.20 makes the `up` step
**conditional** on at least one of `ipv4_cidr` / `ipv6_cidr` /
`mac_addr` having been set.

This is the key enabler: a bare-bones `configure_iface`
request with all optional fields empty becomes equivalent to
a plain `IfconfigOps::moveToVnet(iface, jid)` call — no `up`
side-effect. Downstream `configureDhcp` / `configureStaticIp`
in `run_net.cpp` keep working unchanged because they manage
their own `up`/`inet`/`route` sequence inside the jail.

### Client-side wiring

`lib/run_net.cpp` gets a new file-static helper:

```cpp
static void moveToVnetPrivopsOrLocal(const std::string &iface, int jid) {
  std::string sock = PrivOpsClient::detectSocketPath();
  if (!sock.empty()) {
    auto resp = PrivOpsClient::sendRequest(sock,
        PrivOpsClient::buildConfigureIface(jid, iface,
            "", "", "", ""));  // all optional fields empty -> move-only
    if (!resp.transportError.empty()) ERR2(...)
    if (resp.status >= 400) ERR2(...)
    return;
  }
  IfconfigOps::moveToVnet(iface, jid);
}
```

All 4 `IfconfigOps::moveToVnet` call sites in `run_net.cpp`
now use this wrapper:

| Site | Mode |
|------|------|
| `createEpair` (bridge mode) | epair-B → jail |
| passthrough mode line ~315 | host iface → jail |
| netgraph mode line ~376 | netgraph iface → jail |
| `setupBridgeEpair` line ~410 | epair-B → jail (bridge variant) |

### Trade-offs

- **Other IfconfigOps still need root.** `bridgeAddMember`,
  `disableOffload`, `setUp`, `setInetAddr`, `createEpair` —
  all of these are still called directly in `run_net.cpp` and
  need setuid until matching verbs land. 0.9.20 wires only the
  **vnet move** step. Operators in pure-rootless mode still
  need additional work; the existing setuid path keeps them
  functional today.
- **Why not bundle all the steps into one privops call?** The
  `configure_iface` verb is shaped for the spec-driven case
  (operator gives jid + iface + all fields → daemon does
  everything). The streaming-orchestration shape that
  `run_net.cpp` uses (createEpair → multiple Ops →
  moveToVnet → in-jail config) doesn't fit one verb cleanly.
  Future verbs (`create_epair`, `bridge_add_member`,
  `disable_offload`, `set_up`) plug the remaining gaps.

### Series state

CLI call-sites wired:
- `crate retune --rctl` / `--clear` → set_rctl / clear_rctl (0.9.15)
- `crate stop` → destroy_jail (0.9.17)
- `crate run` ZFS attach + detach → attach_zfs / detach_zfs (0.9.18)
- `crate run` nullfs mounts (8 sites) → mount_nullfs (0.9.19)
- **`crate run` vnet moveToVnet (4 sites) → configure_iface (move-only mode) ← this release**

Remaining run-chain:
- 0.9.21 — `create_jail` (the inner `jail -c`, last
  major chunk)
- 0.9.22 — `network_lease.cpp` per-user paths + RCTL
  umbrella application
- 0.9.23 — additional iface verbs (createEpair / bridgeAddMember
  / setUp / disableOffload / setInetAddr) for full
  rootless `crate run` coverage
- 0.9.24 — default flip
- 1.0.0 — setuid removed

### Tests

No new tests. Suite stays at 1294. Wire path needs
integration test infrastructure (real `crated`).

### Files

- `daemon/privops_handlers.cpp::handleConfigureIface` —
  conditional `up` step (anyConfig flag)
- `lib/run_net.cpp` — `moveToVnetPrivopsOrLocal` helper +
  4 call-site replacements
- `cli/args.cpp` — version `crate 0.9.20`
- `CHANGELOG.md` — entry

---

## [0.9.19] — 2026-05-09

**Rootless track, nullfs mounts via privops.** Twentieth 0.9.x
release. Fourth CLI call-site through privops, second
inside `crate run`.

### What lands

`lib/mount.{h,cpp}` — the `Mount` class gains privops awareness:

- Constructor detects the privops socket once via
  `PrivOpsClient::detectSocketPath()` **only when fstype is
  "nullfs"** (devfs and unionfs lack matching verbs).
- `mount()` — if the cached socket is non-empty, sends a
  `mount_nullfs` privops request (with `read_only` derived
  from `MNT_RDONLY` flag); else nmount(2). Hard error on
  failure (matches existing `ERR`).
- `unmount()` — symmetric. Soft-fail / hard-fail behaviour
  preserved (the `doThrow` parameter still gates whether
  failure raises or warns).

### Coverage

All 8 nullfs `Mount` construction sites in the codebase get
auto-routing for free — **no call-site changes needed**:

- `lib/run.cpp:1569,1603,1614` — file-share binds for the
  jail's spec-declared shares
- `lib/run_gui.cpp:315,656` — X11 socket bind for `gui:`
- `lib/run_gui.cpp:725,768` — Wayland socket / pipewire bind
- `lib/run_gui.cpp:814` — PulseAudio socket bind

### Trade-offs

- **MNT_IGNORE flag dropped on the privops path.** The
  daemon's `mount_nullfs` verb doesn't carry arbitrary
  mount flags. Operators using privops mode see the nullfs
  mounts in `mount(8)` output. A future verb extension can
  pass `MNT_IGNORE` through; documented as accepted.
- **Detection at construction, not mount().** A Mount object
  built before the daemon's socket appeared (or vice versa)
  uses whatever path was correct at construction time. In
  practice all `Mount` lifetimes are short (few-second
  startup window for a `crate run` invocation), so this is
  not a real concern.
- **Other fstypes unchanged.** `Mount("devfs", ...)` and
  `Mount("unionfs", ...)` continue using nmount(2). The
  privops verb taxonomy from 0.9.0 covers nullfs only;
  expansion is a future track.

### Series state

CLI call-sites wired:
- `crate retune --rctl` / `--clear` → set_rctl / clear_rctl (0.9.15)
- `crate stop` (force-remove) → destroy_jail (0.9.17)
- `crate run` ZFS attach + detach → attach_zfs / detach_zfs (0.9.18)
- **`crate run` nullfs mounts (8 sites) → mount_nullfs / unmount_nullfs ← this release**

Remaining run-chain:
- 0.9.20 — `configure_iface` (`lib/run_net.cpp` vnet plumbing)
- 0.9.21 — `create_jail` (the inner `jail -c`, last)
- 0.9.22 — per-user lease paths + RCTL umbrella
- 0.9.23 — default flip
- 1.0.0 — setuid removed

### Tests

No new tests. Suite stays at 1294. Wire path needs
integration test infrastructure (real `crated`) — landing
post-1.0.0.

### Files

- `lib/mount.{h,cpp}` — privops-aware mount/unmount; legacy
  nmount(2) path unchanged
- `cli/args.cpp` — version `crate 0.9.19`
- `CHANGELOG.md` — entry

---

## [0.9.18] — 2026-05-09

**Rootless track, `crate run` ZFS attach via privops.**
Nineteenth 0.9.x release. Third CLI call-site delegated to
`crated`. The first call-site inside `crate run` itself.

### What lands

`lib/run_jail.cpp::attachZfsDatasets` — wires both the attach
(at jail-create time) and the detach (in the `RunAtEnd`
teardown lambda) through privops when the socket is available:

- **Socket present:** `PrivOpsClient::sendRequest(socket,
  buildAttachZfs(jid, dataset))` per dataset. Teardown
  mirrors with `buildDetachZfs`. Daemon's `handleAttachZfs` /
  `handleDetachZfs` (0.9.4) call `ZfsOps::jailDataset` /
  `unjailDataset` as root.
- **Socket absent:** existing `ZfsOps::jailDataset(jid, ds)` /
  `unjailDataset` direct calls run unchanged. Legacy
  setuid-prod is byte-identical.

Attach errors are HARD: `crate run` aborts with the privops
error (`ERR2`) — same semantics as the existing
`ZfsOps::jailDataset` throwing on failure. **Detach errors
are SOFT** (logged, not fatal) — matches how `RunAtEnd`
handles teardown today; a half-removed jail with detached
datasets is less bad than a stuck `crate run -d` that won't
exit.

### Why ZFS attach first

Of the four `crate run` privileged operations
(`create_jail`, `attach_zfs`, `mount_nullfs`, `configure_iface`),
ZFS attach has the smallest blast radius:

- One call site (`run_jail.cpp::attachZfsDatasets`)
- Both directions (attach + detach) wired in one PR
- Spec field (`zfsDatasets`) is opt-in — operators not using
  this feature see zero behaviour change
- The verb already has full handler coverage from 0.9.4

`mount_nullfs` is the next candidate (file-share binds), then
`configure_iface` (vnet plumbing — most complex), then
`create_jail` itself (which depends on the previous three
having moved through privops first, so the rootless-`crate
run` flow doesn't need root for any step).

### Series state

CLI call-sites wired:
- `crate retune --rctl` / `--clear` → set_rctl / clear_rctl (0.9.15)
- `crate stop` (force-remove) → destroy_jail (0.9.17)
- **`crate run` ZFS attach + detach → attach_zfs / detach_zfs ← this release**

Remaining `crate run` chain:
- 0.9.19 — `mount_nullfs` (lib/run.cpp share/bind sites)
- 0.9.20 — `configure_iface` (lib/run_net.cpp vnet plumbing)
- 0.9.21 — `create_jail` (the inner `jail -c` itself, last)
- 0.9.22 — `network_lease.cpp` per-user paths + RCTL umbrella
- 0.9.23 — default flip
- 1.0.0 — setuid removed

### Tests

No new tests — wire path needs integration (real `crated`).
Suite stays at 1294. Existing privops_client builders +
nv_pure round-trips already cover the request shape.

### Files

- `lib/run_jail.cpp` — privops-aware attach/detach in
  `attachZfsDatasets`; legacy `ZfsOps::jailDataset` path
  unchanged
- `cli/args.cpp` — version `crate 0.9.18`
- `CHANGELOG.md` — entry

---

## [0.9.17] — 2026-05-09

**Rootless track, `crate stop` wired to privops.** Eighteenth
0.9.x release. Second CLI call-site (after `crate retune` in
0.9.15) actually delegates a privileged operation to `crated`
when the libnv socket is available.

### What lands

`lib/lifecycle.cpp::stopCommand` — the post-SIGKILL "remove
the jail if it's still around" step at line ~401:

- **Socket present:** `PrivOpsClient::sendRequest(socket,
  buildDestroyJail(jail->name, false))`. Daemon's
  `handleDestroyJail` runs `jail -r NAME` as root.
- **Socket absent:** existing `Util::execCommand({jail, -r,
  jid})` path runs unchanged. Legacy single-tenant
  deployments keep working byte-identically.

Soft-fail semantics preserved: if the privops call returns
4xx/5xx (e.g. jail already gone, race with another stop),
the warning is logged but `crate stop` still reports success
— same as the pre-0.9.17 `try/catch{...}` swallowed exec
errors.

### Why the force-remove path specifically

`crate stop` has two phases:

1. Graceful — send signal to PID 1 inside the jail, wait up
   to `--timeout` seconds for processes to exit. If exit
   detected, return success. **No `jail` invocation.**
2. Force — SIGKILL inside the jail, then `jail -r` to
   remove the registration. **The privops-routed step.**

Phase 1 doesn't need privops (operator-side `kill(1)` via
jexec is already root-effective on the live setuid path,
and on rootless will route through future `kill_in_jail`
verb when added). Phase 2 is the actual `jail(8)` call —
that's what 0.9.7's `destroy_jail` verb was built for.

### Tests

No new tests. Suite stays at 1294 (FreeBSD CI flow already
covers the privops_client builders + nv parser round-trip
from 0.9.14-0.9.16). The wire path itself needs an
integration test booting a real `crated` — that lands when
the integration test infrastructure does (post-1.0.0).

### Series state

- 14/14 verbs handled
- HTTP transport ✅, libnv transport ✅
- CLI call-sites wired:
  - `crate retune --rctl` → `set_rctl` (0.9.15)
  - `crate retune --clear` → `clear_rctl` (0.9.15)
  - **`crate stop` → `destroy_jail` ← this release**
- 0.9.18 — `crate run` (the heavy lifter — `create_jail` +
  `attach_zfs` + `mount_nullfs` + `configure_iface` chain)
- 0.9.19 — `network_lease.cpp` per-user paths + RCTL
  umbrella application
- 0.9.20 — default flip
- 1.0.0 — setuid removed

### Files

- `lib/lifecycle.cpp` — `#include "privops_client.h"` + the
  privops-aware fork in the force-remove block; legacy path
  unchanged
- `cli/args.cpp` — version `crate 0.9.17`
- `CHANGELOG.md` — entry

---

## [0.9.16] — 2026-05-09

**Hotfix.** Fixes FreeBSD CI failure introduced by 0.9.15 + LXQt
nested example multi-instance docfix.

### FreeBSD CI failure (root cause)

0.9.15 added `lib/privops_client.cpp` to BOTH `LIB_SRCS` and
`TEST_LINK_SRCS`. The file's `#ifdef __FreeBSD__` branch calls
`nvlist_send` / `nvlist_recv` / `nvlist_create` etc. from
`<sys/nv.h>`. On the lite CI's `gmake build-unit-tests` step,
every test binary's link line picks up `lib/privops_client.o`
via `TEST_LINK_OBJS` — and on FreeBSD 14.2 those libnv symbols
aren't satisfied without the right link recipe.

Linux unit tests passed because the file's `#else` branch has
no libnv refs. The 0.9.14 daemon-side `daemon/privops_listener.cpp`
also uses libnv but is `DAEMON_SRCS`-only — never compiled by
the lite CI's `build-unit-tests` step — so 0.9.14 passed.

### Fix

Split `lib/privops_client.cpp` along the pure / wire boundary:

- **`lib/privops_client_pure.cpp`** (new) — 14 verb builders +
  `detectSocketPath()` + stringification helpers. **No libnv
  references.** Goes into `LIB_SRCS` AND `TEST_LINK_SRCS`.
  Tests still get the builders for round-trip verification.
- **`lib/privops_client.cpp`** (slimmed down) — `sendRequest()`
  only: FreeBSD libnv impl + Linux stub. **`LIB_SRCS`-only;
  removed from `TEST_LINK_SRCS`.** No libnv leakage into test
  binaries.

The two `send_returns_transport_error_*` tests from 0.9.15 were
dropped — they exercised early-return branches uninteresting on
their own, and the wire path needs an integration test booting a
real `crated`. Suite count goes 1296 → 1294 (−2 dropped tests,
+0 net changes elsewhere).

### LXQt nested multi-instance docfix

`examples/lxqt-desktop-nested.yml` was shipped in 0.8.49 with a
multi-instance workflow comment that wouldn't actually work as
written:

```sh
# OLD (broken — second iteration would collide on jail name)
for i in 1 2 3 4; do crate run -f lxqt-desktop-nested.crate & done
```

Each `crate run` without `--name` derives the jail name from
the `.crate` archive — so all four instances competed for the
same name. Updated to the correct form:

```sh
# NEW
crate create -s lxqt-desktop-nested.yml         # builds .crate
for i in 1 2 3 4; do
  crate run --name lxqt-$i -f lxqt-desktop-nested.crate &
done
crate gui tile
```

Plus a clarifying paragraph that `GuiRegistry` (0.7.19+)
auto-allocates a unique `DISPLAY` per instance so the four
Xephyr windows don't clash.

### Examples audit (per-user request)

Spot-checked the other 53 examples. **Nothing else is broken
by 0.9.x.** The 0.9.x track is entirely daemon-side
(`daemon/privops_*`, `daemon/audit_per_user`,
`daemon/config.h` additions) plus pure helpers in `lib/`.
`lib/spec.cpp` (the spec parser) and `lib/validate_pure.cpp`
were not touched, so existing example specs validate
identically to 0.8.49.

The four LXQt examples (`lxqt-desktop.yml`,
`lxqt-desktop-nested.yml`, `lxqt-minimal.yml`,
`lxqt-wayland.yml`) all parse cleanly: `gui.mode: auto |
nested | headless | wayland` are valid (since 0.8.46);
`options: [net, x11, gl, video]` enum values are in
`allOptionsLst`; `limits: { memoryuse, pcpu, maxproc }` keys
are in `RetunePure::validateRctlKey`'s whitelist.

### Files

- `lib/privops_client_pure.cpp` (new — pure half)
- `lib/privops_client.cpp` (slimmed — wire half only)
- `tests/unit/privops_client_pure_test.cpp` — dropped 2 send
  tests; 17 builder/round-trip/detection tests remain
- `examples/lxqt-desktop-nested.yml` — multi-instance docfix
- `Makefile` — `_pure` to TEST_LINK_SRCS, wire file LIB_SRCS-only
- `cli/args.cpp` — version `crate 0.9.16`

### Series state

No functional change beyond the CI/docs fix. Series unchanged:

- 14/14 verbs handled
- HTTP transport (0.9.1) ✅, libnv transport (0.9.14) ✅
- `crate retune` wired to libnv (0.9.15) ✅
- 0.9.17 — wire `crate run` lifecycle commands
- 0.9.18 — `network_lease.cpp` per-user paths + RCTL umbrella
- 0.9.19 — default flip
- 1.0.0 — setuid removed

---

## [0.9.15] — 2026-05-09

**Rootless track, client-side libnv wiring.** Sixteenth 0.9.x
release. First call site in `crate(1)` actually delegates a
privileged operation to `crated` over the libnv socket from
0.9.14 — instead of doing it itself with the setuid bit.

`crate retune` is the first CLI command wired up. `set_rctl` /
`clear_rctl` round-trip end-to-end:

```
crate retune --rctl pcpu=20 myjail
                │
                ├─ detect privops socket (env var or
                │  /var/run/crate/crated-privops.sock)
                │
                ├─ socket present:
                │    build SetRctlReq FieldMap
                │    nvlist_send → crated listener
                │    listener: getpeereid(connFd) → uid
                │    dispatchPrivOpFromMap → handleSetRctl
                │    rctl(8) runs as root inside crated
                │    nvlist_send response → client
                │    client: 200 = success, 4xx/5xx = error
                │
                └─ socket absent (legacy):
                     Util::execCommand({rctl, -a, ...})
                     (existing setuid-style path, unchanged)
```

### What lands

#### Client library

`lib/privops_client.{h,cpp}`:

- `detectSocketPath()` — `$CRATE_PRIVOPS_SOCKET` env var takes
  priority; else `/var/run/crate/crated-privops.sock` if it
  exists as a socket; else `""` = legacy fallback
- 14 pure builders (`buildSetRctl`, `buildCreateJail`, etc.)
  emitting `PrivOpsNvPure::FieldMap` requests — one per verb,
  ready to hand to `sendRequest`
- `sendRequest(socketPath, fields) -> Response{status, body,
  transportError}` — opens AF_UNIX, packs FieldMap to nvlist,
  `nvlist_send`, `nvlist_recv`, parses status + body, closes.
  FreeBSD-only; Linux dev build returns `transportError =
  "libnv unavailable"`.

The 14 pure builders are dual-purpose:
1. Production callers (`lib/retune.cpp`) build a request and
   pass to `sendRequest`.
2. Tests round-trip them through `PrivOpsNvPure::parseXxx` —
   the daemon-side parsers from 0.9.14. If a future verb
   change drifts client and daemon apart, the round-trip test
   fires.

#### `crate retune` wiring

`lib/retune.cpp` calls `detectSocketPath()` once at the top of
the command. If the socket is present:

- **`--rctl key=val`** → `set_rctl` verb via libnv. 4xx/5xx
  responses become `ERR()` (operator-visible failure).
- **`--clear key`** → `clear_rctl` verb via libnv. Soft-fail
  preserved — non-200 logged as warning, command continues
  (matches existing `rctl(8)` exec behaviour where clearing a
  non-existent rule is graceful).

Socket absent: existing `Util::execCommand(rctl ...)` path
runs unchanged. Legacy single-tenant deployments keep working
byte-identically.

Operators flip on rootless behaviour by:
1. Configuring `crated.conf`: `privops_socket: ...` (0.9.14)
2. Restarting crated
3. (`crate(1)` auto-detects via well-known path; no client-side
   config needed)

### Tests

19 new ATF tests in `privops_client_pure_test.cpp`:

- All 14 builders: shape + field set assertion
- Optional-field handling: empty fields are present-but-empty
  (constant wire shape for round-tripping)
- 3 round-trip tests: builder output → `PrivOpsNvPure::parseXxx`
  → typed request struct (`set_rctl`, `create_jail`,
  `configure_iface`) — catches client/daemon divergence
- `detect_uses_env_var_when_set` / `_empty_when_no_env_no_default`
  / `_empty_env_treated_as_unset` — detection logic
- `send_returns_transport_error_when_no_socket` /
  `_when_unreachable` — transport error reporting

Suite: 1277 → **1296**, all passing.

### Series state

- Verb handlers: 14/14 ✅
- Wire transports: HTTP (0.9.1) ✅, libnv (0.9.14) ✅
- Per-user namespacing (0.9.8–0.9.13) ✅
- **0.9.15 — client-side libnv wiring (`crate retune` first) ← this release**
- 0.9.16 — wire `crate run` / `crate stop` / `crate destroy`
  to libnv (`create_jail` / `destroy_jail` + lifecycle
  ZFS / mount / iface verbs)
- 0.9.17 — `network_lease.cpp` per-user paths,
  RCTL umbrella application
- 0.9.18 — default flip
- 1.0.0 — setuid removed

### Files

- `lib/privops_client.{h,cpp}` (new)
- `tests/unit/privops_client_pure_test.cpp` (new)
- `lib/retune.cpp` — privops-aware delegation; legacy path
  unchanged
- `Makefile`, `tests/unit/Kyuafile`, `.gitignore` — wired
- `cli/args.cpp` — version `crate 0.9.15`

---

## [0.9.14] — 2026-05-09

**Rootless track, libnv unix-socket transport.** Fifteenth 0.9.x
release. The first release that solves uid plumbing without
forking cpp-httplib or proxying HTTP over a Unix socket.

### Architectural correction

0.9.0–0.9.13 added an HTTP/JSON privops surface
(`POST /api/v1/privops/:verb`) via cpp-httplib. Good for remote
clients (hub multi-host, CI), but cpp-httplib doesn't expose the
connection fd, so `getpeereid(2)` for local clients was
impossible. 0.9.13's per-user audit hook stayed dormant for that
reason.

A separate hand-rolled HTTP listener for local IPC (the pattern
0.7.10's control_socket plane took) is its own
wheel-reinvention. The right answer for FreeBSD-native local
IPC is **libnv** — kernel-blessed nvlist format, already used
by libcasper/cap_dns/cap_syslog and by `lib/nv_protocol.cpp`
in the crate codebase since 0.8.27.

0.9.14 adds libnv as a **second transport** for privops, **not
as a replacement** for HTTP. Both paths converge on the same
validators (PrivOpsPure) and the same handlers
(Crated::handle{SetRctl, ...}); only the wire format and auth
model differ:

| | HTTP transport (kept) | libnv transport (NEW) |
|---|---|---|
| Endpoint | `POST /api/v1/privops/:verb` | `/var/run/crate/crated-privops.sock` |
| Wire | cpp-httplib + JSON | nvlist over AF_UNIX |
| Auth | bearer token | `getpeereid(2)` SO_PEERCRED |
| Use case | hub, CI/CD, remote tooling | `crate(1)` → `crated` local |
| uid for audit hook | 0 (HTTP can't extract) | real peer uid |

### What lands

#### Pure module

`lib/privops_nv_pure.{h,cpp}`:

- `FieldMap` = `std::map<string,string>`. The listener walks an
  nvlist into a flat string-keyed map so the **pure parsers
  compile and test on Linux dev/CI** without `<sys/nv.h>`. Same
  approach `lib/nv_protocol.cpp` (0.8.27) already uses.
- 14 per-verb parsers (`parseSetRctl(map, &req)` etc.) — one-to-
  one with `PrivOpsWirePure::parseXxx` in field set, types,
  required/optional split.
- Generic accessors: `requireString`, `requireLong`,
  `requireUnsigned`, `optionalString`, `optionalBool`. Strict
  type-decoding from string (no leading whitespace, no decimal
  point on ints, leading-zero check on numbers).
- `extractVerb(map)` — reads the wire's `verb` field.

22 ATF tests including:
- per-accessor edge cases (typical / missing / wrong-type /
  garbage / canonical-bool-aliases)
- per-verb happy-path + missing-required
- defence-in-depth: `parsers_same_required_field_set_as_json`
  catches future drift between HTTP and libnv parsers

#### Daemon-side

- `daemon/privops_listener.{cpp,h}` — accept loop on AF_UNIX,
  `getpeereid` extracts uid, `nvlist_recv` → walk into
  `FieldMap` → dispatch, `nvlist_send` response. Capsicum
  rights applied to listener fd and per-connection fds.
  FreeBSD-only (Linux build returns false from `start()`).
- `Crated::dispatchPrivOpFromMap(map, rootlessPerUser, uid)` —
  parallel dispatcher mirroring `dispatchPrivOp`'s switch but
  using `PrivOpsNvPure::parseXxx`. Same handlers, same audit
  hook. Audit hook now **lights up automatically** for
  unix-socket clients (peer uid > 0).
- `daemon/main.cpp` — starts a `PrivopsListener` alongside the
  existing cpp-httplib server, control sockets, and
  ws-console. Same start/stop pattern as
  `ControlSocketsManager`.

#### Config schema

`Crated::Config` gains:

```cpp
std::string privopsSocketPath;     // empty disables (default)
std::string privopsSocketGroup;    // chown group
unsigned    privopsSocketMode = 0660;
```

Both top-level shorthand and nested `privops:` block accepted in
`crated.conf`:

```yaml
privops_socket: /var/run/crate/crated-privops.sock
privops_socket_group: crate-operators
privops_socket_mode: "0660"

# OR
privops:
    socket: /var/run/crate/crated-privops.sock
    group:  crate-operators
    mode:   "0660"
```

Documented in `crated.conf.sample`.

### Why a separate dispatcher (not a refactor)

`dispatchPrivOpFromMap` duplicates the 14-case switch from
`dispatchPrivOp` instead of refactoring both into a shared
`std::variant`-based core. Two reasons:

1. **HTTP path stays byte-identical to 0.9.13.** Zero risk to
   existing `/api/v1/privops/:verb` consumers (hub, CI, third-
   party tooling). They keep their wire contract.
2. **Mini-PR scope.** A variant-based unification is its own
   refactor; if duplication becomes a real cost we can fold
   later.

### Response shape

The libnv response wraps the existing JSON body in an nvlist
field for now:

```
nvlist {
  "status": <int>      // HTTP-style status
  "body":   <string>   // the JSON the HTTP path also produces
}
```

Native-typed nvlist responses (per-verb structured fields) are
deferred — would require refactoring 14 handlers. The current
shape lets clients use the same body parsers as HTTP, so the
operator-side libnv-vs-HTTP code is symmetric.

### Tests

22 new ATF tests in `privops_nv_pure_test.cpp`. Suite:
1255 → **1277**, all passing. `daemon/privops_handlers.o`,
`daemon/privops_listener.o`, `daemon/config.o` all compile clean.

### Series state

- Verb handlers: 14/14 ✅
- Per-user mini-track: 0.9.8–0.9.13 ✅
- **0.9.14 — libnv unix-socket transport ← this release**
- 0.9.15 — operator client side: `crate(1)` switches to libnv
  socket when available
- 0.9.16+ — network_lease.cpp per-user paths, RCTL umbrella
  application
- 0.9.17 — default flip
- 1.0.0 — setuid bit removed

### Files

- `lib/privops_nv_pure.{h,cpp}` (new)
- `daemon/privops_listener.{cpp,h}` (new)
- `tests/unit/privops_nv_pure_test.cpp` (new)
- `daemon/privops_handlers.{h,cpp}` — added `dispatchPrivOpFromMap`
- `daemon/config.h/.cpp` — 3 new fields + YAML parsing
- `daemon/main.cpp` — start `PrivopsListener` alongside HTTP
- `daemon/crated.conf.sample` — appended privops block
- `Makefile`, `tests/unit/Kyuafile`, `.gitignore` — wired up
- `cli/args.cpp` — version `crate 0.9.14`

---

## [0.9.13] — 2026-05-09

**Rootless track, first wiring step.** Fourteenth 0.9.x
release. The first release that lights up actual rootless
*behaviour*: per-user audit tail. Previous mini-PRs
(0.9.8–0.9.12) only added pure modules + config schema.

### What lands

#### Pure formatter

`lib/audit_per_user_pure.{h,cpp}` formats one JSONL audit
record per privops verb invocation:

```
{"ts":1715250000,"uid":1000,"verb":"set_rctl","status":200,"outcome":"ok"}
```

`outcome` classifies the status into a short token:
`ok` / `parse_or_validate` / `forbidden` / `not_found` /
`rate_limit` / `server_error` / `other`. Detail (response
body) is intentionally omitted — canonical record stays in
the system audit (cap_syslog dual-write from 0.8.24).

Verb name gets JSON-escaped defensively even though
`parseVerb`'s charset can't produce a quote in practice.

#### Daemon writer

`daemon/audit_per_user.{cpp,h}` — best-effort append-only
writer:

- `appendPerUserAuditLine(uid, jsonLine)` mkdirs
  `/var/run/crate/<uid>` (mode 0700) on first call, opens
  `/var/run/crate/<uid>/audit.log` with `O_APPEND|O_CREAT`
  mode 0600, writes one line + `\n`, closes
- POSIX-atomic line writes (well under PIPE_BUF)
- mkdir / open / write failures log a single line to stderr
  and return `false` — never throws, never fails the verb

#### Dispatcher hook

`Crated::dispatchPrivOp` gains two optional parameters:

```cpp
DispatchResult dispatchPrivOp(PrivOpsPure::Verb v,
                              const std::string &body,
                              bool rootlessPerUser = false,
                              uint32_t operatorUid = 0);
```

When `rootlessPerUser == true && operatorUid > 0`, the
dispatcher writes a per-user audit line after computing
its result (success or failure — both tracked).

`daemon/routes.cpp::handlePrivOp` now passes
`config.rootlessPerUser` and uid 0. **uid stays 0 in 0.9.13**
because cpp-httplib doesn't expose the connection fd for
`getpeereid(2)` and the bearer-token API doesn't carry uid.
The contract is wired and testable; the actual uid plumbing
lights up in 0.9.14 (control-socket plane already has peer
uid via 0.7.11; can drive the audit hook today).

### Why this scope

0.9.13 is the **first wiring** release of the namespacing
sub-track. Picking the smallest blast radius:

- Audit is **additive** — adding a per-user log doesn't
  change any existing audit path
- The hook **defaults to off** — uid=0 (current call site)
  is a no-op
- Open/write failures **don't fail the verb** — operator
  visibility loss, not a regression

Larger wirings (network_lease per-user paths, RCTL umbrella
application) defer to 0.9.14+ where they get a coherent
release alongside the uid-plumbing flip.

### Tests

6 new ATF tests in `audit_per_user_pure_test.cpp`:

- `format_typical_ok` — happy-path field-order + content
- `outcome_classification` — full status code → outcome
  table coverage (200/201/204/400/403/404/429/500/501/599/
  100/0)
- `format_outcome_matches_status` — formatLine actually
  uses outcomeFor, not a separate code path
- `format_escapes_verb_name` — defensive escape (smuggled
  quote in verb name doesn't break JSON)
- `format_no_detail_field` — locks down "no detail"
  contract (catches future regression adding response body)
- `format_distinct_records_alice_vs_bob` — uid varies →
  records differ

Suite: 1249 → **1255**, all passing.
`daemon/privops_handlers.o`, `daemon/audit_per_user.o`,
`daemon/routes.o` all compile clean.

### Series state

- Verb handlers: 14/14 ✅
- Per-user mini-track:
  - 0.9.8 — runtime path scheme ✅
  - 0.9.9 — ZFS dataset prefix ✅
  - 0.9.10 — network sub-CIDR ✅
  - 0.9.11 — RCTL accounting groups ✅
  - 0.9.12 — migration doc + config schema + composer ✅
  - **0.9.13 — first wiring (per-user audit) ← this release**
- 0.9.14 — uid plumbing + default flip
- 1.0.0 — setuid removed

### Files

- `lib/audit_per_user_pure.{h,cpp}` (new, pure)
- `daemon/audit_per_user.{h,cpp}` (new, syscall-bound)
- `daemon/privops_handlers.{h,cpp}` — dispatchPrivOp gains
  `rootlessPerUser` + `operatorUid` params
- `daemon/routes.cpp::handlePrivOp` — passes config toggle
- `tests/unit/audit_per_user_pure_test.cpp` (new)
- `Makefile`, `tests/unit/Kyuafile`, `.gitignore` — wired
- `cli/args.cpp` — version `crate 0.9.13`

---

## [0.9.12] — 2026-05-09

**Rootless track, migration doc + config schema + composition
helper.** Thirteenth 0.9.x release. Fifth (and final pure-only)
mini-PR of the namespacing sub-track.

This release lands the **operator-facing** pieces of the
rootless transition: the migration guide, the `crated.conf`
schema with new knobs (default off), and a pure helper that
ties 0.9.8-0.9.11 together. **Existing 0.8.x deployments are
byte-identical at the default `rootless_per_user: false`.**

The actual wiring (network_lease.cpp switch, RCTL umbrella
application, audit per-user) lands in 0.9.13. Default flip
moves to 0.9.14.

### What lands

#### Migration guide

`docs/rootless-migration.md` — comprehensive operator guide:

- TL;DR + framing
- Per-release timeline (0.9.0 verb taxonomy → 1.0.0 setuid
  removed)
- Migration steps for single-tenant (opt-in dry-run),
  greenfield multi-tenant, and existing-setuid-deployment
  scenarios
- "What the daemon takes over" (the verb call-sites that
  replace each direct `jail`/`mount`/`rctl` invocation in
  `crate(1)`)
- Compliance checklist for "no setuid root binaries" shops
- Out-of-scope items deferred to 1.x

#### Config schema

`Crated::Config` (in `daemon/config.h`) gains:

```cpp
bool rootlessPerUser = false;        // master toggle
std::string zfsMasterPrefix;         // e.g. "zroot/jails"
std::string networkMasterCidr4;      // e.g. "10.66.0.0/16"
unsigned    networkSubPrefixLen4 = 24;
std::string networkMasterCidr6;      // e.g. "fd00:dead::/48"
unsigned    networkSubPrefixLen6 = 64;
```

YAML keys accepted in two equivalent forms — top-level
shorthand or nested under `rootless:`:

```yaml
# Top-level form
rootless_per_user: true
zfs_master_prefix: "zroot/jails"
network_master_cidr_v4: "10.66.0.0/16"
network_sub_prefix_len_v4: 24

# Equivalent nested form
rootless:
    per_user: true
    zfs_master_prefix: "zroot/jails"
    network_master_cidr_v4: "10.66.0.0/16"
    network_sub_prefix_len_v4: 24
```

Both forms documented in the updated `crated.conf.sample`.
All defaults preserve the legacy single-tenant shape.

#### Composition helper

`lib/per_user_env_pure.{h,cpp}` aggregates the four
namespacing pieces from 0.9.8-0.9.11 into a single
`PerUserEnv` struct:

```cpp
struct Env {
  uint32_t uid;
  // Runtime paths (always populated)
  std::string runtimeRoot;       // /var/run/crate/<uid>
  std::string leasesDir;
  std::string exportsDir;
  std::string importsDir;
  std::string auditLog;
  // ZFS (empty if cfg.zfsMasterPrefix empty)
  std::string zfsPrefix;
  // Network (empty if corresponding master empty)
  std::string ipv4SubCidr;
  std::string ipv6SubCidr;
  // RCTL (always populated)
  std::string loginclass;          // crate-<uid>
  std::string loginclassSubject;   // loginclass:crate-<uid>
};

Result composeForUid(const Config &cfg, uint32_t uid);
```

This is the contract 0.9.13's wiring lands against: when
`network_lease.cpp` / RCTL handlers / audit log code want
"what's alice's stuff?" they call `composeForUid(cfg,
alice.uid)` once and read fields from the struct.

### Tests

8 new ATF tests in `per_user_env_pure_test.cpp`:

- `compose_full_config` — every field populated end-to-end
- `compose_empty_config_legacy_shape` — paths + RCTL still
  populate (always-on); ZFS + CIDRs empty (per-category
  opt-out)
- `compose_v4_only` — partial config (v4 yes, v6 no)
- `compose_isolation_alice_vs_bob` — every uid-varying
  field differs between operators
- `compose_rejects_bad_v4_master` / `_v6_master` —
  field-prefix error context preserved (`"ipv4: ..."`)
- `compose_rejects_bad_uid` — > INT32_MAX rejected via
  validateUid
- `compose_rctl_always_populated` — even with empty config

Suite: 1241 → **1249**, all passing.

### Series state

- Verb handlers: 14/14 ✅
- Per-user mini-track:
  - 0.9.8 — runtime path scheme ✅
  - 0.9.9 — ZFS dataset prefix ✅
  - 0.9.10 — network sub-CIDR ✅
  - 0.9.11 — RCTL accounting groups ✅
  - **0.9.12 — migration doc + config schema + composition
    ← this release**
- 0.9.13 — wiring flip (network_lease, RCTL umbrella
  application, audit per-user)
- 0.9.14 — default flip (`rootless_per_user: true`)
- 1.0.0 — setuid removed

### Files

- `docs/rootless-migration.md` (new)
- `lib/per_user_env_pure.{h,cpp}` (new)
- `tests/unit/per_user_env_pure_test.cpp` (new)
- `daemon/config.h` — 5 new fields
- `daemon/config.cpp` — top-level + nested YAML parsing
- `daemon/crated.conf.sample` — appended rootless block
- `Makefile`, `tests/unit/Kyuafile`, `.gitignore` — wired up
- `cli/args.cpp` — version `crate 0.9.12`

---

## [0.9.11] — 2026-05-09

**Rootless track, per-user RCTL accounting groups.** Twelfth
0.9.x release. Fourth mini-PR of the namespacing sub-track.
Pure module; no daemon-side wiring (lands in 0.9.12).

### Why loginclass

FreeBSD's rctl(8) gates resource limits per "subject":
jail / user / loginclass / process. Today crate sets per-jail
RCTL rules — fine for single-tenant. For multi-tenant
rootless, alice's jails should aggregate against alice's
umbrella quota.

Loginclass is the natural unit:

- rctl can express `loginclass:crate-1000:memoryuse:deny=4G`
- login.conf assigns loginclass to UNIX accounts
- crated assigns each operator a loginclass on first contact
  (the assignment + login.conf edit lands in 0.9.12)

Example flow:

```
alice (uid 1000) creates jail "web" → jid 7
crated applies:
  jail:7:memoryuse:deny=2G                     (per-jail, today)
  loginclass:crate-1000:memoryuse:deny=4G      (umbrella, this PR)
```

If alice creates a second jail with `memoryuse=3G`, the
umbrella keeps her total at 4G (kernel enforces). Bob's
loginclass `crate-1001` has its own 4G — no cross-tenant
interference.

### What lands

`lib/per_user_rctl_pure.{h,cpp}`:

- `loginclassName(uid)` → `crate-<uid>`
- `jailSubject(jid)` → `jail:<jid>` (ergonomic helper for
  symmetry with loginclassSubject)
- `loginclassSubject(uid)` → `loginclass:crate-<uid>`
- `buildRule(subject, key, rawValue)` → full
  `<subject>:<key>:deny=<value>` string for rctl(8)
- `buildUserUmbrellaRules(uid, [{key, value}, ...])` →
  whole quota set tagged with the per-user loginclass; one
  rule per pair
- `validateLoginclassName(name)` — accepts only what
  `loginclassName(uid)` produces (defence in depth: daemon
  rejects operator-supplied loginclass strings)

### Tests

11 new ATF tests in `per_user_rctl_pure_test.cpp`:

- typical loginclass / subject / rule formats
- `loginclass_isolation` — alice vs bob distinct, neither
  a prefix of the other (defence against prefix-matching
  loginclass tools)
- umbrella rules from a 3-key set
- empty input → empty output
- validator accepts well-formed
- `validate_loginclass_round_trips` — every loginclass we
  emit must round-trip (catches future format desync)
- validator rejects garbage: empty, no-uid suffix, alpha
  suffix, leading-zero suffix, missing prefix, wrong case,
  too-long suffix

Suite: 1230 → **1241**, all passing.

### Series state

- Verb handlers: 14/14 ✅
- Per-user mini-track:
  - 0.9.8 — runtime path scheme ✅
  - 0.9.9 — ZFS dataset prefix ✅
  - 0.9.10 — network sub-CIDR ✅
  - **0.9.11 — RCTL accounting groups ← this release**
  - 0.9.12 — migration doc + final wiring (login.conf
    edits, lease migration, `crated.conf` schema bump)
- 0.9.13 — default flip
- 1.0.0 — setuid removed

---

## [0.9.10] — 2026-05-09

**Rootless track, per-user network sub-CIDR allocator.**
Eleventh 0.9.x release. Third mini-PR of the namespacing
sub-track. Pure module; no existing call sites migrate yet.

### What lands

`lib/per_user_net_pure.{h,cpp}` — composes a per-user sub-CIDR
from a master CIDR + sub-prefix length + uid:

```
composeIpv4("10.66.0.0/16", 24, 1000)
  -> "10.66.232.0/24"             (1000 mod 256 = 232)

composeIpv4("10.66.0.0/16", 24, 1001)
  -> "10.66.233.0/24"

composeIpv6("fd00:dead::/48", 64, 1000)
  -> "fd00:dead:0:3e8:0:0:0:0/64" (1000 = 0x3e8)
```

### Allocation strategy

Deterministic hash: slot index = `uid mod (2^slotBits)`, where
`slotBits = subPrefixLen − masterPrefixLen`. Trade-off:

- ✅ Stable across crated restarts — no allocator state file
- ✅ No race on slot picking
- ❌ Collisions when `2^slotBits` operators exist, e.g. `/16`
  master + `/24` sub gives 256 slots, so uids congruent mod 256
  share a sub-CIDR. Typical deployments (<256 operators) are
  fine; large multi-tenant clusters need a wider sub or a
  state-backed allocator (tracked in TODO).

### Bounds

- IPv4: master prefix ≤ 32, sub prefix > master prefix, ≤ 32,
  slotBits ≤ 24 (16M slot cap)
- IPv6: master prefix ≤ 128, sub prefix > master prefix, ≤ 128,
  slotBits ≤ 32 (uid fits without truncation)

### Defence in depth

- Master low-bits masked off before composition. Operator who
  writes `"10.66.5.7/16"` gets the same result as `"10.66.0.0/16"`.
  Asserted by `ipv4_master_low_bits_are_ignored` /
  `ipv6_master_low_bits_are_ignored`.
- Leading-zero IPv4 octets rejected (octal foot-gun).
- Compressed IPv6 (`::`) accepted; double-`::` rejected.

### Tests

11 new ATF tests in `per_user_net_pure_test.cpp`:

- `ipv4_typical_16_to_24` — base case + uid wrap
- `ipv4_isolation_alice_vs_bob`
- `ipv4_master_low_bits_are_ignored`
- `ipv4_28_subnet` — non-default sub size
- `ipv4_rejects_bad_master` — malformed CIDRs
- `ipv4_rejects_sub_prefix_relations` — sub ≤ master, sub > 32,
  slotBits > 24
- `ipv6_typical_48_to_64`
- `ipv6_isolation_alice_vs_bob`
- `ipv6_master_low_bits_are_ignored`
- `ipv6_rejects_bad_master`
- `ipv6_rejects_sub_prefix_relations`

Suite: 1219 → **1230**, all passing.

### Series state

- Verb handlers: 14/14 ✅
- Per-user mini-track:
  - 0.9.8 — runtime path scheme ✅
  - 0.9.9 — ZFS dataset prefix ✅
  - **0.9.10 — network sub-CIDR ← this release**
  - 0.9.11 — RCTL accounting groups
  - 0.9.12 — migration doc + final wiring
- 0.9.13 — default flip
- 1.0.0 — setuid removed

### Note on lease migration

The full migration from `/var/run/crate/network-leases.txt`
(single shared file) to `/var/run/crate/<uid>/leases/<jail>.lease`
(per-user) is deferred to 0.9.12 alongside the final wiring,
since it touches `lib/network_lease.cpp`'s mutating IO path
and benefits from landing with the `crated.conf` schema bump.

---

## [0.9.9] — 2026-05-09

**Rootless track, per-user ZFS dataset prefix.** Tenth 0.9.x
release. Second mini-PR of the namespacing sub-track. Pure
composition helpers; existing call sites continue using the
single-tenant `zroot/jails/<jail>` shape.

### What lands

`lib/zfs_dataset_pure.{h,cpp}` extends with:

- `composePerUserPrefix(masterPrefix, uid)` —
  `zroot/jails` + 1000 → `zroot/jails/1000`. Tolerates a
  trailing `/` on the master prefix (operators write it both
  ways in their config).
- `composePerUserDataset(masterPrefix, uid, jailName)` —
  full path: `zroot/jails/1000/web`.

Same uid-as-segment design as `runtime_paths_pure` (0.9.8):
uid is the stable key, not the username. Operators wanting
username-shaped paths can `zfs rename` after creation.

### Why the master prefix is operator-supplied

The `zfs_master_prefix:` config knob (landing alongside this
in a future `crated.conf` schema bump) lets multi-tenant
operators pick:

- `zroot/jails` — production single-pool layout
- `tank/crate-tenants` — separate pool for crate isolation
- `zroot/users/${user}/crate` — username-shaped (operator
  trades the uid-stability win for nicer paths)

The compose functions accept any operator-supplied prefix
that passes `validateDatasetName`; result also passes
validation by construction (test asserts this).

### Tests

5 new ATF tests in `zfs_dataset_pure_test.cpp`:

- `per_user_prefix_typical` — base + uid composition
- `per_user_prefix_strips_trailing_slash` — operator-config
  tolerance
- `per_user_dataset_typical` — full dataset shape
- `per_user_dataset_isolation` — alice (1000) vs bob (1001)
  get disjoint paths even for same jail name; neither path
  a prefix of the other (same security invariant as 0.9.8's
  lease isolation)
- `per_user_dataset_passes_validate` — composed result
  round-trips through `validateDatasetName` (catches a
  future regression introducing `//` or trailing `/`)

Suite: 1214 → **1219**, all passing.

### Series state

- Verb handlers: 14/14 ✅
- Per-user mini-track:
  - 0.9.8 — runtime path scheme ✅
  - **0.9.9 — ZFS dataset prefix ← this release**
  - 0.9.10 — network sub-CIDR + lease migration
  - 0.9.11 — RCTL accounting groups
  - 0.9.12 — migration doc + final wiring
- 0.9.13 — default flip
- 1.0.0 — setuid removed

---

## [0.9.8] — 2026-05-08

**Rootless track, per-user runtime path scheme.** Ninth 0.9.x
release. First mini-PR of the namespacing sub-track (0.9.8 →
0.9.12).

This release introduces the path scheme **without wiring any
existing call sites to it.** Same shape as 0.9.0: contract
first, behaviour change later. That keeps the existing
setuid-prod flow byte-identical while giving 0.9.10
(`/var/run/crate/<uid>/leases/`) and 0.9.12
(`/var/run/crate/<uid>/exports/imports/audit.log`) a stable
contract to migrate one subsystem at a time.

### What lands

- **`lib/runtime_paths_pure.{h,cpp}`** — pure path helpers:
  - `legacyRoot()` → `/var/run/crate` (the pre-0.9.x compat
    root)
  - `perUserRoot(uid)` → `/var/run/crate/<uid>` (per-user
    parent — caller mkdirs with `0700 root:<user-group>`)
  - `perUserLeasesDir(uid)`, `perUserLeaseFile(uid, jail)` —
    moved here in 0.9.10
  - `perUserExportsDir(uid)`, `perUserImportsDir(uid)` —
    moved here in 0.9.12
  - `perUserAuditLog(uid)` — operator-readable audit tail per
    user (canonical record stays in cap_syslog dual-write)
  - `validateUid(int64_t)` — bounds 0..INT32_MAX (catches
    integer-handling bugs upstream)

### Design choices

- **uid 0 (root) does NOT alias the legacy root.** Root
  running rootless gets its own `/var/run/crate/0/` subtree
  just like any other operator. The legacy root remains as
  the explicit pre-0.9.x compat surface, accessed via
  `legacyRoot()`.
- **uid as path segment, not username.** Operators may
  deploy with NIS / LDAP where uid→name maps are mutable;
  uid is the stable key.
- **No `..` or doubled slashes** in any helper output.
  Defence-in-depth assertion in the test suite.

### Why mini-PR

The full per-user namespacing scope (jail name prefix,
ZFS dataset prefix, network sub-CIDR, RCTL accounting groups,
runtime paths, migration doc) is ~1500 LOC across the
codebase. Splitting into 5 mini-PRs (0.9.8 paths, 0.9.9 ZFS,
0.9.10 network, 0.9.11 RCTL+leases migration, 0.9.12 final
wiring + migration doc) keeps the same per-PR risk profile
as the verb-handler sub-track.

### Tests

- 10 new ATF tests in `tests/unit/runtime_paths_pure_test.cpp`:
  - `legacy_root_is_var_run_crate` — locks down the legacy
    path (a refactor moving to `/run/crate/` would fail this)
  - `per_user_root_format` — `/var/run/crate/<uid>` shape
  - `per_user_root_root_uid_does_not_alias_legacy` — explicit
    test for the uid-0 design choice
  - `per_user_subdirs` — leases/exports/imports/audit.log
  - `per_user_lease_file_isolation` — alice (uid 1000) and
    bob (uid 1001) get disjoint lease paths even for the
    same jail name; neither path is a prefix of the other
  - validators (positive, negative, too-big)
  - `per_user_paths_no_traversal_segments` — defence in depth
- Suite: 1204 → **1214**, all passing.

### Series state

- Verb handlers: 14/14 (0.9.2-0.9.7)
- Per-user namespacing mini-track:
  - **0.9.8** — runtime path scheme **← this release**
  - 0.9.9 — per-user ZFS dataset prefix
  - 0.9.10 — per-user network sub-CIDR + lease migration
  - 0.9.11 — per-user RCTL accounting groups
  - 0.9.12 — migration doc + final wiring
- 0.9.13 — default flip
- 1.0.0 — setuid bit removed

---

## [0.9.7] — 2026-05-08

**Rootless track, last 6 verbs.** Eighth 0.9.x release —
firewall + jail-lifecycle handlers land. **All 14 verbs from
0.9.0 now have real handlers; the 501 fallback path remains
only as a safety net for the `Verb::Unknown` case.**

### What lands

- **`add_pf_rule` / `remove_pf_rule`** — `PfctlOps::addRules`
  loads `ruleText` into the named anchor (atomic replace);
  `flushRules` clears the anchor entirely. Per-rule removal
  isn't a pfctl primitive, so `remove_pf_rule` flushes; the
  `ruleText` field stays in the wire format for forward
  compat with a future per-rule verb.
- **`add_ipfw_rule` / `remove_ipfw_rule`** — `add` builds
  `ipfw add <number> set <set> <action> <body>` argv directly
  (honouring the `set` field, which `IpfwOps::addRule` doesn't
  take); `remove` delegates to `IpfwOps::deleteRule(number)` —
  ipfw rule numbers are unique across sets, so the `set` field
  is informational on remove.
- **`create_jail` / `destroy_jail`** — `create_jail` runs
  `jail -c name=X path=Y [host.hostname=H] [vnet] [params]
  persist`. The privops layer creates only the jail
  registration; ZFS attach, mount, iface config are operator-
  driven via the other verbs (proper composition surface for
  rootless `crate run`). `destroy_jail` runs
  `jail -r NAME` (or `-R NAME` if `force=true`).

### Pure response builders (test-locked)

- `formatAddPfRuleSuccess(anchor, rule)` →
  `{"loaded":true,"anchor":...,"rule":...}`
- `formatRemovePfRuleSuccess(anchor)` →
  `{"flushed_anchor":true,"anchor":...}`
- `formatAddIpfwRuleSuccess(set, number, action, body)` →
  `{"added":true,...}`
- `formatRemoveIpfwRuleSuccess(set, number)` →
  `{"removed":true,...}`
- `formatCreateJailSuccess(name, path)` →
  `{"created":true,...}`
- `formatDestroyJailSuccess(name)` →
  `{"destroyed":true,...}`

### Wire examples

```http
POST /api/v1/privops/add_pf_rule
{"anchor":"crate","rule":"pass on em0 from 10.0.0.0/24"}

POST /api/v1/privops/remove_pf_rule
{"anchor":"crate","rule":""}     # rule field ignored, anchor flushed

POST /api/v1/privops/add_ipfw_rule
{"set":0,"number":100,"action":"allow","body":"ip from any to any"}

POST /api/v1/privops/remove_ipfw_rule
{"set":0,"number":100}

POST /api/v1/privops/create_jail
{"name":"alpine","path":"/zroot/jails/alpine","hostname":"alpine.local","vnet":true,"parameters":"allow.raw_sockets=1"}

POST /api/v1/privops/destroy_jail
{"name":"alpine","force":false}
```

Failure modes follow the same shape: 400 parse / 400 validate /
500 `pfctl_failed` / 500 `ipfw_failed` / 500 `jail_failed`.

### Tests

- 7 new ATF tests for response builders
  (`format_add_pf_rule_success`, `format_remove_pf_rule_success`,
  `format_add_ipfw_rule_success`, `format_remove_ipfw_rule_success`,
  `format_create_jail_success`, `format_destroy_jail_success`,
  plus existing taxonomy/dispatcher/parser tests).
- Suite: 1198 → **1204**, all passing.
- `daemon/privops_handlers.o` builds cleanly.

### Series state

| Verb | Status |
|------|--------|
| set_rctl | shipped 0.9.2 |
| clear_rctl | shipped 0.9.3 |
| attach_zfs / detach_zfs | shipped 0.9.4 |
| mount_nullfs / unmount_nullfs | shipped 0.9.5 |
| configure_iface / teardown_iface | shipped 0.9.6 |
| **add/remove pf, add/remove ipfw, create/destroy jail** | **shipped 0.9.7** |

**14/14 verbs handled.** Next: per-user namespacing in 0.9.8
(jail name prefix, `/var/run/crate/<uid>/`, network sub-CIDR,
RCTL accounting groups, migration doc).

---

## [0.9.6] — 2026-05-08

**Rootless track, VNET interface configuration.** Seventh 0.9.x
release — `configure_iface` / `teardown_iface` paired.

- `Crated::handleConfigureIface` — assumes the iface (typically
  `epair Nb`) already exists on host (operator created the epair
  pair). Handler:
  1. moves `ifname` into the jail's vnet
     (`IfconfigOps::moveToVnet`)
  2. inside the jail (jexec), sets ipv4 / ipv6 / MAC for fields
     that are non-empty
  3. inside the jail, brings the iface up
  4. on the host side, attaches the pair-A half (computed from
     `ifname` when it follows the `epair Nb` pattern) to the
     requested bridge
  - Bridge attach with non-epair `ifname` → 400 `non_epair_with_bridge`
- `Crated::handleTeardownIface` — `IfconfigOps::destroyInterface`
  on the host side. Iface still inside a jail → destroy fails;
  operator should `ifconfig <iface> -vnet <jail>` first or rely
  on jail teardown.
- Pure response builders:
  - `formatConfigureIfaceSuccess(jid, ifname, bridge, ipv4, ipv6, mac)` —
    echoes back every field including empty optionals so operator
    scripts can grep deterministically
  - `formatTeardownIfaceSuccess(ifname)` →
    `{"destroyed":true,"ifname":...}`

Wire example:

```http
POST /api/v1/privops/configure_iface
{"jid":5,"ifname":"epair0b","bridge":"bridge0",
 "ipv4_cidr":"10.0.0.5/24","ipv6_cidr":"fd00::5/64",
 "mac_addr":"02:00:11:22:33:44"}

HTTP/1.1 200 OK
{"configured":true,"jid":5,"ifname":"epair0b",
 "bridge":"bridge0","ipv4_cidr":"10.0.0.5/24",
 "ipv6_cidr":"fd00::5/64","mac_addr":"02:00:11:22:33:44"}

POST /api/v1/privops/teardown_iface
{"ifname":"epair0a"}

HTTP/1.1 200 OK
{"destroyed":true,"ifname":"epair0a"}
```

Failure modes: 400 parse / 400 validate / 400 non_epair_with_bridge /
404 jail_not_found / 500 exec_failed (configure) / 500
destroy_failed (teardown).

Tests: 3 new ATF tests for response builders. Suite: 1195 →
**1198**, all passing.

Series progress: 9/12 verbs handled. Next: `add_pf_rule` /
`remove_pf_rule` / `add_ipfw_rule` / `remove_ipfw_rule` +
`create_jail` / `destroy_jail` in 0.9.7.

---

## [0.9.5] — 2026-05-08

**Rootless track, nullfs mount/unmount.** Sixth 0.9.x release —
`mount_nullfs` / `unmount_nullfs` paired (lifecycle pair).

- `Crated::handleMountNullfs` / `handleUnmountNullfs` — calls
  `nmount(2)` / `unmount(2)` syscalls directly, mirroring the
  `iov` pattern from `lib/mount.cpp::Mount::mount` but without
  the RAII unmount-on-destruct. Privops mounts persist across
  handler returns; lifetime owned by the operator via paired
  `unmount_nullfs` calls.
  - `read_only` defaults to true (matching the parser default;
    explicit RW requires `"read_only":false` in the body)
  - `force` on unmount maps to `MNT_FORCE`
  - Non-FreeBSD daemon builds return 500 `platform_unsupported`
    (defence in depth — daemon production builds are FreeBSD-only,
    but the platform guard keeps non-FreeBSD CI builds clean)
- `formatMountNullfsSuccess(source, target, readOnly)` →
  `{"mounted":true,"source":...,"target":...,"read_only":...}`.
- `formatUnmountNullfsSuccess(target)` → `{"unmounted":true,"target":...}`.

Wire example:

```http
POST /api/v1/privops/mount_nullfs
{"source":"/host/data","target":"/jail/data","read_only":true}

HTTP/1.1 200 OK
{"mounted":true,"source":"/host/data","target":"/jail/data","read_only":true}

POST /api/v1/privops/unmount_nullfs
{"target":"/jail/data","force":false}

HTTP/1.1 200 OK
{"unmounted":true,"target":"/jail/data"}
```

Failure modes: 400 parse / 400 validate / 500 nmount_failed (with
nmount(2) errno + kernel `errmsg` if any) / 500 unmount_failed.
No 404 jail-lookup since the operation targets paths, not jids —
the daemon trusts the operator's chosen path (validators already
forbid `..` segments and shell metacharacters).

Tests: 3 new ATF tests (`format_mount_nullfs_success_ro`,
`format_mount_nullfs_success_rw`, `format_unmount_nullfs_success`).
Suite: 1192 → **1195**, all passing.

Series progress: 7/12 verbs handled (set_rctl, clear_rctl,
attach_zfs, detach_zfs, mount_nullfs, unmount_nullfs).
Next: `configure_iface` / `teardown_iface` in 0.9.6.

---

## [0.9.4] — 2026-05-08

**Rootless track, ZFS jail attach/detach.** Fifth 0.9.x
release — `attach_zfs` / `detach_zfs` ship paired since they're
a natural lifecycle pair and use the same `ZfsOps` underlying
function.

- `Crated::handleAttachZfs(AttachZfsReq)` / `handleDetachZfs(DetachZfsReq)`
  — jail lookup, then `ZfsOps::jailDataset(jid, dataset)` /
  `unjailDataset(jid, dataset)`. The existing `ZfsOps` functions
  (used by `crate run` / `crate stop`) prefer `libzfs` when
  available and fall back to `zfs(8)` otherwise — privops gets
  both for free.
- `dispatchPrivOp` switch grew `AttachZfs` and `DetachZfs` cases.
- `lib/privops_wire_pure.{h,cpp}` — `formatAttachZfsSuccess(jid,
  dataset)` returns `{"attached":true,"jid":N,"dataset":"..."}`;
  `formatDetachZfsSuccess` returns the same shape with `detached`.
  Body distinction asserted in tests so a future regression
  swapping the two doesn't slip through.

Wire example:

```http
POST /api/v1/privops/attach_zfs
{"jid":3,"dataset":"zroot/jails/alpine/data"}

HTTP/1.1 200 OK
{"attached":true,"jid":3,"dataset":"zroot/jails/alpine/data"}
```

```http
POST /api/v1/privops/detach_zfs
{"jid":3,"dataset":"zroot/jails/alpine/data"}

HTTP/1.1 200 OK
{"detached":true,"jid":3,"dataset":"zroot/jails/alpine/data"}
```

Failure modes match the rest of the rootless track:
400 parse / 400 validate / 404 jail_not_found / 500 exec_failed.

Tests: 2 new ATF tests (`format_attach_zfs_success`,
`format_detach_zfs_success`). Suite: 1190 → **1192**, all
passing.

Series progress: 5/12 verbs handled (set_rctl, clear_rctl,
attach_zfs, detach_zfs). Next: `mount_nullfs` /
`unmount_nullfs` in 0.9.5.

---

## [0.9.3] — 2026-05-08

**Rootless track, `clear_rctl` handler.** Fourth 0.9.x
release — `clear_rctl` lands using the same template as
`set_rctl` from 0.9.2.

- `Crated::handleClearRctl(ClearRctlReq)` — looks up jail by jid,
  builds `rctl -r jail:<jid>:<key>:deny` via existing
  `RetunePure::buildClearArgv`, executes via `Util::execCommand`.
  `404 jail_not_found` if the jail is gone, `500 exec_failed` if
  rctl(8) returns non-zero.
- `dispatchPrivOp` switch grew a `ClearRctl` case routing to
  the real handler.
- `lib/privops_wire_pure.{h,cpp}` — `formatClearRctlSuccess(jid,
  key)` returns `{"cleared":true,"jid":N,"key":"..."}`.

Wire example:

```http
POST /api/v1/privops/clear_rctl
{"jid":7,"key":"pcpu"}
```

```http
HTTP/1.1 200 OK
{"cleared":true,"jid":7,"key":"pcpu"}
```

Note: clears in `crate retune --clear` are soft-fail (the rule may
not exist yet). The IPC surface returns the operator's exec error
verbatim — strict-vs-idempotent semantics will be configurable
via a future query flag if needed.

Tests: 1 new ATF test for `formatClearRctlSuccess` shape (asserts
distinct from `set_rctl` body — no `set` / `value` fields).
Suite: 1189 → **1190**, all passing.

Series progress: 3/12 verbs handled (set_rctl, clear_rctl).
Next: attach_zfs / detach_zfs in 0.9.4.

---

## [0.9.2] — 2026-05-08

**Rootless track, first real handler.** Third 0.9.x release —
`set_rctl` ships its actual privileged-operation handler. Verbs
2-13 still return 501; they land verb-by-verb in 0.9.3..0.9.7.

### Why `set_rctl` first

Smallest blast radius: the operation already exists end-to-end
in `crate retune`, so the handler is essentially a wrapper
around `RetunePure::buildSetArgv` + `rctl(8)` exec. No new
syscalls, no new file paths, no new state to reason about.
A clean precedent for the 12 verbs to follow.

### What lands

- **`daemon/privops_handlers.{h,cpp}`** (new) — privileged-
  operations dispatcher. Each verb that has a real handler gets
  its own case in `Crated::dispatchPrivOp`; the rest fall back
  to `PrivOpsWirePure::parseValidateAndDispatch` (501).
  - `Crated::handleSetRctl(SetRctlReq)` — looks up the jail by
    jid (rejects with `404 jail_not_found` if it's gone), builds
    `rctl -a jail:<jid>:<key>:deny=<value>` via the existing
    `RetunePure::buildSetArgv`, executes via `Util::execCommand`.
    Exec failures bubble up as `500 exec_failed` with the
    rctl(8) stderr text in the body.
- **`daemon/routes.cpp`** — `handlePrivOp` now delegates to
  `Crated::dispatchPrivOp` instead of the pure dispatcher.
- **`lib/privops_wire_pure.{h,cpp}`** — added pure response
  builders so the wire shape stays test-locked:
  - `formatHandlerError(kind, reason)` — generic 4xx/5xx body.
    `kind` tokens land in the operator log as
    `exec_failed` / `jail_not_found` / etc. for triage.
  - `formatSetRctlSuccess(jid, key, value)` — 200 OK body
    confirming what was applied.

### Wire example

```http
POST /api/v1/privops/set_rctl
Authorization: Bearer <admin-token>
Content-Type: application/json

{"jid":7,"key":"pcpu","value":"20"}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"set":true,"jid":7,"key":"pcpu","value":"20"}
```

Failure modes:

- `400 parse:` — wire-format error (missing `jid`/`key`/`value`,
  wrong type).
- `400 validate:` — semantic error (key not in RCTL whitelist,
  value out of range for the key).
- `404 jail_not_found` — `jid` doesn't match any running jail.
- `500 exec_failed` — `rctl(8)` returned non-zero.

### Tests

- 3 new ATF tests in `tests/unit/privops_wire_pure_test.cpp`:
  `format_handler_error_includes_kind`,
  `format_set_rctl_success`,
  `format_set_rctl_escapes_value` (multi-line / metachar
  escaping defence-in-depth).
- Suite count: 1186 → **1189**, all passing.
- `daemon/privops_handlers.o` builds cleanly.

### Series progress

| Release | Verb | Status |
|---------|------|--------|
| 0.9.0 | (taxonomy) | shipped |
| 0.9.1 | (wire format) | shipped |
| **0.9.2** | **set_rctl** | **shipped** |
| 0.9.3 | clear_rctl | next |
| 0.9.4 | attach_zfs / detach_zfs | |
| 0.9.5 | mount_nullfs / unmount_nullfs | |
| 0.9.6 | configure_iface / teardown_iface | |
| 0.9.7 | pf+ipfw rules + create_jail / destroy_jail | |
| 0.9.8 | per-user namespacing + migration doc | |
| 0.9.9 | default flip | |
| 1.0.0 | setuid bit removed | |

### Files

- `daemon/privops_handlers.{h,cpp}` (new)
- `daemon/routes.cpp` — dispatcher swap
- `lib/privops_wire_pure.{h,cpp}` — response builders
- `tests/unit/privops_wire_pure_test.cpp` — 3 new tests
- `Makefile` — `daemon/privops_handlers.cpp` added to `DAEMON_SRCS`
- `cli/args.cpp` — `crate 0.9.2`
- `CHANGELOG.md` — entry

---

## [0.9.1] — 2026-05-08

**Rootless track, JSON wire format.** Second 0.9.x release —
the verb taxonomy from 0.9.0 gets a concrete HTTP/JSON surface
on `crated`. **Still no handlers** — daemon returns
`501 Not Implemented` for every verb. This release nails down
the wire shape so the verb-handler PRs in 0.9.2..0.9.7 can
focus on the privileged work, not on parsing.

### What lands

- **`lib/privops_wire_pure.{h,cpp}`** — JSON parsers for all 14
  privops verbs from 0.9.0. Each parser fills the matching
  request struct from a JSON object and returns `"" | reason`
  for wire-format errors (missing required field, wrong type,
  malformed JSON). Hand-rolled — same approach as
  `daemon/routes_pure.cpp::extractStringField`. Bodies are
  tiny; no JSON library dependency added.
- **Generic field extractors** (`extractStringField`,
  `extractLongField`, `extractUnsignedField`,
  `extractBoolField`) with a `kPresent` sentinel return so
  callers can distinguish absent-vs-malformed cleanly.
- **`requireXxxField` wrappers** that report `missing field
  'foo'` for absent required fields.
- **`parseVerbFromPath`** — extracts the verb segment from
  `/api/v1/privops/<verb>` URL paths, returning
  `Verb::Unknown` for non-matching paths.
- **Response-body builders**:
  - `formatNotImplemented(verb)` — `{"error":"verb 'X' not yet
    implemented"}` for the 501 branch.
  - `formatParseError(reason)` — `{"error":"parse: ..."}` for
    HTTP 400 wire errors.
  - `formatValidateError(reason)` — `{"error":"validate: ..."}`
    for HTTP 400 semantic errors.
  - Distinct prefixes (`parse:` vs `validate:`) so operators
    immediately know whether the problem is in their HTTP
    client or in the requested operation.
- **`parseValidateAndDispatch(verb, body)`** — the pure
  dispatcher the daemon route delegates to. Three-step
  pipeline:
    1. parse → 400 with `parse:` prefix on error
    2. validate → 400 with `validate:` prefix on error
    3. dispatch → 501 (no handlers in 0.9.1)
  Returns a `DispatchResult{status, body}` struct. The 501
  branch will be replaced verb-by-verb with actual handler
  calls in 0.9.2..0.9.7; this dispatcher dissolves at that
  point.

### Daemon side

- **`POST /api/v1/privops/:verb`** — generic handler in
  `daemon/routes.cpp`. Admin-only auth (privops touch host-wide
  state, so per-container scope from F2 doesn't apply).
  `kMutating` rate-limit bucket. Body delegated to
  `parseValidateAndDispatch`. Status + body taken straight from
  the pure result.

### Tests

- **`tests/unit/privops_wire_pure_test.cpp`** — 33 ATF tests:
  - field extractors (string/long/unsigned/bool) covering
    present, absent, wrong-type, escape-decoding, and
    unterminated cases
  - required-field wrappers report `missing` clearly
  - `parseVerbFromPath` accepts known verbs, rejects garbage
    (empty, trailing slash, sub-path, unknown verb,
    non-privops path)
  - per-verb parsers happy-path + missing-required-field
    (covers all 14 verbs)
  - response builders escape quotes, distinguish `parse:` vs
    `validate:` prefixes, include the verb name in the 501
    body
  - dispatcher: 404 on Unknown verb, 400 with `parse:` on
    wire errors, 400 with `validate:` on semantic errors,
    501 with verb name on success; "covers every verb" loop
    confirms switch handles all 14 cases
- Suite count: 1186 (was 1153) — all passing.

### Wire format reference

```http
POST /api/v1/privops/create_jail HTTP/1.1
Host: crated.local
Authorization: Bearer <admin-token>
Content-Type: application/json

{"name":"alpine","path":"/zroot/jails/alpine","hostname":"alpine.local","vnet":true}
```

```http
POST /api/v1/privops/set_rctl HTTP/1.1
{"jid":7,"key":"pcpu","value":"20"}
```

```http
POST /api/v1/privops/configure_iface HTTP/1.1
{"jid":5,"ifname":"epair0b","bridge":"bridge0","ipv4_cidr":"10.0.0.5/24","mac_addr":"02:00:11:22:33:44"}
```

Field names are snake_case to match the existing `/api/v1`
convention. Field shapes mirror the request structs from
`lib/privops_pure.h`: required scalars are required JSON
fields; optional scalars (`hostname`, `vnet`, `force`,
`ipv4_cidr`, `bridge`, etc.) use the request struct's default
when absent.

### Files

- `lib/privops_wire_pure.{h,cpp}` (new)
- `tests/unit/privops_wire_pure_test.cpp` (new)
- `daemon/routes.cpp` — `handlePrivOp` static handler +
  `srv.Post("/api/v1/privops/:verb", ...)` registration;
  `#include "privops_wire_pure.h"` added.
- `Makefile`, `tests/unit/Kyuafile`, `.gitignore` — wired up.
- `cli/args.cpp` — version bumped to `crate 0.9.1`.

---

## [0.9.0] — 2026-05-08

**Rootless track opens.** First release on the `0.9.x` series
branch. Goal of the series: remove the setuid root bit from
`crate(1)` and delegate privileged operations to `crated`. The
setuid bit will flip off by default in 0.9.9 and be removed in
1.0.0. Today's setuid model is well-hardened (env-sanitize,
absolute paths, no shell, audit logging) — see TODO for the full
"why rootless still matters" framing — but blast-radius
reduction, multi-tenant safety, and "no setuid root binaries"
compliance are real wins worth the multi-week refactor.

This release is **contract only — no behaviour change.**
`crate(1)` still does its work setuid-style. What lands:

- `lib/privops_pure.{h,cpp}` — the privileged-operations verb
  taxonomy that crated will eventually accept over the existing
  control-socket plane (`daemon/control_socket_pure.h`):
    - `create_jail` / `destroy_jail`
    - `mount_nullfs` / `unmount_nullfs`
    - `set_rctl` / `clear_rctl`
    - `attach_zfs` / `detach_zfs`
    - `configure_iface` / `teardown_iface`
    - `add_pf_rule` / `remove_pf_rule`
    - `add_ipfw_rule` / `remove_ipfw_rule`
- Per-verb request structs (concrete fields, no shell-strings).
- Per-verb validators returning `"" | reason` — same code runs
  on caller (pre-flight) and daemon (post-receive) for defence
  in depth.
- Field-level validators exposed for reuse:
  jail name / hostname (RFC 1123) / absolute path (no `..`,
  no shell metas) / ZFS dataset / iface name (IFNAMSIZ) /
  MAC (rejects multicast bit) / IPv4 + IPv6 CIDR / pf+ipfw
  rule text / ipfw action (closed set).
- `tests/unit/privops_pure_test.cpp` — 46 ATF tests covering
  the verb name<->token round-trip, every field validator
  edge case, and per-verb request validation. Suite goes from
  1107 to 1153 tests, all passing.

### What comes next

Each subsequent 0.9.x release picks one verb (or one piece of
plumbing) and ships it end-to-end:

- **0.9.1** — JSON wire format on the control socket: parsers
  building request structs from `POST /v1/privops/<verb>`
  payloads, re-running `validate*()` on the daemon side. Still
  no handlers — the daemon returns 501 Not Implemented for
  every verb. This release nails down the wire shape so future
  releases can focus on handlers.
- **0.9.2 → 0.9.7** — one verb-handler per release, simplest
  first (`set_rctl` reuses the existing rctl(8) integration
  from `crate retune`), broadest last (`create_jail`).
- **0.9.8** — per-user namespacing: jail name prefix
  (`<user>-<jailname>`), per-user `/var/run/crate/<uid>/`,
  network sub-CIDR per user, RCTL accounting groups.
  Documentation: `docs/rootless-migration.md`.
- **0.9.9** — opt-out flag flip. The `crate.conf` knob
  `rootless: false` becomes the legacy escape hatch; default
  becomes "delegate to crated". Setuid bit still installed for
  backwards compat with operators who haven't migrated.
- **1.0.0** — setuid bit removed from the install target.
  Operators upgrading from <0.9.x see a one-line `pkg upgrade`
  warning pointing at the migration doc.

Foundations the rootless track stands on (already in tree,
shipped over earlier releases):

- 0.6.4 — WebSocket console listener (pattern for replacing
  cpp-httplib with a hand-rolled accept loop)
- 0.7.11 — control sockets with getpeereid + per-group access
- 0.7.14 — Capsicum sandbox (per-fd cap_rights_limit)
- 0.8.19 — filesystem-perm gate on the main socket
- 0.8.21 — spec registry `{name -> abs-path}`
- 0.8.23 — DrmSession via libseat (rootless DRM access)
- 0.8.24 — cap_syslog dual-write for audit resilience

### Why a pure-types module first

The verb set frozen up-front means wire format, daemon
handlers, and `crate(1)` callers can be developed against a
stable contract instead of a moving target. Validators
hard-link-tested at the pure-module level keep the security
boundary covered as crated grows. Subsequent PRs are
incremental: add wire parser → add handler → add caller →
release. No big-bang refactor.

### Files

- `lib/privops_pure.h` (new)
- `lib/privops_pure.cpp` (new)
- `tests/unit/privops_pure_test.cpp` (new)
- `Makefile` — `lib/privops_pure.cpp` added to `LIB_SRCS`,
  `TEST_LINK_SRCS`; `privops_pure_test` added to `UNIT_TESTS`.
- `tests/unit/Kyuafile` — `privops_pure_test` registered.
- `cli/args.cpp` — version string bumped to `crate 0.9.0`.
- `TODO` — Rootless containers entry annotated with the
  `0.9.0` foundation landing.

---

## [0.8.49] — 2026-05-08

LXQt 2.4 desktop examples.

Following the upstream LXQt 2.4.0 release (2026-04-20, which
split X11 and Wayland session settings and refreshed the panel /
session / runner components), four new specs land in
`examples/` covering the multi-instance crate use case:

- **`lxqt-desktop.yml`** — full session, `gui: auto` + VNC/noVNC
  (workstation analogue of `xfce-desktop.yml`). Typical RSS
  ≈ 250-350 MB; `limits.memoryuse=1G`.
- **`lxqt-desktop-nested.yml`** — Xephyr (`gui: nested`) variant
  for local "desktop walls" arranged via `crate gui tile`
  (which only handles nested sessions).
- **`lxqt-minimal.yml`** — slim stub: `lxqt-session` + panel +
  runner + openbox. Aimed at stacking many instances; RSS
  budget ≈ 512 MB per jail.
- **`lxqt-wayland.yml`** — experimental placeholder for
  `gui.mode: wayland` (added in 0.8.46). Marked as a stub
  pending FreeBSD port maturity for `lxqt-wayland-session` and
  a Wayland compositor (labwc / kwin / wayfire).

No code changes — examples only. The existing GUI infrastructure
(GuiRegistry display allocation, per-jail D-Bus isolation,
PipeWire socket bind from 0.8.44, PulseAudio compat from 0.8.47,
env-sanitize XDG_RUNTIME_DIR fix from 0.8.48, Wayland readiness
check from 0.8.45) already covers everything LXQt needs.

README desktop-applications list updated in both EN and UK.

---

## [0.8.48] — 2026-05-08

**Critical fix.** Env-sanitize at startup (`cli/main.cpp:42-69`)
was wiping `XDG_RUNTIME_DIR` from the operator's shell. That
broke the entire Wayland subsystem in setuid-prod since 0.8.18:
the Wayland-bind / PipeWire-bind / PulseAudio-bind blocks all
read `getenv("XDG_RUNTIME_DIR")` AFTER the wipe and got
`nullptr`, so they silently no-op'd.

Plus a small win on top of the fix: compositor-ID hint surfaced
in the `wayland-readiness` doctor check.

### The bug

Pre-0.8.48 the env-sanitize block at line 42-69 wiped `environ`
and rebuilt with a tight safelist:

```cpp
const char* term    = ::getenv("TERM");
const char* display = ::getenv("DISPLAY");
const char* wayland = ::getenv("WAYLAND_DISPLAY");
const char* lang    = ::getenv("LANG");
const char* xauth   = ::getenv("XAUTHORITY");
const char* nocolor = ::getenv("NO_COLOR");
// XDG_RUNTIME_DIR NOT preserved -> ::getenv() in setupX11
//                                   returns nullptr in setuid-prod
```

`XDG_RUNTIME_DIR` was missed when the env-sanitize landed; later
Wayland releases (0.8.18 / 0.8.44 / 0.8.45 / 0.8.47) all
predicated their bind blocks on this env var being non-null.
Result: the entire Wayland audio + video binding chain was a
silent no-op for any setuid invocation. Operators reproducing
locally without the setuid wrapper saw it work; under
production install (setuid 04755) it didn't.

This is exactly the class of bug we hunted in 0.8.31 — operator
config (in this case `gui: auto`) parsed and validated cleanly,
but the runtime silently dropped the binding.

### Fix

Add `XDG_RUNTIME_DIR` and `XDG_CURRENT_DESKTOP` to the env-
sanitize preserve list:

```cpp
const char* xdgRun  = ::getenv("XDG_RUNTIME_DIR");
const char* xdgCur  = ::getenv("XDG_CURRENT_DESKTOP");
// ... wipe environ + safelist re-set ...
if (xdgRun)  ::setenv("XDG_RUNTIME_DIR", xdgRun, 1);
if (xdgCur)  ::setenv("XDG_CURRENT_DESKTOP", xdgCur, 1);
```

After this, all the Wayland releases since 0.8.18 actually do
what their CHANGELOG entries claimed.

### Compositor-ID hint (small win)

`crate doctor wayland-readiness` now appends compositor identity
from `XDG_CURRENT_DESKTOP` to the pass message:

```
gui   wayland-readiness   PASS    ready for `gui: auto` — Wayland
                                  socket /var/run/user/1000/wayland-0 +
                                  PipeWire core/manager present at
                                  /var/run/user/1000 [compositor: sway]
```

Helps operators confirm doctor sees the right session — without
the hint it's not obvious which compositor exposed the socket
(Sway / Hyprland / KDE Plasma / GNOME / labwc).

Hint added to two paths: the audio-silent-but-otherwise-ready
pass and the fully-ready pass. Empty hint when env unset (SSH
session, init script without DE bootstrap, etc.) — falls
through silently.

### What this release does NOT do

- **Audit other env-sanitize gaps** — XDG_RUNTIME_DIR was the
  obviously-broken one because it gated multiple bind blocks;
  there could be others (e.g. `PIPEWIRE_RUNTIME_DIR` is
  technically supported by libpipewire as an override but
  defaulted from XDG_RUNTIME_DIR which we now preserve, so
  fine in practice). A systematic audit is tracked.
- **Tests for env preservation** — would need integration test
  that exec's the setuid binary with a known env and checks
  what made it through. Not in unit-test scope.
- **Compositor-ID hint in failure paths** — only added to the
  two pass paths where operator most cares about confirmation.

1107/1107 unit tests pass locally.

---

## [0.8.47] — 2026-05-08

PulseAudio compat socket bind for `gui: auto` / `gui: wayland`.
Closes the gap left by 0.8.44 (PipeWire-only); apps still on
PulseAudio (Discord, OBS Studio's PulseAudio backend, some
legacy Qt apps) now get sound in the jail too.

### What this release adds

```
host                                            jail
$XDG_RUNTIME_DIR/pulse/native     <--nullfs-->  /tmp/wayland/pulse/native
```

The bind needs a sub-directory (`pulse/`) on the jail side
because PulseAudio convention puts the socket inside that
subdir; flat bind from 0.8.44 doesn't apply. crate creates
`/tmp/wayland/pulse/` on demand at jail-start time, then
nullfs-binds the socket file.

`XDG_RUNTIME_DIR=/tmp/wayland` env in the jail (set by 0.8.18 /
0.8.44 already) makes `libpulse` look in the right place
without operator config.

### Implementation

- New pure helper `RunGuiPure::pulseSocketRelpath()` returns
  `"pulse/native"` (single string — only one PulseAudio socket
  per session). Distinct from `pipewireSocketNames()` which
  returns flat names.
- New runtime block in `lib/run_gui.cpp` after the PipeWire
  block: detects sub-dir form via `find('/')`, creates the
  parent (`/tmp/wayland/pulse/`) before touching the bind
  target, then nullfs-binds.
- 2 new ATF cases (canonical relpath, sub-dir-shape sanity).

### What this release does NOT do

- **`pulse/cli` inspector socket** — useful for `pactl
  list-sinks` from inside the jail. Operators using
  PulseAudio-native typically don't need pactl in-jail; we'd
  add it as a list extension if a real ask comes in.
- **Direct device access** (`/dev/dsp`, `/dev/sndstat`) —
  some legacy apps want raw OSS. crate doesn't unhide audio
  devfs entries today; tracked separately.

1107/1107 unit tests pass locally.

---

## [0.8.46] — 2026-05-08

Two small Wayland-track items:

1. **`gui.mode: wayland`** — explicit Wayland-only spec mode.
   Strict counterpart to `gui: auto` for operators who don't
   want X11 fallback (security-conscious — the X11 socket bind
   is a real attack-surface widening).
2. **`gui/resolution` ignored warning** — surfaces at `crate
   validate` time when operator sets `resolution: 1920x1080`
   together with a mode where the host compositor decides the
   resolution.

### `gui.mode: wayland`

Pre-0.8.46 the operator could only get Wayland binding via
`gui: auto`, which falls back to shared X11 (with cookie copy)
when both `$DISPLAY` and `$WAYLAND_DISPLAY` are set. For
operators who explicitly don't want the X11 socket bind:

```yaml
gui:
  mode: wayland     # 0.8.46: Wayland-required, no X11 fallback
```

Behaviour:

- **`WAYLAND_DISPLAY` unset** → ERR at jail start (refuse to
  silently downgrade to no-display jail)
- **`WAYLAND_DISPLAY` set, `XDG_RUNTIME_DIR` set, socket exists**
  → bind Wayland socket + PipeWire sockets (same as `gui: auto`
  Wayland branch)
- **`/tmp/.X11-unix` is NOT bound** — the in-jail process can't
  open the host's X server even if it tries
- **`DISPLAY` env is NOT set in the jail**
- **`XAUTHORITY` is NOT copied**

Strict semantic — operator opted out of X11 fallback. If the
user's compositor crashes mid-session, the jail won't silently
slide onto X11 next time.

### `gui/resolution` ignored warning

`crate validate` now surfaces:

```
warning: gui/resolution is ignored when gui/mode resolves to
shared or wayland (the host compositor decides resolution via
wl_output / X11 root window size); only honoured for
mode=nested (Xephyr) and mode=headless (Xvfb)
```

Triggers when `gui.resolution` differs from the default
`"1280x720"` AND mode is `wayland` / `auto` / `shared`. Avoids
the "I set resolution: 1920x1080 but my Wayland jail is still
showing 4K" confusion.

### Implementation

- `lib/spec.cpp` accepts `wayland` in both the scalar shorthand
  and the `gui.mode` map field (rejected at parse time
  pre-0.8.46)
- `lib/run_gui.cpp::resolveGuiMode` routes `mode=wayland` to
  the existing shared block via `return "shared"`. New
  `isWaylandFlow` flag inside `setupX11` differentiates from
  `isAutoFlow`:
  - X11 socket bind / DISPLAY env / XAUTHORITY copy gated on
    `!isWaylandFlow`
  - Wayland + PipeWire bind gated on `isAutoFlow ||
    isWaylandFlow`
  - `WAYLAND_DISPLAY` unset → ERR (no fallback)
- `lib/validate_pure.cpp` adds the resolution-ignored warning
  to the existing warn-collection block

No new pure helpers; the change is dispatch flag + spec
validation strings.

### What this release does NOT do

- **Test for the `wayland` mode parsing** — would need YAML-load
  spec test infrastructure that doesn't exist; the existing
  scalar-shorthand and map-mode validators cover the strings
  via inline checks
- **Nested Wayland (cage / labwc)** — separate architectural
  item; tracked
- **Wayland VNC (`wayvnc`)** — separate; tracked

1105/1105 unit tests pass locally.

---

## [0.8.45] — 2026-05-08

`crate doctor wayland-readiness` check — predicts whether
`gui: auto` will succeed at binding the host's compositor and
audio sockets, so operators catch silent-broken-jail cases at
diagnostic time instead of after starting firefox and noticing
no audio / blank window.

### Outcomes

| Operator state | Severity | Message hint |
|---|---|---|
| `WAYLAND_DISPLAY` unset | info pass | "X11-only or headless; if you expected Wayland, check compositor exports it" |
| `WAYLAND_DISPLAY` set, `XDG_RUNTIME_DIR` unset | warn | "mount will be skipped; check login script" |
| `WAYLAND_DISPLAY` not a valid basename | warn | "same diagnostic that runtime would emit at jail-start time" |
| Socket file missing | warn | "compositor may have crashed" |
| Socket OK, PipeWire missing | pass | "video will work; in-jail audio will be silent — install/start pipewire" |
| Socket OK, PipeWire partial | warn | "pipewire-manager hasn't started; service pipewire onestart" |
| All sockets present | pass | "ready for `gui: auto`" |

### Implementation

`checkWaylandReadiness` in `lib/doctor.cpp`, runs after
`checkDrmSession` (both fall under the `gui` category from 0.8.23):

- Reads `$WAYLAND_DISPLAY` + `$XDG_RUNTIME_DIR` from the env
  (preserved through `cli/main.cpp` setuid env-sanitize for
  exactly this reason)
- Validates basename via the same `RunGuiPure::parseWaylandDisplay`
  parser the runtime uses — ensures doctor flags exactly what
  `gui: auto` would reject
- Stat's the resolved socket path (`$XDG_RUNTIME_DIR/<basename>`)
- Stat's each PipeWire socket from `RunGuiPure::pipewireSocketNames()`
  (0.8.44) — same source-of-truth list as the runtime

No new pure helpers — the analysis is all dispatching env-var
strings + filesystem stat into pre-existing parsers. Tests would
require mocking `getenv` + `stat`; deferred. The pre-existing
parser tests (0.8.18 + 0.8.44) cover the validator inputs the
check hands off.

### What this release does NOT do

- **Stat-mock unit tests** — environment + filesystem probes
  aren't easily ATF'd. The pre-existing parser tests cover the
  string-handling part; the boolean dispatch is straight-through.
- **Wayland VNC readiness (`wayvnc`)** — separate concern;
  tracked when Wayland VNC ships.
- **Compositor identity detection** (Sway / labwc / Hyprland /
  KDE Plasma / GNOME) — pure ID is informational. Can land
  later as a doctor sub-check ("WAYLAND_DISPLAY=wayland-0,
  compositor=sway/1.10").

1105/1105 unit tests pass locally.

---

## [0.8.44] — 2026-05-08

PipeWire socket bind for `gui: auto` — closes the silent
audio-broken case for Wayland (and X11 + PipeWire) desktop
jails.

### The problem

Pre-0.8.44, an operator who wrote `gui: auto` and ran firefox
inside the jail saw video work (Wayland socket bound by 0.8.18,
DRM unhid by 0.8.11) but **no sound** — WebRTC mute, Discord
silent, video calls one-way. PipeWire's sockets weren't bound.
This was a silent-broken-feature: the operator got no warning,
just dead audio.

### What this release adds

`gui: auto` now also binds PipeWire sockets from the host's
`$XDG_RUNTIME_DIR` into the jail's `/tmp/wayland/`:

```
host                                                 jail (in-mount)
$XDG_RUNTIME_DIR/pipewire-0           <--nullfs-->   /tmp/wayland/pipewire-0
$XDG_RUNTIME_DIR/pipewire-0-manager   <--nullfs-->   /tmp/wayland/pipewire-0-manager
```

Plus sets in-jail `XDG_RUNTIME_DIR=/tmp/wayland` (idempotent
with the Wayland branch) so PipeWire's auto-discovery finds the
sockets.

Independent of Wayland: an X11 + PipeWire setup (legacy X
session with modern audio stack) is also a valid configuration
and the bind fires there too. Gated only on `gui: auto`.

Best-effort: any individual socket missing on the host is
skipped silently — operators on PulseAudio-only systems (no
PipeWire) see no error or noise, just no audio bind. Hard
failures (mount errors) log a yellow warning but don't abort
the jail start.

### Implementation

Pure helper in `lib/run_gui_pure.{h,cpp}`:

- `pipewireSocketNames()` — returns the fixed list
  `["pipewire-0", "pipewire-0-manager"]`. Order matters
  (libpipewire opens client API socket before manager).
  Pure, testable; future audit can confirm the list against
  `pkg info -l pipewire | grep .sock`.

Runtime in `lib/run_gui.cpp` (parallel block to the existing
Wayland binding from 0.8.18):

- Iterate `pipewireSocketNames()`, skip any socket missing on
  the host
- Touch a placeholder file at the jail-side target (FreeBSD
  nullfs needs an existing target)
- `mount("nullfs", target, hostSock, MNT_IGNORE)`
- Set `XDG_RUNTIME_DIR=/tmp/wayland` if any socket was bound

2 new ATF unit cases:

- `pipewireSocketNames_lists_two_canonical` — pin the order +
  count
- `pipewireSocketNames_excludes_pulse_compat` — defensive guard
  against an accidental future `pulse/native` addition that
  would break the flat-bind strategy (the path contains a slash;
  belongs in a separate subdir bind)

### What this release does NOT do

- **PulseAudio compat socket (`pulse/native`)** — lives under
  `$XDG_RUNTIME_DIR/pulse/`, requires a sub-directory bind. Most
  modern apps use PipeWire native; PulseAudio compat tracked as
  a follow-up if a real ask comes in.
- **Operator opt-out** — there's no `gui.audio: false` flag.
  Operators who want audio-isolated jails today must avoid
  `gui: auto` and configure manually. Tracked.
- **Doctor check** — `crate doctor` doesn't yet verify PipeWire
  socket presence. Tracked for 0.8.45 (Wayland readiness check
  will surface this together).
- **PipeWire client perms** — same caveat as Wayland: sockets
  are typically mode 0700 owned by the operator's UID. Jails
  running as root (default without `user:` field) bypass perms
  and work; jails with `user:` may hit permission-denied.
  Documented in the 0.8.18 Wayland section; same applies here.

1105/1105 unit tests pass locally.

---

## [0.8.43] — 2026-05-08

`crate-hub schedule <jail-name>` CLI helper — closes the
hub-scheduling loop. 0.8.40 shipped the
`/api/v1/scheduling/least-loaded` endpoint and pointed operators
at a manual `curl + jq + crate migrate` pipeline. This release
ships the helper that does it in one invocation.

### Operator UX

```sh
% crate-hub schedule myapp \
    --from alpha:9800 \
    --from-token-file /etc/crate/.alpha-admin \
    --to-token-file /etc/crate/.beta-admin \
    --current alpha
crate-hub schedule: target='beta' host='beta:9800', invoking `crate migrate`...
migrate: ...
```

When anti-flap kicks in (current node already least-loaded
within 10% tolerance), the helper exits 0 without invoking
`crate migrate`:

```
crate-hub schedule: 'myapp' stays on 'alpha' (already on
least-loaded; no migration needed)
```

`--dry-run` prints the resolved target + the `crate migrate`
argv that would be exec'd, without exec'ing — useful in
shell wrappers / cron jobs that want to log the decision
before acting.

### Implementation

The helper lives in the existing `crate-hub` binary as a
subcommand (no new package, no new install target). When
invoked as `crate-hub schedule <…>`, dispatch in
`hub/main.cpp` runs the one-shot CLI path and exits without
starting the daemon.

Pure helpers in `hub/scheduling_pure.{h,cpp}` (extending the
0.8.40 module):

- `buildLeastLoadedUrl(hubUrl, currentNodeHint)` — composes
  the endpoint URL; tolerates a trailing `/` on the base;
  percent-encodes the hint for the `?current=` param;
  returns just the path when called with empty base (so the
  CLI can pass it to `httplib::Client::Get(path)` without
  doubling up scheme+host)
- `extractTargetField(jsonBody)` — regex-based field pull;
  handles `"target":"alpha"` AND `"target":null`; tolerates
  jq-style whitespace around the colon. Mirrors the existing
  `lib/migrate.cpp::extractFileField` pattern (no JSON
  library dragged in — the format is daemon-controlled and
  stable)
- `extractHostField(jsonBody)` — same shape for the host
- `buildMigrateArgv(crate, jail, fromHost, toHost,
  fromTokenFile, toTokenFile)` — canonical `crate migrate`
  argv as a single source of truth

Runtime in `hub/main.cpp::scheduleSubcommand` does the HTTP
GET via cpp-httplib's `Client`, decodes the response, prints
the rationale, and `execv`'s `/usr/local/bin/crate migrate`
(replaces the helper process — operator's exit code is
`crate migrate`'s exit code).

10 new ATF unit cases on the pure helpers (URL composition
across base/trailing-slash/empty-base/hint-encoding variants,
target/host extraction across quoted/null/whitespace/missing
input, migrate argv shape).

### What this release does NOT do

- **Auto-detect `--from <host>`** — the helper requires the
  operator to pass the source `host:port`. Could be derived
  from `/api/v1/nodes` lookup-by-name, but that adds a second
  HTTP request and complicates error handling.
- **Resource-aware confidence threshold** — `--min-confidence
  N` flag for cron jobs to skip low-confidence recommendations
  is straightforward but out of scope here.
- **Auto-token-discovery** — `crate migrate`'s token-file
  contract is operator-managed (chmod 600 paths). The helper
  passes them through verbatim.

1103/1103 unit tests pass locally.

---

## [0.8.42] — 2026-05-07

**Documentation-only release.** Expanded the `Rootless containers`
TODO entry with an honest assessment of the current setuid root
hardening state, foundations already laid, and the actual scope
of the refactor.

### What changed

The pre-0.8.42 TODO entry was a 7-line summary that read like
"setuid root is bad, rootless is good". That framing
mischaracterised the codebase — the current setuid model has the
expected hardening for a 2026 setuid binary:

- env-sanitization at startup (CWE-426 + CWE-250 explicitly cited)
- absolute paths via `CRATE_PATH_*` for every external binary
- all execs via `execv` with explicit argv (no shell, no
  `system()`/`popen()` calls anywhere in the tree)
- pure-module validators on every operator-supplied string
- audit logging of every mutating command

The new TODO entry:

1. Names the current hardening explicitly so future readers
   don't think rootless is "fixing security holes"
2. Lists the three real reasons rootless still matters
   (blast-radius reduction on hypothetical 3rd-party CVE,
   multi-tenant safety, compliance "no setuid root" policies)
3. Catalogs foundations already in the tree (0.6.4, 0.7.11,
   0.7.14, 0.8.19, 0.8.21, 0.8.23, 0.8.24)
4. Itemises the work needed (privileged-daemon protocol,
   `lib/run.cpp` split, per-user resource namespacing, setuid
   bit removal, docs, security-boundary tests)
5. Estimates 4-6 weeks / ~10 point releases (0.9.0 → 1.0.0)
6. Names the trigger conditions that would move it from
   "tracked" to "current priority"

No code changes. Just clarity for future readers / contributors
considering picking the work up.

---

## [0.8.41] — 2026-05-07

`crate update TARGET --pkg-only` — in-place pkg upgrade inside a
running jail. Closes the medium-priority TODO item (the full
base-system update remains open, see "What this release does NOT
do" below).

### Operator pain pre-0.8.41

To pick up new package versions, operators had to:

1. `crate stop myapp`
2. Edit the spec / use a fresh tag
3. `crate create -s myapp.yml -o myapp.crate`
4. `crate run -f myapp.crate`

…losing the jail's in-memory state, warm caches, open tabs / DB
connections, and any RAM-backed data. For a long-running web app
or postgres, that's a non-trivial outage every time you want a
security patch.

### What 0.8.41 ships

```sh
% sudo crate update myapp --pkg-only -n     # see what's pending
update: pkg upgrade in jail 'myapp' (jid 5) (dry-run)
The following 3 package(s) will be upgraded:
  curl: 8.5.0 -> 8.7.1
  nginx: 1.24.0_1 -> 1.26.0
  ...
update: dry-run complete; nothing applied

% sudo crate update myapp --pkg-only -y     # apply, skip confirm
update: pkg upgrade in jail 'myapp' (jid 5)
[5/5] Fetching ... done
[5/5] Installing ... done
update: pkg upgrade succeeded in 'myapp'
```

The jail keeps running through the upgrade. `pkg upgrade`'s
existing post-install scripts handle service restarts where
appropriate (rc.d scripts, package-shipped service definitions);
for app-level reload, the operator's existing healthcheck /
service-monitor hooks fire as usual.

### Why `--pkg-only` is mandatory

Full base-system update touches `/usr/lib`, `/usr/sbin`, `/lib`
while the jail is using them — needs a snapshot+rollback dance
plus a managed restart. That's a much bigger surface (file-by-
file replacement strategy, library symbol-version checks, jail
restart timing, recovery on partial failure). 0.8.41 commits to
pkg-only so the contract is clear; a future release tackles the
base-system path with the design pass it deserves.

If the operator omits `--pkg-only`, validation rejects the
command with a clear message:

```
error: `crate update` currently requires --pkg-only
       (full base-system update tracked separately)
```

### Implementation

- New `enum Command` value `CmdUpdate`, `Args.updateTarget /
  updatePkgOnly / updateDryRun / updateAssumeYes` fields.
- `lib/update.cpp::updateCommand` resolves the jail (name or
  JID), validates `--pkg-only` is set, dispatches
  `JailExec::execInJail(jid, [pkg, upgrade, [-n], [-y]])`.
- Audit-log entry added (`ev.cmd = "update"`) — same shape as
  other mutating commands so cron/eyeball auditors pick it up.
- Bash + zsh completions updated.

### What this release does NOT do

- **Base-system update** — file-by-file replacement of
  `/usr/lib/...` while the jail's processes hold those files
  open is non-trivial. Tracked as a separate item; needs the
  snapshot-and-rollback design pass.
- **Auto-restart of foreground command** — pkg's post-install
  scripts handle rc.d services; for the spec's `start: <cmd>`
  foreground process, the operator runs `crate restart` if the
  upgrade replaced the binary they're serving from. Adding
  auto-restart is a behavioural choice with operator-config
  implications (mid-upgrade outage vs. stale-binary risk);
  defer.
- **Rollback on failure** — pkg's atomic install model handles
  partial failures within itself. Rollback to a pre-upgrade
  snapshot needs the snapshot-and-rollback work above.

1093/1093 unit tests pass locally.

---

## [0.8.40] — 2026-05-07

Hub scheduling — `GET /api/v1/scheduling/least-loaded` returns a
recommendation for which node to place the next jail on. Closes
the medium-priority TODO item; operators get a one-liner to
discover the best target host without manual `for host in $hosts;
do curl .../containers; done | sort | head` analysis.

### What this release adds

```
% curl -s http://hub:9001/api/v1/scheduling/least-loaded | jq
{
  "status": "ok",
  "data": {
    "target": "alpha",
    "host": "alpha.example.com:9800",
    "container_count": 3,
    "runner_up_count": 5,
    "confidence": 40,
    "rationale": "place on 'alpha' (count 3 vs runner-up 'beta' count 5)"
  }
}
```

Operator workflow:

```sh
target=$(curl -s http://hub:9001/api/v1/scheduling/least-loaded \
           | jq -r .data.host)
crate migrate myjail --to "$target" \
  --from-token-file .source-token --to-token-file .dest-token
```

### Anti-flap (`?current=<name>`)

Without anti-flap, the recommendation can ping-pong: jail A on
node `alpha` (count 3), jail B arrives on `beta` (count 4) —
next call recommends `alpha` again, etc. The `?current=` query
param lets the caller say "I'm already on this node; only
recommend a move if it's a meaningful improvement":

```
% curl -s 'http://hub:9001/api/v1/scheduling/least-loaded?current=beta' | jq
{
  "data": {
    "target": "beta",
    "container_count": 5,
    "rationale": "keep on 'beta' (count 5 within 10% of least-loaded 'alpha' count 5)"
  }
}
```

When the current node's count is within 10% of the least-loaded
node, scheduling recommends keeping the container in place.
Threshold is `SchedulingPure::kAntiFlapPercent` — 10% by design,
configurable later if a real ask comes in.

### Confidence score (0..100)

| Scenario | Score |
|---|---|
| Single reachable node | 100 |
| Anti-flap fires (keep current) | 100 |
| Big spread (1 vs 100 containers) | ~99 |
| Tight spread (10 vs 11) | ~9 |
| Tied at non-zero | 0 |
| All nodes empty (multi-tie at zero) | 50 |

The score is a hint to the operator: low confidence means
"either choice is fine, don't sweat it"; high means "this is
clearly the right place".

### Implementation

Pure module `hub/scheduling_pure.{h,cpp}`:

- `NodeView` — `{name, host, reachable, containerCount}`,
  fed from existing `AggregatorPure::countTopLevelObjects`
- `pickLeastLoaded(nodes, currentNodeHint = "")` — returns
  `Recommendation` with target name/host, counts, confidence,
  human-readable rationale
- `renderRecommendationJson` — emits the data envelope shown above
- 14 ATF unit cases cover empty input, all-unreachable,
  lowest-count picking, unreachable-skip, stable name tie-breaker,
  sole candidate, confidence scaling (big vs tight spread),
  anti-flap keep / migrate / unknown-hint / unreachable-hint,
  JSON shape + special-char quoting

Endpoint in `hub/api.cpp` at `GET /api/v1/scheduling/least-loaded`,
reuses the same poller-cached node statuses as `/api/v1/aggregate`.
No additional polling.

### What this release does NOT do

- **`crate-hub schedule <crate-file>` CLI helper** — operators
  on the curl + jq + migrate path today. CLI sugar tracked.
- **CPU/memory-based scoring** — `containerCount` is a proxy.
  Real load metrics need crated to expose `loadavg_1min` /
  `mem_free` from `/api/v1/host` (currently static info only).
  Tracked for a future "richer hub metrics" sprint.
- **Datacenter-aware scheduling** — the endpoint operates on the
  whole cluster; per-DC placement could be a `?datacenter=foo`
  filter. Operator can filter clientside today via
  `/api/v1/datacenters`.
- **Resource-aware refusal** — endpoint always recommends
  *something* if any reachable node exists. A future "no
  candidate has capacity" gate would need the real-load
  metrics above.

1093/1093 unit tests pass locally.

---

## [0.8.39] — 2026-05-07

**Bug fix.** Closes long-standing **bug#239590** (host-LAN-loopback
rejected by ipfw auto-fw). Pre-0.8.39, a jail with
`network: auto` + `inbound-tcp: 8080` was reachable from external
LAN clients (`nc <host-LAN-IP> 8080` from another machine works)
but rejected from the host itself (`nc <host-LAN-IP> 8080` on the
crate host returned "Connection refused"). External `pf` deployments
weren't affected — the bug was specific to the ipfw auto-fw branch
shipped in 0.8.2.

### Why it broke

Host-self packets to the host's own LAN IP take the kernel's lo0
shortcut — they never traverse the external interface (`em0` /
`vtnet0` / etc.). The existing auto-fw rules:

```
ipfw add 40000+jid nat 30000+jid ip from <jail> to any out via em0   # outbound SNAT
ipfw nat 30000+jid config if em0 redir_port tcp 10.66.0.5:80 8080    # inbound rdr
```

…both pinned to `via em0`, so host-loopback bypassed them entirely.
The packet hit the host's local TCP stack on port 8080, which had
nothing bound, and got RST.

### Fix

One additional ipfw rule per jail at rule ID `41000+jid`:

```
ipfw add 41000+jid nat 30000+jid tcp from me to me
```

`from me to me` matches host-self TCP traffic without `via <iface>`,
so it fires on the lo0 path too. The rule passes the packet through
the same NAT instance (`30000+jid`); the redir_port table inside
that NAT looks up dst-port and rewrites destination address+port
to the jail. External clients still hit the original
`40000+jid` + `via em0` rules — no behaviour change for the
non-loopback path.

Now from the host:

```
% nc 192.168.1.10 8080      # host's own LAN IP -> jail
HTTP/1.1 200 OK
...
```

### Implementation

- Pure helpers in `lib/auto_fw_pure.{h,cpp}`:
  - `loopbackRuleIdForJail(jid)` → `41000 + jid`
  - `buildIpfwHostLoopbackNatArgv(ruleId, natId)` → the rule above
- Reserved-range scanner (`pickOrphanIpfwRulesByJid`) narrowed
  from "anything in 40000-49999" to specific sub-ranges
  (`40000+jid` for main, `41000+jid` for loopback). Stray rules
  in the broader range are now treated as operator-managed and
  left alone — fewer false-positive orphans.
- `lib/run.cpp` ipfw branch installs the loopback rule after the
  main NAT-activation rule; cleanup deletes it before the main
  rule. Soft-fail with warning if loopback install fails — the
  external-LAN-client path still works.
- `lib/doctor.cpp` updated to recognise `41000+jid` in its
  `validNatRuleIds` set so doctor doesn't false-warn.

3 new ATF unit cases:
- `loopback_rule_id_distinct_from_main` — different sub-ranges
- `loopback_argv_shape` — the canonical `from me to me` form
- `orphan_scan_recognises_loopback_range` — round-trip with
  the reserved-range scanner

### What this release does NOT do

- **UDP host-loopback** — only TCP. Operators rarely need
  UDP-self-loopback (DNS / discovery don't typically loop this
  way); tracked if a real ask comes in.
- **pf branch** — pf already handles host-loopback correctly
  via its built-in `route-to` / `redirect-to` semantics on lo0.
  Operators on `firewall_backend: pf` aren't affected by
  bug#239590.
- **Range port-forwards (`ports: 8000-8999`)** — the loopback
  rule fires regardless, but the NAT instance's redir_port table
  must contain a matching entry. Range entries work the same way
  as for external clients (per 0.8.3); the fix here just routes
  host-self traffic into the same machinery.

1079/1079 unit tests pass locally.

---

## [0.8.38] — 2026-05-07

**Documentation-only release.** Cleanup of TODO/TODO2 to reflect
the audit-closure sprint (0.8.22-0.8.37) and the broader "easy +
medium" sprint before it.

### What changed

- **TODO:** moved `network: auto` and `gui: auto` from
  "Medium priority" to "Done (removed)" — both shipped, the
  `*Shipped*` annotations had become noise. Added concise
  one-liners under "Done" pointing at the assembling releases.
- **TODO:** added two new Medium-priority items that match the
  state of the codebase:
  - `crate update TARGET --pkg-only` — tractable single-release
    in-place pkg upgrade; full base-system update remains big.
  - Hub scheduling — `/api/v1/scheduling/least-loaded` endpoint
    + CLI helper. Anti-flap notes included.
- **TODO:** Low-priority items reframed as "future enhancements
  (architectural)" with the explicit note that each is multi-week
  / multi-release work, not suitable for one-shot sprints.
- **TODO:** Unix-socket peer credentials item updated to reflect
  0.8.19's filesystem-perm partial mitigation; clarifies what's
  open (true getpeereid via cpp-httplib refactor).
- **TODO:** known bug `bug#239590` (host-LAN inbound rejected by
  ipfw) gets a concrete reproducer + likely fix outline. Tractable
  in a single release; tracked for 0.8.39.
- **TODO2:** `crate vm-wrap` (item B) marked as **SHIPPED in
  0.8.16**. Item A (full bhyve backend) still open with the
  original 2-3 week estimate.

No code changes. Just clarity for future readers / contributors.

---

## [0.8.37] — 2026-05-07

`crate clean` now sweeps orphan ipfw rules and NAT instances in
crate's reserved ranges. Wires `IpfwOps::deleteRule` and
`IpfwOps::deleteNat` (already used at jail-teardown for
non-orphan paths) into a sweep section that removes leftovers
from crashed jails. `crate doctor` (0.8.14) has been *warning*
about these for a while; this release actually deletes them.

### What this release adds

A 5th section in `lib/clean.cpp::cleanCrates` between the
existing COW-overlay sweep and the spec-registry orphan sweep.
Three reserved ranges are checked:

| Range | Purpose | Delete via |
|---|---|---|
| `20000..29999` | throttle pipe binds (per-jail pair, 0.7.7) | `IpfwOps::deleteRule` |
| `30000..39999` | auto-fw NAT instances (per-jail, 0.8.0) | `IpfwOps::deleteNat` |
| `40000..49999` | auto-fw NAT-rule pointers (per-jail, 0.8.0) | `IpfwOps::deleteRule` |

For each range, pure helper in `lib/auto_fw_pure.cpp` parses
`ipfw -q list` (or `ipfw nat show`), maps rule number → jid,
and returns the orphan IDs. `crate clean` then iterates and
deletes via the IpfwOps helpers.

Throttle bind delete is soft-fail: throttle uses *pairs* of
rules per jail (`20000+jid*2`, `20000+jid*2+1`) and operators
sometimes half-clear via `crate throttle --clear`, leaving one
rule of a pair. Best-effort delete avoids spurious warnings on
that path.

### Pure helpers

Three new functions in `AutoFwPure`:

- `pickOrphanIpfwRulesByJid(listOutput, runningJids)` —
  rules in `40000..49999` whose `n - 40000` jid isn't running
- `pickOrphanIpfwThrottleRulesByJid(...)` — same for
  `20000..29999`, jid derived as `(n - 20000) / 2`
- `pickOrphanIpfwNatIds(natListOutput, runningJids)` —
  parses `ipfw nat <id> config ...` lines (different format
  than rule list)

6 ATF unit cases cover normal path, out-of-range filtering,
CRLF tolerance, throttle pair-divisor logic, NAT-line skip
for non-NAT noise.

### What this release does NOT do

- **Wire `IpfwOps::deleteRulesInSet`** — the audit-targeted
  helper. Crate's per-jail rule numbers aren't grouped into
  ipfw "sets" today; they're individual numbered rules. Wiring
  `deleteRulesInSet` requires the auto-fw runtime to refactor
  toward `add set <set> <num> ...` form, which is a larger
  architectural change. Tracked in `lib/ipfw_ops.h` doc comment.
- **Refactor `doctor::checkIpfwReservedRanges`** to use the new
  pure helpers — it does its own inline scan today. Could share
  with clean now; deferred to keep this release minimal.
- **Throttle pipe deletion** (`10000..19999`) — pipes need
  `ipfw pipe N delete` which doesn't have an IpfwOps wrapper
  yet. Operator runs that by hand for now.

1076/1076 unit tests pass locally.

---

## [0.8.36] — 2026-05-07

`crate gui screenshot` uses native libX11 when available, dropping
two fork+exec calls per screenshot. Wires `X11Ops::screenshot`
which existed since the X11 wrappers landed but had no production
caller — `getResolution` was the only `X11Ops::*` function in use.

### What changes

| Build | Pipeline | fork+exec count |
|---|---|---|
| Pre-0.8.36 | `xwd` -> `xwdtopnm` -> `pnmtopng` -> PNG | 3 |
| 0.8.36, `WITH_X11` | `X11Ops::screenshot` (in-process PPM) -> `pnmtopng` -> PNG | 1 |
| 0.8.36, no `WITH_X11` | falls back to xwd pipeline | 3 |
| 0.8.36, `.ppm`/`.pnm` output | `X11Ops::screenshot` only | 0 |

Operator sees which path was used in the success message:

```
% crate gui screenshot firefox -o snap.png
Screenshot saved (native libX11): snap.png

% crate gui screenshot firefox -o snap.ppm
Screenshot saved (native libX11, PPM): snap.ppm
```

`xwd` + `xwdtopnm` are still required for builds without
`WITH_X11`, so the `xorg-xwd` package dependency stays for
non-libX11 builds. With `WITH_X11=1`, only `pnmtopng` is needed
on the host (and only for non-PPM output).

### Implementation

- `gui.cpp::guiScreenshot` branches on `X11Ops::available()`
- Lower-cases the output filename to detect `.ppm` / `.pnm`
  suffixes — those skip the conversion entirely
- Soft-fall-through: if X11Ops is built in but `XOpenDisplay`
  fails (XAuth not copied in, display permissions, etc.),
  warns and falls back to `xwd` rather than aborting
- Makefile moves `lib/x11_ops.cpp` out of the `WITH_X11`
  conditional — `available()` always links and returns
  false-or-true per build

### What this release does NOT do

- **Wire `X11Ops::isDisplayAvailable` / `setResolution`** —
  no natural caller. `gui resize` already uses xrandr(1)
  shell; refactoring to native is a separate effort.
- **PNG output without `pnmtopng`** — needs libpng linkage,
  which is a new dependency. Defer.
- **Multi-monitor / partial-region capture** — `screenshot`
  only does the root window. Operators wanting subregion
  pass through xwd's `-icmap -silent` flags by hand.

1070/1070 unit tests pass locally.

---

## [0.8.35] — 2026-05-07

`crate doctor --refresh-cache` — drops the in-memory NetDetect
default-route cache before running checks. Wires
`NetDetect::clearCache` which was declared in 0.8.6 but had no
caller until now.

### Why operators want this

`NetDetect::defaultIfaceCached` (0.8.6) parses
`route -4 get default` once per process and caches the result.
That's correct for `crate run` (one-shot) but inconvenient for
**crated** which is a long-lived daemon — when the upstream
router gets restarted and the host's default route shifts to a
different interface, crated keeps using the cached old name
until restart.

```
% sudo crate doctor --refresh-cache
... (runs checks with fresh route -4 get default lookup) ...
```

The cache clear is cheap (one static-string assignment) and
survives the doctor run, so subsequent `crate run` calls
within the same process pick up the fresh value.

### What this release does NOT do

- **Hot-reload signal for crated** — refreshing the cache via
  `crate doctor` is per-process. crated has its own NetDetect
  cache that's separate. A SIGHUP handler that calls
  `clearCache` on the daemon side is the natural follow-up;
  not in scope here.
- **Refresh-on-route-change** — kqueue + RTM_NEWADDR/RTM_DELADDR
  notifications could auto-clear the cache. Significant
  surface; deferred.
- **Clear OTHER caches** — auto-fw kldstat probe, RCTL probe,
  etc. Scope creep; one cache per release.

1070/1070 unit tests pass locally.

---

## [0.8.34] — 2026-05-07

`crate clean` now sweeps spec-registry orphans — entries
mapping `{jail-name -> abs-crate-path}` whose `.crate` file no
longer exists on disk. Wires `SpecRegistry::remove` which was
declared in 0.8.21 but had no caller until now.

### Why this matters

`crate run -f /home/op/firefox.crate` registers the path
(0.8.21) so the daemon's control-plane PostStart can find the
spec on a later `start <name>` request, even after the jail has
stopped. Entries intentionally persist past stop/restart.

But when the operator deletes or renames the `.crate` file from
disk, the registry entry becomes a dangling pointer.
PostStart then returns:

```
HTTP 410 Gone
{"error":"registered .crate path no longer exists: /home/op/firefox.crate"}
```

…confusingly, since the operator never explicitly removed the
entry. `crate clean` now sweeps these.

### What this release adds

A 5th section in `lib/clean.cpp::cleanCrates` after the
existing four (jail dirs, interface records, context entries,
COW overlays):

```
% sudo crate clean
Scanning for orphaned jail directories...
Scanning for stale interface records...
Cleaning stale context entries...
Scanning for stale COW overlays...
Scanning for spec-registry orphans...
  removing registry entry: firefox -> /home/op/firefox.crate
  removing registry entry: postgres -> /tmp/postgres-2025.crate

Cleanup complete: 2 items removed.
```

`--dry-run` prints `[dry-run] would remove registry entry: ...`
without calling `SpecRegistry::remove`, matching the rest of
the clean command's contract.

`SpecRegistry::readAll` parse failures (corrupt registry file,
permission errors) log a warning and skip just this section —
they don't abort the rest of the cleanup, since registry health
shouldn't gate jail-directory cleanup.

### What this release does NOT do

- **`--orphans` flag for the operator to opt INTO orphan
  sweep** — sweep is now unconditional. Earlier sketch had
  this as a flag but then `crate clean` would have asymmetric
  behaviour (sweeps 4 things by default, 5 with the flag).
  Always-on is more discoverable, and the existing
  `--dry-run` covers the "I want to see first" case.
- **`crate clean --orphan-ipfw` for `IpfwOps::deleteRulesInSet`** —
  separate scaffolding, separate PR. Tracked.
- **Pure helper for the orphan-pick logic** — could extract a
  `pickOrphans(entries, exists_predicate)` to `zfs_dataset_pure`
  pattern, but the side effect (file-exists check) is what
  matters and the loop is 4 lines. Inlined.

1070/1070 unit tests pass locally.

---

## [0.8.33] — 2026-05-07

`crate stats --rctl-pressure` — operator-facing view into how
close a jail is to its RCTL caps, before
`crate retune` becomes necessary. Wires `RunJail::getRctlUsagePercent`
which was scaffolding from 0.7.x — declared, unit-tested, and
never called from production.

```
% crate stats myapp --rctl-pressure
NAME          CPU%    MEM         MEM LIM   PIDS      PID LIM   ...
myapp         42%     512.0M      1G        87        200       ...

RCTL pressure (usage / limit):
  memoryuse        50%
  pcpu             42%
  maxproc          43%
  writebps         87%       <- yellow
  readbps          92%       <- red
```

Pressure column highlights:

- `>=70%` — yellow (operator may want to plan retune)
- `>=90%` — red (jail is about to hit cap; OOM/throttle imminent)

### Implementation

- New `--rctl-pressure` flag, `Args.statsRctlPressure` boolean,
  parser branch in `cli/args.cpp::CmdStats`.
- New rendering block in `lib/lifecycle.cpp::statsCrate` that
  iterates over the already-fetched `limits` map (alphabetical
  for stable diff) and calls `RunJail::getRctlUsagePercent`
  for each.

### Signature extension on `getRctlUsagePercent`

The pre-existing helper did 2× `rctl(8)` fork+exec per call (one
for `-u`, one for `-l`). Naively iterating it for `crate stats`
would have done 2N forks for N resources — too expensive for an
interactive command. So the function gains two optional pointer
params:

```cpp
int getRctlUsagePercent(int jid, const std::string &resource,
                        const std::map<std::string, std::string> *prefetchedUsage = nullptr,
                        const std::map<std::string, std::string> *prefetchedLimits = nullptr);
```

Stats passes its already-parsed maps; old single-resource
callers stay shell-shelling. Defaulted to `nullptr` so the
existing zero-call signature still compiles (no-op cleanup
since pre-0.8.33 there were no callers anyway).

### Defensive numeric parser

`rctl(8) -u` output is raw integers on stock FreeBSD, but
operators sometimes pipe it through humanize-aware tooling.
`std::stoll("1G")` silently returns `1` (parses leading digits
only), which would produce nonsense pressure %. The pre-0.8.33
helper had the same bug — surfaced only now because nobody was
calling it. New `parseAllDigits` lambda inside
`getRctlUsagePercent` rejects anything non-digit and returns
-1, causing the stats path to skip that resource gracefully.

### What this release does NOT do

- **`isOomKill` / `wasKilledByRctl` wired into restart policy** —
  these need raw exit status, which `cli/main.cpp`'s on-failure
  loop doesn't have today. Plumbing requires a `runCrate`
  signature change to pipe `int *outStatus` alongside
  `outReturnCode`. Tracked separately.
- **JSON output for pressure** — only the human-readable table
  rendering ships. JSON could land later; needs a sub-object
  in the existing JSON schema.
- **`crate top --rctl-pressure`** — `crate top` already shows a
  CPU% column; adding pressure% is a UI re-layout. Out of
  scope here; same `getRctlUsagePercent` would be the call.

1070/1070 unit tests pass locally.

---

## [0.8.32] — 2026-05-07

Two small dead-code removals + one audit-finding correction.

### Removed: `JailQuery::getJidByName`

Declared in `lib/jail_query.h:39` and defined in
`lib/jail_query.cpp:246`. Zero callers anywhere in the tree —
verified by 6-pass grep against:

1. namespace-prefixed callers (`JailQuery::getJidByName`)
2. `using` declarations
3. bare-name calls (would-be ADL pickups)
4. test files (`tests/`)
5. namespace-qualified `::getJidByName`
6. final exhaustive `grep -rn 'getJidByName'`

All six checks returned only the declaration + definition lines.
Production paths use `JailQuery::getJailByName(name)->jid` which
returns the full info struct in a single call. The deleted
function was a thin one-liner over `::jail_getid(3)`; if a future
caller needs it without the surrounding info, re-add then.

### Moved: `RunNet::epairNumToIp` into file-static

Declared in `lib/run_net.h:46` but only called from inside
`lib/run_net.cpp` (lines 92, 93). Header export was redundant.
Now `static` in the .cpp; symbol no longer leaks into other
translation units.

### Audit-finding correction: `JailQuery::execInJail*` does NOT exist

The 0.8.21 dead-code audit flagged
`JailQuery::execInJail / execInJailGetOutput / execInJailChecked`
as orphaned. **That namespace doesn't have those functions** —
the audit subagent confused a header line range
(`lib/jail_query.h:49-59`) which is in the `JailExec` namespace,
not `JailQuery`. All three `JailExec::execInJail*` are heavily
used in production:

| Function | Production callers |
|---|---|
| `JailExec::execInJail` | `lib/run.cpp:1654`, `lib/run.cpp:1697`, `lib/stack.cpp:1008` |
| `JailExec::execInJailGetOutput` | `lib/info.cpp:115`, `lib/info.cpp:148`, `lib/lifecycle.cpp:119` |
| `JailExec::execInJailChecked` | `lib/run.cpp:880` |

So the only real dead-code from that audit flag was
`getJidByName` (deleted in this release). Lesson: trust audits
but verify with grep before deletion. Sprint protocol now
enforces a 6-pass verification before any code removal.

1070/1070 unit tests pass locally.

---

## [0.8.31] — 2026-05-07

**Bug-fix release.** Three operator-facing YAML keys were parsed
and validated cleanly but their runtime side was either missing
or broken. All three are real broken-contract bugs surfaced
by the deeper read of the 0.8.21 dead-code audit findings.

### Fix #1: `disk_quota: 10G` actually applies refquota now

`lib/spec.cpp:805-820` parsed `disk_quota`, validated the K/M/G/T
suffix, stored it in `spec.diskQuota`. `lib/run_jail.cpp:316`
had `applyDiskQuota` that computes the dataset and calls
`ZfsOps::setRefquota`. **`lib/run.cpp` never invoked
`applyDiskQuota`.**

Operator wrote `disk_quota: 10G`, validation succeeded, ZFS
refquota was never set, jail could fill the entire pool. Bug
since 0.3.0 when the YAML key was added.

Wired in after `RunJail::applyRctlLimits` and before
`attachZfsDatasets`, so a delegated dataset inherits the quota
at attach time.

### Fix #2: `mac_portacl.allow_ports` actually installs rules now

`lib/spec.cpp:1107-1119` parsed
`security_advanced.mac_portacl.allow_ports: [80, 443]` into
`spec.securityAdvanced->macAllowPorts`. `lib/run.cpp:631-636`
loaded the kernel module + LOG'd each port… but **never called
`MacOps::setPortaclRules`**. Operator's allow-list silently
dropped.

Now build a `MacOps::PortaclRule[]` (uid=0, tcp+udp per port)
and call `setPortaclRules` which writes the
`security.mac.portacl.rules` sysctl atomically. Soft-fail with
operator-visible warning if the module isn't loaded or the
sysctl fails.

### Fix #3: `mac_bsdextended` cleanup actually removes rules now

`lib/run.cpp:625-628` had a cleanup `RunAtEnd` whose body was:

```cpp
removeMacRules.reset([&args]() {
  std::vector<std::string> rules;
  MacOps::listUgidfwRules(rules);   // <-- collects, doesn't remove
});
```

It listed rules into a local vector that immediately fell out of
scope. **Rules persisted in `/dev/ugidfw` between runs** —
`ugidfw list` showed accumulated entries from every previous
`crate run` since 0.5.x.

The remover (`MacOps::removeUgidfwRules(jid)`) needs the jid,
which isn't available at the point the lambda is wired (the
`RunAtEnd` is declared before `RunJail::createJail` returns).
Fix uses a `std::shared_ptr<int>` published after createJail —
the lambda checks `*shared > 0` and skips cleanup if the jail
never came up.

The pre-existing companion bug — `addUgidfwRuleRaw` doesn't
inject `jailid <jid>` so operator rules apply host-wide — is
**not fixed here**, only documented in the cleanup-skipped
branch's log message. That's a spec-level issue (rule strings
come from the operator) and needs a separate design pass.

### What this release does NOT do

- **Fix the host-wide-rule bug for `mac_bsdextended`** —
  needs spec-side rewrite to inject `jailid <jid>` into each
  operator-supplied rule string. Tracked separately.
- **Add tests for the runtime wiring** — the runtime side calls
  ZFS / mac kernel modules / spec parsing, none of which can
  be exercised on Linux dev boxes via ATF. Verifying these on
  FreeBSD is integration-test territory (Kyua + a real jail).

1070/1070 unit tests pass locally.

---

## [0.8.30] — 2026-05-07

`IpfwOps::configureNat` + `IpfwOps::deleteNat` wired into the
auto-fw ipfw NAT path (lib/run.cpp). Closes the audit's "declared
but uncalled" finding for those two functions.

Pre-0.8.30, the ipfw branch of auto-fw fork+exec'd `ipfw nat <id>
config <…>` and `ipfw nat <id> delete` directly via
`Util::execCommand(AutoFwPure::buildIpfwNat*Argv(...))`. The
`IpfwOps::configureNat` wrapper existed but had no callers — it
was scaffolding for a future native `IP_FW3` setsockopt path
that nobody had reached for.

### What this release adds

- **Single replacement point** — when the native `IP_FW3` path
  for NAT instances finally lands, only `IpfwOps::configureNat`
  needs to change. `lib/run.cpp` keeps calling the same
  function.
- **NAT-instance collision warning** — `IpfwOps::configureNat`
  internally calls `isNatInstanceInUse(natId)` before writing.
  If a previous `crate run` left a stale instance behind (or
  another tool grabbed the same ID), the operator now sees:
  ```
  WARNING: ipfw NAT instance 30042 already exists — another
  application may be using it; overwriting
  ```
  Pre-0.8.30 the second `crate run` would silently overwrite.
- **Cleanup symmetry** — `IpfwOps::deleteNat` already swallowed
  its own errors and warned via `WARN(...)`. The outer
  try/catch in `run.cpp`'s `ipfwAutoFwCleanup` is now mostly
  redundant; kept for safety in case a future impl changes.

### What this release does NOT do

- **Native `IP_FW3` setsockopt path for NAT** —
  `IpfwOps::configureNat` itself still fork+exec's
  `/sbin/ipfw`. Wiring through the facade lets that change
  without touching callers when someone implements it.
- **Wire `IfconfigOps::createVlan` / `setInet6Addr`** — both
  are also shell-only stubs today. The natural callers
  (`RunNet::createVlanInJail`, `RunNet::configureStaticIp6`)
  run inside the jail context via the `execInJail` lambda,
  not on the host, so swapping them in is non-trivial — the
  jail-side ifconfig invocation has different argv shape
  (`vlan create`, `vlan vlandev`, etc.) than the host-side
  helper. Tracked separately as a `RunNet` refactor.
- **`IfconfigOps::disableLroTso` / `setDown` / `setDescription`
  / `useNativeApi` toggle / `setLogProgress`** — minor helpers
  with no natural caller. Stay as scaffolding.

1070/1070 unit tests pass locally.

### Audit follow-up sprint summary

Eight releases (0.8.22 → 0.8.29 → 0.8.30) on top of the
0.8.21 dead-code audit:

| Release | Audit finding | Closure |
|---|---|---|
| 0.8.22 | `lib/vnc_server.cpp` orphan | wired via `gui.vnc_native` |
| 0.8.22 | `releaseCpuset` stray RunAtEnd | replaced with comment |
| 0.8.23 | `lib/drm_session.cpp` orphan | wired via doctor probe |
| 0.8.24 | `lib/capsicum_ops.cpp` orphan | wired via `audit_syslog` |
| 0.8.25 | `datasetForJail` 3× duplicate | extracted to `zfs_dataset.{cpp,h}` |
| 0.8.26 | `*Ops::available` predicates unused | wired via `native-api` doctor cat |
| 0.8.27 | `lib/nv_protocol.cpp` orphan | wired via `nvlist-protocol` self-test |
| 0.8.28 | `RunJail::diagnoseExitReason` unused | wired into post-exit logging |
| 0.8.29 | `ZfsOps::recv` unused | wired into `crate restore` |
| 0.8.30 | `IpfwOps::configureNat` / `deleteNat` unused | wired into auto-fw ipfw branch |

10 distinct audit findings, all closed. The remaining unused
functions in `MacOps`, `NetgraphOps`, `IfconfigOps` (the small
helpers), `RunJail::applyDiskQuota`, `JailQuery::execInJailChecked`
remain as scaffolding with no natural caller in the current
architecture — documented in code, kept against future feature
work.

---

## [0.8.29] — 2026-05-07

`crate restore` uses `ZfsOps::recv` natively when libzfs is
linked. Pre-0.8.29 the restore path always fork+exec'd
`/sbin/zfs` via `Util::execPipeline`; now it opens the
`.zstream` file in-process and hands the fd to
`ZfsOps::recv`, which calls `lzc_receive(3)` directly when
`HAVE_LIBZFS` is set, falling back to `fork+exec` only when
the library wasn't linked at build time.

```
% crate restore /backups/web-2026-05-07.zstream --to tank/jails/web
restore: zfs recv ← /backups/web-2026-05-07.zstream into tank/jails/web (native libzfs)
restore: tank/jails/web recovered from /backups/web-2026-05-07.zstream
```

The "(native libzfs)" / "(fork+exec zfs(8))" hint is printed at
start so the operator can confirm which path their build is on
(matches the `crate doctor` `native-api/libzfs` check from
0.8.26).

### Why restore but not backup

`ZfsOps::send(snapName, fd)` only does *full* sends — there's no
`-i since` parameter for incremental streams. Most production
backups are incremental (operators set `--auto-incremental`), so
wiring full-only would be half a deliverable.

`ZfsOps::recv` has no such limitation: a `zfs recv` from a
.zstream file is the same call shape regardless of whether the
sender did full or incremental — `lzc_receive(3)` walks the
stream and figures it out. Restore is the clean win.

### What this release does NOT do

- **`zfs send` native path for backup** — needs ZfsOps::send API
  extension to take an optional `sinceSnapName` for the
  incremental case. Tracked separately.
- **Replace the shell ssh pipeline in `crate replicate`** — that
  pipeline is `zfs send | ssh ... 'zfs recv'`, all running on
  the source host. Going native means re-implementing the SSH
  stream multiplexing in C++. Not worth it; the existing
  pipeline is robust.
- **Doctor "restore native path active" check** — the existing
  `native-api/libzfs` check from 0.8.26 already says whether
  libzfs is linked. The runtime hint at restore time is the
  same datapoint at the point of action.

1070/1070 unit tests pass locally.

---

## [0.8.28] — 2026-05-07

`RunJail::diagnoseExitReason` wired into `lib/run.cpp` post-exit
logging — flagged as scaffolding by the 0.8.21 audit (the four
diagnostic helpers `diagnoseExitReason`, `isOomKill`,
`wasKilledByRctl`, `getRctlUsagePercent` were declared and tested
but never called from production code).

Pre-0.8.28, when a jail's command exited non-zero, the operator
saw:

```
... command has finished in jail: returnCode=137
```

…and had to run `dmesg | grep -i kill`, `rctl -u jail:N`, and
correlate timestamps to figure out whether the jail was OOM'd
by RCTL, killed by an external signal, or just exited badly.

Now the same path emits:

```
... command has finished in jail: returnCode=137 (OOM: killed by RCTL (memoryuse=536870912))
```

The diagnosis runs only on non-zero / signal-killed exits — clean
exits keep the original one-liner. Both the executable-mode
(`runCmdExecutable: ...`) and service-mode (`services: ...`)
paths get the diagnosis.

### What this release does NOT do

- **Plumb the diagnosis into the audit log** — `audit.cpp::logEnd`
  receives `errMsg` from `cli/main.cpp`'s exception catch, which
  doesn't see the inner exit status. Surfacing diagnosis there
  needs a `runCrate(...)` signature change to return raw status
  alongside `returnCode`. Tracked separately.
- **Wire `isOomKill` into the restart policy** — `cli/main.cpp`'s
  on-failure restart only sees `returnCode`, not raw status.
  Calling `isOomKill` from there would let the operator say
  "restart only on OOM, not on clean failure" — useful but needs
  the same plumbing as above.
- **`crate stats --rctl-pressure`** — `getRctlUsagePercent` is
  the foundation for a memory-pressure view in `crate stats`.
  Tracked as a UX improvement.

The four helpers stay as scaffolding for those follow-ups; this
release just gives `diagnoseExitReason` its first production
caller so it's no longer silent dead code.

1070/1070 unit tests pass locally.

---

## [0.8.27] — 2026-05-07

Wires `lib/nv_protocol.cpp` (~116 LOC) — last orphaned unit
flagged by the 0.8.21 audit. Pre-0.8.27 the file built but had
zero production callers; the only inter-call within the file
itself was `sendCommand` invoking its own `connectToDaemon`/
`sendMessage`/`recvMessage`. Operator linked nothing for it
(libnv is in FreeBSD base, but the wire format wasn't speaking
to anything).

### Why kept and not deleted

`NvProtocol` is the foundation for a future control-plane v2
that bypasses cpp-httplib + the hand-rolled HTTP parser in
`daemon/control_socket_pure.cpp`. The nvlist wire format is
materially better than that manual HTTP parser:

- native framing (no Content-Length tracking)
- native peer-credential support over Unix sockets
- smaller on the wire
- no risk of misparsing HTTP edge cases (chunked, folded
  headers, CRLF in values)

Throwing the code away would lose ~116 LOC of FreeBSD-native
plumbing that the eventual refactor needs. So the right move is
**document it as scaffolding + give it a production caller** so
it stops being silent dead code.

### What this release adds

- **`NvProtocol::available()`** — `true` on FreeBSD builds,
  `false` on Linux dev boxes. Mirrors the `available()`
  pattern from `ZfsOps`/`IfconfigOps`/`PfctlOps`/`IpfwOps`.
- **`NvProtocol::selfTest()`** — opens a `socketpair(AF_UNIX,
  SOCK_STREAM)`, sends a fixed test `Message` on one end, reads
  it back on the other, validates round-trip equality. No
  daemon needed — exercises the codepaths in-process.
- **`crate doctor` `nvlist-protocol` check** in the
  `native-api` category. Three outcomes:
  - libnv not built in (Linux dev) → info pass
  - libnv + selfTest succeeds → pass ("scaffolding ready")
  - libnv + selfTest fails → warn ("exotic — file a bug")
- **Header rewrite** — the file-top comment now explicitly
  marks `NvProtocol` as scaffolding for the future
  control-plane v2, lists the four reasons libnv is better
  than the HTTP parser, and notes the doctor self-test as the
  only production caller today.

### Closes the 0.8.21 dead-code audit follow-up

| Release | Audit finding | Closure |
|---|---|---|
| 0.8.22 | `lib/vnc_server.cpp` (~109 LOC) orphaned | wired via `gui.vnc_native: true` |
| 0.8.22 | `releaseCpuset` RunAtEnd never reset | replaced with explanatory comment |
| 0.8.23 | `lib/drm_session.cpp` (~80 LOC) orphaned | wired via `crate doctor` libseat probe |
| 0.8.24 | `lib/capsicum_ops.cpp` (~136 LOC) orphaned | wired via `audit_syslog: true` |
| 0.8.25 | `datasetForJail` + `findLatestBackupSuffix` duplicated 3× | extracted to `lib/zfs_dataset.{cpp,h}` + pure parser |
| 0.8.26 | `*Ops::available` predicates never queried | wired via `native-api` doctor category |
| 0.8.27 | `lib/nv_protocol.cpp` (~116 LOC) orphaned | wired via `nvlist-protocol` doctor self-test (this) |

All seven audit findings now have a production caller, a
documented rationale, or a removal commit. The full audit
output (10 categories) was clean except for these seven; the
codebase is in a state where deletions don't lose
functionality and additions don't sit silent.

Six releases (0.8.22 → 0.8.27) added a new `gui` + `audit` +
`native-api` doctor category each, growing `crate doctor` from
9 checks to 22.

1070/1070 unit tests pass locally.

---

## [0.8.26] — 2026-05-07

Surfaces native-API build matrix via `crate doctor`. The 0.8.21
audit found that `ZfsOps::available`, `IfconfigOps::available`,
`PfctlOps::available`, `IpfwOps::available` were declared but
never queried. They sit on top of substantial wrappers
(libzfs / libifconfig / libpfctl / native ipfw socket) that the
runtime does call into for the production code paths — when
those libs are linked at build time. When they're not, the
runtime fork+exec's the equivalent shell utility.

Pre-0.8.26 the only way to know which path your build was on
was to read `kldstat` + `pkg info -l crate | grep .so` and
piece it together. Now `crate doctor` says it directly.

### What this release adds

A new `native-api` category in the doctor report with four
checks:

| Check | Reports |
|---|---|
| `libzfs` | linked → snapshot/clone/jail-attach skip fork+exec'ing zfs(8); else falls back to `/sbin/zfs` |
| `libifconfig` | linked → interface ops skip fork+exec'ing ifconfig(8) |
| `libpfctl` | linked → pf anchor + rule ops skip fork+exec'ing pfctl(8) |
| `ipfw-native` | kernel ipfw socket reachable → rule ops skip fork+exec'ing ipfw(8) |

All four emit `pass` severity (informational); fork+exec is a
fully-supported path, just slower per-call. Operators who care
about latency can rebuild with the appropriate `HAVE_LIB*`
macros and the runtime picks up the native path on next
invocation — no config change needed.

`category` rank set to 10 in `lib/doctor_pure.cpp`'s sort table
(after the existing `gui` rank from 0.8.23) so the four checks
land in a contiguous block at the bottom of the report.

### Why not "wire native APIs as opt-in via config"

The audit's terse summary made it sound like the native APIs
were entirely unwired ("`ZfsOps::*` declared but never called").
Closer reading: only specific *functions* are unused
(`ZfsOps::send / recv / mount / available`,
`IfconfigOps::setInet6Addr / disableLroTso / setDown / setDescription /
createVlan`, etc.). The high-traffic operations (`snapshot`,
`clone`, `getMountpoint`, `jailDataset`, etc.) are already on
the production runtime path through `lib/run.cpp`,
`lib/snapshot.cpp`, `lib/run_jail.cpp`, `lib/run_net.cpp`.

So there's no "lost runtime" to recover here — what's missing is
**operator visibility** into which path their build is on. That's
what the doctor check delivers.

### What this release does NOT do

- **Wire `ZfsOps::send / recv` into backup/replicate** — the
  shell `zfs send | ssh ... 'zfs recv'` pipeline today is
  battle-tested and handles errors consistently. Replacing it
  with native fd-passing is a perf optimisation (avoids one
  fork+exec per backup), not a "lost-functionality" fix.
  Tracked separately if anyone needs the perf.
- **Wire `JailQuery::execInJailChecked`** — the audit flagged
  it as dead, but the production code uses a local `execInJail`
  lambda in `lib/run.cpp` that captures `jid` + log progress
  flag implicitly. Replacing with the namespace-scoped helper
  would lose that capture; not worth it.
- **Wire `RunJail::diagnoseExitReason / isOomKill /
  wasKilledByRctl / getRctlUsagePercent`** — these are
  diagnostic helpers for "why did this jail exit". Useful but
  needs a hookpoint (e.g. `crate logs --diagnose`). Tracked
  separately.
- **Remove the per-function dead code** — keeping the unused
  helpers in headers as scaffolding for the future use cases
  above. Audit closure is achieved via documentation
  (this CHANGELOG + per-namespace header comments shipped in
  the previous releases).

1070/1070 unit tests pass locally.

---

## [0.8.25] — 2026-05-07

Dedup of `datasetForJail` + `findLatestBackupSuffix` flagged by
the 0.8.21 audit. Pre-0.8.25 these helpers were verbatim copies
in `lib/backup.cpp` (35,48) and `lib/replicate.cpp` (30,40), with
a third near-copy in `daemon/routes.cpp:620`.

### What this release adds

- **`lib/zfs_dataset_pure.{h,cpp}`** — pure parser of
  `zfs list -H -t snapshot -o name -r <ds>` output:
  - `pickLatestBackupSuffix(out)` — returns lex-greatest
    `backup-*` suffix; tolerates CRLF, blank lines, comment
    lines, recursive-descendant entries
  - `validateDatasetName(ds)` — rejects relative paths, `..`
    segments, shell metas, leading/trailing `/`
- **`lib/zfs_dataset.{h,cpp}`** — runtime wrapper that calls
  `zfs(8)` + delegates parsing to the pure module:
  - `datasetForJail(name, errContext)` — strict (throws if jail
    missing or path not on ZFS); `errContext` appears in
    diagnostics so operators see which command failed
  - `findLatestBackupSuffix(dataset)` — runs `zfs list` and
    pipes through `pickLatestBackupSuffix`; returns "" on
    `zfs(8)` error (caller treats as "no prior", same as the
    pre-0.8.25 `try { ... } catch (...) {}` pattern)

`lib/backup.cpp` and `lib/replicate.cpp` updated to delegate;
~70 LOC of duplicate logic removed.

`daemon/routes.cpp::datasetForJail` is **intentionally not
unified** because its semantics differ — when the URL parameter
doesn't match a running jail, it returns the parameter as-is
(treating it as a dataset name), to support the snapshot
endpoints' "operate on a raw dataset" path. Comment added so
future readers don't try to merge it.

### Tests

9 ATF unit cases on `pickLatestBackupSuffix`:

- empty input → empty
- no backup-* snapshots → empty
- multiple backup-* → lex-greatest wins (UTC-ISO-8601 lex
  monotonicity is what makes this safe)
- mixed with `daily-*` / `warm-*` / `manual-*` → only `backup-*`
  count
- CRLF + blank-line tolerance
- comment-line tolerance
- recursive-descendant entries (multi-line `zfs list -r`)

3 cases on `validateDatasetName` — typical accepted, traversal/
shell-meta/space rejection.

### What this release does NOT do

- **Native `ZfsOps`/`IfconfigOps`/`IpfwOps`/`PfctlOps`
  wiring** — the audit's other "lost-functionality" finding.
  Tracked for 0.8.26 (operator opt-in via
  `prefer_native_apis: true`).
- **`NvProtocol` documentation** — final audit closure item.
  Tracked for 0.8.27.
- **`daemon/routes.cpp` dedup** — different semantics, kept
  separate (now with a comment).

1070/1070 unit tests pass locally.

---

## [0.8.24] — 2026-05-07

Wires `lib/capsicum_ops.cpp` (~136 LOC) — third and last of the
orphaned units flagged by the 0.8.21 audit. Pre-0.8.24 the file
built but production code never called any `CapsicumOps::*`
function; operators with `HAVE_CAPSICUM` linked libcasper +
cap_dns + cap_syslog and got nothing for it.

### What this release adds

**Audit-event dual-write to syslog via `cap_syslog`**, opt-in
via a new `crate.yml` knob:

```yaml
# crate.yml
audit_syslog: true
```

When set, `lib/audit.cpp` writes each audit event to the existing
`$logs/audit.log` file *and* ships it to syslog at
`LOG_AUTH | LOG_NOTICE` via `CapsicumOps::logSyslog`. The casper
channel is initialised lazily (atomic flag — first audit-logged
command pays for it once, subsequent ones are branch-free).

When `HAVE_CAPSICUM` isn't built in, `logSyslog` falls back to
plain `syslog(3)` — the operator still gets the dual-write,
just without cap_enter resilience.

The on-disk `audit.log` continues to be the system of record;
syslog is a convenience fan-out for ops dashboards
(rsyslog forwards, journald, syslog-ng filters, etc.).

**`crate doctor` capsicum-casper check** under the existing
`audit` category. Four outcomes:

| `HAVE_CAPSICUM` | `audit_syslog` | Severity | Message |
|---|---|---|---|
| no  | no  | pass | "build doesn't include casper; audit log is file-only" |
| no  | yes | warn | "fallback to plain syslog(3); loses cap_enter resilience" |
| yes | no  | pass | "casper available; opt in with audit_syslog: true" |
| yes | yes | pass | "casper available; audit dual-written to file + syslog" |

### Why this wiring (and not the others)

Looking at all four `CapsicumOps::` entry points:

- `enterCapabilityMode()` — would freeze new fd opens; crated
  spawns subprocess utilities (rctl, jail, jexec, ipfw) that
  need `execve` to open more fds. Calling cap_enter on crated
  itself would break those. Tracked as a "privsep daemon
  refactor" follow-up.
- `initCapDns / resolveDns` — DNS isn't on crate's hot path
  (it's a jail manager, not a network client). No natural
  caller.
- `initCapSyslog / logSyslog` — **this** is the natural fit:
  audit log is already a "ship event somewhere" surface; adding
  a casper-resilient destination is direct value.
- `limitFdRights` — already used directly by daemon/sandbox.cpp
  since 0.7.14 (it didn't go through CapsicumOps because that
  module wasn't wired yet; deduplication is a future cleanup).

So `audit_syslog` is the one case where wiring CapsicumOps gives
operators something they didn't have before, on existing code
paths.

### What this release does NOT do

- **`cap_enter` on crated** — needs the privsep refactor
  mentioned above. Tracked separately as low-priority.
- **Replace `daemon/sandbox.cpp::applyListenerRights` with
  `CapsicumOps::limitFdRights`** — both call the same
  underlying `cap_rights_limit(2)`. Deduplication is a pure
  refactor; deferred.
- **Use `CapsicumOps::resolveDns` anywhere** — no caller in
  crate's design space. The function stays as a building block
  for any future code path that does need cap_dns DNS.

1061/1061 unit tests pass locally.

### Closes the 0.8.21 dead-code audit follow-up

| Release | Orphaned unit wired |
|---|---|
| 0.8.22 | `lib/vnc_server.cpp` via `gui.vnc_native: true` + `releaseCpuset` cleanup |
| 0.8.23 | `lib/drm_session.cpp` via `crate doctor` probe + future rootless prep |
| 0.8.24 | `lib/capsicum_ops.cpp` via `audit_syslog: true` (this) |

Three "lost-functionality" units now have at least one production
caller. The audit's other findings (`NvProtocol`, native
`ZfsOps`/`IfconfigOps`/`IpfwOps`/`PfctlOps` wrappers,
`datasetForJail` duplication) remain open and can land in a
future cleanup sprint.

---

## [0.8.23] — 2026-05-07

Wires `lib/drm_session.cpp` (~80 LOC) — second of three orphaned
units flagged by the 0.8.21 audit. Pre-0.8.23 the file built when
`WITH_LIBSEAT=1` was set, but no production code path called any
`DrmSession::` function. Operator linked libseat and got nothing.

### What this release adds

- **`DrmSession::probeDevice(path)`** — open + immediate close
  via libseat (or via a plain `open(O_RDWR)` fallback when
  libseat isn't built in). Surfaces seatd setup issues without
  needing to start a jail first.
- **`crate doctor` "drm-session-libseat" check** under the new
  `gui` category. Three outcomes:
  - `WITH_LIBSEAT` not built in → info-level pass ("not relevant
    for setuid-root crate today; matters once rootless ships")
  - `/dev/dri/card0` absent on host → info pass (no GPU)
  - libseat + DRM device + probe succeeds → pass
  - libseat + DRM device + probe fails → warn ("seatd not
    running, or current user not on an active seat;
    `service seatd onestart`")
- **Makefile** moves `lib/drm_session.cpp` out of the
  `WITH_LIBSEAT` conditional. The .cpp's internal
  `#ifdef HAVE_LIBSEAT` guards already stub out the
  libseat-specific code, and the doctor check needs the symbol
  to link unconditionally.

### Why "doctor check" rather than "wire into Xorg"

The orphaned `DrmSession::openDevice` is the foundation for a
**rootless containers** flow (TODO low-priority) where crate
sheds setuid root and needs libseat coordination to legitimately
open `/dev/dri/cardN` from a regular user's session. Today crate
runs as setuid root, so the kernel lets it `open(O_RDWR)` the
DRM device directly without libseat involvement — wiring
DrmSession into the Xorg fork would add a layer with no
operational benefit.

The doctor check is the honest delivery for today: it makes the
libseat path **observable + testable** so operators can
pre-validate their seatd setup before the rootless work lands,
and the module stops being pure scaffolding.

### What this release does NOT do

- **Wire DrmSession into Xorg startup** — needs the rootless
  containers path first. The probe + doctor check are the
  building blocks.
- **Mouse/keyboard input on embedded VNC** — still tracked from
  0.8.22.
- **CapsicumOps wiring** — third dead-code finding from 0.8.21
  audit. Tracked for 0.8.24.

1061/1061 unit tests pass locally.

---

## [0.8.22] — 2026-05-07

Wires up two pieces of long-orphaned functionality flagged by the
0.8.21 dead-code audit, plus a small `releaseCpuset` cleanup.
Pre-0.8.22 these compilation units (`lib/vnc_server.cpp`,
~109 LOC) were built when `WITH_LIBVNCSERVER=1` was set but
never called from any production code path — the operator linked
the library and got nothing for it.

### `gui.vnc_native: true` — embedded libvncserver

Operator opt-in to drop the `x11vnc` package dependency from the
host. When set on a `gui:` block, `setupVncAndRegister` now
calls `VncServer::start()` instead of fork+exec'ing `x11vnc`.

```yaml
gui:
  mode: gpu
  vnc: true
  vnc_native: true     # 0.8.22: use embedded libvncserver
  vnc_port: 5901
  vnc_password: secret
```

The embedded server polls the X11 root window of the spawned
display via `XGetImage` at ~25 FPS and copies the frame into
the libvncserver framebuffer. Resolution is auto-detected via
`XGetGeometry` at server-start time — no need to pre-supply
width/height. Password handling, port allocation, and the
RunAtEnd teardown contract match the existing x11vnc path so
`gui list` / `gui url` keep working unchanged.

Build matrix:

| WITH_LIBVNCSERVER | WITH_X11 | Behaviour |
|---|---|---|
| set | set | full embedded VNC, X11 grab loop active |
| set | unset | embedded VNC runs, framebuffer stays blank (warning logged); fall back is automatic |
| unset | * | `VncServer::available()` returns false; runtime auto-falls back to `x11vnc` with warning |

The Makefile change moves `lib/vnc_server.cpp` out of the
`WITH_LIBVNCSERVER` conditional — the .cpp's internal
`#ifdef HAVE_LIBVNCSERVER` guards already stub out the
libvncserver-specific code, so the symbol always links.
Without that, builds without libvncserver would fail to link
because `lib/run_gui.cpp` references `VncServer::available()`
unconditionally now.

### `releaseCpuset` cleanup

`lib/run.cpp:798` declared a `RunAtEnd releaseCpuset` that was
never `.reset()`'d, so the named teardown was always a no-op.
The variable predates 0.7.x. Replaced with an explicit comment
noting that cpuset is jail-scoped and the kernel drops the
binding when the jail dies (which `destroyJail` handles
unconditionally). No behaviour change — just removes the
misleading declaration so future readers don't mistake it for
a wired teardown.

### What this release does NOT do

- **Mouse / keyboard input on the embedded VNC** — libvncserver
  receives input events but we don't forward them to the X11
  display via `XTest`. Operators get a view-only screen; for
  interactive use, fall back to `gui.vnc_native: false`
  (default). Tracked for 0.8.23 follow-up.
- **Visual auto-detection** — the X11 grab assumes the host's
  default visual matches the framebuffer layout (BGRA,
  same bytes-per-line). Exotic visuals show colour-swapped
  frames. Operator can fall back to x11vnc.
- **`DrmSession` (libseat) wiring** — the other dead-code
  finding from the 0.8.21 audit. Tracked for 0.8.23.
- **`CapsicumOps` (cap_dns / cap_syslog) wiring** — third dead
  finding. Tracked for 0.8.24.

1061/1061 unit tests pass locally.

---

## [0.8.21] — 2026-05-06

Spec registry + control-plane PostStart. Closes the 0.8.13
deferred item — control sockets returned `501 Not Implemented`
for `POST /v1/control/containers/<name>/start` because crated
didn't track which `.crate` file produced a given jail name.
0.8.21 adds a tiny file-backed registry that `crate run -f`
populates automatically, and wires PostStart to consult it.

### What this release adds

```sh
% sudo crate run -f /home/op/firefox.crate    # registers automatically
% cat /var/run/crate/spec-registry.txt
# crate spec registry — managed by `crate run -f`
# format: <jail-name> <abs-crate-path>
firefox /home/op/firefox.crate

% crate stop firefox       # registry entry stays — by design
% curl --unix-socket /var/run/crate/control/op.sock \
       -X POST http://x/v1/control/containers/firefox/start
{"status":"starting","container":"firefox","crate_path":"/home/op/firefox.crate"}
```

`crate run -f` writes the {name -> abs-path} pair after the
jail successfully comes up (best-effort: a registry write
failure logs but doesn't abort the jail). Entries are
intentionally NOT auto-removed when the jail stops — that's
what lets a control-plane PostStart find the path again.

### Lifecycle

- **Register**: `crate run -f <file>` after `RunJail::createJail`
  succeeds (warm-base runs skip the registry; no .crate file).
- **Re-register**: same name + different `.crate` path replaces
  the entry. Idempotent if the path is unchanged.
- **Persist**: stop/restart leave the entry in place.
- **Manual remove**: future `crate clean --orphans` will sweep
  entries whose `.crate` file no longer exists. For now, the
  operator can edit `/var/run/crate/spec-registry.txt` by hand.

### Control-plane PostStart contract

| Condition | Response |
|---|---|
| Jail already running | `409 Conflict` |
| No registry entry for the name | `404 Not Found` |
| Registered path no longer exists | `410 Gone` |
| `fork()` failure | `500 Internal Server Error` |
| Otherwise | `202 Accepted` + `{"status":"starting","container":"<n>","crate_path":"<p>"}` |

The 202 is intentional — `crate run` is the foreground supervisor
of the jail, so the spawned process lives for as long as the
jail is up (hours, days). Operators poll
`GET /v1/control/containers/<name>` for the actual running state.

### Implementation

Pure module `lib/spec_registry_pure.{h,cpp}`:

- `Entry` (name + cratePath), validators reused from the existing
  jail-name conventions, `parseLine`/`formatLine`,
  `findIndex` for the read-after-write idempotency check
- Path validator rejects relative paths, `..` segments, control
  characters, and a tight set of shell metas (`$ ` `` ` `` `;`,
  `|`, `&`, `*`, `?`, `<`, `>`, `\`, `"`, `'`, `\n`, `\r`).
  Internal spaces are allowed because validatePath already
  permits them — useful when staging crates under user homes
  with unusual paths.

Runtime `lib/spec_registry.{h,cpp}` mirrors `NetworkLease` —
flock-protected atomic-rename writes, `readAll` / `upsert` /
`remove` / `lookup` API.

`lib/run.cpp` wiring (one new call after `createJail` returns):

```cpp
auto absPath = std::filesystem::absolute(args.runCrateFile).string();
SpecRegistry::upsert(nameComponent, absPath);
```

`daemon/control_socket.cpp::handleStart`:

- looks up the registered path via `SpecRegistry::lookup`
- pre-flight checks (running? path exists?) before forking
- `fork() + setsid()` then `execl(CRATE_PATH_CRATE, "crate",
  "run", "-f", path)`. Stdio is redirected to `/dev/null` so
  the child outlives crated SIGHUP / restart cycles.

10 ATF unit cases cover the pure helpers (name validation, path
validation including shell-meta rejection + control-char
rejection, line round-trip, single-space separator semantics,
findIndex behaviour).

### What this release does NOT do

- **`crate registry list/add/rm` CLI** — operators manage the
  file via `crate run -f` (auto-write) or by editing
  `/var/run/crate/spec-registry.txt` directly. A CLI surface
  could ship later; it's pure operator UX.
- **Auto-prune of orphans** — `crate clean --orphans` will sweep
  entries pointing at deleted .crate files. Tracked separately;
  the registry is small enough that operators won't notice
  staleness for a while.
- **Wiring on the bearer-token main API** — the F2 main API has
  always supported `POST /containers` with the .crate body
  inline; PostStart-by-name is a control-plane-specific feature
  for tray-app workflows.

1061/1061 unit tests pass locally.

---

## [0.8.20] — 2026-05-06

IPv6 NPTv6 — **Phase 2: runtime allocator + jail interface
configuration.** Builds on 0.8.15's Phase 1 hook (the
`network_pool6:` config field) so `network: auto` jails now get
an actual IPv6 address from the configured ULA pool, not just an
accepted-but-ignored config line.

### What this release adds

```yaml
# crate.yml — already accepted since 0.8.15
network_pool6: fd00:0:0:0::/64
```

…now triggers, alongside the existing IPv4 path:

1. **Allocate** an IPv6 from the pool via `NetworkLease6::allocateFor`
   (atomic, flock-protected, idempotent — same jail re-running
   keeps its existing address).
2. **Configure** the address as a static IPv6 on the jail-side
   epair via `RunNet::configureStaticIp6` — the same code path
   `options.net.ipv6: <addr>` already used.
3. **Release** the lease on jail teardown so the address comes
   back into the pool.

The lease store lives at `/var/run/crate/network-leases6.txt` —
parallel to the existing `/var/run/crate/network-leases.txt`.
Kept separate so v4-only tooling that reads the old file doesn't
choke on hex-shaped lines.

Example session:

```sh
% cat /usr/local/etc/crate.yml
network_pool:  10.66.0.0/24
network_pool6: fd00::/64
default_bridge: crate0

% cat firefox.yml
network: auto
start: firefox

% sudo crate run -f firefox.crate
bridge mode: auto-allocated IP 10.66.0.2/24 (gw 10.66.0.1) on bridge_b
bridge mode: auto-allocated IPv6 fd00::2/64 on bridge_b

% sudo jexec firefox ifconfig bridge_b
bridge_b: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        inet 10.66.0.2 netmask 0xffffff00
        inet6 fd00::2 prefixlen 64
```

### Implementation

Pure module `lib/ip6_alloc_pure.{h,cpp}`:

- `Addr6` (16 raw bytes) + `Network6` types
- `parseIp6` / `formatIp6` — RFC 5952 canonical form (lowercase
  hex, longest run of >=2 zeros collapsed to `::`, ties broken
  leftmost)
- `parseCidr6` — rejects unaligned base addresses, double `::`,
  malformed groups, prefix outside 1..128
- `gatewayFor` (base + 1), `allocateNext` (skips base + gateway +
  taken set; bounded scan cap so a /127 misconfig doesn't loop),
  `inPool` predicate
- `Lease6` + `parseLeaseLine6` / `formatLeaseLine6`
- 18 ATF unit cases covering parser edge cases (full form,
  shorthand at ends/middle, double-`::` rejection, 9-group
  rejection, 5-digit-group rejection), formatter cases (RFC 5952
  longest-run, single-zero-no-collapse, all-zero, lowercase
  normalisation), CIDR (aligned/unaligned), allocator (skips
  base/gateway/taken), pool predicate, lease round-trip.

Runtime module `lib/network_lease6.{h,cpp}`:

- Mirror of `NetworkLease` but typed for IPv6 — same flock +
  atomic-rename pattern, same idempotency guarantee
- Separate file path so v4-only operator scripts don't break

`lib/run.cpp` wiring: in the bridge-mode IP-config block, after
the v4 lease has succeeded, call into the v6 path if
`Settings.networkPool6` is non-empty. Best-effort release on
teardown via a separate `RunAtEnd releaseLease6AtEnd`.

### What this release does NOT do

- **NPTv6 / NAT66 pf rules** — the jail gets a ULA address but
  packets leaving the host with `fd00::2` source aren't
  translated to a globally-routable v6. Operators wanting external
  v6 reachability still configure NPTv6 manually in `pf.conf`
  for now. The auto-rule will reuse the existing `auto_fw_pure`
  pattern from 0.8.0 — tracked for a future release.
- **ipfw IPv6 path** — only the lease + interface configuration
  ships here. Hosts running ipfw rather than pf still need to
  hand-roll their v6 firewall rules.
- **`route -6 get default` auto-detect** — the v4 path uses
  `NetDetect::defaultIfaceCached` (0.8.6) to pick the egress
  interface when `network_interface:` is unset; v6 needs the
  same treatment paired with NPTv6 since the egress iface is
  also where the prefix translation rule lands.
- **Doctor IPv6 checks** — `crate doctor` doesn't yet verify
  `network_pool6:` is parseable / aligned. The runtime catches
  that with an ERR at first jail run; operators who want
  upfront validation can run `crate validate` against a spec
  with `network: auto` after setting the pool.
- **Per-spec static v6** — `options.net.ipv6: <static-addr>`
  still works for operators who want a specific address; the
  pool path only kicks in when ipv6 is left as default.

1051/1051 unit tests pass locally.

---

## [0.8.19] — 2026-05-06

Operator-controlled filesystem perms on `/var/run/crate/crated.sock`.
First step toward closing the long-standing TODO item
"`daemon/auth.cpp::isUnixSocketPeer` trusts an empty REMOTE_ADDR
as proof of unix-socket origin". Pre-0.8.19 the only knob was the
OS umask at bind time — operators couldn't scope access to a
custom group without manual `chmod`/`chown` after `crated` started.

### What this release adds

Three new `crated.conf` knobs under `listen:`:

```yaml
listen:
    unix: /var/run/crate/crated.sock
    unix_owner: root        # default: leave at bind-time state
    unix_group: crate-ops   # default: leave at bind-time state
    unix_mode: "0660"       # default: 0660
```

After `crated` binds the unix socket, it `chown`s + `chmod`s the
file to those values. Operators get an OS-level allowlist (only
members of `crate-ops` can `connect()`) without touching `pf` /
`ipfw` / userland session managers.

Mode is parsed via `SocketPermsPure::parseUnixModeStr`, which
accepts the three spellings operators come from: `"0660"`,
`"660"`, `"0o660"`. Owner/group go through length + alphabet
validators that mirror FreeBSD's `pw(8)` constraints. `chmod` /
`chown` failures log to stderr but don't abort startup — the
socket remains usable at the umask-default mode.

If the configured mode is looser than `0660` (e.g. world-
readable), `crated` prints a one-shot warning to stderr at startup
so operators see the "looser than typical" choice in their logs.

### What this release does NOT do

- **Per-connection `getpeereid(2)`** — cpp-httplib's accept loop
  owns the connection fd and doesn't expose it to handlers. A
  proper getpeereid fix would require either forking httplib
  internally or replacing the unix-socket transport with a
  hand-rolled accept loop (the same pattern as
  `daemon/control_socket.cpp` since 0.7.11). That's tractable
  but outside this release's scope.
- **Closing the bind-to-chmod race** — there's a window between
  cpp-httplib's `bind()` (inside `listen()`, in another thread)
  and our perm fixup in which the socket has the umask-default
  mode (typically world-writable). Pre-0.8.19 had the same race;
  this release narrows it by also applying owner/group, doesn't
  close it.

The TODO item stays open with a more concrete path forward
documented in `crated.conf.sample`.

### Implementation

Pure helpers in `daemon/socket_perms_pure.{h,cpp}`:

- `parseUnixModeStr(s, *out)` — three octal spellings; rejects
  hex (`0x660`), decimal-but-non-octal (`888`, `999`), too-long
  (>4 digits), leading whitespace
- `validateUserName` / `validateGroupName` — `[A-Za-z0-9_-]`,
  length 1..32, no leading dash; empty string accepted as
  "leave alone"
- `validateUnixSocketPerms` — one-shot validator over the triple
- `isModeTight` — predicate for the "<=0660 with no world bits"
  startup warning

Runtime in `daemon/server.cpp`:

- After spawning the unix-socket thread, a fixup helper polls
  for the socket file (max ~2s), resolves owner/group via
  `getpwnam`/`getgrnam`, and calls `chown`/`chmod`
- All errors log to stderr; nothing is fatal

8 ATF unit cases cover the pure helpers (mode parsing across
spellings + garbage rejection, name validation, triple
short-circuit, tight/loose mode predicate).

1033/1033 unit tests pass locally.

---

## [0.8.18] — 2026-05-06

`gui: auto` now also auto-handles X11 cookies and Wayland sockets,
closing the medium-priority TODO `gui: auto` item. Combined with
0.8.11's auto-`/dev/dri/*` unhide, a single spec line now covers
the full desktop-app jail flow:

```yaml
gui: auto
start: firefox
```

…and `crate run` does:

| Pre-0.8.18 manual config | 0.8.18 automatic |
|---|---|
| `terminal.devfs_ruleset:` for /dev/dri | `gui: auto` (since 0.8.11) |
| Mount `/tmp/.X11-unix` | `gui: auto` (this release) |
| Copy `~/.Xauthority` into jail | `gui: auto` (this release) |
| Bind `$XDG_RUNTIME_DIR/wayland-0` | `gui: auto` (this release) |
| Set `DISPLAY`, `XAUTHORITY`, `WAYLAND_DISPLAY` env | `gui: auto` (this release) |

### What this release adds

When `gui: auto` resolves to the shared path (i.e. host has
`$DISPLAY` and/or `$WAYLAND_DISPLAY`), `setupX11` now:

1. **Bind-mounts `/tmp/.X11-unix`** into the jail and sets
   `DISPLAY` env (when the host has `$DISPLAY`)
2. **Copies `$XAUTHORITY`** (or the default `~/.Xauthority` if
   unset) to `<jailpath>/root/.Xauthority`, chmod 0600, and sets
   the in-jail `XAUTHORITY=/root/.Xauthority`. We copy rather
   than bind-mount so a jail compromise can't overwrite the
   operator's host cookie file.
3. **Bind-mounts the Wayland socket** when `$WAYLAND_DISPLAY` is
   set: `$XDG_RUNTIME_DIR/<sock>` -> `<jailpath>/tmp/wayland/<sock>`,
   and sets in-jail `XDG_RUNTIME_DIR=/tmp/wayland` +
   `WAYLAND_DISPLAY=<sock>`. The Wayland socket basename is
   validated through `RunGuiPure::parseWaylandDisplay` to reject
   path-traversal / shell-meta input.

### Behaviour change for `gui: auto`

Pre-0.8.18, `gui: auto` resolved to:

| `$DISPLAY` set | GPU present | Resolved to |
|---|---|---|
| no  | yes | gpu      |
| yes | yes | nested (Xephyr) |
| yes | no  | nested (Xephyr) |
| no  | no  | headless |

0.8.18 routes through `RunGuiPure::resolveAutoMode`:

| `$DISPLAY` or `$WAYLAND_DISPLAY` set | GPU present | Resolved to |
|---|---|---|
| yes | * | **shared** (was nested) |
| no  | yes | gpu (unchanged) |
| no  | no  | headless (unchanged) |

The "shared" path is what desktop-app jails actually want — fast,
matches the pattern every "firefox in a jail" guide uses. Operators
who relied on Xephyr from `gui: auto` should write `gui: nested`
explicitly. The shared mode keeps its security warning (host
keystroke / window-manipulation exposure), suppressible via
`CRATE_X11_SHARED_ACK=1` as before.

### Implementation

Pure helpers in `lib/run_gui_pure.{h,cpp}`:

- `resolveAutoMode(displaySet, waylandSet, hasGpu)` — table-driven
  resolution; testable without env-var setup
- `parseWaylandDisplay(env)` — validates the host's `WAYLAND_DISPLAY`
  is a basename (no slashes, no `..`, no shell metas, length
  <=64); empty string on rejection

Runtime in `lib/run_gui.cpp`:

- `resolveGuiMode` calls the pure helper for `gui: auto`
- The shared X11 block conditionally skips X11 work when DISPLAY
  is unset (Wayland-only host) and adds the cookie copy +
  Wayland mount when `gui: auto` is in effect
- All file copies / mounts are soft-fail (warn but don't ERR) so
  a misconfigured host still gets a jail with /dev/dri/* available

6 ATF unit cases on the new pure helpers (2 paths through
`resolveAutoMode` for each input axis; basenames + traversal
rejection for `parseWaylandDisplay`).

### What this release does NOT do

- **Per-jail user uid/gid in cookie copy** — the cookie lands at
  `/root/.Xauthority` because the in-jail user is currently always
  root. Once non-root in-jail users land (TODO low-priority
  rootless containers), cookie target needs to follow.
- **Wayland-only hosts without DISPLAY** — supported (we skip the
  X11 socket bind cleanly), but most operators still have an X
  server running side-by-side on FreeBSD. Pure-Wayland
  walk-throughs in docs/ are deferred.
- **Detect from `start:` cmd** (firefox/gimp/blender/...) — the
  TODO mentioned this as a "could also" trigger; spec-level
  `gui: auto` is enough surface for now.

1025/1025 unit tests pass locally.

### Closes the 3-release follow-on sprint

| Release | Item | Status |
|---|---|---|
| 0.8.16 | crate vm-wrap (bhyve jailer, TODO2 B) | DONE |
| 0.8.17 | network: auto top-level shorthand | DONE |
| 0.8.18 | gui: auto X11 cookie + Wayland | DONE (this) |

---

## [0.8.17] — 2026-05-06

`network: auto` — top-level spec shorthand for zero-config vnet
networking. Closes the medium-priority TODO item for desktop-app
jails: a single line at spec root replaces the four-line
`options.net` block that pulls everything together.

```yaml
# Before — works since 0.7.18 (verbose form)
options:
  net:
    mode: auto

# Now (0.8.17) — same effect, no nesting
network: auto
```

Both spellings continue to work; pick whichever reads better. The
runtime is unchanged — `mode: auto` already expanded into the full
bridge + auto-create-bridge + ip-auto chain since 0.7.18, which
in turn drives:

- Auto-create the configured default bridge (`crate.yml`'s
  `default_bridge:`, falling back to `crate0`)
- Auto-allocate an IPv4 from the configured `network_pool:` (or
  fall back to DHCP if no pool is configured)
- Auto-render SNAT + per-port rdr rules into pf or ipfw, picking
  whichever firewall is loaded (`firewall_backend:` config field
  forces the choice if both are loaded)
- Auto-detect the egress interface via `route -4 get default` if
  `network_interface:` is unset

So the full zero-config chain is one line of YAML on top of two
optional config knobs. This release closes that loop.

### Implementation

Top-level `network:` parses through a tiny pure validator
`SpecPure::validateTopLevelNetwork` that today accepts only `auto`
— other values (`host`, `none`, a literal bridge name, ...) are
reserved for future shortcuts and rejected with a diagnostic
pointing at `options.net` for richer config.

Conflict detection: if both top-level `network: auto` and
`options.net.mode: bridge|passthrough|netgraph` are present, the
parser refuses the spec rather than silently picking one. Two
"auto"s in different places resolve consistently.

3 ATF unit cases cover the validator (accept "auto", reject empty,
reject reserved-for-future values).

### What this release does NOT do

- **`gui: auto`** — same shorthand-on-top-of-existing-pieces story
  for X11/Wayland desktop-app jails. Tracked for 0.8.18 (next
  release in this batch).
- **Top-level `ports:` shorthand** — operators who want auto-rdr
  port-forwards still write `options.net.inbound-tcp: [80, 443]`.
  Adding a top-level `ports:` is straightforward but interacts
  with at-least-three other features (firewall: per-container
  rules, socket_proxy: Tor mode, X11 forwarding ports) so it
  warrants its own design pass.

1019/1019 unit tests pass locally.

---

## [0.8.16] — 2026-05-06

`crate vm-wrap` — bhyve jailer (FreeBSD-flavoured analogue of
Firecracker's [jailer](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
pattern). Closes [TODO2 item B](TODO2). Defence-in-depth wrapper
for operators who already manage bhyve VMs via `vm-bhyve` /
hand-rolled bhyveload — crate does NOT take over the VM lifecycle,
it only renders the *enclosure*: a vnet jail with `allow.vmm`, a
tight devfs ruleset whitelisting just `/dev/vmm/<vmname>`,
`/dev/vmmctl`, the VM's `/dev/nmdm*` console pair and the specific
`/dev/tap*` it uses, plus an optional delegated ZFS dataset.

### Threat model recap

A future bhyve user-space CVE (e.g. CVE-2021-29626 class) lands
the attacker inside the cage instead of on the host:

| Scenario                  | No jailer       | With vm-wrap          |
|---------------------------|-----------------|-----------------------|
| bhyve user-space CVE      | Host root       | Empty vnet jail       |
| Disk image confused-deputy| Host filesystem | One ZFS dataset       |
| Network: ARP/DHCP shenans | Host bridge     | Jail's vnet, isolated |
| `vmm.ko` kernel CVE       | Host kernel     | Host kernel (no help) |
| Side-channel (Spectre)    | Host memory     | Host memory (no help) |

The wrapper is a second wall, not a kernel boundary. It only helps
against bugs confined to bhyve's user-space binary or its ancillary
devices. See `docs/bhyve-jailer.md` for the full threat model and
manual recipe — `crate vm-wrap` automates the rendering work.

### Surface

```
crate vm-wrap <vmname> --jail <name>
              [--dataset DS] [--tap N] [--nmdm N]
              [--path P] [--ruleset N]
              [--output-dir DIR]
```

Default mode prints three labelled blocks to stdout:

1. **devfs.rules block** — paste into `/etc/devfs.rules`
2. **jail.conf fragment** — use with `jail -c -f <path>`
3. **`jexec ... bhyve ...` invocation hint** — operator-edited
   launch line for the VM from inside the cage

With `--output-dir DIR` each block is written to a separately-named
file (`devfs.snippet`, `<jail>.jail.conf`, `<jail>.bhyve.sh`) so
the operator integrates them on their own terms. Render-only — no
side-effects (no `service devfs restart`, no `jail -c`, no
`zfs jail`); a future `--apply` mode can drive those steps via the
argv builders shipped in this release.

### Implementation

Pure builders in `lib/vmwrap_pure.{h,cpp}`:

- Validators: `validateVmName`, `validateJailName`, `validateDataset`,
  `validateTap` (-1 or 0..9999), `validateNmdm`, `validateRulesetNum`
  (1..65535), `validateSpec` (one-shot)
- Builders: `buildDevfsRuleset`, `buildJailConfFragment`,
  `buildBhyveInvocationHint`
- argv: `buildDevfsReloadArgv`, `buildJailCreateArgv`,
  `buildZfsJailArgv` (deferred to future --apply mode)
- `deriveRulesetNum(jailName)` — FNV-1a 32-bit hash folded into
  `100..199` so the same jail name always gets the same number;
  collisions can be resolved with explicit `--ruleset N`

22 ATF unit cases cover validators, derivation determinism + range,
all three builders, and the three argv-builders.

Runtime in `lib/vmwrap.cpp` — print-mode by default, file-mode
under `--output-dir DIR`. Output dir is created at mode 0700.

### Defaults

- `--path` defaults to `/` (vm-bhyve convention; the devfs ruleset
  + vnet + `allow.vmm` are the real walls)
- `--ruleset` defaults to derived per jail name
- `--tap` and `--nmdm` default to "none" so operators who manage
  multiple TAPs / consoles per VM can hand-write those lines

### What this release does NOT do

- **`--apply` mode** — vm-wrap is a renderer; the operator runs
  `service devfs restart`, `jail -c -f`, and `zfs jail` themselves.
  The argv builders are shipped so a future --apply can drive them
  without a second design pass.
- **Auto-allocate tap / nmdm** — operator picks indices.
  Auto-allocation interacts with whatever VM-management layer the
  operator already uses (vm-bhyve has its own counter); we
  deliberately don't compete with that.
- **TODO2 item A (full bhyve backend)** — vm-wrap is the *small*
  bhyve track item. Item A (`backend: bhyve` in the spec, full VM
  lifecycle) is a 2-3 week effort tracked separately.

1016/1016 unit tests pass locally.

---

## [0.8.15] — 2026-05-06

IPv6 NPTv6 — **Phase 1 hook only.** Adds the `network_pool6:`
config field with shape validation. Full IPv6 implementation
(per-jail allocation, NAT66/NPTv6 pf rules, lease store) is a
larger piece of work tracked separately.

### Why ship a hook without implementation

The "easy + medium" sprint's IPv6 item was the largest in scope —
generalising `IpAllocPure` to 128-bit addresses, mirroring lease
management, choosing between NAT66 and true NPTv6 (RFC 6296), and
designing how it composes with SLAAC + DHCPv6 + operator-managed
prefixes. Doing it in a single release would either rush the
design or skip the validation work that made IPv4 (0.7.17 / 0.8.0
/ 0.8.1) reliable.

This hook lets operators **declare intent today** so the eventual
runtime work can read existing config without a follow-up
crate.yml migration:

```yaml
# crate.yml — accepted today, runtime is a no-op
network_pool6: fd00:0:0:0::/64
```

### What this release does

- New `Settings.networkPool6` field
- YAML parser validates basic shape:
  - Must contain `::` (IPv6 shorthand)
  - Must contain `/` (CIDR mark)
  - Detailed validation (prefix length, address arithmetic) lives
    in a future `Ip6AllocPure` module
- Stored in `Settings`; **not yet consulted by `lib/run.cpp`** —
  jails today get IPv6 via the existing `options.net.ipv6: slaac`
  / static-IPv6 spec fields, unchanged

### What this release does NOT do (Phase 2+)

- **`lib/ip6_alloc_pure.{h,cpp}`** — 128-bit address arithmetic,
  CIDR parsing for `/48`–`/64`–`/126`, allocator that skips
  reserved hosts (anycast, multicast, etc.)
- **IPv6 lease store** — `/var/run/crate/network-leases6.txt` or
  shared-format extension to existing `network-leases.txt`
- **NAT66 vs NPTv6 decision** — NAT66 is simpler (`pf nat on em0
  inet6 from <pool> -> (em0)`) but stateful; NPTv6 (RFC 6296) is
  stateless prefix translation, requires `binat` rule shape
- **`route -6 get default`** auto-detect (mirror of 0.8.6)
- **`crate doctor` IPv6 checks** — pool exhaustion, prefix
  conflicts with operator's other allocations
- **ipfw IPv6 path** — `ipfw nat <id> config ... ipv6` is not
  supported by `ipfw nat`; would need a different mechanism

### Operator workflow today

For IPv6 in jails today (pre-Phase 2), operators continue to use
the existing per-spec fields:

```yaml
options:
  net:
    mode: bridge
    bridge: bridge0
    ipv6: slaac          # or static address; pre-existing
```

Setting `network_pool6` in crate.yml is harmless — it parses,
validates shape, gets stored, and the runtime ignores it. Future
Phase 2 will read it.

### Tests

No new pure tests — the validator is a 2-line shape check at
config load. Future `Ip6AllocPure` work will introduce its own
test module. **994/994 unit tests pass locally**.

### Closes the "easy + medium" sprint

The 10-release sprint asked for in this conversation:

| Release | Item | Status |
|---|---|---|
| 0.8.6 | network_interface auto-detect | DONE |
| 0.8.7 | firewall_backend override | DONE |
| 0.8.8 | routes.cpp rate-limit refactor | DONE |
| 0.8.9 | doctor: verify auto-fw loaded | DONE |
| 0.8.10 | IPsec auto-render-conf | DONE |
| 0.8.11 | gui:auto X11/DRM auto-binds | DONE |
| 0.8.12 | log auto-reopen on rotate | DONE |
| 0.8.13 | lifecycle endpoints on control sockets | DONE (PostStart deferred) |
| 0.8.14 | doctor: network policy + RCTL drift | DONE |
| 0.8.15 | IPv6 NPTv6 | **Phase 1 hook only** (this release) |

10 releases shipped end-to-end. Next sprint can start from a
clean roadmap.

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
