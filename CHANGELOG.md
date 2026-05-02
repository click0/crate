# Changelog

All notable changes to **crate** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
