# getpeereid on the main HTTP API socket — design notes

**Status:** design only — no code change. Argues for **deferring** the
big refactor, and lists the option space if/when it becomes necessary.

**Touches:** `daemon/server.cpp:89` `// requires the bigger getpeereid
refactor (TODO)`, `TODO` "True `getpeereid(2)`-based unix-socket auth in
crated."

---

## 1. The problem, recapped

`daemon/server.cpp` runs the main HTTP API over an `AF_UNIX` socket via
cpp-httplib (`httplib::Server::listen` with `set_address_family(AF_UNIX)`,
lines 62–72). cpp-httplib hides the per-connection fd, so the daemon
cannot call `getpeereid(2)` on it. Today's compensations:

- **0.8.19 fs-perm gate.** Post-`listen()` poll for the socket file,
  then `chmod` / `chown` to the configured `unix_owner / unix_group /
  unix_mode`. Restricts who can `connect(2)`.
- **Admin-token bearer auth.** `isAuthorized(req, config, "admin")`
  on every privileged endpoint (`daemon/routes.cpp`); the unix-socket
  path doesn't bypass auth.

What is missing:

1. **Per-connection peer uid.** The HTTP handlers run as `uid == 0`
   regardless of the connecting operator, so per-user audit is a no-op
   on this path (`daemon/privops_handlers.cpp:1013-1019` comment notes
   it).
2. **Bind→chmod race.** From `bind(2)` inside httplib until the
   post-listen `chmod` runs (~ms but measurable), the socket sits at
   the umask-default mode. A concurrent attacker could connect during
   the window. The 0.8.19 code knows about this gap (`server.cpp:82-89`).

---

## 2. Is this security-critical? — **No**, per the current trust model

[`docs/trust-model.md`](trust-model.md) §"Plane 1" classifies the main
HTTP API + the admin token as **a single trust domain by design**:

> *§"Privops touch host-wide state … so per-container scope from the F2
> surface doesn't apply"* (`daemon/routes.cpp:997-999`).

> *§2d: Local Unix-socket access to the main HTTP API — NOT isolated.*

Tenant isolation on `crated` lives on **Plane 2** — the dedicated
control sockets (per-group, with `getpeereid` already hooked, see
`daemon/control_socket.cpp:395`), bearer-token scopes, and the
ws-console listener. The 1.1.12 + 1.1.13 + 1.1.14 + 1.1.15 privops
authz series closes the per-tenant gate on the libnv-socket privops
plane *without* needing this refactor.

So the value of the bigger refactor is:

- **(a)** per-request uid in the audit tail on the main HTTP API
  (today's audit is uid-blind there);
- **(b)** closing the bind→chmod race fully (today's gap is small but
  real);
- **(c)** future-proofing in case some HTTP endpoint ever needs
  per-tenant ownership (not requested today).

None of these is a blocker. **Recommendation: defer the big refactor
until a concrete multi-tenant feature on the main HTTP API forces
(c).** That moment can equally well be answered by *pushing the new
feature onto a control-socket / per-user surface* — the architecture
the project already chose.

---

## 3. Smaller wins available *without* the big refactor

These are tractable as one- or two-PR follow-ups; they don't fix
(a) or (c), but they do address (b) and improve hygiene.

### 3.1 Close the bind→chmod race via an "outer listener"

Replace the cpp-httplib UDS code path with a thin wrapper that:

1. Creates the socket, `bind`s it.
2. **Before** `listen()`, `chmod`/`chown` to the configured mode/owner.
3. `listen()`.
4. Hands the listening fd to cpp-httplib via its existing
   `Server::set_socket(int fd)` API (if available in our pinned httplib
   version) or by forking the listen loop.

This is materially less work than (3.2) below; it closes the race for
free if httplib's `set_socket` works on AF_UNIX. Worth an exploratory
PR before committing to the bigger plan.

### 3.2 Log peer uid on connection accept (audit-only)

Tap into cpp-httplib's `Server::set_pre_routing_handler` (or
`set_socket_options`) and pull the peer uid from the connection. If
httplib's threading model lets a callback see the connection fd in any
form, this avoids touching handlers; if not, it requires a tiny fork.
The recorded uid feeds `maybeWritePerUserAudit` (currently no-op on
the HTTP path); per-user audit then "just works" on the main API too.

---

## 4. Option space *if* we proceed with the big refactor

Three viable shapes, ranked by long-term maintenance cost.

### A. Fork cpp-httplib locally — narrow patch

Vendor cpp-httplib into `third_party/` and apply a minimal patch that
exposes `Server::socket()` on the per-request thread, plus an accept
hook. Every handler then reads `req.socket_fd` and calls
`getpeereid(fd)`.

| pros | cons |
|---|---|
| ~30 lines of patch, no handler rewrite | rebase friction on every httplib upgrade; we own a fork |
| Aligns with how 0.6.4 ws-console handled a similar need | "vendor a 3rd-party library" sets precedent |

### B. Hand-rolled UDS listener mirroring `control_socket.cpp`

Replace the AF_UNIX path entirely. `daemon/server.cpp` keeps its
SSL/TCP path on httplib but spawns a hand-rolled listener for the
`unix_socket`. Each connection:

1. `accept(listenFd)` → `connFd`
2. `getpeereid(connFd, &uid, &gid)`
3. `Sandbox::applyConnectionRights(connFd)` (already used by
   `control_socket.cpp:405`)
4. `ControlSocketPure::parseHttpHead(head)` — reuse the pure parser
5. Bridge to the existing `httplib::Request` / `httplib::Response`
   shape so all 40+ handlers in `daemon/routes.cpp` keep working
   unchanged. (Or migrate handlers off the httplib types over a few
   PRs.)

| pros | cons |
|---|---|
| No fork; same pattern we already trust (`control_socket.cpp`, `ws_console.cpp`, `privops_listener.cpp`) | Big — ~600 LOC of new daemon code; bridge layer is its own complexity |
| Capsicum-friendly per existing pattern | Routing/handler types divorce httplib gradually — multi-PR rewrite |

### C. Header-injection wrapper

Thin shim that wraps httplib's UDS path; on each accept, captures
`getpeereid(fd)` into a thread-local; handlers read the TLS var.

| pros | cons |
|---|---|
| Minimal handler change | Brittle (depends on httplib's threading model not changing); race-prone on connection reuse |

### Recommendation if a refactor is mandated

**B** is the most defensible long-term — it matches the rest of the
codebase's accept-loop pattern, makes Capsicum work obvious, and
removes one more cpp-httplib dependency. Plan it as a 3-PR series:

1. **Phase 1:** lift `ControlSocketPure::parseHttpHead` / `readUntilNeedle`
   / `writeAll` / Capsicum hook into a shared `daemon/http_parser_pure.{h,cpp}`
   + `daemon/connection_loop.{h,cpp}`. Same body, just shared. Zero
   behavior change; ~150 LOC + tests.
2. **Phase 2:** add a hand-rolled UDS listener to `daemon/server.cpp`
   that uses the shared loop but still bridges into the existing
   `httplib::Server::handle_request` via a shim — handlers untouched.
   `getpeereid` lands on the peer uid; audit gets the right uid; race
   closed. ~300 LOC.
3. **Phase 3:** migrate handlers off `httplib::Request` / `Response`
   over one or two PRs (group by route family). Drop the bridge. ~600
   LOC spread over multiple PRs; can stretch into 1.3.x.

---

## 5. Decision recap

- **Now:** do nothing big. The trust-model deliberately treats the
  main API as single trust domain; the privops authz series (#211..#213)
  covered the actual tenant-isolation surface.
- **Soonish (1.1.x):** consider §3.1 (race-window close via
  `set_socket`) as a small hygiene PR if httplib's API allows it. ~50
  LOC. Worth doing.
- **Later (1.2.x+):** if/when a concrete feature wants per-tenant
  access on the main HTTP API, execute Plan B in the 3-phase
  migration. Until then, the architectural choice is: **new
  per-tenant surface lives on control sockets, not on the main API**
  — matching where Plane 2 already is in the trust model.

---

## See also

- [`trust-model.md`](trust-model.md) §"Plane 1" and §"2d" — why the
  main API is intentionally single trust domain.
- `daemon/control_socket.cpp:385-543` — the existing hand-rolled
  pattern we'd lift in Phase 1.
- `daemon/server.cpp:62-104` — the current UDS path and the
  bind→chmod race code.
- `TODO` "True `getpeereid(2)`-based unix-socket auth in crated."
