# Trust model and multi-tenant isolation

**Audience:** operators running crate on a shared host (multiple
operators on one machine) and contributors extending the privileged
surface.

**Applies to:** 1.1.11 (rootless model, `crate(1)` non-setuid). For the
≤ 0.9.x setuid model and the migration, see
[`rootless-migration.md`](rootless-migration.md).

This document states, explicitly, **where cross-tenant isolation is
enforced and where it is not** — so deployments size their trust
boundaries correctly and future work doesn't silently regress them.

---

## TL;DR

Crate has two planes, with two different trust models:

1. **The privileged execution plane — `crated`'s privops surface.**
   Since 1.0.0 `crate(1)` is **no longer setuid** (`Makefile`,
   `-m 0755`); it is an unprivileged client. Every root operation
   (jail create/destroy, ZFS attach, mount, RCTL, interface/firewall
   config, signal) is performed by `crated` (which runs as root) when
   asked over **privops** — either `POST /api/v1/privops/<verb>`
   (admin-only) or the libnv `AF_UNIX` privops socket (group-gated).
   This plane **does not arbitrate between operators.** Anyone who can
   reach privops has root-equivalent control over *every* jail on the
   host. It is a **single trust domain** — the same property the old
   setuid `crate(1)` had, relocated into the daemon.

2. **The pooled observability / control plane.** This is where
   **per-tenant isolation is enforced**, via pool ACLs + token scope,
   on the entry points that carry caller identity: dedicated control
   sockets (`getpeereid` gid + pool ACL), remote bearer tokens (scope +
   pool ACL), and the ws-console (bearer + pool ACL). Surface:
   `list` / `get` / `stats` / `logs` / `start` / `stop` / `restart` /
   `PATCH resources` / interactive console.

**The invariant:** multi-tenant isolation between mutually-distrusting
operators lives **only** on the pooled plane's identity-carrying entry
points (control-socket `pools`, token `pools` + `scope`), enforced
daemon-side per request and keyed on the **target** jail's pool. The
privops plane, and local Unix-socket access to the main HTTP API, are
single trust domains. A hostile-multi-tenant deployment must therefore
hand untrusted operators a **pool-scoped control socket or bearer
token only** — never privops-socket access, never an admin token, and
never the main API's Unix socket.

---

## What changed since 0.7.19 — the privileged plane relocated

In 0.7.19 the single-trust-domain privileged plane was the setuid-root
`crate(1)` binary. The rootless track (0.9.0–1.0.0, see
[`rootless-migration.md`](rootless-migration.md)) moved every
privileged operation out of `crate(1)` and into `crated`'s privops
surface; 1.0.0 removed the setuid bit (`Makefile`, comment at the
`crate` install line: *"setuid bit removed. crate(1) runs as the
operator and delegates privileged operations to crated(8)"*).

The single-trust-domain property did **not** disappear — it relocated.
Reasoning about isolation on 1.1.11 means reasoning about who can reach
**privops**, not who can run `crate(1)`.

---

## Plane 1 — the privops privileged execution plane (single trust domain)

`crate(1)` is installed `-m 0755` (`Makefile`; setuid removed 1.0.0).
`crated` runs as root (rc.d) and is the only privileged binary. It
performs root operations only in response to a closed set of **privops
verbs** (`create_jail`, `destroy_jail`, `attach_zfs`, `set_rctl`,
`configure_iface`, `add_pf_rule`, `signal_jail`, `apply_devfs_ruleset`,
… — `lib/privops_pure.h`). Two transports reach it:

- **HTTP — `POST /api/v1/privops/<verb>`.** Gated **admin-only**:
  `isAuthorized(req, config, "admin")` (`daemon/routes.cpp:1007`). The
  handler comment states the design intent explicitly — *"Privops
  touch host-wide state … so per-container scope from the F2 surface
  doesn't apply"* (`daemon/routes.cpp:997-999`). On this path the
  operator uid stays `0` (cpp-httplib doesn't expose the connection fd
  for `getpeereid`), so per-user audit is a no-op
  (`daemon/routes.cpp:1013-1019`).
- **libnv `AF_UNIX` socket (0.9.14).** Group-gated: the listener
  `chmod`s the socket to its mode and `chown`s it `root:<group>`
  (`daemon/privops_listener.cpp:179,188`; default mode `0660`,
  `daemon/config.h:117-119`). `getpeereid(2)` extracts the peer uid
  (`daemon/privops_listener.cpp:90`) and feeds both the per-user audit /
  namespacing hook **and** the authorize-before-dispatch gate below.

Verb dispatch is `parse → validate → handle` (`dispatchPrivOp` /
`dispatchPrivOpFromMap`, `daemon/privops_handlers.cpp`). Authorization
differs by transport:

- **HTTP:** no per-resource check — `admin`-only and host-wide by
  design (`daemon/routes.cpp:997-999`).
- **libnv (real peer uid):** as of 1.1.12 an authorize-before-dispatch
  gate (`dispatchPrivOpFromMap` → `PrivOpsAuthzPure::authorize`,
  `lib/privops_authz_pure.cpp`) enforces per-user ownership for the
  verbs that carry a robust ownership signal, keyed on the caller's
  `composeForUid` env: `attach_zfs`/`detach_zfs` (the `dataset` must lie
  within the caller's ZFS prefix `<master>/<uid>`) and
  `set_loginclass_rctl`/`clear_loginclass_rctl` (the `loginclass` must
  be the caller's `crate-<uid>`). A foreign target is denied `403`
  before the handler runs (fail closed).

The remaining verbs still pass the gate: **host-global** verbs
(iface/pf/ipfw/nat/epair) cannot be pool-scoped and stay host-wide by
design; **jid-scoped** verbs (`set_rctl`, `signal_jail`, `create_jail`,
`set_jail_cpuset`, devfs, …) carry no request-borne owner and are not
yet gated — a jid→owner registry is deferred (see the open gap below).
The per-verb handlers remain uid-blind; the gate runs ahead of them.

> Consequence: whoever can reach privops — an `admin` bearer token, or
> membership in the privops socket's group — still has host-wide control
> over the **un-gated** surface (jail lifecycle, signals, firewall,
> interfaces). The 1.1.12 gate closes cross-tenant ZFS-dataset and
> RCTL-umbrella access on the libnv path, but privops remains, in the
> general case, a single trust domain — handing an operator privops
> access is close to handing them the old setuid `crate(1)`.

### Per-user namespacing is convenience, not a boundary

Rootless mode derives per-operator paths, ZFS prefixes, network
sub-CIDRs and an RCTL umbrella class from the connecting operator's uid
(`lib/per_user_*`, `lib/runtime_paths_pure.*`; see
[`rootless-migration.md`](rootless-migration.md)). This cleanly
separates **honest** operators — alice's and bob's `web` jails land in
different ZFS subtrees and CIDRs.

It is **not** an adversarial boundary on the privops plane. The per-uid
prefix is computed **client-side** (in `crate(1)`) and passed in the
request; `crated` does **not** re-derive or validate the request's
`jid` / `dataset` / `path` against the peer uid. A hostile privops-group
member can craft a raw nvlist request naming another operator's prefix
and `crated` will act on it. So "bob can't run a jail in alice's ZFS
prefix" ([`rootless-migration.md`](rootless-migration.md)) holds for
honest clients going through an honest `crate(1)`; it is not a
daemon-enforced cross-tenant boundary. Enforced adversarial isolation
lives on Plane 2.

---

## Plane 2 — the pooled observability / control plane (isolated)

`crated`'s non-privileged surface. Per-tenant isolation is enforced on
the entry points that carry caller identity.

### 2a. Dedicated control sockets (0.7.10) — isolated

Per-group `AF_UNIX` sockets under `/var/run/crate/control/`, with three
layers of defense:

1. **Filesystem perms (kernel).** Socket `chmod`'d to the spec mode and
   `chown`'d `root:<group>` so only group members can `connect(2)` —
   `daemon/control_socket.cpp:582,586`.
2. **`getpeereid(2)` gid re-check.** Even if the mode is loosened, the
   peer's gid must equal the socket's expected gid —
   `daemon/control_socket.cpp:395` feeding `ControlSocketPure::authorize`
   (`daemon/control_socket_pure.cpp:277`, `Decision::DenyGidMismatch`).
3. **Pool ACL.** For per-container actions the container's pool
   (`PoolPure::inferPool`, `daemon/control_socket_pure.cpp:292`) must be
   visible on the socket's `pools` list — `poolVisibleOnSocket`
   (`:293`, defined `:406`). Mutating actions (`PATCH resources`,
   `POST start`/`stop`/`restart`) additionally require the `admin` role
   (`:282`, 0.8.13).

Result: alice's socket (`pools: ["alice"]`) cannot observe, patch, or
start/stop a jail in bob's pool. This is the mechanism a multi-tenant
deployment relies on. Note these sockets cover the *control* surface
only — they do **not** expose `create_jail` / `attach_zfs`, which are
privops (Plane 1).

### 2b. Remote bearer tokens (0.7.1 scope, 0.7.4 pools) — isolated

HTTP API clients authenticate with a bearer token carrying expiry
(`daemon/config.h:21`; `0` == never), scope path-globs
(`daemon/config.h:26`; matched by `AuthPure::pathInScope`,
`lib/auth_pure.cpp:81`), a role, and a pool ACL (`daemon/config.h:31`).
`checkBearerAuthFull` gates expiry + scope + role
(`lib/auth_pure.cpp:101`); the per-container pool gate is
`isAuthorizedForContainer` → `PoolPure::tokenAllowsContainer`
(`daemon/auth.cpp:83-84`).

> Caveat: an **`admin`** bearer token also unlocks the privops HTTP
> plane (2a above is role-gated, privops is `admin`-gated). An admin
> token is therefore host-wide, **not** pool-confined. Only
> `viewer`/pool-scoped tokens are isolation-bearing.

### 2c. ws-console interactive shell — isolated (bearer + pool)

The websocket console grants an interactive `jexec` shell inside a
jail, so its gate is load-bearing. It requires an `admin` bearer token
(`daemon/ws_console.cpp:231`) **and** that the jail's pool be allowed by
the token (`PoolPure::inferPool` / `tokenAllowsContainer`,
`daemon/ws_console.cpp:254-255`).

### 2d. Local Unix-socket access to the main HTTP API — NOT isolated

The main `crated` HTTP API is also reachable over a local Unix socket.
On that path cpp-httplib does not expose the peer fd, so `getpeereid(2)`
is not wired in. **Unix-socket peers are trusted wholesale:**

- `isAuthorized` returns `true` immediately for Unix peers, bypassing
  bearer auth — `daemon/auth.cpp:48-49`.
- `isAuthorizedForContainer` likewise bypasses the pool ACL for Unix
  peers — `daemon/auth.cpp:74-75`.

The socket file mode (default `0660 root:wheel`) is the *only* gate —
`daemon/auth.cpp:36-40`. So local access to the main API is, like
privops, a **single trust domain**. `getpeereid`-based auth here is
still future work (roadmap §5.3). Only the dedicated control sockets
(2a) carry per-pool identity locally.

---

## The invariant, stated for implementers

> **Cross-tenant isolation = pool ACLs (control-socket `pools`, token
> `pools`) + token scope, enforced per request, keyed on the target
> jail's pool. It exists only on entry points that carry caller
> identity (Plane 2a/2b/2c). The privops plane and the main API's Unix
> socket are single trust domains.**

This is the contract any new privileged surface inherits.

---

## The open gap, and the guardrail for closing it

1.1.12 began closing this gap: the libnv path now authorizes
`attach_zfs`/`detach_zfs` (by ZFS prefix) and the loginclass-RCTL verbs
(by `crate-<uid>`) before dispatch. The rest of Plane 1 is still a
single trust domain — host-wide `admin` token on HTTP, host-wide group
membership on the libnv socket for every un-gated verb. That is fine
**as long as privops access is treated as equivalent to handing out the
old setuid `crate(1)`** — i.e. only ever given to fully-trusted
operators.

The unresolved tension: the rootless model *requires* `crate(1)` to
reach privops to create a jail at all, while the per-user namespacing
(above) is marketed as multi-tenant isolation. To make privops itself
safe for **mutually-distrusting** operators, the following MUST hold for
*every* verb — or the per-user split is honest-operator hygiene, not a
security boundary:

1. **Authorize before dispatch.** `getpeereid` uid/gid *identifies* the
   caller; it does **not** *authorize* the operation. Every privileged
   verb must run an ownership check — the same shape as
   `poolVisibleOnSocket` / `tokenAllowsContainer` — keyed on the
   **target** jail/pool/dataset, *before* the operation runs.
   *Done (1.1.12):* dataset and loginclass verbs
   (`lib/privops_authz_pure.cpp`). *Remaining:* the jid-scoped verbs
   (`set_rctl`, `signal_jail`, `set_jail_cpuset`, devfs, `destroy_jail`,
   `query_jail_rctl`) and the `create_jail` / `mount_nullfs` path
   arguments. These need a **jid→owner registry** (record the operator
   uid at `create_jail` time, check it on every jid-keyed verb), since a
   live jid carries no request-borne owner.

2. **Per-operator namespacing is convenience, not a boundary.** Any
   `path` / `jid` / `dataset` argument crossing the privops socket must
   be re-derived or validated **daemon-side** against the caller's
   uid-prefix — never taken at face value. *Done* for `dataset`;
   *remaining* for `path` / `jid` (see (1)).

3. **Fail closed on identity loss.** On any path that authorizes, a
   `getpeereid` failure must deny. It may degrade to a no-op only for
   identity-tagged side effects that are not access decisions (e.g. the
   audit tail — its current behavior).

Until the jid-scoped verbs in (1) are gated, a multi-tenant deployment
that needs operators to create their own jails must mediate jail
creation through a trusted
broker rather than handing operators raw privops-socket access.

---

## Deployment guidance (mutually-distrusting tenants)

- **Give untrusted operators:** a pool-scoped dedicated control socket
  (2a) and/or a `viewer`/pool-scoped bearer token (2b) only.
- **Do not give untrusted operators:** privops-socket (group) access,
  an `admin` bearer token, the main API's Unix socket, or a `crate(1)`
  that must reach privops to create jails.
- Honest-operator separation (per-user paths/datasets/CIDRs) and
  enforced adversarial isolation (pool-ACL'd Plane 2) are different
  guarantees — don't conflate them.

---

## See also

- [`rootless-migration.md`](rootless-migration.md) — the 0.9.0–1.0.0
  setuid → privops migration and the per-user model.
- [`security-command-paths.md`](security-command-paths.md) — absolute
  command paths / env-sanitization (CWE-426). Now most relevant to
  `crated`, which is the process that execs host tools as root.
- [`implementation-roadmap.md`](implementation-roadmap.md) §5.1
  (high-level REST write endpoints), §5.3 (`getpeereid` auth on the
  main API).
