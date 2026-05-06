// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for the crated control-socket plane (0.7.10).
//
// The control plane gives non-root operators (GUI/tray apps,
// IDE plugins) a Unix-socket REST API for status polling and
// live RCTL tuning, authenticated via filesystem permissions
// + getpeereid(2) instead of bearer tokens.
//
// Multiple sockets are supported, each scoped to a unix group
// and a list of pools (0.7.4). Operator A (member of group
// "dev-team") connects to /var/run/crate/control/dev.sock and
// can only reach jails in pools [dev, stage]. Operator B
// (group "ops") connects to a different socket and reaches
// only [prod] jails. Defence in depth:
//
//   1. Filesystem perms (mode 0660 root:<group>) — kernel
//      blocks connect(2) before crated sees a byte.
//   2. getpeereid(2) re-check inside crated — even if perms
//      get loosened, peer.gid must match the socket's group.
//   3. Pool ACL — request paths are validated against the
//      socket's pools list.
//
// This module owns:
//   - config-time validation of a ControlSocketSpec
//   - parse of REST routes ("/v1/control/containers/:name/...")
//   - the authorize() decision matrix
//   - JSON rendering of responses
//   - parse + whitelist of PATCH /resources bodies
//
// All filesystem / socket / process work lives in
// daemon/control_socket.cpp.
//

#include <string>
#include <vector>

namespace ControlSocketPure {

// --- Config struct ---

struct ControlSocketSpec {
  std::string path;             // /var/run/crate/control/dev.sock
  std::string group;            // unix group name (looked up via getgrnam(3))
  unsigned    mode = 0660;      // file mode after chmod
  std::vector<std::string> pools;  // pool ACL; "*" = all-pools
  std::string role = "viewer";  // "admin" or "viewer"
};

// --- Validation ---

// Validate a ControlSocketSpec at config-load time. Returns "" on
// success, otherwise a human-readable error.
//
// Rules:
//   - path must be absolute, non-empty, no `..` segments, no shell
//     metas, length <= 1024
//   - path must live under /var/run/crate/control/ (we own that
//     directory; we do not let operators put sockets in /etc or /tmp)
//   - group must be non-empty, <=32 chars, alnum + ._- (POSIX
//     getgrnam-friendly)
//   - mode must be in [0..0777]
//   - pools entries: "*" or alnum + ._- length 1..64
//   - role: "admin" or "viewer"
std::string validateSocketSpec(const ControlSocketSpec &spec);

// Returns true if `mode` is safe (0660 or stricter — no world bits).
// Caller WARNs but proceeds if false (per operator config).
bool isModeSafe(unsigned mode);

// --- Route parsing ---

enum class Action {
  Unknown,
  ListContainers,        // GET  /v1/control/containers
  GetContainer,          // GET  /v1/control/containers/:name
  GetContainerStats,     // GET  /v1/control/containers/:name/stats
  PatchResources,        // PATCH /v1/control/containers/:name/resources
};

struct ParsedRoute {
  Action      action = Action::Unknown;
  std::string container;   // empty for ListContainers
};

// Parse method+path into a ParsedRoute. Unknown routes -> Action::Unknown
// with empty container. Method-mismatch (e.g. POST on a known path) is
// also Action::Unknown.
ParsedRoute parseRoute(const std::string &method, const std::string &path);

// --- ACL decision ---

enum class Decision {
  Allow,
  DenyGidMismatch,    // peer.gid != socket.group's gid
  DenyPoolMismatch,   // container's inferred pool not in socket.pools
  DenyRoleMismatch,   // viewer attempting PATCH
  DenyUnknownAction,  // route didn't parse
};

struct AuthorizeInput {
  // Peer credentials extracted via getpeereid(2)
  long peerUid = -1;
  long peerGid = -1;
  // Socket-side context (from ControlSocketSpec + resolved gid)
  long socketExpectedGid = -1;
  std::string socketRole;             // "admin" or "viewer"
  std::vector<std::string> socketPools;
  // Request
  Action      action = Action::Unknown;
  std::string container;              // "" for ListContainers
  // Pool inference config (matches Crated::Config::poolSeparator)
  char poolSeparator = '-';
};

// Pure decision: would this peer be allowed to perform this action?
//
// Rules (in the order they're checked; first match returns):
//   1. ListContainers and other actions on ANY socket require
//      peer.gid == socketExpectedGid (the kernel already enforced
//      this via filesystem perms — we re-check defensively).
//   2. PATCH actions require role == "admin" (viewer is read-only).
//   3. Per-container actions: inferPool(container) must be in
//      socketPools (matches "*"). Pool-less containers (jail names
//      without the separator) reachable only by sockets with "*".
//   4. ListContainers is allowed once (1)+(2) pass; the route
//      handler filters the listing by socketPools at render time.
//
// Returns Decision::Allow on success.
Decision authorize(const AuthorizeInput &in);

// --- PATCH body parsing ---

struct ResourcesPatch {
  // Whitelisted RCTL keys (subset of the retune whitelist —
  // intentionally narrower since the control socket is reachable
  // by less-privileged users).
  //
  // Format: same as retune values (e.g. "20" for pcpu,
  // "512M" for memoryuse). Empty string = field not present in
  // the patch.
  std::string pcpu;        // 0..100
  std::string memoryuse;   // K/M/G/T suffix
  std::string readbps;     // K/M/G/T suffix
  std::string writebps;    // K/M/G/T suffix
};

// Parse a JSON body into a ResourcesPatch. Returns "" on success,
// human-readable error otherwise. Unknown keys are rejected
// (rather than silently ignored) so a typo by a tray-app developer
// doesn't silently fail to apply a limit.
//
// Body is a flat JSON object: {"pcpu":"20","writebps":"5M"}.
// At least one key is required (empty {} is rejected).
std::string parseResourcesPatch(const std::string &body, ResourcesPatch &out);

// --- JSON rendering ---

struct ContainerSummary {
  std::string name;
  std::string pool;        // inferred via PoolPure::inferPool
  std::string state;       // "running" | "stopped" — caller decides
  long        jid = 0;     // 0 if not running
};

// Render the GET /v1/control/containers list. Caller filters by
// socketPools before passing in. Output is stable-sorted by name
// for diff-friendliness.
std::string renderContainersJson(const std::vector<ContainerSummary> &items);

// Render an error envelope: {"error": "<msg>"}
std::string renderErrorJson(const std::string &msg);

// Render a single PATCH /resources OK response with the applied
// keys echoed back. Same ResourcesPatch struct as parseResourcesPatch.
std::string renderPatchOkJson(const ResourcesPatch &applied);

// --- Helpers ---

// HTTP status code that should accompany a Decision.
int httpStatusFor(Decision d);

// Stable short label for an Action — used as part of the rate-limit
// bucket key so each action class (list / get / stats / patch) gets
// its own counter per peer uid. Matches the route's "verb" rather
// than its URL path, so per-jail granularity doesn't fragment the
// counter into thousands of buckets.
//   ListContainers     -> "list"
//   GetContainer       -> "get"
//   GetContainerStats  -> "stats"
//   PatchResources     -> "patch"
//   Unknown            -> "unknown"
const char *actionLabel(Action a);

// True if this action is a state-changing one (PATCH today; future:
// any method that mutates server state). Caller picks a tighter
// rate-limit cap for these.
bool actionIsMutating(Action a);

// Filter a vector of pool names against the socket's pools list:
// returns the input pools that are visible to the socket. "*" in
// socketPools means "everything". Used by GET /containers handlers
// to scope the listing.
bool poolVisibleOnSocket(const std::string &pool,
                         const std::vector<std::string> &socketPools);

// --- Minimal HTTP/1.1 wire parsing (0.7.11) ---
//
// 0.7.11 ditches cpp-httplib for control sockets and runs a
// hand-rolled accept loop so getpeereid(2) can be called on the
// connection fd at accept time. The wire-level parsing is small
// because the API surface is small (4 routes, JSON bodies).
//
// Strict subset of HTTP we accept:
//   - HTTP/1.0 or HTTP/1.1 (we always reply with Connection: close)
//   - Request line: METHOD SP PATH SP VERSION CRLF
//   - Headers: case-insensitive NAME ":" VALUE CRLF; we only honour
//     Content-Length, all others are ignored.
//   - Headers terminated by empty CRLF.
//   - No chunked encoding, no continuation lines, no folding.
//
// Anything outside this subset is rejected; the runtime returns
// HTTP 400 and closes the connection.

struct ParsedHttp {
  std::string method;             // "GET" / "PATCH"
  std::string path;               // "/v1/control/containers"
  std::size_t contentLength = 0;  // from Content-Length header (0 if absent)
  bool        bad = false;
  std::string error;              // populated when bad == true
};

// Parse the header block of an HTTP request — bytes from connection
// start up to and including the first empty CRLF line. The body
// (if any) is read separately by the caller using ContentLength.
//
// Caps:
//   - method:  16 chars  (we don't need the larger spec-allowed set)
//   - path:    1024 chars
//   - any single header line: 4096 chars
//
// On any cap exceeded or syntax violation, returns ParsedHttp with
// bad == true and error filled.
ParsedHttp parseHttpHead(const std::string &head);

// Build a minimal HTTP/1.1 response. Always includes:
//   - Status line
//   - Content-Type
//   - Content-Length
//   - Connection: close
// No chunked encoding, no Transfer-Encoding, no Server header.
std::string buildHttpResponse(int status, const std::string &body,
                              const std::string &contentType = "application/json");

} // namespace ControlSocketPure
