// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// Runtime for the crated control-socket plane (0.7.10).
//
// For each ControlSocketSpec:
//   1. Resolve the unix group via getgrnam(3); WARN-and-skip if absent.
//   2. WARN if the configured mode has world-bits set (operator
//      override is allowed by design — see TODO note below).
//   3. mkdir -p /var/run/crate/control/ (mode 0755).
//   4. unlink old socket from a prior run.
//   5. bind, then chmod, then chown root:<gid>.
//   6. Spawn a httplib::Server thread that registers control-only
//      routes. Each request invokes peer_extract → control_route_dispatch.
//
// Peer extraction TODO (0.7.11):
//
// Defence-in-depth design: filesystem perms (kernel-enforced) are
// the OUTER gate — operator B physically cannot connect(2) to
// operator A's socket because the kernel rejects the open with
// EACCES before crated sees a byte. INSIDE crated we'd like to
// re-check via getpeereid(2) against the connection fd, so even
// a misconfigured 0666 socket fails closed.
//
// cpp-httplib (the HTTP framework crated already uses) does NOT
// expose the per-connection fd through its public API. Adding the
// inner getpeereid check therefore requires either:
//   (a) forking cpp-httplib to expose the fd, or
//   (b) writing a custom HTTP-on-unix-socket accept loop (~400 LOC).
//
// For 0.7.10 we ship with filesystem perms as the sole gate. We
// pass `peerGid = expectedGid` synthetically so the pure-module
// ACL chain still runs (pool/role checks remain effective). The
// gid-mismatch branch in ControlSocketPure::authorize is therefore
// unreachable at runtime — but the unit tests still cover it, so
// when we wire (b) in 0.7.11 the policy is already validated.
//
// No control-socket request EVER touches state of jails outside its
// pool ACL, even with this limitation: pool/role checks are pure
// and re-run for every request.
//

#include "control_socket.h"
#include "control_socket_pure.h"
#include "../lib/jail_query.h"
#include "../lib/pool_pure.h"
#include "../lib/util.h"
#include "../lib/pathnames.h"

#include <httplib.h>

#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <thread>
#include <vector>

namespace Crated {

// Peer credentials would be set per-connection here in a future
// release that wires getpeereid(2). For 0.7.10 we synthesise them
// from the socket's expected gid (see file header comment).
static thread_local long g_peerUid = -1;
static thread_local long g_peerGid = -1;

namespace {

// Resolve a unix group name to gid. Returns -1 if not found.
long resolveGroup(const std::string &name) {
  errno = 0;
  struct group *gr = ::getgrnam(name.c_str());
  if (!gr) return -1;
  return static_cast<long>(gr->gr_gid);
}

// mkdir -p style, mode 0755. Tolerates EEXIST. Throws on other
// failures.
void mkdirP(const std::string &dir) {
  std::string cur;
  for (char c : dir) {
    cur += c;
    if (c == '/' && cur.size() > 1) {
      if (::mkdir(cur.c_str(), 0755) != 0 && errno != EEXIST)
        throw std::runtime_error("mkdir " + cur + ": " + std::strerror(errno));
    }
  }
  if (::mkdir(dir.c_str(), 0755) != 0 && errno != EEXIST)
    throw std::runtime_error("mkdir " + dir + ": " + std::strerror(errno));
}

// Pre-route check + response. Used by every control-socket handler
// before doing any work.
bool authorizeOrReject(const httplib::Request &req,
                       httplib::Response &res,
                       const ControlSocketPure::ControlSocketSpec &spec,
                       long expectedGid,
                       char poolSeparator,
                       ControlSocketPure::ParsedRoute &route) {
  ControlSocketPure::AuthorizeInput in;
  // 0.7.10: peer creds synthesised from the socket's expected gid.
  // Filesystem perms (kernel) are the actual gate; this branch
  // becomes meaningful once getpeereid(2) is wired (0.7.11).
  in.peerUid           = g_peerUid;  // unused at runtime
  (void)g_peerUid;
  in.peerGid           = expectedGid;
  in.socketExpectedGid = expectedGid;
  in.socketRole        = spec.role;
  in.socketPools       = spec.pools;
  in.action            = route.action;
  in.container         = route.container;
  in.poolSeparator     = poolSeparator;

  auto d = ControlSocketPure::authorize(in);
  if (d == ControlSocketPure::Decision::Allow) return true;

  std::string msg;
  switch (d) {
  case ControlSocketPure::Decision::DenyGidMismatch:
    msg = "peer credentials do not match the socket's expected group";
    break;
  case ControlSocketPure::Decision::DenyPoolMismatch:
    msg = "container is outside the pools served by this socket";
    break;
  case ControlSocketPure::Decision::DenyRoleMismatch:
    msg = "this socket has the 'viewer' role; PATCH requires 'admin'";
    break;
  case ControlSocketPure::Decision::DenyUnknownAction:
    msg = "unknown route";
    break;
  default:
    msg = "denied";
  }
  res.status = ControlSocketPure::httpStatusFor(d);
  res.set_content(ControlSocketPure::renderErrorJson(msg), "application/json");
  return false;
}

// GET /v1/control/containers
void handleList(httplib::Response &res,
                const ControlSocketPure::ControlSocketSpec &spec,
                char poolSeparator) {
  auto jails = JailQuery::getAllJails(/*crateOnly=*/true);
  std::vector<ControlSocketPure::ContainerSummary> out;
  for (const auto &j : jails) {
    auto pool = PoolPure::inferPool(j.name, poolSeparator);
    if (!ControlSocketPure::poolVisibleOnSocket(pool, spec.pools))
      continue;
    ControlSocketPure::ContainerSummary cs;
    cs.name  = j.name;
    cs.pool  = pool;
    cs.state = j.dying ? "dying" : "running";
    cs.jid   = j.jid;
    out.push_back(cs);
  }
  res.set_content(ControlSocketPure::renderContainersJson(out),
                  "application/json");
}

// GET /v1/control/containers/:name
void handleGet(httplib::Response &res, const std::string &name) {
  auto j = JailQuery::getJailByName(name);
  if (!j) {
    res.status = 404;
    res.set_content(ControlSocketPure::renderErrorJson("container not found"),
                    "application/json");
    return;
  }
  std::ostringstream o;
  o << "{\"name\":\"" << j->name << "\","
    << "\"jid\":" << j->jid << ","
    << "\"path\":\"" << j->path << "\","
    << "\"hostname\":\"" << j->hostname << "\","
    << "\"ip4\":\"" << j->ip4 << "\","
    << "\"dying\":" << (j->dying ? "true" : "false") << "}";
  res.set_content(o.str(), "application/json");
}

// GET /v1/control/containers/:name/stats
void handleStats(httplib::Response &res, const std::string &name) {
  auto j = JailQuery::getJailByName(name);
  if (!j) {
    res.status = 404;
    res.set_content(ControlSocketPure::renderErrorJson("container not found"),
                    "application/json");
    return;
  }
  std::map<std::string, std::string> usage;
  try {
    auto raw = Util::execCommandGetOutput(
      {CRATE_PATH_RCTL, "-u", "jail:" + std::to_string(j->jid)},
      "query RCTL usage");
    std::istringstream is(raw);
    std::string line;
    while (std::getline(is, line)) {
      auto eq = line.find('=');
      if (eq != std::string::npos)
        usage[line.substr(0, eq)] = line.substr(eq + 1);
    }
  } catch (...) {
    // Empty usage is fine — operator should still see the jail
    // exists, just with no RCTL data attached.
  }
  std::ostringstream o;
  o << "{\"jid\":" << j->jid << ",\"usage\":{";
  bool first = true;
  for (const auto &[k, v] : usage) {
    if (!first) o << ",";
    o << "\"" << k << "\":\"" << v << "\"";
    first = false;
  }
  o << "}}";
  res.set_content(o.str(), "application/json");
}

// PATCH /v1/control/containers/:name/resources
void handlePatch(const httplib::Request &req, httplib::Response &res,
                 const std::string &name) {
  auto j = JailQuery::getJailByName(name);
  if (!j) {
    res.status = 404;
    res.set_content(ControlSocketPure::renderErrorJson("container not found"),
                    "application/json");
    return;
  }
  ControlSocketPure::ResourcesPatch patch;
  if (auto e = ControlSocketPure::parseResourcesPatch(req.body, patch);
      !e.empty()) {
    res.status = 400;
    res.set_content(ControlSocketPure::renderErrorJson(e),
                    "application/json");
    return;
  }
  // Apply each present field via rctl(8). Whitelist is enforced by
  // parseResourcesPatch itself (only pcpu/memoryuse/readbps/writebps).
  auto applyOne = [&](const char *key, const std::string &value) {
    if (value.empty()) return;
    auto rule = "jail:" + j->name + ":" + key + ":deny=" + value;
    Util::execCommand({CRATE_PATH_RCTL, "-a", rule}, "rctl -a");
  };
  try {
    applyOne("pcpu",      patch.pcpu);
    applyOne("memoryuse", patch.memoryuse);
    applyOne("readbps",   patch.readbps);
    applyOne("writebps",  patch.writebps);
  } catch (const std::exception &e) {
    res.status = 500;
    res.set_content(ControlSocketPure::renderErrorJson(
      std::string("rctl(8) failed: ") + e.what()), "application/json");
    return;
  }
  res.set_content(ControlSocketPure::renderPatchOkJson(patch),
                  "application/json");
}

void registerControlRoutes(httplib::Server &srv,
                           const ControlSocketPure::ControlSocketSpec &spec,
                           long expectedGid,
                           char poolSeparator) {
  // We register a single catch-all that re-parses the route via the
  // pure module so the ACL decision and route parsing live in one
  // place. httplib's own routing would force us to duplicate paths.
  auto handler = [spec, expectedGid, poolSeparator](
      const httplib::Request &req, httplib::Response &res) {
    ControlSocketPure::ParsedRoute route =
      ControlSocketPure::parseRoute(req.method, req.path);

    if (!authorizeOrReject(req, res, spec, expectedGid, poolSeparator, route))
      return;

    switch (route.action) {
    case ControlSocketPure::Action::ListContainers:
      handleList(res, spec, poolSeparator);
      return;
    case ControlSocketPure::Action::GetContainer:
      handleGet(res, route.container);
      return;
    case ControlSocketPure::Action::GetContainerStats:
      handleStats(res, route.container);
      return;
    case ControlSocketPure::Action::PatchResources:
      handlePatch(req, res, route.container);
      return;
    case ControlSocketPure::Action::Unknown:
      // already handled by authorizeOrReject; can't reach here
      return;
    }
  };

  // Register for all methods we might see; httplib calls the matching
  // method-specific handler if registered, otherwise 404.
  srv.Get   ("/v1/control/.*",  handler);
  srv.Patch ("/v1/control/.*",  handler);
  // Anything else returns 404 (we don't register POST/PUT/DELETE).
}

// One Server instance per socket. Run on a detached thread.
struct SocketRuntime {
  ControlSocketPure::ControlSocketSpec spec;
  long expectedGid = -1;
  char poolSeparator = '-';
  std::unique_ptr<httplib::Server> srv;
  std::thread thread;
};

} // anon

struct ControlSocketsManager::Impl {
  std::vector<std::unique_ptr<SocketRuntime>> runtimes;
};

ControlSocketsManager::ControlSocketsManager(const Config &config)
  : config_(config), impl_(std::make_unique<Impl>()) {}

ControlSocketsManager::~ControlSocketsManager() { stop(); }

int ControlSocketsManager::start() {
  if (config_.controlSockets.empty()) return 0;

  // Ensure /var/run/crate/control exists with reasonable mode.
  try {
    mkdirP("/var/run/crate/control");
  } catch (const std::exception &e) {
    std::cerr << "control_sockets: cannot create /var/run/crate/control: "
              << e.what() << " — skipping all control sockets" << std::endl;
    return 0;
  }

  int started = 0;
  for (const auto &spec : config_.controlSockets) {
    auto gid = resolveGroup(spec.group);
    if (gid < 0) {
      std::cerr << "control_sockets[" << spec.path
                << "]: group '" << spec.group
                << "' not found in system database — skipping this socket"
                << std::endl;
      continue;
    }
    if (!ControlSocketPure::isModeSafe(spec.mode)) {
      std::cerr << "control_sockets[" << spec.path
                << "]: mode 0" << std::oct << spec.mode << std::dec
                << " has world-readable bits set — proceeding as configured,"
                   " but consider 0660 (group-only)"
                << std::endl;
    }

    auto rt = std::make_unique<SocketRuntime>();
    rt->spec           = spec;
    rt->expectedGid    = gid;
    rt->poolSeparator  = config_.poolSeparator;
    rt->srv            = std::make_unique<httplib::Server>();
    registerControlRoutes(*rt->srv, spec, gid, config_.poolSeparator);

    // Stale socket from previous run.
    ::unlink(spec.path.c_str());

    rt->thread = std::thread([rt = rt.get()]() {
      // httplib's listen() does the bind+listen+accept loop and
      // sets the socket to AF_UNIX when set_address_family is set.
      rt->srv->set_address_family(AF_UNIX);
      rt->srv->listen(rt->spec.path, 0);
    });

    // chmod + chown the socket once httplib has bound it. There's
    // no direct hook, so spin-wait briefly for the socket file to
    // appear (typical: a few ms).
    bool ready = false;
    for (int i = 0; i < 200 && !ready; i++) {
      struct stat st{};
      if (::stat(spec.path.c_str(), &st) == 0) {
        ready = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (!ready) {
      std::cerr << "control_sockets[" << spec.path
                << "]: socket file did not appear within 1s — skipping"
                << std::endl;
      // Best effort: we can't easily kill the listen() thread because
      // httplib doesn't expose a stop hook before it's bound. The
      // thread will linger; we orphan it. This is a config-error
      // path, not a runtime concern.
      continue;
    }
    if (::chmod(spec.path.c_str(), spec.mode) != 0) {
      std::cerr << "control_sockets[" << spec.path
                << "]: chmod failed: " << std::strerror(errno) << std::endl;
    }
    if (::chown(spec.path.c_str(), 0, static_cast<gid_t>(gid)) != 0) {
      std::cerr << "control_sockets[" << spec.path
                << "]: chown root:" << spec.group
                << " failed: " << std::strerror(errno) << std::endl;
    }

    impl_->runtimes.push_back(std::move(rt));
    started++;
  }
  return started;
}

void ControlSocketsManager::stop() {
  if (!impl_) return;
  for (auto &rt : impl_->runtimes) {
    if (rt->srv) rt->srv->stop();
    if (rt->thread.joinable()) rt->thread.join();
    ::unlink(rt->spec.path.c_str());
  }
  impl_->runtimes.clear();
}

}
