// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// Runtime for the crated control-socket plane.
//
// 0.7.10 prototype used cpp-httplib for control sockets, which gave
// us routing and HTTP parsing for free but did NOT expose the
// per-connection fd to handlers — defeating the whole point of
// peer-cred verification. 0.7.11 replaces that with a hand-rolled
// accept loop:
//
//   thread per socket:
//     1. socket(AF_UNIX, SOCK_STREAM)
//     2. bind(spec.path), listen(...)
//     3. chmod + chown to spec.mode and spec.group
//     4. accept-loop:
//        a. accept(fd) — returns connection fd
//        b. getpeereid(connFd, &uid, &gid)  ← THIS is what 0.7.10 missed
//        c. read header bytes until \r\n\r\n (8KB cap)
//        d. ControlSocketPure::parseHttpHead -> {method, path, content-length}
//        e. read body up to content-length (64KB cap)
//        f. ControlSocketPure::parseRoute -> ParsedRoute
//        g. ControlSocketPure::authorize with REAL peer creds
//        h. dispatch + write response, close fd
//
// All policy lives in ControlSocketPure. This file is socket I/O only.
//
// Defence in depth (now complete):
//   1. Filesystem perms (kernel)        — outer gate, most attackers stop here
//   2. getpeereid(2) re-check (THIS)    — even if perms get loosened, peer.gid
//                                          must match the configured group
//   3. Pool ACL (pure)                  — request paths scoped to socket.pools
//   4. Role gate (pure)                 — viewer rejects PATCH
//

#include "control_socket.h"
#include "control_socket_pure.h"
#include "rate_limit.h"
#include "rate_limit_pure.h"
#include "sandbox.h"
#include "../lib/args.h"
#include "../lib/commands.h"
#include "../lib/jail_query.h"
#include "../lib/pool_pure.h"
#include "../lib/util.h"
#include "../lib/pathnames.h"

#include <grp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

// getpeereid(2) — declared in <unistd.h> on FreeBSD, but glibc on
// Linux only exposes it under _DEFAULT_SOURCE / _BSD_SOURCE. The
// extern declaration below is a no-op when the platform header
// already declared it (BSD signature is stable since 4.4BSD), and
// it lets the same source compile on a Linux dev box for syntax
// checks without pulling in feature-test macros.
extern "C" int getpeereid(int s, uid_t *euid, gid_t *egid);

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <thread>
#include <vector>

namespace Crated {

namespace {

constexpr std::size_t kMaxHeader = 8 * 1024;
constexpr std::size_t kMaxBody   = 64 * 1024;
constexpr int         kAcceptTimeoutSec = 1;  // for graceful shutdown

// Resolve a unix group name to gid. Returns -1 if not found.
long resolveGroup(const std::string &name) {
  errno = 0;
  struct group *gr = ::getgrnam(name.c_str());
  if (!gr) return -1;
  return static_cast<long>(gr->gr_gid);
}

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

// Read until needle is found, or capacity exceeded, or EOF. Returns the
// buffer including the needle. Sets `bad` if cap exceeded or peer closed
// before needle.
std::string readUntilNeedle(int fd, const std::string &needle,
                            std::size_t cap, bool &bad) {
  std::string buf;
  bad = false;
  buf.reserve(1024);
  char tmp[1024];
  while (true) {
    if (auto pos = buf.find(needle); pos != std::string::npos)
      return buf;
    if (buf.size() >= cap) { bad = true; return buf; }
    ssize_t n = ::read(fd, tmp, sizeof(tmp));
    if (n <= 0) { bad = true; return buf; }
    buf.append(tmp, (std::size_t)n);
  }
}

// Read exactly `want` bytes (or until EOF). Sets `bad` on EOF before
// reaching `want` or on read error.
std::string readExact(int fd, std::size_t want, bool &bad) {
  std::string buf;
  bad = false;
  buf.reserve(want);
  char tmp[1024];
  while (buf.size() < want) {
    auto remaining = want - buf.size();
    auto chunk = remaining > sizeof(tmp) ? sizeof(tmp) : remaining;
    ssize_t n = ::read(fd, tmp, chunk);
    if (n <= 0) { bad = true; return buf; }
    buf.append(tmp, (std::size_t)n);
  }
  return buf;
}

void writeAll(int fd, const std::string &data) {
  std::size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n <= 0) return;  // peer gone — best effort
    off += (std::size_t)n;
  }
}

// Per-jail handlers. These are the same as 0.7.10 but the pre-route
// authorize() check now runs with REAL peer creds.

void handleList(std::string &resBody, int &status,
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
  status  = 200;
  resBody = ControlSocketPure::renderContainersJson(out);
}

void handleGet(std::string &resBody, int &status, const std::string &name) {
  auto j = JailQuery::getJailByName(name);
  if (!j) {
    status  = 404;
    resBody = ControlSocketPure::renderErrorJson("container not found");
    return;
  }
  std::ostringstream o;
  o << "{\"name\":\""    << j->name     << "\","
    << "\"jid\":"        << j->jid      << ","
    << "\"path\":\""     << j->path     << "\","
    << "\"hostname\":\"" << j->hostname << "\","
    << "\"ip4\":\""      << j->ip4      << "\","
    << "\"dying\":"      << (j->dying ? "true" : "false") << "}";
  status  = 200;
  resBody = o.str();
}

void handleStats(std::string &resBody, int &status, const std::string &name) {
  auto j = JailQuery::getJailByName(name);
  if (!j) {
    status  = 404;
    resBody = ControlSocketPure::renderErrorJson("container not found");
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
  } catch (...) {}
  std::ostringstream o;
  o << "{\"jid\":" << j->jid << ",\"usage\":{";
  bool first = true;
  for (const auto &[k, v] : usage) {
    if (!first) o << ",";
    o << "\"" << k << "\":\"" << v << "\"";
    first = false;
  }
  o << "}}";
  status  = 200;
  resBody = o.str();
}

// 0.8.13: lifecycle handlers — POST stop / restart. PostStart not
// implementable from this plane (no .crate file path tracked once
// the jail is stopped — would need a separate "registry" of
// known specs that's out of scope here; documented in CHANGELOG).
void handleStop(std::string &resBody, int &status, const std::string &name) {
  auto j = JailQuery::getJailByName(name);
  if (!j) {
    status  = 404;
    resBody = ControlSocketPure::renderErrorJson("container not found");
    return;
  }
  Args args;
  args.cmd = CmdStop;
  args.stopTarget = name;
  try {
    if (stopCrate(args)) {
      status  = 200;
      resBody = R"({"status":"stopped","container":")" + name + "\"}";
    } else {
      status  = 500;
      resBody = ControlSocketPure::renderErrorJson("stop returned failure");
    }
  } catch (const std::exception &e) {
    status  = 500;
    resBody = ControlSocketPure::renderErrorJson(
      std::string("stop failed: ") + e.what());
  }
}

void handleRestart(std::string &resBody, int &status, const std::string &name) {
  auto j = JailQuery::getJailByName(name);
  if (!j) {
    status  = 404;
    resBody = ControlSocketPure::renderErrorJson("container not found");
    return;
  }
  Args args;
  args.cmd = CmdRestart;
  args.restartTarget = name;
  try {
    if (restartCrate(args)) {
      status  = 200;
      resBody = R"({"status":"restarted","container":")" + name + "\"}";
    } else {
      status  = 500;
      resBody = ControlSocketPure::renderErrorJson("restart returned failure");
    }
  } catch (const std::exception &e) {
    status  = 500;
    resBody = ControlSocketPure::renderErrorJson(
      std::string("restart failed: ") + e.what());
  }
}

void handlePatch(std::string &resBody, int &status,
                 const std::string &name, const std::string &body) {
  auto j = JailQuery::getJailByName(name);
  if (!j) {
    status  = 404;
    resBody = ControlSocketPure::renderErrorJson("container not found");
    return;
  }
  ControlSocketPure::ResourcesPatch patch;
  if (auto e = ControlSocketPure::parseResourcesPatch(body, patch); !e.empty()) {
    status  = 400;
    resBody = ControlSocketPure::renderErrorJson(e);
    return;
  }
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
    status  = 500;
    resBody = ControlSocketPure::renderErrorJson(
      std::string("rctl(8) failed: ") + e.what());
    return;
  }
  status  = 200;
  resBody = ControlSocketPure::renderPatchOkJson(patch);
}

void handleConnection(int connFd,
                      const ControlSocketPure::ControlSocketSpec &spec,
                      long expectedGid,
                      char poolSeparator) {
  // Layer 2: getpeereid on the connection fd. This is the whole reason
  // we abandoned cpp-httplib for control sockets.
  long peerUid = -1, peerGid = -1;
  {
    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;
    if (::getpeereid(connFd, &uid, &gid) == 0) {
      peerUid = (long)uid;
      peerGid = (long)gid;
    }
  }

  // Capsicum (0.7.14): once we've extracted peer creds, the only ops
  // this fd needs are recv/send/shutdown. Limit it before any HTTP
  // parsing runs, so a parser-side bug can't repurpose the fd into
  // anything else.
  Sandbox::applyConnectionRights(connFd);

  bool bad = false;
  auto headBlob = readUntilNeedle(connFd, "\r\n\r\n", kMaxHeader, bad);
  if (bad) {
    auto r = ControlSocketPure::buildHttpResponse(
      400, ControlSocketPure::renderErrorJson("malformed or oversized request head"));
    writeAll(connFd, r);
    ::close(connFd);
    return;
  }

  // Trim everything after the first \r\n\r\n so parseHttpHead sees just
  // the head; the body (if any) is in the remaining bytes already read,
  // plus whatever's still on the wire.
  auto endOfHead = headBlob.find("\r\n\r\n") + 4;
  std::string head = headBlob.substr(0, endOfHead);
  std::string carriedBody = headBlob.substr(endOfHead);

  auto parsed = ControlSocketPure::parseHttpHead(head);
  if (parsed.bad) {
    auto r = ControlSocketPure::buildHttpResponse(
      400, ControlSocketPure::renderErrorJson("HTTP parse: " + parsed.error));
    writeAll(connFd, r);
    ::close(connFd);
    return;
  }

  // Read body.
  std::string body = carriedBody;
  if (parsed.contentLength > body.size()) {
    auto more = readExact(connFd,
                          parsed.contentLength - body.size(), bad);
    if (bad) {
      auto r = ControlSocketPure::buildHttpResponse(
        400, ControlSocketPure::renderErrorJson("body shorter than Content-Length"));
      writeAll(connFd, r);
      ::close(connFd);
      return;
    }
    body += more;
  } else if (body.size() > parsed.contentLength) {
    body.resize(parsed.contentLength);
  }

  auto route = ControlSocketPure::parseRoute(parsed.method, parsed.path);

  ControlSocketPure::AuthorizeInput in;
  in.peerUid           = peerUid;
  in.peerGid           = peerGid;
  in.socketExpectedGid = expectedGid;
  in.socketRole        = spec.role;
  in.socketPools       = spec.pools;
  in.action            = route.action;
  in.container         = route.container;
  in.poolSeparator     = poolSeparator;

  auto d = ControlSocketPure::authorize(in);
  if (d == ControlSocketPure::Decision::Allow) {
    // Rate-limit (0.7.15): per-uid + per-action bucket. PATCH gets
    // the tighter `kMutating` cap; reads use `kRead`. Key includes
    // the unix-group gid so multiple users in the same operator
    // group share a bucket — that's intentional: a runaway tray
    // app deserves the same throttle as a runaway script run by
    // the operator beside them.
    auto cap = ControlSocketPure::actionIsMutating(route.action)
                 ? RateLimit::kMutating : RateLimit::kRead;
    std::string key = "uid:" + std::to_string(peerUid)
                    + "|gid:" + std::to_string(peerGid)
                    + "|"     + ControlSocketPure::actionLabel(route.action);
    if (!RateLimit::check(key, cap)) {
      auto r = ControlSocketPure::buildHttpResponse(
        429,
        ControlSocketPure::renderErrorJson(
          "rate limit exceeded; retry in "
          + std::to_string(RateLimitPure::retryAfterSeconds())
          + "s"));
      writeAll(connFd, r);
      ::close(connFd);
      return;
    }
  }
  if (d != ControlSocketPure::Decision::Allow) {
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
    auto r = ControlSocketPure::buildHttpResponse(
      ControlSocketPure::httpStatusFor(d),
      ControlSocketPure::renderErrorJson(msg));
    writeAll(connFd, r);
    ::close(connFd);
    return;
  }

  // Dispatch.
  std::string resBody;
  int         status = 500;
  switch (route.action) {
  case ControlSocketPure::Action::ListContainers:
    handleList(resBody, status, spec, poolSeparator);
    break;
  case ControlSocketPure::Action::GetContainer:
    handleGet(resBody, status, route.container);
    break;
  case ControlSocketPure::Action::GetContainerStats:
    handleStats(resBody, status, route.container);
    break;
  case ControlSocketPure::Action::PatchResources:
    handlePatch(resBody, status, route.container, body);
    break;
  case ControlSocketPure::Action::PostStop:
    handleStop(resBody, status, route.container);
    break;
  case ControlSocketPure::Action::PostRestart:
    handleRestart(resBody, status, route.container);
    break;
  case ControlSocketPure::Action::PostStart:
    // 0.8.13: not implemented in this release — starting a stopped
    // jail requires the .crate file path which crated doesn't track.
    // A future "spec registry" hook would close this; for now reply 501.
    status  = 501;
    resBody = ControlSocketPure::renderErrorJson(
      "POST /start not implemented on control sockets — "
      "use bearer-token main API or `crate run -f <file.crate>`");
    break;
  case ControlSocketPure::Action::Unknown:
    // unreachable: filtered by authorize() above
    break;
  }
  writeAll(connFd,
           ControlSocketPure::buildHttpResponse(status, resBody));
  ::close(connFd);
}

struct SocketRuntime {
  ControlSocketPure::ControlSocketSpec spec;
  long expectedGid = -1;
  char poolSeparator = '-';
  int  listenFd = -1;
  std::atomic<bool> stopFlag{false};
  std::thread thread;
};

// Bind + listen on the unix socket, set mode + group, return fd.
// Throws on hard failures; warning-class issues (mode > 0660) are
// printed but the bind continues.
int bindSocketOrThrow(const ControlSocketPure::ControlSocketSpec &spec,
                      long expectedGid) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    throw std::runtime_error(std::string("socket(AF_UNIX): ") + std::strerror(errno));

  ::unlink(spec.path.c_str());

  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (spec.path.size() >= sizeof(addr.sun_path)) {
    ::close(fd);
    throw std::runtime_error("socket path too long for sockaddr_un");
  }
  std::strncpy(addr.sun_path, spec.path.c_str(), sizeof(addr.sun_path) - 1);

  if (::bind(fd, (struct sockaddr *)&addr,
             (socklen_t)(sizeof(addr.sun_family) + spec.path.size())) < 0) {
    int e = errno;
    ::close(fd);
    throw std::runtime_error("bind " + spec.path + ": " + std::strerror(e));
  }
  if (::chmod(spec.path.c_str(), spec.mode) != 0) {
    std::cerr << "control_sockets[" << spec.path
              << "]: chmod failed: " << std::strerror(errno) << std::endl;
  }
  if (::chown(spec.path.c_str(), 0, (gid_t)expectedGid) != 0) {
    std::cerr << "control_sockets[" << spec.path
              << "]: chown root:" << spec.group
              << " failed: " << std::strerror(errno) << std::endl;
  }
  if (::listen(fd, 16) < 0) {
    int e = errno;
    ::close(fd);
    throw std::runtime_error("listen " + spec.path + ": " + std::strerror(e));
  }
  // Capsicum (0.7.14): listener fd needs only accept(2). If a
  // memory-corruption bug snags this fd reference, an attacker can't
  // turn it into a sender — only an acceptor of new connections.
  // No-op on platforms without HAVE_CAPSICUM.
  Sandbox::applyListenerRights(fd);
  return fd;
}

void acceptLoop(SocketRuntime *rt) {
  // Set a recv timeout on the listen fd so accept() returns periodically
  // and we can check the stopFlag for graceful shutdown.
  struct timeval tv{};
  tv.tv_sec  = kAcceptTimeoutSec;
  tv.tv_usec = 0;
  ::setsockopt(rt->listenFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  while (!rt->stopFlag.load()) {
    int connFd = ::accept(rt->listenFd, nullptr, nullptr);
    if (connFd < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        continue;
      // Real error — break out so we don't spin.
      std::cerr << "control_sockets[" << rt->spec.path
                << "]: accept failed: " << std::strerror(errno) << std::endl;
      break;
    }
    // Per-connection thread; detached so we don't track lifecycle.
    std::thread(handleConnection, connFd, rt->spec,
                rt->expectedGid, rt->poolSeparator).detach();
  }
}

} // anon

struct ControlSocketsManager::Impl {
  std::vector<std::unique_ptr<SocketRuntime>> runtimes;
};

ControlSocketsManager::ControlSocketsManager(const Config &config)
  : config_(config), impl_(std::make_unique<Impl>()) {}

ControlSocketsManager::~ControlSocketsManager() { stop(); }

int ControlSocketsManager::start() {
  if (config_.controlSockets.empty()) return 0;

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
                   " but consider 0660 (group-only)" << std::endl;
    }
    auto rt = std::make_unique<SocketRuntime>();
    rt->spec          = spec;
    rt->expectedGid   = gid;
    rt->poolSeparator = config_.poolSeparator;

    try {
      rt->listenFd = bindSocketOrThrow(spec, gid);
    } catch (const std::exception &e) {
      std::cerr << "control_sockets[" << spec.path << "]: " << e.what()
                << " — skipping this socket" << std::endl;
      continue;
    }
    rt->thread = std::thread(acceptLoop, rt.get());
    impl_->runtimes.push_back(std::move(rt));
    started++;
  }
  return started;
}

void ControlSocketsManager::stop() {
  if (!impl_) return;
  for (auto &rt : impl_->runtimes) {
    rt->stopFlag.store(true);
    if (rt->listenFd >= 0) ::close(rt->listenFd);
    if (rt->thread.joinable()) rt->thread.join();
    ::unlink(rt->spec.path.c_str());
  }
  impl_->runtimes.clear();
}

}
