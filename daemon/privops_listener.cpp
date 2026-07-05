// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privops_listener.h"

#include "privops_handlers.h"
#include "sandbox.h"

#include "../lib/privops_nv_pure.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifdef __FreeBSD__
#include <sys/nv.h>
extern "C" int getpeereid(int s, uid_t *euid, gid_t *egid);
#endif

#include <grp.h>

namespace Crated {

namespace {

constexpr int kAcceptTimeoutSec = 1;       // graceful-stop poll period

#ifdef __FreeBSD__

// Walk an nvlist into a flat string-keyed FieldMap. Mirrors what
// PrivOpsNvPure tests express directly. nvlist values become:
//   string -> as-is
//   number -> std::to_string
//   bool   -> "true"/"false"
// Other types (binary, nested nvlist, descriptors) are skipped —
// privops requests don't use them. A future verb that needs nested
// nvlist would extend this walker.
PrivOpsNvPure::FieldMap nvlistToMap(const nvlist_t *nvl) {
  PrivOpsNvPure::FieldMap out;
  if (nvl == nullptr) return out;
  void *cookie = nullptr;
  const char *name = nullptr;
  int type = 0;
  while ((name = nvlist_next(nvl, &type, &cookie)) != nullptr) {
    switch (type) {
      case NV_TYPE_STRING:
        out[name] = nvlist_get_string(nvl, name);
        break;
      case NV_TYPE_NUMBER:
        out[name] = std::to_string(nvlist_get_number(nvl, name));
        break;
      case NV_TYPE_BOOL:
        out[name] = nvlist_get_bool(nvl, name) ? "true" : "false";
        break;
      default:
        // Unknown type — skip silently (validators will catch the
        // missing field).
        break;
    }
  }
  return out;
}

void writeErrorResponse(int fd, int status, const std::string &body) {
  nvlist_t *resp = nvlist_create(0);
  if (!resp) return;
  nvlist_add_number(resp, "status", (uint64_t)status);
  nvlist_add_string(resp, "body", body.c_str());
  nvlist_send(fd, resp);
  nvlist_destroy(resp);
}

// Per-connection handler. Reads one nvlist request, dispatches,
// writes one nvlist response, closes.
void handleConnection(int connFd, bool rootlessPerUser) {
  // getpeereid (unix-socket peer credentials).
  uint32_t peerUid = 0;
  bool havePeerUid = false;
  int peerErrno = 0;
  {
    uid_t uid = (uid_t)-1;
    gid_t gid = (gid_t)-1;
    if (::getpeereid(connFd, &uid, &gid) == 0) {
      peerUid = (uint32_t)uid;
      havePeerUid = true;
    } else {
      peerErrno = errno;   // capture before applyConnectionRights clobbers it
    }
  }

  // Capsicum: limit fd to recv/send/shutdown. Same rationale as
  // control_socket plane (0.7.14).
  Sandbox::applyConnectionRights(connFd);

  // Fail closed on identity loss. When per-user enforcement is on, the
  // authorize-before-dispatch gate keys on peerUid; a getpeereid
  // failure (peer exited between accept and getpeereid, a kernel edge)
  // must NOT degrade to peerUid = 0, because the dispatcher treats
  // uid 0 as the admin/host-wide path and skips EVERY per-tenant gate.
  // Reject rather than silently authorize. (When per-user enforcement
  // is off there is nothing to gate — peerUid only fed the audit
  // trail — so a failure there is harmless and we proceed.)
  if (rootlessPerUser && !havePeerUid) {
    std::cerr << "privops_listener: getpeereid failed on a rootless "
                 "per-user connection — rejecting (fail closed): "
              << std::strerror(peerErrno) << std::endl;
    writeErrorResponse(connFd, 403,
        "{\"error\":\"forbidden: could not determine peer uid "
        "(getpeereid failed); refusing to run unauthenticated\"}");
    ::close(connFd);
    return;
  }

  nvlist_t *req = nvlist_recv(connFd, 0);
  if (!req) {
    writeErrorResponse(connFd, 400,
        "{\"error\":\"nvlist_recv failed (malformed request or closed)\"}");
    ::close(connFd);
    return;
  }

  PrivOpsNvPure::FieldMap m = nvlistToMap(req);
  nvlist_destroy(req);

  auto result = dispatchPrivOpFromMap(m, rootlessPerUser, peerUid);

  nvlist_t *resp = nvlist_create(0);
  nvlist_add_number(resp, "status", (uint64_t)result.status);
  nvlist_add_string(resp, "body", result.body.c_str());
  if (nvlist_send(connFd, resp) != 0) {
    std::cerr << "privops_listener: nvlist_send failed: "
              << std::strerror(errno) << std::endl;
  }
  nvlist_destroy(resp);
  ::close(connFd);
}

#endif // __FreeBSD__

struct Runtime {
  int listenFd = -1;
  std::atomic<bool> stopFlag{false};
  std::thread acceptThread;
  bool rootlessPerUser = false;
  std::string socketPath;
};

#ifdef __FreeBSD__
void acceptLoop(Runtime *rt) {
  struct timeval tv{};
  tv.tv_sec  = kAcceptTimeoutSec;
  tv.tv_usec = 0;
  ::setsockopt(rt->listenFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  while (!rt->stopFlag.load()) {
    int connFd = ::accept(rt->listenFd, nullptr, nullptr);
    if (connFd < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        continue;
      std::cerr << "privops_listener: accept failed: "
                << std::strerror(errno) << std::endl;
      break;
    }
    std::thread(handleConnection, connFd, rt->rootlessPerUser).detach();
  }
}
#endif

#ifdef __FreeBSD__
int openListener(const std::string &path, const std::string &group,
                 unsigned mode) {
  int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
  }
  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path))
    throw std::runtime_error("privops socket path too long: " + path);
  std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

  ::unlink(path.c_str());
  if (::bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    int e = errno;
    ::close(fd);
    throw std::runtime_error("bind " + path + ": " + std::strerror(e));
  }

  // chmod to mode (typically 0660).
  if (::chmod(path.c_str(), (mode_t)mode) != 0) {
    std::cerr << "privops_listener: chmod " << path
              << " failed: " << std::strerror(errno) << std::endl;
  }

  // chown root:<group> if group resolvable.
  if (!group.empty()) {
    struct group *gr = ::getgrnam(group.c_str());
    if (gr) {
      if (::chown(path.c_str(), 0, gr->gr_gid) != 0) {
        std::cerr << "privops_listener: chown root:" << group
                  << " failed: " << std::strerror(errno) << std::endl;
      }
    } else {
      std::cerr << "privops_listener: group '" << group
                << "' not found via getgrnam" << std::endl;
    }
  }

  if (::listen(fd, 16) < 0) {
    int e = errno;
    ::close(fd);
    throw std::runtime_error("listen " + path + ": " + std::strerror(e));
  }

  Sandbox::applyListenerRights(fd);
  return fd;
}
#endif // __FreeBSD__

} // anon

// --- PrivopsListener Impl ---

struct PrivopsListener::Impl {
  Runtime rt;
  bool started = false;
  std::string group;
  unsigned mode = 0660;
};

PrivopsListener::PrivopsListener(const Config &config)
  : impl_(new Impl{}) {
  impl_->rt.rootlessPerUser = config.rootlessPerUser;
  impl_->rt.socketPath      = config.privopsSocketPath;
  impl_->group              = config.privopsSocketGroup;
  impl_->mode               = config.privopsSocketMode;
}

PrivopsListener::~PrivopsListener() {
  stop();
  delete impl_;
}

bool PrivopsListener::start() {
#ifndef __FreeBSD__
  // libnv unavailable — listener is FreeBSD-only.
  std::cerr << "privops_listener: skipped (libnv requires FreeBSD)"
            << std::endl;
  return false;
#else
  if (impl_->started) return true;
  if (impl_->rt.socketPath.empty()) {
    // Operator opted out by leaving privops_socket: empty (default).
    return false;
  }
  try {
    impl_->rt.listenFd = openListener(impl_->rt.socketPath,
                                      impl_->group,
                                      impl_->mode);
  } catch (const std::exception &e) {
    std::cerr << "privops_listener: " << e.what() << std::endl;
    return false;
  }
  impl_->rt.acceptThread = std::thread(acceptLoop, &impl_->rt);
  impl_->started = true;
  return true;
#endif
}

void PrivopsListener::stop() {
  if (!impl_->started) return;
  impl_->rt.stopFlag.store(true);
  if (impl_->rt.listenFd >= 0) {
    ::shutdown(impl_->rt.listenFd, SHUT_RD);
  }
  if (impl_->rt.acceptThread.joinable())
    impl_->rt.acceptThread.join();
  if (impl_->rt.listenFd >= 0) {
    ::close(impl_->rt.listenFd);
    impl_->rt.listenFd = -1;
  }
  if (!impl_->rt.socketPath.empty())
    ::unlink(impl_->rt.socketPath.c_str());
  impl_->started = false;
}

} // namespace Crated
