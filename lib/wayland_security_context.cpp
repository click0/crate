// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wayland_security_context.h"
#include "wayland_wire_pure.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace WaylandSecurityContext {

namespace W = WaylandWirePure;

namespace {

// the client's object ids for this short conversation
constexpr uint32_t kRegistryId  = 2;
constexpr uint32_t kSync1Id     = 3;
constexpr uint32_t kManagerId   = 4;
constexpr uint32_t kContextId   = 5;
constexpr uint32_t kSync2Id     = 6;

// A compositor that does not answer must not hang `crate run`.
constexpr int kIoTimeoutSec = 3;
// Far more than a registry listing takes (a few KB).
constexpr size_t kMaxReply = 1024 * 1024;

std::string errnoText(const char *what) {
  return std::string(what) + ": " + ::strerror(errno);
}

bool fillAddr(const std::string &path, struct sockaddr_un &addr) {
  ::memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (path.empty() || path.size() >= sizeof(addr.sun_path)) return false;
  ::memcpy(addr.sun_path, path.data(), path.size());
  return true;
}

// The whole buffer; the fds ride on the first sendmsg(2).
bool sendAll(int sock, const std::string &data, const int *fds, size_t nfds) {
  size_t off = 0;
  bool fdsSent = (nfds == 0);
  while (off < data.size()) {
    struct iovec iov;
    iov.iov_base = const_cast<char*>(data.data() + off);
    iov.iov_len = data.size() - off;
    struct msghdr msg;
    ::memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    union {
      char buf[CMSG_SPACE(sizeof(int) * 2)];
      struct cmsghdr align;
    } ctl;
    if (!fdsSent) {
      if (nfds > 2) return false;
      ::memset(&ctl, 0, sizeof(ctl));
      msg.msg_control = ctl.buf;
      msg.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
      struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
      c->cmsg_level = SOL_SOCKET;
      c->cmsg_type = SCM_RIGHTS;
      c->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
      ::memcpy(CMSG_DATA(c), fds, sizeof(int) * nfds);
    }
    const ssize_t n = ::sendmsg(sock, &msg, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    fdsSent = true;
    off += (size_t)n;
  }
  return true;
}

// Read events until the wl_callback `syncId` is done. onEvent sees every
// other one. false with err set on a display error, a malformed stream,
// a timeout or a closed connection.
template<typename F>
bool readUntilSync(int sock, uint32_t syncId, F onEvent, std::string &err) {
  std::string buf;
  size_t off = 0;
  for (;;) {
    W::Event ev;
    for (;;) {
      const auto r = W::nextEvent(buf, off, ev);
      if (r == W::Next::NeedMore) break;
      if (r == W::Next::Malformed) { err = "malformed message from the compositor"; return false; }
      if (ev.objectId == W::kDisplayId && ev.opcode == W::kDisplayError) {
        uint32_t obj = 0, code = 0;
        std::string text;
        if (W::parseDisplayError(ev.payload, obj, code, text))
          err = "the compositor refused: " + text + " (object " + std::to_string(obj) +
                ", error " + std::to_string(code) + ")";
        else
          err = "the compositor reported a protocol error";
        return false;
      }
      if (ev.objectId == syncId && ev.opcode == W::kCallbackDone) return true;
      onEvent(ev);
    }
    if (buf.size() > kMaxReply) { err = "the compositor sent too much"; return false; }
    char chunk[4096];
    const ssize_t n = ::recv(sock, chunk, sizeof(chunk), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      err = (errno == EAGAIN || errno == EWOULDBLOCK)
            ? "the compositor did not answer in " + std::to_string(kIoTimeoutSec) + " s"
            : errnoText("recv");
      return false;
    }
    if (n == 0) { err = "the compositor closed the connection"; return false; }
    buf.append(chunk, (size_t)n);
  }
}

void closeFd(int &fd) {
  if (fd >= 0) ::close(fd);
  fd = -1;
}

// Connect and list the compositor's globals. Ok: `conn` is open and
// managerName is the security-context manager's registry name;
// otherwise conn is closed and err says why.
Status connectAndFindManager(const std::string &compositorSocket, int &conn,
                             uint32_t &managerName, std::string &err) {
  conn = -1;
  struct sockaddr_un addr;
  if (!fillAddr(compositorSocket, addr)) {
    err = "compositor socket path is empty or too long";
    return Status::Failed;
  }
  conn = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (conn < 0) {
    err = errnoText("socket");
    return Status::Failed;
  }
  struct timeval tv;
  tv.tv_sec = kIoTimeoutSec;
  tv.tv_usec = 0;
  ::setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  ::setsockopt(conn, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  if (::connect(conn, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    err = errnoText(("connect " + compositorSocket).c_str());
    closeFd(conn);
    return Status::Failed;
  }
  if (!sendAll(conn, W::displayGetRegistry(kRegistryId) + W::displaySync(kSync1Id), nullptr, 0)) {
    err = errnoText("send");
    closeFd(conn);
    return Status::Failed;
  }
  bool found = false;
  if (!readUntilSync(conn, kSync1Id, [&](const W::Event &ev) {
        if (ev.objectId != kRegistryId || ev.opcode != W::kRegistryGlobal) return;
        uint32_t gname = 0, gversion = 0;
        std::string iface;
        if (W::parseRegistryGlobal(ev.payload, gname, iface, gversion) &&
            iface == W::kSecurityContextManager && gversion >= W::kSecurityContextVersion) {
          found = true;
          managerName = gname;
        }
      }, err)) {
    closeFd(conn);
    return Status::Failed;
  }
  if (!found) {
    err = std::string("the compositor does not offer ") + W::kSecurityContextManager;
    closeFd(conn);
    return Status::Unsupported;
  }
  return Status::Ok;
}

}

Status probe(const std::string &compositorSocket, std::string &err) {
  int conn = -1;
  uint32_t managerName = 0;
  const Status st = connectAndFindManager(compositorSocket, conn, managerName, err);
  closeFd(conn);
  return st;
}

Listener create(const std::string &compositorSocket, const std::string &dirTemplate,
                const std::string &name, const std::string &appId,
                const std::string &instanceId) {
  Listener l;
  int conn = -1, listenFd = -1, pipeFds[2] = {-1, -1};
  auto fail = [&](Status st, const std::string &why) {
    closeFd(conn);
    closeFd(listenFd);
    closeFd(pipeFds[0]);
    closeFd(pipeFds[1]);
    if (!l.socketPath.empty()) ::unlink(l.socketPath.c_str());
    if (!l.dir.empty()) ::rmdir(l.dir.c_str());
    l = Listener();
    l.status = st;
    l.error = why;
    return l;
  };

  // --- ask the compositor what it offers ---
  uint32_t managerName = 0;
  std::string err;
  if (const Status st = connectAndFindManager(compositorSocket, conn, managerName, err);
      st != Status::Ok)
    return fail(st, err);

  // --- the socket the jail's clients will connect to ---
  l.dir = dirTemplate;
  if (::mkdtemp(&l.dir[0]) == nullptr) {
    const auto why = errnoText(("mkdtemp " + dirTemplate).c_str());
    l.dir.clear();
    return fail(Status::Failed, why);
  }
  l.socketPath = l.dir + "/" + name;
  struct sockaddr_un laddr;
  if (!fillAddr(l.socketPath, laddr)) {
    l.socketPath.clear();
    return fail(Status::Failed, "socket path too long for a Unix socket");
  }
  listenFd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listenFd < 0) {
    const auto why = errnoText("socket");
    l.socketPath.clear();
    return fail(Status::Failed, why);
  }
  if (::bind(listenFd, (struct sockaddr*)&laddr, sizeof(laddr)) != 0) {
    const auto why = errnoText(("bind " + l.socketPath).c_str());
    l.socketPath.clear();
    return fail(Status::Failed, why);
  }
  // Whoever the command runs as in the jail may connect: on the host the
  // 0700 directory above is what guards the socket.
  if (::chmod(l.socketPath.c_str(), 0666) != 0)
    return fail(Status::Failed, errnoText("chmod"));
  if (::listen(listenFd, 16) != 0)
    return fail(Status::Failed, errnoText("listen"));
  if (::pipe2(pipeFds, O_CLOEXEC) != 0)
    return fail(Status::Failed, errnoText("pipe2"));

  // --- register it ---
  std::string req = W::registryBind(kRegistryId, managerName, W::kSecurityContextManager,
                                    W::kSecurityContextVersion, kManagerId)
                  + W::managerCreateListener(kManagerId, kContextId)
                  + W::contextSetSandboxEngine(kContextId, W::kSandboxEngine);
  const auto app = W::sanitizeId(appId), inst = W::sanitizeId(instanceId);
  if (!app.empty())  req += W::contextSetAppId(kContextId, app);
  if (!inst.empty()) req += W::contextSetInstanceId(kContextId, inst);
  req += W::contextCommit(kContextId) + W::contextDestroy(kContextId) + W::displaySync(kSync2Id);
  // the compositor gets the listening socket and the pipe's read end: it
  // sees a hangup there once the write end (keepFd) is closed
  const int fds[2] = {listenFd, pipeFds[0]};
  if (!sendAll(conn, req, fds, 2))
    return fail(Status::Failed, errnoText("send"));
  if (!readUntilSync(conn, kSync2Id, [](const W::Event &) {}, err))
    return fail(Status::Failed, err);

  // The context outlives this connection; the compositor has its own
  // copies of the two fds.
  closeFd(conn);
  closeFd(listenFd);
  closeFd(pipeFds[0]);
  l.keepFd = pipeFds[1];
  l.status = Status::Ok;
  return l;
}

void destroy(Listener &l) {
  closeFd(l.keepFd);
  if (!l.socketPath.empty()) ::unlink(l.socketPath.c_str());
  if (!l.dir.empty()) ::rmdir(l.dir.c_str());
  l.socketPath.clear();
  l.dir.clear();
}

}
