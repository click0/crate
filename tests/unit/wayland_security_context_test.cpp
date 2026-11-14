// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// 1.1.78: the Wayland security-context client. Two layers:
//  - WaylandWirePure: the message encoding, byte for byte;
//  - WaylandSecurityContext::create against a stand-in compositor that
//    runs in a thread of this test and speaks just enough of the
//    protocol — the registry, the security-context manager, the two
//    file descriptors — written here from the protocol text, not with
//    the code under test.

#include "wayland_security_context.h"
#include "wayland_wire_pure.h"

#include <atf-c++.hpp>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

namespace W = WaylandWirePure;
using WaylandSecurityContext::Status;

namespace {

// --- the test's own encoders (host byte order, like the protocol) ---

std::string u32(uint32_t v) {
  return std::string(reinterpret_cast<const char*>(&v), 4);
}

std::string wstr(const std::string &s) {
  std::string out = u32((uint32_t)s.size() + 1) + s;
  out.push_back('\0');
  while (out.size() % 4) out.push_back('\0');
  return out;
}

std::string msg(uint32_t obj, uint16_t opcode, const std::string &args) {
  return u32(obj) + u32(((uint32_t)(8 + args.size()) << 16) | opcode) + args;
}

uint32_t rd32(const std::string &s, size_t off) {
  uint32_t v;
  std::memcpy(&v, s.data() + off, 4);
  return v;
}

// a string argument at the front of a payload
std::string rdstr(const std::string &p, size_t off = 0) {
  const uint32_t len = rd32(p, off);
  return p.substr(off + 4, len - 1);
}

// --- the stand-in compositor ---

struct Compositor {
  // how it behaves
  bool offerManager = true;
  bool refuseCommit = false;
  bool hangUpEarly = false;

  // what it saw
  std::string boundInterface;
  uint32_t boundVersion = 0;
  std::string engine, appId, instanceId;
  bool committed = false;
  int listenFd = -1, closeFd = -1;
  unsigned fdCount = 0;

  std::string path;
  int srv = -1;
  std::thread thr;

  void start(const std::string &sockPath) {
    path = sockPath;
    ::unlink(path.c_str());
    srv = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ATF_REQUIRE(srv >= 0);
    struct sockaddr_un a;
    std::memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    std::strncpy(a.sun_path, path.c_str(), sizeof(a.sun_path) - 1);
    ATF_REQUIRE(::bind(srv, (struct sockaddr*)&a, sizeof(a)) == 0);
    ATF_REQUIRE(::listen(srv, 4) == 0);
    thr = std::thread([this]() { serve(); });
  }

  void join() {
    if (thr.joinable()) thr.join();
    if (srv >= 0) ::close(srv);
    srv = -1;
    ::unlink(path.c_str());
  }

  ~Compositor() {
    join();
    if (listenFd >= 0) ::close(listenFd);
    if (closeFd >= 0) ::close(closeFd);
  }

  void serve() {
    const int c = ::accept(srv, nullptr, nullptr);
    if (c < 0) return;
    if (hangUpEarly) { ::close(c); return; }
    const uint32_t kManagerName = 7;
    uint32_t registryId = 0, managerId = 0, contextId = 0;
    unsigned syncs = 0;
    std::string buf;
    size_t off = 0;
    bool done = false;
    while (!done) {
      char chunk[4096];
      struct iovec iov = {chunk, sizeof(chunk)};
      union { char b[CMSG_SPACE(sizeof(int) * 4)]; struct cmsghdr align; } ctl;
      struct msghdr m;
      std::memset(&m, 0, sizeof(m));
      m.msg_iov = &iov;
      m.msg_iovlen = 1;
      m.msg_control = ctl.b;
      m.msg_controllen = sizeof(ctl.b);
      const ssize_t n = ::recvmsg(c, &m, 0);
      if (n <= 0) break;
      for (struct cmsghdr *h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h)) {
        if (h->cmsg_level != SOL_SOCKET || h->cmsg_type != SCM_RIGHTS) continue;
        const size_t cnt = (h->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < cnt; i++) {
          int fd;
          std::memcpy(&fd, CMSG_DATA(h) + i * sizeof(int), sizeof(int));
          if (fdCount == 0) listenFd = fd;
          else if (fdCount == 1) closeFd = fd;
          else ::close(fd);
          fdCount++;
        }
      }
      buf.append(chunk, (size_t)n);
      W::Event ev;   // requests have the same framing as events
      while (W::nextEvent(buf, off, ev) == W::Next::Event) {
        std::string reply;
        if (ev.objectId == 1 && ev.opcode == 1) {            // get_registry
          registryId = rd32(ev.payload, 0);
        } else if (ev.objectId == 1 && ev.opcode == 0) {     // sync
          const uint32_t cb = rd32(ev.payload, 0);
          if (syncs == 0) {
            reply += msg(registryId, 0, u32(1) + wstr("wl_compositor") + u32(6));
            reply += msg(registryId, 0, u32(2) + wstr("xdg_wm_base") + u32(5));
            if (offerManager)
              reply += msg(registryId, 0, u32(kManagerName) + wstr("wp_security_context_manager_v1") + u32(1));
            reply += msg(registryId, 0, u32(9) + wstr("zwlr_screencopy_manager_v1") + u32(3));
          } else if (refuseCommit) {
            reply += msg(1, 0, u32(contextId) + u32(3) + wstr("invalid metadata"));   // wl_display.error
            ::send(c, reply.data(), reply.size(), MSG_NOSIGNAL);
            done = true;
            break;
          }
          reply += msg(1, 1, u32(cb));       // wl_display.delete_id, to be skipped
          reply += msg(cb, 0, u32(0));       // wl_callback.done
          if (++syncs == 2) done = true;
        } else if (registryId && ev.objectId == registryId && ev.opcode == 0) {   // bind
          if (rd32(ev.payload, 0) == kManagerName) {
            boundInterface = rdstr(ev.payload, 4);
            const size_t after = 4 + 4 + ((boundInterface.size() + 1 + 3) & ~(size_t)3);
            boundVersion = rd32(ev.payload, after);
            managerId = rd32(ev.payload, after + 4);
          }
        } else if (managerId && ev.objectId == managerId && ev.opcode == 1) {     // create_listener
          contextId = rd32(ev.payload, 0);
        } else if (contextId && ev.objectId == contextId) {
          if (ev.opcode == 1) engine = rdstr(ev.payload);
          else if (ev.opcode == 2) appId = rdstr(ev.payload);
          else if (ev.opcode == 3) instanceId = rdstr(ev.payload);
          else if (ev.opcode == 4) committed = true;
        }
        if (!reply.empty())
          ::send(c, reply.data(), reply.size(), MSG_NOSIGNAL);
      }
    }
    ::close(c);
  }
};

// is anything left of the crate-wl-* directories in the cwd
unsigned leftovers() {
  return (unsigned)::system("ls -d ctx-* >/dev/null 2>&1") == 0 ? 1u : 0u;
}

int connectTo(const std::string &path) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un a;
  std::memset(&a, 0, sizeof(a));
  a.sun_family = AF_UNIX;
  std::strncpy(a.sun_path, path.c_str(), sizeof(a.sun_path) - 1);
  if (::connect(fd, (struct sockaddr*)&a, sizeof(a)) != 0) { ::close(fd); return -1; }
  return fd;
}

}

// --- WaylandWirePure ---

ATF_TEST_CASE_WITHOUT_HEAD(wire_requests);
ATF_TEST_CASE_BODY(wire_requests) {
  // wl_display.get_registry(2): object 1, opcode 1, 12 bytes
  ATF_REQUIRE(W::displayGetRegistry(2) == u32(1) + u32((12u << 16) | 1) + u32(2));
  // wl_display.sync(3): opcode 0
  ATF_REQUIRE(W::displaySync(3) == u32(1) + u32((12u << 16) | 0) + u32(3));
  // wl_registry.bind: name, interface string, version, new id
  ATF_REQUIRE(W::registryBind(2, 7, "wp_security_context_manager_v1", 1, 4) ==
              msg(2, 0, u32(7) + wstr("wp_security_context_manager_v1") + u32(1) + u32(4)));
  // the manager: destroy is opcode 0, create_listener 1; fds are not in the bytes
  ATF_REQUIRE(W::managerCreateListener(4, 5) == msg(4, 1, u32(5)));
  // the context: destroy 0, set_sandbox_engine 1, set_app_id 2,
  // set_instance_id 3, commit 4
  ATF_REQUIRE(W::contextDestroy(5) == msg(5, 0, ""));
  ATF_REQUIRE(W::contextSetSandboxEngine(5, "io.github.click0.crate") == msg(5, 1, wstr("io.github.click0.crate")));
  ATF_REQUIRE(W::contextSetAppId(5, "firefox") == msg(5, 2, wstr("firefox")));
  ATF_REQUIRE(W::contextSetInstanceId(5, "jail-1") == msg(5, 3, wstr("jail-1")));
  ATF_REQUIRE(W::contextCommit(5) == msg(5, 4, ""));
  // string padding: length counts the NUL, the bytes are padded to a word
  for (const char *s : {"", "a", "ab", "abc", "abcd", "abcde"}) {
    const auto m = W::contextSetAppId(5, s);
    ATF_REQUIRE_EQ(m.size() % 4, 0u);
    ATF_REQUIRE_EQ(rd32(m, 4) >> 16, m.size());
    ATF_REQUIRE_EQ(rd32(m, 8), std::strlen(s) + 1);
  }
  // an over-long string is cut, the message stays within the 16-bit size
  const auto big = W::contextSetAppId(5, std::string(100000, 'x'));
  ATF_REQUIRE(big.size() <= W::kMaxMessage);
  ATF_REQUIRE_EQ(rd32(big, 8), W::kMaxString + 1);
  ATF_REQUIRE_EQ(std::string(W::kSecurityContextManager), "wp_security_context_manager_v1");
  ATF_REQUIRE_EQ(std::string(W::kSandboxEngine), "io.github.click0.crate");
}

ATF_TEST_CASE_WITHOUT_HEAD(wire_events);
ATF_TEST_CASE_BODY(wire_events) {
  const std::string g1 = msg(2, 0, u32(1) + wstr("wl_compositor") + u32(6));
  const std::string g2 = msg(2, 0, u32(7) + wstr("wp_security_context_manager_v1") + u32(1));
  const std::string done = msg(3, 0, u32(0));
  const std::string stream = g1 + g2 + done;

  // whole messages come off one by one
  size_t off = 0;
  W::Event ev;
  ATF_REQUIRE(W::nextEvent(stream, off, ev) == W::Next::Event);
  ATF_REQUIRE_EQ(ev.objectId, 2u);
  ATF_REQUIRE_EQ(ev.opcode, W::kRegistryGlobal);
  uint32_t name = 0, version = 0;
  std::string iface;
  ATF_REQUIRE(W::parseRegistryGlobal(ev.payload, name, iface, version));
  ATF_REQUIRE_EQ(name, 1u);
  ATF_REQUIRE_EQ(iface, "wl_compositor");
  ATF_REQUIRE_EQ(version, 6u);
  ATF_REQUIRE(W::nextEvent(stream, off, ev) == W::Next::Event);
  ATF_REQUIRE(W::parseRegistryGlobal(ev.payload, name, iface, version));
  ATF_REQUIRE_EQ(name, 7u);
  ATF_REQUIRE_EQ(iface, "wp_security_context_manager_v1");
  ATF_REQUIRE(W::nextEvent(stream, off, ev) == W::Next::Event);
  ATF_REQUIRE_EQ(ev.objectId, 3u);
  ATF_REQUIRE_EQ(ev.opcode, W::kCallbackDone);
  ATF_REQUIRE_EQ(off, stream.size());
  ATF_REQUIRE(W::nextEvent(stream, off, ev) == W::Next::NeedMore);

  // a message cut anywhere is "need more", never a partial event
  for (size_t cut = 0; cut < g1.size(); cut++) {
    size_t o = 0;
    ATF_REQUIRE(W::nextEvent(g1.substr(0, cut), o, ev) == W::Next::NeedMore);
    ATF_REQUIRE_EQ(o, 0u);
  }

  // sizes below the header or off the word grid are malformed
  size_t o = 0;
  ATF_REQUIRE(W::nextEvent(u32(2) + u32((4u << 16) | 0), o, ev) == W::Next::Malformed);
  o = 0;
  ATF_REQUIRE(W::nextEvent(u32(2) + u32((10u << 16) | 0) + u32(0), o, ev) == W::Next::Malformed);
  o = 0;
  ATF_REQUIRE(W::nextEvent(u32(2) + u32(0), o, ev) == W::Next::Malformed);

  // wl_display.error
  uint32_t obj = 0, code = 0;
  std::string text;
  ATF_REQUIRE(W::parseDisplayError(u32(5) + u32(3) + wstr("invalid metadata"), obj, code, text));
  ATF_REQUIRE_EQ(obj, 5u);
  ATF_REQUIRE_EQ(code, 3u);
  ATF_REQUIRE_EQ(text, "invalid metadata");

  // payloads that lie about their strings are refused, not read past
  ATF_REQUIRE(!W::parseRegistryGlobal("", name, iface, version));
  ATF_REQUIRE(!W::parseRegistryGlobal(u32(1), name, iface, version));
  ATF_REQUIRE(!W::parseRegistryGlobal(u32(1) + u32(1000) + "abc", name, iface, version));
  ATF_REQUIRE(!W::parseRegistryGlobal(u32(1) + u32(0xffffffffu) + "abcd", name, iface, version));
  ATF_REQUIRE(!W::parseRegistryGlobal(u32(1) + u32(4) + "abcd" + u32(1), name, iface, version));   // no NUL
  ATF_REQUIRE(!W::parseRegistryGlobal(u32(1) + wstr("wl_shm"), name, iface, version));              // no version
  ATF_REQUIRE(!W::parseDisplayError(u32(5), obj, code, text));
  ATF_REQUIRE(!W::parseDisplayError(u32(5) + u32(3) + u32(64) + "x", obj, code, text));
}

ATF_TEST_CASE_WITHOUT_HEAD(wire_sanitize_id);
ATF_TEST_CASE_BODY(wire_sanitize_id) {
  ATF_REQUIRE_EQ(W::sanitizeId("firefox"), "firefox");
  ATF_REQUIRE_EQ(W::sanitizeId("jail-web-1a2b_pid123"), "jail-web-1a2b_pid123");
  ATF_REQUIRE_EQ(W::sanitizeId("a b\tc\nd"), "a_b_c_d");
  ATF_REQUIRE_EQ(W::sanitizeId(std::string("a\0b", 3)), "a_b");
  ATF_REQUIRE_EQ(W::sanitizeId("\xd1\x97"), "__");
  ATF_REQUIRE_EQ(W::sanitizeId(""), "");
  ATF_REQUIRE_EQ(W::sanitizeId(std::string(1000, 'x')).size(), W::kMaxString);
}

// --- WaylandSecurityContext against the stand-in compositor ---

ATF_TEST_CASE_WITHOUT_HEAD(context_made);
ATF_TEST_CASE_BODY(context_made) {
  Compositor comp;
  comp.start("comp.sock");
  auto l = WaylandSecurityContext::create("comp.sock", "ctx-XXXXXXXX", "wayland-1",
                                          "fire fox", "jail-firefox-1a2b_pid42");
  comp.join();
  ATF_REQUIRE(l.status == Status::Ok);

  // what the compositor was told
  ATF_REQUIRE_EQ(comp.boundInterface, "wp_security_context_manager_v1");
  ATF_REQUIRE_EQ(comp.boundVersion, 1u);
  ATF_REQUIRE_EQ(comp.engine, "io.github.click0.crate");
  ATF_REQUIRE_EQ(comp.appId, "fire_fox");                      // sanitized
  ATF_REQUIRE_EQ(comp.instanceId, "jail-firefox-1a2b_pid42");
  ATF_REQUIRE(comp.committed);
  ATF_REQUIRE_EQ(comp.fdCount, 2u);

  // the socket: in a private 0700 directory, connectable by any uid
  struct stat st;
  ATF_REQUIRE(::stat(l.dir.c_str(), &st) == 0);
  ATF_REQUIRE_EQ(st.st_mode & 07777, 0700u);
  ATF_REQUIRE_EQ(l.socketPath, l.dir + "/wayland-1");
  ATF_REQUIRE(::lstat(l.socketPath.c_str(), &st) == 0);
  ATF_REQUIRE(S_ISSOCK(st.st_mode));
  ATF_REQUIRE_EQ(st.st_mode & 0777, 0666u);

  // the first fd the compositor got is that listening socket: a client
  // connecting to the path shows up on it
  const int client = connectTo(l.socketPath);
  ATF_REQUIRE(client >= 0);
  struct pollfd p = {comp.listenFd, POLLIN, 0};
  ATF_REQUIRE_EQ(::poll(&p, 1, 2000), 1);
  const int accepted = ::accept(comp.listenFd, nullptr, nullptr);
  ATF_REQUIRE(accepted >= 0);
  ::close(accepted);
  ::close(client);

  // the second is the read end of a pipe crate keeps the other end of:
  // quiet while crate lives ...
  ATF_REQUIRE(l.keepFd >= 0);
  ATF_REQUIRE((::fcntl(l.keepFd, F_GETFD) & FD_CLOEXEC) != 0);   // not for the jail's command
  struct pollfd h = {comp.closeFd, 0, 0};
  ATF_REQUIRE_EQ(::poll(&h, 1, 100), 0);
  // ... and hung up once it lets go
  WaylandSecurityContext::destroy(l);
  ATF_REQUIRE_EQ(::poll(&h, 1, 2000), 1);
  ATF_REQUIRE((h.revents & POLLHUP) != 0);
  ATF_REQUIRE_EQ(l.keepFd, -1);
  ATF_REQUIRE_EQ(leftovers(), 0u);
  WaylandSecurityContext::destroy(l);   // twice is harmless
}

ATF_TEST_CASE_WITHOUT_HEAD(context_ids_optional);
ATF_TEST_CASE_BODY(context_ids_optional) {
  Compositor comp;
  comp.start("comp.sock");
  auto l = WaylandSecurityContext::create("comp.sock", "ctx-XXXXXXXX", "wayland-0", "", "");
  comp.join();
  ATF_REQUIRE(l.status == Status::Ok);
  ATF_REQUIRE_EQ(comp.engine, "io.github.click0.crate");
  ATF_REQUIRE(comp.appId.empty());
  ATF_REQUIRE(comp.instanceId.empty());
  ATF_REQUIRE(comp.committed);
  WaylandSecurityContext::destroy(l);
  ATF_REQUIRE_EQ(leftovers(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(context_unsupported);
ATF_TEST_CASE_BODY(context_unsupported) {
  Compositor comp;
  comp.offerManager = false;
  comp.start("comp.sock");
  auto l = WaylandSecurityContext::create("comp.sock", "ctx-XXXXXXXX", "wayland-1", "app", "inst");
  ATF_REQUIRE(l.status == Status::Unsupported);
  ATF_REQUIRE(l.error.find("wp_security_context_manager_v1") != std::string::npos);
  ATF_REQUIRE_EQ(l.keepFd, -1);
  ATF_REQUIRE(l.socketPath.empty());
  ATF_REQUIRE_EQ(leftovers(), 0u);   // no directory was made
  comp.join();
  ATF_REQUIRE_EQ(comp.fdCount, 0u);

  // probe says the same without making anything
  Compositor c2;
  c2.offerManager = false;
  c2.start("comp2.sock");
  std::string err;
  ATF_REQUIRE(WaylandSecurityContext::probe("comp2.sock", err) == Status::Unsupported);
  c2.join();
  Compositor c3;
  c3.start("comp3.sock");
  ATF_REQUIRE(WaylandSecurityContext::probe("comp3.sock", err) == Status::Ok);
  c3.join();
  ATF_REQUIRE_EQ(leftovers(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(context_refused);
ATF_TEST_CASE_BODY(context_refused) {
  Compositor comp;
  comp.refuseCommit = true;
  comp.start("comp.sock");
  auto l = WaylandSecurityContext::create("comp.sock", "ctx-XXXXXXXX", "wayland-1", "app", "inst");
  comp.join();
  ATF_REQUIRE(l.status == Status::Failed);
  ATF_REQUIRE(l.error.find("invalid metadata") != std::string::npos);
  ATF_REQUIRE_EQ(l.keepFd, -1);
  ATF_REQUIRE_EQ(leftovers(), 0u);   // socket and directory removed again
}

ATF_TEST_CASE_WITHOUT_HEAD(context_no_compositor);
ATF_TEST_CASE_BODY(context_no_compositor) {
  // nothing at the path
  auto l = WaylandSecurityContext::create("nothing.sock", "ctx-XXXXXXXX", "wayland-1", "a", "b");
  ATF_REQUIRE(l.status == Status::Failed);
  ATF_REQUIRE(l.error.find("connect") != std::string::npos);
  // a path no sockaddr_un can hold
  l = WaylandSecurityContext::create(std::string(300, 'x'), "ctx-XXXXXXXX", "wayland-1", "a", "b");
  ATF_REQUIRE(l.status == Status::Failed);
  l = WaylandSecurityContext::create("", "ctx-XXXXXXXX", "wayland-1", "a", "b");
  ATF_REQUIRE(l.status == Status::Failed);
  // a compositor that hangs up at once
  Compositor comp;
  comp.hangUpEarly = true;
  comp.start("comp.sock");
  l = WaylandSecurityContext::create("comp.sock", "ctx-XXXXXXXX", "wayland-1", "a", "b");
  comp.join();
  ATF_REQUIRE(l.status == Status::Failed);
  // the private directory cannot be made
  Compositor c2;
  c2.start("comp2.sock");
  l = WaylandSecurityContext::create("comp2.sock", "no-such-dir/ctx-XXXXXXXX", "wayland-1", "a", "b");
  c2.join();
  ATF_REQUIRE(l.status == Status::Failed);
  ATF_REQUIRE(l.error.find("mkdtemp") != std::string::npos);
  ATF_REQUIRE_EQ(leftovers(), 0u);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, wire_requests);
  ATF_ADD_TEST_CASE(tcs, wire_events);
  ATF_ADD_TEST_CASE(tcs, wire_sanitize_id);
  ATF_ADD_TEST_CASE(tcs, context_made);
  ATF_ADD_TEST_CASE(tcs, context_ids_optional);
  ATF_ADD_TEST_CASE(tcs, context_unsupported);
  ATF_ADD_TEST_CASE(tcs, context_refused);
  ATF_ADD_TEST_CASE(tcs, context_no_compositor);
}
