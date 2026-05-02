// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ws_console.h"
#include "ws_pure.h"
#include "auth_pure.h"

#include "jail_query.h"
#include "pathnames.h"
#include "util.h"

#include <openssl/sha.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <atomic>
#include <iomanip>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace Crated {

std::atomic<bool> WsConsole::g_running{false};
std::thread WsConsole::g_thread;
int WsConsole::g_listenFd = -1;

namespace {

std::string sha256hex(const std::string &input) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
  std::ostringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
  return "sha256:" + ss.str();
}

// Read until "\r\n\r\n" or until `cap` bytes are buffered. Returns the
// header block (incl. the terminator) or "" if the client disconnected
// or the cap was exceeded.
std::string readHttpHeaders(int fd, size_t cap = 8192) {
  std::string buf;
  buf.reserve(512);
  char ch;
  while (buf.size() < cap) {
    ssize_t n = ::recv(fd, &ch, 1, 0);
    if (n <= 0) return "";
    buf += ch;
    if (buf.size() >= 4 && buf.compare(buf.size() - 4, 4, "\r\n\r\n") == 0)
      return buf;
  }
  return "";
}

void writeAll(int fd, const std::string &data) {
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n <= 0) return;
    off += (size_t)n;
  }
}

// Extract `Authorization: Bearer <token>` from raw HTTP header bytes.
// Case-insensitive header name match; the value is the rest of the
// line trimmed.
std::string extractAuthHeader(const std::string &raw) {
  std::regex re(R"((?:^|\r\n)[Aa][Uu][Tt][Hh][Oo][Rr][Ii][Zz][Aa][Tt][Ii][Oo][Nn]\s*:\s*([^\r\n]*))");
  std::smatch m;
  if (std::regex_search(raw, m, re))
    return m[1].str();
  return "";
}

// Pull the jail-name segment out of a URL like
// `/api/v1/containers/<NAME>/console`. Returns "" on mismatch.
std::string extractJailName(const std::string &path) {
  std::regex re(R"(^/api/v1/containers/([A-Za-z0-9._-]+)/console/?$)");
  std::smatch m;
  if (std::regex_match(path, m, re))
    return m[1].str();
  return "";
}

// Run an interactive shell inside the jail and proxy bytes between
// the WebSocket and the child PTY. Per-connection thread, blocks
// until either side EOFs.
void runJailSession(int wsFd, int jid) {
  // Open a PTY pair; the child becomes session leader of the slave
  // and joins the jail before exec'ing /bin/sh -i.
  int master = ::posix_openpt(O_RDWR | O_NOCTTY);
  if (master < 0) {
    writeAll(wsFd, WsPure::encodeCloseFrame(1011, "openpt failed"));
    return;
  }
  if (::grantpt(master) != 0 || ::unlockpt(master) != 0) {
    ::close(master);
    writeAll(wsFd, WsPure::encodeCloseFrame(1011, "grantpt/unlockpt failed"));
    return;
  }
  const char *slaveName = ::ptsname(master);
  if (!slaveName) {
    ::close(master);
    writeAll(wsFd, WsPure::encodeCloseFrame(1011, "ptsname failed"));
    return;
  }
  std::string slaveNameCopy(slaveName);

  pid_t pid = ::fork();
  if (pid < 0) {
    ::close(master);
    writeAll(wsFd, WsPure::encodeCloseFrame(1011, "fork failed"));
    return;
  }
  if (pid == 0) {
    // Child: become a session leader, attach to the slave PTY, then
    // jail_attach + exec /bin/sh.
    ::close(master);
    ::setsid();
    int slave = ::open(slaveNameCopy.c_str(), O_RDWR);
    if (slave < 0) ::_exit(127);
    ::dup2(slave, 0);
    ::dup2(slave, 1);
    ::dup2(slave, 2);
    if (slave > 2) ::close(slave);

    // Use jexec(8) — same path as crate console — so we don't need
    // to link the daemon against libjail's jail_attach() here.
    ::execl(CRATE_PATH_JEXEC, "jexec", std::to_string(jid).c_str(),
            "/bin/sh", "-i", (char*)nullptr);
    ::_exit(127);
  }

  // Parent: pump bytes between wsFd and master.
  std::string wsBuf;
  std::string fromShell(4096, '\0');
  bool closed = false;
  while (!closed) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(wsFd, &rfds);
    FD_SET(master, &rfds);
    int maxFd = wsFd > master ? wsFd : master;
    timeval tv{1, 0};
    int sel = ::select(maxFd + 1, &rfds, nullptr, nullptr, &tv);
    if (sel < 0) { if (errno == EINTR) continue; break; }

    // 1) WS -> PTY: read frames from the socket, decode, forward
    //    payload bytes to the master fd.
    if (FD_ISSET(wsFd, &rfds)) {
      char rb[2048];
      ssize_t n = ::recv(wsFd, rb, sizeof(rb), 0);
      if (n <= 0) { closed = true; break; }
      wsBuf.append(rb, (size_t)n);
      while (!wsBuf.empty()) {
        WsPure::Frame f;
        int consumed = WsPure::parseFrame(wsBuf, f);
        if (consumed == 0) break;             // need more bytes
        if (consumed < 0) { closed = true; break; }
        wsBuf.erase(0, (size_t)consumed);
        switch (f.opcode) {
          case WsPure::Opcode::Close:
            closed = true;
            break;
          case WsPure::Opcode::Ping:
            writeAll(wsFd, WsPure::encodeFrame(WsPure::Opcode::Pong, f.payload));
            break;
          case WsPure::Opcode::Pong:
            // ignore
            break;
          case WsPure::Opcode::Text:
          case WsPure::Opcode::Binary:
          case WsPure::Opcode::Continuation:
            ::write(master, f.payload.data(), f.payload.size());
            break;
        }
      }
    }

    // 2) PTY -> WS: read whatever the shell printed and ship it as a
    //    binary frame (binary so byte-faithful for raw TTY output).
    if (FD_ISSET(master, &rfds)) {
      ssize_t n = ::read(master, &fromShell[0], fromShell.size());
      if (n <= 0) { closed = true; break; }
      writeAll(wsFd, WsPure::encodeFrame(WsPure::Opcode::Binary,
                                         fromShell.substr(0, (size_t)n)));
    }
  }

  // Best-effort: terminate the shell, reap the zombie.
  ::kill(pid, SIGTERM);
  ::waitpid(pid, nullptr, WNOHANG);
  ::close(master);
}

// One client connection: handshake + auth + session.
void handleClient(int fd, Config config) {
  auto raw = readHttpHeaders(fd);
  if (raw.empty()) { ::close(fd); return; }
  auto hs = WsPure::parseHandshakeRequest(raw);
  if (!hs.ok) {
    writeAll(fd, WsPure::buildHandshakeRejection(hs.failureReason));
    ::close(fd);
    return;
  }

  // Bearer-token auth (admin role required).
  auto authHeader = extractAuthHeader(raw);
  if (!AuthPure::checkBearerAuth(authHeader, config.tokens, "admin", sha256hex)) {
    writeAll(fd, WsPure::buildHandshakeRejection("authentication required"));
    ::close(fd);
    return;
  }

  auto jailName = extractJailName(hs.path);
  if (jailName.empty()) {
    writeAll(fd, WsPure::buildHandshakeRejection("expected /api/v1/containers/<name>/console"));
    ::close(fd);
    return;
  }
  auto jail = JailQuery::getJailByName(jailName);
  if (!jail) {
    writeAll(fd, WsPure::buildHandshakeRejection("container not found"));
    ::close(fd);
    return;
  }

  // Accept the upgrade and hand off to the session pump.
  writeAll(fd, WsPure::buildHandshakeResponse(WsPure::computeAcceptKey(hs.clientKey)));
  runJailSession(fd, jail->jid);
  ::close(fd);
}

void acceptLoop(Config config, int listenFd) {
  // Reaping disconnected clients is per-thread; just detach.
  while (WsConsole::g_running.load()) {
    // Use sockaddr_storage so the same loop accepts either v4 or v6.
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    int cfd = ::accept(listenFd, (sockaddr*)&addr, &len);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      break;
    }
    std::thread([cfd, config]() { handleClient(cfd, config); }).detach();
  }
  ::close(listenFd);
}

// Resolve `host` (which may be an IPv4 literal like "127.0.0.1", an
// IPv6 literal like "::1" or "::", or a hostname) and create a
// listening socket. Prefers IPv6 with IPV6_V6ONLY=0 so a single
// socket on "::" accepts both families. Falls back to IPv4 if
// getaddrinfo only returns AF_INET candidates.
int openListenSocket(const std::string &host, unsigned port) {
  addrinfo hints{};
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = AI_PASSIVE | AI_NUMERICSERV;
  addrinfo *res = nullptr;
  auto portStr = std::to_string(port);
  if (::getaddrinfo(host.empty() ? nullptr : host.c_str(),
                    portStr.c_str(), &hints, &res) != 0)
    return -1;

  // Prefer IPv6 candidates so we can dual-stack with one socket.
  addrinfo *ipv6 = nullptr, *ipv4 = nullptr;
  for (auto *p = res; p; p = p->ai_next) {
    if (p->ai_family == AF_INET6 && !ipv6) ipv6 = p;
    else if (p->ai_family == AF_INET && !ipv4) ipv4 = p;
  }
  addrinfo *pick = ipv6 ? ipv6 : ipv4;
  if (!pick) { ::freeaddrinfo(res); return -1; }

  int fd = ::socket(pick->ai_family, pick->ai_socktype, pick->ai_protocol);
  if (fd < 0) { ::freeaddrinfo(res); return -1; }
  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if (pick->ai_family == AF_INET6) {
    int zero = 0; // accept v4-mapped addrs on the same socket
    ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
  }
  if (::bind(fd, pick->ai_addr, pick->ai_addrlen) != 0) {
    ::close(fd); ::freeaddrinfo(res); return -1;
  }
  ::freeaddrinfo(res);
  if (::listen(fd, 16) != 0) { ::close(fd); return -1; }
  return fd;
}

} // anon

bool WsConsole::start(const Config &config) {
  if (config.consoleWsPort == 0) return false;
  int fd = openListenSocket(config.consoleWsBind, config.consoleWsPort);
  if (fd < 0) return false;

  ::signal(SIGCHLD, SIG_IGN); // auto-reap session children
  g_listenFd = fd;
  g_running.store(true);
  g_thread = std::thread(acceptLoop, config, fd);
  return true;
}

void WsConsole::stop() {
  if (!g_running.exchange(false)) return;
  if (g_listenFd >= 0) {
    ::shutdown(g_listenFd, SHUT_RDWR);
    g_listenFd = -1;
  }
  if (g_thread.joinable()) g_thread.join();
}

} // namespace Crated
