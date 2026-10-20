// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// HTTP server implementation using cpp-httplib.
// Registers routes from routes.h and serves on configured endpoints.

#include "server.h"
#include "routes.h"
#include "socket_perms_pure.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>

namespace Crated {

struct Server::Impl {
  std::unique_ptr<httplib::Server> httpSrv;   // TCP (optionally TLS) listener
  // 1.1.26: the Unix-socket server is a member, not a lambda-local.
  // It used to live only inside unixThread's closure, so stop() could
  // never call its stop(), listen() never returned, and ~Impl destroyed
  // a still-joinable std::thread → std::terminate (SIGABRT) on every
  // clean shutdown with the default unixSocket configured.
  std::unique_ptr<httplib::Server> udsSrv;
  std::thread tcpThread;
  std::thread unixThread;
};

Server::Server(const Config &config)
  : config_(config), impl_(std::make_unique<Impl>())
{
  // Create HTTP server (TLS if certs provided)
  if (!config_.tlsCert.empty() && !config_.tlsKey.empty()) {
    impl_->httpSrv = std::make_unique<httplib::SSLServer>(
      config_.tlsCert.c_str(), config_.tlsKey.c_str(),
      config_.tlsCa.empty() ? nullptr : config_.tlsCa.c_str());
  } else {
    impl_->httpSrv = std::make_unique<httplib::Server>();
  }

  // Register all REST routes. This is the TCP listener (remote,
  // token-gated) — isUnixListener = false.
  registerRoutes(*impl_->httpSrv, config_, /*isUnixListener=*/false);
  applyListenerLimits(*impl_->httpSrv);
}

// 1.1.37: body cap, worker pool, CLOEXEC on the listening socket.
//   - set_payload_max_length: cpp-httplib buffers the body before our
//     handler (and auth gate) runs — unbounded by default.
//   - new_task_queue: stop/restart/export hold a worker for seconds to
//     minutes; the default pool is small enough that a few concurrent
//     calls starved /healthz.
//   - FD_CLOEXEC on the listener: crated forks `crate run` and other
//     children; they must not inherit the HTTP listening socket (the
//     hand-rolled listeners got SOCK_CLOEXEC in 1.1.26).
void Server::applyListenerLimits(httplib::Server &srv) {
  srv.set_payload_max_length((size_t)config_.maxBodyBytes);
  const unsigned workers = config_.httpWorkers;
  srv.new_task_queue = [workers] { return new httplib::ThreadPool(workers); };
  srv.set_socket_options([](socket_t sock) {
    int fl = ::fcntl(sock, F_GETFD);
    if (fl != -1) ::fcntl(sock, F_SETFD, fl | FD_CLOEXEC);
    int yes = 1;
    ::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  });
}

Server::~Server() {
  stop();
}

void Server::start() {
  auto &srv = *impl_->httpSrv;

  // TCP listener
  if (config_.tcpPort != 0) {
    impl_->tcpThread = std::thread([this, &srv]() {
      srv.listen(config_.tcpBind, config_.tcpPort);
    });
  }

  // Unix socket listener (separate httplib::Server instance on UDS)
  if (!config_.unixSocket.empty()) {
    // Remove stale socket
    ::unlink(config_.unixSocket.c_str());

    // This is the Unix-socket listener (local, root-owned socket) —
    // isUnixListener = true, so its peers are treated as trusted.
    // Built here (not inside the thread) so stop() can reach it.
    impl_->udsSrv = std::make_unique<httplib::Server>();
    registerRoutes(*impl_->udsSrv, config_, /*isUnixListener=*/true);
    applyListenerLimits(*impl_->udsSrv);
    impl_->udsSrv->set_address_family(AF_UNIX);

    // 1.1.55: bind→chmod race closed (docs/getpeereid-main-api-refactor.md
    // §3.1). 0.8.19 started the accept loop first and a detached thread
    // polled for the socket file to chmod/chown it; between httplib's
    // bind(2) and that chmod the file sat at the umask-default mode, and
    // with the default config (no owner/group, mode 0660) the fixup did
    // not run at all, so the documented root:wheel 0660 was never applied.
    //
    // Now: bind synchronously under umask 0077 — the socket file is born
    // 0700, nobody but root can connect() to it — then chown/chmod to the
    // configured owner/group/mode, and only then start the accept loop.
    // umask is process-wide, but this runs once at startup before any
    // worker thread exists that creates files.
    mode_t oldMask = ::umask(0077);
    bool bound = impl_->udsSrv->bind_to_port(config_.unixSocket, 0);
    ::umask(oldMask);
    if (!bound) {
      std::cerr << "crated: cannot bind unix socket " << config_.unixSocket
                << ": " << std::strerror(errno) << std::endl;
      impl_->udsSrv.reset();
      return;
    }
    applyUnixSocketPerms();
    impl_->unixThread = std::thread([this]() {
      impl_->udsSrv->listen_after_bind();
    });
  }
}

// 1.1.55: owner/group/mode of the main-API unix socket, applied between
// bind(2) and the accept loop (see start()). Failures are reported, not
// fatal: the socket is still 0700 root-only at this point, which is
// tighter than anything the config asks for.
void Server::applyUnixSocketPerms() {
  // Resolve owner -> uid (empty leaves uid alone via -1).
  uid_t uid = (uid_t)-1;
  if (!config_.unixSocketOwner.empty()) {
    struct passwd *pw = ::getpwnam(config_.unixSocketOwner.c_str());
    if (pw == nullptr) {
      std::cerr << "crated: listen.unix_owner '" << config_.unixSocketOwner
                << "' not found; socket stays root-only (0700)" << std::endl;
      return;
    }
    uid = pw->pw_uid;
  }
  // Resolve group -> gid (empty leaves gid alone via -1).
  gid_t gid = (gid_t)-1;
  if (!config_.unixSocketGroup.empty()) {
    struct group *gr = ::getgrnam(config_.unixSocketGroup.c_str());
    if (gr == nullptr) {
      std::cerr << "crated: listen.unix_group '" << config_.unixSocketGroup
                << "' not found; socket stays root-only (0700)" << std::endl;
      return;
    }
    gid = gr->gr_gid;
  }

  if ((uid != (uid_t)-1 || gid != (gid_t)-1)
      && ::chown(config_.unixSocket.c_str(), uid, gid) != 0) {
    std::cerr << "crated: chown " << config_.unixSocket
              << " failed: " << std::strerror(errno) << std::endl;
  }
  if (::chmod(config_.unixSocket.c_str(), config_.unixSocketMode) != 0) {
    std::cerr << "crated: chmod " << config_.unixSocket
              << " failed: " << std::strerror(errno) << std::endl;
  }
  if (!SocketPermsPure::isModeTight(config_.unixSocketMode)) {
    std::cerr << "crated: listen.unix_mode 0"
              << std::oct << config_.unixSocketMode << std::dec
              << " is looser than 0660 — anyone with filesystem "
              << "access can talk to the daemon. Tighten unless "
              << "you intend this." << std::endl;
  }
}

void Server::stop() {
  if (impl_->httpSrv)
    impl_->httpSrv->stop();
  if (impl_->tcpThread.joinable())
    impl_->tcpThread.join();
  // 1.1.26: stop the Unix-socket server too and JOIN its thread. The
  // old comment "Unix socket thread will exit when server stops" was
  // false — nothing ever stopped that server, and destroying the
  // joinable thread aborted the process.
  if (impl_->udsSrv)
    impl_->udsSrv->stop();
  if (impl_->unixThread.joinable())
    impl_->unixThread.join();
  if (!config_.unixSocket.empty())
    ::unlink(config_.unixSocket.c_str());
}

}
