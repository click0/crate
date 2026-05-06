// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// HTTP server implementation using cpp-httplib.
// Registers routes from routes.h and serves on configured endpoints.

#include "server.h"
#include "routes.h"
#include "socket_perms_pure.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>

namespace Crated {

struct Server::Impl {
  std::unique_ptr<httplib::Server> httpSrv;
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

  // Register all REST routes
  registerRoutes(*impl_->httpSrv, config_);
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

    impl_->unixThread = std::thread([this]() {
      httplib::Server udsSrv;
      registerRoutes(udsSrv, config_);
      udsSrv.set_address_family(AF_UNIX);
      udsSrv.listen(config_.unixSocket, 0);
    });

    // 0.8.19: enforce post-bind filesystem perms.
    //
    // cpp-httplib's listen() returns only on shutdown, so we can't
    // run perm fixups inline before bind. Instead, poll for the
    // socket file's existence (httplib creates it inside listen())
    // for up to ~2s and chmod/chown then. This is a one-shot at
    // startup; no per-connection cost.
    //
    // Race window: from the bind() call inside httplib until the
    // chmod completes here, the socket has the umask-default mode
    // (typically 0777 on Linux, 0666 on FreeBSD modulo umask). On
    // a multi-user host an attacker watching for the socket file
    // could connect during that window. The pre-0.8.19 code had
    // the SAME race — this release just narrows it by also
    // applying owner/group, not by closing it. A full fix
    // requires the bigger getpeereid refactor (TODO).
    if (!config_.unixSocketOwner.empty()
        || !config_.unixSocketGroup.empty()
        || config_.unixSocketMode != 0660) {
      std::thread([this]() {
        // Poll for socket presence, max ~2s.
        struct stat st{};
        for (int i = 0; i < 200; i++) {
          if (::stat(config_.unixSocket.c_str(), &st) == 0)
            break;
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (st.st_mode == 0) {
          std::cerr << "crated: unix_socket " << config_.unixSocket
                    << " did not appear within 2s; perm fixup skipped"
                    << std::endl;
          return;
        }

        // Resolve owner -> uid (empty leaves uid alone via -1).
        uid_t uid = (uid_t)-1;
        if (!config_.unixSocketOwner.empty()) {
          struct passwd *pw = ::getpwnam(config_.unixSocketOwner.c_str());
          if (pw == nullptr) {
            std::cerr << "crated: listen.unix_owner '" << config_.unixSocketOwner
                      << "' not found; perm fixup skipped" << std::endl;
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
                      << "' not found; perm fixup skipped" << std::endl;
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
      }).detach();
    }
  }
}

void Server::stop() {
  if (impl_->httpSrv)
    impl_->httpSrv->stop();
  if (impl_->tcpThread.joinable())
    impl_->tcpThread.join();
  // Unix socket thread will exit when server stops
  if (!config_.unixSocket.empty())
    ::unlink(config_.unixSocket.c_str());
}

}
