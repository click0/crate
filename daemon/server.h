// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// HTTP/TLS server for crated.
// Uses cpp-httplib (header-only) for HTTP.
// Listens on both Unix socket (local) and TCP/TLS (remote).

#pragma once

#include "config.h"

#include <memory>
#include <thread>

namespace httplib { class Server; }

namespace Crated {

class Server {
public:
  explicit Server(const Config &config);
  ~Server();

  void start();
  void stop();

private:
  Config config_;

  // 1.1.37: body cap / worker pool / FD_CLOEXEC, applied to both the
  // TCP and the unix-socket httplib instances.
  void applyListenerLimits(httplib::Server &srv);
  void applyUnixSocketPerms();   // 1.1.55: between bind(2) and accept

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}
