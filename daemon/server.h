// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// HTTP/TLS server for crated.
// Uses cpp-httplib (header-only) for HTTP.
// Listens on both Unix socket (local) and TCP/TLS (remote).

#pragma once

#include "config.h"

#include <memory>
#include <thread>

namespace Crated {

class Server {
public:
  explicit Server(const Config &config);
  ~Server();

  void start();
  void stop();

private:
  Config config_;

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}
