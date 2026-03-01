// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// HTTP server implementation using cpp-httplib.
// Registers routes from routes.h and serves on configured endpoints.

#include "server.h"
#include "routes.h"

#include <httplib.h>

#include <sys/un.h>
#include <unistd.h>

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
