// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "config.h"

#include <yaml-cpp/yaml.h>
#include <stdexcept>

namespace Crated {

Config Config::load(const std::string &path) {
  Config cfg;
  YAML::Node root = YAML::LoadFile(path);

  if (auto listen = root["listen"]) {
    if (listen["unix"])
      cfg.unixSocket = listen["unix"].as<std::string>();
    if (listen["tcp_port"])
      cfg.tcpPort = listen["tcp_port"].as<unsigned>();
    if (listen["tcp_bind"])
      cfg.tcpBind = listen["tcp_bind"].as<std::string>();
  }

  if (auto tls = root["tls"]) {
    if (tls["cert"])
      cfg.tlsCert = tls["cert"].as<std::string>();
    if (tls["key"])
      cfg.tlsKey = tls["key"].as<std::string>();
    if (tls["ca"])
      cfg.tlsCa = tls["ca"].as<std::string>();
    if (tls["require_client_cert"])
      cfg.requireClientCert = tls["require_client_cert"].as<bool>();
  }

  if (auto auth = root["auth"]) {
    if (auto tokens = auth["tokens"]) {
      for (auto t : tokens) {
        AuthToken at;
        at.name = t["name"].as<std::string>();
        at.tokenHash = t["token_hash"].as<std::string>();
        at.role = t["role"].as<std::string>("viewer");
        cfg.tokens.push_back(at);
      }
    }
  }

  if (auto log = root["log"]) {
    if (log["file"])
      cfg.logFile = log["file"].as<std::string>();
    if (log["level"])
      cfg.logLevel = log["level"].as<std::string>();
  }

  if (auto cons = root["console_ws"]) {
    if (cons["port"])
      cfg.consoleWsPort = cons["port"].as<unsigned>();
    if (cons["bind"])
      cfg.consoleWsBind = cons["bind"].as<std::string>();
  }

  return cfg;
}

}
