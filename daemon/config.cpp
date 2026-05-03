// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "config.h"
#include "../lib/auth_pure.h"

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
        if (t["expires_at"]) {
          auto raw = t["expires_at"].as<std::string>();
          auto parsed = AuthPure::parseIso8601Utc(raw);
          if (parsed < 0)
            throw std::runtime_error(
              "auth.tokens[" + at.name + "].expires_at is not a valid ISO 8601 UTC timestamp: '" + raw + "'");
          at.expiresAt = parsed;
        }
        if (t["scope"]) {
          auto sc = t["scope"];
          if (sc.IsSequence()) {
            for (auto s : sc) at.scope.push_back(s.as<std::string>());
          } else if (sc.IsScalar()) {
            at.scope.push_back(sc.as<std::string>());
          }
        }
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
