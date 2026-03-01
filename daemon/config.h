// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// crated configuration — parsed from /usr/local/etc/crated.conf (YAML).

#pragma once

#include <string>
#include <vector>

namespace Crated {

struct AuthToken {
  std::string name;
  std::string tokenHash;   // "sha256:<hex>"
  std::string role;         // "admin" or "viewer"
};

struct Config {
  // Listen endpoints
  std::string unixSocket = "/var/run/crate/crated.sock";
  unsigned tcpPort = 9800;
  std::string tcpBind = "0.0.0.0";

  // TLS (for TCP listener)
  std::string tlsCert;
  std::string tlsKey;
  std::string tlsCa;        // CA for mTLS client verification
  bool requireClientCert = false;

  // Authentication
  std::vector<AuthToken> tokens;

  // Logging
  std::string logFile = "/var/log/crated.log";
  std::string logLevel = "info";

  // Load from YAML file
  static Config load(const std::string &path);
};

}
