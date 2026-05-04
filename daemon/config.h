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
  // Expiry: UNIX epoch seconds. 0 means "never expires" — preserves
  // backward compatibility with existing crated.conf files that have
  // no expires_at field.
  long expiresAt = 0;
  // Scope: list of glob patterns matched against the request path.
  // Empty list means "no restriction" (any path the role allows).
  // Patterns: literal path or trailing `/*`. See AuthPure::pathInScope.
  //   ["/api/v1/containers", "/api/v1/containers/*"]
  std::vector<std::string> scope;
  // Pool ACL (added in 0.7.4): list of pool names the token may
  // touch. The pool of a container is inferred from the jail name
  // via PoolPure::inferPool. Empty = unrestricted (pre-0.7.4
  // behaviour). "*" = explicit all-pools grant.
  std::vector<std::string> pools;
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
  // Separator used by PoolPure::inferPool to extract pool from a
  // jail name. Default '-'. A single byte; YAML key
  // `auth.pool_separator: "-"`. Operators who already have hyphens
  // inside container names can use `_` or `.`.
  char poolSeparator = '-';

  // Logging
  std::string logFile = "/var/log/crated.log";
  std::string logLevel = "info";

  // WebSocket console (opt-in: 0 disables). Handshakes are
  // authenticated via `Authorization: Bearer <admin-token>`.
  unsigned consoleWsPort = 0;
  std::string consoleWsBind = "127.0.0.1";

  // Load from YAML file
  static Config load(const std::string &path);
};

}
