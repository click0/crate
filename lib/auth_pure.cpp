// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auth_pure.h"

namespace AuthPure {

std::string parseBearerToken(const std::string &authHeader) {
  static const std::string prefix = "Bearer ";
  if (authHeader.size() <= prefix.size())
    return "";
  if (authHeader.compare(0, prefix.size(), prefix) != 0)
    return "";
  return authHeader.substr(prefix.size());
}

bool checkTokenRole(const std::string &tokenHash,
                    const std::vector<Crated::AuthToken> &tokens,
                    const std::string &requiredRole) {
  for (auto &t : tokens) {
    if (t.tokenHash == tokenHash) {
      if (requiredRole == "viewer")
        return true;
      return t.role == requiredRole || t.role == "admin";
    }
  }
  return false;
}

bool checkBearerAuth(const std::string &authHeader,
                     const std::vector<Crated::AuthToken> &tokens,
                     const std::string &requiredRole,
                     const std::function<std::string(const std::string&)> &sha256Fn) {
  auto token = parseBearerToken(authHeader);
  if (token.empty())
    return false;
  auto hash = sha256Fn(token);
  return checkTokenRole(hash, tokens, requiredRole);
}

}
