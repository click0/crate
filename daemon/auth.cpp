// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auth.h"

#include <httplib.h>

#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

namespace Crated {

static std::string sha256hex(const std::string &input) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
  std::ostringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
  return "sha256:" + ss.str();
}

bool isAuthorized(const httplib::Request &req, const Config &config,
                  const std::string &requiredRole) {
  // Unix socket connections are always admin (peer cred check by OS)
  // TODO: detect Unix socket vs TCP from request

  // Check Bearer token
  auto authHeader = req.get_header_value("Authorization");
  if (authHeader.substr(0, 7) == "Bearer ") {
    auto token = authHeader.substr(7);
    auto tokenHash = sha256hex(token);
    for (auto &t : config.tokens) {
      if (t.tokenHash == tokenHash) {
        if (requiredRole == "viewer")
          return true;  // any role can view
        return t.role == requiredRole || t.role == "admin";
      }
    }
    return false; // token not found
  }

  // No auth provided — reject for TCP, allow for Unix socket
  // (TCP without auth is rejected)
  return false;
}

}
