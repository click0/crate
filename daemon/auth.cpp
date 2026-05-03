// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auth.h"
#include "auth_pure.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <openssl/evp.h>

#include <iomanip>
#include <sstream>

namespace Crated {

static std::string sha256hex(const std::string &input) {
  // EVP API (OpenSSL 3.0+ replaces the deprecated SHA256() one-shot).
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLen = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  EVP_DigestUpdate(ctx, input.data(), input.size());
  EVP_DigestFinal_ex(ctx, hash, &hashLen);
  EVP_MD_CTX_free(ctx);
  std::ostringstream ss;
  for (unsigned int i = 0; i < hashLen; i++)
    ss << std::hex << std::setfill('0') << std::setw(2) << (int)hash[i];
  return "sha256:" + ss.str();
}

// Check if request comes from a Unix socket. cpp-httplib leaves
// REMOTE_ADDR empty for unix-socket peers; that's our signal.
//
// Tightening to actually verify the peer's uid/gid via
// getpeereid(2) requires the connection's underlying fd, which
// httplib doesn't expose. Until we fork that code path, the unix
// socket file's mode (default 0660 owned by root:wheel) is the
// effective access control.
static bool isUnixSocketPeer(const httplib::Request &req) {
  auto remoteAddr = req.get_header_value("REMOTE_ADDR");
  return remoteAddr.empty();
}

bool isAuthorized(const httplib::Request &req, const Config &config,
                  const std::string &requiredRole) {
  if (isUnixSocketPeer(req))
    return true;

  // Bearer-token check via pure helper (lib/auth_pure.cpp).
  return AuthPure::checkBearerAuth(
    req.get_header_value("Authorization"),
    config.tokens,
    requiredRole,
    sha256hex);
}

}
