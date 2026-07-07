// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auth.h"
#include "auth_pure.h"
#include "pool_pure.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <openssl/evp.h>

#include <ctime>
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

// Check if the request arrived on the Unix-socket listener (local,
// trusted) rather than the TCP listener (remote, token-gated).
//
// 1.1.23: this is decided from the `X-Crated-Listener` marker that
// registerRoutes' pre-routing handler stamps from the accepting server
// instance — AFTER erasing any client-supplied copy — so it is
// authoritative. The previous check keyed on `REMOTE_ADDR.empty()`,
// which a remote TCP client could shadow by sending its own empty
// `REMOTE_ADDR:` header (cpp-httplib stores request headers in a
// multimap; get_header_value returns the first match, the client's).
// A missing marker (pre-routing handler somehow skipped) reads as NOT a
// socket peer → token required → fail-closed.
//
// The unix socket file's mode (default 0660 owned by root:wheel)
// remains the access control for who may reach that listener; a
// getpeereid(2) uid/gid check would need the connection fd, which
// httplib doesn't expose (see the libnv privops socket for that).
static bool isUnixSocketPeer(const httplib::Request &req) {
  return req.get_header_value("X-Crated-Listener") == "unix";
}

bool isAuthorized(const httplib::Request &req, const Config &config,
                  const std::string &requiredRole) {
  if (isUnixSocketPeer(req))
    return true;

  // Bearer-token check (with TTL + scope) via pure helper.
  // Tokens with expiresAt=0 / empty scope are unrestricted, so
  // pre-0.7.1 crated.conf files keep working untouched.
  return AuthPure::checkBearerAuthFull(
    req.get_header_value("Authorization"),
    config.tokens,
    requiredRole,
    req.path,
    (long)::time(nullptr),
    sha256hex);
}

bool isAuthorizedForContainer(const httplib::Request &req,
                              const Config &config,
                              const std::string &requiredRole,
                              const std::string &containerName) {
  // Run the standard auth gate first (role + expiry + scope).
  if (!isAuthorized(req, config, requiredRole))
    return false;
  // Unix socket peers don't have an associated token entry, so
  // they bypass the pool ACL too. (Treating socket peers as
  // unrestricted matches the wider "socket file mode is the gate"
  // model documented in CAVEATS in crated.8.)
  if (isUnixSocketPeer(req))
    return true;
  // Find the matching token entry and consult its `pools:` list.
  auto rawToken = AuthPure::parseBearerToken(req.get_header_value("Authorization"));
  if (rawToken.empty())
    return false;   // shouldn't happen — isAuthorized already returned true
  auto hash = sha256hex(rawToken);
  for (auto &t : config.tokens) {
    if (t.tokenHash != hash) continue;
    auto containerPool = PoolPure::inferPool(containerName, config.poolSeparator);
    return PoolPure::tokenAllowsContainer(t.pools, containerPool);
  }
  return false;
}

}
