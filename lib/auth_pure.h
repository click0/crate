// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Pure Bearer-token authorisation logic extracted from daemon/auth.cpp.
// Decoupled from OpenSSL: callers (and tests) supply the SHA-256 callback.
// The httplib/getpeereid bits stay in daemon/auth.cpp.

#pragma once

#include "../daemon/config.h"   // Crated::AuthToken

#include <functional>
#include <string>

namespace AuthPure {

// Strip the "Bearer " prefix from an Authorization header value.
// Returns empty string if the header is empty, too short, or not Bearer.
std::string parseBearerToken(const std::string &authHeader);

// Look up a hashed token in the token list and check the role gate.
//   - if no entry matches -> false
//   - if requiredRole == "viewer", any role is allowed
//   - otherwise the role must match exactly OR be "admin"
bool checkTokenRole(const std::string &tokenHash,
                    const std::vector<Crated::AuthToken> &tokens,
                    const std::string &requiredRole);

// Combined: parse + hash + role-check. sha256Fn is injected so tests
// don't need OpenSSL.
bool checkBearerAuth(const std::string &authHeader,
                     const std::vector<Crated::AuthToken> &tokens,
                     const std::string &requiredRole,
                     const std::function<std::string(const std::string&)> &sha256Fn);

// --- TTL + scope (added in 0.7.1) ---

// Parse an ISO 8601 UTC timestamp ("YYYY-MM-DDTHH:MM:SSZ" or
// "YYYY-MM-DDTHH:MM:SS+00:00") into a UNIX epoch. Returns -1 on
// any parse error. Pure — uses timegm via the standard library.
long parseIso8601Utc(const std::string &s);

// True iff `now` is strictly after the token's expiry. Tokens with
// expiresAt == 0 are treated as "never expires" so existing
// crated.conf files keep working untouched.
bool isExpired(const Crated::AuthToken &t, long now);

// True iff at least one entry in `scope` matches `path`. An empty
// `scope` list means "no restriction" (always true). Patterns:
//   - exact match:   "/api/v1/host"
//   - trailing wild: "/api/v1/containers/*" matches any path that
//                    starts with "/api/v1/containers/" (note: the
//                    slash is required so the bare prefix
//                    "/api/v1/containers" does NOT match this glob).
bool pathInScope(const std::vector<std::string> &scope,
                 const std::string &path);

// Combined: parse + hash + role-check + expiry-check + scope-check.
// `now` is the current UNIX epoch (injectable for tests). `path` is
// the request path the daemon is gating; used for scope matching.
bool checkBearerAuthFull(const std::string &authHeader,
                         const std::vector<Crated::AuthToken> &tokens,
                         const std::string &requiredRole,
                         const std::string &path,
                         long now,
                         const std::function<std::string(const std::string&)> &sha256Fn);

}
