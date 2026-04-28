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

}
