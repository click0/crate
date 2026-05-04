// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// Authentication middleware for crated REST API.
// Supports: mTLS client certificates, Bearer API tokens.

#pragma once

#include "config.h"

#include <string>

namespace httplib { struct Request; }

namespace Crated {

// Check if request is authorized for the given role.
// Returns true if authorized, false otherwise.
// Checks in order: mTLS CN → Bearer token → Unix socket (always admin).
bool isAuthorized(const httplib::Request &req, const Config &config,
                  const std::string &requiredRole);

// As above, but also enforces the per-token pool ACL (added in
// 0.7.4) against the container the request is targeting. The pool
// is inferred from `containerName` via PoolPure::inferPool with
// `config.poolSeparator`. F2 endpoints with a `:name` URL
// parameter should use this variant; routes that don't address a
// specific container (e.g. /api/v1/host) keep using
// isAuthorized().
bool isAuthorizedForContainer(const httplib::Request &req,
                              const Config &config,
                              const std::string &requiredRole,
                              const std::string &containerName);

}
