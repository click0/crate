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

}
