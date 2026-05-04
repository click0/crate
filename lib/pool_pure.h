// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for resource pools + ACL (0.7.4).
//
// A "pool" is a logical grouping of containers — operators map it
// to teams/tenants/environments. We avoid adding a new spec field
// (which would force every existing crate.yml to declare its pool)
// by inferring the pool from the jail name using a configurable
// separator (default "-"):
//
//   jail name           → pool       (separator: "-")
//   ─────────           ─────
//   dev-postgres-1      → dev
//   stage-redis         → stage
//   monolithic          → ""    (no separator → no pool)
//
// Tokens declared in crated.conf can carry a `pools:` whitelist:
//
//   auth:
//     tokens:
//       - name: alice
//         token_hash: "..."
//         role: viewer
//         pools: ["dev", "stage"]
//
// Empty `pools:` list = no pool restriction (backward compatible
// with pre-0.7.4 configs). A token with `pools: ["dev"]` may only
// access F2 endpoints for jails whose inferred pool is "dev".
//
// On the hub side, the same `inferPool` helper drives
// /api/v1/pools — a flat summary of distinct pools across the
// running containers.
//

#include <cstdint>
#include <string>
#include <vector>

namespace PoolPure {

// Infer the pool prefix from a jail name. Returns "" if the
// separator does not occur, or if the prefix would be empty
// (`-foo` is not pool "" — it's no-pool).
//
// `separator` must be exactly 1 byte. The runtime caller picks
// it from `pool_separator:` in crated.conf (default "-").
std::string inferPool(const std::string &jailName, char separator);

// Validate a pool name as it appears in a token's `pools:` list.
// Rules:
//   - non-empty, ≤32 chars
//   - first character: letter or digit (no `_`, no `.`)
//   - body characters: letters, digits, '_', '-'
// Mirrors the jail-name alphabet; if a name passes
// validateJailName it can also be a pool name.
// Returns "" on success.
std::string validatePoolName(const std::string &name);

// Check whether a token's pool whitelist permits access to a
// container with the given inferred pool. Rules:
//   - tokenPools empty → unrestricted (backward compat)
//   - containerPool empty (jail has no pool prefix) → only
//     unrestricted tokens may access; a tokens with explicit
//     `pools:` cannot reach pool-less jails (operator must
//     adopt the prefix convention or grant `pools: ["*"]`).
//   - tokenPools contains "*" → unrestricted (explicit
//     "all pools" grant; preferred over leaving `pools:` out
//     when the operator wants to document the intent).
//   - otherwise: containerPool must appear in tokenPools.
bool tokenAllowsContainer(const std::vector<std::string> &tokenPools,
                          const std::string &containerPool);

} // namespace PoolPure
