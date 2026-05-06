// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Runtime side of the IP-pool lease store (0.7.17).
//
// File-backed registry of {jail_name -> ip} mappings, used by
// `network: auto` to track allocations across concurrent
// `crate run` invocations.
//
// Storage: /var/run/crate/network-leases.txt
// Format:  one "<name> <ip>" per line; lines starting with `#` and
//          empty lines are ignored. Atomic writes via tmpfile +
//          rename + flock(2) so two concurrent allocations don't
//          race.
//

#include "ip_alloc_pure.h"

#include <string>
#include <vector>

namespace NetworkLease {

// Standard lease file path. Override-able for tests via `setPathForTesting`.
const std::string &leasePath();
void setPathForTesting(const std::string &path);

// Read the lease file. Missing file is NOT an error — returns
// empty list. Throws on permission errors / parse errors / corrupt
// lines.
std::vector<IpAllocPure::Lease> readAll();

// Atomically allocate an IP from `pool`, write a lease for `jail`,
// and return the chosen IP. Throws if the pool is exhausted, if a
// lease for `jail` already exists with a different IP, or on file
// errors. If `jail` already has a lease, returns the existing IP
// (idempotent — same jail starting twice picks up its old IP).
//
// Locking: holds an exclusive flock on `leasePath()` for the
// duration so two concurrent `crate run` invocations don't pick
// the same IP.
uint32_t allocateFor(const std::string &jail,
                     const IpAllocPure::Network &pool);

// Atomically remove the lease for `jail`. No-op if absent.
void releaseFor(const std::string &jail);

} // namespace NetworkLease
