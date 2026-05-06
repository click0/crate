// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// IPv6 lease store (0.8.20). Counterpart to NetworkLease for the v4
// path. See lib/network_lease.h for the design rationale; the v6
// version is a near-copy with Ip6AllocPure types substituted.
//
// Storage: /var/run/crate/network-leases6.txt
// Format:  one "<name> <ip6>" per line; lines starting with `#` and
//          empty lines are ignored. Atomic writes via tmpfile +
//          rename + flock(2).
//
// Kept separate from network-leases.txt because the IPv4 file is
// older (0.7.17) and tooling that reads it doesn't expect v6
// addresses to appear there.
//

#include "ip6_alloc_pure.h"

#include <string>
#include <vector>

namespace NetworkLease6 {

const std::string &leasePath();
void setPathForTesting(const std::string &path);

std::vector<Ip6AllocPure::Lease6> readAll();

// Allocate an IPv6 from `pool`, write a lease for `jail`, return
// the chosen address. Throws on exhaustion / file errors.
// Idempotent: same jail picks up its existing lease.
Ip6AllocPure::Addr6 allocateFor(const std::string &jail,
                                const Ip6AllocPure::Network6 &pool);

void releaseFor(const std::string &jail);

} // namespace NetworkLease6
