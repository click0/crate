// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Per-user network sub-CIDR allocator (0.9.10, rootless track).
//
// Single-tenant deployments allocate jail IPs from one shared pool
// (e.g. 10.66.0.0/16). For multi-tenant, alice and bob need disjoint
// IP ranges so:
//   - their jails can't accidentally collide on IP
//   - operator-side firewall rules can scope per-user via the
//     sub-CIDR itself (no need for per-jail tagging)
//
// This module composes a per-user sub-CIDR from a master CIDR + a
// sub-prefix length + the operator's uid:
//
//   compose("10.66.0.0/16", 24, 1000)
//     -> "10.66.232.0/24"        (1000 % 256 = 232)
//
//   compose("10.66.0.0/16", 24, 1001)
//     -> "10.66.233.0/24"        (1001 % 256 = 233)
//
//   compose("fd00:dead::/48", 64, 1000)
//     -> "fd00:dead:0:3e8::/64"  (1000 = 0x3e8)
//
// Allocation strategy: deterministic hash from uid into the slot
// space. Slot index = uid mod (number of /<subLen> blocks under the
// master). Trade-off:
//   - Pros: stable across crated restarts, no allocator state file,
//     no race on slot picking
//   - Cons: collisions when 2^(slotBits) operators exist; e.g. with
//     /16 master + /24 sub there are 256 slots, so uids that are
//     congruent mod 256 land in the same sub-CIDR. For typical
//     deployments (<256 operators) this is fine; large multi-tenant
//     clusters need a wider sub or a state-backed allocator (future
//     work, tracked in TODO under "Rootless containers").
//
// IPv4 + IPv6 supported. The CIDR string syntax matches the existing
// PrivOpsPure validators (validateIpv4Cidr, validateIpv6Cidr) — IPv4
// is dotted quad + /<0..32>; IPv6 is colon-hex + /<0..128>.
//
// All work is pure: the module never touches the network. Tests
// exercise the bit-arithmetic edge cases.
//

#include <cstdint>
#include <string>

namespace PerUserNetPure {

struct Result {
  std::string cidr;   // e.g. "10.66.232.0/24"; empty if error non-empty
  std::string error;  // "" on success, otherwise reason
};

// Compose a per-user IPv4 sub-CIDR.
//
// `masterCidr` — operator config, e.g. "10.66.0.0/16"
// `subPrefixLen` — desired sub-CIDR prefix, must be > master prefix
//                  and ≤ 32
// `uid` — operator uid (0..INT32_MAX)
//
// Errors when:
//   - masterCidr is malformed
//   - subPrefixLen ≤ master prefix or > 32
//   - subPrefixLen - masterPrefix > 24 (slot space > 16M; we cap to
//     keep arithmetic simple and the slot collision risk auditable)
//
// Returns {cidr, ""} on success, {"", reason} on error.
Result composeIpv4(const std::string &masterCidr,
                   unsigned subPrefixLen,
                   uint32_t uid);

// Compose a per-user IPv6 sub-CIDR.
//
// Same shape as composeIpv4 but with /<0..128> bounds and slot-bit
// cap of 32 (so uids fit in the slot index without truncation).
Result composeIpv6(const std::string &masterCidr,
                   unsigned subPrefixLen,
                   uint32_t uid);

} // namespace PerUserNetPure
