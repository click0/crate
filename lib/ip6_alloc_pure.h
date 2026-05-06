// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for IPv6 pool allocation (0.8.20 — Phase 2 of IPv6
// support that 0.8.15 hooked into config). Counterpart to
// IpAllocPure for the v4 path.
//
// Conventions inherited from IpAllocPure:
//   - pool's base address (.::0) is reserved as the network address
//   - pool's base+1 (.::1) is reserved as the gateway
//   - allocateNext skips both plus any IP present in `taken`
//   - exhaustion returns the all-zero address (callers refuse the
//     operation rather than emit a bogus IP)
//
// IPv6-specific quirks worth flagging:
//   - "fd00::/8" is the ULA prefix per RFC 4193; we don't enforce
//     ULA-only pools — operators can use a global /64 if they
//     understand the routing implications
//   - parseCidr6 normalises base addresses to the CIDR boundary
//     (so "fd00:0:0:1::dead/64" is rejected; operator should have
//     written "fd00:0:0:1::/64")
//   - formatIp6 emits canonical RFC 5952 form (lowercase hex,
//     longest run of zeros collapsed to "::")
//   - allocation is sequential within the lower 64 bits; for /64
//     pools that's 2^64 addresses which is more than enough
//

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace Ip6AllocPure {

// 128-bit address as 16 raw bytes in network order
// (byte 0 is the most significant).
using Addr6 = std::array<uint8_t, 16>;

// IPv6 network: base address + prefix length (1..128).
struct Network6 {
  Addr6    base{};      // zero-initialised
  unsigned prefixLen = 0;
};

// Parse "fd00::/64" into Network6. Returns "" on success and fills
// `out`; otherwise returns a human-readable error message.
//
// Validation:
//   - exactly one '/'
//   - canonical-or-shorthand IPv6 address in the part before '/'
//     (single "::" allowed; double "::" rejected)
//   - prefix 1..128
//   - base address is aligned to the prefix (host bits all zero)
std::string parseCidr6(const std::string &cidr, Network6 &out);

// Parse a single IPv6 literal into raw bytes. Returns "" on
// success; otherwise an error. Accepts shorthand "::" notation.
// Rejects:
//   - more than one "::" run
//   - more than 8 16-bit groups
//   - hex groups longer than 4 digits
//   - non-hex characters
//   - empty string
//   - dotted-quad IPv4 embedding (we don't currently need it; can
//     be added when the doctor 4-mapped-6 check lands)
std::string parseIp6(const std::string &s, Addr6 &out);

// Format an IPv6 address in canonical RFC 5952 form:
//   - lowercase hex
//   - leading zeros stripped from each group ("0001" -> "1")
//   - longest run of >=2 consecutive zero groups collapsed to "::"
//     (ties broken by leftmost)
std::string formatIp6(const Addr6 &addr);

// Conventional gateway for a pool — base + 1.
Addr6 gatewayFor(const Network6 &n);

// Pick the next free IP from the pool, skipping:
//   - the network address (base)
//   - the gateway (base + 1)
//   - any IP present in `taken`
//
// Allocation strategy: linear scan from base+2 within the host
// bits. Returns the all-zero address on exhaustion. For /64 pools
// the 2^62 search space makes the scan trivial in practice (the
// `taken` list is bounded by the number of running jails on the
// host, which is in the dozens, not billions).
Addr6 allocateNext(const Network6 &pool, const std::vector<Addr6> &taken);

// Predicate: does `addr` fall inside `pool`?
bool inPool(const Network6 &pool, const Addr6 &addr);

// --- Lease file format (mirrors IpAllocPure::Lease) ---
struct Lease6 {
  std::string name;
  Addr6       ip{};
};

// Parse one lease-file line "<name> <ip6>". Returns "" on success.
std::string parseLeaseLine6(const std::string &line, Lease6 &out);

// Format one lease-file line (no trailing newline; caller adds it).
std::string formatLeaseLine6(const Lease6 &l);

} // namespace Ip6AllocPure
