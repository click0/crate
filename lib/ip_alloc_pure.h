// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#pragma once

//
// Pure helpers for IP-pool allocation (0.7.17 — `network: auto`).
//
// The "network: auto" shortcut expands to bridge mode + auto-IP from
// a configured CIDR pool. This module owns:
//   - CIDR parsing (base + prefix length)
//   - dotted-decimal formatting
//   - "next free IP" given a pool and a list of taken IPs
//   - lease-file line parse/format ("<jail-name> <ip>")
//
// Convention: pool's `.0` (network) and `.255`-equivalent (broadcast)
// are reserved by the kernel; `.1` is reserved as the gateway by
// crate convention. allocateNext skips all three.
//
// All file I/O lives in lib/network_lease.cpp.
//

#include <cstdint>
#include <string>
#include <vector>

namespace IpAllocPure {

// IPv4 network: base address (host byte order) + prefix length.
struct Network {
  uint32_t base       = 0;
  unsigned prefixLen  = 0;
};

// Parse "10.66.0.0/24" into Network. Returns "" on success and fills
// `out`; otherwise returns a human-readable error message.
//
// Validation:
//   - exactly one '/'
//   - dotted quad with octets 0..255
//   - prefix 1..30 (smaller than 1 = pool is the whole IPv4 space,
//     not useful; bigger than 30 = fewer than 4 hosts after we skip
//     base/gateway/broadcast)
//   - base address must already be aligned to the prefix (e.g.
//     10.66.0.5/24 is rejected — operator should have written
//     10.66.0.0/24)
std::string parseCidr(const std::string &cidr, Network &out);

// Format an IPv4 address (host byte order) as dotted decimal.
std::string formatIp(uint32_t addr);

// Parse "1.2.3.4" into uint32_t (host byte order). Returns "" on
// success, error message otherwise.
std::string parseIp(const std::string &s, uint32_t &out);

// The conventional gateway IP for a pool — base address plus 1.
uint32_t gatewayFor(const Network &n);

// The broadcast address for a pool — base address plus
// (1 << (32 - prefixLen)) - 1.
uint32_t broadcastFor(const Network &n);

// Pick the next free IP from the pool, skipping:
//   - the network address (.0)
//   - the gateway (.1, conventional)
//   - the broadcast (.255 for /24, etc.)
//   - any IP present in `taken`
//
// Returns 0 if the pool is exhausted (signals caller to refuse the
// operation rather than emit a bogus IP).
uint32_t allocateNext(const Network &pool, const std::vector<uint32_t> &taken);

// --- Lease file format ---
//
// One line per active jail: "<jail-name> <ip>"
// Whitespace-separated; lines starting with `#` are comments.
// No trailing whitespace, single space between fields, single LF.
struct Lease {
  std::string name;
  uint32_t    ip = 0;
};

// Parse one lease-file line. Returns "" on success and fills `out`.
// Comments and blank lines are not parsed — caller filters them
// before calling. Errors:
//   - missing space
//   - empty name
//   - invalid IP
std::string parseLeaseLine(const std::string &line, Lease &out);

// Format one lease-file line (no trailing newline; caller adds it).
std::string formatLeaseLine(const Lease &l);

} // namespace IpAllocPure
