// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ip_alloc_pure.h"

#include <atf-c++.hpp>

#include <cstdint>
#include <string>
#include <vector>

using IpAllocPure::Lease;
using IpAllocPure::Network;
using IpAllocPure::allocateNext;
using IpAllocPure::broadcastFor;
using IpAllocPure::formatIp;
using IpAllocPure::formatLeaseLine;
using IpAllocPure::gatewayFor;
using IpAllocPure::parseCidr;
using IpAllocPure::parseIp;
using IpAllocPure::parseLeaseLine;

// ----------------------------------------------------------------------
// IP parse / format
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(ip_round_trip);
ATF_TEST_CASE_BODY(ip_round_trip) {
  // Round-trip property: parseIp(formatIp(x)) == x for several values.
  for (uint32_t a : {0u, 1u, 0x0a420005u /*10.66.0.5*/,
                     0xc0a80101u /*192.168.1.1*/,
                     0xffffffffu}) {
    uint32_t b = 0;
    ATF_REQUIRE_EQ(parseIp(formatIp(a), b), std::string());
    ATF_REQUIRE_EQ(b, a);
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(ip_parse_rejects_bad);
ATF_TEST_CASE_BODY(ip_parse_rejects_bad) {
  uint32_t out = 0;
  ATF_REQUIRE(!parseIp("",            out).empty());
  ATF_REQUIRE(!parseIp("1.2.3",       out).empty());     // 3 octets
  ATF_REQUIRE(!parseIp("1.2.3.4.5",   out).empty());     // 5 octets
  ATF_REQUIRE(!parseIp("1.2.3.256",   out).empty());     // octet OOR
  ATF_REQUIRE(!parseIp("1.2.3.-1",    out).empty());     // negative
  ATF_REQUIRE(!parseIp("01.2.3.4",    out).empty());     // leading zero
  ATF_REQUIRE(!parseIp("1.2.3.4 ",    out).empty());     // trailing space
  ATF_REQUIRE(!parseIp("a.b.c.d",     out).empty());
}

// ----------------------------------------------------------------------
// CIDR parse
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(cidr_typical);
ATF_TEST_CASE_BODY(cidr_typical) {
  Network n;
  ATF_REQUIRE_EQ(parseCidr("10.66.0.0/24", n), std::string());
  ATF_REQUIRE_EQ(n.base, 0x0a420000u);
  ATF_REQUIRE_EQ(n.prefixLen, 24u);

  ATF_REQUIRE_EQ(parseCidr("192.168.0.0/16", n), std::string());
  ATF_REQUIRE_EQ(n.prefixLen, 16u);

  ATF_REQUIRE_EQ(parseCidr("172.16.5.0/30", n), std::string());
  ATF_REQUIRE_EQ(n.prefixLen, 30u);
}

ATF_TEST_CASE_WITHOUT_HEAD(cidr_rejects_bad);
ATF_TEST_CASE_BODY(cidr_rejects_bad) {
  Network n;
  ATF_REQUIRE(!parseCidr("10.66.0.0",       n).empty());  // no slash
  ATF_REQUIRE(!parseCidr("10.66.0.0/",      n).empty());  // empty prefix
  ATF_REQUIRE(!parseCidr("10.66.0.0/abc",   n).empty());  // non-numeric
  ATF_REQUIRE(!parseCidr("10.66.0.0/0",     n).empty());  // /0 too wide
  ATF_REQUIRE(!parseCidr("10.66.0.0/31",    n).empty());  // /31 too narrow
  ATF_REQUIRE(!parseCidr("10.66.0.0/33",    n).empty());  // out of range
  ATF_REQUIRE(!parseCidr("256.0.0.0/24",    n).empty());  // bad octet
  // Misaligned base address.
  ATF_REQUIRE(!parseCidr("10.66.0.5/24",    n).empty());
}

// ----------------------------------------------------------------------
// gateway / broadcast
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(gateway_and_broadcast_for_24);
ATF_TEST_CASE_BODY(gateway_and_broadcast_for_24) {
  Network n;
  parseCidr("10.66.0.0/24", n);
  ATF_REQUIRE_EQ(formatIp(gatewayFor(n)),   std::string("10.66.0.1"));
  ATF_REQUIRE_EQ(formatIp(broadcastFor(n)), std::string("10.66.0.255"));
}

ATF_TEST_CASE_WITHOUT_HEAD(gateway_and_broadcast_for_30);
ATF_TEST_CASE_BODY(gateway_and_broadcast_for_30) {
  // /30 has only 2 usable hosts (.1 + .2); broadcast is .3.
  Network n;
  parseCidr("172.16.0.0/30", n);
  ATF_REQUIRE_EQ(formatIp(gatewayFor(n)),   std::string("172.16.0.1"));
  ATF_REQUIRE_EQ(formatIp(broadcastFor(n)), std::string("172.16.0.3"));
}

// ----------------------------------------------------------------------
// allocateNext
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(allocate_first_in_empty_pool);
ATF_TEST_CASE_BODY(allocate_first_in_empty_pool) {
  // Empty pool, /24: skip .0 (network) + .1 (gateway), first free is .2.
  Network n;
  parseCidr("10.66.0.0/24", n);
  uint32_t a = allocateNext(n, {});
  ATF_REQUIRE(a != 0);
  ATF_REQUIRE_EQ(formatIp(a), std::string("10.66.0.2"));
}

ATF_TEST_CASE_WITHOUT_HEAD(allocate_skips_taken);
ATF_TEST_CASE_BODY(allocate_skips_taken) {
  Network n;
  parseCidr("10.66.0.0/24", n);
  uint32_t taken_2 = 0; parseIp("10.66.0.2", taken_2);
  uint32_t taken_3 = 0; parseIp("10.66.0.3", taken_3);
  uint32_t a = allocateNext(n, {taken_2, taken_3});
  ATF_REQUIRE_EQ(formatIp(a), std::string("10.66.0.4"));
}

ATF_TEST_CASE_WITHOUT_HEAD(allocate_skips_gateway_even_if_in_taken);
ATF_TEST_CASE_BODY(allocate_skips_gateway_even_if_in_taken) {
  // Defensive: a configurator listing the gateway in `taken` doesn't
  // confuse us — the gateway is unconditionally skipped.
  Network n;
  parseCidr("10.66.0.0/24", n);
  uint32_t gw = gatewayFor(n);
  uint32_t a = allocateNext(n, {gw});
  ATF_REQUIRE_EQ(formatIp(a), std::string("10.66.0.2"));
}

ATF_TEST_CASE_WITHOUT_HEAD(allocate_returns_zero_when_pool_exhausted);
ATF_TEST_CASE_BODY(allocate_returns_zero_when_pool_exhausted) {
  // /30: only .1 (gateway) + .2 are usable. If .2 is taken, pool is
  // exhausted (we don't allocate gateway, and broadcast is .3).
  Network n;
  parseCidr("172.16.0.0/30", n);
  uint32_t taken_2 = 0; parseIp("172.16.0.2", taken_2);
  ATF_REQUIRE_EQ(allocateNext(n, {taken_2}), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(allocate_30_full_pool);
ATF_TEST_CASE_BODY(allocate_30_full_pool) {
  // Same /30 with empty taken: expect .2 (skip network .0 + gateway .1).
  Network n;
  parseCidr("172.16.0.0/30", n);
  uint32_t a = allocateNext(n, {});
  ATF_REQUIRE_EQ(formatIp(a), std::string("172.16.0.2"));
}

ATF_TEST_CASE_WITHOUT_HEAD(allocate_does_not_assign_broadcast);
ATF_TEST_CASE_BODY(allocate_does_not_assign_broadcast) {
  // Build a pool where everything except the broadcast is taken;
  // we should NOT return the broadcast.
  Network n;
  parseCidr("192.168.10.0/29", n);  // 8 IPs total (.0-.7), .7 is broadcast
  std::vector<uint32_t> taken;
  // Take .2 .. .6 — leaves only .7 (broadcast) untaken (after gateway+net skip).
  for (uint32_t a = n.base + 2; a < broadcastFor(n); a++)
    taken.push_back(a);
  ATF_REQUIRE_EQ(allocateNext(n, taken), 0u);
}

// ----------------------------------------------------------------------
// Lease lines
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(lease_round_trip);
ATF_TEST_CASE_BODY(lease_round_trip) {
  Lease in;
  in.name = "myjail";
  parseIp("10.66.0.42", in.ip);
  auto line = formatLeaseLine(in);
  ATF_REQUIRE_EQ(line, std::string("myjail 10.66.0.42"));
  Lease out;
  ATF_REQUIRE_EQ(parseLeaseLine(line, out), std::string());
  ATF_REQUIRE_EQ(out.name, std::string("myjail"));
  ATF_REQUIRE_EQ(out.ip,   in.ip);
}

ATF_TEST_CASE_WITHOUT_HEAD(lease_rejects_bad);
ATF_TEST_CASE_BODY(lease_rejects_bad) {
  Lease out;
  ATF_REQUIRE(!parseLeaseLine("",                            out).empty());
  ATF_REQUIRE(!parseLeaseLine("nameonly",                    out).empty());
  ATF_REQUIRE(!parseLeaseLine("name 1.2.3",                  out).empty());  // bad ip
  ATF_REQUIRE(!parseLeaseLine("ba/d 10.0.0.1",               out).empty());  // slash in name
  ATF_REQUIRE(!parseLeaseLine(" leading 10.0.0.1",           out).empty());  // leading space
  ATF_REQUIRE(!parseLeaseLine("name  10.0.0.1",              out).empty());  // double space
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, ip_round_trip);
  ATF_ADD_TEST_CASE(tcs, ip_parse_rejects_bad);
  ATF_ADD_TEST_CASE(tcs, cidr_typical);
  ATF_ADD_TEST_CASE(tcs, cidr_rejects_bad);
  ATF_ADD_TEST_CASE(tcs, gateway_and_broadcast_for_24);
  ATF_ADD_TEST_CASE(tcs, gateway_and_broadcast_for_30);
  ATF_ADD_TEST_CASE(tcs, allocate_first_in_empty_pool);
  ATF_ADD_TEST_CASE(tcs, allocate_skips_taken);
  ATF_ADD_TEST_CASE(tcs, allocate_skips_gateway_even_if_in_taken);
  ATF_ADD_TEST_CASE(tcs, allocate_returns_zero_when_pool_exhausted);
  ATF_ADD_TEST_CASE(tcs, allocate_30_full_pool);
  ATF_ADD_TEST_CASE(tcs, allocate_does_not_assign_broadcast);
  ATF_ADD_TEST_CASE(tcs, lease_round_trip);
  ATF_ADD_TEST_CASE(tcs, lease_rejects_bad);
}
