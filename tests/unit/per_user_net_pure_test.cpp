// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "per_user_net_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace PerUserNetPure;

// --- IPv4 ---

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_typical_16_to_24);
ATF_TEST_CASE_BODY(ipv4_typical_16_to_24) {
  // /16 + /24 → 256 slots; uid 1000 % 256 = 232
  auto r = composeIpv4("10.66.0.0/16", 24, 1000);
  ATF_REQUIRE_EQ(r.error, std::string());
  ATF_REQUIRE_EQ(r.cidr, std::string("10.66.232.0/24"));

  // uid 0 → slot 0
  r = composeIpv4("10.66.0.0/16", 24, 0);
  ATF_REQUIRE_EQ(r.cidr, std::string("10.66.0.0/24"));

  // uid 256 wraps back to slot 0
  r = composeIpv4("10.66.0.0/16", 24, 256);
  ATF_REQUIRE_EQ(r.cidr, std::string("10.66.0.0/24"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_isolation_alice_vs_bob);
ATF_TEST_CASE_BODY(ipv4_isolation_alice_vs_bob) {
  // Adjacent uids must land in adjacent (non-overlapping) sub-CIDRs.
  auto alice = composeIpv4("10.66.0.0/16", 24, 1000);
  auto bob   = composeIpv4("10.66.0.0/16", 24, 1001);
  ATF_REQUIRE_EQ(alice.error, std::string());
  ATF_REQUIRE_EQ(bob.error, std::string());
  ATF_REQUIRE(alice.cidr != bob.cidr);
  // Same /16 root
  ATF_REQUIRE(alice.cidr.substr(0, 6) == std::string("10.66."));
  ATF_REQUIRE(bob.cidr.substr(0, 6)   == std::string("10.66."));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_master_low_bits_are_ignored);
ATF_TEST_CASE_BODY(ipv4_master_low_bits_are_ignored) {
  // Operator wrote "10.66.5.7/16" — non-canonical. Compose must
  // mask off the low 16 bits and produce the same result as with
  // "10.66.0.0/16".
  auto canonical = composeIpv4("10.66.0.0/16", 24, 1000);
  auto sloppy    = composeIpv4("10.66.5.7/16", 24, 1000);
  ATF_REQUIRE_EQ(canonical.cidr, sloppy.cidr);
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_28_subnet);
ATF_TEST_CASE_BODY(ipv4_28_subnet) {
  // /24 master + /28 sub → 16 slots, each /28 is 16 IPs.
  // uid 5 → 10.0.0.80/28
  auto r = composeIpv4("10.0.0.0/24", 28, 5);
  ATF_REQUIRE_EQ(r.error, std::string());
  ATF_REQUIRE_EQ(r.cidr, std::string("10.0.0.80/28"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_rejects_bad_master);
ATF_TEST_CASE_BODY(ipv4_rejects_bad_master) {
  ATF_REQUIRE(!composeIpv4("not a cidr", 24, 0).error.empty());
  ATF_REQUIRE(!composeIpv4("10.0.0.0", 24, 0).error.empty());
  ATF_REQUIRE(!composeIpv4("10.0.0.256/24", 28, 0).error.empty());
  ATF_REQUIRE(!composeIpv4("10.0.0.0/33", 28, 0).error.empty());
  ATF_REQUIRE(!composeIpv4("10.0.0.01/24", 28, 0).error.empty()); // leading zero
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_rejects_sub_prefix_relations);
ATF_TEST_CASE_BODY(ipv4_rejects_sub_prefix_relations) {
  // sub <= master
  ATF_REQUIRE(!composeIpv4("10.0.0.0/24", 24, 0).error.empty());
  ATF_REQUIRE(!composeIpv4("10.0.0.0/24", 16, 0).error.empty());
  // sub > 32
  ATF_REQUIRE(!composeIpv4("10.0.0.0/8", 33, 0).error.empty());
  // slot space too wide (master /8, sub /33 — diff > 24)
  ATF_REQUIRE(!composeIpv4("10.0.0.0/0", 25, 0).error.empty());
}

// --- IPv6 ---

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_typical_48_to_64);
ATF_TEST_CASE_BODY(ipv6_typical_48_to_64) {
  // /48 + /64 → 16 slot bits. uid 1000 = 0x3e8 → 4th group = 03e8
  auto r = composeIpv6("fd00:dead::/48", 64, 1000);
  ATF_REQUIRE_EQ(r.error, std::string());
  ATF_REQUIRE_EQ(r.cidr, std::string("fd00:dead:0:3e8:0:0:0:0/64"));

  // uid 0 → all-zero slot
  r = composeIpv6("fd00:dead::/48", 64, 0);
  ATF_REQUIRE_EQ(r.cidr, std::string("fd00:dead:0:0:0:0:0:0/64"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_isolation_alice_vs_bob);
ATF_TEST_CASE_BODY(ipv6_isolation_alice_vs_bob) {
  auto alice = composeIpv6("fd00:dead::/48", 64, 1000);
  auto bob   = composeIpv6("fd00:dead::/48", 64, 1001);
  ATF_REQUIRE_EQ(alice.error, std::string());
  ATF_REQUIRE_EQ(bob.error, std::string());
  ATF_REQUIRE(alice.cidr != bob.cidr);
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_master_low_bits_are_ignored);
ATF_TEST_CASE_BODY(ipv6_master_low_bits_are_ignored) {
  // Non-canonical master (low bits set) — should be masked.
  auto canonical = composeIpv6("fd00:dead::/48", 64, 1000);
  auto sloppy    = composeIpv6("fd00:dead:0:5::1/48", 64, 1000);
  ATF_REQUIRE_EQ(canonical.cidr, sloppy.cidr);
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_rejects_bad_master);
ATF_TEST_CASE_BODY(ipv6_rejects_bad_master) {
  ATF_REQUIRE(!composeIpv6("not a cidr", 64, 0).error.empty());
  ATF_REQUIRE(!composeIpv6("ggg::1/48", 64, 0).error.empty());
  ATF_REQUIRE(!composeIpv6("fd00::/129", 64, 0).error.empty());
  ATF_REQUIRE(!composeIpv6("fd00::/48", 129, 0).error.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_rejects_sub_prefix_relations);
ATF_TEST_CASE_BODY(ipv6_rejects_sub_prefix_relations) {
  ATF_REQUIRE(!composeIpv6("fd00::/64", 64, 0).error.empty()); // sub == master
  ATF_REQUIRE(!composeIpv6("fd00::/64", 48, 0).error.empty()); // sub < master
  // slot space too wide (>32 bits)
  ATF_REQUIRE(!composeIpv6("fd00::/0", 33, 0).error.empty());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, ipv4_typical_16_to_24);
  ATF_ADD_TEST_CASE(tcs, ipv4_isolation_alice_vs_bob);
  ATF_ADD_TEST_CASE(tcs, ipv4_master_low_bits_are_ignored);
  ATF_ADD_TEST_CASE(tcs, ipv4_28_subnet);
  ATF_ADD_TEST_CASE(tcs, ipv4_rejects_bad_master);
  ATF_ADD_TEST_CASE(tcs, ipv4_rejects_sub_prefix_relations);
  ATF_ADD_TEST_CASE(tcs, ipv6_typical_48_to_64);
  ATF_ADD_TEST_CASE(tcs, ipv6_isolation_alice_vs_bob);
  ATF_ADD_TEST_CASE(tcs, ipv6_master_low_bits_are_ignored);
  ATF_ADD_TEST_CASE(tcs, ipv6_rejects_bad_master);
  ATF_ADD_TEST_CASE(tcs, ipv6_rejects_sub_prefix_relations);
}
