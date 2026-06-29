// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "per_user_net_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace PerUserNetPure;

// --- IPv4 ---

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_typical_8_to_24);
ATF_TEST_CASE_BODY(ipv4_typical_8_to_24) {
  // /8 + /24 → 16-bit slot space (65536 slots), so a real uid like
  // 1000 fits without collision. uid 1000 = 0x03E8 -> 10.3.232.0/24.
  auto r = composeIpv4("10.0.0.0/8", 24, 1000);
  ATF_REQUIRE_EQ(r.error, std::string());
  ATF_REQUIRE_EQ(r.cidr, std::string("10.3.232.0/24"));

  // uid 0 → slot 0
  r = composeIpv4("10.0.0.0/8", 24, 0);
  ATF_REQUIRE_EQ(r.cidr, std::string("10.0.0.0/24"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_uid_overflowing_slot_space_errors);
ATF_TEST_CASE_BODY(ipv4_uid_overflowing_slot_space_errors) {
  // 1.1.18: an 8-bit slot space (/16 + /24) holds uids 0..255. The
  // boundary uid 255 is fine; 256 and above must ERROR rather than
  // silently wrap to an already-taken slot (pre-1.1.18 they collided).
  ATF_REQUIRE_EQ(composeIpv4("10.66.0.0/16", 24, 255).error, std::string());
  ATF_REQUIRE(!composeIpv4("10.66.0.0/16", 24, 256).error.empty());
  ATF_REQUIRE(!composeIpv4("10.66.0.0/16", 24, 1000).error.empty());
  // The error must mention the offending uid so operators can act.
  ATF_REQUIRE(composeIpv4("10.66.0.0/16", 24, 256).error.find("256")
              != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_isolation_alice_vs_bob);
ATF_TEST_CASE_BODY(ipv4_isolation_alice_vs_bob) {
  // Adjacent uids must land in adjacent (non-overlapping) sub-CIDRs.
  // Use a /8 master so realistic uids fit the slot space.
  auto alice = composeIpv4("10.0.0.0/8", 24, 1000);
  auto bob   = composeIpv4("10.0.0.0/8", 24, 1001);
  ATF_REQUIRE_EQ(alice.error, std::string());
  ATF_REQUIRE_EQ(bob.error, std::string());
  ATF_REQUIRE(alice.cidr != bob.cidr);
  // Same /8 root
  ATF_REQUIRE(alice.cidr.substr(0, 3) == std::string("10."));
  ATF_REQUIRE(bob.cidr.substr(0, 3)   == std::string("10."));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv4_master_low_bits_are_ignored);
ATF_TEST_CASE_BODY(ipv4_master_low_bits_are_ignored) {
  // Operator wrote "10.66.5.7/16" — non-canonical. Compose must
  // mask off the low 16 bits and produce the same result as with
  // "10.66.0.0/16". (uid 5 fits the 8-bit slot space.)
  auto canonical = composeIpv4("10.66.0.0/16", 24, 5);
  auto sloppy    = composeIpv4("10.66.5.7/16", 24, 5);
  ATF_REQUIRE_EQ(canonical.error, std::string());
  ATF_REQUIRE_EQ(canonical.cidr, sloppy.cidr);
  ATF_REQUIRE_EQ(canonical.cidr, std::string("10.66.5.0/24"));
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

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_uid_overflowing_slot_space_errors);
ATF_TEST_CASE_BODY(ipv6_uid_overflowing_slot_space_errors) {
  // 1.1.18: an 8-bit slot space (/64 + /72) holds uids 0..255.
  ATF_REQUIRE_EQ(composeIpv6("fd00::/64", 72, 255).error, std::string());
  ATF_REQUIRE(!composeIpv6("fd00::/64", 72, 256).error.empty());
  // A 16-bit slot space (/48 + /64) comfortably holds uid 1000.
  ATF_REQUIRE_EQ(composeIpv6("fd00:dead::/48", 64, 1000).error, std::string());
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
  ATF_ADD_TEST_CASE(tcs, ipv4_typical_8_to_24);
  ATF_ADD_TEST_CASE(tcs, ipv4_uid_overflowing_slot_space_errors);
  ATF_ADD_TEST_CASE(tcs, ipv4_isolation_alice_vs_bob);
  ATF_ADD_TEST_CASE(tcs, ipv4_master_low_bits_are_ignored);
  ATF_ADD_TEST_CASE(tcs, ipv4_28_subnet);
  ATF_ADD_TEST_CASE(tcs, ipv4_rejects_bad_master);
  ATF_ADD_TEST_CASE(tcs, ipv4_rejects_sub_prefix_relations);
  ATF_ADD_TEST_CASE(tcs, ipv6_typical_48_to_64);
  ATF_ADD_TEST_CASE(tcs, ipv6_uid_overflowing_slot_space_errors);
  ATF_ADD_TEST_CASE(tcs, ipv6_isolation_alice_vs_bob);
  ATF_ADD_TEST_CASE(tcs, ipv6_master_low_bits_are_ignored);
  ATF_ADD_TEST_CASE(tcs, ipv6_rejects_bad_master);
  ATF_ADD_TEST_CASE(tcs, ipv6_rejects_sub_prefix_relations);
}
