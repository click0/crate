// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ip6_alloc_pure.h"

#include <atf-c++.hpp>

#include <string>

using Ip6AllocPure::Addr6;
using Ip6AllocPure::Lease6;
using Ip6AllocPure::Network6;
using Ip6AllocPure::allocateNext;
using Ip6AllocPure::formatIp6;
using Ip6AllocPure::formatLeaseLine6;
using Ip6AllocPure::gatewayFor;
using Ip6AllocPure::inPool;
using Ip6AllocPure::parseCidr6;
using Ip6AllocPure::parseIp6;
using Ip6AllocPure::parseLeaseLine6;

static Addr6 a6(std::initializer_list<uint8_t> bytes) {
  Addr6 a{};
  size_t i = 0;
  for (auto b : bytes) { if (i < 16) a[i++] = b; }
  return a;
}

// --- parseIp6 ---

ATF_TEST_CASE_WITHOUT_HEAD(parseIp6_full_form);
ATF_TEST_CASE_BODY(parseIp6_full_form) {
  Addr6 a{};
  ATF_REQUIRE_EQ(parseIp6("2001:0db8:0000:0000:0000:0000:0000:0001", a), std::string());
  ATF_REQUIRE(a == a6({0x20,0x01, 0x0d,0xb8, 0,0, 0,0, 0,0, 0,0, 0,0, 0,1}));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseIp6_shorthand_middle);
ATF_TEST_CASE_BODY(parseIp6_shorthand_middle) {
  Addr6 a{};
  ATF_REQUIRE_EQ(parseIp6("2001:db8::1", a), std::string());
  ATF_REQUIRE(a == a6({0x20,0x01, 0x0d,0xb8, 0,0, 0,0, 0,0, 0,0, 0,0, 0,1}));
  // ULA prefix
  ATF_REQUIRE_EQ(parseIp6("fd00::1", a), std::string());
  ATF_REQUIRE(a == a6({0xfd,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1}));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseIp6_shorthand_at_ends);
ATF_TEST_CASE_BODY(parseIp6_shorthand_at_ends) {
  Addr6 a{};
  ATF_REQUIRE_EQ(parseIp6("::1", a), std::string());
  ATF_REQUIRE(a == a6({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1}));
  ATF_REQUIRE_EQ(parseIp6("fe80::", a), std::string());
  ATF_REQUIRE(a == a6({0xfe,0x80, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0}));
  // All-zero
  ATF_REQUIRE_EQ(parseIp6("::", a), std::string());
  ATF_REQUIRE(a == a6({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseIp6_rejects_garbage);
ATF_TEST_CASE_BODY(parseIp6_rejects_garbage) {
  Addr6 a{};
  ATF_REQUIRE(!parseIp6("",                a).empty());
  ATF_REQUIRE(!parseIp6("zzz",             a).empty());
  ATF_REQUIRE(!parseIp6("fd00:::1",        a).empty());   // double "::"
  ATF_REQUIRE(!parseIp6("fd00::1::2",      a).empty());   // two "::" runs
  ATF_REQUIRE(!parseIp6("fd00:1:2:3:4:5:6:7:8", a).empty()); // 9 groups
  ATF_REQUIRE(!parseIp6("fd00:12345::1",   a).empty());   // 5-digit group
  ATF_REQUIRE(!parseIp6("fd00:xxxx::1",    a).empty());   // non-hex
  ATF_REQUIRE(!parseIp6(":1",              a).empty());   // leading single ':'
  ATF_REQUIRE(!parseIp6("1:",              a).empty());   // trailing single ':'
  ATF_REQUIRE(!parseIp6("0:1:2:3:4:5:6:7", a).empty() == false);   // exactly 8 groups OK
}

// --- formatIp6 (RFC 5952) ---

ATF_TEST_CASE_WITHOUT_HEAD(formatIp6_collapses_longest_zero_run);
ATF_TEST_CASE_BODY(formatIp6_collapses_longest_zero_run) {
  // 2001:db8:0:0:1:0:0:1 -> 2001:db8::1:0:0:1
  // (leftmost wins on ties; first run is longer or equal -> collapse first)
  ATF_REQUIRE_EQ(formatIp6(a6({0x20,0x01, 0x0d,0xb8, 0,0, 0,0, 0,1, 0,0, 0,0, 0,1})),
                 std::string("2001:db8::1:0:0:1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(formatIp6_minimal_addresses);
ATF_TEST_CASE_BODY(formatIp6_minimal_addresses) {
  ATF_REQUIRE_EQ(formatIp6(a6({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0})),
                 std::string("::"));
  ATF_REQUIRE_EQ(formatIp6(a6({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1})),
                 std::string("::1"));
  ATF_REQUIRE_EQ(formatIp6(a6({0xfe,0x80, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0})),
                 std::string("fe80::"));
  ATF_REQUIRE_EQ(formatIp6(a6({0xfd,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1})),
                 std::string("fd00::1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(formatIp6_no_collapse_when_no_runs);
ATF_TEST_CASE_BODY(formatIp6_no_collapse_when_no_runs) {
  // No two consecutive zero groups -> no collapse.
  ATF_REQUIRE_EQ(formatIp6(a6({0x20,0x01, 0x0d,0xb8, 0,1, 0,2, 0,3, 0,4, 0,5, 0,6})),
                 std::string("2001:db8:1:2:3:4:5:6"));
}

ATF_TEST_CASE_WITHOUT_HEAD(formatIp6_no_collapse_for_single_zero);
ATF_TEST_CASE_BODY(formatIp6_no_collapse_for_single_zero) {
  // RFC 5952 §4.2.2: don't collapse a single zero group.
  // 2001:db8:0:1:1:1:1:1 -> stays as-is (no "::" for one zero).
  ATF_REQUIRE_EQ(formatIp6(a6({0x20,0x01, 0x0d,0xb8, 0,0, 0,1, 0,1, 0,1, 0,1, 0,1})),
                 std::string("2001:db8:0:1:1:1:1:1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(formatIp6_lowercase_hex);
ATF_TEST_CASE_BODY(formatIp6_lowercase_hex) {
  // 2001:DB8::1 should round-trip to 2001:db8::1
  Addr6 a{};
  ATF_REQUIRE_EQ(parseIp6("2001:DB8::1", a), std::string());
  ATF_REQUIRE_EQ(formatIp6(a), std::string("2001:db8::1"));
}

// --- parseCidr6 ---

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr6_typical_accepted);
ATF_TEST_CASE_BODY(parseCidr6_typical_accepted) {
  Network6 n{};
  ATF_REQUIRE_EQ(parseCidr6("fd00::/64", n), std::string());
  ATF_REQUIRE_EQ(n.prefixLen, 64u);
  ATF_REQUIRE(n.base == a6({0xfd,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0}));

  ATF_REQUIRE_EQ(parseCidr6("2001:db8:1:2::/64", n), std::string());
  ATF_REQUIRE_EQ(n.prefixLen, 64u);

  ATF_REQUIRE_EQ(parseCidr6("::/1", n), std::string());
  ATF_REQUIRE_EQ(parseCidr6("fd00::/8", n), std::string());
  ATF_REQUIRE_EQ(parseCidr6("2001:db8::/128", n), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr6_rejects_unaligned);
ATF_TEST_CASE_BODY(parseCidr6_rejects_unaligned) {
  Network6 n{};
  // 2001:db8::1/64 has host bits set (the trailing ::1).
  auto err = parseCidr6("2001:db8::1/64", n);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("aligned") != std::string::npos);
  ATF_REQUIRE(!parseCidr6("fd00:0:0:1::/16", n).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr6_rejects_garbage);
ATF_TEST_CASE_BODY(parseCidr6_rejects_garbage) {
  Network6 n{};
  ATF_REQUIRE(!parseCidr6("",            n).empty());
  ATF_REQUIRE(!parseCidr6("fd00::",      n).empty());     // no slash
  ATF_REQUIRE(!parseCidr6("fd00:://64",  n).empty());     // double slash
  ATF_REQUIRE(!parseCidr6("fd00::/abc",  n).empty());     // non-numeric prefix
  ATF_REQUIRE(!parseCidr6("fd00::/0",    n).empty());     // prefix 0 rejected
  ATF_REQUIRE(!parseCidr6("fd00::/129",  n).empty());     // > 128
  ATF_REQUIRE(!parseCidr6("fd00::/-1",   n).empty());
}

// --- gatewayFor / allocateNext / inPool ---

ATF_TEST_CASE_WITHOUT_HEAD(gateway_is_base_plus_one);
ATF_TEST_CASE_BODY(gateway_is_base_plus_one) {
  Network6 n{};
  ATF_REQUIRE_EQ(parseCidr6("fd00::/64", n), std::string());
  auto g = gatewayFor(n);
  ATF_REQUIRE(g == a6({0xfd,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,1}));
  ATF_REQUIRE_EQ(formatIp6(g), std::string("fd00::1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(allocateNext_skips_base_and_gateway);
ATF_TEST_CASE_BODY(allocateNext_skips_base_and_gateway) {
  Network6 n{};
  parseCidr6("fd00::/64", n);
  auto a = allocateNext(n, {});
  // First pickable address is base + 2.
  ATF_REQUIRE(a == a6({0xfd,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,2}));
  ATF_REQUIRE_EQ(formatIp6(a), std::string("fd00::2"));
}

ATF_TEST_CASE_WITHOUT_HEAD(allocateNext_skips_taken);
ATF_TEST_CASE_BODY(allocateNext_skips_taken) {
  Network6 n{};
  parseCidr6("fd00::/64", n);
  auto two   = a6({0xfd,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,2});
  auto three = a6({0xfd,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,3});
  auto a = allocateNext(n, {two, three});
  ATF_REQUIRE(a == a6({0xfd,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,4}));
}

ATF_TEST_CASE_WITHOUT_HEAD(inPool_predicate);
ATF_TEST_CASE_BODY(inPool_predicate) {
  Network6 n{};
  parseCidr6("fd00::/64", n);
  ATF_REQUIRE( inPool(n, a6({0xfd,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,5})));
  ATF_REQUIRE( inPool(n, a6({0xfd,0, 0,0, 0,0, 0,0, 0xff,0xff, 0xff,0xff, 0xff,0xff, 0xff,0xff})));
  ATF_REQUIRE(!inPool(n, a6({0xfd,0, 0,0, 0,0, 0,1, 0,0, 0,0, 0,0, 0,0})));
  ATF_REQUIRE(!inPool(n, a6({0xfd,0xff, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0, 0,0})));
}

// --- Lease line round trip ---

ATF_TEST_CASE_WITHOUT_HEAD(lease_round_trip);
ATF_TEST_CASE_BODY(lease_round_trip) {
  Lease6 in;
  in.name = "jail-firefox-abcd";
  parseIp6("fd00::42", in.ip);
  auto line = formatLeaseLine6(in);
  ATF_REQUIRE_EQ(line, std::string("jail-firefox-abcd fd00::42"));
  Lease6 out;
  ATF_REQUIRE_EQ(parseLeaseLine6(line, out), std::string());
  ATF_REQUIRE_EQ(out.name, in.name);
  ATF_REQUIRE(out.ip == in.ip);
}

ATF_TEST_CASE_WITHOUT_HEAD(lease_parse_rejects_garbage);
ATF_TEST_CASE_BODY(lease_parse_rejects_garbage) {
  Lease6 out;
  ATF_REQUIRE(!parseLeaseLine6("",          out).empty());
  ATF_REQUIRE(!parseLeaseLine6("only-name", out).empty());
  ATF_REQUIRE(!parseLeaseLine6(" fd00::1",  out).empty());   // empty name
  ATF_REQUIRE(!parseLeaseLine6("name not-an-ip", out).empty());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, parseIp6_full_form);
  ATF_ADD_TEST_CASE(tcs, parseIp6_shorthand_middle);
  ATF_ADD_TEST_CASE(tcs, parseIp6_shorthand_at_ends);
  ATF_ADD_TEST_CASE(tcs, parseIp6_rejects_garbage);
  ATF_ADD_TEST_CASE(tcs, formatIp6_collapses_longest_zero_run);
  ATF_ADD_TEST_CASE(tcs, formatIp6_minimal_addresses);
  ATF_ADD_TEST_CASE(tcs, formatIp6_no_collapse_when_no_runs);
  ATF_ADD_TEST_CASE(tcs, formatIp6_no_collapse_for_single_zero);
  ATF_ADD_TEST_CASE(tcs, formatIp6_lowercase_hex);
  ATF_ADD_TEST_CASE(tcs, parseCidr6_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, parseCidr6_rejects_unaligned);
  ATF_ADD_TEST_CASE(tcs, parseCidr6_rejects_garbage);
  ATF_ADD_TEST_CASE(tcs, gateway_is_base_plus_one);
  ATF_ADD_TEST_CASE(tcs, allocateNext_skips_base_and_gateway);
  ATF_ADD_TEST_CASE(tcs, allocateNext_skips_taken);
  ATF_ADD_TEST_CASE(tcs, inPool_predicate);
  ATF_ADD_TEST_CASE(tcs, lease_round_trip);
  ATF_ADD_TEST_CASE(tcs, lease_parse_rejects_garbage);
}
