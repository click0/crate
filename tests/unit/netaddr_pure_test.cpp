// ATF unit tests for NetAddrPure (lib/netaddr_pure.cpp).
//
// The shared IP-address / hostname predicates (1.1.30) behind
// wireguard_pure, ipsec_pure, migrate_pure, replicate_pure and
// throttle_pure. Those modules' own tests still exercise them end to
// end through each validator; these pin the predicates directly so a
// change here is caught once, not five times.

#include <atf-c++.hpp>
#include <string>

#include "netaddr_pure.h"

using NetAddrPure::isV4Octet;
using NetAddrPure::isV4;
using NetAddrPure::isV6;
using NetAddrPure::looksLikeV4Shape;
using NetAddrPure::isHostname;

ATF_TEST_CASE_WITHOUT_HEAD(v4_octet);
ATF_TEST_CASE_BODY(v4_octet)
{
	ATF_REQUIRE(isV4Octet("0"));
	ATF_REQUIRE(isV4Octet("255"));
	ATF_REQUIRE(isV4Octet("010"));          // leading zero accepted (as before)
	ATF_REQUIRE(!isV4Octet(""));
	ATF_REQUIRE(!isV4Octet("256"));
	ATF_REQUIRE(!isV4Octet("1234"));
	ATF_REQUIRE(!isV4Octet("-1"));
	ATF_REQUIRE(!isV4Octet("1a"));
}

ATF_TEST_CASE_WITHOUT_HEAD(v4);
ATF_TEST_CASE_BODY(v4)
{
	ATF_REQUIRE(isV4("10.0.0.1"));
	ATF_REQUIRE(isV4("0.0.0.0"));
	ATF_REQUIRE(isV4("255.255.255.255"));
	ATF_REQUIRE(!isV4("256.0.0.1"));
	ATF_REQUIRE(!isV4("10.0.0"));
	ATF_REQUIRE(!isV4("10.0.0.1.2"));
	ATF_REQUIRE(!isV4("10..0.1"));
	ATF_REQUIRE(!isV4("10.0.0.1 "));
	ATF_REQUIRE(!isV4(""));
}

ATF_TEST_CASE_WITHOUT_HEAD(v6);
ATF_TEST_CASE_BODY(v6)
{
	ATF_REQUIRE(isV6("::1"));
	ATF_REQUIRE(isV6("fd00::1"));
	ATF_REQUIRE(isV6("2001:db8:0:0:0:0:0:1"));
	ATF_REQUIRE(isV6("FD00::ABCD"));
	ATF_REQUIRE(!isV6(""));
	ATF_REQUIRE(!isV6("1::2::3"));           // two "::"
	ATF_REQUIRE(!isV6("2001:db8:0:0:0:0:0"));  // 7 groups, no "::"
	ATF_REQUIRE(!isV6("fe80::1%vtnet0"));    // zone suffix not accepted
	ATF_REQUIRE(!isV6("g::1"));
	ATF_REQUIRE(isV6("::"));                 // unspecified address
	ATF_REQUIRE(isV6("1::"));
}

// 1.1.30: bugs shared by all five former private copies, found when
// the consolidated predicate got its own direct tests.
ATF_TEST_CASE_WITHOUT_HEAD(v6_rejects_unseparated_and_stray_colons);
ATF_TEST_CASE_BODY(v6_rejects_unseparated_and_stray_colons)
{
	ATF_REQUIRE(!isV6("12345::1"));          // 5 hex digits in one group
	ATF_REQUIRE(!isV6("fd001::1"));
	ATF_REQUIRE(!isV6(std::string(32, 'a')));    // 32 hex, no colons at all
	ATF_REQUIRE(!isV6("1:2:3:4:5:6:7:8:"));  // trailing single colon
	ATF_REQUIRE(!isV6("1:::2"));             // single colon right after "::"
	ATF_REQUIRE(!isV6(":1:2"));              // leading single colon
	// …while every well-formed spelling still passes.
	ATF_REQUIRE(isV6("1:2:3:4:5:6:7:8"));
	ATF_REQUIRE(isV6("::1:2"));
	ATF_REQUIRE(isV6("fe80::abcd:1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(v4_shape);
ATF_TEST_CASE_BODY(v4_shape)
{
	ATF_REQUIRE(looksLikeV4Shape("256.0.0.1"));   // shape only, not range
	ATF_REQUIRE(looksLikeV4Shape("1.2"));
	ATF_REQUIRE(!looksLikeV4Shape("123"));        // needs a dot
	ATF_REQUIRE(!looksLikeV4Shape("a.b"));
	ATF_REQUIRE(!looksLikeV4Shape(""));
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname);
ATF_TEST_CASE_BODY(hostname)
{
	ATF_REQUIRE(isHostname("localhost"));
	ATF_REQUIRE(isHostname("alpha.example.com"));
	ATF_REQUIRE(isHostname("a-b.c1"));
	ATF_REQUIRE(isHostname(std::string(63, 'a')));
	ATF_REQUIRE(!isHostname(std::string(64, 'a')));     // label > 63
	ATF_REQUIRE(!isHostname(""));
	ATF_REQUIRE(!isHostname("-lead.example"));
	ATF_REQUIRE(!isHostname("trail-.example"));
	ATF_REQUIRE(!isHostname("a..b"));                   // empty label
	ATF_REQUIRE(!isHostname("a_b.example"));
	ATF_REQUIRE(!isHostname("a.b;rm"));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, v4_octet);
	ATF_ADD_TEST_CASE(tcs, v4);
	ATF_ADD_TEST_CASE(tcs, v6);
	ATF_ADD_TEST_CASE(tcs, v6_rejects_unseparated_and_stray_colons);
	ATF_ADD_TEST_CASE(tcs, v4_shape);
	ATF_ADD_TEST_CASE(tcs, hostname);
}
