// ATF unit tests for IPv6 address validation.
//
// Uses real StackPure::isIpv6Address from lib/stack_pure.cpp
// (mirror of Net::isIpv6Address).

#include <atf-c++.hpp>
#include <string>

#include "stack_pure.h"

using StackPure::isIpv6Address;

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_loopback);
ATF_TEST_CASE_BODY(ipv6_loopback)
{
	ATF_REQUIRE(isIpv6Address("::1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_unspecified);
ATF_TEST_CASE_BODY(ipv6_unspecified)
{
	ATF_REQUIRE(isIpv6Address("::"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_full);
ATF_TEST_CASE_BODY(ipv6_full)
{
	ATF_REQUIRE(isIpv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_abbreviated);
ATF_TEST_CASE_BODY(ipv6_abbreviated)
{
	ATF_REQUIRE(isIpv6Address("2001:db8::1"));
	ATF_REQUIRE(isIpv6Address("fe80::1"));
	ATF_REQUIRE(isIpv6Address("fd00::50"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_link_local);
ATF_TEST_CASE_BODY(ipv6_link_local)
{
	ATF_REQUIRE(isIpv6Address("fe80::1:2:3:4"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_not_ipv4);
ATF_TEST_CASE_BODY(ipv6_not_ipv4)
{
	ATF_REQUIRE(!isIpv6Address("192.168.1.1"));
	ATF_REQUIRE(!isIpv6Address("10.0.0.1"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_not_garbage);
ATF_TEST_CASE_BODY(ipv6_not_garbage)
{
	ATF_REQUIRE(!isIpv6Address(""));
	ATF_REQUIRE(!isIpv6Address("not-an-address"));
	ATF_REQUIRE(!isIpv6Address("12345"));
	ATF_REQUIRE(!isIpv6Address("::gggg"));
}

ATF_TEST_CASE_WITHOUT_HEAD(ipv6_mapped_v4);
ATF_TEST_CASE_BODY(ipv6_mapped_v4)
{
	ATF_REQUIRE(isIpv6Address("::ffff:192.168.1.1"));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, ipv6_loopback);
	ATF_ADD_TEST_CASE(tcs, ipv6_unspecified);
	ATF_ADD_TEST_CASE(tcs, ipv6_full);
	ATF_ADD_TEST_CASE(tcs, ipv6_abbreviated);
	ATF_ADD_TEST_CASE(tcs, ipv6_link_local);
	ATF_ADD_TEST_CASE(tcs, ipv6_not_ipv4);
	ATF_ADD_TEST_CASE(tcs, ipv6_not_garbage);
	ATF_ADD_TEST_CASE(tcs, ipv6_mapped_v4);
}
