// ATF unit tests for CIDR/IP helpers from lib/stack.cpp.
//
// Uses real StackPure:: symbols from lib/stack_pure.cpp.

#include <atf-c++.hpp>
#include <cstdint>
#include <string>

#include "stack_pure.h"

using StackPure::parseCidr;
using StackPure::ipToString;

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_class_c);
ATF_TEST_CASE_BODY(parseCidr_class_c)
{
	uint32_t base;
	unsigned prefix;
	ATF_REQUIRE(parseCidr("192.168.1.0/24", base, prefix));
	ATF_REQUIRE_EQ(prefix, 24u);
	ATF_REQUIRE_EQ(ipToString(base), "192.168.1.0");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_class_a);
ATF_TEST_CASE_BODY(parseCidr_class_a)
{
	uint32_t base;
	unsigned prefix;
	ATF_REQUIRE(parseCidr("10.0.0.0/8", base, prefix));
	ATF_REQUIRE_EQ(prefix, 8u);
	ATF_REQUIRE_EQ(ipToString(base), "10.0.0.0");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_host);
ATF_TEST_CASE_BODY(parseCidr_host)
{
	uint32_t base;
	unsigned prefix;
	ATF_REQUIRE(parseCidr("10.0.0.1/32", base, prefix));
	ATF_REQUIRE_EQ(prefix, 32u);
	ATF_REQUIRE_EQ(ipToString(base), "10.0.0.1");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_no_slash_fails);
ATF_TEST_CASE_BODY(parseCidr_no_slash_fails)
{
	uint32_t base;
	unsigned prefix;
	ATF_REQUIRE(!parseCidr("10.0.0.0", base, prefix));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_invalid_addr_fails);
ATF_TEST_CASE_BODY(parseCidr_invalid_addr_fails)
{
	uint32_t base;
	unsigned prefix;
	ATF_REQUIRE(!parseCidr("999.999.999.999/24", base, prefix));
	ATF_REQUIRE(!parseCidr("not-an-ip/24", base, prefix));
}

ATF_TEST_CASE_WITHOUT_HEAD(parseCidr_private_ranges);
ATF_TEST_CASE_BODY(parseCidr_private_ranges)
{
	uint32_t base;
	unsigned prefix;

	ATF_REQUIRE(parseCidr("172.16.0.0/12", base, prefix));
	ATF_REQUIRE_EQ(prefix, 12u);
	ATF_REQUIRE_EQ(ipToString(base), "172.16.0.0");

	ATF_REQUIRE(parseCidr("192.168.0.0/16", base, prefix));
	ATF_REQUIRE_EQ(prefix, 16u);
	ATF_REQUIRE_EQ(ipToString(base), "192.168.0.0");
}

ATF_TEST_CASE_WITHOUT_HEAD(ipToString_zero);
ATF_TEST_CASE_BODY(ipToString_zero)
{
	ATF_REQUIRE_EQ(ipToString(0), "0.0.0.0");
}

ATF_TEST_CASE_WITHOUT_HEAD(ipToString_loopback);
ATF_TEST_CASE_BODY(ipToString_loopback)
{
	ATF_REQUIRE_EQ(ipToString(0x7F000001), "127.0.0.1");
}

ATF_TEST_CASE_WITHOUT_HEAD(ipToString_broadcast);
ATF_TEST_CASE_BODY(ipToString_broadcast)
{
	ATF_REQUIRE_EQ(ipToString(0xFFFFFFFF), "255.255.255.255");
}

ATF_TEST_CASE_WITHOUT_HEAD(ipToString_roundtrip);
ATF_TEST_CASE_BODY(ipToString_roundtrip)
{
	uint32_t base;
	unsigned prefix;
	ATF_REQUIRE(parseCidr("10.20.30.40/24", base, prefix));
	ATF_REQUIRE_EQ(ipToString(base), "10.20.30.40");
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, parseCidr_class_c);
	ATF_ADD_TEST_CASE(tcs, parseCidr_class_a);
	ATF_ADD_TEST_CASE(tcs, parseCidr_host);
	ATF_ADD_TEST_CASE(tcs, parseCidr_no_slash_fails);
	ATF_ADD_TEST_CASE(tcs, parseCidr_invalid_addr_fails);
	ATF_ADD_TEST_CASE(tcs, parseCidr_private_ranges);
	ATF_ADD_TEST_CASE(tcs, ipToString_zero);
	ATF_ADD_TEST_CASE(tcs, ipToString_loopback);
	ATF_ADD_TEST_CASE(tcs, ipToString_broadcast);
	ATF_ADD_TEST_CASE(tcs, ipToString_roundtrip);
}
