// ATF unit tests for Net::isIpv6Address
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/network_ipv6_test \
//       tests/unit/network_ipv6_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>

// ===================================================================
// Local copy of isIpv6Address from lib/net.cpp
// ===================================================================

static bool isIpv6Address(const std::string &addr) {
	struct in6_addr result;
	return ::inet_pton(AF_INET6, addr.c_str(), &result) == 1;
}

// ===================================================================
// Tests: isIpv6Address
// ===================================================================

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
	// IPv4-mapped IPv6 address
	ATF_REQUIRE(isIpv6Address("::ffff:192.168.1.1"));
}

// ===================================================================
// Registration
// ===================================================================

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
