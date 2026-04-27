// ATF unit tests for pure helpers from lib/spec.cpp + lib/util.cpp.
//
// Uses real SpecPure::parsePortRange (from lib/spec_pure.cpp) and
// Util::toUInt (from lib/util_pure.cpp).

#include <atf-c++.hpp>

#include "spec_pure.h"
#include "util.h"
#include "err.h"

using SpecPure::PortRange;
using SpecPure::parsePortRange;
using Util::toUInt;

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_single);
ATF_TEST_CASE_BODY(parsePortRange_single)
{
	auto r = parsePortRange("8080");
	ATF_REQUIRE_EQ(r.first, 8080u);
	ATF_REQUIRE_EQ(r.second, 8080u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_range);
ATF_TEST_CASE_BODY(parsePortRange_range)
{
	auto r = parsePortRange("1000-2000");
	ATF_REQUIRE_EQ(r.first, 1000u);
	ATF_REQUIRE_EQ(r.second, 2000u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_zero);
ATF_TEST_CASE_BODY(parsePortRange_zero)
{
	auto r = parsePortRange("0");
	ATF_REQUIRE_EQ(r.first, 0u);
	ATF_REQUIRE_EQ(r.second, 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_max_port);
ATF_TEST_CASE_BODY(parsePortRange_max_port)
{
	auto r = parsePortRange("65535");
	ATF_REQUIRE_EQ(r.first, 65535u);
	ATF_REQUIRE_EQ(r.second, 65535u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_full_range);
ATF_TEST_CASE_BODY(parsePortRange_full_range)
{
	auto r = parsePortRange("1-65535");
	ATF_REQUIRE_EQ(r.first, 1u);
	ATF_REQUIRE_EQ(r.second, 65535u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parsePortRange_invalid_throws);
ATF_TEST_CASE_BODY(parsePortRange_invalid_throws)
{
	ATF_REQUIRE_THROW(Exception, parsePortRange("abc"));
	ATF_REQUIRE_THROW(Exception, parsePortRange(""));
	ATF_REQUIRE_THROW(Exception, parsePortRange("80abc"));
}

ATF_TEST_CASE_WITHOUT_HEAD(toUInt_valid);
ATF_TEST_CASE_BODY(toUInt_valid)
{
	ATF_REQUIRE_EQ(toUInt("0"), 0u);
	ATF_REQUIRE_EQ(toUInt("1"), 1u);
	ATF_REQUIRE_EQ(toUInt("8080"), 8080u);
	ATF_REQUIRE_EQ(toUInt("4294967295"), 4294967295u);  // UINT32_MAX
}

ATF_TEST_CASE_WITHOUT_HEAD(toUInt_invalid_throws);
ATF_TEST_CASE_BODY(toUInt_invalid_throws)
{
	ATF_REQUIRE_THROW(Exception, toUInt("abc"));
	ATF_REQUIRE_THROW(Exception, toUInt(""));
	ATF_REQUIRE_THROW(Exception, toUInt("80abc"));
	ATF_REQUIRE_THROW(Exception, toUInt(" "));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, parsePortRange_single);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_range);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_zero);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_max_port);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_full_range);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_invalid_throws);
	ATF_ADD_TEST_CASE(tcs, toUInt_valid);
	ATF_ADD_TEST_CASE(tcs, toUInt_invalid_throws);
}
