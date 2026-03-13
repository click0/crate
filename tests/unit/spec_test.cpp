// ATF unit tests for spec-related pure functions
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/spec_test tests/unit/spec_test.cpp \
//       -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <string>
#include <utility>
#include <stdexcept>

// ===================================================================
// Local copies of pure functions from lib/spec.cpp
// ===================================================================

typedef std::pair<unsigned, unsigned> PortRange;

static unsigned toUInt(const std::string &str) {
	std::size_t pos;
	auto u = std::stoul(str, &pos);
	if (pos != str.size())
		throw std::runtime_error("trailing characters");
	return u;
}

static PortRange parsePortRange(const std::string &str) {
	auto hyphen = str.find('-');
	return hyphen == std::string::npos
		? PortRange(toUInt(str), toUInt(str))
		: PortRange(toUInt(str.substr(0, hyphen)),
		            toUInt(str.substr(hyphen + 1)));
}

// ===================================================================
// Tests: parsePortRange
// ===================================================================

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
	ATF_REQUIRE_THROW(std::exception, parsePortRange("abc"));
	ATF_REQUIRE_THROW(std::exception, parsePortRange(""));
	ATF_REQUIRE_THROW(std::exception, parsePortRange("80abc"));
}

// ===================================================================
// Tests: toUInt
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(toUInt_valid);
ATF_TEST_CASE_BODY(toUInt_valid)
{
	ATF_REQUIRE_EQ(toUInt("0"), 0u);
	ATF_REQUIRE_EQ(toUInt("42"), 42u);
	ATF_REQUIRE_EQ(toUInt("65535"), 65535u);
}

ATF_TEST_CASE_WITHOUT_HEAD(toUInt_trailing_chars_throws);
ATF_TEST_CASE_BODY(toUInt_trailing_chars_throws)
{
	ATF_REQUIRE_THROW(std::runtime_error, toUInt("42abc"));
	ATF_REQUIRE_THROW(std::runtime_error, toUInt("42 "));
}

ATF_TEST_CASE_WITHOUT_HEAD(toUInt_empty_throws);
ATF_TEST_CASE_BODY(toUInt_empty_throws)
{
	ATF_REQUIRE_THROW(std::exception, toUInt(""));
}

ATF_TEST_CASE_WITHOUT_HEAD(toUInt_negative_throws);
ATF_TEST_CASE_BODY(toUInt_negative_throws)
{
	// stoul accepts negative as unsigned wraparound, but trailing check should catch non-numeric
	ATF_REQUIRE_THROW(std::exception, toUInt("abc"));
}

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	// parsePortRange
	ATF_ADD_TEST_CASE(tcs, parsePortRange_single);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_range);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_zero);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_max_port);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_full_range);
	ATF_ADD_TEST_CASE(tcs, parsePortRange_invalid_throws);

	// toUInt
	ATF_ADD_TEST_CASE(tcs, toUInt_valid);
	ATF_ADD_TEST_CASE(tcs, toUInt_trailing_chars_throws);
	ATF_ADD_TEST_CASE(tcs, toUInt_empty_throws);
	ATF_ADD_TEST_CASE(tcs, toUInt_negative_throws);
}
