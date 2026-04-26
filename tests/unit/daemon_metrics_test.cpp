// ATF unit tests for parseRctlUsage from daemon/metrics.cpp
//
// Build:
//   c++ -std=c++17 -o tests/unit/daemon_metrics_test \
//       tests/unit/daemon_metrics_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <map>
#include <sstream>
#include <string>

// ===================================================================
// Local copy of pure parser from daemon/metrics.cpp
// ===================================================================

static std::map<std::string, std::string> parseRctlUsage(const std::string &rctlOutput) {
	std::map<std::string, std::string> result;
	std::istringstream is(rctlOutput);
	std::string line;
	while (std::getline(is, line)) {
		auto eqPos = line.find('=');
		if (eqPos == std::string::npos) continue;
		result[line.substr(0, eqPos)] = line.substr(eqPos + 1);
	}
	return result;
}

// ===================================================================
// Tests
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_empty);
ATF_TEST_CASE_BODY(parseRctl_empty)
{
	auto m = parseRctlUsage("");
	ATF_REQUIRE_EQ(m.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_single_pair);
ATF_TEST_CASE_BODY(parseRctl_single_pair)
{
	auto m = parseRctlUsage("cputime=42\n");
	ATF_REQUIRE_EQ(m.size(), 1u);
	ATF_REQUIRE_EQ(m["cputime"], "42");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_typical_output);
ATF_TEST_CASE_BODY(parseRctl_typical_output)
{
	// Realistic rctl -u output for a jail
	std::string raw =
		"cputime=123\n"
		"datasize=1048576\n"
		"stacksize=8192\n"
		"coredumpsize=0\n"
		"memoryuse=4194304\n"
		"memorylocked=0\n"
		"maxproc=12\n"
		"openfiles=64\n";
	auto m = parseRctlUsage(raw);
	ATF_REQUIRE_EQ(m.size(), 8u);
	ATF_REQUIRE_EQ(m["memoryuse"], "4194304");
	ATF_REQUIRE_EQ(m["maxproc"], "12");
	ATF_REQUIRE_EQ(m["coredumpsize"], "0");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_no_trailing_newline);
ATF_TEST_CASE_BODY(parseRctl_no_trailing_newline)
{
	// Last line without trailing \n must still be parsed
	auto m = parseRctlUsage("a=1\nb=2");
	ATF_REQUIRE_EQ(m.size(), 2u);
	ATF_REQUIRE_EQ(m["a"], "1");
	ATF_REQUIRE_EQ(m["b"], "2");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_skips_lines_without_eq);
ATF_TEST_CASE_BODY(parseRctl_skips_lines_without_eq)
{
	// Header lines, blanks, garbage — anything without '=' is silently dropped
	auto m = parseRctlUsage("# comment\n\nkey=value\nbroken\n");
	ATF_REQUIRE_EQ(m.size(), 1u);
	ATF_REQUIRE_EQ(m["key"], "value");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_value_with_equals);
ATF_TEST_CASE_BODY(parseRctl_value_with_equals)
{
	// First '=' is the separator; subsequent ones belong to the value
	auto m = parseRctlUsage("key=a=b=c\n");
	ATF_REQUIRE_EQ(m.size(), 1u);
	ATF_REQUIRE_EQ(m["key"], "a=b=c");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_empty_value);
ATF_TEST_CASE_BODY(parseRctl_empty_value)
{
	auto m = parseRctlUsage("empty=\n");
	ATF_REQUIRE_EQ(m.size(), 1u);
	ATF_REQUIRE_EQ(m["empty"], "");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_empty_key);
ATF_TEST_CASE_BODY(parseRctl_empty_key)
{
	// "=value" — empty key, parser keeps it (no validation)
	auto m = parseRctlUsage("=orphan\n");
	ATF_REQUIRE_EQ(m.size(), 1u);
	ATF_REQUIRE_EQ(m[""], "orphan");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseRctl_duplicate_key_last_wins);
ATF_TEST_CASE_BODY(parseRctl_duplicate_key_last_wins)
{
	auto m = parseRctlUsage("k=1\nk=2\nk=3\n");
	ATF_REQUIRE_EQ(m.size(), 1u);
	ATF_REQUIRE_EQ(m["k"], "3");
}

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, parseRctl_empty);
	ATF_ADD_TEST_CASE(tcs, parseRctl_single_pair);
	ATF_ADD_TEST_CASE(tcs, parseRctl_typical_output);
	ATF_ADD_TEST_CASE(tcs, parseRctl_no_trailing_newline);
	ATF_ADD_TEST_CASE(tcs, parseRctl_skips_lines_without_eq);
	ATF_ADD_TEST_CASE(tcs, parseRctl_value_with_equals);
	ATF_ADD_TEST_CASE(tcs, parseRctl_empty_value);
	ATF_ADD_TEST_CASE(tcs, parseRctl_empty_key);
	ATF_ADD_TEST_CASE(tcs, parseRctl_duplicate_key_last_wins);
}
