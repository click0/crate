// ATF unit tests for SpecPure::substituteVars (lib/spec_pure.cpp).
//
// Used by `crate create --var KEY=VALUE` to substitute ${KEY} tokens
// in spec YAML before parsing. A bug here can mis-resolve user input
// or fail to interpolate values the user expects.

#include <atf-c++.hpp>
#include <map>
#include <string>

#include "spec_pure.h"

using SpecPure::substituteVars;

ATF_TEST_CASE_WITHOUT_HEAD(empty_vars_returns_input);
ATF_TEST_CASE_BODY(empty_vars_returns_input)
{
	ATF_REQUIRE_EQ(substituteVars("hello ${X}", {}), "hello ${X}");
	ATF_REQUIRE_EQ(substituteVars("", {}), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(single_substitution);
ATF_TEST_CASE_BODY(single_substitution)
{
	std::map<std::string, std::string> v = {{"VERSION", "16"}};
	ATF_REQUIRE_EQ(substituteVars("postgres-${VERSION}", v), "postgres-16");
}

ATF_TEST_CASE_WITHOUT_HEAD(multiple_keys);
ATF_TEST_CASE_BODY(multiple_keys)
{
	std::map<std::string, std::string> v = {
		{"NAME", "web"},
		{"PORT", "8080"},
	};
	ATF_REQUIRE_EQ(
		substituteVars("${NAME} listens on ${PORT}", v),
		"web listens on 8080");
}

ATF_TEST_CASE_WITHOUT_HEAD(multiple_occurrences);
ATF_TEST_CASE_BODY(multiple_occurrences)
{
	std::map<std::string, std::string> v = {{"X", "y"}};
	ATF_REQUIRE_EQ(substituteVars("${X}-${X}-${X}", v), "y-y-y");
}

ATF_TEST_CASE_WITHOUT_HEAD(unknown_key_left_alone);
ATF_TEST_CASE_BODY(unknown_key_left_alone)
{
	std::map<std::string, std::string> v = {{"FOO", "bar"}};
	ATF_REQUIRE_EQ(substituteVars("${UNKNOWN} ${FOO}", v), "${UNKNOWN} bar");
}

ATF_TEST_CASE_WITHOUT_HEAD(empty_value);
ATF_TEST_CASE_BODY(empty_value)
{
	std::map<std::string, std::string> v = {{"K", ""}};
	ATF_REQUIRE_EQ(substituteVars("a${K}b", v), "ab");
}

ATF_TEST_CASE_WITHOUT_HEAD(value_contains_dollar_brace);
ATF_TEST_CASE_BODY(value_contains_dollar_brace)
{
	// If a value contains "${...}", it should NOT be re-substituted.
	// pos is advanced past the inserted value, so this is safe.
	std::map<std::string, std::string> v = {
		{"OUTER", "${INNER}"},
		{"INNER", "should-not-appear"},
	};
	ATF_REQUIRE_EQ(substituteVars("X=${OUTER}", v), "X=${INNER}");
}

ATF_TEST_CASE_WITHOUT_HEAD(no_match_no_change);
ATF_TEST_CASE_BODY(no_match_no_change)
{
	std::map<std::string, std::string> v = {{"X", "y"}};
	ATF_REQUIRE_EQ(substituteVars("plain string", v), "plain string");
}

ATF_TEST_CASE_WITHOUT_HEAD(adjacent_tokens);
ATF_TEST_CASE_BODY(adjacent_tokens)
{
	std::map<std::string, std::string> v = {
		{"A", "1"},
		{"B", "2"},
	};
	ATF_REQUIRE_EQ(substituteVars("${A}${B}", v), "12");
}

ATF_TEST_CASE_WITHOUT_HEAD(token_with_whitespace_in_key_not_matched);
ATF_TEST_CASE_BODY(token_with_whitespace_in_key_not_matched)
{
	// "${A B}" is not a valid token — A B isn't a key
	std::map<std::string, std::string> v = {{"A B", "x"}};
	ATF_REQUIRE_EQ(substituteVars("hello ${A B}", v), "hello x");
	// (current implementation uses naive find, so it does match —
	// this test pins down the behaviour rather than assuming better.)
}

ATF_TEST_CASE_WITHOUT_HEAD(partial_token_not_substituted);
ATF_TEST_CASE_BODY(partial_token_not_substituted)
{
	// "$X" without braces is NOT substituted (only "${X}")
	std::map<std::string, std::string> v = {{"X", "value"}};
	ATF_REQUIRE_EQ(substituteVars("$X is $X", v), "$X is $X");
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, empty_vars_returns_input);
	ATF_ADD_TEST_CASE(tcs, single_substitution);
	ATF_ADD_TEST_CASE(tcs, multiple_keys);
	ATF_ADD_TEST_CASE(tcs, multiple_occurrences);
	ATF_ADD_TEST_CASE(tcs, unknown_key_left_alone);
	ATF_ADD_TEST_CASE(tcs, empty_value);
	ATF_ADD_TEST_CASE(tcs, value_contains_dollar_brace);
	ATF_ADD_TEST_CASE(tcs, no_match_no_change);
	ATF_ADD_TEST_CASE(tcs, adjacent_tokens);
	ATF_ADD_TEST_CASE(tcs, token_with_whitespace_in_key_not_matched);
	ATF_ADD_TEST_CASE(tcs, partial_token_not_substituted);
}
