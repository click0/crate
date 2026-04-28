// ATF unit tests for RunPure helpers (lib/run_pure.cpp).

#include <atf-c++.hpp>
#include <cstdlib>
#include <string>

#include "run_pure.h"

ATF_TEST_CASE_WITHOUT_HEAD(argsToString_empty);
ATF_TEST_CASE_BODY(argsToString_empty)
{
	ATF_REQUIRE_EQ(RunPure::argsToString(0, nullptr), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(argsToString_basic);
ATF_TEST_CASE_BODY(argsToString_basic)
{
	char a[] = "crate";
	char b[] = "run";
	char c[] = "/tmp/foo.crate";
	char *argv[] = {a, b, c};
	auto out = RunPure::argsToString(3, argv);
	// Each arg single-quoted with leading space.
	ATF_REQUIRE_EQ(out, " 'crate' 'run' '/tmp/foo.crate'");
}

ATF_TEST_CASE_WITHOUT_HEAD(argsToString_quotes_special);
ATF_TEST_CASE_BODY(argsToString_quotes_special)
{
	char a[] = "echo";
	char b[] = "$(rm -rf /)";
	char *argv[] = {a, b};
	auto out = RunPure::argsToString(2, argv);
	// shellQuote wraps the second arg without expanding.
	ATF_REQUIRE_EQ(out, " 'echo' '$(rm -rf /)'");
}

ATF_TEST_CASE_WITHOUT_HEAD(envOrDefault_unset_returns_default);
ATF_TEST_CASE_BODY(envOrDefault_unset_returns_default)
{
	::unsetenv("CRATE_TEST_ENV_NOPE");
	ATF_REQUIRE_EQ(RunPure::envOrDefault("CRATE_TEST_ENV_NOPE", 42u), 42u);
}

ATF_TEST_CASE_WITHOUT_HEAD(envOrDefault_set_valid);
ATF_TEST_CASE_BODY(envOrDefault_set_valid)
{
	::setenv("CRATE_TEST_ENV_VAL", "1234", 1);
	ATF_REQUIRE_EQ(RunPure::envOrDefault("CRATE_TEST_ENV_VAL", 0u), 1234u);
	::unsetenv("CRATE_TEST_ENV_VAL");
}

ATF_TEST_CASE_WITHOUT_HEAD(envOrDefault_set_garbage_returns_default);
ATF_TEST_CASE_BODY(envOrDefault_set_garbage_returns_default)
{
	::setenv("CRATE_TEST_ENV_BAD", "not-a-number", 1);
	ATF_REQUIRE_EQ(RunPure::envOrDefault("CRATE_TEST_ENV_BAD", 99u), 99u);
	::unsetenv("CRATE_TEST_ENV_BAD");
}

ATF_TEST_CASE_WITHOUT_HEAD(envOrDefault_set_empty_returns_default);
ATF_TEST_CASE_BODY(envOrDefault_set_empty_returns_default)
{
	::setenv("CRATE_TEST_ENV_EMPTY", "", 1);
	// "" → toUInt throws "invalid numeric string" → catch returns def
	ATF_REQUIRE_EQ(RunPure::envOrDefault("CRATE_TEST_ENV_EMPTY", 7u), 7u);
	::unsetenv("CRATE_TEST_ENV_EMPTY");
}

ATF_TEST_CASE_WITHOUT_HEAD(envOrDefault_overflow_returns_default);
ATF_TEST_CASE_BODY(envOrDefault_overflow_returns_default)
{
	// >UINT_MAX — 0.4.5's toUInt rejects this, so envOrDefault falls back.
	::setenv("CRATE_TEST_ENV_BIG", "99999999999", 1);
	ATF_REQUIRE_EQ(RunPure::envOrDefault("CRATE_TEST_ENV_BIG", 5u), 5u);
	::unsetenv("CRATE_TEST_ENV_BIG");
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, argsToString_empty);
	ATF_ADD_TEST_CASE(tcs, argsToString_basic);
	ATF_ADD_TEST_CASE(tcs, argsToString_quotes_special);
	ATF_ADD_TEST_CASE(tcs, envOrDefault_unset_returns_default);
	ATF_ADD_TEST_CASE(tcs, envOrDefault_set_valid);
	ATF_ADD_TEST_CASE(tcs, envOrDefault_set_garbage_returns_default);
	ATF_ADD_TEST_CASE(tcs, envOrDefault_set_empty_returns_default);
	ATF_ADD_TEST_CASE(tcs, envOrDefault_overflow_returns_default);
}
