// ATF unit tests for Exception class (lib/err.h).
//
// Uses the real Exception type linked from lib/err.cpp + lib/util_pure.cpp.
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/err_test \
//       tests/unit/err_test.cpp lib/util_pure.cpp lib/err.cpp \
//       -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <cstring>
#include <exception>
#include <string>

#include "err.h"

ATF_TEST_CASE_WITHOUT_HEAD(exception_what_contains_loc_and_msg);
ATF_TEST_CASE_BODY(exception_what_contains_loc_and_msg)
{
	Exception e("spec parser", "unexpected key");
	std::string w = e.what();
	ATF_REQUIRE(w.find("spec parser") != std::string::npos);
	ATF_REQUIRE(w.find("unexpected key") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(exception_is_std_exception);
ATF_TEST_CASE_BODY(exception_is_std_exception)
{
	bool caught = false;
	try {
		throw Exception("test", "message");
	} catch (const std::exception &e) {
		caught = true;
		ATF_REQUIRE(std::strlen(e.what()) > 0);
	}
	ATF_REQUIRE(caught);
}

ATF_TEST_CASE_WITHOUT_HEAD(exception_empty_strings);
ATF_TEST_CASE_BODY(exception_empty_strings)
{
	Exception e("", "");
	ATF_REQUIRE(std::strlen(e.what()) > 0);  // at least ": "
}

ATF_TEST_CASE_WITHOUT_HEAD(exception_copy);
ATF_TEST_CASE_BODY(exception_copy)
{
	Exception e1("loc", "msg");
	Exception e2 = e1;
	ATF_REQUIRE_EQ(std::string(e1.what()), std::string(e2.what()));
}

// ERR2 macro round-trip — verify the macro throws with both location
// and a stream-formatted message. Catches a real-world regression
// where the macro was accidentally dropping the message.
ATF_TEST_CASE_WITHOUT_HEAD(err2_macro_throws_with_message);
ATF_TEST_CASE_BODY(err2_macro_throws_with_message)
{
	try {
		ERR2("test loc", "the answer is " << 42)
		ATF_REQUIRE(false);  // unreachable
	} catch (const Exception &e) {
		std::string w = e.what();
		ATF_REQUIRE(w.find("test loc") != std::string::npos);
		ATF_REQUIRE(w.find("the answer is 42") != std::string::npos);
	}
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, exception_what_contains_loc_and_msg);
	ATF_ADD_TEST_CASE(tcs, exception_is_std_exception);
	ATF_ADD_TEST_CASE(tcs, exception_empty_strings);
	ATF_ADD_TEST_CASE(tcs, exception_copy);
	ATF_ADD_TEST_CASE(tcs, err2_macro_throws_with_message);
}
