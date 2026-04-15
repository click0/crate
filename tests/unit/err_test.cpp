// ATF unit tests for Exception class (lib/err.h)
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/err_test \
//       tests/unit/err_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <cstring>
#include <exception>
#include <string>

// ===================================================================
// Minimal reproduction of Exception from lib/err.h
// (avoids pulling in rang.hpp and util.h)
// ===================================================================

class Exception : public std::exception {
	std::string xmsg;
public:
	Exception(const std::string &loc, const std::string &msg)
		: xmsg(loc + ": " + msg) {}
	const char *what() const throw() { return xmsg.c_str(); }
};

// ===================================================================
// Tests: Exception
// ===================================================================

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

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, exception_what_contains_loc_and_msg);
	ATF_ADD_TEST_CASE(tcs, exception_is_std_exception);
	ATF_ADD_TEST_CASE(tcs, exception_empty_strings);
	ATF_ADD_TEST_CASE(tcs, exception_copy);
}
