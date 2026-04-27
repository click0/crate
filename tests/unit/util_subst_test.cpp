// ATF unit tests for variable-substitution helpers in lib/util.cpp.
//
// Uses real Util::pathSubstituteVarsInPath / Util::pathSubstituteVarsInString
// (now in lib/util_pure.cpp). These run before any setuid-root operation,
// so a regression here can mis-resolve paths into unintended locations.

#include <atf-c++.hpp>
#include <cstdlib>
#include <pwd.h>
#include <string>
#include <unistd.h>

#include "util.h"

// Resolve the runtime user's $HOME via getpwuid for cross-checks.
static std::string realHome() {
	auto *pw = ::getpwuid(::getuid());
	return pw && pw->pw_dir ? pw->pw_dir : "";
}

static std::string realUser() {
	auto *pw = ::getpwuid(::getuid());
	return pw && pw->pw_name ? pw->pw_name : "";
}

// ===================================================================
// Util::pathSubstituteVarsInPath — only $HOME at the start
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(pathSubst_no_var);
ATF_TEST_CASE_BODY(pathSubst_no_var)
{
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInPath("/usr/local/etc"), "/usr/local/etc");
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInPath(""), "");
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInPath("relative/path"), "relative/path");
}

ATF_TEST_CASE_WITHOUT_HEAD(pathSubst_home_at_start);
ATF_TEST_CASE_BODY(pathSubst_home_at_start)
{
	auto out = Util::pathSubstituteVarsInPath("$HOME/.config/crate");
	auto expected = realHome() + "/.config/crate";
	ATF_REQUIRE_EQ(out, expected);
}

ATF_TEST_CASE_WITHOUT_HEAD(pathSubst_home_only_at_start);
ATF_TEST_CASE_BODY(pathSubst_home_only_at_start)
{
	// $HOME in the middle is NOT substituted by pathSubstituteVarsInPath
	auto out = Util::pathSubstituteVarsInPath("/etc/$HOME/file");
	ATF_REQUIRE_EQ(out, "/etc/$HOME/file");
}

ATF_TEST_CASE_WITHOUT_HEAD(pathSubst_short_input);
ATF_TEST_CASE_BODY(pathSubst_short_input)
{
	// "$HOME" alone is exactly 5 chars; the `> 5` check means it stays.
	// This documents the current (slightly counter-intuitive) behaviour.
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInPath("$HOME"), "$HOME");
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInPath("$HOM"), "$HOM");
}

// ===================================================================
// Util::pathSubstituteVarsInString — $HOME and $USER anywhere
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(stringSubst_home);
ATF_TEST_CASE_BODY(stringSubst_home)
{
	auto out = Util::pathSubstituteVarsInString("home is $HOME, ok");
	auto expected = "home is " + realHome() + ", ok";
	ATF_REQUIRE_EQ(out, expected);
}

ATF_TEST_CASE_WITHOUT_HEAD(stringSubst_user);
ATF_TEST_CASE_BODY(stringSubst_user)
{
	auto out = Util::pathSubstituteVarsInString("user=$USER end");
	auto expected = "user=" + realUser() + " end";
	ATF_REQUIRE_EQ(out, expected);
}

ATF_TEST_CASE_WITHOUT_HEAD(stringSubst_both);
ATF_TEST_CASE_BODY(stringSubst_both)
{
	auto out = Util::pathSubstituteVarsInString("$USER@host:$HOME");
	auto expected = realUser() + "@host:" + realHome();
	ATF_REQUIRE_EQ(out, expected);
}

ATF_TEST_CASE_WITHOUT_HEAD(stringSubst_no_var);
ATF_TEST_CASE_BODY(stringSubst_no_var)
{
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInString("plain text"), "plain text");
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInString(""), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(stringSubst_word_boundary);
ATF_TEST_CASE_BODY(stringSubst_word_boundary)
{
	// $HOMER should NOT be substituted (followed by alphanumeric)
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInString("$HOMER"), "$HOMER");
	// $USERNAME also stays untouched
	ATF_REQUIRE_EQ(Util::pathSubstituteVarsInString("$USERNAME"), "$USERNAME");
}

ATF_TEST_CASE_WITHOUT_HEAD(stringSubst_punctuation_boundary);
ATF_TEST_CASE_BODY(stringSubst_punctuation_boundary)
{
	// $USER followed by '/' or '.' should be substituted
	auto out = Util::pathSubstituteVarsInString("$USER/foo");
	auto expected = realUser() + "/foo";
	ATF_REQUIRE_EQ(out, expected);

	auto out2 = Util::pathSubstituteVarsInString("$USER.txt");
	auto expected2 = realUser() + ".txt";
	ATF_REQUIRE_EQ(out2, expected2);
}

ATF_TEST_CASE_WITHOUT_HEAD(stringSubst_multiple_occurrences);
ATF_TEST_CASE_BODY(stringSubst_multiple_occurrences)
{
	auto out = Util::pathSubstituteVarsInString("$USER and $USER again");
	auto u = realUser();
	auto expected = u + " and " + u + " again";
	ATF_REQUIRE_EQ(out, expected);
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, pathSubst_no_var);
	ATF_ADD_TEST_CASE(tcs, pathSubst_home_at_start);
	ATF_ADD_TEST_CASE(tcs, pathSubst_home_only_at_start);
	ATF_ADD_TEST_CASE(tcs, pathSubst_short_input);
	ATF_ADD_TEST_CASE(tcs, stringSubst_home);
	ATF_ADD_TEST_CASE(tcs, stringSubst_user);
	ATF_ADD_TEST_CASE(tcs, stringSubst_both);
	ATF_ADD_TEST_CASE(tcs, stringSubst_no_var);
	ATF_ADD_TEST_CASE(tcs, stringSubst_word_boundary);
	ATF_ADD_TEST_CASE(tcs, stringSubst_punctuation_boundary);
	ATF_ADD_TEST_CASE(tcs, stringSubst_multiple_occurrences);
}
