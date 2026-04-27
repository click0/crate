// ATF unit tests for security-critical helpers in lib/util.cpp.
//
// PROOF-OF-CONCEPT for the new "link tests against lib/util_pure.cpp"
// methodology: this file uses the *real* Util:: symbols by including
// lib/util.h and linking against lib/util_pure.cpp + lib/err.cpp.
// A bug introduced in lib/util_pure.cpp will now actually fail this
// suite (versus the previous "duplicate the function into the test"
// pattern, which only checked a frozen copy).
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/util_security_test \
//       tests/unit/util_security_test.cpp lib/util_pure.cpp lib/err.cpp \
//       -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>

#include "util.h"
#include "err.h"

// Test fixture: a unique temp directory for each ATF test case
static std::string makeTempDir(const std::string &name) {
	namespace fs = std::filesystem;
	auto base = fs::temp_directory_path() / ("crate_safepath_" + name);
	fs::remove_all(base);
	fs::create_directories(base);
	return base.string();
}

// ===================================================================
// Tests: Util::safePath — directory traversal protection
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(safePath_inside_prefix_ok);
ATF_TEST_CASE_BODY(safePath_inside_prefix_ok)
{
	auto dir = makeTempDir("inside");
	auto child = dir + "/sub/file.txt";
	auto out = Util::safePath(child, dir, "test");
	ATF_REQUIRE(out.compare(0, dir.size(), dir) == 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_traversal_rejected);
ATF_TEST_CASE_BODY(safePath_traversal_rejected)
{
	auto dir = makeTempDir("traversal");
	auto evil = dir + "/../../etc/passwd";
	ATF_REQUIRE_THROW(Exception, Util::safePath(evil, dir, "spec"));
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_sibling_rejected);
ATF_TEST_CASE_BODY(safePath_sibling_rejected)
{
	// String prefix /foo would naively match /foobar — guard against it.
	auto dir = makeTempDir("sibling");
	auto bad = dir + "_neighbour/file";
	ATF_REQUIRE_THROW(Exception, Util::safePath(bad, dir, "spec"));
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_absolute_outside_rejected);
ATF_TEST_CASE_BODY(safePath_absolute_outside_rejected)
{
	auto dir = makeTempDir("outside");
	ATF_REQUIRE_THROW(Exception, Util::safePath("/etc/passwd", dir, "spec"));
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_dot_segments_normalized);
ATF_TEST_CASE_BODY(safePath_dot_segments_normalized)
{
	auto dir = makeTempDir("dots");
	auto p = dir + "/./sub/../file.txt";
	auto out = Util::safePath(p, dir, "test");
	ATF_REQUIRE(out.find("/..") == std::string::npos);
	ATF_REQUIRE(out.find("/./") == std::string::npos);
	ATF_REQUIRE_EQ(out, dir + "/file.txt");
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_symlink_escape_rejected);
ATF_TEST_CASE_BODY(safePath_symlink_escape_rejected)
{
	namespace fs = std::filesystem;
	auto dir = makeTempDir("symlink");
	auto link = fs::path(dir) / "escape";
	std::error_code ec;
	fs::create_symlink("/etc", link, ec);
	if (ec)
		ATF_SKIP(("cannot create symlink: " + ec.message()).c_str());
	ATF_REQUIRE_THROW(Exception,
		Util::safePath((link / "passwd").string(), dir, "spec"));
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_returns_canonical);
ATF_TEST_CASE_BODY(safePath_returns_canonical)
{
	namespace fs = std::filesystem;
	auto dir = makeTempDir("canon");
	auto sub = fs::path(dir) / "sub";
	fs::create_directories(sub);
	std::ofstream(sub / "file.txt") << "x";
	auto messy = dir + "/sub/./file.txt";
	auto out = Util::safePath(messy, dir, "test");
	ATF_REQUIRE_EQ(out, (sub / "file.txt").string());
}

// ===================================================================
// Tests: Util::shellQuote — security against command injection
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_neutralizes_command_substitution);
ATF_TEST_CASE_BODY(shellQuote_neutralizes_command_substitution)
{
	ATF_REQUIRE_EQ(Util::shellQuote("$(rm -rf /)"), "'$(rm -rf /)'");
	ATF_REQUIRE_EQ(Util::shellQuote("`rm -rf /`"), "'`rm -rf /`'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_neutralizes_separators);
ATF_TEST_CASE_BODY(shellQuote_neutralizes_separators)
{
	ATF_REQUIRE_EQ(Util::shellQuote("a;b"),  "'a;b'");
	ATF_REQUIRE_EQ(Util::shellQuote("a&&b"), "'a&&b'");
	ATF_REQUIRE_EQ(Util::shellQuote("a||b"), "'a||b'");
	ATF_REQUIRE_EQ(Util::shellQuote("a|b"),  "'a|b'");
	ATF_REQUIRE_EQ(Util::shellQuote("a\nb"), "'a\nb'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_escapes_single_quote);
ATF_TEST_CASE_BODY(shellQuote_escapes_single_quote)
{
	ATF_REQUIRE_EQ(Util::shellQuote("a'b"), "'a'\\''b'");
	ATF_REQUIRE_EQ(Util::shellQuote("'"),   "''\\'''");
	ATF_REQUIRE_EQ(Util::shellQuote("''"),  "''\\'''\\'''");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_round_trip_through_sh);
ATF_TEST_CASE_BODY(shellQuote_round_trip_through_sh)
{
	if (!std::filesystem::exists("/bin/sh"))
		ATF_SKIP("/bin/sh not available");
	auto temp = std::filesystem::temp_directory_path() / "crate_shellquote_out";
	const std::string inputs[] = {
		"hello",
		"with spaces",
		"weird!@#$%^&*()",
		"a'b'c",
		"new\nline",
		"\\back\\slash",
	};
	for (const auto &in : inputs) {
		auto cmd = "/bin/sh -c \"printf %s " + Util::shellQuote(in) + "\" > " + temp.string();
		int rc = std::system(cmd.c_str());
		ATF_REQUIRE_EQ(rc, 0);
		std::ifstream ifs(temp);
		std::string got((std::istreambuf_iterator<char>(ifs)),
		                 std::istreambuf_iterator<char>());
		ATF_REQUIRE_EQ(got, in);
	}
	std::filesystem::remove(temp);
}

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	// safePath
	ATF_ADD_TEST_CASE(tcs, safePath_inside_prefix_ok);
	ATF_ADD_TEST_CASE(tcs, safePath_traversal_rejected);
	ATF_ADD_TEST_CASE(tcs, safePath_sibling_rejected);
	ATF_ADD_TEST_CASE(tcs, safePath_absolute_outside_rejected);
	ATF_ADD_TEST_CASE(tcs, safePath_dot_segments_normalized);
	ATF_ADD_TEST_CASE(tcs, safePath_symlink_escape_rejected);
	ATF_ADD_TEST_CASE(tcs, safePath_returns_canonical);

	// shellQuote
	ATF_ADD_TEST_CASE(tcs, shellQuote_neutralizes_command_substitution);
	ATF_ADD_TEST_CASE(tcs, shellQuote_neutralizes_separators);
	ATF_ADD_TEST_CASE(tcs, shellQuote_escapes_single_quote);
	ATF_ADD_TEST_CASE(tcs, shellQuote_round_trip_through_sh);
}
