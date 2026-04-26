// ATF unit tests for security-critical helpers from lib/util.cpp.
//
// Focuses on:
//   - safePath()       — path-traversal guard (CRITICAL: setuid binary)
//   - shellQuote()     — shell-metachar escaping
//   - sha256hex idempotence (using a local SHA reimplementation would be
//     redundant; we instead verify shellQuote covers known-bad inputs)
//
// Build:
//   c++ -std=c++17 -o tests/unit/util_security_test \
//       tests/unit/util_security_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>

// ===================================================================
// Local copies of pure functions from lib/util.cpp
// (ERR2 macro replaced with std::runtime_error throw)
// ===================================================================

#define ERR2(loc, msg) do { std::ostringstream _e; _e << loc << ": " << msg; throw std::runtime_error(_e.str()); } while (0)

static std::string safePath(const std::string &path,
                            const std::string &requiredPrefix,
                            const std::string &what) {
	namespace fs = std::filesystem;
	auto canonical = fs::weakly_canonical(path).string();
	if (canonical.size() < requiredPrefix.size() ||
	    canonical.compare(0, requiredPrefix.size(), requiredPrefix) != 0 ||
	    (canonical.size() > requiredPrefix.size() &&
	     canonical[requiredPrefix.size()] != '/'))
		ERR2("path validation", "'" << what << "' path '" << path << "' resolves to '"
		     << canonical << "' which is outside required prefix '" << requiredPrefix << "'");
	return canonical;
}

static std::string shellQuote(const std::string &arg) {
	std::ostringstream ss;
	ss << '\'';
	for (auto chr : arg)
		if (chr == '\'')
			ss << "'\\''";
		else
			ss << chr;
	ss << '\'';
	return ss.str();
}

// Test fixture: a unique temp directory for each ATF test case
static std::string makeTempDir(const std::string &name) {
	namespace fs = std::filesystem;
	auto base = fs::temp_directory_path() / ("crate_safepath_" + name);
	fs::remove_all(base);
	fs::create_directories(base);
	return base.string();
}

// ===================================================================
// Tests: safePath — directory traversal protection
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(safePath_inside_prefix_ok);
ATF_TEST_CASE_BODY(safePath_inside_prefix_ok)
{
	auto dir = makeTempDir("inside");
	auto child = dir + "/sub/file.txt";
	auto out = safePath(child, dir, "test");
	ATF_REQUIRE(out.compare(0, dir.size(), dir) == 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_traversal_rejected);
ATF_TEST_CASE_BODY(safePath_traversal_rejected)
{
	auto dir = makeTempDir("traversal");
	// /tmp/.../traversal/../../etc/passwd resolves outside the prefix
	auto evil = dir + "/../../etc/passwd";
	ATF_REQUIRE_THROW(std::runtime_error, safePath(evil, dir, "spec"));
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_sibling_rejected);
ATF_TEST_CASE_BODY(safePath_sibling_rejected)
{
	// String prefix /foo would naively match /foobar — guard against it.
	auto dir = makeTempDir("sibling");
	auto bad = dir + "_neighbour/file";
	ATF_REQUIRE_THROW(std::runtime_error, safePath(bad, dir, "spec"));
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_absolute_outside_rejected);
ATF_TEST_CASE_BODY(safePath_absolute_outside_rejected)
{
	auto dir = makeTempDir("outside");
	ATF_REQUIRE_THROW(std::runtime_error, safePath("/etc/passwd", dir, "spec"));
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_dot_segments_normalized);
ATF_TEST_CASE_BODY(safePath_dot_segments_normalized)
{
	auto dir = makeTempDir("dots");
	// /tmp/.../dots/./sub/../file.txt — weakly_canonical collapses to /tmp/.../dots/file.txt
	auto p = dir + "/./sub/../file.txt";
	auto out = safePath(p, dir, "test");
	ATF_REQUIRE(out.find("/..") == std::string::npos);
	ATF_REQUIRE(out.find("/./") == std::string::npos);
	ATF_REQUIRE_EQ(out, dir + "/file.txt");
}

ATF_TEST_CASE_WITHOUT_HEAD(safePath_symlink_escape_rejected);
ATF_TEST_CASE_BODY(safePath_symlink_escape_rejected)
{
	namespace fs = std::filesystem;
	auto dir = makeTempDir("symlink");
	// Create a symlink inside `dir` that points outside it
	auto link = fs::path(dir) / "escape";
	std::error_code ec;
	fs::create_symlink("/etc", link, ec);
	if (ec) {
		// Symlink creation can fail in restricted environments; skip rather than fail
		ATF_SKIP(("cannot create symlink: " + ec.message()).c_str());
	}
	// safePath uses weakly_canonical which resolves symlinks → must reject
	ATF_REQUIRE_THROW(std::runtime_error,
		safePath((link / "passwd").string(), dir, "spec"));
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
	auto out = safePath(messy, dir, "test");
	ATF_REQUIRE_EQ(out, (sub / "file.txt").string());
}

// ===================================================================
// Tests: shellQuote — security against command injection
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_neutralizes_command_substitution);
ATF_TEST_CASE_BODY(shellQuote_neutralizes_command_substitution)
{
	// Neither $(...) nor `...` may execute when result is used in a shell cmd
	auto q1 = shellQuote("$(rm -rf /)");
	auto q2 = shellQuote("`rm -rf /`");
	ATF_REQUIRE_EQ(q1, "'$(rm -rf /)'");
	ATF_REQUIRE_EQ(q2, "'`rm -rf /`'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_neutralizes_separators);
ATF_TEST_CASE_BODY(shellQuote_neutralizes_separators)
{
	ATF_REQUIRE_EQ(shellQuote("a;b"),  "'a;b'");
	ATF_REQUIRE_EQ(shellQuote("a&&b"), "'a&&b'");
	ATF_REQUIRE_EQ(shellQuote("a||b"), "'a||b'");
	ATF_REQUIRE_EQ(shellQuote("a|b"),  "'a|b'");
	ATF_REQUIRE_EQ(shellQuote("a\nb"), "'a\nb'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_escapes_single_quote);
ATF_TEST_CASE_BODY(shellQuote_escapes_single_quote)
{
	// ' ends the quoted string, then '\'' inserts a literal ', then '
	// reopens the quoted string.
	ATF_REQUIRE_EQ(shellQuote("a'b"), "'a'\\''b'");
	ATF_REQUIRE_EQ(shellQuote("'"),   "''\\'''");
	ATF_REQUIRE_EQ(shellQuote("''"),  "''\\'''\\'''");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_round_trip_through_sh);
ATF_TEST_CASE_BODY(shellQuote_round_trip_through_sh)
{
	// Black-box check: feed the quoted output into `sh -c "printf %s ..."`
	// and verify the input survives unchanged. Skips if /bin/sh missing.
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
		auto cmd = "/bin/sh -c \"printf %s " + shellQuote(in) + "\" > " + temp.string();
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
