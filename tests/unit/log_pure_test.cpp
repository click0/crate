// ATF unit tests for LogPure (lib/log_pure.cpp).
//
// Filesystem-safe path computation for crate's per-jail diagnostic logs.
// A bug here can write logs in unexpected places (path traversal,
// hidden files, broken paths).

#include <atf-c++.hpp>
#include <string>

#include "log_pure.h"

using LogPure::sanitizeName;
using LogPure::createLogPath;

// ===================================================================
// sanitizeName
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(sanitize_passes_safe);
ATF_TEST_CASE_BODY(sanitize_passes_safe)
{
	ATF_REQUIRE_EQ(sanitizeName("web"), "web");
	ATF_REQUIRE_EQ(sanitizeName("my-app_1.0"), "my-app_1.0");
	ATF_REQUIRE_EQ(sanitizeName("UPPER123"), "UPPER123");
}

ATF_TEST_CASE_WITHOUT_HEAD(sanitize_replaces_slashes);
ATF_TEST_CASE_BODY(sanitize_replaces_slashes)
{
	// '/' must never appear — would change the directory.
	ATF_REQUIRE_EQ(sanitizeName("a/b"), "a_b");
	ATF_REQUIRE_EQ(sanitizeName("/etc/passwd"), "_etc_passwd");
}

ATF_TEST_CASE_WITHOUT_HEAD(sanitize_replaces_backslashes);
ATF_TEST_CASE_BODY(sanitize_replaces_backslashes)
{
	ATF_REQUIRE_EQ(sanitizeName("a\\b"), "a_b");
}

ATF_TEST_CASE_WITHOUT_HEAD(sanitize_collapses_leading_dots);
ATF_TEST_CASE_BODY(sanitize_collapses_leading_dots)
{
	// "." or ".." must not be a usable filename.
	ATF_REQUIRE_EQ(sanitizeName("."), "_");
	ATF_REQUIRE_EQ(sanitizeName(".."), "__");
	ATF_REQUIRE_EQ(sanitizeName("...hidden"), "___hidden");
	ATF_REQUIRE_EQ(sanitizeName(".env"), "_env");
}

ATF_TEST_CASE_WITHOUT_HEAD(sanitize_keeps_dots_in_middle);
ATF_TEST_CASE_BODY(sanitize_keeps_dots_in_middle)
{
	// Dots in the middle are fine.
	ATF_REQUIRE_EQ(sanitizeName("foo.bar"), "foo.bar");
	ATF_REQUIRE_EQ(sanitizeName("v1.2.3"), "v1.2.3");
}

ATF_TEST_CASE_WITHOUT_HEAD(sanitize_replaces_null);
ATF_TEST_CASE_BODY(sanitize_replaces_null)
{
	std::string s{"a\0b", 3};
	auto out = sanitizeName(s);
	ATF_REQUIRE_EQ(out, "a_b");
}

ATF_TEST_CASE_WITHOUT_HEAD(sanitize_empty_returns_unnamed);
ATF_TEST_CASE_BODY(sanitize_empty_returns_unnamed)
{
	// Empty input must not produce a zero-length basename
	// (would result in e.g. "/var/log/crate/create-.log").
	ATF_REQUIRE_EQ(sanitizeName(""), "unnamed");
}

ATF_TEST_CASE_WITHOUT_HEAD(sanitize_long_input_passthrough);
ATF_TEST_CASE_BODY(sanitize_long_input_passthrough)
{
	// We don't truncate — that's the OS's PATH_MAX problem, not ours.
	std::string in(500, 'x');
	ATF_REQUIRE_EQ(sanitizeName(in).size(), 500u);
}

// ===================================================================
// createLogPath
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(createLogPath_basic);
ATF_TEST_CASE_BODY(createLogPath_basic)
{
	auto p = createLogPath("/var/log/crate", "create", "web");
	ATF_REQUIRE_EQ(p, "/var/log/crate/create-web.log");
}

ATF_TEST_CASE_WITHOUT_HEAD(createLogPath_sanitizes_name);
ATF_TEST_CASE_BODY(createLogPath_sanitizes_name)
{
	// Path-traversal in `name` must not escape the logs dir.
	auto p = createLogPath("/var/log/crate", "create", "../../etc/passwd");
	// Result must NOT contain any path separator past the logs dir
	// (that's what would let it escape).
	auto basename = p.substr(std::string("/var/log/crate/").size());
	ATF_REQUIRE(basename.find('/') == std::string::npos);
	// Result starts with the expected prefix and ends with .log.
	ATF_REQUIRE(p.find("/var/log/crate/create-") == 0u);
	ATF_REQUIRE(p.size() >= 4u && p.substr(p.size() - 4) == ".log");
	// And the dangerous "etc/passwd" substring is broken up.
	ATF_REQUIRE(p.find("etc/passwd") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(createLogPath_different_kinds);
ATF_TEST_CASE_BODY(createLogPath_different_kinds)
{
	auto a = createLogPath("/var/log/crate", "create", "x");
	auto b = createLogPath("/var/log/crate", "run",    "x");
	ATF_REQUIRE(a != b);
	ATF_REQUIRE(a.find("create-") != std::string::npos);
	ATF_REQUIRE(b.find("run-")    != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, sanitize_passes_safe);
	ATF_ADD_TEST_CASE(tcs, sanitize_replaces_slashes);
	ATF_ADD_TEST_CASE(tcs, sanitize_replaces_backslashes);
	ATF_ADD_TEST_CASE(tcs, sanitize_collapses_leading_dots);
	ATF_ADD_TEST_CASE(tcs, sanitize_keeps_dots_in_middle);
	ATF_ADD_TEST_CASE(tcs, sanitize_replaces_null);
	ATF_ADD_TEST_CASE(tcs, sanitize_empty_returns_unnamed);
	ATF_ADD_TEST_CASE(tcs, sanitize_long_input_passthrough);
	ATF_ADD_TEST_CASE(tcs, createLogPath_basic);
	ATF_ADD_TEST_CASE(tcs, createLogPath_sanitizes_name);
	ATF_ADD_TEST_CASE(tcs, createLogPath_different_kinds);
}
