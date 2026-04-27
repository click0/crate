// ATF unit tests for lib/util.cpp pure helpers.
//
// Uses real Util:: symbols from lib/util_pure.cpp.
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/util_test \
//       tests/unit/util_test.cpp lib/util_pure.cpp lib/err.cpp \
//       -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <string>
#include <vector>

#include "util.h"

// ===================================================================
// Tests: Util::filePathToBareName
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_full_path);
ATF_TEST_CASE_BODY(filePathToBareName_full_path)
{
	ATF_REQUIRE_EQ(Util::filePathToBareName("/usr/local/etc/crate/foo.yml"), "foo");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_no_dir);
ATF_TEST_CASE_BODY(filePathToBareName_no_dir)
{
	ATF_REQUIRE_EQ(Util::filePathToBareName("bar.conf"), "bar");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_no_ext);
ATF_TEST_CASE_BODY(filePathToBareName_no_ext)
{
	ATF_REQUIRE_EQ(Util::filePathToBareName("/tmp/noext"), "noext");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_dotfile);
ATF_TEST_CASE_BODY(filePathToBareName_dotfile)
{
	ATF_REQUIRE_EQ(Util::filePathToBareName("/home/user/.hidden"), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_multiple_dots);
ATF_TEST_CASE_BODY(filePathToBareName_multiple_dots)
{
	ATF_REQUIRE_EQ(Util::filePathToBareName("/tmp/archive.tar.gz"), "archive");
}

// ===================================================================
// Tests: Util::filePathToFileName
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(filePathToFileName_basic);
ATF_TEST_CASE_BODY(filePathToFileName_basic)
{
	ATF_REQUIRE_EQ(Util::filePathToFileName("/etc/rc.conf"), "rc.conf");
	ATF_REQUIRE_EQ(Util::filePathToFileName("simple"), "simple");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToFileName_trailing_slash);
ATF_TEST_CASE_BODY(filePathToFileName_trailing_slash)
{
	ATF_REQUIRE_EQ(Util::filePathToFileName("/usr/local/"), "");
}

// ===================================================================
// Tests: Util::stripTrailingSpace
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(stripTrailingSpace_basic);
ATF_TEST_CASE_BODY(stripTrailingSpace_basic)
{
	ATF_REQUIRE_EQ(Util::stripTrailingSpace("hello   "), "hello");
	ATF_REQUIRE_EQ(Util::stripTrailingSpace("hello"), "hello");
	ATF_REQUIRE_EQ(Util::stripTrailingSpace(""), "");
	ATF_REQUIRE_EQ(Util::stripTrailingSpace("  \t\n"), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(stripTrailingSpace_preserves_leading);
ATF_TEST_CASE_BODY(stripTrailingSpace_preserves_leading)
{
	ATF_REQUIRE_EQ(Util::stripTrailingSpace("  hello  "), "  hello");
}

// ===================================================================
// Tests: Util::isUrl
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(isUrl_http);
ATF_TEST_CASE_BODY(isUrl_http)
{
	ATF_REQUIRE(Util::isUrl("http://example.com/file.yml"));
	ATF_REQUIRE(Util::isUrl("https://example.com/file.yml"));
}

ATF_TEST_CASE_WITHOUT_HEAD(isUrl_not_url);
ATF_TEST_CASE_BODY(isUrl_not_url)
{
	ATF_REQUIRE(!Util::isUrl("/usr/local/etc/crate/foo.yml"));
	ATF_REQUIRE(!Util::isUrl(""));
	ATF_REQUIRE(!Util::isUrl("ftp://example.com"));
	ATF_REQUIRE(!Util::isUrl("http://"));  // too short
}

// ===================================================================
// Tests: Util::splitString
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(splitString_comma);
ATF_TEST_CASE_BODY(splitString_comma)
{
	auto v = Util::splitString("a,b,c", ",");
	ATF_REQUIRE_EQ(v.size(), 3u);
	ATF_REQUIRE_EQ(v[0], "a");
	ATF_REQUIRE_EQ(v[1], "b");
	ATF_REQUIRE_EQ(v[2], "c");
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_no_delim);
ATF_TEST_CASE_BODY(splitString_no_delim)
{
	auto v = Util::splitString("single", ",");
	ATF_REQUIRE_EQ(v.size(), 1u);
	ATF_REQUIRE_EQ(v[0], "single");
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_empty);
ATF_TEST_CASE_BODY(splitString_empty)
{
	auto v = Util::splitString("", ",");
	ATF_REQUIRE_EQ(v.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_consecutive_delimiters);
ATF_TEST_CASE_BODY(splitString_consecutive_delimiters)
{
	auto v = Util::splitString("a,,b", ",");
	ATF_REQUIRE_EQ(v.size(), 2u);
	ATF_REQUIRE_EQ(v[0], "a");
	ATF_REQUIRE_EQ(v[1], "b");
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_multi_char_delim);
ATF_TEST_CASE_BODY(splitString_multi_char_delim)
{
	auto v = Util::splitString("one::two::three", "::");
	ATF_REQUIRE_EQ(v.size(), 3u);
	ATF_REQUIRE_EQ(v[0], "one");
	ATF_REQUIRE_EQ(v[1], "two");
	ATF_REQUIRE_EQ(v[2], "three");
}

// ===================================================================
// Tests: Util::reverseVector
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(reverseVector_basic);
ATF_TEST_CASE_BODY(reverseVector_basic)
{
	std::vector<std::string> v = {"a", "b", "c"};
	auto r = Util::reverseVector(v);
	ATF_REQUIRE_EQ(r.size(), 3u);
	ATF_REQUIRE_EQ(r[0], "c");
	ATF_REQUIRE_EQ(r[1], "b");
	ATF_REQUIRE_EQ(r[2], "a");
}

ATF_TEST_CASE_WITHOUT_HEAD(reverseVector_empty);
ATF_TEST_CASE_BODY(reverseVector_empty)
{
	std::vector<std::string> v;
	ATF_REQUIRE_EQ(Util::reverseVector(v).size(), 0u);
}

// ===================================================================
// Tests: Util::shellQuote
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_simple);
ATF_TEST_CASE_BODY(shellQuote_simple)
{
	ATF_REQUIRE_EQ(Util::shellQuote("hello"), "'hello'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_with_spaces);
ATF_TEST_CASE_BODY(shellQuote_with_spaces)
{
	ATF_REQUIRE_EQ(Util::shellQuote("hello world"), "'hello world'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_with_single_quote);
ATF_TEST_CASE_BODY(shellQuote_with_single_quote)
{
	ATF_REQUIRE_EQ(Util::shellQuote("it's"), "'it'\\''s'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_empty);
ATF_TEST_CASE_BODY(shellQuote_empty)
{
	ATF_REQUIRE_EQ(Util::shellQuote(""), "''");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_special_chars);
ATF_TEST_CASE_BODY(shellQuote_special_chars)
{
	ATF_REQUIRE_EQ(Util::shellQuote("$(rm -rf /)"), "'$(rm -rf /)'");
	ATF_REQUIRE_EQ(Util::shellQuote("a;b&c|d"), "'a;b&c|d'");
}

// ===================================================================
// Tests: Util::Fs::hasExtension
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_match);
ATF_TEST_CASE_BODY(hasExtension_match)
{
	ATF_REQUIRE(Util::Fs::hasExtension("foo.yml", ".yml"));
	ATF_REQUIRE(Util::Fs::hasExtension("/etc/crate/jail.conf", ".conf"));
}

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_no_match);
ATF_TEST_CASE_BODY(hasExtension_no_match)
{
	ATF_REQUIRE(!Util::Fs::hasExtension("foo.yml", ".conf"));
	ATF_REQUIRE(!Util::Fs::hasExtension("noext", ".yml"));
}

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_partial);
ATF_TEST_CASE_BODY(hasExtension_partial)
{
	ATF_REQUIRE(Util::Fs::hasExtension("archive.tar.gz", ".gz"));
	ATF_REQUIRE(!Util::Fs::hasExtension("archive.tar.gz", ".tar.gz"));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_full_path);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_no_dir);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_no_ext);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_dotfile);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_multiple_dots);
	ATF_ADD_TEST_CASE(tcs, filePathToFileName_basic);
	ATF_ADD_TEST_CASE(tcs, filePathToFileName_trailing_slash);
	ATF_ADD_TEST_CASE(tcs, stripTrailingSpace_basic);
	ATF_ADD_TEST_CASE(tcs, stripTrailingSpace_preserves_leading);
	ATF_ADD_TEST_CASE(tcs, isUrl_http);
	ATF_ADD_TEST_CASE(tcs, isUrl_not_url);
	ATF_ADD_TEST_CASE(tcs, splitString_comma);
	ATF_ADD_TEST_CASE(tcs, splitString_no_delim);
	ATF_ADD_TEST_CASE(tcs, splitString_empty);
	ATF_ADD_TEST_CASE(tcs, splitString_consecutive_delimiters);
	ATF_ADD_TEST_CASE(tcs, splitString_multi_char_delim);
	ATF_ADD_TEST_CASE(tcs, reverseVector_basic);
	ATF_ADD_TEST_CASE(tcs, reverseVector_empty);
	ATF_ADD_TEST_CASE(tcs, shellQuote_simple);
	ATF_ADD_TEST_CASE(tcs, shellQuote_with_spaces);
	ATF_ADD_TEST_CASE(tcs, shellQuote_with_single_quote);
	ATF_ADD_TEST_CASE(tcs, shellQuote_empty);
	ATF_ADD_TEST_CASE(tcs, shellQuote_special_chars);
	ATF_ADD_TEST_CASE(tcs, hasExtension_match);
	ATF_ADD_TEST_CASE(tcs, hasExtension_no_match);
	ATF_ADD_TEST_CASE(tcs, hasExtension_partial);
}
