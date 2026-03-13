// ATF unit tests for lib/util.cpp (Util:: namespace)
//
// Build:
//   c++ -std=c++17 -Ilib -o tests/unit/util_test tests/unit/util_test.cpp \
//       -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

// ===================================================================
// Local copies of pure functions from lib/util.cpp
// (no FreeBSD-specific deps, no ERR2 macro — safe for any platform)
// ===================================================================

static const char sepFilePath = '/';
static const char sepFileExt  = '.';

static std::string filePathToBareName(const std::string &path) {
	auto i = path.rfind(sepFilePath);
	std::string p = (i != std::string::npos ? path.substr(i + 1) : path);
	i = p.find(sepFileExt);
	return i != std::string::npos ? p.substr(0, i) : p;
}

static std::string filePathToFileName(const std::string &path) {
	auto i = path.rfind(sepFilePath);
	return i != std::string::npos ? path.substr(i + 1) : path;
}

static std::string stripTrailingSpace(const std::string &str) {
	unsigned sz = str.size();
	while (sz > 0 && ::isspace(str[sz - 1]))
		sz--;
	return str.substr(0, sz);
}

static bool isUrl(const std::string &str) {
	return str.size() > 8 &&
	       (str.substr(0, 7) == "http://" || str.substr(0, 8) == "https://");
}

static std::vector<std::string> splitString(const std::string &str,
                                            const std::string &delimiter) {
	std::vector<std::string> res;
	std::string s = str;
	size_t pos = 0;
	while ((pos = s.find(delimiter)) != std::string::npos) {
		if (pos > 0)
			res.push_back(s.substr(0, pos));
		s.erase(0, pos + delimiter.length());
	}
	if (!s.empty())
		res.push_back(s);
	return res;
}

static std::vector<std::string> reverseVector(const std::vector<std::string> &v) {
	auto vc = v;
	std::reverse(vc.begin(), vc.end());
	return vc;
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

static bool hasExtension(const char *file, const char *extension) {
	auto ext = ::strrchr(file, '.');
	return ext != nullptr && ::strcmp(ext, extension) == 0;
}

// ===================================================================
// Tests: filePathToBareName
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_full_path);
ATF_TEST_CASE_BODY(filePathToBareName_full_path)
{
	ATF_REQUIRE_EQ(filePathToBareName("/usr/local/etc/crate/foo.yml"), "foo");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_no_dir);
ATF_TEST_CASE_BODY(filePathToBareName_no_dir)
{
	ATF_REQUIRE_EQ(filePathToBareName("bar.conf"), "bar");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_no_ext);
ATF_TEST_CASE_BODY(filePathToBareName_no_ext)
{
	ATF_REQUIRE_EQ(filePathToBareName("/tmp/noext"), "noext");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_dotfile);
ATF_TEST_CASE_BODY(filePathToBareName_dotfile)
{
	// .hidden -> empty bare name (first char is dot = extension separator)
	ATF_REQUIRE_EQ(filePathToBareName("/home/user/.hidden"), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToBareName_multiple_dots);
ATF_TEST_CASE_BODY(filePathToBareName_multiple_dots)
{
	ATF_REQUIRE_EQ(filePathToBareName("/tmp/archive.tar.gz"), "archive");
}

// ===================================================================
// Tests: filePathToFileName
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(filePathToFileName_basic);
ATF_TEST_CASE_BODY(filePathToFileName_basic)
{
	ATF_REQUIRE_EQ(filePathToFileName("/etc/rc.conf"), "rc.conf");
	ATF_REQUIRE_EQ(filePathToFileName("simple"), "simple");
}

ATF_TEST_CASE_WITHOUT_HEAD(filePathToFileName_trailing_slash);
ATF_TEST_CASE_BODY(filePathToFileName_trailing_slash)
{
	// trailing slash gives empty filename
	ATF_REQUIRE_EQ(filePathToFileName("/usr/local/"), "");
}

// ===================================================================
// Tests: stripTrailingSpace
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(stripTrailingSpace_basic);
ATF_TEST_CASE_BODY(stripTrailingSpace_basic)
{
	ATF_REQUIRE_EQ(stripTrailingSpace("hello   "), "hello");
	ATF_REQUIRE_EQ(stripTrailingSpace("hello"), "hello");
	ATF_REQUIRE_EQ(stripTrailingSpace(""), "");
	ATF_REQUIRE_EQ(stripTrailingSpace("  \t\n"), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(stripTrailingSpace_preserves_leading);
ATF_TEST_CASE_BODY(stripTrailingSpace_preserves_leading)
{
	ATF_REQUIRE_EQ(stripTrailingSpace("  hello  "), "  hello");
}

// ===================================================================
// Tests: isUrl
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(isUrl_http);
ATF_TEST_CASE_BODY(isUrl_http)
{
	ATF_REQUIRE(isUrl("http://example.com/file.yml"));
	ATF_REQUIRE(isUrl("https://example.com/file.yml"));
}

ATF_TEST_CASE_WITHOUT_HEAD(isUrl_not_url);
ATF_TEST_CASE_BODY(isUrl_not_url)
{
	ATF_REQUIRE(!isUrl("/usr/local/etc/crate/foo.yml"));
	ATF_REQUIRE(!isUrl(""));
	ATF_REQUIRE(!isUrl("ftp://example.com"));
	ATF_REQUIRE(!isUrl("http://"));  // too short
}

// ===================================================================
// Tests: splitString
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(splitString_comma);
ATF_TEST_CASE_BODY(splitString_comma)
{
	auto v = splitString("a,b,c", ",");
	ATF_REQUIRE_EQ(v.size(), 3u);
	ATF_REQUIRE_EQ(v[0], "a");
	ATF_REQUIRE_EQ(v[1], "b");
	ATF_REQUIRE_EQ(v[2], "c");
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_no_delim);
ATF_TEST_CASE_BODY(splitString_no_delim)
{
	auto v = splitString("single", ",");
	ATF_REQUIRE_EQ(v.size(), 1u);
	ATF_REQUIRE_EQ(v[0], "single");
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_empty);
ATF_TEST_CASE_BODY(splitString_empty)
{
	auto v = splitString("", ",");
	ATF_REQUIRE_EQ(v.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_consecutive_delimiters);
ATF_TEST_CASE_BODY(splitString_consecutive_delimiters)
{
	// consecutive delimiters produce no empty elements
	auto v = splitString("a,,b", ",");
	ATF_REQUIRE_EQ(v.size(), 2u);
	ATF_REQUIRE_EQ(v[0], "a");
	ATF_REQUIRE_EQ(v[1], "b");
}

ATF_TEST_CASE_WITHOUT_HEAD(splitString_multi_char_delim);
ATF_TEST_CASE_BODY(splitString_multi_char_delim)
{
	auto v = splitString("one::two::three", "::");
	ATF_REQUIRE_EQ(v.size(), 3u);
	ATF_REQUIRE_EQ(v[0], "one");
	ATF_REQUIRE_EQ(v[1], "two");
	ATF_REQUIRE_EQ(v[2], "three");
}

// ===================================================================
// Tests: reverseVector
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(reverseVector_basic);
ATF_TEST_CASE_BODY(reverseVector_basic)
{
	std::vector<std::string> v = {"a", "b", "c"};
	auto r = reverseVector(v);
	ATF_REQUIRE_EQ(r.size(), 3u);
	ATF_REQUIRE_EQ(r[0], "c");
	ATF_REQUIRE_EQ(r[1], "b");
	ATF_REQUIRE_EQ(r[2], "a");
}

ATF_TEST_CASE_WITHOUT_HEAD(reverseVector_empty);
ATF_TEST_CASE_BODY(reverseVector_empty)
{
	std::vector<std::string> v;
	ATF_REQUIRE_EQ(reverseVector(v).size(), 0u);
}

// ===================================================================
// Tests: shellQuote
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_simple);
ATF_TEST_CASE_BODY(shellQuote_simple)
{
	ATF_REQUIRE_EQ(shellQuote("hello"), "'hello'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_with_spaces);
ATF_TEST_CASE_BODY(shellQuote_with_spaces)
{
	ATF_REQUIRE_EQ(shellQuote("hello world"), "'hello world'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_with_single_quote);
ATF_TEST_CASE_BODY(shellQuote_with_single_quote)
{
	ATF_REQUIRE_EQ(shellQuote("it's"), "'it'\\''s'");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_empty);
ATF_TEST_CASE_BODY(shellQuote_empty)
{
	ATF_REQUIRE_EQ(shellQuote(""), "''");
}

ATF_TEST_CASE_WITHOUT_HEAD(shellQuote_special_chars);
ATF_TEST_CASE_BODY(shellQuote_special_chars)
{
	// shell metacharacters should be safely quoted
	ATF_REQUIRE_EQ(shellQuote("$(rm -rf /)"), "'$(rm -rf /)'");
	ATF_REQUIRE_EQ(shellQuote("a;b&c|d"), "'a;b&c|d'");
}

// ===================================================================
// Tests: hasExtension
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_match);
ATF_TEST_CASE_BODY(hasExtension_match)
{
	ATF_REQUIRE(hasExtension("foo.yml", ".yml"));
	ATF_REQUIRE(hasExtension("/etc/crate/jail.conf", ".conf"));
}

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_no_match);
ATF_TEST_CASE_BODY(hasExtension_no_match)
{
	ATF_REQUIRE(!hasExtension("foo.yml", ".conf"));
	ATF_REQUIRE(!hasExtension("noext", ".yml"));
}

ATF_TEST_CASE_WITHOUT_HEAD(hasExtension_partial);
ATF_TEST_CASE_BODY(hasExtension_partial)
{
	// .tar.gz — hasExtension checks only the last extension
	ATF_REQUIRE(hasExtension("archive.tar.gz", ".gz"));
	ATF_REQUIRE(!hasExtension("archive.tar.gz", ".tar.gz"));
}

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	// filePathToBareName
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_full_path);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_no_dir);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_no_ext);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_dotfile);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_multiple_dots);

	// filePathToFileName
	ATF_ADD_TEST_CASE(tcs, filePathToFileName_basic);
	ATF_ADD_TEST_CASE(tcs, filePathToFileName_trailing_slash);

	// stripTrailingSpace
	ATF_ADD_TEST_CASE(tcs, stripTrailingSpace_basic);
	ATF_ADD_TEST_CASE(tcs, stripTrailingSpace_preserves_leading);

	// isUrl
	ATF_ADD_TEST_CASE(tcs, isUrl_http);
	ATF_ADD_TEST_CASE(tcs, isUrl_not_url);

	// splitString
	ATF_ADD_TEST_CASE(tcs, splitString_comma);
	ATF_ADD_TEST_CASE(tcs, splitString_no_delim);
	ATF_ADD_TEST_CASE(tcs, splitString_empty);
	ATF_ADD_TEST_CASE(tcs, splitString_consecutive_delimiters);
	ATF_ADD_TEST_CASE(tcs, splitString_multi_char_delim);

	// reverseVector
	ATF_ADD_TEST_CASE(tcs, reverseVector_basic);
	ATF_ADD_TEST_CASE(tcs, reverseVector_empty);

	// shellQuote
	ATF_ADD_TEST_CASE(tcs, shellQuote_simple);
	ATF_ADD_TEST_CASE(tcs, shellQuote_with_spaces);
	ATF_ADD_TEST_CASE(tcs, shellQuote_with_single_quote);
	ATF_ADD_TEST_CASE(tcs, shellQuote_empty);
	ATF_ADD_TEST_CASE(tcs, shellQuote_special_chars);

	// hasExtension
	ATF_ADD_TEST_CASE(tcs, hasExtension_match);
	ATF_ADD_TEST_CASE(tcs, hasExtension_no_match);
	ATF_ADD_TEST_CASE(tcs, hasExtension_partial);
}
