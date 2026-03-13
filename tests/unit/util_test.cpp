// ATF unit tests for lib/util.cpp (Util:: namespace)
//
// Build:
//   c++ -std=c++17 -Ilib $(pkg-config --cflags yaml-cpp) \
//       -o tests/unit/util_test tests/unit/util_test.cpp \
//       -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <string>

// --- Util::filePathToBareName ---

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

// --- Tests ---

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

ATF_TEST_CASE_WITHOUT_HEAD(filePathToFileName_basic);
ATF_TEST_CASE_BODY(filePathToFileName_basic)
{
	ATF_REQUIRE_EQ(filePathToFileName("/etc/rc.conf"), "rc.conf");
	ATF_REQUIRE_EQ(filePathToFileName("simple"), "simple");
}

ATF_TEST_CASE_WITHOUT_HEAD(stripTrailingSpace_basic);
ATF_TEST_CASE_BODY(stripTrailingSpace_basic)
{
	ATF_REQUIRE_EQ(stripTrailingSpace("hello   "), "hello");
	ATF_REQUIRE_EQ(stripTrailingSpace("hello"), "hello");
	ATF_REQUIRE_EQ(stripTrailingSpace(""), "");
	ATF_REQUIRE_EQ(stripTrailingSpace("  \t\n"), "");
}

ATF_TEST_CASE_WITHOUT_HEAD(isUrl_basic);
ATF_TEST_CASE_BODY(isUrl_basic)
{
	ATF_REQUIRE(isUrl("http://example.com/file.yml"));
	ATF_REQUIRE(isUrl("https://example.com/file.yml"));
	ATF_REQUIRE(!isUrl("/usr/local/etc/crate/foo.yml"));
	ATF_REQUIRE(!isUrl(""));
	ATF_REQUIRE(!isUrl("ftp://example.com"));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_full_path);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_no_dir);
	ATF_ADD_TEST_CASE(tcs, filePathToBareName_no_ext);
	ATF_ADD_TEST_CASE(tcs, filePathToFileName_basic);
	ATF_ADD_TEST_CASE(tcs, stripTrailingSpace_basic);
	ATF_ADD_TEST_CASE(tcs, isUrl_basic);
}
