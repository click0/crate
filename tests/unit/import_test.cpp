// ATF unit tests for parsing/validation helpers used by lib/import.cpp.
//
// The shell-out portions of import.cpp (xz, tar, sha256) cannot be unit-
// tested without fixtures, but the inline parsing/validation steps can:
//
//   - sha256 file format:  "hexhash  filename" or just "hexhash"
//   - directory-traversal check on tar listing entries
//   - archive entry name normalization (./prefix and trailing-slash strip)
//
// Build:
//   c++ -std=c++17 -o tests/unit/import_test \
//       tests/unit/import_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <sstream>
#include <string>
#include <vector>

// ===================================================================
// Helpers extracted from lib/import.cpp
// ===================================================================

// stripTrailingSpace — local copy from lib/util.cpp (used by parser below)
static std::string stripTrailingSpace(const std::string &str) {
	unsigned sz = str.size();
	while (sz > 0 && ::isspace(str[sz - 1]))
		sz--;
	return str.substr(0, sz);
}

// Mirrors the inline parser in import.cpp validateChecksum():
// reads first line of a .sha256 file and returns the hex digest portion.
static std::string parseSha256File(const std::string &line) {
	auto spacePos = line.find(' ');
	auto expectedHash = (spacePos != std::string::npos) ? line.substr(0, spacePos) : line;
	return stripTrailingSpace(expectedHash);
}

// Mirrors the inline check in validateArchive():
// returns true iff any entry contains a ".." path component → reject.
static bool archiveHasTraversal(const std::string &listing) {
	std::istringstream is(listing);
	std::string entry;
	while (std::getline(is, entry))
		if (entry.find("..") != std::string::npos)
			return true;
	return false;
}

// Mirrors the inline normalizer in archiveHasSpec():
// strips leading "./" and trailing slashes from a tar entry name.
static std::string normalizeArchiveEntry(const std::string &entry) {
	std::string name = entry;
	if (name.substr(0, 2) == "./") name = name.substr(2);
	while (!name.empty() && name.back() == '/') name.pop_back();
	return name;
}

// ===================================================================
// Tests: parseSha256File — handle BSD and GNU coreutils output formats
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(parseSha256_bsd_format);
ATF_TEST_CASE_BODY(parseSha256_bsd_format)
{
	// FreeBSD `sha256 -q` output (just the hash)
	auto h = parseSha256File("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	ATF_REQUIRE_EQ(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseSha256_gnu_format);
ATF_TEST_CASE_BODY(parseSha256_gnu_format)
{
	// `sha256sum` output: "hexhash  filename"
	auto h = parseSha256File("abc123  archive.crate");
	ATF_REQUIRE_EQ(h, "abc123");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseSha256_trailing_whitespace);
ATF_TEST_CASE_BODY(parseSha256_trailing_whitespace)
{
	// Plain hash with trailing CR or whitespace
	ATF_REQUIRE_EQ(parseSha256File("abc123\r"),  "abc123");
	ATF_REQUIRE_EQ(parseSha256File("abc123\t"),  "abc123");
	ATF_REQUIRE_EQ(parseSha256File("abc123   "), "abc123");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseSha256_empty);
ATF_TEST_CASE_BODY(parseSha256_empty)
{
	ATF_REQUIRE_EQ(parseSha256File(""), "");
}

// ===================================================================
// Tests: archiveHasTraversal — refuse archives that escape extraction dir
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(traversal_clean_listing);
ATF_TEST_CASE_BODY(traversal_clean_listing)
{
	std::string listing =
		"./+CRATE.SPEC\n"
		"./root/etc/rc.conf\n"
		"./root/usr/local/bin/app\n";
	ATF_REQUIRE(!archiveHasTraversal(listing));
}

ATF_TEST_CASE_WITHOUT_HEAD(traversal_dotdot_segment_rejected);
ATF_TEST_CASE_BODY(traversal_dotdot_segment_rejected)
{
	std::string listing =
		"./root/etc/rc.conf\n"
		"./../../etc/passwd\n";
	ATF_REQUIRE(archiveHasTraversal(listing));
}

ATF_TEST_CASE_WITHOUT_HEAD(traversal_dotdot_anywhere_rejected);
ATF_TEST_CASE_BODY(traversal_dotdot_anywhere_rejected)
{
	// Current implementation flags `..` substring anywhere — this is
	// intentionally aggressive (false-positive on filenames containing
	// "..", e.g. "release..txt"). Tests document the current behaviour
	// so a future relaxation is a deliberate decision, not a regression.
	ATF_REQUIRE(archiveHasTraversal("release..notes\n"));
	ATF_REQUIRE(archiveHasTraversal("./root/foo..bar\n"));
}

ATF_TEST_CASE_WITHOUT_HEAD(traversal_empty_listing);
ATF_TEST_CASE_BODY(traversal_empty_listing)
{
	ATF_REQUIRE(!archiveHasTraversal(""));
}

ATF_TEST_CASE_WITHOUT_HEAD(traversal_single_dot_ok);
ATF_TEST_CASE_BODY(traversal_single_dot_ok)
{
	// Single dot (current dir) is fine, only ".." should trigger
	ATF_REQUIRE(!archiveHasTraversal("./file\n"));
	ATF_REQUIRE(!archiveHasTraversal("./.hidden\n"));
}

// ===================================================================
// Tests: normalizeArchiveEntry — used to detect +CRATE.SPEC inside archive
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(normalize_strips_leading_dot_slash);
ATF_TEST_CASE_BODY(normalize_strips_leading_dot_slash)
{
	ATF_REQUIRE_EQ(normalizeArchiveEntry("./+CRATE.SPEC"), "+CRATE.SPEC");
	ATF_REQUIRE_EQ(normalizeArchiveEntry("./root/etc"), "root/etc");
}

ATF_TEST_CASE_WITHOUT_HEAD(normalize_strips_trailing_slash);
ATF_TEST_CASE_BODY(normalize_strips_trailing_slash)
{
	ATF_REQUIRE_EQ(normalizeArchiveEntry("dir/"), "dir");
	ATF_REQUIRE_EQ(normalizeArchiveEntry("dir///"), "dir");
}

ATF_TEST_CASE_WITHOUT_HEAD(normalize_combined);
ATF_TEST_CASE_BODY(normalize_combined)
{
	ATF_REQUIRE_EQ(normalizeArchiveEntry("./root/"), "root");
}

ATF_TEST_CASE_WITHOUT_HEAD(normalize_no_change);
ATF_TEST_CASE_BODY(normalize_no_change)
{
	ATF_REQUIRE_EQ(normalizeArchiveEntry("+CRATE.SPEC"), "+CRATE.SPEC");
	ATF_REQUIRE_EQ(normalizeArchiveEntry("plain"), "plain");
}

ATF_TEST_CASE_WITHOUT_HEAD(normalize_empty);
ATF_TEST_CASE_BODY(normalize_empty)
{
	ATF_REQUIRE_EQ(normalizeArchiveEntry(""), "");
	ATF_REQUIRE_EQ(normalizeArchiveEntry("/"), "");
	ATF_REQUIRE_EQ(normalizeArchiveEntry("///"), "");
}

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, parseSha256_bsd_format);
	ATF_ADD_TEST_CASE(tcs, parseSha256_gnu_format);
	ATF_ADD_TEST_CASE(tcs, parseSha256_trailing_whitespace);
	ATF_ADD_TEST_CASE(tcs, parseSha256_empty);

	ATF_ADD_TEST_CASE(tcs, traversal_clean_listing);
	ATF_ADD_TEST_CASE(tcs, traversal_dotdot_segment_rejected);
	ATF_ADD_TEST_CASE(tcs, traversal_dotdot_anywhere_rejected);
	ATF_ADD_TEST_CASE(tcs, traversal_empty_listing);
	ATF_ADD_TEST_CASE(tcs, traversal_single_dot_ok);

	ATF_ADD_TEST_CASE(tcs, normalize_strips_leading_dot_slash);
	ATF_ADD_TEST_CASE(tcs, normalize_strips_trailing_slash);
	ATF_ADD_TEST_CASE(tcs, normalize_combined);
	ATF_ADD_TEST_CASE(tcs, normalize_no_change);
	ATF_ADD_TEST_CASE(tcs, normalize_empty);
}
