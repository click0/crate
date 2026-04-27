// ATF unit tests for parsing/validation helpers used by lib/import.cpp.
//
// Uses real ImportPure:: symbols from lib/import_pure.cpp.

#include <atf-c++.hpp>

#include "import_pure.h"

using ImportPure::parseSha256File;
using ImportPure::archiveHasTraversal;
using ImportPure::normalizeArchiveEntry;

ATF_TEST_CASE_WITHOUT_HEAD(parseSha256_bsd_format);
ATF_TEST_CASE_BODY(parseSha256_bsd_format)
{
	auto h = parseSha256File("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	ATF_REQUIRE_EQ(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseSha256_gnu_format);
ATF_TEST_CASE_BODY(parseSha256_gnu_format)
{
	auto h = parseSha256File("abc123  archive.crate");
	ATF_REQUIRE_EQ(h, "abc123");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseSha256_trailing_whitespace);
ATF_TEST_CASE_BODY(parseSha256_trailing_whitespace)
{
	ATF_REQUIRE_EQ(parseSha256File("abc123\r"),  "abc123");
	ATF_REQUIRE_EQ(parseSha256File("abc123\t"),  "abc123");
	ATF_REQUIRE_EQ(parseSha256File("abc123   "), "abc123");
}

ATF_TEST_CASE_WITHOUT_HEAD(parseSha256_empty);
ATF_TEST_CASE_BODY(parseSha256_empty)
{
	ATF_REQUIRE_EQ(parseSha256File(""), "");
}

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
	// Documents the current (intentionally aggressive) behaviour:
	// any ".." substring triggers the traversal check, even in
	// filenames like "release..notes".
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
	ATF_REQUIRE(!archiveHasTraversal("./file\n"));
	ATF_REQUIRE(!archiveHasTraversal("./.hidden\n"));
}

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
