// ATF unit tests for AutoNamePure (lib/autoname_pure.cpp).
//
// Verifies the timestamp-based name format. Doesn't pin the exact value
// (would be flaky), but does pin the structure.

#include <atf-c++.hpp>
#include <cctype>
#include <regex>
#include <string>

#include "autoname_pure.h"

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_name_format);
ATF_TEST_CASE_BODY(snapshot_name_format)
{
	auto name = AutoNamePure::snapshotName();
	// "20260428T204122" — 15 chars, all digits except 'T' at position 8.
	ATF_REQUIRE_EQ(name.size(), 15u);
	ATF_REQUIRE_EQ(name[8], 'T');
	for (size_t i = 0; i < name.size(); i++)
		if (i != 8)
			ATF_REQUIRE(std::isdigit(static_cast<unsigned char>(name[i])));
}

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_name_year_plausible);
ATF_TEST_CASE_BODY(snapshot_name_year_plausible)
{
	auto name = AutoNamePure::snapshotName();
	int year = std::stoi(name.substr(0, 4));
	// Sanity: year is somewhere this side of 1970 and not the year 9999.
	ATF_REQUIRE(year >= 2025 && year < 2100);
}

ATF_TEST_CASE_WITHOUT_HEAD(export_name_format);
ATF_TEST_CASE_BODY(export_name_format)
{
	auto name = AutoNamePure::exportName("web");
	// Expected pattern: web-YYYYMMDD-HHMMSS.crate
	std::regex pat(R"(^web-\d{8}-\d{6}\.crate$)");
	ATF_REQUIRE(std::regex_match(name, pat));
}

ATF_TEST_CASE_WITHOUT_HEAD(export_name_preserves_basename);
ATF_TEST_CASE_BODY(export_name_preserves_basename)
{
	auto name = AutoNamePure::exportName("my-container");
	ATF_REQUIRE(name.compare(0, 13, "my-container-") == 0);
	ATF_REQUIRE(name.size() >= std::string("my-container-").size() + 8 + 1 + 6 + 6);
	// ends with .crate
	ATF_REQUIRE(name.compare(name.size() - 6, 6, ".crate") == 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(export_name_empty_basename);
ATF_TEST_CASE_BODY(export_name_empty_basename)
{
	auto name = AutoNamePure::exportName("");
	// "-YYYYMMDD-HHMMSS.crate" — leading hyphen, then digits.
	ATF_REQUIRE_EQ(name[0], '-');
	std::regex pat(R"(^-\d{8}-\d{6}\.crate$)");
	ATF_REQUIRE(std::regex_match(name, pat));
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, snapshot_name_format);
	ATF_ADD_TEST_CASE(tcs, snapshot_name_year_plausible);
	ATF_ADD_TEST_CASE(tcs, export_name_format);
	ATF_ADD_TEST_CASE(tcs, export_name_preserves_basename);
	ATF_ADD_TEST_CASE(tcs, export_name_empty_basename);
}
