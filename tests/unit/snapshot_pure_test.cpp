// ATF unit tests for SnapshotPure (lib/snapshot_pure.cpp).

#include <atf-c++.hpp>
#include <string>
#include <vector>

#include "snapshot_pure.h"

using SnapshotPure::Entry;
using SnapshotPure::renderTableStr;

ATF_TEST_CASE_WITHOUT_HEAD(table_empty_dataset);
ATF_TEST_CASE_BODY(table_empty_dataset)
{
	auto out = renderTableStr("tank/jails/web", {});
	ATF_REQUIRE_EQ(out, "No snapshots found for tank/jails/web\n");
}

ATF_TEST_CASE_WITHOUT_HEAD(table_header);
ATF_TEST_CASE_BODY(table_header)
{
	std::vector<Entry> snaps = {
		{"tank/jails/web@2026-01-01", "1.5G", "5.2G", "2026-01-01 10:00"},
	};
	auto out = renderTableStr("tank/jails/web", snaps);
	ATF_REQUIRE(out.find("NAME") != std::string::npos);
	ATF_REQUIRE(out.find("CREATION") != std::string::npos);
	ATF_REQUIRE(out.find("USED") != std::string::npos);
	ATF_REQUIRE(out.find("REFER") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(table_data_columns);
ATF_TEST_CASE_BODY(table_data_columns)
{
	std::vector<Entry> snaps = {
		{"tank@a", "1G", "2G", "2026-01-01"},
	};
	auto out = renderTableStr("tank", snaps);
	ATF_REQUIRE(out.find("tank@a") != std::string::npos);
	ATF_REQUIRE(out.find("1G") != std::string::npos);
	ATF_REQUIRE(out.find("2G") != std::string::npos);
	ATF_REQUIRE(out.find("2026-01-01") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(table_multiple_rows);
ATF_TEST_CASE_BODY(table_multiple_rows)
{
	std::vector<Entry> snaps = {
		{"tank@a", "1G", "2G", "2026-01-01"},
		{"tank@b", "3G", "4G", "2026-02-01"},
	};
	auto out = renderTableStr("tank", snaps);
	ATF_REQUIRE(out.find("tank@a") != std::string::npos);
	ATF_REQUIRE(out.find("tank@b") != std::string::npos);
	// Header + 2 rows = 3 newlines minimum
	int nl = 0;
	for (char c : out) if (c == '\n') nl++;
	ATF_REQUIRE(nl >= 3);
}

ATF_TEST_CASE_WITHOUT_HEAD(table_long_name_still_padded);
ATF_TEST_CASE_BODY(table_long_name_still_padded)
{
	// Name longer than 44 chars — padding clamps to min(1) but doesn't crash.
	std::vector<Entry> snaps = {
		{std::string(60, 'x') + "@snap", "1G", "2G", "2026-01-01"},
	};
	auto out = renderTableStr("tank", snaps);
	ATF_REQUIRE(out.find("xxxxxx@snap") != std::string::npos);
	// Creation column still appears
	ATF_REQUIRE(out.find("2026-01-01") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, table_empty_dataset);
	ATF_ADD_TEST_CASE(tcs, table_header);
	ATF_ADD_TEST_CASE(tcs, table_data_columns);
	ATF_ADD_TEST_CASE(tcs, table_multiple_rows);
	ATF_ADD_TEST_CASE(tcs, table_long_name_still_padded);
}
