// ATF unit tests for ListPure (lib/list_pure.cpp).
//
// `crate list` (and `crate list -j`) display logic. A regression here
// breaks operator dashboards and any JSON-consuming tooling.

#include <atf-c++.hpp>
#include <sstream>
#include <string>
#include <vector>

#include "list_pure.h"

using ListPure::Entry;
using ListPure::renderJsonStr;
using ListPure::renderTableStr;

static Entry mkEntry(int jid, const std::string &name) {
	Entry e;
	e.jid = jid;
	e.name = name;
	e.path = "/var/run/crate/" + name;
	e.ip = "10.0.0." + std::to_string(jid);
	e.hostname = name + ".local";
	e.ports = "80,443";
	e.mounts = "2";
	e.hasHealthcheck = true;
	return e;
}

// ===================================================================
// JSON
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(json_empty);
ATF_TEST_CASE_BODY(json_empty)
{
	ATF_REQUIRE_EQ(renderJsonStr({}), "[\n]\n");
}

ATF_TEST_CASE_WITHOUT_HEAD(json_one_entry);
ATF_TEST_CASE_BODY(json_one_entry)
{
	auto out = renderJsonStr({mkEntry(1, "web")});
	ATF_REQUIRE(out.find("\"jid\":1") != std::string::npos);
	ATF_REQUIRE(out.find("\"name\":\"web\"") != std::string::npos);
	ATF_REQUIRE(out.find("\"hostname\":\"web.local\"") != std::string::npos);
	ATF_REQUIRE(out.find("\"healthcheck\":true") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_separator_between_entries);
ATF_TEST_CASE_BODY(json_separator_between_entries)
{
	auto out = renderJsonStr({mkEntry(1, "a"), mkEntry(2, "b")});
	// Comma between objects, none after the last.
	ATF_REQUIRE(out.find("},") != std::string::npos);
	// "}\n]" at the end (no trailing comma).
	ATF_REQUIRE(out.rfind(",\n]") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_healthcheck_false);
ATF_TEST_CASE_BODY(json_healthcheck_false)
{
	auto e = mkEntry(1, "web"); e.hasHealthcheck = false;
	auto out = renderJsonStr({e});
	ATF_REQUIRE(out.find("\"healthcheck\":false") != std::string::npos);
}

// ===================================================================
// Table
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(table_empty);
ATF_TEST_CASE_BODY(table_empty)
{
	ATF_REQUIRE_EQ(renderTableStr({}), "No running crate containers.\n");
}

ATF_TEST_CASE_WITHOUT_HEAD(table_header_present);
ATF_TEST_CASE_BODY(table_header_present)
{
	auto out = renderTableStr({mkEntry(1, "web")});
	ATF_REQUIRE(out.find("JID") != std::string::npos);
	ATF_REQUIRE(out.find("NAME") != std::string::npos);
	ATF_REQUIRE(out.find("IP") != std::string::npos);
	ATF_REQUIRE(out.find("HOSTNAME") != std::string::npos);
	ATF_REQUIRE(out.find("PORTS") != std::string::npos);
	ATF_REQUIRE(out.find("MOUNTS") != std::string::npos);
	ATF_REQUIRE(out.find("HC") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(table_singular_plural);
ATF_TEST_CASE_BODY(table_singular_plural)
{
	auto one = renderTableStr({mkEntry(1, "web")});
	ATF_REQUIRE(one.find("1 running container.") != std::string::npos);

	auto many = renderTableStr({mkEntry(1, "a"), mkEntry(2, "b")});
	ATF_REQUIRE(many.find("2 running containers.") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(table_dash_for_empty_fields);
ATF_TEST_CASE_BODY(table_dash_for_empty_fields)
{
	Entry e;
	e.jid = 5; e.name = "x";
	auto out = renderTableStr({e});
	// IP / PORTS / MOUNTS each replaced with "-" when empty.
	// Count "- " (dash-space) occurrences in the data row — at least 3.
	size_t count = 0;
	size_t pos = 0;
	while ((pos = out.find("- ", pos)) != std::string::npos) { count++; pos++; }
	ATF_REQUIRE(count >= 3u);
}

ATF_TEST_CASE_WITHOUT_HEAD(table_hc_y_n);
ATF_TEST_CASE_BODY(table_hc_y_n)
{
	auto y = renderTableStr({mkEntry(1, "web")});
	ATF_REQUIRE(y.find("Y\n") != std::string::npos);

	auto e = mkEntry(1, "web"); e.hasHealthcheck = false;
	auto n = renderTableStr({e});
	ATF_REQUIRE(n.find("-\n") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, json_empty);
	ATF_ADD_TEST_CASE(tcs, json_one_entry);
	ATF_ADD_TEST_CASE(tcs, json_separator_between_entries);
	ATF_ADD_TEST_CASE(tcs, json_healthcheck_false);
	ATF_ADD_TEST_CASE(tcs, table_empty);
	ATF_ADD_TEST_CASE(tcs, table_header_present);
	ATF_ADD_TEST_CASE(tcs, table_singular_plural);
	ATF_ADD_TEST_CASE(tcs, table_dash_for_empty_fields);
	ATF_ADD_TEST_CASE(tcs, table_hc_y_n);
}
