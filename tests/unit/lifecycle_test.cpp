// ATF unit tests for humanBytes from lib/lifecycle.cpp.
//
// Uses real LifecyclePure::humanBytes from lib/lifecycle_pure.cpp.

#include <atf-c++.hpp>
#include <cstdint>

#include "lifecycle_pure.h"

using LifecyclePure::humanBytes;

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_zero);
ATF_TEST_CASE_BODY(humanBytes_zero)
{
	ATF_REQUIRE_EQ(humanBytes(0), "0B");
}

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_bytes);
ATF_TEST_CASE_BODY(humanBytes_bytes)
{
	ATF_REQUIRE_EQ(humanBytes(1), "1B");
	ATF_REQUIRE_EQ(humanBytes(512), "512B");
	ATF_REQUIRE_EQ(humanBytes(1023), "1023B");
}

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_kilobytes);
ATF_TEST_CASE_BODY(humanBytes_kilobytes)
{
	ATF_REQUIRE_EQ(humanBytes(1024), "1.0K");
	ATF_REQUIRE_EQ(humanBytes(1536), "1.5K");
	ATF_REQUIRE_EQ(humanBytes(10240), "10.0K");
}

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_megabytes);
ATF_TEST_CASE_BODY(humanBytes_megabytes)
{
	ATF_REQUIRE_EQ(humanBytes(1048576), "1.0M");
	ATF_REQUIRE_EQ(humanBytes(1572864), "1.5M");
	ATF_REQUIRE_EQ(humanBytes(536870912), "512.0M");
}

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_gigabytes);
ATF_TEST_CASE_BODY(humanBytes_gigabytes)
{
	ATF_REQUIRE_EQ(humanBytes(1073741824ULL), "1.0G");
	ATF_REQUIRE_EQ(humanBytes(1610612736ULL), "1.5G");
	ATF_REQUIRE_EQ(humanBytes(4294967296ULL), "4.0G");
	ATF_REQUIRE_EQ(humanBytes(17179869184ULL), "16.0G");
}

ATF_TEST_CASE_WITHOUT_HEAD(humanBytes_boundary);
ATF_TEST_CASE_BODY(humanBytes_boundary)
{
	ATF_REQUIRE_EQ(humanBytes(1023), "1023B");
	ATF_REQUIRE_EQ(humanBytes(1024), "1.0K");
	ATF_REQUIRE_EQ(humanBytes(1048575), "1024.0K");
	ATF_REQUIRE_EQ(humanBytes(1048576), "1.0M");
	ATF_REQUIRE_EQ(humanBytes(1073741823), "1024.0M");
	ATF_REQUIRE_EQ(humanBytes(1073741824), "1.0G");
}

// --- 1.1.44: netstat --libxo json interface counters ---

ATF_TEST_CASE_WITHOUT_HEAD(netstat_json_iface_bytes);
ATF_TEST_CASE_BODY(netstat_json_iface_bytes) {
	const std::string doc =
	  R"({"__version":"2","statistics":{"interface":[)"
	  R"({"name":"epair3a","flags":"0x8843","mtu":1500,"network":"<Link#5>","address":"02:00:00:00:00:0a",)"
	  R"("received-packets":10,"received-errors":0,"dropped-packets":0,"received-bytes":1536,)"
	  R"("sent-packets":7,"send-errors":0,"sent-bytes":4096,"collisions":0},)"
	  R"({"name":"epair3a","network":"10.0.0.100/31","address":"10.0.0.100",)"
	  R"("received-packets":9,"received-errors":0,"dropped-packets":0,"received-bytes":1200,)"
	  R"("sent-packets":6,"send-errors":0,"sent-bytes":3000,"collisions":0}]}})";
	uint64_t in = 0, out = 0;
	// first (link-level) object wins — that is the one with the interface totals
	ATF_REQUIRE(LifecyclePure::parseNetstatIfaceBytesJson(doc, "epair3a", in, out));
	ATF_REQUIRE_EQ(in, 1536u);
	ATF_REQUIRE_EQ(out, 4096u);
	// absent interface, non-JSON, empty, truncated object -> false
	ATF_REQUIRE(!LifecyclePure::parseNetstatIfaceBytesJson(doc, "epair9a", in, out));
	ATF_REQUIRE(!LifecyclePure::parseNetstatIfaceBytesJson("Name Mtu Network", "epair3a", in, out));
	ATF_REQUIRE(!LifecyclePure::parseNetstatIfaceBytesJson("", "epair3a", in, out));
	ATF_REQUIRE(!LifecyclePure::parseNetstatIfaceBytesJson(R"({"statistics":{"interface":[{"name":"epair3a","received-bytes":5}]}})", "epair3a", in, out));
	// large counters survive
	ATF_REQUIRE(LifecyclePure::parseNetstatIfaceBytesJson(
	  R"({"statistics":{"interface":[{"name":"epair0a","received-bytes": 18446744073709551615,"sent-bytes":1}]}})",
	  "epair0a", in, out));
	ATF_REQUIRE_EQ(in, 18446744073709551615ull);
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, humanBytes_zero);
	ATF_ADD_TEST_CASE(tcs, humanBytes_bytes);
	ATF_ADD_TEST_CASE(tcs, humanBytes_kilobytes);
	ATF_ADD_TEST_CASE(tcs, humanBytes_megabytes);
	ATF_ADD_TEST_CASE(tcs, humanBytes_gigabytes);
	ATF_ADD_TEST_CASE(tcs, humanBytes_boundary);
	ATF_ADD_TEST_CASE(tcs, netstat_json_iface_bytes);
}
