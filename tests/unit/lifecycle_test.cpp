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

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, humanBytes_zero);
	ATF_ADD_TEST_CASE(tcs, humanBytes_bytes);
	ATF_ADD_TEST_CASE(tcs, humanBytes_kilobytes);
	ATF_ADD_TEST_CASE(tcs, humanBytes_megabytes);
	ATF_ADD_TEST_CASE(tcs, humanBytes_gigabytes);
	ATF_ADD_TEST_CASE(tcs, humanBytes_boundary);
}
