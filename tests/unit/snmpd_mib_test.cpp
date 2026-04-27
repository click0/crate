// ATF unit tests for AgentX wire-protocol encoders from snmpd/mib.cpp.
//
// Uses real MibPure:: symbols from snmpd/mib_pure.cpp.

#include <atf-c++.hpp>
#include <cstdint>
#include <string>
#include <vector>

#include "mib_pure.h"

using MibPure::encodeUint32;
using MibPure::encodeOid;
using MibPure::encodeOctetString;

ATF_TEST_CASE_WITHOUT_HEAD(encodeUint32_zero);
ATF_TEST_CASE_BODY(encodeUint32_zero)
{
	std::vector<uint8_t> buf;
	encodeUint32(buf, 0);
	ATF_REQUIRE_EQ(buf.size(), 4u);
	ATF_REQUIRE_EQ(buf[0], 0x00);
	ATF_REQUIRE_EQ(buf[3], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeUint32_max);
ATF_TEST_CASE_BODY(encodeUint32_max)
{
	std::vector<uint8_t> buf;
	encodeUint32(buf, 0xFFFFFFFFu);
	ATF_REQUIRE_EQ(buf.size(), 4u);
	ATF_REQUIRE_EQ(buf[0], 0xFF);
	ATF_REQUIRE_EQ(buf[3], 0xFF);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeUint32_endianness);
ATF_TEST_CASE_BODY(encodeUint32_endianness)
{
	std::vector<uint8_t> buf;
	encodeUint32(buf, 0x12345678);
	ATF_REQUIRE_EQ(buf[0], 0x12);
	ATF_REQUIRE_EQ(buf[1], 0x34);
	ATF_REQUIRE_EQ(buf[2], 0x56);
	ATF_REQUIRE_EQ(buf[3], 0x78);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeUint32_appends);
ATF_TEST_CASE_BODY(encodeUint32_appends)
{
	std::vector<uint8_t> buf = {0xAA, 0xBB};
	encodeUint32(buf, 1);
	ATF_REQUIRE_EQ(buf.size(), 6u);
	ATF_REQUIRE_EQ(buf[0], 0xAA);
	ATF_REQUIRE_EQ(buf[1], 0xBB);
	ATF_REQUIRE_EQ(buf[5], 0x01);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_short_no_prefix);
ATF_TEST_CASE_BODY(encodeOid_short_no_prefix)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1});
	ATF_REQUIRE_EQ(buf.size(), 8u + 4u * 4u);
	ATF_REQUIRE_EQ(buf[3], 0x04);
	ATF_REQUIRE_EQ(buf[4], 0x00);
	ATF_REQUIRE_EQ(buf[5], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_with_prefix);
ATF_TEST_CASE_BODY(encodeOid_with_prefix)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 4, 1, 59999, 1, 1, 0});
	ATF_REQUIRE_EQ(buf.size(), 8u + 5u * 4u);
	ATF_REQUIRE_EQ(buf[3], 0x05);
	ATF_REQUIRE_EQ(buf[4], 0x04);
	ATF_REQUIRE_EQ(buf[5], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_include_flag);
ATF_TEST_CASE_BODY(encodeOid_include_flag)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1}, true);
	ATF_REQUIRE_EQ(buf[5], 0x01);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_prefix_threshold);
ATF_TEST_CASE_BODY(encodeOid_prefix_threshold)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 256, 1, 2});
	ATF_REQUIRE_EQ(buf[3], 0x07);
	ATF_REQUIRE_EQ(buf[4], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_subid_byte_order);
ATF_TEST_CASE_BODY(encodeOid_subid_byte_order)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 4, 1, 59999});
	ATF_REQUIRE_EQ(buf[8], 0x00);
	ATF_REQUIRE_EQ(buf[9], 0x00);
	ATF_REQUIRE_EQ(buf[10], 0x00);
	ATF_REQUIRE_EQ(buf[11], 0x01);
	ATF_REQUIRE_EQ(buf[12], 0x00);
	ATF_REQUIRE_EQ(buf[13], 0x00);
	ATF_REQUIRE_EQ(buf[14], 0xEA);
	ATF_REQUIRE_EQ(buf[15], 0x5F);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_empty);
ATF_TEST_CASE_BODY(encodeOctetString_empty)
{
	std::vector<uint8_t> buf;
	encodeOctetString(buf, "");
	ATF_REQUIRE_EQ(buf.size(), 4u);
	ATF_REQUIRE_EQ(buf[0], 0x00);
	ATF_REQUIRE_EQ(buf[3], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_aligned);
ATF_TEST_CASE_BODY(encodeOctetString_aligned)
{
	std::vector<uint8_t> buf;
	encodeOctetString(buf, "abcd");
	ATF_REQUIRE_EQ(buf.size(), 8u);
	ATF_REQUIRE_EQ(buf[3], 0x04);
	ATF_REQUIRE_EQ(buf[4], 'a');
	ATF_REQUIRE_EQ(buf[7], 'd');
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_padding_1);
ATF_TEST_CASE_BODY(encodeOctetString_padding_1)
{
	std::vector<uint8_t> buf;
	encodeOctetString(buf, "x");
	ATF_REQUIRE_EQ(buf.size(), 8u);
	ATF_REQUIRE_EQ(buf[3], 0x01);
	ATF_REQUIRE_EQ(buf[4], 'x');
	ATF_REQUIRE_EQ(buf[5], 0x00);
	ATF_REQUIRE_EQ(buf[6], 0x00);
	ATF_REQUIRE_EQ(buf[7], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_padding_2);
ATF_TEST_CASE_BODY(encodeOctetString_padding_2)
{
	std::vector<uint8_t> buf;
	encodeOctetString(buf, "hello");
	ATF_REQUIRE_EQ(buf.size(), 12u);
	ATF_REQUIRE_EQ(buf[3], 0x05);
	ATF_REQUIRE_EQ(buf[4], 'h');
	ATF_REQUIRE_EQ(buf[8], 'o');
	ATF_REQUIRE_EQ(buf[9], 0x00);
	ATF_REQUIRE_EQ(buf[10], 0x00);
	ATF_REQUIRE_EQ(buf[11], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_padding_aligned_after_existing);
ATF_TEST_CASE_BODY(encodeOctetString_padding_aligned_after_existing)
{
	std::vector<uint8_t> buf = {0xDE, 0xAD};
	encodeOctetString(buf, "x");
	ATF_REQUIRE_EQ(buf.size() % 4u, 0u);
	ATF_REQUIRE_EQ(buf.size(), 8u);
}

ATF_INIT_TEST_CASES(tcs)
{
	ATF_ADD_TEST_CASE(tcs, encodeUint32_zero);
	ATF_ADD_TEST_CASE(tcs, encodeUint32_max);
	ATF_ADD_TEST_CASE(tcs, encodeUint32_endianness);
	ATF_ADD_TEST_CASE(tcs, encodeUint32_appends);
	ATF_ADD_TEST_CASE(tcs, encodeOid_short_no_prefix);
	ATF_ADD_TEST_CASE(tcs, encodeOid_with_prefix);
	ATF_ADD_TEST_CASE(tcs, encodeOid_include_flag);
	ATF_ADD_TEST_CASE(tcs, encodeOid_prefix_threshold);
	ATF_ADD_TEST_CASE(tcs, encodeOid_subid_byte_order);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_empty);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_aligned);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_padding_1);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_padding_2);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_padding_aligned_after_existing);
}
