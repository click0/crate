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
	// 4-byte header (nSubid, prefix, include, reserved) + 4 subids × 4 bytes
	ATF_REQUIRE_EQ(buf.size(), 4u + 4u * 4u);
	ATF_REQUIRE_EQ(buf[0], 0x04);    // n_subid = 4
	ATF_REQUIRE_EQ(buf[1], 0x00);    // prefix
	ATF_REQUIRE_EQ(buf[2], 0x00);    // include
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_with_prefix);
ATF_TEST_CASE_BODY(encodeOid_with_prefix)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 4, 1, 59999, 1, 1, 0});
	// First 5 sub-ids "1.3.6.1.4" become prefix=4; remaining 5 sub-ids encoded.
	ATF_REQUIRE_EQ(buf.size(), 4u + 5u * 4u);
	ATF_REQUIRE_EQ(buf[0], 0x05);    // n_subid = 5
	ATF_REQUIRE_EQ(buf[1], 0x04);    // prefix = 4
	ATF_REQUIRE_EQ(buf[2], 0x00);    // include
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_include_flag);
ATF_TEST_CASE_BODY(encodeOid_include_flag)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1}, true);
	ATF_REQUIRE_EQ(buf[2], 0x01);    // include
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_prefix_threshold);
ATF_TEST_CASE_BODY(encodeOid_prefix_threshold)
{
	// oid[4] = 256 exceeds the 1-byte prefix range, so no prefix optimisation.
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 256, 1, 2});
	ATF_REQUIRE_EQ(buf[0], 0x07);    // n_subid = 7
	ATF_REQUIRE_EQ(buf[1], 0x00);    // prefix = 0
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_subid_byte_order);
ATF_TEST_CASE_BODY(encodeOid_subid_byte_order)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 4, 1, 59999});
	// Header is 4 bytes; first subid (1) starts at offset 4.
	ATF_REQUIRE_EQ(buf[4], 0x00);
	ATF_REQUIRE_EQ(buf[5], 0x00);
	ATF_REQUIRE_EQ(buf[6], 0x00);
	ATF_REQUIRE_EQ(buf[7], 0x01);
	ATF_REQUIRE_EQ(buf[8],  0x00);
	ATF_REQUIRE_EQ(buf[9],  0x00);
	ATF_REQUIRE_EQ(buf[10], 0xEA);
	ATF_REQUIRE_EQ(buf[11], 0x5F);
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

// --- 1.1.50: decoder hardening ---

ATF_TEST_CASE_WITHOUT_HEAD(decodeOctetString_length_overflow_rejected);
ATF_TEST_CASE_BODY(decodeOctetString_length_overflow_rejected)
{
	// length 0xFFFFFFFE: (n + 3) wrapped to 1 → padded 0 → the bounds check
	// passed and out.assign() read ~4 GB past the buffer.
	std::vector<uint8_t> buf = {0xFF, 0xFF, 0xFF, 0xFE, 'a', 'b', 'c', 'd'};
	std::string out;
	ATF_REQUIRE_EQ(MibPure::decodeOctetString(buf, 0, out), 0);
	// a length larger than what is present is a short read, not a success
	std::vector<uint8_t> shortBuf = {0x00, 0x00, 0x00, 0x09, 'a', 'b', 'c', 'd'};
	ATF_REQUIRE_EQ(MibPure::decodeOctetString(shortBuf, 0, out), 0);
	// well-formed: "hello" padded to 8
	std::vector<uint8_t> ok = {0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o', 0, 0, 0};
	ATF_REQUIRE_EQ(MibPure::decodeOctetString(ok, 0, out), 12);
	ATF_REQUIRE_EQ(out, std::string("hello"));
}

ATF_TEST_CASE_WITHOUT_HEAD(decoders_honour_little_endian_flag);
ATF_TEST_CASE_BODY(decoders_honour_little_endian_flag)
{
	// OID with prefix 4 and one sub-id 59999 (0xEA5F) in LITTLE-endian
	std::vector<uint8_t> oidLe = {0x01, 0x04, 0x00, 0x00, 0x5F, 0xEA, 0x00, 0x00};
	std::vector<uint32_t> oid;
	ATF_REQUIRE_EQ(MibPure::decodeOid(oidLe, 0, oid, nullptr, /*bigEndian=*/false), 8);
	ATF_REQUIRE_EQ(oid.size(), 6u);
	ATF_REQUIRE_EQ(oid[5], 59999u);
	// the same bytes read big-endian are a different (huge) sub-id
	std::vector<uint32_t> oidBe;
	ATF_REQUIRE_EQ(MibPure::decodeOid(oidLe, 0, oidBe), 8);
	ATF_REQUIRE(oidBe[5] != 59999u);
	// octet string length little-endian
	std::vector<uint8_t> strLe = {0x02, 0x00, 0x00, 0x00, 'h', 'i', 0, 0};
	std::string out;
	ATF_REQUIRE_EQ(MibPure::decodeOctetString(strLe, 0, out, false), 8);
	ATF_REQUIRE_EQ(out, std::string("hi"));
	// decodeGetRequest picks the byte order from the header flags
	// (0x10 = NETWORK_BYTE_ORDER): one SearchRange, both OIDs LE.
	std::vector<uint8_t> req;
	for (int i = 0; i < 2; i++) req.insert(req.end(), oidLe.begin(), oidLe.end());
	std::vector<std::vector<uint32_t>> oids;
	ATF_REQUIRE(MibPure::decodeGetRequest(req, 0, /*flags=*/0x00, oids) > 0);
	ATF_REQUIRE_EQ(oids.size(), 1u);
	ATF_REQUIRE_EQ(oids[0][5], 59999u);
	ATF_REQUIRE(MibPure::kMaxPayloadLen >= 65536u);
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
	ATF_ADD_TEST_CASE(tcs, decodeOctetString_length_overflow_rejected);
	ATF_ADD_TEST_CASE(tcs, decoders_honour_little_endian_flag);
}
