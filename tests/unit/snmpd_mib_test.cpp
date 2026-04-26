// ATF unit tests for AgentX wire-protocol encoders from snmpd/mib.cpp
//
// Verifies byte-exact output of encodeUint32, encodeOid, encodeOctetString
// against RFC 2741 (AgentX wire format).
//
// Build:
//   c++ -std=c++17 -o tests/unit/snmpd_mib_test \
//       tests/unit/snmpd_mib_test.cpp -L/usr/local/lib -latf-c++ -latf-c
//
// Run:
//   cd tests && kyua test

#include <atf-c++.hpp>
#include <cstdint>
#include <string>
#include <vector>

// ===================================================================
// Local copies of pure encoders from snmpd/mib.cpp
// ===================================================================

static void encodeUint32(std::vector<uint8_t> &buf, uint32_t val) {
	buf.push_back((val >> 24) & 0xFF);
	buf.push_back((val >> 16) & 0xFF);
	buf.push_back((val >> 8) & 0xFF);
	buf.push_back(val & 0xFF);
}

static void encodeOid(std::vector<uint8_t> &buf, const std::vector<uint32_t> &oid,
                      bool include = false) {
	uint8_t prefix = 0;
	size_t start = 0;
	if (oid.size() >= 5 &&
	    oid[0] == 1 && oid[1] == 3 && oid[2] == 6 && oid[3] == 1 && oid[4] <= 255) {
		prefix = (uint8_t)oid[4];
		start = 5;
	}

	uint32_t nSubid = (uint32_t)(oid.size() - start);
	encodeUint32(buf, nSubid);
	buf.push_back(prefix);
	buf.push_back(include ? 1 : 0);
	buf.push_back(0); // reserved
	buf.push_back(0);
	for (size_t i = start; i < oid.size(); i++)
		encodeUint32(buf, oid[i]);
}

static void encodeOctetString(std::vector<uint8_t> &buf, const std::string &s) {
	encodeUint32(buf, (uint32_t)s.size());
	for (char c : s)
		buf.push_back((uint8_t)c);
	while (buf.size() % 4 != 0)
		buf.push_back(0);
}

// ===================================================================
// Tests: encodeUint32 — network byte order (big-endian)
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(encodeUint32_zero);
ATF_TEST_CASE_BODY(encodeUint32_zero)
{
	std::vector<uint8_t> buf;
	encodeUint32(buf, 0);
	ATF_REQUIRE_EQ(buf.size(), 4u);
	ATF_REQUIRE_EQ(buf[0], 0x00);
	ATF_REQUIRE_EQ(buf[1], 0x00);
	ATF_REQUIRE_EQ(buf[2], 0x00);
	ATF_REQUIRE_EQ(buf[3], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeUint32_max);
ATF_TEST_CASE_BODY(encodeUint32_max)
{
	std::vector<uint8_t> buf;
	encodeUint32(buf, 0xFFFFFFFFu);
	ATF_REQUIRE_EQ(buf.size(), 4u);
	ATF_REQUIRE_EQ(buf[0], 0xFF);
	ATF_REQUIRE_EQ(buf[1], 0xFF);
	ATF_REQUIRE_EQ(buf[2], 0xFF);
	ATF_REQUIRE_EQ(buf[3], 0xFF);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeUint32_endianness);
ATF_TEST_CASE_BODY(encodeUint32_endianness)
{
	// 0x12345678 must encode to 12 34 56 78 (big-endian, regardless of host)
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
	// Existing buffer contents must be preserved
	std::vector<uint8_t> buf = {0xAA, 0xBB};
	encodeUint32(buf, 1);
	ATF_REQUIRE_EQ(buf.size(), 6u);
	ATF_REQUIRE_EQ(buf[0], 0xAA);
	ATF_REQUIRE_EQ(buf[1], 0xBB);
	ATF_REQUIRE_EQ(buf[5], 0x01);
}

// ===================================================================
// Tests: encodeOid — RFC 2741 §5.1
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_short_no_prefix);
ATF_TEST_CASE_BODY(encodeOid_short_no_prefix)
{
	// 4-element OID — too short for prefix optimization
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1});
	// header: nSubid=4, prefix=0, include=0, reserved=0,0
	ATF_REQUIRE_EQ(buf.size(), 8u + 4u * 4u);
	ATF_REQUIRE_EQ(buf[3], 0x04);  // n_subid LSB
	ATF_REQUIRE_EQ(buf[4], 0x00);  // prefix
	ATF_REQUIRE_EQ(buf[5], 0x00);  // include
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_with_prefix);
ATF_TEST_CASE_BODY(encodeOid_with_prefix)
{
	// .1.3.6.1.4.1.59999.1.1.0 — should use prefix=4, omit .1.3.6.1.4
	// AgentX header: n_subid=5 (1, 59999, 1, 1, 0), prefix=4
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 4, 1, 59999, 1, 1, 0});
	// nSubid (4B) + prefix (1B) + include (1B) + reserved (2B) + 5*4B subids
	ATF_REQUIRE_EQ(buf.size(), 8u + 5u * 4u);
	ATF_REQUIRE_EQ(buf[3], 0x05);  // 5 sub-identifiers after prefix
	ATF_REQUIRE_EQ(buf[4], 0x04);  // prefix = oid[4] = 4
	ATF_REQUIRE_EQ(buf[5], 0x00);  // include = false
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_include_flag);
ATF_TEST_CASE_BODY(encodeOid_include_flag)
{
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1}, true);
	ATF_REQUIRE_EQ(buf[5], 0x01);  // include byte
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_prefix_threshold);
ATF_TEST_CASE_BODY(encodeOid_prefix_threshold)
{
	// oid[4] == 256 — exceeds single-byte prefix range, no compression
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 256, 1, 2});
	ATF_REQUIRE_EQ(buf[3], 0x07);  // all 7 sub-ids encoded
	ATF_REQUIRE_EQ(buf[4], 0x00);  // no prefix used
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOid_subid_byte_order);
ATF_TEST_CASE_BODY(encodeOid_subid_byte_order)
{
	// Sub-ids are encoded as big-endian uint32 — verify with 59999 = 0x0000EA5F
	std::vector<uint8_t> buf;
	encodeOid(buf, {1, 3, 6, 1, 4, 1, 59999});
	// after 8-byte header, first sub-id = 1 (00 00 00 01)
	ATF_REQUIRE_EQ(buf[8], 0x00);
	ATF_REQUIRE_EQ(buf[9], 0x00);
	ATF_REQUIRE_EQ(buf[10], 0x00);
	ATF_REQUIRE_EQ(buf[11], 0x01);
	// next sub-id = 59999 = 0x0000EA5F
	ATF_REQUIRE_EQ(buf[12], 0x00);
	ATF_REQUIRE_EQ(buf[13], 0x00);
	ATF_REQUIRE_EQ(buf[14], 0xEA);
	ATF_REQUIRE_EQ(buf[15], 0x5F);
}

// ===================================================================
// Tests: encodeOctetString — RFC 2741 §5.3 (length-prefixed, padded to 4)
// ===================================================================

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_empty);
ATF_TEST_CASE_BODY(encodeOctetString_empty)
{
	std::vector<uint8_t> buf;
	encodeOctetString(buf, "");
	// length=0, no string bytes, no padding (already multiple of 4)
	ATF_REQUIRE_EQ(buf.size(), 4u);
	ATF_REQUIRE_EQ(buf[0], 0x00);
	ATF_REQUIRE_EQ(buf[3], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_aligned);
ATF_TEST_CASE_BODY(encodeOctetString_aligned)
{
	// 4-byte string — no padding needed
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
	// 1-byte string — needs 3 bytes of padding
	std::vector<uint8_t> buf;
	encodeOctetString(buf, "x");
	ATF_REQUIRE_EQ(buf.size(), 8u);
	ATF_REQUIRE_EQ(buf[3], 0x01);  // length
	ATF_REQUIRE_EQ(buf[4], 'x');
	ATF_REQUIRE_EQ(buf[5], 0x00);
	ATF_REQUIRE_EQ(buf[6], 0x00);
	ATF_REQUIRE_EQ(buf[7], 0x00);
}

ATF_TEST_CASE_WITHOUT_HEAD(encodeOctetString_padding_2);
ATF_TEST_CASE_BODY(encodeOctetString_padding_2)
{
	// 5-byte string — needs 3 bytes of padding to reach 12
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
	// Padding is to total buffer alignment, not to string-only alignment.
	// Pre-fill buf with 2 bytes; encoding "x" (1 byte) gives 4 (len) + 1 (x)
	// = total 7, padded to 8 (next multiple of 4).
	std::vector<uint8_t> buf = {0xDE, 0xAD};
	encodeOctetString(buf, "x");
	ATF_REQUIRE_EQ(buf.size() % 4u, 0u);
	ATF_REQUIRE_EQ(buf.size(), 8u);
}

// ===================================================================
// Registration
// ===================================================================

ATF_INIT_TEST_CASES(tcs)
{
	// encodeUint32
	ATF_ADD_TEST_CASE(tcs, encodeUint32_zero);
	ATF_ADD_TEST_CASE(tcs, encodeUint32_max);
	ATF_ADD_TEST_CASE(tcs, encodeUint32_endianness);
	ATF_ADD_TEST_CASE(tcs, encodeUint32_appends);

	// encodeOid
	ATF_ADD_TEST_CASE(tcs, encodeOid_short_no_prefix);
	ATF_ADD_TEST_CASE(tcs, encodeOid_with_prefix);
	ATF_ADD_TEST_CASE(tcs, encodeOid_include_flag);
	ATF_ADD_TEST_CASE(tcs, encodeOid_prefix_threshold);
	ATF_ADD_TEST_CASE(tcs, encodeOid_subid_byte_order);

	// encodeOctetString
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_empty);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_aligned);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_padding_1);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_padding_2);
	ATF_ADD_TEST_CASE(tcs, encodeOctetString_padding_aligned_after_existing);
}
