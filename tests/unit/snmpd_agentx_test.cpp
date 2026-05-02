// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.
//
// AgentX wire-protocol decoders + varBind encoders (RFC 2741).

#include "mib_pure.h"

#include <atf-c++.hpp>

#include <cstdint>
#include <string>
#include <vector>

using namespace MibPure;

namespace {

std::vector<uint8_t> roundTripHeader(const Header &h) {
  std::vector<uint8_t> buf;
  encodeHeader(buf, h);
  return buf;
}

} // anon

// --- Header encode/decode round-trip ---

ATF_TEST_CASE_WITHOUT_HEAD(header_round_trip);
ATF_TEST_CASE_BODY(header_round_trip) {
  Header h;
  h.version = 1;
  h.type = PDU_GET;
  h.flags = 0;          // encodeHeader will OR in NETWORK_BYTE_ORDER
  h.sessionId = 0xdeadbeef;
  h.transactionId = 1234;
  h.packetId = 5678;
  h.payloadLen = 100;
  auto buf = roundTripHeader(h);
  ATF_REQUIRE_EQ(buf.size(), (size_t)20);
  ATF_REQUIRE((buf[2] & 0x10) != 0);    // NETWORK_BYTE_ORDER set

  Header out;
  ATF_REQUIRE_EQ(decodeHeader(buf, 0, out), 20);
  ATF_REQUIRE_EQ(out.version,       (uint8_t)1);
  ATF_REQUIRE_EQ(out.type,          (uint8_t)PDU_GET);
  ATF_REQUIRE_EQ(out.sessionId,     (uint32_t)0xdeadbeef);
  ATF_REQUIRE_EQ(out.transactionId, (uint32_t)1234);
  ATF_REQUIRE_EQ(out.packetId,      (uint32_t)5678);
  ATF_REQUIRE_EQ(out.payloadLen,    (uint32_t)100);
}

ATF_TEST_CASE_WITHOUT_HEAD(header_short_input_returns_zero);
ATF_TEST_CASE_BODY(header_short_input_returns_zero) {
  Header out;
  std::vector<uint8_t> empty;
  ATF_REQUIRE_EQ(decodeHeader(empty, 0, out), 0);
  std::vector<uint8_t> almost(19, 0);
  ATF_REQUIRE_EQ(decodeHeader(almost, 0, out), 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(header_little_endian_flag_clear);
ATF_TEST_CASE_BODY(header_little_endian_flag_clear) {
  // Manually construct a little-endian header (NETWORK_BYTE_ORDER bit clear).
  std::vector<uint8_t> buf = {
    1, PDU_GET, 0x00 /*flags: BE bit clear*/, 0,
    0x78, 0x56, 0x34, 0x12,   // sessionId LE
    0x00, 0x00, 0x00, 0x00,   // transactionId
    0x00, 0x00, 0x00, 0x00,   // packetId
    0x10, 0x00, 0x00, 0x00,   // payloadLen LE = 16
  };
  Header out;
  ATF_REQUIRE_EQ(decodeHeader(buf, 0, out), 20);
  ATF_REQUIRE_EQ(out.sessionId,  (uint32_t)0x12345678);
  ATF_REQUIRE_EQ(out.payloadLen, (uint32_t)16);
}

// --- OID encode/decode round-trip ---

ATF_TEST_CASE_WITHOUT_HEAD(oid_round_trip_no_prefix);
ATF_TEST_CASE_BODY(oid_round_trip_no_prefix) {
  std::vector<uint8_t> buf;
  std::vector<uint32_t> oid = {1, 3, 6, 1};
  encodeOid(buf, oid);
  std::vector<uint32_t> dec;
  bool inc = false;
  ATF_REQUIRE_EQ(decodeOid(buf, 0, dec, &inc), (int)buf.size());
  ATF_REQUIRE(dec == oid);
  ATF_REQUIRE(!inc);
}

ATF_TEST_CASE_WITHOUT_HEAD(oid_round_trip_with_prefix);
ATF_TEST_CASE_BODY(oid_round_trip_with_prefix) {
  std::vector<uint8_t> buf;
  std::vector<uint32_t> oid = {1, 3, 6, 1, 4, 1, 59999, 1, 2, 0};
  encodeOid(buf, oid);
  std::vector<uint32_t> dec;
  ATF_REQUIRE_EQ(decodeOid(buf, 0, dec), (int)buf.size());
  ATF_REQUIRE(dec == oid);
}

ATF_TEST_CASE_WITHOUT_HEAD(oid_round_trip_include_bit);
ATF_TEST_CASE_BODY(oid_round_trip_include_bit) {
  std::vector<uint8_t> buf;
  encodeOid(buf, {1, 3, 6, 1, 4, 1, 59999, 2, 1}, true);
  std::vector<uint32_t> dec;
  bool inc = false;
  ATF_REQUIRE(decodeOid(buf, 0, dec, &inc) > 0);
  ATF_REQUIRE(inc);
}

// --- OctetString round-trip ---

ATF_TEST_CASE_WITHOUT_HEAD(octetstring_round_trip);
ATF_TEST_CASE_BODY(octetstring_round_trip) {
  for (auto &s : std::vector<std::string>{"", "a", "abcd", "hello world", std::string(7, 'x')}) {
    std::vector<uint8_t> buf;
    encodeOctetString(buf, s);
    std::string dec;
    ATF_REQUIRE_EQ(decodeOctetString(buf, 0, dec), (int)buf.size());
    ATF_REQUIRE_EQ(dec, s);
  }
}

// --- SearchRange + GetRequest decoding ---

ATF_TEST_CASE_WITHOUT_HEAD(search_range_round_trip);
ATF_TEST_CASE_BODY(search_range_round_trip) {
  std::vector<uint32_t> a = {1, 3, 6, 1, 4, 1, 59999, 1, 1, 0};
  std::vector<uint32_t> b = {1, 3, 6, 1, 4, 1, 59999, 1, 1, 1};
  std::vector<uint8_t> buf;
  encodeOid(buf, a);
  encodeOid(buf, b);
  std::vector<uint32_t> da, db;
  ATF_REQUIRE_EQ(decodeSearchRange(buf, 0, da, db), (int)buf.size());
  ATF_REQUIRE(da == a);
  ATF_REQUIRE(db == b);
}

ATF_TEST_CASE_WITHOUT_HEAD(get_request_one_oid);
ATF_TEST_CASE_BODY(get_request_one_oid) {
  std::vector<uint32_t> a = {1, 3, 6, 1, 4, 1, 59999, 1, 1, 0};
  std::vector<uint32_t> b;
  std::vector<uint8_t> buf;
  encodeOid(buf, a);
  encodeOid(buf, b);   // null end OID = open range
  std::vector<std::vector<uint32_t>> oids;
  ATF_REQUIRE(decodeGetRequest(buf, 0, /*flags*/0, oids) > 0);
  ATF_REQUIRE_EQ(oids.size(), (size_t)1);
  ATF_REQUIRE(oids[0] == a);
}

ATF_TEST_CASE_WITHOUT_HEAD(get_request_two_oids);
ATF_TEST_CASE_BODY(get_request_two_oids) {
  std::vector<uint32_t> a = {1, 3, 6, 1, 4, 1, 59999, 1, 1, 0};
  std::vector<uint32_t> b = {1, 3, 6, 1, 4, 1, 59999, 1, 2, 0};
  std::vector<uint8_t> buf;
  encodeOid(buf, a); encodeOid(buf, std::vector<uint32_t>());
  encodeOid(buf, b); encodeOid(buf, std::vector<uint32_t>());
  std::vector<std::vector<uint32_t>> oids;
  ATF_REQUIRE(decodeGetRequest(buf, 0, 0, oids) > 0);
  ATF_REQUIRE_EQ(oids.size(), (size_t)2);
  ATF_REQUIRE(oids[0] == a);
  ATF_REQUIRE(oids[1] == b);
}

ATF_TEST_CASE_WITHOUT_HEAD(get_request_with_context_octetstring);
ATF_TEST_CASE_BODY(get_request_with_context_octetstring) {
  // NON_DEFAULT_CONTEXT flag (0x08): a leading octet-string precedes the
  // SearchRangeList. The decoder must skip it.
  std::vector<uint8_t> buf;
  encodeOctetString(buf, "ctx");
  std::vector<uint32_t> a = {1, 3, 6, 1};
  encodeOid(buf, a);
  encodeOid(buf, std::vector<uint32_t>());
  std::vector<std::vector<uint32_t>> oids;
  ATF_REQUIRE(decodeGetRequest(buf, 0, /*flags*/0x08, oids) > 0);
  ATF_REQUIRE_EQ(oids.size(), (size_t)1);
  ATF_REQUIRE(oids[0] == a);
}

// --- VarBind encoders ---

ATF_TEST_CASE_WITHOUT_HEAD(varbind_integer_encodes_type_tag);
ATF_TEST_CASE_BODY(varbind_integer_encodes_type_tag) {
  std::vector<uint8_t> buf;
  encodeVarBindInteger(buf, {1, 3, 6, 1, 4, 1, 59999, 1, 1, 0}, 42);
  // Type tag at bytes [0..1] big-endian
  ATF_REQUIRE_EQ(buf[0], 0x00);
  ATF_REQUIRE_EQ(buf[1], (uint8_t)VB_INTEGER);
  // Last 4 bytes are the value 42.
  ATF_REQUIRE_EQ(buf[buf.size() - 4], 0x00);
  ATF_REQUIRE_EQ(buf[buf.size() - 1], 42);
}

ATF_TEST_CASE_WITHOUT_HEAD(varbind_counter64_encodes_eight_bytes);
ATF_TEST_CASE_BODY(varbind_counter64_encodes_eight_bytes) {
  std::vector<uint8_t> buf;
  encodeVarBindCounter64(buf, {1, 3, 6, 1, 4, 1, 59999, 2, 1, 1, 6, 7}, 0x0102030405060708ULL);
  ATF_REQUIRE_EQ(buf[1], (uint8_t)VB_COUNTER64);
  // Last 8 bytes hold the value.
  ATF_REQUIRE_EQ(buf[buf.size() - 8], 0x01);
  ATF_REQUIRE_EQ(buf[buf.size() - 1], 0x08);
}

ATF_TEST_CASE_WITHOUT_HEAD(varbind_octetstring_pads);
ATF_TEST_CASE_BODY(varbind_octetstring_pads) {
  std::vector<uint8_t> buf;
  encodeVarBindOctetString(buf, {1, 3, 6, 1, 4, 1, 59999, 1, 3, 0}, "hi");
  // Type tag = 4 (OctetString)
  ATF_REQUIRE_EQ(buf[1], (uint8_t)VB_OCTETSTRING);
  // Total size must be 4-byte aligned (header + OID + length + 2-byte string + 2-byte padding).
  ATF_REQUIRE_EQ(buf.size() % 4, (size_t)0);
}

ATF_TEST_CASE_WITHOUT_HEAD(varbind_null_has_no_value_payload);
ATF_TEST_CASE_BODY(varbind_null_has_no_value_payload) {
  std::vector<uint8_t> buf;
  encodeVarBindNull(buf, {1, 3, 6, 1});
  // 4-byte VarBind header + 4-byte OID header + 4 sub-ids × 4 bytes = 24 bytes.
  ATF_REQUIRE_EQ(buf.size(), (size_t)24);
  ATF_REQUIRE_EQ(buf[1], (uint8_t)VB_NULL);
}

ATF_TEST_CASE_WITHOUT_HEAD(varbind_endofmibview_distinct_tag);
ATF_TEST_CASE_BODY(varbind_endofmibview_distinct_tag) {
  std::vector<uint8_t> buf;
  encodeVarBindEndOfMibView(buf, {1, 3, 6, 1});
  ATF_REQUIRE_EQ(buf[1], (uint8_t)VB_END_OF_MIB_VIEW);
}

// --- Response payload header ---

ATF_TEST_CASE_WITHOUT_HEAD(response_header_layout);
ATF_TEST_CASE_BODY(response_header_layout) {
  std::vector<uint8_t> buf;
  encodeResponseHeader(buf, /*sysUpTime*/0xCAFEBABE, /*errStatus*/0, /*errIndex*/0);
  ATF_REQUIRE_EQ(buf.size(), (size_t)8);
  ATF_REQUIRE_EQ(buf[0], 0xCA);
  ATF_REQUIRE_EQ(buf[1], 0xFE);
  ATF_REQUIRE_EQ(buf[2], 0xBA);
  ATF_REQUIRE_EQ(buf[3], 0xBE);
  ATF_REQUIRE_EQ(buf[4], 0); ATF_REQUIRE_EQ(buf[5], 0);    // err status
  ATF_REQUIRE_EQ(buf[6], 0); ATF_REQUIRE_EQ(buf[7], 0);    // err index
}

ATF_TEST_CASE_WITHOUT_HEAD(response_header_carries_error);
ATF_TEST_CASE_BODY(response_header_carries_error) {
  std::vector<uint8_t> buf;
  encodeResponseHeader(buf, 0, ERR_GENERIC, 3);
  ATF_REQUIRE_EQ(buf[5], (uint8_t)ERR_GENERIC);
  ATF_REQUIRE_EQ(buf[7], 3);
}

// --- OID comparison ---

ATF_TEST_CASE_WITHOUT_HEAD(oid_compare_orders_lexicographically);
ATF_TEST_CASE_BODY(oid_compare_orders_lexicographically) {
  ATF_REQUIRE_EQ(compareOid({1, 3, 6}, {1, 3, 6}), 0);
  ATF_REQUIRE(compareOid({1, 3, 6}, {1, 3, 7}) < 0);
  ATF_REQUIRE(compareOid({1, 3, 7}, {1, 3, 6}) > 0);
  // Prefix: shorter is less.
  ATF_REQUIRE(compareOid({1, 3, 6}, {1, 3, 6, 1}) < 0);
  ATF_REQUIRE(compareOid({1, 3, 6, 1}, {1, 3, 6}) > 0);
  // Sub-id comparison treats values as unsigned 32-bit.
  ATF_REQUIRE(compareOid({1, 3, 6, 1, 100}, {1, 3, 6, 1, 99}) > 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(oid_is_child_of);
ATF_TEST_CASE_BODY(oid_is_child_of) {
  std::vector<uint32_t> base = {1, 3, 6, 1, 4, 1, 59999};
  ATF_REQUIRE(oidIsChildOf({1, 3, 6, 1, 4, 1, 59999, 1, 1, 0}, base));
  ATF_REQUIRE(!oidIsChildOf(base, base));      // not strict child of itself
  ATF_REQUIRE(!oidIsChildOf({1, 3, 6, 1, 4, 1, 59998}, base));
  ATF_REQUIRE(!oidIsChildOf({1, 3}, base));    // shorter
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, header_round_trip);
  ATF_ADD_TEST_CASE(tcs, header_short_input_returns_zero);
  ATF_ADD_TEST_CASE(tcs, header_little_endian_flag_clear);
  ATF_ADD_TEST_CASE(tcs, oid_round_trip_no_prefix);
  ATF_ADD_TEST_CASE(tcs, oid_round_trip_with_prefix);
  ATF_ADD_TEST_CASE(tcs, oid_round_trip_include_bit);
  ATF_ADD_TEST_CASE(tcs, octetstring_round_trip);
  ATF_ADD_TEST_CASE(tcs, search_range_round_trip);
  ATF_ADD_TEST_CASE(tcs, get_request_one_oid);
  ATF_ADD_TEST_CASE(tcs, get_request_two_oids);
  ATF_ADD_TEST_CASE(tcs, get_request_with_context_octetstring);
  ATF_ADD_TEST_CASE(tcs, varbind_integer_encodes_type_tag);
  ATF_ADD_TEST_CASE(tcs, varbind_counter64_encodes_eight_bytes);
  ATF_ADD_TEST_CASE(tcs, varbind_octetstring_pads);
  ATF_ADD_TEST_CASE(tcs, varbind_null_has_no_value_payload);
  ATF_ADD_TEST_CASE(tcs, varbind_endofmibview_distinct_tag);
  ATF_ADD_TEST_CASE(tcs, response_header_layout);
  ATF_ADD_TEST_CASE(tcs, response_header_carries_error);
  ATF_ADD_TEST_CASE(tcs, oid_compare_orders_lexicographically);
  ATF_ADD_TEST_CASE(tcs, oid_is_child_of);
}
