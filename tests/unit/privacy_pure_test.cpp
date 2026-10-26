// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "privacy_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace PrivacyPure;

ATF_TEST_CASE_WITHOUT_HEAD(hostid_modes);
ATF_TEST_CASE_BODY(hostid_modes) {
  Mode m; std::string v = "keep";
  ATF_REQUIRE_EQ(parseHostid("", m, v), std::string());        ATF_REQUIRE(m == Mode::Host);   ATF_REQUIRE(v.empty());
  ATF_REQUIRE_EQ(parseHostid("host", m, v), std::string());    ATF_REQUIRE(m == Mode::Host);
  ATF_REQUIRE_EQ(parseHostid("random", m, v), std::string());  ATF_REQUIRE(m == Mode::Random); ATF_REQUIRE(v.empty());
  ATF_REQUIRE_EQ(parseHostid("123E4567-E89B-12D3-A456-426614174000", m, v), std::string());
  ATF_REQUIRE(m == Mode::Fixed);
  ATF_REQUIRE_EQ(v, std::string("123e4567-e89b-12d3-a456-426614174000"));
  for (const char *bad : {"yes", "Random", "123e4567-e89b-12d3-a456-42661417400", "123e4567e89b12d3a456426614174000",
                          "123e4567-e89b-12d3-a456-42661417400g", "0x1234", "-"}) {
    m = Mode::Random; v = "keep";
    ATF_REQUIRE(!parseHostid(bad, m, v).empty());
  }
  ATF_REQUIRE(isUuid("00000000-0000-0000-0000-000000000000"));
  ATF_REQUIRE(!isUuid("00000000-0000-0000-0000-00000000000"));
  ATF_REQUIRE(!isUuid("00000000_0000-0000-0000-000000000000"));
}

ATF_TEST_CASE_WITHOUT_HEAD(hostname_modes);
ATF_TEST_CASE_BODY(hostname_modes) {
  Mode m; std::string v;
  ATF_REQUIRE_EQ(parseHostname("", m, v), std::string());          ATF_REQUIRE(m == Mode::Host);
  ATF_REQUIRE_EQ(parseHostname("host", m, v), std::string());      ATF_REQUIRE(m == Mode::Host);
  ATF_REQUIRE_EQ(parseHostname("random", m, v), std::string());    ATF_REQUIRE(m == Mode::Random);
  ATF_REQUIRE_EQ(parseHostname("box", m, v), std::string());       ATF_REQUIRE(m == Mode::Fixed); ATF_REQUIRE_EQ(v, std::string("box"));
  ATF_REQUIRE_EQ(parseHostname("web-01.example.org", m, v), std::string());
  for (const char *bad : {"a b", "-x", "x_y", "a..b", "$(id)", "ü"})
    ATF_REQUIRE(!parseHostname(bad, m, v).empty());
  ATF_REQUIRE(!parseHostname(std::string(64, 'a'), m, v).empty());   // label too long
  ATF_REQUIRE_EQ(randomHostname("A1B2C3D4E5F6"), std::string("crate-a1b2c3d4"));
}

ATF_TEST_CASE_WITHOUT_HEAD(uuid_from_hex);
ATF_TEST_CASE_BODY(uuid_from_hex) {
  const std::string u = uuidFromHex("00112233445566778899AABBCCDDEEFF");
  ATF_REQUIRE_EQ(u, std::string("00112233-4455-4677-8899-aabbccddeeff"));   // version 4, variant 10
  ATF_REQUIRE(isUuid(u));
  // the variant nibble covers all four spellings and nothing else
  for (const char *in : {"00000000000000000000000000000000", "00000000000000001000000000000000",
                         "00000000000000002000000000000000", "0000000000000000f000000000000000"}) {
    const std::string x = uuidFromHex(in);
    char var = x[19];
    ATF_REQUIRE(var == '8' || var == '9' || var == 'a' || var == 'b');
    ATF_REQUIRE_EQ(x[14], '4');
  }
  ATF_REQUIRE_EQ(uuidFromHex("0011"), std::string());
  ATF_REQUIRE_EQ(uuidFromHex("0011223344556677889900aabbccddeg"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(md5_and_hostid);
ATF_TEST_CASE_BODY(md5_and_hostid) {
  // RFC 1321 vectors
  ATF_REQUIRE_EQ(md5Hex(""), std::string("d41d8cd98f00b204e9800998ecf8427e"));
  ATF_REQUIRE_EQ(md5Hex("a"), std::string("0cc175b9c0f1b6a831c399e269772661"));
  ATF_REQUIRE_EQ(md5Hex("abc"), std::string("900150983cd24fb0d6963f7d28e17f72"));
  ATF_REQUIRE_EQ(md5Hex("message digest"), std::string("f96b697d7cb7938d525a2f31aaf161d0"));
  ATF_REQUIRE_EQ(md5Hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
                 std::string("57edf4a22be3c955ac49da2e2107b67a"));
  // 55/56/64-byte boundaries (padding paths); values from md5sum(1)
  ATF_REQUIRE_EQ(md5Hex(std::string(55, 'x')), std::string("04364420e25c512fd958a70738aa8f72"));
  ATF_REQUIRE_EQ(md5Hex(std::string(56, 'a')), std::string("3b0c8ac703f828b04c6c197006d17218"));
  ATF_REQUIRE_EQ(md5Hex(std::string(64, 'a')), std::string("014842d480b571495a4a0363793f7367"));

  // /etc/rc.d/hostid: id = first 8 hex digits of md5(uuid):
  // md5("123e4567-e89b-12d3-a456-426614174000") = 3b32b2dc26c45b3a34a56515df7c216c
  const std::string uuid = "123e4567-e89b-12d3-a456-426614174000";
  ATF_REQUIRE_EQ(md5Hex(uuid), std::string("3b32b2dc26c45b3a34a56515df7c216c"));
  ATF_REQUIRE_EQ(hostidFromUuid(uuid), 0x3b32b2dcUL);
  ATF_REQUIRE_EQ(hostidFromUuid("ffffffff-ffff-ffff-ffff-ffffffffffff") <= 0xffffffffUL, true);
  ATF_REQUIRE(hostidFromUuid(uuid) != hostidFromUuid("123e4567-e89b-12d3-a456-426614174001"));

  auto p = jailParams(uuid);
  ATF_REQUIRE_EQ(p.size(), 2u);
  ATF_REQUIRE_EQ(p[0], std::string("host.hostuuid=") + uuid);
  ATF_REQUIRE_EQ(p[1], std::string("host.hostid=") + std::to_string(hostidFromUuid(uuid)));
  ATF_REQUIRE(jailParams("").empty());
  ATF_REQUIRE_EQ(hostidFileContent(uuid), uuid + "\n");
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, hostid_modes);
  ATF_ADD_TEST_CASE(tcs, hostname_modes);
  ATF_ADD_TEST_CASE(tcs, uuid_from_hex);
  ATF_ADD_TEST_CASE(tcs, md5_and_hostid);
}
