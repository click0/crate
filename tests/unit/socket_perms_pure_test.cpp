// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "socket_perms_pure.h"

#include <atf-c++.hpp>

#include <string>

using SocketPermsPure::isModeTight;
using SocketPermsPure::parseUnixModeStr;
using SocketPermsPure::validateGroupName;
using SocketPermsPure::validateUnixSocketPerms;
using SocketPermsPure::validateUserName;

// --- parseUnixModeStr ---

ATF_TEST_CASE_WITHOUT_HEAD(mode_typical_octal_accepted);
ATF_TEST_CASE_BODY(mode_typical_octal_accepted) {
  unsigned m = 0;
  ATF_REQUIRE_EQ(parseUnixModeStr("0660", &m), std::string());
  ATF_REQUIRE_EQ(m, 0660u);
  ATF_REQUIRE_EQ(parseUnixModeStr("660",  &m), std::string());
  ATF_REQUIRE_EQ(m, 0660u);
  ATF_REQUIRE_EQ(parseUnixModeStr("0o660", &m), std::string());
  ATF_REQUIRE_EQ(m, 0660u);
  ATF_REQUIRE_EQ(parseUnixModeStr("0600", &m), std::string());
  ATF_REQUIRE_EQ(m, 0600u);
  ATF_REQUIRE_EQ(parseUnixModeStr("0640", &m), std::string());
  ATF_REQUIRE_EQ(m, 0640u);
  ATF_REQUIRE_EQ(parseUnixModeStr("777", &m), std::string());
  ATF_REQUIRE_EQ(m, 0777u);
  // Sticky/setuid/setgid bits
  ATF_REQUIRE_EQ(parseUnixModeStr("4755", &m), std::string());
  ATF_REQUIRE_EQ(m, 04755u);
  ATF_REQUIRE_EQ(parseUnixModeStr("01777", &m), std::string());
  ATF_REQUIRE_EQ(m, 01777u);
}

ATF_TEST_CASE_WITHOUT_HEAD(mode_rejects_garbage);
ATF_TEST_CASE_BODY(mode_rejects_garbage) {
  unsigned m = 0;
  ATF_REQUIRE(!parseUnixModeStr("",      &m).empty());
  ATF_REQUIRE(!parseUnixModeStr("rw-",   &m).empty());     // chmod symbolic — not supported
  ATF_REQUIRE(!parseUnixModeStr("0x660", &m).empty());     // hex prefix
  ATF_REQUIRE(!parseUnixModeStr("999",   &m).empty());     // 9 not octal
  ATF_REQUIRE(!parseUnixModeStr("0888",  &m).empty());
  ATF_REQUIRE(!parseUnixModeStr("12345", &m).empty());     // > 4 digits
  ATF_REQUIRE(!parseUnixModeStr("abc",   &m).empty());
  ATF_REQUIRE(!parseUnixModeStr(" 660",  &m).empty());     // leading space
}

ATF_TEST_CASE_WITHOUT_HEAD(mode_null_out_rejected);
ATF_TEST_CASE_BODY(mode_null_out_rejected) {
  ATF_REQUIRE(!parseUnixModeStr("0660", nullptr).empty());
}

// --- validateUserName / validateGroupName ---

ATF_TEST_CASE_WITHOUT_HEAD(name_typical_accepted);
ATF_TEST_CASE_BODY(name_typical_accepted) {
  ATF_REQUIRE_EQ(validateUserName(""), std::string());            // empty = "leave alone"
  ATF_REQUIRE_EQ(validateUserName("root"), std::string());
  ATF_REQUIRE_EQ(validateUserName("crate-ops"), std::string());
  ATF_REQUIRE_EQ(validateUserName("op_42"), std::string());
  ATF_REQUIRE_EQ(validateGroupName("wheel"), std::string());
  ATF_REQUIRE_EQ(validateGroupName("operator"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_rejects_garbage);
ATF_TEST_CASE_BODY(name_rejects_garbage) {
  ATF_REQUIRE(!validateUserName("-leadingdash").empty());
  ATF_REQUIRE(!validateUserName("with space").empty());
  ATF_REQUIRE(!validateUserName("with/slash").empty());
  ATF_REQUIRE(!validateUserName("$(id)").empty());
  ATF_REQUIRE(!validateUserName("name;reboot").empty());
  // length cap 32
  std::string toolong(33, 'a');
  ATF_REQUIRE(!validateUserName(toolong).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(triple_validator_short_circuits);
ATF_TEST_CASE_BODY(triple_validator_short_circuits) {
  ATF_REQUIRE_EQ(validateUnixSocketPerms("", "", 0660), std::string());
  ATF_REQUIRE_EQ(validateUnixSocketPerms("root", "wheel", 0600), std::string());
  ATF_REQUIRE(!validateUnixSocketPerms("-bad", "", 0660).empty());
  ATF_REQUIRE(!validateUnixSocketPerms("", "with space", 0660).empty());
  ATF_REQUIRE(!validateUnixSocketPerms("", "", 010000).empty()); // mode out of range
}

// --- isModeTight ---

ATF_TEST_CASE_WITHOUT_HEAD(tight_modes_pass);
ATF_TEST_CASE_BODY(tight_modes_pass) {
  ATF_REQUIRE(isModeTight(0600));
  ATF_REQUIRE(isModeTight(0640));
  ATF_REQUIRE(isModeTight(0660));
}

ATF_TEST_CASE_WITHOUT_HEAD(loose_modes_warn);
ATF_TEST_CASE_BODY(loose_modes_warn) {
  ATF_REQUIRE(!isModeTight(0666));
  ATF_REQUIRE(!isModeTight(0777));
  ATF_REQUIRE(!isModeTight(0664));   // world-readable
  ATF_REQUIRE(!isModeTight(0662));   // world-writable
  ATF_REQUIRE(!isModeTight(0661));   // world-executable
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, mode_typical_octal_accepted);
  ATF_ADD_TEST_CASE(tcs, mode_rejects_garbage);
  ATF_ADD_TEST_CASE(tcs, mode_null_out_rejected);
  ATF_ADD_TEST_CASE(tcs, name_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, name_rejects_garbage);
  ATF_ADD_TEST_CASE(tcs, triple_validator_short_circuits);
  ATF_ADD_TEST_CASE(tcs, tight_modes_pass);
  ATF_ADD_TEST_CASE(tcs, loose_modes_warn);
}
