// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "per_user_rctl_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace PerUserRctlPure;

// --- loginclassName ---

ATF_TEST_CASE_WITHOUT_HEAD(loginclass_typical);
ATF_TEST_CASE_BODY(loginclass_typical) {
  ATF_REQUIRE_EQ(loginclassName(0),     std::string("crate-0"));
  ATF_REQUIRE_EQ(loginclassName(1000),  std::string("crate-1000"));
  ATF_REQUIRE_EQ(loginclassName(65534), std::string("crate-65534"));
}

ATF_TEST_CASE_WITHOUT_HEAD(loginclass_isolation);
ATF_TEST_CASE_BODY(loginclass_isolation) {
  // alice and bob get distinct loginclass names; neither a prefix
  // of the other (would let one operator's rules accidentally
  // match the other's via prefix-based loginclass matching tools).
  std::string alice = loginclassName(1000);
  std::string bob   = loginclassName(1001);
  ATF_REQUIRE(alice != bob);
  ATF_REQUIRE(alice.find(bob) == std::string::npos);
  ATF_REQUIRE(bob.find(alice) == std::string::npos);
}

// --- subject builders ---

ATF_TEST_CASE_WITHOUT_HEAD(jail_subject_format);
ATF_TEST_CASE_BODY(jail_subject_format) {
  ATF_REQUIRE_EQ(jailSubject(7),  std::string("jail:7"));
  ATF_REQUIRE_EQ(jailSubject(0),  std::string("jail:0"));
  ATF_REQUIRE_EQ(jailSubject(99), std::string("jail:99"));
}

ATF_TEST_CASE_WITHOUT_HEAD(loginclass_subject_format);
ATF_TEST_CASE_BODY(loginclass_subject_format) {
  ATF_REQUIRE_EQ(loginclassSubject(1000),
                 std::string("loginclass:crate-1000"));
  ATF_REQUIRE_EQ(loginclassSubject(0),
                 std::string("loginclass:crate-0"));
}

// --- buildRule ---

ATF_TEST_CASE_WITHOUT_HEAD(build_rule_jail);
ATF_TEST_CASE_BODY(build_rule_jail) {
  ATF_REQUIRE_EQ(buildRule("jail:7", "memoryuse", "2G"),
                 std::string("jail:7:memoryuse:deny=2G"));
  ATF_REQUIRE_EQ(buildRule("jail:7", "pcpu", "20"),
                 std::string("jail:7:pcpu:deny=20"));
}

ATF_TEST_CASE_WITHOUT_HEAD(build_rule_loginclass);
ATF_TEST_CASE_BODY(build_rule_loginclass) {
  ATF_REQUIRE_EQ(buildRule("loginclass:crate-1000", "memoryuse", "4G"),
                 std::string("loginclass:crate-1000:memoryuse:deny=4G"));
}

// --- buildUserUmbrellaRules ---

ATF_TEST_CASE_WITHOUT_HEAD(umbrella_rules_typical);
ATF_TEST_CASE_BODY(umbrella_rules_typical) {
  std::vector<KeyValue> pairs = {
    {"memoryuse", "4G"},
    {"pcpu", "200"},
    {"openfiles", "1024"},
  };
  auto rules = buildUserUmbrellaRules(1000, pairs);
  ATF_REQUIRE_EQ(rules.size(), (size_t)3);
  ATF_REQUIRE_EQ(rules[0],
                 std::string("loginclass:crate-1000:memoryuse:deny=4G"));
  ATF_REQUIRE_EQ(rules[1],
                 std::string("loginclass:crate-1000:pcpu:deny=200"));
  ATF_REQUIRE_EQ(rules[2],
                 std::string("loginclass:crate-1000:openfiles:deny=1024"));
}

ATF_TEST_CASE_WITHOUT_HEAD(umbrella_rules_empty_input);
ATF_TEST_CASE_BODY(umbrella_rules_empty_input) {
  auto rules = buildUserUmbrellaRules(1000, {});
  ATF_REQUIRE_EQ(rules.size(), (size_t)0);
}

// --- validateLoginclassName ---

ATF_TEST_CASE_WITHOUT_HEAD(validate_loginclass_accepts_well_formed);
ATF_TEST_CASE_BODY(validate_loginclass_accepts_well_formed) {
  ATF_REQUIRE_EQ(validateLoginclassName("crate-0"),     std::string());
  ATF_REQUIRE_EQ(validateLoginclassName("crate-1000"),  std::string());
  ATF_REQUIRE_EQ(validateLoginclassName("crate-65534"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_loginclass_round_trips);
ATF_TEST_CASE_BODY(validate_loginclass_round_trips) {
  // Every loginclass we emit must round-trip through the validator
  // — defence-in-depth that a future format tweak doesn't desync
  // the two.
  for (uint32_t uid : {(uint32_t)0, 1u, 100u, 1000u, 65535u, 1000000u}) {
    ATF_REQUIRE_EQ(validateLoginclassName(loginclassName(uid)),
                   std::string());
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_loginclass_rejects_garbage);
ATF_TEST_CASE_BODY(validate_loginclass_rejects_garbage) {
  ATF_REQUIRE(!validateLoginclassName("").empty());
  ATF_REQUIRE(!validateLoginclassName("crate-").empty());
  ATF_REQUIRE(!validateLoginclassName("crate-abc").empty());
  ATF_REQUIRE(!validateLoginclassName("crate-01000").empty()); // leading zero
  ATF_REQUIRE(!validateLoginclassName("not-crate-1000").empty());
  ATF_REQUIRE(!validateLoginclassName("Crate-1000").empty());  // case
  ATF_REQUIRE(!validateLoginclassName("crate-99999999999").empty()); // too long
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, loginclass_typical);
  ATF_ADD_TEST_CASE(tcs, loginclass_isolation);
  ATF_ADD_TEST_CASE(tcs, jail_subject_format);
  ATF_ADD_TEST_CASE(tcs, loginclass_subject_format);
  ATF_ADD_TEST_CASE(tcs, build_rule_jail);
  ATF_ADD_TEST_CASE(tcs, build_rule_loginclass);
  ATF_ADD_TEST_CASE(tcs, umbrella_rules_typical);
  ATF_ADD_TEST_CASE(tcs, umbrella_rules_empty_input);
  ATF_ADD_TEST_CASE(tcs, validate_loginclass_accepts_well_formed);
  ATF_ADD_TEST_CASE(tcs, validate_loginclass_round_trips);
  ATF_ADD_TEST_CASE(tcs, validate_loginclass_rejects_garbage);
}
