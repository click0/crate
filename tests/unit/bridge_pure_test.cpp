// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "bridge_pure.h"

#include <atf-c++.hpp>

#include <string>

using BridgePure::Action;
using BridgePure::Inputs;
using BridgePure::chooseAction;
using BridgePure::actionName;
using BridgePure::validateBridgeName;

// --- chooseAction ---

ATF_TEST_CASE_WITHOUT_HEAD(action_existing_is_always_noop);
ATF_TEST_CASE_BODY(action_existing_is_always_noop) {
  // When the bridge already exists the autoCreate flag is irrelevant.
  ATF_REQUIRE(chooseAction({true,  true})  == Action::NoOp);
  ATF_REQUIRE(chooseAction({true,  false}) == Action::NoOp);
}

ATF_TEST_CASE_WITHOUT_HEAD(action_missing_with_optin_creates);
ATF_TEST_CASE_BODY(action_missing_with_optin_creates) {
  ATF_REQUIRE(chooseAction({false, true}) == Action::Create);
}

ATF_TEST_CASE_WITHOUT_HEAD(action_missing_without_optin_errors);
ATF_TEST_CASE_BODY(action_missing_without_optin_errors) {
  ATF_REQUIRE(chooseAction({false, false}) == Action::Error);
}

ATF_TEST_CASE_WITHOUT_HEAD(action_decision_table_is_total);
ATF_TEST_CASE_BODY(action_decision_table_is_total) {
  // Sanity check: every 2x2 input produces a known action.
  for (int e = 0; e < 2; e++) {
    for (int a = 0; a < 2; a++) {
      Action got = chooseAction({(bool)e, (bool)a});
      bool ok = got == Action::NoOp
             || got == Action::Create
             || got == Action::Error;
      ATF_REQUIRE(ok);
    }
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(action_names_are_distinct);
ATF_TEST_CASE_BODY(action_names_are_distinct) {
  std::string n1 = actionName(Action::NoOp);
  std::string n2 = actionName(Action::Create);
  std::string n3 = actionName(Action::Error);
  ATF_REQUIRE(!n1.empty()); ATF_REQUIRE(!n2.empty()); ATF_REQUIRE(!n3.empty());
  ATF_REQUIRE(n1 != n2);
  ATF_REQUIRE(n2 != n3);
  ATF_REQUIRE(n1 != n3);
  ATF_REQUIRE_EQ(n2, std::string("create"));
}

// --- validateBridgeName ---

ATF_TEST_CASE_WITHOUT_HEAD(validateBridge_empty_is_rejected);
ATF_TEST_CASE_BODY(validateBridge_empty_is_rejected) {
  ATF_REQUIRE(!validateBridgeName("").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(validateBridge_too_long_is_rejected);
ATF_TEST_CASE_BODY(validateBridge_too_long_is_rejected) {
  // IFNAMSIZ - 1 == 15; one over should fail, exactly 15 should pass.
  // Use "bridge" + 9 digits = 15 chars at limit.
  ATF_REQUIRE_EQ(validateBridgeName("bridge012345678"), std::string());
  ATF_REQUIRE(!validateBridgeName("bridge0123456789").empty()); // 16 chars
}

ATF_TEST_CASE_WITHOUT_HEAD(validateBridge_rejects_metacharacters);
ATF_TEST_CASE_BODY(validateBridge_rejects_metacharacters) {
  ATF_REQUIRE(!validateBridgeName("bridge0;rm").empty());
  ATF_REQUIRE(!validateBridgeName("bridge 0").empty());
  ATF_REQUIRE(!validateBridgeName("bridge`x`").empty());
  ATF_REQUIRE(!validateBridgeName("bridge$0").empty());
  ATF_REQUIRE(!validateBridgeName("../bridge0").empty());
  ATF_REQUIRE(!validateBridgeName("bridge/0").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(validateBridge_rejects_no_driver_prefix);
ATF_TEST_CASE_BODY(validateBridge_rejects_no_driver_prefix) {
  // Pure digits — no driver prefix.
  ATF_REQUIRE(!validateBridgeName("0").empty());
  ATF_REQUIRE(!validateBridgeName("0123").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(validateBridge_rejects_no_unit_number);
ATF_TEST_CASE_BODY(validateBridge_rejects_no_unit_number) {
  ATF_REQUIRE(!validateBridgeName("bridge").empty());
  ATF_REQUIRE(!validateBridgeName("br").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(validateBridge_accepts_typical_names);
ATF_TEST_CASE_BODY(validateBridge_accepts_typical_names) {
  ATF_REQUIRE_EQ(validateBridgeName("bridge0"), std::string());
  ATF_REQUIRE_EQ(validateBridgeName("bridge42"), std::string());
  ATF_REQUIRE_EQ(validateBridgeName("br0"), std::string());
  ATF_REQUIRE_EQ(validateBridgeName("vmbr0"), std::string());
  // Digits inside the name are allowed as long as alpha + a digit are present.
  ATF_REQUIRE_EQ(validateBridgeName("br0a1"), std::string());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, action_existing_is_always_noop);
  ATF_ADD_TEST_CASE(tcs, action_missing_with_optin_creates);
  ATF_ADD_TEST_CASE(tcs, action_missing_without_optin_errors);
  ATF_ADD_TEST_CASE(tcs, action_decision_table_is_total);
  ATF_ADD_TEST_CASE(tcs, action_names_are_distinct);
  ATF_ADD_TEST_CASE(tcs, validateBridge_empty_is_rejected);
  ATF_ADD_TEST_CASE(tcs, validateBridge_too_long_is_rejected);
  ATF_ADD_TEST_CASE(tcs, validateBridge_rejects_metacharacters);
  ATF_ADD_TEST_CASE(tcs, validateBridge_rejects_no_driver_prefix);
  ATF_ADD_TEST_CASE(tcs, validateBridge_rejects_no_unit_number);
  ATF_ADD_TEST_CASE(tcs, validateBridge_accepts_typical_names);
}
