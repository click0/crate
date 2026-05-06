// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "auto_fw_pure.h"

#include <atf-c++.hpp>

#include <string>

using AutoFwPure::formatSnatAnchorLine;
using AutoFwPure::formatSnatRule;
using AutoFwPure::validateExternalIface;
using AutoFwPure::validateRuleAddress;

// ----------------------------------------------------------------------
// Iface validator
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(iface_typical_accepted);
ATF_TEST_CASE_BODY(iface_typical_accepted) {
  ATF_REQUIRE_EQ(validateExternalIface("em0"),       std::string());
  ATF_REQUIRE_EQ(validateExternalIface("igb0"),      std::string());
  ATF_REQUIRE_EQ(validateExternalIface("vlan0.100"), std::string());
  ATF_REQUIRE_EQ(validateExternalIface("bridge0"),   std::string());
  ATF_REQUIRE_EQ(validateExternalIface("vtnet1"),    std::string());
  ATF_REQUIRE_EQ(validateExternalIface("a"),         std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(iface_invalid_rejected);
ATF_TEST_CASE_BODY(iface_invalid_rejected) {
  ATF_REQUIRE(!validateExternalIface("").empty());
  ATF_REQUIRE(!validateExternalIface(std::string(16, 'a')).empty());  // > IFNAMSIZ-1
  ATF_REQUIRE(!validateExternalIface("em 0").empty());                 // space
  ATF_REQUIRE(!validateExternalIface("em0;rm").empty());               // semicolon
  ATF_REQUIRE(!validateExternalIface("em0`pwd`").empty());             // backtick
  ATF_REQUIRE(!validateExternalIface("em0/em1").empty());              // slash
  ATF_REQUIRE(!validateExternalIface("em\n0").empty());                // newline
}

// ----------------------------------------------------------------------
// Address validator
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(address_typical_accepted);
ATF_TEST_CASE_BODY(address_typical_accepted) {
  ATF_REQUIRE_EQ(validateRuleAddress("10.66.0.5"),       std::string());
  ATF_REQUIRE_EQ(validateRuleAddress("10.66.0.0/24"),    std::string());
  ATF_REQUIRE_EQ(validateRuleAddress("192.168.1.1"),     std::string());
  ATF_REQUIRE_EQ(validateRuleAddress("172.16.0.0/12"),   std::string());
  ATF_REQUIRE_EQ(validateRuleAddress("0.0.0.0/0"),       std::string());  // catch-all
}

ATF_TEST_CASE_WITHOUT_HEAD(address_invalid_rejected);
ATF_TEST_CASE_BODY(address_invalid_rejected) {
  ATF_REQUIRE(!validateRuleAddress("").empty());
  // Shell-injection attempts.
  ATF_REQUIRE(!validateRuleAddress("10.66.0.5; rm -rf /").empty());
  ATF_REQUIRE(!validateRuleAddress("10.66.0.5`pwd`").empty());
  ATF_REQUIRE(!validateRuleAddress("$(id)").empty());
  // Non-numeric chars.
  ATF_REQUIRE(!validateRuleAddress("ten.dot.zero.five").empty());
  // Multiple slashes.
  ATF_REQUIRE(!validateRuleAddress("10.66.0.0/24/8").empty());
  // Way too long.
  ATF_REQUIRE(!validateRuleAddress(std::string(50, '1')).empty());
}

// ----------------------------------------------------------------------
// formatSnatRule
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_shape_single_ip);
ATF_TEST_CASE_BODY(snat_rule_shape_single_ip) {
  // Single-IP form (used per-jail with the allocator).
  ATF_REQUIRE_EQ(formatSnatRule("em0", "10.66.0.5"),
                 std::string("nat on em0 inet from 10.66.0.5 to ! 10.66.0.5 -> (em0)"));
}

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_shape_cidr);
ATF_TEST_CASE_BODY(snat_rule_shape_cidr) {
  // Pool-wide form (could be used for one rule covering the whole
  // pool rather than per-jail; we keep it formatable but don't use
  // it in the runtime today).
  ATF_REQUIRE_EQ(formatSnatRule("igb0", "10.66.0.0/24"),
                 std::string("nat on igb0 inet from 10.66.0.0/24 to ! 10.66.0.0/24 -> (igb0)"));
}

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_inet_token_present);
ATF_TEST_CASE_BODY(snat_rule_inet_token_present) {
  // "inet" qualifier ensures the rule is IPv4-only — without it,
  // pf would also try to match IPv6 and complain (pre-13 behaviour).
  // Pin the token so a future re-format doesn't accidentally drop it.
  auto r = formatSnatRule("em0", "10.66.0.5");
  ATF_REQUIRE(r.find(" inet from ") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_excludes_intra_pool_traffic);
ATF_TEST_CASE_BODY(snat_rule_excludes_intra_pool_traffic) {
  // The "to ! <jailAddr>" segment prevents intra-jail traffic from
  // being NAT'd. A typo here would silently break jail-to-jail
  // routing on the same bridge — pin the format.
  auto r = formatSnatRule("em0", "10.66.0.5");
  ATF_REQUIRE(r.find(" to ! 10.66.0.5 ") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(snat_rule_uses_iface_token);
ATF_TEST_CASE_BODY(snat_rule_uses_iface_token) {
  // "(<iface>)" with parens means "translate to whatever address
  // is currently on <iface>" — robust against DHCP lease changes.
  // Without parens, pf would lock the rule to the IP at the time
  // the rule was added.
  auto r = formatSnatRule("em0", "10.66.0.5");
  ATF_REQUIRE(r.find("-> (em0)") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(anchor_line_has_trailing_newline);
ATF_TEST_CASE_BODY(anchor_line_has_trailing_newline) {
  // formatSnatAnchorLine adds a trailing \n so multiple lines
  // concatenate cleanly when caller builds the rules text.
  auto line = formatSnatAnchorLine("em0", "10.66.0.5");
  ATF_REQUIRE_EQ(line.back(), '\n');
}

ATF_TEST_CASE_WITHOUT_HEAD(anchor_line_starts_with_rule);
ATF_TEST_CASE_BODY(anchor_line_starts_with_rule) {
  auto line = formatSnatAnchorLine("em0", "10.66.0.5");
  ATF_REQUIRE(line.find("nat on em0 inet from 10.66.0.5") == 0u);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, iface_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, iface_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, address_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, address_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, snat_rule_shape_single_ip);
  ATF_ADD_TEST_CASE(tcs, snat_rule_shape_cidr);
  ATF_ADD_TEST_CASE(tcs, snat_rule_inet_token_present);
  ATF_ADD_TEST_CASE(tcs, snat_rule_excludes_intra_pool_traffic);
  ATF_ADD_TEST_CASE(tcs, snat_rule_uses_iface_token);
  ATF_ADD_TEST_CASE(tcs, anchor_line_has_trailing_newline);
  ATF_ADD_TEST_CASE(tcs, anchor_line_starts_with_rule);
}
