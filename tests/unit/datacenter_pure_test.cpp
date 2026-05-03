// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "datacenter_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using AggregatorPure::NodeView;
using DatacenterPure::DcSummary;
using DatacenterPure::DcView;
using DatacenterPure::canonicalName;
using DatacenterPure::groupAndSummarise;
using DatacenterPure::renderJson;
using DatacenterPure::validateName;

// --- validateName ---

ATF_TEST_CASE_WITHOUT_HEAD(name_typical_accepted);
ATF_TEST_CASE_BODY(name_typical_accepted) {
  ATF_REQUIRE_EQ(validateName("dc1"),       std::string());
  ATF_REQUIRE_EQ(validateName("default"),   std::string());
  ATF_REQUIRE_EQ(validateName("eu-west-1"), std::string());
  ATF_REQUIRE_EQ(validateName("us.east"),   std::string());
  ATF_REQUIRE_EQ(validateName(std::string(32, 'a')), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_invalid_rejected);
ATF_TEST_CASE_BODY(name_invalid_rejected) {
  ATF_REQUIRE(!validateName("").empty());
  ATF_REQUIRE(!validateName(std::string(33, 'a')).empty());
  ATF_REQUIRE(!validateName("foo bar").empty());
  ATF_REQUIRE(!validateName("foo/bar").empty());
  ATF_REQUIRE(!validateName("foo;rm").empty());
  ATF_REQUIRE(!validateName("foo$bar").empty());
}

// --- canonicalName ---

ATF_TEST_CASE_WITHOUT_HEAD(canonical_empty_becomes_default);
ATF_TEST_CASE_BODY(canonical_empty_becomes_default) {
  ATF_REQUIRE_EQ(canonicalName(""),    std::string("default"));
  ATF_REQUIRE_EQ(canonicalName("dc1"), std::string("dc1"));
  ATF_REQUIRE_EQ(canonicalName("default"), std::string("default"));
}

// --- groupAndSummarise ---

ATF_TEST_CASE_WITHOUT_HEAD(group_empty_input);
ATF_TEST_CASE_BODY(group_empty_input) {
  ATF_REQUIRE(groupAndSummarise({}).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(group_single_dc);
ATF_TEST_CASE_BODY(group_single_dc) {
  std::vector<DcView> v = {
    {{"alpha", "10.0.0.1", true,  3}, "dc1"},
    {{"beta",  "10.0.0.2", true,  5}, "dc1"},
    {{"gamma", "10.0.0.3", false, 0}, "dc1"},
  };
  auto out = groupAndSummarise(v);
  ATF_REQUIRE_EQ(out.size(), (size_t)1);
  ATF_REQUIRE_EQ(out[0].name, std::string("dc1"));
  ATF_REQUIRE_EQ(out[0].nodesTotal,      (unsigned)3);
  ATF_REQUIRE_EQ(out[0].nodesReachable,  (unsigned)2);
  ATF_REQUIRE_EQ(out[0].nodesDown,       (unsigned)1);
  ATF_REQUIRE_EQ(out[0].containersTotal, (unsigned)8);
}

ATF_TEST_CASE_WITHOUT_HEAD(group_two_dcs_sorted_alphabetically);
ATF_TEST_CASE_BODY(group_two_dcs_sorted_alphabetically) {
  std::vector<DcView> v = {
    {{"a", "1", true,  2}, "us-east"},
    {{"b", "2", true,  3}, "eu-west"},
    {{"c", "3", false, 0}, "us-east"},
  };
  auto out = groupAndSummarise(v);
  ATF_REQUIRE_EQ(out.size(), (size_t)2);
  // Alphabetical: eu-west, us-east.
  ATF_REQUIRE_EQ(out[0].name, std::string("eu-west"));
  ATF_REQUIRE_EQ(out[1].name, std::string("us-east"));
  ATF_REQUIRE_EQ(out[0].containersTotal, (unsigned)3);
  ATF_REQUIRE_EQ(out[1].containersTotal, (unsigned)2);
}

ATF_TEST_CASE_WITHOUT_HEAD(group_empty_dc_becomes_default);
ATF_TEST_CASE_BODY(group_empty_dc_becomes_default) {
  std::vector<DcView> v = {
    {{"a", "1", true, 2}, ""},
    {{"b", "2", true, 1}, "dc1"},
  };
  auto out = groupAndSummarise(v);
  ATF_REQUIRE_EQ(out.size(), (size_t)2);
  // "dc1" sorts before "default" alphabetically.
  ATF_REQUIRE_EQ(out[0].name, std::string("dc1"));
  ATF_REQUIRE_EQ(out[1].name, std::string("default"));
  ATF_REQUIRE_EQ(out[1].containersTotal, (unsigned)2);
}

ATF_TEST_CASE_WITHOUT_HEAD(group_unreachable_excluded_from_container_total);
ATF_TEST_CASE_BODY(group_unreachable_excluded_from_container_total) {
  // Stale containerCount on an unreachable node MUST NOT be counted —
  // the same invariant we test for in AggregatorPure::summarise.
  std::vector<DcView> v = {
    {{"a", "1", false, 999}, "dc1"},
    {{"b", "2", true,    3}, "dc1"},
  };
  auto out = groupAndSummarise(v);
  ATF_REQUIRE_EQ(out.size(), (size_t)1);
  ATF_REQUIRE_EQ(out[0].containersTotal, (unsigned)3);
  ATF_REQUIRE_EQ(out[0].nodesDown,       (unsigned)1);
}

// --- renderJson ---

ATF_TEST_CASE_WITHOUT_HEAD(render_json_empty);
ATF_TEST_CASE_BODY(render_json_empty) {
  ATF_REQUIRE_EQ(renderJson({}), std::string("[]"));
}

ATF_TEST_CASE_WITHOUT_HEAD(render_json_field_order_stable);
ATF_TEST_CASE_BODY(render_json_field_order_stable) {
  std::vector<DcSummary> dcs = {{"dc1", 3, 2, 1, 8}};
  auto j = renderJson(dcs);
  ATF_REQUIRE_EQ(j, std::string(
    "[{\"name\":\"dc1\""
    ",\"nodes_total\":3"
    ",\"nodes_reachable\":2"
    ",\"nodes_down\":1"
    ",\"containers_total\":8}]"));
}

ATF_TEST_CASE_WITHOUT_HEAD(render_json_multiple_dcs_comma_separated);
ATF_TEST_CASE_BODY(render_json_multiple_dcs_comma_separated) {
  std::vector<DcSummary> dcs = {
    {"eu-west", 1, 1, 0, 5},
    {"us-east", 2, 1, 1, 7},
  };
  auto j = renderJson(dcs);
  ATF_REQUIRE(j.find("\"name\":\"eu-west\"") != std::string::npos);
  ATF_REQUIRE(j.find("\"name\":\"us-east\"") != std::string::npos);
  // First entry's `}` followed by `,{`.
  ATF_REQUIRE(j.find("},{") != std::string::npos);
  ATF_REQUIRE(j.front() == '[');
  ATF_REQUIRE(j.back()  == ']');
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, name_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, name_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, canonical_empty_becomes_default);
  ATF_ADD_TEST_CASE(tcs, group_empty_input);
  ATF_ADD_TEST_CASE(tcs, group_single_dc);
  ATF_ADD_TEST_CASE(tcs, group_two_dcs_sorted_alphabetically);
  ATF_ADD_TEST_CASE(tcs, group_empty_dc_becomes_default);
  ATF_ADD_TEST_CASE(tcs, group_unreachable_excluded_from_container_total);
  ATF_ADD_TEST_CASE(tcs, render_json_empty);
  ATF_ADD_TEST_CASE(tcs, render_json_field_order_stable);
  ATF_ADD_TEST_CASE(tcs, render_json_multiple_dcs_comma_separated);
}
