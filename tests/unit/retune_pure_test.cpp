// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "retune_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using RetunePure::RctlPair;
using RetunePure::buildClearArgv;
using RetunePure::buildSetArgv;
using RetunePure::buildShowArgv;
using RetunePure::parseHumanSize;
using RetunePure::validatePairs;
using RetunePure::validateRctlKey;
using RetunePure::validateRctlValue;

// --- validateRctlKey ---

ATF_TEST_CASE_WITHOUT_HEAD(key_known_accepted);
ATF_TEST_CASE_BODY(key_known_accepted) {
  for (auto k : {"pcpu", "memoryuse", "vmemoryuse",
                 "readbps", "writebps", "readiops", "writeiops",
                 "maxproc", "openfiles", "nthr"}) {
    ATF_REQUIRE_EQ(validateRctlKey(k), std::string());
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(key_unknown_rejected_with_help);
ATF_TEST_CASE_BODY(key_unknown_rejected_with_help) {
  // Typos should produce an error that names the supported set
  // — operators look at this, not the source code.
  auto err = validateRctlKey("witebps");           // common typo
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("supported") != std::string::npos);
  ATF_REQUIRE(err.find("writebps") != std::string::npos);
  ATF_REQUIRE(!validateRctlKey("").empty());
  ATF_REQUIRE(!validateRctlKey("rm -rf /").empty());
}

// --- validateRctlValue ---

ATF_TEST_CASE_WITHOUT_HEAD(value_pcpu_percentage);
ATF_TEST_CASE_BODY(value_pcpu_percentage) {
  ATF_REQUIRE_EQ(validateRctlValue("pcpu", "0"),    std::string());
  ATF_REQUIRE_EQ(validateRctlValue("pcpu", "50"),   std::string());
  ATF_REQUIRE_EQ(validateRctlValue("pcpu", "100"),  std::string());
  // Out of range / suffix not allowed for percentages.
  ATF_REQUIRE(!validateRctlValue("pcpu", "101").empty());
  ATF_REQUIRE(!validateRctlValue("pcpu", "50M").empty());
  ATF_REQUIRE(!validateRctlValue("pcpu", "").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(value_byte_rates_with_suffix);
ATF_TEST_CASE_BODY(value_byte_rates_with_suffix) {
  ATF_REQUIRE_EQ(validateRctlValue("writebps", "1024"),    std::string());
  ATF_REQUIRE_EQ(validateRctlValue("writebps", "1K"),      std::string());
  ATF_REQUIRE_EQ(validateRctlValue("writebps", "10M"),     std::string());
  ATF_REQUIRE_EQ(validateRctlValue("writebps", "1.5G"),    std::string());
  ATF_REQUIRE_EQ(validateRctlValue("memoryuse", "512M"),   std::string());
  // Lowercase suffix accepted.
  ATF_REQUIRE_EQ(validateRctlValue("writebps", "10m"),     std::string());
  // Garbage suffix rejected.
  ATF_REQUIRE(!validateRctlValue("writebps", "10X").empty());
  // Pure suffix without digits rejected.
  ATF_REQUIRE(!validateRctlValue("writebps", "M").empty());
  // Empty rejected.
  ATF_REQUIRE(!validateRctlValue("writebps", "").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(value_iops_no_suffix);
ATF_TEST_CASE_BODY(value_iops_no_suffix) {
  ATF_REQUIRE_EQ(validateRctlValue("readiops", "500"),  std::string());
  ATF_REQUIRE_EQ(validateRctlValue("maxproc", "200"),    std::string());
  // Suffix forbidden for IOPS / counts.
  ATF_REQUIRE(!validateRctlValue("readiops", "1K").empty());
  ATF_REQUIRE(!validateRctlValue("maxproc", "1.5K").empty());
}

// --- validatePairs ---

ATF_TEST_CASE_WITHOUT_HEAD(pairs_typical_accepted);
ATF_TEST_CASE_BODY(pairs_typical_accepted) {
  std::vector<RctlPair> p = {
    {"pcpu", "20"},
    {"writebps", "1M"},
    {"readiops", "500"},
  };
  ATF_REQUIRE_EQ(validatePairs(p), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(pairs_empty_rejected);
ATF_TEST_CASE_BODY(pairs_empty_rejected) {
  ATF_REQUIRE(!validatePairs({}).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(pairs_index_in_error);
ATF_TEST_CASE_BODY(pairs_index_in_error) {
  // Second pair has bad value — error should say rctl[1].
  std::vector<RctlPair> p = {
    {"pcpu", "20"},
    {"pcpu", "999"},   // out of range
  };
  auto err = validatePairs(p);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("rctl[1]") != std::string::npos);
}

// --- parseHumanSize ---

ATF_TEST_CASE_WITHOUT_HEAD(parse_size_plain_int);
ATF_TEST_CASE_BODY(parse_size_plain_int) {
  ATF_REQUIRE_EQ(parseHumanSize("0"),    0L);
  ATF_REQUIRE_EQ(parseHumanSize("1024"), 1024L);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_size_K_M_G_T_are_1024_based);
ATF_TEST_CASE_BODY(parse_size_K_M_G_T_are_1024_based) {
  ATF_REQUIRE_EQ(parseHumanSize("1K"), 1024L);
  ATF_REQUIRE_EQ(parseHumanSize("1M"), 1048576L);
  ATF_REQUIRE_EQ(parseHumanSize("1G"), 1073741824L);
  ATF_REQUIRE_EQ(parseHumanSize("1T"), 1099511627776L);
  // Lowercase same as upper.
  ATF_REQUIRE_EQ(parseHumanSize("1m"), 1048576L);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_size_decimal_supported);
ATF_TEST_CASE_BODY(parse_size_decimal_supported) {
  ATF_REQUIRE_EQ(parseHumanSize("1.5M"), 1572864L);
  ATF_REQUIRE_EQ(parseHumanSize("0.5K"), 512L);
}

ATF_TEST_CASE_WITHOUT_HEAD(parse_size_invalid_returns_neg_one);
ATF_TEST_CASE_BODY(parse_size_invalid_returns_neg_one) {
  ATF_REQUIRE_EQ(parseHumanSize(""),       -1L);
  ATF_REQUIRE_EQ(parseHumanSize("M"),      -1L);
  ATF_REQUIRE_EQ(parseHumanSize("abc"),    -1L);
  ATF_REQUIRE_EQ(parseHumanSize("1.2.3M"), -1L);
}

// --- argv builders ---

ATF_TEST_CASE_WITHOUT_HEAD(set_argv_shape);
ATF_TEST_CASE_BODY(set_argv_shape) {
  RctlPair p{"writebps", "10M"};
  auto v = buildSetArgv(42, p);
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[0], std::string("/usr/bin/rctl"));
  ATF_REQUIRE_EQ(v[1], std::string("-a"));
  ATF_REQUIRE_EQ(v[2], std::string("jail:42:writebps:deny=10M"));
}

ATF_TEST_CASE_WITHOUT_HEAD(set_argv_passes_raw_suffix_to_rctl);
ATF_TEST_CASE_BODY(set_argv_passes_raw_suffix_to_rctl) {
  // The runtime feeds the operator's raw value through to rctl(8)
  // unchanged — rctl itself handles K/M/G/T. No double-conversion.
  RctlPair p{"memoryuse", "1.5G"};
  auto v = buildSetArgv(7, p);
  ATF_REQUIRE_EQ(v.back(), std::string("jail:7:memoryuse:deny=1.5G"));
}

ATF_TEST_CASE_WITHOUT_HEAD(clear_argv_shape);
ATF_TEST_CASE_BODY(clear_argv_shape) {
  auto v = buildClearArgv(42, "writebps");
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[1], std::string("-r"));
  ATF_REQUIRE_EQ(v[2], std::string("jail:42:writebps:deny"));
}

ATF_TEST_CASE_WITHOUT_HEAD(show_argv_shape);
ATF_TEST_CASE_BODY(show_argv_shape) {
  auto v = buildShowArgv(42);
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[1], std::string("-u"));
  ATF_REQUIRE_EQ(v[2], std::string("jail:42"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, key_known_accepted);
  ATF_ADD_TEST_CASE(tcs, key_unknown_rejected_with_help);
  ATF_ADD_TEST_CASE(tcs, value_pcpu_percentage);
  ATF_ADD_TEST_CASE(tcs, value_byte_rates_with_suffix);
  ATF_ADD_TEST_CASE(tcs, value_iops_no_suffix);
  ATF_ADD_TEST_CASE(tcs, pairs_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, pairs_empty_rejected);
  ATF_ADD_TEST_CASE(tcs, pairs_index_in_error);
  ATF_ADD_TEST_CASE(tcs, parse_size_plain_int);
  ATF_ADD_TEST_CASE(tcs, parse_size_K_M_G_T_are_1024_based);
  ATF_ADD_TEST_CASE(tcs, parse_size_decimal_supported);
  ATF_ADD_TEST_CASE(tcs, parse_size_invalid_returns_neg_one);
  ATF_ADD_TEST_CASE(tcs, set_argv_shape);
  ATF_ADD_TEST_CASE(tcs, set_argv_passes_raw_suffix_to_rctl);
  ATF_ADD_TEST_CASE(tcs, clear_argv_shape);
  ATF_ADD_TEST_CASE(tcs, show_argv_shape);
}
