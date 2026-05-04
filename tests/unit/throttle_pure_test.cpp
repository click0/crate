// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "throttle_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using ThrottlePure::ThrottleSpec;
using ThrottlePure::buildBindArgv;
using ThrottlePure::buildPipeConfigArgv;
using ThrottlePure::buildPipeDeleteArgv;
using ThrottlePure::buildPipeShowArgv;
using ThrottlePure::buildRuleDeleteArgv;
using ThrottlePure::hasAnyThrottle;
using ThrottlePure::pipeIdForJail;
using ThrottlePure::ruleIdForJail;
using ThrottlePure::validateBurst;
using ThrottlePure::validateIp;
using ThrottlePure::validateQueue;
using ThrottlePure::validateRate;
using ThrottlePure::validateSpec;

// --- validateRate ---

ATF_TEST_CASE_WITHOUT_HEAD(rate_typical_units);
ATF_TEST_CASE_BODY(rate_typical_units) {
  ATF_REQUIRE_EQ(validateRate("10Mbit/s"),  std::string());
  ATF_REQUIRE_EQ(validateRate("100Kbit/s"), std::string());
  ATF_REQUIRE_EQ(validateRate("1Gbit/s"),   std::string());
  ATF_REQUIRE_EQ(validateRate("10MB/s"),    std::string());
  ATF_REQUIRE_EQ(validateRate("100KB/s"),   std::string());
  ATF_REQUIRE_EQ(validateRate("10000"),     std::string());
  // Decimal numbers in body are accepted.
  ATF_REQUIRE_EQ(validateRate("1.5Mbit/s"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(rate_invalid_rejected);
ATF_TEST_CASE_BODY(rate_invalid_rejected) {
  ATF_REQUIRE(!validateRate("").empty());
  // Bare "10M" is intentionally REJECTED: ipfw accepts it but it
  // confuses bit/s and byte/s. We force the operator to spell it out.
  ATF_REQUIRE(!validateRate("10M").empty());
  ATF_REQUIRE(!validateRate("10mbit/s").empty());   // lowercase b — reject; ipfw is finicky
  ATF_REQUIRE(!validateRate("Mbit/s").empty());     // suffix only
  ATF_REQUIRE(!validateRate("ten Mbit/s").empty());
  ATF_REQUIRE(!validateRate("10Mbps").empty());     // wrong abbreviation
}

// --- validateBurst ---

ATF_TEST_CASE_WITHOUT_HEAD(burst_typical_or_empty);
ATF_TEST_CASE_BODY(burst_typical_or_empty) {
  ATF_REQUIRE_EQ(validateBurst(""),       std::string());   // empty = no burst
  ATF_REQUIRE_EQ(validateBurst("1MB"),    std::string());
  ATF_REQUIRE_EQ(validateBurst("100KB"),  std::string());
  ATF_REQUIRE_EQ(validateBurst("100000"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(burst_invalid_rejected);
ATF_TEST_CASE_BODY(burst_invalid_rejected) {
  ATF_REQUIRE(!validateBurst("KB").empty());
  ATF_REQUIRE(!validateBurst("1MB/s").empty());     // burst is bytes, not bytes/s
  ATF_REQUIRE(!validateBurst("1mb").empty());       // wrong case
  ATF_REQUIRE(!validateBurst("abc").empty());
}

// --- validateQueue ---

ATF_TEST_CASE_WITHOUT_HEAD(queue_typical);
ATF_TEST_CASE_BODY(queue_typical) {
  ATF_REQUIRE_EQ(validateQueue(""),       std::string());
  ATF_REQUIRE_EQ(validateQueue("50"),     std::string());
  ATF_REQUIRE_EQ(validateQueue("1000"),   std::string());
  ATF_REQUIRE_EQ(validateQueue("100KB"),  std::string());
  ATF_REQUIRE_EQ(validateQueue("1MB"),    std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(queue_out_of_range);
ATF_TEST_CASE_BODY(queue_out_of_range) {
  // Slot count bounds: dummynet ipfw documents 100 default; we
  // cap at 1000 to avoid operators turning it into an unbounded
  // memory sink.
  ATF_REQUIRE(!validateQueue("0").empty());
  ATF_REQUIRE(!validateQueue("10000").empty());
  ATF_REQUIRE(!validateQueue("abc").empty());
}

// --- validateIp ---

ATF_TEST_CASE_WITHOUT_HEAD(ip_typical);
ATF_TEST_CASE_BODY(ip_typical) {
  ATF_REQUIRE_EQ(validateIp("10.0.0.5"),       std::string());
  ATF_REQUIRE_EQ(validateIp("192.168.1.100"),  std::string());
  ATF_REQUIRE_EQ(validateIp("0.0.0.0"),        std::string());
  ATF_REQUIRE_EQ(validateIp("255.255.255.255"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(ip_invalid);
ATF_TEST_CASE_BODY(ip_invalid) {
  ATF_REQUIRE(!validateIp("").empty());
  ATF_REQUIRE(!validateIp("256.0.0.1").empty());
  ATF_REQUIRE(!validateIp("10.0.0").empty());
  ATF_REQUIRE(!validateIp("10.0.0.1.5").empty());
  ATF_REQUIRE(!validateIp("10.0.0.").empty());
}

// --- pipeIdForJail / ruleIdForJail ---

ATF_TEST_CASE_WITHOUT_HEAD(pipe_id_deterministic_per_jail);
ATF_TEST_CASE_BODY(pipe_id_deterministic_per_jail) {
  // Same JID + direction → same pipe ID across calls. Critical
  // so a teardown after a daemon restart can find the right pipe.
  ATF_REQUIRE_EQ(pipeIdForJail(7, false), pipeIdForJail(7, false));
  ATF_REQUIRE_EQ(pipeIdForJail(7, true),  pipeIdForJail(7, true));
  // Ingress and egress get distinct IDs.
  ATF_REQUIRE(pipeIdForJail(7, false) != pipeIdForJail(7, true));
  // Different jails get different pipe IDs.
  ATF_REQUIRE(pipeIdForJail(7, false) != pipeIdForJail(8, false));
}

ATF_TEST_CASE_WITHOUT_HEAD(pipe_and_rule_ids_in_disjoint_ranges);
ATF_TEST_CASE_BODY(pipe_and_rule_ids_in_disjoint_ranges) {
  // kPipeBase = 10000, kRuleBase = 20000 — no overlap so an
  // operator listing rules sees the correspondence at a glance.
  ATF_REQUIRE(pipeIdForJail(7, false) >= ThrottlePure::kPipeBase);
  ATF_REQUIRE(pipeIdForJail(7, false) <  ThrottlePure::kRuleBase);
  ATF_REQUIRE(ruleIdForJail(7, false) >= ThrottlePure::kRuleBase);
}

// --- validateSpec ---

ATF_TEST_CASE_WITHOUT_HEAD(spec_typical_full);
ATF_TEST_CASE_BODY(spec_typical_full) {
  ThrottleSpec s;
  s.ingressRate = "10Mbit/s"; s.ingressBurst = "1MB";
  s.egressRate  = "5Mbit/s";  s.egressBurst  = "500KB";
  s.queue = "100";
  ATF_REQUIRE_EQ(validateSpec(s), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_one_direction_only);
ATF_TEST_CASE_BODY(spec_one_direction_only) {
  // Throttling only egress is a common pattern (download is fine,
  // upload is the one fighting your IDE).
  ThrottleSpec s;
  s.egressRate = "1Mbit/s";
  ATF_REQUIRE_EQ(validateSpec(s), std::string());
  ATF_REQUIRE(hasAnyThrottle(s));
}

ATF_TEST_CASE_WITHOUT_HEAD(spec_burst_without_rate_is_an_error);
ATF_TEST_CASE_BODY(spec_burst_without_rate_is_an_error) {
  // Operator typo — burst alone has no effect; we surface this
  // instead of silently accepting it.
  ThrottleSpec s;
  s.ingressBurst = "1MB";
  auto err = validateSpec(s);
  ATF_REQUIRE(!err.empty());
  ATF_REQUIRE(err.find("burst") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(has_any_throttle_predicate);
ATF_TEST_CASE_BODY(has_any_throttle_predicate) {
  ThrottleSpec s;
  ATF_REQUIRE(!hasAnyThrottle(s));
  s.ingressRate = "10Mbit/s";
  ATF_REQUIRE(hasAnyThrottle(s));
}

// --- argv builders ---

ATF_TEST_CASE_WITHOUT_HEAD(pipe_config_full_argv);
ATF_TEST_CASE_BODY(pipe_config_full_argv) {
  auto v = buildPipeConfigArgv(10001, "10Mbit/s", "1MB", "100");
  // ipfw pipe 10001 config bw 10Mbit/s burst 1MB queue 100
  ATF_REQUIRE_EQ(v[0], std::string("/sbin/ipfw"));
  ATF_REQUIRE_EQ(v[1], std::string("pipe"));
  ATF_REQUIRE_EQ(v[2], std::string("10001"));
  ATF_REQUIRE_EQ(v[3], std::string("config"));
  ATF_REQUIRE_EQ(v[4], std::string("bw"));
  ATF_REQUIRE_EQ(v[5], std::string("10Mbit/s"));
  ATF_REQUIRE_EQ(v[6], std::string("burst"));
  ATF_REQUIRE_EQ(v[7], std::string("1MB"));
  ATF_REQUIRE_EQ(v[8], std::string("queue"));
  ATF_REQUIRE_EQ(v[9], std::string("100"));
}

ATF_TEST_CASE_WITHOUT_HEAD(pipe_config_omits_optional_burst_and_queue);
ATF_TEST_CASE_BODY(pipe_config_omits_optional_burst_and_queue) {
  auto v = buildPipeConfigArgv(10001, "10Mbit/s", "", "");
  ATF_REQUIRE_EQ(v.size(), (size_t)6);   // ipfw pipe N config bw RATE
  // No "burst" or "queue" tokens.
  for (auto &s : v) {
    ATF_REQUIRE(s != "burst");
    ATF_REQUIRE(s != "queue");
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(bind_egress_uses_from_ip_to_any);
ATF_TEST_CASE_BODY(bind_egress_uses_from_ip_to_any) {
  auto v = buildBindArgv(20001, 10001, "10.0.0.5", /*egress*/true);
  // ipfw add 20001 pipe 10001 ip from 10.0.0.5 to any out
  ATF_REQUIRE_EQ(v[2], std::string("20001"));
  ATF_REQUIRE_EQ(v[3], std::string("pipe"));
  ATF_REQUIRE_EQ(v[4], std::string("10001"));
  // The from/to ordering is what makes egress vs. ingress work.
  bool sawFromIp = false;
  for (size_t i = 0; i + 1 < v.size(); i++)
    if (v[i] == "from" && v[i + 1] == "10.0.0.5") sawFromIp = true;
  ATF_REQUIRE(sawFromIp);
  ATF_REQUIRE_EQ(v.back(), std::string("out"));
}

ATF_TEST_CASE_WITHOUT_HEAD(bind_ingress_uses_from_any_to_ip);
ATF_TEST_CASE_BODY(bind_ingress_uses_from_any_to_ip) {
  auto v = buildBindArgv(20000, 10000, "10.0.0.5", /*egress*/false);
  bool sawToIp = false;
  for (size_t i = 0; i + 1 < v.size(); i++)
    if (v[i] == "to" && v[i + 1] == "10.0.0.5") sawToIp = true;
  ATF_REQUIRE(sawToIp);
  ATF_REQUIRE_EQ(v.back(), std::string("in"));
}

ATF_TEST_CASE_WITHOUT_HEAD(rule_and_pipe_delete_argv);
ATF_TEST_CASE_BODY(rule_and_pipe_delete_argv) {
  auto rd = buildRuleDeleteArgv(20001);
  ATF_REQUIRE_EQ(rd.size(), (size_t)3);
  ATF_REQUIRE_EQ(rd[1], std::string("delete"));
  ATF_REQUIRE_EQ(rd[2], std::string("20001"));
  auto pd = buildPipeDeleteArgv(10001);
  // ipfw pipe N delete (note: word order — delete is LAST for pipes).
  ATF_REQUIRE_EQ(pd[1], std::string("pipe"));
  ATF_REQUIRE_EQ(pd[2], std::string("10001"));
  ATF_REQUIRE_EQ(pd[3], std::string("delete"));
}

ATF_TEST_CASE_WITHOUT_HEAD(pipe_show_argv);
ATF_TEST_CASE_BODY(pipe_show_argv) {
  auto v = buildPipeShowArgv(10001);
  ATF_REQUIRE_EQ(v[1], std::string("pipe"));
  ATF_REQUIRE_EQ(v[2], std::string("show"));
  ATF_REQUIRE_EQ(v[3], std::string("10001"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, rate_typical_units);
  ATF_ADD_TEST_CASE(tcs, rate_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, burst_typical_or_empty);
  ATF_ADD_TEST_CASE(tcs, burst_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, queue_typical);
  ATF_ADD_TEST_CASE(tcs, queue_out_of_range);
  ATF_ADD_TEST_CASE(tcs, ip_typical);
  ATF_ADD_TEST_CASE(tcs, ip_invalid);
  ATF_ADD_TEST_CASE(tcs, pipe_id_deterministic_per_jail);
  ATF_ADD_TEST_CASE(tcs, pipe_and_rule_ids_in_disjoint_ranges);
  ATF_ADD_TEST_CASE(tcs, spec_typical_full);
  ATF_ADD_TEST_CASE(tcs, spec_one_direction_only);
  ATF_ADD_TEST_CASE(tcs, spec_burst_without_rate_is_an_error);
  ATF_ADD_TEST_CASE(tcs, has_any_throttle_predicate);
  ATF_ADD_TEST_CASE(tcs, pipe_config_full_argv);
  ATF_ADD_TEST_CASE(tcs, pipe_config_omits_optional_burst_and_queue);
  ATF_ADD_TEST_CASE(tcs, bind_egress_uses_from_ip_to_any);
  ATF_ADD_TEST_CASE(tcs, bind_ingress_uses_from_any_to_ip);
  ATF_ADD_TEST_CASE(tcs, rule_and_pipe_delete_argv);
  ATF_ADD_TEST_CASE(tcs, pipe_show_argv);
}
