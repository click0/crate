// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "audit_per_user_pure.h"

#include <atf-c++.hpp>

#include <string>

using namespace AuditPerUserPure;

ATF_TEST_CASE_WITHOUT_HEAD(format_typical_ok);
ATF_TEST_CASE_BODY(format_typical_ok) {
  Record r;
  r.timestamp = 1715250000;
  r.uid = 1000;
  r.verb = "set_rctl";
  r.status = 200;
  std::string line = formatLine(r);
  // Field order stable
  ATF_REQUIRE(line.find("\"ts\":1715250000") != std::string::npos);
  ATF_REQUIRE(line.find("\"uid\":1000") != std::string::npos);
  ATF_REQUIRE(line.find("\"verb\":\"set_rctl\"") != std::string::npos);
  ATF_REQUIRE(line.find("\"status\":200") != std::string::npos);
  ATF_REQUIRE(line.find("\"outcome\":\"ok\"") != std::string::npos);
  // Single-line: no embedded newlines
  ATF_REQUIRE(line.find('\n') == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(outcome_classification);
ATF_TEST_CASE_BODY(outcome_classification) {
  ATF_REQUIRE_EQ(std::string(outcomeFor(200)), std::string("ok"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(201)), std::string("ok"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(204)), std::string("ok"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(400)),
                 std::string("parse_or_validate"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(403)), std::string("forbidden"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(404)), std::string("not_found"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(429)), std::string("rate_limit"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(500)), std::string("server_error"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(501)), std::string("server_error"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(599)), std::string("server_error"));
  // Unknown territory
  ATF_REQUIRE_EQ(std::string(outcomeFor(100)), std::string("other"));
  ATF_REQUIRE_EQ(std::string(outcomeFor(0)),   std::string("other"));
}

ATF_TEST_CASE_WITHOUT_HEAD(format_outcome_matches_status);
ATF_TEST_CASE_BODY(format_outcome_matches_status) {
  // Sanity check that formatLine actually uses outcomeFor(status).
  Record r;
  r.timestamp = 0; r.uid = 0; r.verb = "set_rctl";

  r.status = 200;
  ATF_REQUIRE(formatLine(r).find("\"outcome\":\"ok\"") != std::string::npos);
  r.status = 400;
  ATF_REQUIRE(formatLine(r).find("\"outcome\":\"parse_or_validate\"")
              != std::string::npos);
  r.status = 501;
  ATF_REQUIRE(formatLine(r).find("\"outcome\":\"server_error\"")
              != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_escapes_verb_name);
ATF_TEST_CASE_BODY(format_escapes_verb_name) {
  // Verb tokens are alphanumeric + underscore in practice (parseVerb
  // gates this), but defence in depth: a smuggled quote in a future
  // verb name must get escaped, not break the JSON.
  Record r;
  r.timestamp = 0; r.uid = 0; r.status = 200;
  r.verb = "evil\"verb";
  std::string line = formatLine(r);
  ATF_REQUIRE(line.find("evil\\\"verb") != std::string::npos);
  // No raw unescaped quote injecting a new field
  ATF_REQUIRE(line.find("\"verb\":\"evil\"verb\"") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_no_detail_field);
ATF_TEST_CASE_BODY(format_no_detail_field) {
  // The audit line intentionally OMITS the response body / detail;
  // canonical record stays in cap_syslog dual-write. Lock it down
  // so a future "let's add detail here" change requires explicit
  // test update.
  Record r;
  r.timestamp = 1715250000; r.uid = 1000;
  r.verb = "set_rctl"; r.status = 200;
  std::string line = formatLine(r);
  ATF_REQUIRE(line.find("\"detail\"") == std::string::npos);
  ATF_REQUIRE(line.find("\"body\"")   == std::string::npos);
  ATF_REQUIRE(line.find("\"error\"")  == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(format_distinct_records_alice_vs_bob);
ATF_TEST_CASE_BODY(format_distinct_records_alice_vs_bob) {
  Record alice; alice.timestamp = 100; alice.uid = 1000;
  alice.verb = "set_rctl"; alice.status = 200;
  Record bob = alice; bob.uid = 1001;
  ATF_REQUIRE(formatLine(alice) != formatLine(bob));
  ATF_REQUIRE(formatLine(alice).find("\"uid\":1000") != std::string::npos);
  ATF_REQUIRE(formatLine(bob).find("\"uid\":1001")   != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, format_typical_ok);
  ATF_ADD_TEST_CASE(tcs, outcome_classification);
  ATF_ADD_TEST_CASE(tcs, format_outcome_matches_status);
  ATF_ADD_TEST_CASE(tcs, format_escapes_verb_name);
  ATF_ADD_TEST_CASE(tcs, format_no_detail_field);
  ATF_ADD_TEST_CASE(tcs, format_distinct_records_alice_vs_bob);
}
