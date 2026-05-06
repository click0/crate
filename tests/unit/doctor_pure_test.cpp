// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "doctor_pure.h"

#include <atf-c++.hpp>

#include <string>

using DoctorPure::Check;
using DoctorPure::Counts;
using DoctorPure::Report;
using DoctorPure::Severity;
using DoctorPure::exitCodeFor;
using DoctorPure::failCheck;
using DoctorPure::passCheck;
using DoctorPure::renderJson;
using DoctorPure::renderText;
using DoctorPure::severityLabel;
using DoctorPure::tally;
using DoctorPure::warnCheck;

// ----------------------------------------------------------------------
// Constructors + tally + exit code
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(constructors_set_severity);
ATF_TEST_CASE_BODY(constructors_set_severity) {
  ATF_REQUIRE(passCheck("kernel", "vmm").severity == Severity::Pass);
  ATF_REQUIRE(warnCheck("audit", "log size", "85 MB").severity == Severity::Warn);
  ATF_REQUIRE(failCheck("kernel", "dummynet", "kldload it").severity == Severity::Fail);
}

ATF_TEST_CASE_WITHOUT_HEAD(severity_labels);
ATF_TEST_CASE_BODY(severity_labels) {
  ATF_REQUIRE_EQ(std::string(severityLabel(Severity::Pass)), std::string("PASS"));
  ATF_REQUIRE_EQ(std::string(severityLabel(Severity::Warn)), std::string("WARN"));
  ATF_REQUIRE_EQ(std::string(severityLabel(Severity::Fail)), std::string("FAIL"));
}

ATF_TEST_CASE_WITHOUT_HEAD(tally_counts);
ATF_TEST_CASE_BODY(tally_counts) {
  Report r;
  r.checks.push_back(passCheck("k", "a"));
  r.checks.push_back(passCheck("k", "b"));
  r.checks.push_back(warnCheck("k", "c", "x"));
  r.checks.push_back(failCheck("k", "d", "y"));
  auto c = tally(r);
  ATF_REQUIRE_EQ(c.pass, 2);
  ATF_REQUIRE_EQ(c.warn, 1);
  ATF_REQUIRE_EQ(c.fail, 1);
}

ATF_TEST_CASE_WITHOUT_HEAD(exit_code_priorities);
ATF_TEST_CASE_BODY(exit_code_priorities) {
  Report r;
  // empty
  ATF_REQUIRE_EQ(exitCodeFor(r), 0);

  // all pass
  r.checks.push_back(passCheck("k", "a"));
  ATF_REQUIRE_EQ(exitCodeFor(r), 0);

  // pass + warn -> 1
  r.checks.push_back(warnCheck("k", "b", "x"));
  ATF_REQUIRE_EQ(exitCodeFor(r), 1);

  // pass + warn + fail -> 2
  r.checks.push_back(failCheck("k", "c", "y"));
  ATF_REQUIRE_EQ(exitCodeFor(r), 2);

  // fail outweighs warn even when warn comes after
  Report r2;
  r2.checks.push_back(failCheck("k", "a", "boom"));
  r2.checks.push_back(warnCheck("k", "b", "tepid"));
  ATF_REQUIRE_EQ(exitCodeFor(r2), 2);
}

// ----------------------------------------------------------------------
// renderText — alignment, category grouping, summary
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(text_groups_by_category);
ATF_TEST_CASE_BODY(text_groups_by_category) {
  Report r;
  r.checks.push_back(passCheck("kernel",  "vmm"));
  r.checks.push_back(passCheck("command", "/sbin/zfs"));
  r.checks.push_back(passCheck("kernel",  "nmdm"));
  auto t = renderText(r, /*noColor=*/true);
  // kernel header should appear before command header
  auto pk = t.find("kernel:");
  auto pc = t.find("command:");
  ATF_REQUIRE(pk != std::string::npos);
  ATF_REQUIRE(pc != std::string::npos);
  ATF_REQUIRE(pk < pc);
  // Both kernel checks under the kernel header (vmm before nmdm
  // because they're sorted by name within a category)
  auto nmdm = t.find("nmdm");
  auto vmm  = t.find("vmm");
  ATF_REQUIRE(nmdm != std::string::npos);
  ATF_REQUIRE(vmm  != std::string::npos);
  ATF_REQUIRE(nmdm < vmm);
}

ATF_TEST_CASE_WITHOUT_HEAD(text_severity_labels_present);
ATF_TEST_CASE_BODY(text_severity_labels_present) {
  Report r;
  r.checks.push_back(passCheck("kernel", "vmm"));
  r.checks.push_back(warnCheck("audit", "size", "big"));
  r.checks.push_back(failCheck("kernel", "dummynet", "load it"));
  auto t = renderText(r, true);
  ATF_REQUIRE(t.find("[PASS]") != std::string::npos);
  ATF_REQUIRE(t.find("[WARN]") != std::string::npos);
  ATF_REQUIRE(t.find("[FAIL]") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(text_includes_summary);
ATF_TEST_CASE_BODY(text_includes_summary) {
  Report r;
  r.checks.push_back(passCheck("k", "a"));
  r.checks.push_back(warnCheck("k", "b", "x"));
  r.checks.push_back(failCheck("k", "c", "y"));
  auto t = renderText(r, true);
  ATF_REQUIRE(t.find("Summary:")    != std::string::npos);
  ATF_REQUIRE(t.find("1 PASS")      != std::string::npos);
  ATF_REQUIRE(t.find("1 WARN")      != std::string::npos);
  ATF_REQUIRE(t.find("1 FAIL")      != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(text_no_color_omits_ansi);
ATF_TEST_CASE_BODY(text_no_color_omits_ansi) {
  Report r;
  r.checks.push_back(failCheck("k", "vmm", "kldload vmm"));
  auto t = renderText(r, /*noColor=*/true);
  ATF_REQUIRE(t.find("\x1b[") == std::string::npos);  // no ANSI escape

  auto t2 = renderText(r, /*noColor=*/false);
  ATF_REQUIRE(t2.find("\x1b[31m") != std::string::npos);  // red for FAIL
  ATF_REQUIRE(t2.find("\x1b[0m")  != std::string::npos);  // reset
}

ATF_TEST_CASE_WITHOUT_HEAD(text_detail_appears_when_present);
ATF_TEST_CASE_BODY(text_detail_appears_when_present) {
  Report r;
  r.checks.push_back(failCheck("kernel", "dummynet", "load with: kldload dummynet"));
  auto t = renderText(r, true);
  ATF_REQUIRE(t.find("load with: kldload dummynet") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(text_category_canonical_order);
ATF_TEST_CASE_BODY(text_category_canonical_order) {
  // Stable rank: kernel < command < filesystem < zfs < config < jails < audit
  Report r;
  r.checks.push_back(passCheck("audit",      "log"));
  r.checks.push_back(passCheck("kernel",     "vmm"));
  r.checks.push_back(passCheck("command",    "zfs"));
  r.checks.push_back(passCheck("zfs",        "tank"));
  r.checks.push_back(passCheck("filesystem", "/var/run/crate"));
  auto t = renderText(r, true);
  // Find the line of each header in order they appear.
  auto pk = t.find("kernel:");
  auto pc = t.find("command:");
  auto pf = t.find("filesystem:");
  auto pz = t.find("zfs:");
  auto pa = t.find("audit:");
  ATF_REQUIRE(pk < pc);
  ATF_REQUIRE(pc < pf);
  ATF_REQUIRE(pf < pz);
  ATF_REQUIRE(pz < pa);
}

// ----------------------------------------------------------------------
// renderJson — structure + escaping
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(json_top_level_shape);
ATF_TEST_CASE_BODY(json_top_level_shape) {
  Report r;
  r.checks.push_back(passCheck("k", "a"));
  auto j = renderJson(r);
  // top-level keys
  ATF_REQUIRE(j.find("\"checks\":")   != std::string::npos);
  ATF_REQUIRE(j.find("\"summary\":")  != std::string::npos);
  ATF_REQUIRE(j.find("\"pass\":1")    != std::string::npos);
  ATF_REQUIRE(j.find("\"warn\":0")    != std::string::npos);
  ATF_REQUIRE(j.find("\"fail\":0")    != std::string::npos);
  // a check with all required fields
  ATF_REQUIRE(j.find("\"category\":\"k\"") != std::string::npos);
  ATF_REQUIRE(j.find("\"name\":\"a\"")     != std::string::npos);
  ATF_REQUIRE(j.find("\"severity\":\"PASS\"") != std::string::npos);
  ATF_REQUIRE(j.find("\"detail\":\"\"")    != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(json_empty_report);
ATF_TEST_CASE_BODY(json_empty_report) {
  Report r;
  auto j = renderJson(r);
  ATF_REQUIRE_EQ(j,
    std::string("{\"checks\":[],\"summary\":{\"pass\":0,\"warn\":0,\"fail\":0}}"));
}

ATF_TEST_CASE_WITHOUT_HEAD(json_escapes_quotes_and_newlines);
ATF_TEST_CASE_BODY(json_escapes_quotes_and_newlines) {
  Report r;
  r.checks.push_back(failCheck("kernel", "vmm",
    "fix:\nkldload \"vmm\""));
  auto j = renderJson(r);
  ATF_REQUIRE(j.find("\\\"vmm\\\"") != std::string::npos);
  ATF_REQUIRE(j.find("\\n")         != std::string::npos);
  // No raw newline in the JSON.
  ATF_REQUIRE(j.find('\n') == std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, constructors_set_severity);
  ATF_ADD_TEST_CASE(tcs, severity_labels);
  ATF_ADD_TEST_CASE(tcs, tally_counts);
  ATF_ADD_TEST_CASE(tcs, exit_code_priorities);
  ATF_ADD_TEST_CASE(tcs, text_groups_by_category);
  ATF_ADD_TEST_CASE(tcs, text_severity_labels_present);
  ATF_ADD_TEST_CASE(tcs, text_includes_summary);
  ATF_ADD_TEST_CASE(tcs, text_no_color_omits_ansi);
  ATF_ADD_TEST_CASE(tcs, text_detail_appears_when_present);
  ATF_ADD_TEST_CASE(tcs, text_category_canonical_order);
  ATF_ADD_TEST_CASE(tcs, json_top_level_shape);
  ATF_ADD_TEST_CASE(tcs, json_empty_report);
  ATF_ADD_TEST_CASE(tcs, json_escapes_quotes_and_newlines);
}
