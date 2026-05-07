// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "spec_registry_pure.h"

#include <atf-c++.hpp>

#include <string>

using SpecRegistryPure::Entry;
using SpecRegistryPure::findIndex;
using SpecRegistryPure::formatLine;
using SpecRegistryPure::parseLine;
using SpecRegistryPure::validateEntry;
using SpecRegistryPure::validateName;
using SpecRegistryPure::validatePath;

// --- validateName ---

ATF_TEST_CASE_WITHOUT_HEAD(name_typical_accepted);
ATF_TEST_CASE_BODY(name_typical_accepted) {
  ATF_REQUIRE_EQ(validateName("firefox"),    std::string());
  ATF_REQUIRE_EQ(validateName("dev-postgres"), std::string());
  ATF_REQUIRE_EQ(validateName("vm_42"),      std::string());
  ATF_REQUIRE_EQ(validateName("Web-App"),    std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(name_rejects_garbage);
ATF_TEST_CASE_BODY(name_rejects_garbage) {
  ATF_REQUIRE(!validateName("").empty());
  ATF_REQUIRE(!validateName("-leading").empty());
  ATF_REQUIRE(!validateName(".leading").empty());
  ATF_REQUIRE(!validateName("with space").empty());
  ATF_REQUIRE(!validateName("with/slash").empty());
  ATF_REQUIRE(!validateName("$(reboot)").empty());
  // length cap
  std::string toolong(64, 'a');
  ATF_REQUIRE(!validateName(toolong).empty());
}

// --- validatePath ---

ATF_TEST_CASE_WITHOUT_HEAD(path_typical_accepted);
ATF_TEST_CASE_BODY(path_typical_accepted) {
  ATF_REQUIRE_EQ(validatePath("/home/op/firefox.crate"), std::string());
  ATF_REQUIRE_EQ(validatePath("/var/run/crate/specs/web.crate"), std::string());
  ATF_REQUIRE_EQ(validatePath("/has space/spec.crate"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(path_rejects_relative);
ATF_TEST_CASE_BODY(path_rejects_relative) {
  ATF_REQUIRE(!validatePath("").empty());
  ATF_REQUIRE(!validatePath("relative.crate").empty());
  ATF_REQUIRE(!validatePath("./local.crate").empty());
  ATF_REQUIRE(!validatePath("../parent.crate").empty());
  ATF_REQUIRE(!validatePath("/foo/../bar.crate").empty());   // .. segment
}

ATF_TEST_CASE_WITHOUT_HEAD(path_rejects_shell_metas);
ATF_TEST_CASE_BODY(path_rejects_shell_metas) {
  for (auto p : {"/foo/$(id).crate",
                 "/foo/`id`.crate",
                 "/foo/spec;reboot",
                 "/foo/a|b.crate",
                 "/foo/a&b.crate",
                 "/foo/star*.crate",
                 "/foo/q?.crate",
                 "/foo/a<b.crate",
                 "/foo/a>b.crate",
                 "/foo/a\"b.crate",
                 "/foo/a'b.crate",
                 "/foo/a\\b.crate",
                 "/foo/with\nnewline.crate"}) {
    auto err = validatePath(p);
    ATF_REQUIRE(!err.empty());
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(path_rejects_control_chars);
ATF_TEST_CASE_BODY(path_rejects_control_chars) {
  std::string p = std::string("/has\x01") + "ctrl.crate";
  ATF_REQUIRE(!validatePath(p).empty());
  std::string del = std::string("/has\x7f") + "del.crate";
  ATF_REQUIRE(!validatePath(del).empty());
}

// --- parse / format round-trip ---

ATF_TEST_CASE_WITHOUT_HEAD(line_round_trip);
ATF_TEST_CASE_BODY(line_round_trip) {
  Entry in;
  in.name = "firefox";
  in.cratePath = "/home/op/firefox.crate";
  auto line = formatLine(in);
  ATF_REQUIRE_EQ(line, std::string("firefox /home/op/firefox.crate"));
  Entry out;
  ATF_REQUIRE_EQ(parseLine(line, out), std::string());
  ATF_REQUIRE_EQ(out.name, in.name);
  ATF_REQUIRE_EQ(out.cratePath, in.cratePath);
}

ATF_TEST_CASE_WITHOUT_HEAD(line_rejects_extra_spaces);
ATF_TEST_CASE_BODY(line_rejects_extra_spaces) {
  Entry out;
  // Path with a literal space is supported via the single-space
  // separator + remainder-as-path convention.
  ATF_REQUIRE_EQ(parseLine("firefox /home/has space/firefox.crate", out),
                 std::string());
  // But two spaces between name and path is rejected (operator
  // typo, not a valid path-with-space).
  ATF_REQUIRE(!parseLine("firefox  /home/op.crate", out).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(line_rejects_garbage);
ATF_TEST_CASE_BODY(line_rejects_garbage) {
  Entry out;
  ATF_REQUIRE(!parseLine("",                   out).empty());
  ATF_REQUIRE(!parseLine("only-name",          out).empty());
  ATF_REQUIRE(!parseLine("name relative.crate", out).empty());
  ATF_REQUIRE(!parseLine("-bad /abs.crate",    out).empty());
  ATF_REQUIRE(!parseLine(" /abs.crate",        out).empty());   // empty name
}

// --- findIndex ---

ATF_TEST_CASE_WITHOUT_HEAD(findIndex_works);
ATF_TEST_CASE_BODY(findIndex_works) {
  std::vector<Entry> es = {
    {"a", "/a.crate"},
    {"b", "/b.crate"},
    {"c", "/c.crate"},
  };
  ATF_REQUIRE_EQ(findIndex(es, "a"), 0);
  ATF_REQUIRE_EQ(findIndex(es, "b"), 1);
  ATF_REQUIRE_EQ(findIndex(es, "c"), 2);
  ATF_REQUIRE_EQ(findIndex(es, "missing"), -1);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, name_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, name_rejects_garbage);
  ATF_ADD_TEST_CASE(tcs, path_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, path_rejects_relative);
  ATF_ADD_TEST_CASE(tcs, path_rejects_shell_metas);
  ATF_ADD_TEST_CASE(tcs, path_rejects_control_chars);
  ATF_ADD_TEST_CASE(tcs, line_round_trip);
  ATF_ADD_TEST_CASE(tcs, line_rejects_extra_spaces);
  ATF_ADD_TEST_CASE(tcs, line_rejects_garbage);
  ATF_ADD_TEST_CASE(tcs, findIndex_works);
}
