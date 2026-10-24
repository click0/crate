// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "devices_pure.h"
#include "privops_pure.h"

#include <atf-c++.hpp>

#include <algorithm>
#include <string>

using namespace DevicesPure;

namespace {
bool has(const std::vector<std::string> &v, const std::string &s) {
  return std::find(v.begin(), v.end(), s) != v.end();
}
}

ATF_TEST_CASE_WITHOUT_HEAD(classes_set_describe_merge);
ATF_TEST_CASE_BODY(classes_set_describe_merge) {
  Devices d;
  ATF_REQUIRE(!d.any());
  ATF_REQUIRE_EQ(describe(d), std::string("none"));
  ATF_REQUIRE_EQ(classNames().size(), 6u);
  for (const auto &c : classNames()) ATF_REQUIRE(setClass(d, c, true));
  ATF_REQUIRE(d.sound && d.gpu && d.video && d.input && d.usb && d.serial);
  ATF_REQUIRE_EQ(describe(d), std::string("sound, gpu, video, input, usb, serial"));
  ATF_REQUIRE(setClass(d, "input", false));
  ATF_REQUIRE(!d.input);
  ATF_REQUIRE(!setClass(d, "keyboard", true));
  ATF_REQUIRE(!setClass(d, "", true));
  ATF_REQUIRE(!setClass(d, "Sound", true));   // case matters, like every other spec key

  Devices a; a.sound = true;
  Devices b; b.gpu = true; b.all = true;
  a.merge(b);
  ATF_REQUIRE(a.sound && a.gpu && a.all);
  ATF_REQUIRE_EQ(describe(a), std::string("all"));
}

ATF_TEST_CASE_WITHOUT_HEAD(patterns_per_class);
ATF_TEST_CASE_BODY(patterns_per_class) {
  ATF_REQUIRE(has(patternsFor("gpu"), "dri/*"));
  ATF_REQUIRE(has(patternsFor("gpu"), "nvidia*"));
  ATF_REQUIRE(has(patternsFor("sound"), "dsp*"));
  ATF_REQUIRE(has(patternsFor("sound"), "sndstat"));
  ATF_REQUIRE(has(patternsFor("video"), "video*"));
  ATF_REQUIRE(has(patternsFor("input"), "input/*"));
  ATF_REQUIRE(has(patternsFor("usb"), "ugen*"));
  ATF_REQUIRE(has(patternsFor("usb"), "uhid*"));
  ATF_REQUIRE(has(patternsFor("serial"), "cua*"));
  ATF_REQUIRE(patternsFor("disks").empty());
  // nothing a class unhides is a host-wide device
  for (const auto &c : classNames())
    for (const auto &p : patternsFor(c)) {
      ATF_REQUIRE(p != "mem" && p != "kmem" && p != "io" && p != "pf");
      ATF_REQUIRE(p[0] != '/');
      ATF_REQUIRE(p.find("..") == std::string::npos);
    }

  Devices d; d.gpu = true; d.sound = true;
  auto u = unhidePatterns(d);
  ATF_REQUIRE_EQ(u.size(), patternsFor("sound").size() + patternsFor("gpu").size());
  ATF_REQUIRE_EQ(u[0], std::string("dsp*"));   // class order: sound before gpu
  ATF_REQUIRE(unhidePatterns(Devices{}).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(base_rules_and_build);
ATF_TEST_CASE_BODY(base_rules_and_build) {
  auto base = baseRules(false);
  ATF_REQUIRE_EQ(base[0], std::string("hide"));
  for (const char *n : {"null", "zero", "random", "urandom", "crypto", "tty", "ptmx", "pts", "pts/*",
                        "fd", "fd/*", "stdin", "stdout", "stderr", "fuse", "zfs"})
    ATF_REQUIRE(has(base, std::string("path ") + n + " unhide"));
  ATF_REQUIRE(!has(base, "path bpf* unhide"));
  ATF_REQUIRE(has(baseRules(true), "path bpf* unhide"));
  // nothing else: no disks, no keyboards, no mem
  for (const auto &r : base) {
    ATF_REQUIRE(r.find("ada") == std::string::npos);
    ATF_REQUIRE(r.find("kbd") == std::string::npos);
    ATF_REQUIRE(r.find("mem") == std::string::npos);
  }

  // default base + classes
  Devices d; d.gpu = true;
  auto rules = buildRules(d, -1, true);
  ATF_REQUIRE_EQ(rules[0], std::string("hide"));
  ATF_REQUIRE(has(rules, "path bpf* unhide"));
  ATF_REQUIRE(has(rules, "path dri/* unhide"));
  ATF_REQUIRE_EQ(rules.back(), std::string("path nvidia* unhide"));
  ATF_REQUIRE(!has(rules, "path dsp* unhide"));

  // a custom terminal/devfs_ruleset is included instead of the base
  auto custom = buildRules(d, 42, true);
  ATF_REQUIRE_EQ(custom[0], std::string("include 42"));
  ATF_REQUIRE(!has(custom, "hide"));
  ATF_REQUIRE(!has(custom, "path null unhide"));
  ATF_REQUIRE(has(custom, "path dri unhide"));
  // ruleset 0 = none -> the base
  ATF_REQUIRE_EQ(buildRules(d, 0, false)[0], std::string("hide"));

  // every emitted rule passes the privops grammar
  for (const auto &r : buildRules(Devices{true, true, true, true, true, true, false}, -1, true))
    ATF_REQUIRE_EQ(PrivOpsPure::validateDevfsRuleSpec(r), std::string());
  for (const auto &r : buildRules(d, 7, false))
    ATF_REQUIRE_EQ(PrivOpsPure::validateDevfsRuleSpec(r), std::string());
  ATF_REQUIRE(buildRules(Devices{true, true, true, true, true, true, false}, -1, true).size()
              <= PrivOpsPure::kApplyDevfsRulesMaxRules);
}

ATF_TEST_CASE_WITHOUT_HEAD(ruleset_number_and_warnings);
ATF_TEST_CASE_BODY(ruleset_number_and_warnings) {
  ATF_REQUIRE_EQ(rulesetNumberFor(0), 10000u);
  ATF_REQUIRE_EQ(rulesetNumberFor(1), 10001u);
  ATF_REQUIRE_EQ(rulesetNumberFor(49999), 59999u);
  ATF_REQUIRE_EQ(rulesetNumberFor(50000), 10000u);
  ATF_REQUIRE_EQ(rulesetNumberFor(99999), 59999u);
  ATF_REQUIRE_EQ(rulesetNumberFor(-7), 10007u);
  for (long p : {1L, 4321L, 99999L, 123456789L}) {
    unsigned n = rulesetNumberFor(p);
    ATF_REQUIRE(n >= 10000u && n <= 59999u);   // never the stock 1..5, always a valid ruleset id
  }

  Devices d;
  ATF_REQUIRE(warnings(d).empty());
  d.sound = true; d.gpu = true; d.video = true;
  ATF_REQUIRE(warnings(d).empty());            // media classes are not a warning
  d.input = true;
  ATF_REQUIRE_EQ(warnings(d).size(), 1u);
  ATF_REQUIRE(warnings(d)[0].find("input") != std::string::npos);
  d.usb = true; d.serial = true;
  ATF_REQUIRE_EQ(warnings(d).size(), 3u);
  Devices all; all.all = true;
  ATF_REQUIRE_EQ(warnings(all).size(), 1u);
  ATF_REQUIRE(warnings(all)[0].find("whole /dev") != std::string::npos);
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, classes_set_describe_merge);
  ATF_ADD_TEST_CASE(tcs, patterns_per_class);
  ATF_ADD_TEST_CASE(tcs, base_rules_and_build);
  ATF_ADD_TEST_CASE(tcs, ruleset_number_and_warnings);
}
