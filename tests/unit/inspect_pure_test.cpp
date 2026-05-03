// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "inspect_pure.h"

#include <atf-c++.hpp>

#include <string>

using InspectPure::Interface;
using InspectPure::InspectData;
using InspectPure::Mount;
using InspectPure::applyMountOutput;
using InspectPure::applyRctlOutput;
using InspectPure::escapeJsonString;
using InspectPure::renderJson;

// --- escapeJsonString ---

ATF_TEST_CASE_WITHOUT_HEAD(escape_passthrough_ascii);
ATF_TEST_CASE_BODY(escape_passthrough_ascii) {
  ATF_REQUIRE_EQ(escapeJsonString("Hello, world!"),
                 std::string("Hello, world!"));
  ATF_REQUIRE_EQ(escapeJsonString(""), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(escape_quote_and_backslash);
ATF_TEST_CASE_BODY(escape_quote_and_backslash) {
  ATF_REQUIRE_EQ(escapeJsonString("a\"b"),  std::string("a\\\"b"));
  ATF_REQUIRE_EQ(escapeJsonString("c\\d"), std::string("c\\\\d"));
}

ATF_TEST_CASE_WITHOUT_HEAD(escape_control_chars);
ATF_TEST_CASE_BODY(escape_control_chars) {
  ATF_REQUIRE_EQ(escapeJsonString("\n"),  std::string("\\n"));
  ATF_REQUIRE_EQ(escapeJsonString("\r"),  std::string("\\r"));
  ATF_REQUIRE_EQ(escapeJsonString("\t"),  std::string("\\t"));
  ATF_REQUIRE_EQ(escapeJsonString(std::string("\x01", 1)),
                 std::string("\\u0001"));
  ATF_REQUIRE_EQ(escapeJsonString(std::string("\x1f", 1)),
                 std::string("\\u001f"));
}

ATF_TEST_CASE_WITHOUT_HEAD(escape_passthrough_utf8);
ATF_TEST_CASE_BODY(escape_passthrough_utf8) {
  // "Олексій" in UTF-8 — high bytes must pass through unchanged
  // (RFC 8259 allows non-ASCII to be raw or \u-escaped; raw is fine).
  std::string ukr = "Олексій";
  ATF_REQUIRE_EQ(escapeJsonString(ukr), ukr);
}

// --- renderJson ---

ATF_TEST_CASE_WITHOUT_HEAD(render_minimal_shape);
ATF_TEST_CASE_BODY(render_minimal_shape) {
  InspectData d;
  d.name = "myjail";
  d.jid  = 7;
  d.hostname = "myjail.local";
  d.path = "/jails/myjail";
  d.osrelease = "14.2-RELEASE";
  d.startedAt = 1730000000;
  d.inspectedAt = 1730000123;
  auto j = renderJson(d);

  // Stable key presence + values.
  ATF_REQUIRE(j.find("\"name\": \"myjail\"")          != std::string::npos);
  ATF_REQUIRE(j.find("\"jid\": 7")                    != std::string::npos);
  ATF_REQUIRE(j.find("\"hostname\": \"myjail.local\"") != std::string::npos);
  ATF_REQUIRE(j.find("\"path\": \"/jails/myjail\"")    != std::string::npos);
  ATF_REQUIRE(j.find("\"osrelease\": \"14.2-RELEASE\"") != std::string::npos);
  ATF_REQUIRE(j.find("\"started_at\": 1730000000")     != std::string::npos);
  ATF_REQUIRE(j.find("\"inspected_at\": 1730000123")   != std::string::npos);

  // Empty containers serialised consistently.
  ATF_REQUIRE(j.find("\"jail_params\": {}")  != std::string::npos);
  ATF_REQUIRE(j.find("\"interfaces\": []")   != std::string::npos);
  ATF_REQUIRE(j.find("\"mounts\": []")       != std::string::npos);
  ATF_REQUIRE(j.find("\"rctl_usage\": {}")   != std::string::npos);

  // Trailing newline.
  ATF_REQUIRE(!j.empty());
  ATF_REQUIRE_EQ(j.back(), '\n');
  // Outer braces.
  ATF_REQUIRE(j.front() == '{');
  // Document is multi-line (we pretty-print).
  size_t lines = 0;
  for (char c : j) if (c == '\n') lines++;
  ATF_REQUIRE(lines > 5);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_jail_params_sorted);
ATF_TEST_CASE_BODY(render_jail_params_sorted) {
  InspectData d;
  d.name = "j";
  d.jailParams["securelevel"]   = "2";
  d.jailParams["allow.nullfs"]  = "1";
  d.jailParams["allow.mount"]   = "1";
  auto j = renderJson(d);
  // std::map ordering is alphabetical → allow.mount, allow.nullfs, securelevel.
  auto am = j.find("\"allow.mount\"");
  auto an = j.find("\"allow.nullfs\"");
  auto sl = j.find("\"securelevel\"");
  ATF_REQUIRE(am < an);
  ATF_REQUIRE(an < sl);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_interfaces_array);
ATF_TEST_CASE_BODY(render_interfaces_array) {
  InspectData d;
  d.name = "j";
  Interface eth;
  eth.name = "epair0b";
  eth.ip4 = "10.0.0.5";
  eth.ip6 = "fd00::5";
  eth.mac = "58:9c:fc:00:00:01";
  d.interfaces.push_back(eth);
  auto j = renderJson(d);
  ATF_REQUIRE(j.find("\"name\": \"epair0b\"")        != std::string::npos);
  ATF_REQUIRE(j.find("\"ip4\": \"10.0.0.5\"")        != std::string::npos);
  ATF_REQUIRE(j.find("\"ip6\": \"fd00::5\"")         != std::string::npos);
  ATF_REQUIRE(j.find("\"mac\": \"58:9c:fc:00:00:01\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_mounts_array);
ATF_TEST_CASE_BODY(render_mounts_array) {
  InspectData d;
  d.name = "j";
  Mount m;
  m.source = "tmpfs"; m.target = "/jails/j/tmp"; m.fstype = "tmpfs";
  d.mounts.push_back(m);
  auto j = renderJson(d);
  ATF_REQUIRE(j.find("\"source\": \"tmpfs\"")          != std::string::npos);
  ATF_REQUIRE(j.find("\"target\": \"/jails/j/tmp\"")   != std::string::npos);
  ATF_REQUIRE(j.find("\"fstype\": \"tmpfs\"")          != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_gui_fields);
ATF_TEST_CASE_BODY(render_gui_fields) {
  InspectData d;
  d.name = "j";
  d.hasGui = true;
  d.guiDisplay = 100;
  d.guiVncPort = 5900;
  d.guiWsPort  = 6080;
  d.guiMode    = "nested";
  auto j = renderJson(d);
  ATF_REQUIRE(j.find("\"has_gui\": true")     != std::string::npos);
  ATF_REQUIRE(j.find("\"gui_display\": 100")  != std::string::npos);
  ATF_REQUIRE(j.find("\"gui_vnc_port\": 5900") != std::string::npos);
  ATF_REQUIRE(j.find("\"gui_mode\": \"nested\"") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(render_escapes_special_chars);
ATF_TEST_CASE_BODY(render_escapes_special_chars) {
  InspectData d;
  d.name = "weird\"name\\with\nnewline";
  auto j = renderJson(d);
  ATF_REQUIRE(j.find("\"name\": \"weird\\\"name\\\\with\\nnewline\"")
              != std::string::npos);
}

// --- applyRctlOutput ---

ATF_TEST_CASE_WITHOUT_HEAD(applyRctl_typical_output);
ATF_TEST_CASE_BODY(applyRctl_typical_output) {
  InspectData d;
  applyRctlOutput(
    "cputime=120\n"
    "memoryuse=12345678\n"
    "writebps=999\n",
    d);
  ATF_REQUIRE_EQ(d.rctlUsage["cputime"],   std::string("120"));
  ATF_REQUIRE_EQ(d.rctlUsage["memoryuse"], std::string("12345678"));
  ATF_REQUIRE_EQ(d.rctlUsage["writebps"],  std::string("999"));
  ATF_REQUIRE_EQ(d.rctlUsage.size(), (size_t)3);
}

ATF_TEST_CASE_WITHOUT_HEAD(applyRctl_tolerates_blank_and_malformed);
ATF_TEST_CASE_BODY(applyRctl_tolerates_blank_and_malformed) {
  InspectData d;
  applyRctlOutput(
    "\n"
    "memoryuse=42\n"
    "garbage line\n"
    "\n"
    "cputime=7\n",
    d);
  ATF_REQUIRE_EQ(d.rctlUsage.size(), (size_t)2);
  ATF_REQUIRE_EQ(d.rctlUsage["memoryuse"], std::string("42"));
  ATF_REQUIRE_EQ(d.rctlUsage["cputime"],   std::string("7"));
}

ATF_TEST_CASE_WITHOUT_HEAD(applyRctl_empty_input);
ATF_TEST_CASE_BODY(applyRctl_empty_input) {
  InspectData d;
  applyRctlOutput("", d);
  ATF_REQUIRE(d.rctlUsage.empty());
}

// --- applyMountOutput ---

ATF_TEST_CASE_WITHOUT_HEAD(applyMount_filters_to_jail_subtree);
ATF_TEST_CASE_BODY(applyMount_filters_to_jail_subtree) {
  InspectData d;
  std::string out =
    "/dev/ada0p2 on / (ufs, local)\n"
    "devfs on /dev (devfs)\n"
    "tmpfs on /jails/myjail/tmp (tmpfs, local)\n"
    "/data on /jails/myjail/data (nullfs, local)\n"
    "/dev/ada1 on /home (ufs, local)\n";
  applyMountOutput(out, "/jails/myjail", d);
  // Only entries under /jails/myjail/ should land.
  ATF_REQUIRE_EQ(d.mounts.size(), (size_t)2);
  ATF_REQUIRE_EQ(d.mounts[0].target, std::string("/jails/myjail/tmp"));
  ATF_REQUIRE_EQ(d.mounts[0].fstype, std::string("tmpfs"));
  ATF_REQUIRE_EQ(d.mounts[1].target, std::string("/jails/myjail/data"));
  ATF_REQUIRE_EQ(d.mounts[1].fstype, std::string("nullfs"));
}

ATF_TEST_CASE_WITHOUT_HEAD(applyMount_includes_jail_root_itself);
ATF_TEST_CASE_BODY(applyMount_includes_jail_root_itself) {
  InspectData d;
  std::string out = "pool/jails/myjail on /jails/myjail (zfs, local)\n";
  applyMountOutput(out, "/jails/myjail", d);
  ATF_REQUIRE_EQ(d.mounts.size(), (size_t)1);
  ATF_REQUIRE_EQ(d.mounts[0].source, std::string("pool/jails/myjail"));
  ATF_REQUIRE_EQ(d.mounts[0].target, std::string("/jails/myjail"));
}

ATF_TEST_CASE_WITHOUT_HEAD(applyMount_skips_path_prefix_collisions);
ATF_TEST_CASE_BODY(applyMount_skips_path_prefix_collisions) {
  // /jails/myjail-other must NOT match /jails/myjail/* even though the
  // string compare-prefix would otherwise succeed without the trailing
  // slash sentinel.
  InspectData d;
  std::string out =
    "/dev/ada0 on /jails/myjail-other/data (ufs, local)\n"
    "tmpfs on /jails/myjail/tmp (tmpfs, local)\n";
  applyMountOutput(out, "/jails/myjail", d);
  ATF_REQUIRE_EQ(d.mounts.size(), (size_t)1);
  ATF_REQUIRE_EQ(d.mounts[0].target, std::string("/jails/myjail/tmp"));
}

ATF_TEST_CASE_WITHOUT_HEAD(applyMount_tolerates_malformed_lines);
ATF_TEST_CASE_BODY(applyMount_tolerates_malformed_lines) {
  InspectData d;
  std::string out =
    "garbage\n"
    "tmpfs on /jails/j/tmp (tmpfs)\n"
    "no parens here\n"
    "broken on (no close\n";
  applyMountOutput(out, "/jails/j", d);
  ATF_REQUIRE_EQ(d.mounts.size(), (size_t)1);
  ATF_REQUIRE_EQ(d.mounts[0].fstype, std::string("tmpfs"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, escape_passthrough_ascii);
  ATF_ADD_TEST_CASE(tcs, escape_quote_and_backslash);
  ATF_ADD_TEST_CASE(tcs, escape_control_chars);
  ATF_ADD_TEST_CASE(tcs, escape_passthrough_utf8);
  ATF_ADD_TEST_CASE(tcs, render_minimal_shape);
  ATF_ADD_TEST_CASE(tcs, render_jail_params_sorted);
  ATF_ADD_TEST_CASE(tcs, render_interfaces_array);
  ATF_ADD_TEST_CASE(tcs, render_mounts_array);
  ATF_ADD_TEST_CASE(tcs, render_gui_fields);
  ATF_ADD_TEST_CASE(tcs, render_escapes_special_chars);
  ATF_ADD_TEST_CASE(tcs, applyRctl_typical_output);
  ATF_ADD_TEST_CASE(tcs, applyRctl_tolerates_blank_and_malformed);
  ATF_ADD_TEST_CASE(tcs, applyRctl_empty_input);
  ATF_ADD_TEST_CASE(tcs, applyMount_filters_to_jail_subtree);
  ATF_ADD_TEST_CASE(tcs, applyMount_includes_jail_root_itself);
  ATF_ADD_TEST_CASE(tcs, applyMount_skips_path_prefix_collisions);
  ATF_ADD_TEST_CASE(tcs, applyMount_tolerates_malformed_lines);
}
