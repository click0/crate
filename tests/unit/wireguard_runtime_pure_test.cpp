// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "wireguard_runtime_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using WireguardRuntimePure::buildDownArgv;
using WireguardRuntimePure::buildUpArgv;
using WireguardRuntimePure::isEnabled;
using WireguardRuntimePure::validateConfigPath;

// --- validateConfigPath ---

ATF_TEST_CASE_WITHOUT_HEAD(path_typical_accepted);
ATF_TEST_CASE_BODY(path_typical_accepted) {
  ATF_REQUIRE_EQ(validateConfigPath("/usr/local/etc/wireguard/wg0.conf"),
                 std::string());
  ATF_REQUIRE_EQ(validateConfigPath("/etc/wireguard/wg0.conf"),
                 std::string());
  ATF_REQUIRE_EQ(validateConfigPath("/var/lib/wg/tun-prod.conf"),
                 std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(path_empty_rejected);
ATF_TEST_CASE_BODY(path_empty_rejected) {
  ATF_REQUIRE(!validateConfigPath("").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(path_relative_rejected);
ATF_TEST_CASE_BODY(path_relative_rejected) {
  ATF_REQUIRE(!validateConfigPath("wg0.conf").empty());
  ATF_REQUIRE(!validateConfigPath("./wg0.conf").empty());
  ATF_REQUIRE(!validateConfigPath("etc/wg0.conf").empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(path_too_long_rejected);
ATF_TEST_CASE_BODY(path_too_long_rejected) {
  std::string at = "/" + std::string(254, 'a');   // 255 chars total
  ATF_REQUIRE_EQ(validateConfigPath(at), std::string());
  std::string over = "/" + std::string(255, 'a'); // 256 chars
  ATF_REQUIRE(!validateConfigPath(over).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(path_dotdot_segment_rejected);
ATF_TEST_CASE_BODY(path_dotdot_segment_rejected) {
  // `..` as an entire segment must be rejected.
  ATF_REQUIRE(!validateConfigPath("/etc/../etc/wg0.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/..").empty());
  ATF_REQUIRE(!validateConfigPath("/../wg0.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/..").empty());
  // BUT `..` inside a longer segment is fine (no traversal effect).
  ATF_REQUIRE_EQ(validateConfigPath("/etc/wg/foo..bar.conf"),
                 std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(path_metacharacters_rejected);
ATF_TEST_CASE_BODY(path_metacharacters_rejected) {
  ATF_REQUIRE(!validateConfigPath("/etc/wg/wg0;rm.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/`x`.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/$VAR.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/a|b.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/a&b.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/a<b.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/a>b.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/a\\b.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/a\nb.conf").empty());
  ATF_REQUIRE(!validateConfigPath("/etc/wg/a\rb.conf").empty());
}

// --- buildUpArgv / buildDownArgv ---

ATF_TEST_CASE_WITHOUT_HEAD(up_argv_shape);
ATF_TEST_CASE_BODY(up_argv_shape) {
  auto argv = buildUpArgv("/etc/wireguard/wg0.conf");
  ATF_REQUIRE_EQ(argv.size(), (size_t)3);
  ATF_REQUIRE_EQ(argv[0], std::string("/usr/local/bin/wg-quick"));
  ATF_REQUIRE_EQ(argv[1], std::string("up"));
  ATF_REQUIRE_EQ(argv[2], std::string("/etc/wireguard/wg0.conf"));
}

ATF_TEST_CASE_WITHOUT_HEAD(down_argv_shape);
ATF_TEST_CASE_BODY(down_argv_shape) {
  auto argv = buildDownArgv("/etc/wireguard/wg0.conf");
  ATF_REQUIRE_EQ(argv.size(), (size_t)3);
  ATF_REQUIRE_EQ(argv[0], std::string("/usr/local/bin/wg-quick"));
  ATF_REQUIRE_EQ(argv[1], std::string("down"));
  ATF_REQUIRE_EQ(argv[2], std::string("/etc/wireguard/wg0.conf"));
}

ATF_TEST_CASE_WITHOUT_HEAD(up_and_down_use_absolute_path_to_wg_quick);
ATF_TEST_CASE_BODY(up_and_down_use_absolute_path_to_wg_quick) {
  // Defense in depth: argv[0] must be an absolute path so the
  // runtime doesn't depend on PATH (which crate sanitises at
  // setuid-init time anyway).
  auto u = buildUpArgv("/x/y.conf");
  auto d = buildDownArgv("/x/y.conf");
  ATF_REQUIRE(!u.empty() && u[0].front() == '/');
  ATF_REQUIRE(!d.empty() && d[0].front() == '/');
  ATF_REQUIRE_EQ(u[0], d[0]);   // same binary
}

// --- isEnabled ---

ATF_TEST_CASE_WITHOUT_HEAD(enabled_predicate);
ATF_TEST_CASE_BODY(enabled_predicate) {
  ATF_REQUIRE(!isEnabled(""));
  ATF_REQUIRE(isEnabled("/etc/wg0.conf"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, path_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, path_empty_rejected);
  ATF_ADD_TEST_CASE(tcs, path_relative_rejected);
  ATF_ADD_TEST_CASE(tcs, path_too_long_rejected);
  ATF_ADD_TEST_CASE(tcs, path_dotdot_segment_rejected);
  ATF_ADD_TEST_CASE(tcs, path_metacharacters_rejected);
  ATF_ADD_TEST_CASE(tcs, up_argv_shape);
  ATF_ADD_TEST_CASE(tcs, down_argv_shape);
  ATF_ADD_TEST_CASE(tcs, up_and_down_use_absolute_path_to_wg_quick);
  ATF_ADD_TEST_CASE(tcs, enabled_predicate);
}
