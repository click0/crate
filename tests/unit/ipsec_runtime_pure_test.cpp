// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "ipsec_runtime_pure.h"

#include <atf-c++.hpp>

#include <string>
#include <vector>

using IpsecRuntimePure::buildAddArgv;
using IpsecRuntimePure::buildDeleteArgv;
using IpsecRuntimePure::buildDownArgv;
using IpsecRuntimePure::buildUpArgv;
using IpsecRuntimePure::isEnabled;
using IpsecRuntimePure::validateConnName;

// ----------------------------------------------------------------------
// Conn-name validator
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(conn_typical);
ATF_TEST_CASE_BODY(conn_typical) {
  ATF_REQUIRE_EQ(validateConnName("tunnel-1"),       std::string());
  ATF_REQUIRE_EQ(validateConnName("alpha_to_beta"),  std::string());
  ATF_REQUIRE_EQ(validateConnName("v6.gw"),          std::string());
  ATF_REQUIRE_EQ(validateConnName("a"),              std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(conn_invalid);
ATF_TEST_CASE_BODY(conn_invalid) {
  ATF_REQUIRE(!validateConnName("").empty());
  ATF_REQUIRE(!validateConnName(std::string(33, 'a')).empty());  // > 32
  ATF_REQUIRE(!validateConnName("%default").empty());            // strongSwan reserved
  ATF_REQUIRE(!validateConnName("bad name").empty());            // space
  ATF_REQUIRE(!validateConnName("bad/name").empty());            // slash
  ATF_REQUIRE(!validateConnName("bad;rm").empty());              // shell meta
  ATF_REQUIRE(!validateConnName("bad`pwd`").empty());            // backtick
}

// ----------------------------------------------------------------------
// argv builders
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(add_argv_shape);
ATF_TEST_CASE_BODY(add_argv_shape) {
  auto v = buildAddArgv("my-tunnel");
  ATF_REQUIRE_EQ(v.size(), (size_t)4);
  ATF_REQUIRE_EQ(v[0], std::string("/usr/local/sbin/ipsec"));
  ATF_REQUIRE_EQ(v[1], std::string("auto"));
  ATF_REQUIRE_EQ(v[2], std::string("--add"));
  ATF_REQUIRE_EQ(v[3], std::string("my-tunnel"));
}

ATF_TEST_CASE_WITHOUT_HEAD(up_down_delete_argv_verbs);
ATF_TEST_CASE_BODY(up_down_delete_argv_verbs) {
  // Each verb produces an argv where index [2] is the verb and
  // [3] is the conn name. Pin the contract so a future re-format
  // doesn't accidentally swap or drop a verb.
  ATF_REQUIRE_EQ(buildUpArgv("foo")[2],     std::string("--up"));
  ATF_REQUIRE_EQ(buildUpArgv("foo")[3],     std::string("foo"));
  ATF_REQUIRE_EQ(buildDownArgv("foo")[2],   std::string("--down"));
  ATF_REQUIRE_EQ(buildDownArgv("foo")[3],   std::string("foo"));
  ATF_REQUIRE_EQ(buildDeleteArgv("foo")[2], std::string("--delete"));
  ATF_REQUIRE_EQ(buildDeleteArgv("foo")[3], std::string("foo"));
}

ATF_TEST_CASE_WITHOUT_HEAD(absolute_ipsec_path);
ATF_TEST_CASE_BODY(absolute_ipsec_path) {
  // We deliberately use the absolute path on FreeBSD so the runtime
  // doesn't depend on $PATH (matches WireguardRuntimePure's
  // absolute /usr/local/bin/wg-quick policy).
  ATF_REQUIRE_EQ(buildAddArgv("x")[0],
                 std::string("/usr/local/sbin/ipsec"));
  ATF_REQUIRE_EQ(buildUpArgv("x")[0],
                 std::string("/usr/local/sbin/ipsec"));
  ATF_REQUIRE_EQ(buildDownArgv("x")[0],
                 std::string("/usr/local/sbin/ipsec"));
  ATF_REQUIRE_EQ(buildDeleteArgv("x")[0],
                 std::string("/usr/local/sbin/ipsec"));
}

// ----------------------------------------------------------------------
// isEnabled
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(enabled_predicate);
ATF_TEST_CASE_BODY(enabled_predicate) {
  ATF_REQUIRE(!isEnabled(""));
  ATF_REQUIRE( isEnabled("my-tunnel"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, conn_typical);
  ATF_ADD_TEST_CASE(tcs, conn_invalid);
  ATF_ADD_TEST_CASE(tcs, add_argv_shape);
  ATF_ADD_TEST_CASE(tcs, up_down_delete_argv_verbs);
  ATF_ADD_TEST_CASE(tcs, absolute_ipsec_path);
  ATF_ADD_TEST_CASE(tcs, enabled_predicate);
}
