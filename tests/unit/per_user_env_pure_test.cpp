// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "per_user_env_pure.h"

#include <atf-c++.hpp>

#include <climits>
#include <string>

using namespace PerUserEnvPure;

static Config defaultCfg() {
  Config c;
  c.zfsMasterPrefix       = "zroot/jails";
  c.pathMasterPrefix      = "/jails-tenants";
  c.networkMasterCidr4    = "10.0.0.0/8";   // 1.1.18: /8 so uid 1000 fits the slot space
  c.networkSubPrefixLen4  = 24;
  c.networkMasterCidr6    = "fd00:dead::/48";
  c.networkSubPrefixLen6  = 64;
  return c;
}

ATF_TEST_CASE_WITHOUT_HEAD(compose_full_config);
ATF_TEST_CASE_BODY(compose_full_config) {
  auto r = composeForUid(defaultCfg(), 1000);
  ATF_REQUIRE_EQ(r.error, std::string());
  ATF_REQUIRE_EQ(r.env.uid, 1000u);
  // Runtime paths
  ATF_REQUIRE_EQ(r.env.runtimeRoot, std::string("/var/run/crate/1000"));
  ATF_REQUIRE_EQ(r.env.leasesDir,   std::string("/var/run/crate/1000/leases"));
  ATF_REQUIRE_EQ(r.env.exportsDir,  std::string("/var/run/crate/1000/exports"));
  ATF_REQUIRE_EQ(r.env.importsDir,  std::string("/var/run/crate/1000/imports"));
  ATF_REQUIRE_EQ(r.env.auditLog,    std::string("/var/run/crate/1000/audit.log"));
  // ZFS
  ATF_REQUIRE_EQ(r.env.zfsPrefix,   std::string("zroot/jails/1000"));
  // 1.1.15: jail path prefix
  ATF_REQUIRE_EQ(r.env.pathPrefix,       std::string("/jails-tenants/1000"));
  ATF_REQUIRE_EQ(r.env.pathMasterPrefix, std::string("/jails-tenants"));   // 1.1.17
  // Network
  ATF_REQUIRE_EQ(r.env.ipv4SubCidr, std::string("10.3.232.0/24"));   // /8+/24, uid 1000
  ATF_REQUIRE_EQ(r.env.ipv6SubCidr,
                 std::string("fd00:dead:0:3e8:0:0:0:0/64"));
  // RCTL
  ATF_REQUIRE_EQ(r.env.loginclass,        std::string("crate-1000"));
  ATF_REQUIRE_EQ(r.env.loginclassSubject, std::string("loginclass:crate-1000"));
}

ATF_TEST_CASE_WITHOUT_HEAD(compose_empty_config_legacy_shape);
ATF_TEST_CASE_BODY(compose_empty_config_legacy_shape) {
  // All-empty config: paths + RCTL still populate (always-on),
  // but ZFS prefix and CIDRs are empty (operator opted out per
  // category).
  Config c;
  auto r = composeForUid(c, 1000);
  ATF_REQUIRE_EQ(r.error, std::string());
  ATF_REQUIRE_EQ(r.env.runtimeRoot, std::string("/var/run/crate/1000"));
  ATF_REQUIRE_EQ(r.env.loginclass,  std::string("crate-1000"));
  ATF_REQUIRE_EQ(r.env.zfsPrefix,   std::string());
  ATF_REQUIRE_EQ(r.env.pathPrefix,       std::string());   // 1.1.15: opt-in
  ATF_REQUIRE_EQ(r.env.pathMasterPrefix, std::string());   // 1.1.17: opt-in
  ATF_REQUIRE_EQ(r.env.ipv4SubCidr, std::string());
  ATF_REQUIRE_EQ(r.env.ipv6SubCidr, std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(path_prefix_strips_trailing_slash);
ATF_TEST_CASE_BODY(path_prefix_strips_trailing_slash) {
  // Operators may type "/jails/" or "/jails" — both compose the same.
  Config c;  c.pathMasterPrefix = "/jails/";
  auto r = composeForUid(c, 1000);
  ATF_REQUIRE_EQ(r.env.pathPrefix,       std::string("/jails/1000"));
  ATF_REQUIRE_EQ(r.env.pathMasterPrefix, std::string("/jails"));   // 1.1.17: slash stripped
}

ATF_TEST_CASE_WITHOUT_HEAD(path_prefix_with_different_uids);
ATF_TEST_CASE_BODY(path_prefix_with_different_uids) {
  Config c;  c.pathMasterPrefix = "/zpool/jails";
  ATF_REQUIRE_EQ(composeForUid(c, 1000).env.pathPrefix,
                 std::string("/zpool/jails/1000"));
  ATF_REQUIRE_EQ(composeForUid(c, 1001).env.pathPrefix,
                 std::string("/zpool/jails/1001"));
}

ATF_TEST_CASE_WITHOUT_HEAD(compose_v4_only);
ATF_TEST_CASE_BODY(compose_v4_only) {
  Config c;
  c.networkMasterCidr4   = "10.0.0.0/8";   // 1.1.18: /8 so uid 1000 fits
  c.networkSubPrefixLen4 = 24;
  // v6 left empty
  auto r = composeForUid(c, 1000);
  ATF_REQUIRE_EQ(r.error, std::string());
  ATF_REQUIRE(!r.env.ipv4SubCidr.empty());
  ATF_REQUIRE_EQ(r.env.ipv6SubCidr, std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(compose_isolation_alice_vs_bob);
ATF_TEST_CASE_BODY(compose_isolation_alice_vs_bob) {
  auto cfg = defaultCfg();
  auto alice = composeForUid(cfg, 1000);
  auto bob   = composeForUid(cfg, 1001);
  ATF_REQUIRE_EQ(alice.error, std::string());
  ATF_REQUIRE_EQ(bob.error, std::string());
  // Every field that varies by uid must differ.
  ATF_REQUIRE(alice.env.runtimeRoot       != bob.env.runtimeRoot);
  ATF_REQUIRE(alice.env.leasesDir         != bob.env.leasesDir);
  ATF_REQUIRE(alice.env.zfsPrefix         != bob.env.zfsPrefix);
  ATF_REQUIRE(alice.env.ipv4SubCidr       != bob.env.ipv4SubCidr);
  ATF_REQUIRE(alice.env.ipv6SubCidr       != bob.env.ipv6SubCidr);
  ATF_REQUIRE(alice.env.loginclass        != bob.env.loginclass);
  ATF_REQUIRE(alice.env.loginclassSubject != bob.env.loginclassSubject);
}

ATF_TEST_CASE_WITHOUT_HEAD(compose_rejects_bad_v4_master);
ATF_TEST_CASE_BODY(compose_rejects_bad_v4_master) {
  Config c;
  c.networkMasterCidr4 = "not a cidr";
  auto r = composeForUid(c, 1000);
  ATF_REQUIRE(!r.error.empty());
  // Field-prefix context preserved
  ATF_REQUIRE(r.error.find("ipv4:") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(compose_rejects_bad_v6_master);
ATF_TEST_CASE_BODY(compose_rejects_bad_v6_master) {
  Config c;
  c.networkMasterCidr6 = "ggg::/48";
  auto r = composeForUid(c, 1000);
  ATF_REQUIRE(!r.error.empty());
  ATF_REQUIRE(r.error.find("ipv6:") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(compose_rejects_bad_uid);
ATF_TEST_CASE_BODY(compose_rejects_bad_uid) {
  Config c;
  // uid larger than INT32_MAX cap from runtime_paths_pure
  // -> passing UINT32_MAX (which is > INT32_MAX) hits the validate path
  auto r = composeForUid(c, (uint32_t)UINT32_MAX);
  ATF_REQUIRE(!r.error.empty());
  ATF_REQUIRE(r.error.find("uid:") != std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(compose_rctl_always_populated);
ATF_TEST_CASE_BODY(compose_rctl_always_populated) {
  // Even with an entirely empty config, RCTL fields populate —
  // they're a property of the operator (their loginclass), not
  // a config knob.
  Config c;
  auto r = composeForUid(c, 0);
  ATF_REQUIRE_EQ(r.env.loginclass, std::string("crate-0"));
  ATF_REQUIRE_EQ(r.env.loginclassSubject,
                 std::string("loginclass:crate-0"));
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, compose_full_config);
  ATF_ADD_TEST_CASE(tcs, compose_empty_config_legacy_shape);
  ATF_ADD_TEST_CASE(tcs, path_prefix_strips_trailing_slash);
  ATF_ADD_TEST_CASE(tcs, path_prefix_with_different_uids);
  ATF_ADD_TEST_CASE(tcs, compose_v4_only);
  ATF_ADD_TEST_CASE(tcs, compose_isolation_alice_vs_bob);
  ATF_ADD_TEST_CASE(tcs, compose_rejects_bad_v4_master);
  ATF_ADD_TEST_CASE(tcs, compose_rejects_bad_v6_master);
  ATF_ADD_TEST_CASE(tcs, compose_rejects_bad_uid);
  ATF_ADD_TEST_CASE(tcs, compose_rctl_always_populated);
}
