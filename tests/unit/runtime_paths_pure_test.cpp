// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "runtime_paths_pure.h"

#include <atf-c++.hpp>

#include <climits>
#include <string>

using namespace RuntimePathsPure;

ATF_TEST_CASE_WITHOUT_HEAD(legacy_root_is_var_run_crate);
ATF_TEST_CASE_BODY(legacy_root_is_var_run_crate) {
  // The legacy single-tenant root path is the stable contract every
  // pre-0.9.x deployment relies on. Lock it down so a future refactor
  // doesn't silently move /var/run/crate/ -> /run/crate/ (which would
  // invalidate every operator's paths in their scripts and rc files).
  ATF_REQUIRE_EQ(legacyRoot(), std::string("/var/run/crate"));
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_root_format);
ATF_TEST_CASE_BODY(per_user_root_format) {
  ATF_REQUIRE_EQ(perUserRoot(0), std::string("/var/run/crate/0"));
  ATF_REQUIRE_EQ(perUserRoot(1000), std::string("/var/run/crate/1000"));
  ATF_REQUIRE_EQ(perUserRoot(65534), std::string("/var/run/crate/65534"));
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_root_root_uid_does_not_alias_legacy);
ATF_TEST_CASE_BODY(per_user_root_root_uid_does_not_alias_legacy) {
  // uid 0 (root) intentionally gets its own subtree; we don't fold
  // it back to the legacy /var/run/crate. The legacy root is the
  // pre-0.9.x compat surface, NOT root's per-user tree.
  ATF_REQUIRE(perUserRoot(0) != legacyRoot());
  ATF_REQUIRE_EQ(perUserRoot(0), legacyRoot() + "/0");
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_subdirs);
ATF_TEST_CASE_BODY(per_user_subdirs) {
  ATF_REQUIRE_EQ(perUserLeasesDir(1000),  std::string("/var/run/crate/1000/leases"));
  ATF_REQUIRE_EQ(perUserExportsDir(1000), std::string("/var/run/crate/1000/exports"));
  ATF_REQUIRE_EQ(perUserImportsDir(1000), std::string("/var/run/crate/1000/imports"));
  ATF_REQUIRE_EQ(perUserAuditLog(1000),   std::string("/var/run/crate/1000/audit.log"));
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_lease_file);
ATF_TEST_CASE_BODY(per_user_lease_file) {
  ATF_REQUIRE_EQ(perUserLeaseFile(1000, "alpine"),
                 std::string("/var/run/crate/1000/leases/alpine.lease"));
  ATF_REQUIRE_EQ(perUserLeaseFile(1000, "dev-01"),
                 std::string("/var/run/crate/1000/leases/dev-01.lease"));
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_lease_file_isolation);
ATF_TEST_CASE_BODY(per_user_lease_file_isolation) {
  // alice (uid 1000) and bob (uid 1001) get disjoint lease paths
  // even for the SAME jail name. This is the security invariant
  // that lets multi-tenant operators run identically-named jails.
  std::string alice = perUserLeaseFile(1000, "web");
  std::string bob   = perUserLeaseFile(1001, "web");
  ATF_REQUIRE(alice != bob);
  // Neither should be a prefix of the other (would let alice
  // probe bob's path via path-traversal-like writes).
  ATF_REQUIRE(alice.find(bob) == std::string::npos);
  ATF_REQUIRE(bob.find(alice) == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_uid_accepts_typical);
ATF_TEST_CASE_BODY(validate_uid_accepts_typical) {
  ATF_REQUIRE_EQ(validateUid(0), std::string());
  ATF_REQUIRE_EQ(validateUid(1000), std::string());
  ATF_REQUIRE_EQ(validateUid(65534), std::string());
  ATF_REQUIRE_EQ(validateUid((int64_t)INT32_MAX), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_uid_rejects_negative);
ATF_TEST_CASE_BODY(validate_uid_rejects_negative) {
  ATF_REQUIRE(!validateUid(-1).empty());
  ATF_REQUIRE(!validateUid(-1000).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(validate_uid_rejects_too_big);
ATF_TEST_CASE_BODY(validate_uid_rejects_too_big) {
  ATF_REQUIRE(!validateUid((int64_t)INT32_MAX + 1).empty());
  ATF_REQUIRE(!validateUid((int64_t)1ULL << 40).empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_paths_no_traversal_segments);
ATF_TEST_CASE_BODY(per_user_paths_no_traversal_segments) {
  // Defence in depth: nothing the per-user path builders produce
  // should contain `..` or doubled slashes. uids are integers so
  // injecting a traversal segment isn't possible from this entry,
  // but the assertion catches a future bug where someone adds a
  // string-based suffix.
  std::string p = perUserLeaseFile(1000, "alpine");
  ATF_REQUIRE(p.find("..") == std::string::npos);
  ATF_REQUIRE(p.find("//") == std::string::npos);
  // 1.1.41: crate(1)'s own audit fallback sits next to the daemon's
  // audit.log, under the same per-user root, with a distinct name.
  ATF_REQUIRE_EQ(perUserCrateAuditLog(1000), std::string("/var/run/crate/1000/crate-audit.log"));
  ATF_REQUIRE(perUserCrateAuditLog(1000) != perUserAuditLog(1000));
}

// --- 1.1.39: crate jail path recognition (legacy + per-user layouts) ---

ATF_TEST_CASE_WITHOUT_HEAD(crate_jail_path_both_layouts);
ATF_TEST_CASE_BODY(crate_jail_path_both_layouts) {
  // legacy / root
  ATF_REQUIRE(isCrateJailPath("/var/run/crate/jail-web-1a2b"));
  ATF_REQUIRE_EQ(crateJailDirName("/var/run/crate/jail-web-1a2b"), std::string("jail-web-1a2b"));
  // rootless per-user
  ATF_REQUIRE(isCrateJailPath("/var/run/crate/1000/jail-web-1a2b"));
  ATF_REQUIRE_EQ(crateJailDirName("/var/run/crate/1000/jail-web-1a2b"), std::string("jail-web-1a2b"));
  ATF_REQUIRE(isCrateJailPath(perUserRoot(65534) + "/jail-x-0"));
  // names may contain dots and dashes
  ATF_REQUIRE_EQ(crateJailDirName("/var/run/crate/jail-my.app-2-ffff"), std::string("jail-my.app-2-ffff"));
}

ATF_TEST_CASE_WITHOUT_HEAD(crate_jail_path_rejects_others);
ATF_TEST_CASE_BODY(crate_jail_path_rejects_others) {
  const char *bad[] = {
    "",
    "/var/run/crate",
    "/var/run/crate/",
    "/var/run/crate/jail-",                    // empty name
    "/var/run/crate/1000",                     // the per-user root itself
    "/var/run/crate/1000/leases",              // a per-user subdir, not a jail
    "/var/run/crate/alice/jail-web-1",         // non-numeric uid segment
    "/var/run/crate/1000/x/jail-web-1",        // too deep
    "/var/run/crate/jail-web-1/etc",           // inside a jail, not its root
    "/var/run/crate/chroot-create-web-1",      // create scratch dir
    "/var/run/cratex/jail-web-1",              // prefix lookalike
    "/zroot/jails/jail-web-1",
  };
  for (const char *p : bad)
    if (isCrateJailPath(p))
      ATF_FAIL(std::string("accepted: ") + p);
  ATF_REQUIRE_EQ(crateJailDirName("/var/run/crate/1000/leases"), std::string());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, crate_jail_path_both_layouts);
  ATF_ADD_TEST_CASE(tcs, crate_jail_path_rejects_others);
  ATF_ADD_TEST_CASE(tcs, legacy_root_is_var_run_crate);
  ATF_ADD_TEST_CASE(tcs, per_user_root_format);
  ATF_ADD_TEST_CASE(tcs, per_user_root_root_uid_does_not_alias_legacy);
  ATF_ADD_TEST_CASE(tcs, per_user_subdirs);
  ATF_ADD_TEST_CASE(tcs, per_user_lease_file);
  ATF_ADD_TEST_CASE(tcs, per_user_lease_file_isolation);
  ATF_ADD_TEST_CASE(tcs, validate_uid_accepts_typical);
  ATF_ADD_TEST_CASE(tcs, validate_uid_rejects_negative);
  ATF_ADD_TEST_CASE(tcs, validate_uid_rejects_too_big);
  ATF_ADD_TEST_CASE(tcs, per_user_paths_no_traversal_segments);
}
