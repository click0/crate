// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "warm_pure.h"

#include <atf-c++.hpp>

#include <string>

using WarmPure::buildCloneArgv;
using WarmPure::buildPromoteArgv;
using WarmPure::buildSnapshotArgv;
using WarmPure::fullSnapshotName;
using WarmPure::validateJailName;
using WarmPure::validateSnapshotSuffix;
using WarmPure::validateTemplateDataset;
using WarmPure::warmRunCloneName;
using WarmPure::warmRunSnapshotSuffix;
using WarmPure::warmSnapshotSuffix;

// --- validateTemplateDataset ---

ATF_TEST_CASE_WITHOUT_HEAD(template_dataset_typical);
ATF_TEST_CASE_BODY(template_dataset_typical) {
  ATF_REQUIRE_EQ(validateTemplateDataset("tank/templates/firefox-warm"),
                 std::string());
  ATF_REQUIRE_EQ(validateTemplateDataset("a"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(template_dataset_invalid);
ATF_TEST_CASE_BODY(template_dataset_invalid) {
  ATF_REQUIRE(!validateTemplateDataset("").empty());
  ATF_REQUIRE(!validateTemplateDataset("/tank/templates").empty());
  ATF_REQUIRE(!validateTemplateDataset("tank/templates/").empty());
  ATF_REQUIRE(!validateTemplateDataset("tank//templates").empty());
  ATF_REQUIRE(!validateTemplateDataset("tank/../etc").empty());
  ATF_REQUIRE(!validateTemplateDataset("tank/./templates").empty());
  ATF_REQUIRE(!validateTemplateDataset("tank;rm/templates").empty());
  // ZFS namespace `:` is reserved for snapshots/bookmarks; reject.
  ATF_REQUIRE(!validateTemplateDataset("tank/templates:warm").empty());
}

// --- validateSnapshotSuffix ---

ATF_TEST_CASE_WITHOUT_HEAD(suffix_typical);
ATF_TEST_CASE_BODY(suffix_typical) {
  ATF_REQUIRE_EQ(validateSnapshotSuffix("warm-2026-05-04T12:00:00Z"),
                 std::string());
  ATF_REQUIRE_EQ(validateSnapshotSuffix("manual-baseline"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(suffix_invalid);
ATF_TEST_CASE_BODY(suffix_invalid) {
  ATF_REQUIRE(!validateSnapshotSuffix("").empty());
  ATF_REQUIRE(!validateSnapshotSuffix(std::string(65, 'a')).empty());
  // Embedded '@' / '/' would let an attacker reach into another
  // dataset via the constructed snapshot name.
  ATF_REQUIRE(!validateSnapshotSuffix("foo@bar").empty());
  ATF_REQUIRE(!validateSnapshotSuffix("foo/bar").empty());
  // Shell metacharacter sneak-in (we feed the result to `zfs
  // snapshot` argv unquoted on the local side — the `;` would
  // not actually escape Util::execCommand's argv-style call, but
  // the validation is the documented contract).
  ATF_REQUIRE(!validateSnapshotSuffix("foo;rm").empty());
}

// --- warmSnapshotSuffix ---

ATF_TEST_CASE_WITHOUT_HEAD(suffix_canonical_epochs);
ATF_TEST_CASE_BODY(suffix_canonical_epochs) {
  ATF_REQUIRE_EQ(warmSnapshotSuffix(0),
                 std::string("warm-1970-01-01T00:00:00Z"));
  ATF_REQUIRE_EQ(warmSnapshotSuffix(946684800),
                 std::string("warm-2000-01-01T00:00:00Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(suffix_lex_sort_matches_chrono);
ATF_TEST_CASE_BODY(suffix_lex_sort_matches_chrono) {
  // Same property the backup module relies on for retention
  // pruning — without it `ls -1 | sort | head -n -N` would
  // delete the wrong snapshots.
  ATF_REQUIRE(warmSnapshotSuffix(1000000000) < warmSnapshotSuffix(2000000000));
  ATF_REQUIRE(warmSnapshotSuffix(0)          < warmSnapshotSuffix(1));
}

// --- fullSnapshotName ---

ATF_TEST_CASE_WITHOUT_HEAD(full_snapshot_name_shape);
ATF_TEST_CASE_BODY(full_snapshot_name_shape) {
  ATF_REQUIRE_EQ(
    fullSnapshotName("tank/jails/firefox", "warm-X"),
    std::string("tank/jails/firefox@warm-X"));
}

// --- argv builders ---

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_argv_shape);
ATF_TEST_CASE_BODY(snapshot_argv_shape) {
  auto v = buildSnapshotArgv("tank/jails/firefox", "warm-NOW");
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[0], std::string("/sbin/zfs"));
  ATF_REQUIRE_EQ(v[1], std::string("snapshot"));
  ATF_REQUIRE_EQ(v[2], std::string("tank/jails/firefox@warm-NOW"));
}

ATF_TEST_CASE_WITHOUT_HEAD(clone_argv_shape);
ATF_TEST_CASE_BODY(clone_argv_shape) {
  auto v = buildCloneArgv("tank/jails/firefox", "warm-NOW",
                          "tank/templates/firefox-warm");
  ATF_REQUIRE_EQ(v.size(), (size_t)4);
  ATF_REQUIRE_EQ(v[1], std::string("clone"));
  ATF_REQUIRE_EQ(v[2], std::string("tank/jails/firefox@warm-NOW"));
  ATF_REQUIRE_EQ(v[3], std::string("tank/templates/firefox-warm"));
}

ATF_TEST_CASE_WITHOUT_HEAD(promote_argv_shape);
ATF_TEST_CASE_BODY(promote_argv_shape) {
  auto v = buildPromoteArgv("tank/templates/firefox-warm");
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[1], std::string("promote"));
  ATF_REQUIRE_EQ(v[2], std::string("tank/templates/firefox-warm"));
}

// --- Warm-base consumer-side helpers (0.7.9) ---

ATF_TEST_CASE_WITHOUT_HEAD(warm_base_jail_name_typical);
ATF_TEST_CASE_BODY(warm_base_jail_name_typical) {
  ATF_REQUIRE_EQ(validateJailName("firefox"),         std::string());
  ATF_REQUIRE_EQ(validateJailName("dev-postgres"),    std::string());
  ATF_REQUIRE_EQ(validateJailName("worker.1"),        std::string());
  ATF_REQUIRE_EQ(validateJailName("a"),               std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(warm_base_jail_name_invalid);
ATF_TEST_CASE_BODY(warm_base_jail_name_invalid) {
  ATF_REQUIRE(!validateJailName("").empty());
  ATF_REQUIRE(!validateJailName(".").empty());        // reserved
  ATF_REQUIRE(!validateJailName("..").empty());       // reserved
  ATF_REQUIRE(!validateJailName("foo/bar").empty());  // path separator
  ATF_REQUIRE(!validateJailName("foo bar").empty());  // space
  ATF_REQUIRE(!validateJailName("foo;rm").empty());   // shell meta
  ATF_REQUIRE(!validateJailName("foo`pwd`").empty()); // backtick
  ATF_REQUIRE(!validateJailName(std::string(65, 'a')).empty());  // > 64 chars
}

ATF_TEST_CASE_WITHOUT_HEAD(warm_run_suffix_distinct_from_template_suffix);
ATF_TEST_CASE_BODY(warm_run_suffix_distinct_from_template_suffix) {
  // Property: warmrun-* vs warm-* — different prefixes so operators
  // can prune one without affecting the other.
  auto runSuf  = warmRunSnapshotSuffix(1767225600L);   // 2026-01-01
  auto tmplSuf = warmSnapshotSuffix(1767225600L);
  ATF_REQUIRE(runSuf.find("warmrun-") == 0);
  ATF_REQUIRE(tmplSuf.find("warm-")   == 0);
  ATF_REQUIRE(tmplSuf.find("warmrun-") == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(warm_run_suffix_canonical_epochs);
ATF_TEST_CASE_BODY(warm_run_suffix_canonical_epochs) {
  // 2026-05-04T12:00:00Z = 1777896000
  ATF_REQUIRE_EQ(warmRunSnapshotSuffix(1777896000L),
                 std::string("warmrun-2026-05-04T12:00:00Z"));
  // 1970-01-01T00:00:00Z = 0
  ATF_REQUIRE_EQ(warmRunSnapshotSuffix(0L),
                 std::string("warmrun-1970-01-01T00:00:00Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(warm_run_suffix_lex_sort_matches_chrono);
ATF_TEST_CASE_BODY(warm_run_suffix_lex_sort_matches_chrono) {
  // Cron-friendly retention property: lexicographic order = chronological.
  auto a = warmRunSnapshotSuffix(1767225600L);   // 2026-01-01
  auto b = warmRunSnapshotSuffix(1798761600L);   // 2027-01-01
  auto c = warmRunSnapshotSuffix(4102444800L);   // 2100-01-01
  ATF_REQUIRE(a < b);
  ATF_REQUIRE(b < c);
}

ATF_TEST_CASE_WITHOUT_HEAD(warm_run_clone_name_shape);
ATF_TEST_CASE_BODY(warm_run_clone_name_shape) {
  // Same naming convention as Locations::jailDirectoryPath/jail-<name>-<hex>:
  // the parent dataset's mountpoint covers the whole path, so the
  // clone's mountpoint inheritance lands the rootfs at the expected
  // jail directory automatically.
  ATF_REQUIRE_EQ(warmRunCloneName("tank/jails", "firefox", "abcd"),
                 std::string("tank/jails/jail-firefox-abcd"));
  ATF_REQUIRE_EQ(warmRunCloneName("zroot/crate", "dev-postgres", "1234"),
                 std::string("zroot/crate/jail-dev-postgres-1234"));
  // Empty parent is a runtime input we don't sanitize here — caller's
  // responsibility (it comes from getZfsDataset, not user input).
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, template_dataset_typical);
  ATF_ADD_TEST_CASE(tcs, template_dataset_invalid);
  ATF_ADD_TEST_CASE(tcs, suffix_typical);
  ATF_ADD_TEST_CASE(tcs, suffix_invalid);
  ATF_ADD_TEST_CASE(tcs, suffix_canonical_epochs);
  ATF_ADD_TEST_CASE(tcs, suffix_lex_sort_matches_chrono);
  ATF_ADD_TEST_CASE(tcs, full_snapshot_name_shape);
  ATF_ADD_TEST_CASE(tcs, snapshot_argv_shape);
  ATF_ADD_TEST_CASE(tcs, clone_argv_shape);
  ATF_ADD_TEST_CASE(tcs, promote_argv_shape);
  ATF_ADD_TEST_CASE(tcs, warm_base_jail_name_typical);
  ATF_ADD_TEST_CASE(tcs, warm_base_jail_name_invalid);
  ATF_ADD_TEST_CASE(tcs, warm_run_suffix_distinct_from_template_suffix);
  ATF_ADD_TEST_CASE(tcs, warm_run_suffix_canonical_epochs);
  ATF_ADD_TEST_CASE(tcs, warm_run_suffix_lex_sort_matches_chrono);
  ATF_ADD_TEST_CASE(tcs, warm_run_clone_name_shape);
}
