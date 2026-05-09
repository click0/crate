// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "zfs_dataset_pure.h"

#include <atf-c++.hpp>

#include <string>

using ZfsDatasetPure::pickLatestBackupSuffix;
using ZfsDatasetPure::validateDatasetName;

// --- pickLatestBackupSuffix ---

ATF_TEST_CASE_WITHOUT_HEAD(empty_input_returns_empty);
ATF_TEST_CASE_BODY(empty_input_returns_empty) {
  ATF_REQUIRE_EQ(pickLatestBackupSuffix(""), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(no_backup_snapshots_returns_empty);
ATF_TEST_CASE_BODY(no_backup_snapshots_returns_empty) {
  // Only non-backup snapshots present.
  std::string in =
    "tank/jails/web@daily-2026-01-01\n"
    "tank/jails/web@manual-test\n";
  ATF_REQUIRE_EQ(pickLatestBackupSuffix(in), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(picks_lex_greatest_backup_suffix);
ATF_TEST_CASE_BODY(picks_lex_greatest_backup_suffix) {
  // snapshotSuffix() emits UTC-ISO-8601-lex-monotone names.
  // Newest = lex-greatest.
  std::string in =
    "tank/jails/web@backup-20260101T010101Z\n"
    "tank/jails/web@backup-20260507T010101Z\n"   // newest
    "tank/jails/web@backup-20260301T010101Z\n";
  ATF_REQUIRE_EQ(pickLatestBackupSuffix(in),
                 std::string("backup-20260507T010101Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(skips_unrelated_snapshots);
ATF_TEST_CASE_BODY(skips_unrelated_snapshots) {
  // Mix of backup-* and other snapshots — only backup-* count.
  std::string in =
    "tank/jails/web@daily-2026-05-06\n"
    "tank/jails/web@backup-20260101T010101Z\n"
    "tank/jails/web@warm-template\n"
    "tank/jails/web@backup-20260601T010101Z\n";  // newest backup
  ATF_REQUIRE_EQ(pickLatestBackupSuffix(in),
                 std::string("backup-20260601T010101Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(tolerates_crlf_and_blanks);
ATF_TEST_CASE_BODY(tolerates_crlf_and_blanks) {
  std::string in =
    "\r\n"
    "tank/jails/web@backup-20260101T010101Z\r\n"
    "\n"
    "tank/jails/web@backup-20260601T010101Z\r\n";
  ATF_REQUIRE_EQ(pickLatestBackupSuffix(in),
                 std::string("backup-20260601T010101Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(skips_comments);
ATF_TEST_CASE_BODY(skips_comments) {
  // zfs list shouldn't emit comment lines, but be tolerant.
  std::string in =
    "# zfs list output preview\n"
    "tank/jails/web@backup-20260601T010101Z\n";
  ATF_REQUIRE_EQ(pickLatestBackupSuffix(in),
                 std::string("backup-20260601T010101Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(handles_recursive_descendants);
ATF_TEST_CASE_BODY(handles_recursive_descendants) {
  // `zfs list -r` includes descendant datasets — match should still
  // pick the lex-greatest @backup-* across the whole listing.
  std::string in =
    "tank/jails/web@backup-20260101T010101Z\n"
    "tank/jails/web/data@backup-20260201T010101Z\n"
    "tank/jails/web/cache@backup-20260301T010101Z\n";
  ATF_REQUIRE_EQ(pickLatestBackupSuffix(in),
                 std::string("backup-20260301T010101Z"));
}

// --- validateDatasetName ---

ATF_TEST_CASE_WITHOUT_HEAD(typical_datasets_accepted);
ATF_TEST_CASE_BODY(typical_datasets_accepted) {
  ATF_REQUIRE_EQ(validateDatasetName("tank"), std::string());
  ATF_REQUIRE_EQ(validateDatasetName("tank/jails/web-01"), std::string());
  ATF_REQUIRE_EQ(validateDatasetName("zroot/templates/firefox-warm"),
                 std::string());
  ATF_REQUIRE_EQ(validateDatasetName("pool0/sub.dataset_42"), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(rejects_traversal_and_garbage);
ATF_TEST_CASE_BODY(rejects_traversal_and_garbage) {
  ATF_REQUIRE(!validateDatasetName("").empty());
  ATF_REQUIRE(!validateDatasetName("/abs/leading").empty());
  ATF_REQUIRE(!validateDatasetName("trailing/").empty());
  ATF_REQUIRE(!validateDatasetName("tank/../etc").empty());
  ATF_REQUIRE(!validateDatasetName("tank/$(id)").empty());
  ATF_REQUIRE(!validateDatasetName("name with space").empty());
  ATF_REQUIRE(!validateDatasetName("a;reboot").empty());
}

// --- Per-user composition (0.9.9) ---

ATF_TEST_CASE_WITHOUT_HEAD(per_user_prefix_typical);
ATF_TEST_CASE_BODY(per_user_prefix_typical) {
  ATF_REQUIRE_EQ(ZfsDatasetPure::composePerUserPrefix("zroot/jails", 1000),
                 std::string("zroot/jails/1000"));
  ATF_REQUIRE_EQ(ZfsDatasetPure::composePerUserPrefix("zroot/jails", 0),
                 std::string("zroot/jails/0"));
  ATF_REQUIRE_EQ(ZfsDatasetPure::composePerUserPrefix("tank", 65534),
                 std::string("tank/65534"));
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_prefix_strips_trailing_slash);
ATF_TEST_CASE_BODY(per_user_prefix_strips_trailing_slash) {
  // Operators sometimes write the master prefix with a trailing /
  // in their config. Compose should be tolerant.
  ATF_REQUIRE_EQ(ZfsDatasetPure::composePerUserPrefix("zroot/jails/", 1000),
                 std::string("zroot/jails/1000"));
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_dataset_typical);
ATF_TEST_CASE_BODY(per_user_dataset_typical) {
  ATF_REQUIRE_EQ(ZfsDatasetPure::composePerUserDataset(
                    "zroot/jails", 1000, "web"),
                 std::string("zroot/jails/1000/web"));
  ATF_REQUIRE_EQ(ZfsDatasetPure::composePerUserDataset(
                    "tank", 0, "alpine.local"),
                 std::string("tank/0/alpine.local"));
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_dataset_isolation);
ATF_TEST_CASE_BODY(per_user_dataset_isolation) {
  // alice (1000) and bob (1001) get disjoint dataset paths even
  // for the same jail name. Same isolation invariant as the
  // runtime_paths_pure test from 0.9.8 — neither path a prefix
  // of the other.
  std::string alice = ZfsDatasetPure::composePerUserDataset(
                          "zroot/jails", 1000, "web");
  std::string bob   = ZfsDatasetPure::composePerUserDataset(
                          "zroot/jails", 1001, "web");
  ATF_REQUIRE(alice != bob);
  ATF_REQUIRE(alice.find(bob) == std::string::npos);
  ATF_REQUIRE(bob.find(alice) == std::string::npos);
}

ATF_TEST_CASE_WITHOUT_HEAD(per_user_dataset_passes_validate);
ATF_TEST_CASE_BODY(per_user_dataset_passes_validate) {
  // Composed dataset must round-trip through validateDatasetName.
  // If a future refactor introduced a // or trailing /, this
  // test catches it.
  std::string ds = ZfsDatasetPure::composePerUserDataset(
                       "zroot/jails", 1000, "alpine");
  ATF_REQUIRE_EQ(ZfsDatasetPure::validateDatasetName(ds), std::string());
  // And with a tolerated trailing slash on master:
  ds = ZfsDatasetPure::composePerUserDataset(
           "zroot/jails/", 1000, "alpine");
  ATF_REQUIRE_EQ(ZfsDatasetPure::validateDatasetName(ds), std::string());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, empty_input_returns_empty);
  ATF_ADD_TEST_CASE(tcs, no_backup_snapshots_returns_empty);
  ATF_ADD_TEST_CASE(tcs, picks_lex_greatest_backup_suffix);
  ATF_ADD_TEST_CASE(tcs, skips_unrelated_snapshots);
  ATF_ADD_TEST_CASE(tcs, tolerates_crlf_and_blanks);
  ATF_ADD_TEST_CASE(tcs, skips_comments);
  ATF_ADD_TEST_CASE(tcs, handles_recursive_descendants);
  ATF_ADD_TEST_CASE(tcs, typical_datasets_accepted);
  ATF_ADD_TEST_CASE(tcs, rejects_traversal_and_garbage);
  ATF_ADD_TEST_CASE(tcs, per_user_prefix_typical);
  ATF_ADD_TEST_CASE(tcs, per_user_prefix_strips_trailing_slash);
  ATF_ADD_TEST_CASE(tcs, per_user_dataset_typical);
  ATF_ADD_TEST_CASE(tcs, per_user_dataset_isolation);
  ATF_ADD_TEST_CASE(tcs, per_user_dataset_passes_validate);
}
