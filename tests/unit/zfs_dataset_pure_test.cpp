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
}
