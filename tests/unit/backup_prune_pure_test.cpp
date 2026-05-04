// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "backup_prune_pure.h"
#include "backup_pure.h"

#include <atf-c++.hpp>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

using BackupPrunePure::StreamFile;
using BackupPrunePure::PruneDecision;
using BackupPrunePure::dayBucket;
using BackupPrunePure::decidePrune;
using BackupPrunePure::explainKeeps;
using BackupPrunePure::hourBucket;
using BackupPrunePure::monthBucket;
using BackupPrunePure::parseStreamFilename;
using BackupPrunePure::parseSuffixEpoch;
using BackupPrunePure::validateDir;
using BackupPrunePure::validateJailFilter;
using BackupPrunePure::weekBucket;
using BackupPure::RetentionPolicy;

static bool contains(const std::vector<std::string> &v, const std::string &s) {
  return std::find(v.begin(), v.end(), s) != v.end();
}

// ----------------------------------------------------------------------
// validateDir
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(dir_accepts_absolute);
ATF_TEST_CASE_BODY(dir_accepts_absolute) {
  ATF_REQUIRE_EQ(validateDir("/var/backups/crate"), std::string());
  ATF_REQUIRE_EQ(validateDir("/"),                  std::string());
  ATF_REQUIRE_EQ(validateDir("/mnt/usb/zstreams"),  std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(dir_rejects_bad);
ATF_TEST_CASE_BODY(dir_rejects_bad) {
  ATF_REQUIRE(!validateDir("").empty());
  ATF_REQUIRE(!validateDir("relative/path").empty());
  ATF_REQUIRE(!validateDir("/var/back ups").empty() == false ||
              validateDir("/var/back ups") == "");  // space ok (no shell meta)
  ATF_REQUIRE(!validateDir("/var/../etc").empty());
  ATF_REQUIRE(!validateDir("/var/`pwd`").empty());
  ATF_REQUIRE(!validateDir("/var/$IFS").empty());
  ATF_REQUIRE(!validateDir("/var/foo;rm").empty());
  ATF_REQUIRE(!validateDir("/var/glob*").empty());
}

// ----------------------------------------------------------------------
// validateJailFilter
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(jail_filter);
ATF_TEST_CASE_BODY(jail_filter) {
  ATF_REQUIRE_EQ(validateJailFilter(""),         std::string());  // empty == no filter
  ATF_REQUIRE_EQ(validateJailFilter("postgres"), std::string());
  ATF_REQUIRE_EQ(validateJailFilter("dev-pg.1"), std::string());
  ATF_REQUIRE(!validateJailFilter("a/b").empty());
  ATF_REQUIRE(!validateJailFilter("a;b").empty());
  ATF_REQUIRE(!validateJailFilter("a@b").empty());
}

// ----------------------------------------------------------------------
// parseSuffixEpoch — round-trips with BackupPure::snapshotSuffix
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(epoch_known_dates);
ATF_TEST_CASE_BODY(epoch_known_dates) {
  // 1970-01-01T00:00:00Z is rejected (epoch 0 is our "parse failed"
  // sentinel — nobody names backups that)
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-1970-01-01T00:00:00Z"), 0L);
  // Some exact dates from `date -u -d '...' +%s`:
  // 2024-10-27T03:33:20Z = 1730000000
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2024-10-27T03:33:20Z"), 1730000000L);
  // 2026-01-01T00:00:00Z = 1767225600
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2026-01-01T00:00:00Z"), 1767225600L);
  // 2000-03-01T00:00:00Z = 951868800 (post-leap-day cross-check for civil-to-epoch)
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2000-03-01T00:00:00Z"), 951868800L);
}

ATF_TEST_CASE_WITHOUT_HEAD(epoch_round_trip);
ATF_TEST_CASE_BODY(epoch_round_trip) {
  // BackupPure::snapshotSuffix(epoch) produces our canonical form.
  // parseSuffixEpoch must invert it for any reasonable epoch.
  for (long e : {1735689600L,    // 2025-01-01T00:00:00Z
                 1767225600L,    // 2026-01-01T00:00:00Z
                 1798761600L,    // 2027-01-01T00:00:00Z
                 4102444800L}) { // 2100-01-01T00:00:00Z
    auto s = BackupPure::snapshotSuffix(e);
    ATF_REQUIRE_EQ(parseSuffixEpoch(s), e);
  }
}

ATF_TEST_CASE_WITHOUT_HEAD(epoch_rejects_malformed);
ATF_TEST_CASE_BODY(epoch_rejects_malformed) {
  ATF_REQUIRE_EQ(parseSuffixEpoch(""), 0L);
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-"), 0L);
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2026-13-01T00:00:00Z"), 0L);  // bad month
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2026-01-32T00:00:00Z"), 0L);  // bad day
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2026-01-01T25:00:00Z"), 0L);  // bad hour
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2026-01-01T00:60:00Z"), 0L);  // bad minute
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2026-01-01T00:00:00 "), 0L);  // missing Z
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-2026/01/01T00:00:00Z"), 0L);  // bad separators
  ATF_REQUIRE_EQ(parseSuffixEpoch("snap-2026-01-01T00:00:00Z"),   0L);  // wrong prefix
  ATF_REQUIRE_EQ(parseSuffixEpoch("backup-202X-01-01T00:00:00Z"), 0L);  // non-digit
}

// ----------------------------------------------------------------------
// parseStreamFilename
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(filename_full);
ATF_TEST_CASE_BODY(filename_full) {
  StreamFile sf;
  std::string err;
  ATF_REQUIRE(parseStreamFilename(
    "myjail-backup-2026-01-01T12:00:00Z.zstream", sf, err));
  ATF_REQUIRE_EQ(err, std::string());
  ATF_REQUIRE_EQ(sf.jailName, std::string("myjail"));
  ATF_REQUIRE_EQ(sf.suffix,   std::string("backup-2026-01-01T12:00:00Z"));
  ATF_REQUIRE_EQ(sf.incFromSuffix, std::string());
  ATF_REQUIRE(sf.unixEpoch > 0);
}

ATF_TEST_CASE_WITHOUT_HEAD(filename_incremental);
ATF_TEST_CASE_BODY(filename_incremental) {
  StreamFile sf;
  std::string err;
  ATF_REQUIRE(parseStreamFilename(
    "pg-backup-2026-01-02T00:00:00Z.inc-from-backup-2026-01-01T00:00:00Z.zstream",
    sf, err));
  ATF_REQUIRE_EQ(err, std::string());
  ATF_REQUIRE_EQ(sf.jailName,      std::string("pg"));
  ATF_REQUIRE_EQ(sf.suffix,        std::string("backup-2026-01-02T00:00:00Z"));
  ATF_REQUIRE_EQ(sf.incFromSuffix, std::string("backup-2026-01-01T00:00:00Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(filename_jail_with_dashes);
ATF_TEST_CASE_BODY(filename_jail_with_dashes) {
  // Jail names can contain '-'. Make sure rfind("-backup-") picks the
  // RIGHTMOST one — otherwise "dev-postgres" would be parsed as "dev"
  // with jail "postgres-backup-...". We use rfind to fix that.
  StreamFile sf;
  std::string err;
  ATF_REQUIRE(parseStreamFilename(
    "dev-postgres-backup-2026-01-01T00:00:00Z.zstream", sf, err));
  ATF_REQUIRE_EQ(sf.jailName, std::string("dev-postgres"));
}

ATF_TEST_CASE_WITHOUT_HEAD(filename_rejects);
ATF_TEST_CASE_BODY(filename_rejects) {
  StreamFile sf;
  std::string err;
  // Other tools' files in the same dir.
  ATF_REQUIRE(!parseStreamFilename("README.md",     sf, err));
  ATF_REQUIRE(!parseStreamFilename("backup.tar.gz", sf, err));
  ATF_REQUIRE(!parseStreamFilename(".DS_Store",     sf, err));
  // Looks close but not quite.
  ATF_REQUIRE(!parseStreamFilename("foo-backup-2026-01-01T00:00:00Z.txt", sf, err));
  ATF_REQUIRE(!parseStreamFilename("just.zstream",  sf, err));
  ATF_REQUIRE(!parseStreamFilename("foo.zstream",   sf, err));
  // Jail name empty (filename starts with -backup-).
  ATF_REQUIRE(!parseStreamFilename("-backup-2026-01-01T00:00:00Z.zstream", sf, err));
  // Bad inc-from suffix.
  ATF_REQUIRE(!parseStreamFilename(
    "p-backup-2026-01-02T00:00:00Z.inc-from-garbage.zstream", sf, err));
}

// ----------------------------------------------------------------------
// Bucket key derivations
// ----------------------------------------------------------------------

ATF_TEST_CASE_WITHOUT_HEAD(buckets_distinguish);
ATF_TEST_CASE_BODY(buckets_distinguish) {
  // Two timestamps in same hour -> same hour-bucket
  long a = parseSuffixEpoch("backup-2026-01-01T00:10:00Z");
  long b = parseSuffixEpoch("backup-2026-01-01T00:50:00Z");
  ATF_REQUIRE_EQ(hourBucket(a), hourBucket(b));
  ATF_REQUIRE_EQ(dayBucket(a),  dayBucket(b));
  // Different hour -> different hour-bucket but same day
  long c = parseSuffixEpoch("backup-2026-01-01T05:00:00Z");
  ATF_REQUIRE(hourBucket(a) != hourBucket(c));
  ATF_REQUIRE_EQ(dayBucket(a), dayBucket(c));
  // Different day -> different day, week, month
  long d = parseSuffixEpoch("backup-2026-02-15T00:00:00Z");
  ATF_REQUIRE(dayBucket(a) != dayBucket(d));
  ATF_REQUIRE(monthBucket(a) != monthBucket(d));
}

ATF_TEST_CASE_WITHOUT_HEAD(buckets_month_calendar_aligned);
ATF_TEST_CASE_BODY(buckets_month_calendar_aligned) {
  // All backups in Feb 2026 share a monthBucket.
  long e1 = parseSuffixEpoch("backup-2026-02-01T00:00:00Z");
  long e2 = parseSuffixEpoch("backup-2026-02-15T00:00:00Z");
  long e3 = parseSuffixEpoch("backup-2026-02-28T23:59:59Z");
  ATF_REQUIRE_EQ(monthBucket(e1), monthBucket(e2));
  ATF_REQUIRE_EQ(monthBucket(e2), monthBucket(e3));
  // March 1 lands in next bucket.
  long e4 = parseSuffixEpoch("backup-2026-03-01T00:00:00Z");
  ATF_REQUIRE(monthBucket(e3) != monthBucket(e4));
}

// ----------------------------------------------------------------------
// decidePrune
// ----------------------------------------------------------------------

// Helper: build a StreamFile by parsing its filename. Crashes the test
// (via ATF_REQUIRE) if parsing fails — keeps fixture noise low.
static StreamFile mkFile(const std::string &basename) {
  StreamFile sf;
  std::string err;
  ATF_REQUIRE(parseStreamFilename(basename, sf, err));
  return sf;
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_daily_keeps_newest_per_day);
ATF_TEST_CASE_BODY(prune_daily_keeps_newest_per_day) {
  std::vector<StreamFile> files = {
    // Two on day 1 -> keep newest
    mkFile("j-backup-2026-01-01T03:00:00Z.zstream"),
    mkFile("j-backup-2026-01-01T22:00:00Z.zstream"),
    // One per day for next 5 days
    mkFile("j-backup-2026-01-02T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-03T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-04T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-05T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-06T00:00:00Z.zstream"),
  };
  RetentionPolicy p; p.daily = 3;
  auto d = decidePrune(files, p, /*deleteOrphans=*/false);

  // Newest 3 distinct days = Jan 6, Jan 5, Jan 4 — kept.
  ATF_REQUIRE(contains(d.keep, "j-backup-2026-01-06T00:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.keep, "j-backup-2026-01-05T00:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.keep, "j-backup-2026-01-04T00:00:00Z.zstream"));
  // Older fulls + the early-day-1 sibling -> removed.
  ATF_REQUIRE(contains(d.remove, "j-backup-2026-01-03T00:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.remove, "j-backup-2026-01-02T00:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.remove, "j-backup-2026-01-01T03:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.remove, "j-backup-2026-01-01T22:00:00Z.zstream"));
  ATF_REQUIRE_EQ(d.keep.size(), 3u);
  ATF_REQUIRE_EQ(d.remove.size(), 4u);
  ATF_REQUIRE_EQ(d.orphans.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_union_across_buckets);
ATF_TEST_CASE_BODY(prune_union_across_buckets) {
  // Daily=2 + monthly=2 => keep newest of each month, plus newest 2 days.
  std::vector<StreamFile> files = {
    mkFile("p-backup-2026-01-15T00:00:00Z.zstream"),  // Jan
    mkFile("p-backup-2026-02-01T00:00:00Z.zstream"),  // Feb (older of month)
    mkFile("p-backup-2026-02-28T00:00:00Z.zstream"),  // Feb (newest of month)
    mkFile("p-backup-2026-03-15T00:00:00Z.zstream"),  // Mar
    mkFile("p-backup-2026-03-16T00:00:00Z.zstream"),  // Mar (newest day)
  };
  RetentionPolicy p; p.daily = 2; p.monthly = 2;
  auto d = decidePrune(files, p, false);

  // daily=2 picks Mar-16 + Mar-15 (newest 2 days)
  // monthly=2 picks Mar-16 + Feb-28 (newest of Mar + Feb)
  // union: {Mar-16, Mar-15, Feb-28}
  ATF_REQUIRE_EQ(d.keep.size(), 3u);
  ATF_REQUIRE(contains(d.keep, "p-backup-2026-03-16T00:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.keep, "p-backup-2026-03-15T00:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.keep, "p-backup-2026-02-28T00:00:00Z.zstream"));
  // Removed: Jan-15 + Feb-01 (older monthly siblings, no daily slot).
  ATF_REQUIRE_EQ(d.remove.size(), 2u);
  ATF_REQUIRE(contains(d.remove, "p-backup-2026-01-15T00:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.remove, "p-backup-2026-02-01T00:00:00Z.zstream"));
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_empty_policy_keeps_nothing);
ATF_TEST_CASE_BODY(prune_empty_policy_keeps_nothing) {
  // No bucket types set -> all fulls go to remove.
  std::vector<StreamFile> files = {
    mkFile("j-backup-2026-01-01T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-02T00:00:00Z.zstream"),
  };
  RetentionPolicy p;  // all zeros
  auto d = decidePrune(files, p, false);
  ATF_REQUIRE_EQ(d.keep.size(), 0u);
  ATF_REQUIRE_EQ(d.remove.size(), 2u);
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_incremental_kept_with_base);
ATF_TEST_CASE_BODY(prune_incremental_kept_with_base) {
  std::vector<StreamFile> files = {
    mkFile("j-backup-2026-01-01T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-02T00:00:00Z.inc-from-backup-2026-01-01T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-03T00:00:00Z.inc-from-backup-2026-01-01T00:00:00Z.zstream"),
  };
  RetentionPolicy p; p.daily = 5;
  auto d = decidePrune(files, p, false);
  // Base full kept -> all 3 stay.
  ATF_REQUIRE_EQ(d.keep.size(), 3u);
  ATF_REQUIRE_EQ(d.remove.size(), 0u);
  ATF_REQUIRE_EQ(d.orphans.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_incremental_orphaned_when_base_dropped);
ATF_TEST_CASE_BODY(prune_incremental_orphaned_when_base_dropped) {
  std::vector<StreamFile> files = {
    mkFile("j-backup-2026-01-01T00:00:00Z.zstream"),                                       // old full -> drop
    mkFile("j-backup-2026-01-02T00:00:00Z.inc-from-backup-2026-01-01T00:00:00Z.zstream"), // depends on dropped
    mkFile("j-backup-2026-02-01T00:00:00Z.zstream"),                                       // new full
  };
  RetentionPolicy p; p.daily = 1;  // only newest full survives
  auto d = decidePrune(files, p, /*deleteOrphans=*/false);
  ATF_REQUIRE(contains(d.keep, "j-backup-2026-02-01T00:00:00Z.zstream"));
  ATF_REQUIRE(contains(d.remove, "j-backup-2026-01-01T00:00:00Z.zstream"));
  // Orphan: not in remove (safe default), in orphans list.
  ATF_REQUIRE(contains(d.orphans,
    "j-backup-2026-01-02T00:00:00Z.inc-from-backup-2026-01-01T00:00:00Z.zstream"));
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_orphans_deleted_with_flag);
ATF_TEST_CASE_BODY(prune_orphans_deleted_with_flag) {
  std::vector<StreamFile> files = {
    mkFile("j-backup-2026-01-01T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-02T00:00:00Z.inc-from-backup-2026-01-01T00:00:00Z.zstream"),
    mkFile("j-backup-2026-02-01T00:00:00Z.zstream"),
  };
  RetentionPolicy p; p.daily = 1;
  auto d = decidePrune(files, p, /*deleteOrphans=*/true);
  ATF_REQUIRE(contains(d.remove,
    "j-backup-2026-01-02T00:00:00Z.inc-from-backup-2026-01-01T00:00:00Z.zstream"));
  ATF_REQUIRE_EQ(d.orphans.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_lists_disjoint);
ATF_TEST_CASE_BODY(prune_lists_disjoint) {
  // No file should ever appear in more than one of {keep, remove, orphans}.
  std::vector<StreamFile> files = {
    mkFile("j-backup-2026-01-01T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-02T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-03T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-04T00:00:00Z.inc-from-backup-2026-01-01T00:00:00Z.zstream"),
  };
  RetentionPolicy p; p.daily = 2; p.weekly = 1;
  auto d = decidePrune(files, p, false);
  std::set<std::string> all;
  for (const auto &n : d.keep)    ATF_REQUIRE(all.insert(n).second);
  for (const auto &n : d.remove)  ATF_REQUIRE(all.insert(n).second);
  for (const auto &n : d.orphans) ATF_REQUIRE(all.insert(n).second);
  ATF_REQUIRE_EQ(all.size(), files.size());
}

ATF_TEST_CASE_WITHOUT_HEAD(explain_keeps_assigns_reasons);
ATF_TEST_CASE_BODY(explain_keeps_assigns_reasons) {
  std::vector<StreamFile> files = {
    mkFile("j-backup-2026-01-01T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-02T00:00:00Z.zstream"),
    mkFile("j-backup-2026-02-01T00:00:00Z.zstream"),
  };
  RetentionPolicy p; p.daily = 2; p.monthly = 2;
  auto explained = explainKeeps(files, p);
  // Should mention daily:1, daily:2, monthly:1, monthly:2 reasons across
  // up to 3 distinct files.
  bool sawDaily1 = false, sawDaily2 = false;
  bool sawMonthly1 = false, sawMonthly2 = false;
  for (const auto &kr : explained) {
    if (kr.reason == "daily:1")   sawDaily1 = true;
    if (kr.reason == "daily:2")   sawDaily2 = true;
    if (kr.reason == "monthly:1") sawMonthly1 = true;
    if (kr.reason == "monthly:2") sawMonthly2 = true;
  }
  ATF_REQUIRE(sawDaily1);
  ATF_REQUIRE(sawDaily2);
  ATF_REQUIRE(sawMonthly1);
  ATF_REQUIRE(sawMonthly2);
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_handles_empty_input);
ATF_TEST_CASE_BODY(prune_handles_empty_input) {
  std::vector<StreamFile> files;
  RetentionPolicy p; p.daily = 7;
  auto d = decidePrune(files, p, false);
  ATF_REQUIRE_EQ(d.keep.size(), 0u);
  ATF_REQUIRE_EQ(d.remove.size(), 0u);
  ATF_REQUIRE_EQ(d.orphans.size(), 0u);
}

ATF_TEST_CASE_WITHOUT_HEAD(prune_more_buckets_than_files);
ATF_TEST_CASE_BODY(prune_more_buckets_than_files) {
  // Asking for daily=100 when only 2 files exist -> all kept.
  std::vector<StreamFile> files = {
    mkFile("j-backup-2026-01-01T00:00:00Z.zstream"),
    mkFile("j-backup-2026-01-02T00:00:00Z.zstream"),
  };
  RetentionPolicy p; p.daily = 100;
  auto d = decidePrune(files, p, false);
  ATF_REQUIRE_EQ(d.keep.size(), 2u);
  ATF_REQUIRE_EQ(d.remove.size(), 0u);
}

// ----------------------------------------------------------------------
// Test entrypoint
// ----------------------------------------------------------------------

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, dir_accepts_absolute);
  ATF_ADD_TEST_CASE(tcs, dir_rejects_bad);
  ATF_ADD_TEST_CASE(tcs, jail_filter);
  ATF_ADD_TEST_CASE(tcs, epoch_known_dates);
  ATF_ADD_TEST_CASE(tcs, epoch_round_trip);
  ATF_ADD_TEST_CASE(tcs, epoch_rejects_malformed);
  ATF_ADD_TEST_CASE(tcs, filename_full);
  ATF_ADD_TEST_CASE(tcs, filename_incremental);
  ATF_ADD_TEST_CASE(tcs, filename_jail_with_dashes);
  ATF_ADD_TEST_CASE(tcs, filename_rejects);
  ATF_ADD_TEST_CASE(tcs, buckets_distinguish);
  ATF_ADD_TEST_CASE(tcs, buckets_month_calendar_aligned);
  ATF_ADD_TEST_CASE(tcs, prune_daily_keeps_newest_per_day);
  ATF_ADD_TEST_CASE(tcs, prune_union_across_buckets);
  ATF_ADD_TEST_CASE(tcs, prune_empty_policy_keeps_nothing);
  ATF_ADD_TEST_CASE(tcs, prune_incremental_kept_with_base);
  ATF_ADD_TEST_CASE(tcs, prune_incremental_orphaned_when_base_dropped);
  ATF_ADD_TEST_CASE(tcs, prune_orphans_deleted_with_flag);
  ATF_ADD_TEST_CASE(tcs, prune_lists_disjoint);
  ATF_ADD_TEST_CASE(tcs, explain_keeps_assigns_reasons);
  ATF_ADD_TEST_CASE(tcs, prune_handles_empty_input);
  ATF_ADD_TEST_CASE(tcs, prune_more_buckets_than_files);
}
