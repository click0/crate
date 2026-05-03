// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "backup_pure.h"

#include <atf-c++.hpp>

#include <string>

using BackupPure::Inputs;
using BackupPure::Plan;
using BackupPure::RetentionPolicy;
using BackupPure::buildDestroySnapshotArgv;
using BackupPure::buildRecvArgv;
using BackupPure::buildSendArgv;
using BackupPure::buildSnapshotArgv;
using BackupPure::choosePlan;
using BackupPure::fullSnapshotName;
using BackupPure::parseRetention;
using BackupPure::snapshotSuffix;
using BackupPure::streamFilename;
using BackupPure::validateJailName;
using BackupPure::validateOutputDir;
using BackupPure::validateSinceName;

// --- snapshotSuffix / fullSnapshotName / streamFilename ---

ATF_TEST_CASE_WITHOUT_HEAD(suffix_unix_epoch_is_iso8601_utc);
ATF_TEST_CASE_BODY(suffix_unix_epoch_is_iso8601_utc) {
  ATF_REQUIRE_EQ(snapshotSuffix(0),
                 std::string("backup-1970-01-01T00:00:00Z"));
  ATF_REQUIRE_EQ(snapshotSuffix(946684800),
                 std::string("backup-2000-01-01T00:00:00Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(suffix_lexicographic_matches_chronological);
ATF_TEST_CASE_BODY(suffix_lexicographic_matches_chronological) {
  // Critical property: cron-driven backups must sort
  // chronologically by name so retention pruning is trivial.
  ATF_REQUIRE(snapshotSuffix(1000000000) < snapshotSuffix(2000000000));
  ATF_REQUIRE(snapshotSuffix(0)          < snapshotSuffix(1));
}

ATF_TEST_CASE_WITHOUT_HEAD(full_snapshot_name);
ATF_TEST_CASE_BODY(full_snapshot_name) {
  ATF_REQUIRE_EQ(fullSnapshotName("pool/jails/foo", "backup-2000-01-01T00:00:00Z"),
                 std::string("pool/jails/foo@backup-2000-01-01T00:00:00Z"));
}

ATF_TEST_CASE_WITHOUT_HEAD(stream_filename_full_vs_incremental);
ATF_TEST_CASE_BODY(stream_filename_full_vs_incremental) {
  ATF_REQUIRE_EQ(streamFilename("foo", "backup-CURR", ""),
                 std::string("foo-backup-CURR.zstream"));
  ATF_REQUIRE_EQ(streamFilename("foo", "backup-CURR", "backup-PREV"),
                 std::string("foo-backup-CURR.inc-from-backup-PREV.zstream"));
}

// --- validateJailName ---

ATF_TEST_CASE_WITHOUT_HEAD(jail_name_typical_accepted);
ATF_TEST_CASE_BODY(jail_name_typical_accepted) {
  ATF_REQUIRE_EQ(validateJailName("postgres-prod"), std::string());
  ATF_REQUIRE_EQ(validateJailName("v0.7.0"),        std::string());
  ATF_REQUIRE_EQ(validateJailName(std::string(64, 'a')), std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(jail_name_invalid_rejected);
ATF_TEST_CASE_BODY(jail_name_invalid_rejected) {
  ATF_REQUIRE(!validateJailName("").empty());
  ATF_REQUIRE(!validateJailName(".").empty());
  ATF_REQUIRE(!validateJailName("..").empty());
  ATF_REQUIRE(!validateJailName(std::string(65, 'a')).empty());
  ATF_REQUIRE(!validateJailName("foo/bar").empty());
  ATF_REQUIRE(!validateJailName("foo;rm").empty());
}

// --- validateOutputDir ---

ATF_TEST_CASE_WITHOUT_HEAD(outdir_typical_accepted);
ATF_TEST_CASE_BODY(outdir_typical_accepted) {
  ATF_REQUIRE_EQ(validateOutputDir("/var/backups/crate"), std::string());
  ATF_REQUIRE_EQ(validateOutputDir("/srv/zfs-backups"),    std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(outdir_invalid_rejected);
ATF_TEST_CASE_BODY(outdir_invalid_rejected) {
  ATF_REQUIRE(!validateOutputDir("").empty());
  ATF_REQUIRE(!validateOutputDir("relative/path").empty());
  ATF_REQUIRE(!validateOutputDir("/var/../etc/passwd").empty());
  ATF_REQUIRE(!validateOutputDir("/var/backups;rm").empty());
  ATF_REQUIRE(!validateOutputDir("/var/back$up").empty());
  ATF_REQUIRE(!validateOutputDir("/var/back\\up").empty());
}

// --- validateSinceName ---

ATF_TEST_CASE_WITHOUT_HEAD(since_typical_accepted);
ATF_TEST_CASE_BODY(since_typical_accepted) {
  ATF_REQUIRE_EQ(validateSinceName("backup-2024-10-27T03:33:20Z"), std::string());
  ATF_REQUIRE_EQ(validateSinceName("backup-2025+01-01"),           std::string());
}

ATF_TEST_CASE_WITHOUT_HEAD(since_invalid_rejected);
ATF_TEST_CASE_BODY(since_invalid_rejected) {
  ATF_REQUIRE(!validateSinceName("").empty());
  ATF_REQUIRE(!validateSinceName("foo@bar").empty());
  ATF_REQUIRE(!validateSinceName("foo/bar").empty());
  ATF_REQUIRE(!validateSinceName("foo bar").empty());
  ATF_REQUIRE(!validateSinceName("foo;rm").empty());
}

// --- argv builders ---

ATF_TEST_CASE_WITHOUT_HEAD(snapshot_argv_shape);
ATF_TEST_CASE_BODY(snapshot_argv_shape) {
  auto v = buildSnapshotArgv("pool/jails/foo", "backup-NOW");
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[0], std::string("/sbin/zfs"));
  ATF_REQUIRE_EQ(v[1], std::string("snapshot"));
  ATF_REQUIRE_EQ(v[2], std::string("pool/jails/foo@backup-NOW"));
}

ATF_TEST_CASE_WITHOUT_HEAD(send_argv_full_stream);
ATF_TEST_CASE_BODY(send_argv_full_stream) {
  auto v = buildSendArgv("pool/jails/foo", "backup-NOW", "");
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[0], std::string("/sbin/zfs"));
  ATF_REQUIRE_EQ(v[1], std::string("send"));
  ATF_REQUIRE_EQ(v[2], std::string("pool/jails/foo@backup-NOW"));
}

ATF_TEST_CASE_WITHOUT_HEAD(send_argv_incremental_stream);
ATF_TEST_CASE_BODY(send_argv_incremental_stream) {
  auto v = buildSendArgv("pool/jails/foo", "backup-NOW", "backup-PREV");
  ATF_REQUIRE_EQ(v.size(), (size_t)5);
  ATF_REQUIRE_EQ(v[1], std::string("send"));
  ATF_REQUIRE_EQ(v[2], std::string("-i"));
  ATF_REQUIRE_EQ(v[3], std::string("pool/jails/foo@backup-PREV"));
  ATF_REQUIRE_EQ(v[4], std::string("pool/jails/foo@backup-NOW"));
}

ATF_TEST_CASE_WITHOUT_HEAD(recv_argv_shape);
ATF_TEST_CASE_BODY(recv_argv_shape) {
  auto v = buildRecvArgv("pool/jails/restored");
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[1], std::string("recv"));
  ATF_REQUIRE_EQ(v[2], std::string("pool/jails/restored"));
}

ATF_TEST_CASE_WITHOUT_HEAD(destroy_snapshot_argv_shape);
ATF_TEST_CASE_BODY(destroy_snapshot_argv_shape) {
  auto v = buildDestroySnapshotArgv("pool/jails/foo", "backup-OLD");
  ATF_REQUIRE_EQ(v.size(), (size_t)3);
  ATF_REQUIRE_EQ(v[1], std::string("destroy"));
  ATF_REQUIRE_EQ(v[2], std::string("pool/jails/foo@backup-OLD"));
}

// --- parseRetention ---

ATF_TEST_CASE_WITHOUT_HEAD(retention_typical_spec);
ATF_TEST_CASE_BODY(retention_typical_spec) {
  RetentionPolicy p;
  ATF_REQUIRE_EQ(parseRetention("hourly=24,daily=7,weekly=4,monthly=12", p),
                 std::string());
  ATF_REQUIRE_EQ(p.hourly,  (unsigned)24);
  ATF_REQUIRE_EQ(p.daily,   (unsigned)7);
  ATF_REQUIRE_EQ(p.weekly,  (unsigned)4);
  ATF_REQUIRE_EQ(p.monthly, (unsigned)12);
}

ATF_TEST_CASE_WITHOUT_HEAD(retention_partial_spec);
ATF_TEST_CASE_BODY(retention_partial_spec) {
  RetentionPolicy p;
  ATF_REQUIRE_EQ(parseRetention("daily=7", p), std::string());
  ATF_REQUIRE_EQ(p.daily,   (unsigned)7);
  ATF_REQUIRE_EQ(p.hourly,  (unsigned)0);
  ATF_REQUIRE_EQ(p.weekly,  (unsigned)0);
  ATF_REQUIRE_EQ(p.monthly, (unsigned)0);
}

ATF_TEST_CASE_WITHOUT_HEAD(retention_invalid_spec_rejected);
ATF_TEST_CASE_BODY(retention_invalid_spec_rejected) {
  RetentionPolicy p;
  ATF_REQUIRE(!parseRetention("", p).empty());
  ATF_REQUIRE(!parseRetention("daily", p).empty());           // missing =value
  ATF_REQUIRE(!parseRetention("daily=", p).empty());          // empty value
  ATF_REQUIRE(!parseRetention("daily=abc", p).empty());       // non-numeric
  ATF_REQUIRE(!parseRetention("yearly=1", p).empty());        // unknown key
  ATF_REQUIRE(!parseRetention("daily=-5", p).empty());        // negative
}

// --- choosePlan ---

ATF_TEST_CASE_WITHOUT_HEAD(plan_default_is_full);
ATF_TEST_CASE_BODY(plan_default_is_full) {
  Inputs in;
  in.sinceProvided = false;
  in.priorBackupExists = false;
  auto p = choosePlan(in, false);
  ATF_REQUIRE(p.kind == Plan::Kind::Full);
  ATF_REQUIRE(p.sinceSuffix.empty());
}

ATF_TEST_CASE_WITHOUT_HEAD(plan_since_takes_priority);
ATF_TEST_CASE_BODY(plan_since_takes_priority) {
  // Operator-supplied --since trumps any auto-detection logic.
  Inputs in;
  in.sinceProvided = true;
  in.sinceName = "backup-OLD";
  in.priorBackupExists = true;
  in.priorSnapshotSuffix = "backup-LATEST-AUTO";
  auto p = choosePlan(in, true);
  ATF_REQUIRE(p.kind == Plan::Kind::Incremental);
  ATF_REQUIRE_EQ(p.sinceSuffix, std::string("backup-OLD"));
}

ATF_TEST_CASE_WITHOUT_HEAD(plan_auto_incremental_uses_prior);
ATF_TEST_CASE_BODY(plan_auto_incremental_uses_prior) {
  Inputs in;
  in.priorBackupExists = true;
  in.priorSnapshotSuffix = "backup-LATEST";
  auto p = choosePlan(in, /*autoIncremental*/true);
  ATF_REQUIRE(p.kind == Plan::Kind::Incremental);
  ATF_REQUIRE_EQ(p.sinceSuffix, std::string("backup-LATEST"));
}

ATF_TEST_CASE_WITHOUT_HEAD(plan_auto_incremental_falls_back_to_full);
ATF_TEST_CASE_BODY(plan_auto_incremental_falls_back_to_full) {
  // --auto-incremental but no prior snapshot → first run, must be full.
  Inputs in;
  in.priorBackupExists = false;
  auto p = choosePlan(in, /*autoIncremental*/true);
  ATF_REQUIRE(p.kind == Plan::Kind::Full);
}

ATF_TEST_CASE_WITHOUT_HEAD(plan_since_empty_value_is_error);
ATF_TEST_CASE_BODY(plan_since_empty_value_is_error) {
  Inputs in;
  in.sinceProvided = true;
  in.sinceName = "";
  auto p = choosePlan(in, false);
  ATF_REQUIRE(p.kind == Plan::Kind::Error);
  ATF_REQUIRE(!p.reason.empty());
}

ATF_INIT_TEST_CASES(tcs) {
  ATF_ADD_TEST_CASE(tcs, suffix_unix_epoch_is_iso8601_utc);
  ATF_ADD_TEST_CASE(tcs, suffix_lexicographic_matches_chronological);
  ATF_ADD_TEST_CASE(tcs, full_snapshot_name);
  ATF_ADD_TEST_CASE(tcs, stream_filename_full_vs_incremental);
  ATF_ADD_TEST_CASE(tcs, jail_name_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, jail_name_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, outdir_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, outdir_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, since_typical_accepted);
  ATF_ADD_TEST_CASE(tcs, since_invalid_rejected);
  ATF_ADD_TEST_CASE(tcs, snapshot_argv_shape);
  ATF_ADD_TEST_CASE(tcs, send_argv_full_stream);
  ATF_ADD_TEST_CASE(tcs, send_argv_incremental_stream);
  ATF_ADD_TEST_CASE(tcs, recv_argv_shape);
  ATF_ADD_TEST_CASE(tcs, destroy_snapshot_argv_shape);
  ATF_ADD_TEST_CASE(tcs, retention_typical_spec);
  ATF_ADD_TEST_CASE(tcs, retention_partial_spec);
  ATF_ADD_TEST_CASE(tcs, retention_invalid_spec_rejected);
  ATF_ADD_TEST_CASE(tcs, plan_default_is_full);
  ATF_ADD_TEST_CASE(tcs, plan_since_takes_priority);
  ATF_ADD_TEST_CASE(tcs, plan_auto_incremental_uses_prior);
  ATF_ADD_TEST_CASE(tcs, plan_auto_incremental_falls_back_to_full);
  ATF_ADD_TEST_CASE(tcs, plan_since_empty_value_is_error);
}
