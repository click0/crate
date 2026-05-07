// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// Runtime side of `crate backup` / `crate restore`. Uses ZFS
// send/recv (no external compressor — ZFS already compresses
// datasets, and the stream format is dedup-friendly).
//

#include "args.h"
#include "backup_pure.h"
#include "commands.h"
#include "jail_query.h"
#include "util.h"
#include "zfs_dataset.h"
#include "err.h"

#include <rang.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>

#define ERR(msg...) ERR2("backup", msg)

// 0.8.25: datasetForJail + findLatestBackupSuffix moved to
// lib/zfs_dataset.{h,cpp} where they're shared with replicate.cpp.
// The pure parsing of `zfs list` output lives in
// lib/zfs_dataset_pure.cpp and is unit-tested.

bool backupCrate(const Args &args) {
  if (auto e = BackupPure::validateJailName(args.backupTarget); !e.empty())
    ERR(e)
  if (auto e = BackupPure::validateOutputDir(args.backupOutputDir); !e.empty())
    ERR(e)
  if (!args.backupSince.empty())
    if (auto e = BackupPure::validateSinceName(args.backupSince); !e.empty())
      ERR(e)

  auto dataset = ZfsDataset::datasetForJail(args.backupTarget, "backup");

  BackupPure::Inputs in;
  in.sinceProvided = !args.backupSince.empty();
  in.sinceName     = args.backupSince;
  if (!in.sinceProvided && args.backupAutoIncremental) {
    auto prev = ZfsDataset::findLatestBackupSuffix(dataset);
    if (!prev.empty()) {
      in.priorBackupExists      = true;
      in.priorSnapshotSuffix    = prev;
    }
  }
  auto plan = BackupPure::choosePlan(in, args.backupAutoIncremental);
  if (plan.kind == BackupPure::Plan::Kind::Error)
    ERR(plan.reason)

  auto suffix = BackupPure::snapshotSuffix(::time(nullptr));
  // `zfs snapshot <ds>@<suffix>`
  Util::execCommand(BackupPure::buildSnapshotArgv(dataset, suffix),
                    "zfs snapshot");

  auto streamFile = args.backupOutputDir + "/" +
    BackupPure::streamFilename(args.backupTarget, suffix,
                               plan.kind == BackupPure::Plan::Kind::Incremental
                                 ? plan.sinceSuffix
                                 : "");

  std::cerr << rang::fg::cyan << "backup: "
            << (plan.kind == BackupPure::Plan::Kind::Incremental ? "incremental" : "full")
            << " stream → " << streamFile
            << rang::style::reset << std::endl;

  // Pipe `zfs send ...` stdout into <streamFile>.
  auto sendArgv = BackupPure::buildSendArgv(
    dataset, suffix,
    plan.kind == BackupPure::Plan::Kind::Incremental ? plan.sinceSuffix : "");
  Util::execPipeline({sendArgv}, "zfs send to file", "", streamFile);

  // Report file size for operator confirmation.
  struct stat st{};
  if (::stat(streamFile.c_str(), &st) == 0) {
    double mb = (double)st.st_size / (1024.0 * 1024.0);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%.1f MB", mb);
    std::cout << rang::fg::green << "backup: wrote " << streamFile
              << " (" << buf << ")" << rang::style::reset << std::endl;
  }
  return true;
}

bool restoreCrate(const Args &args) {
  if (args.restoreFile.empty())
    ERR("restore requires <stream-file>")
  if (args.restoreDataset.empty())
    ERR("restore requires --to <pool/jails/name>")
  if (!Util::Fs::fileExists(args.restoreFile))
    ERR("stream file not found: " << args.restoreFile)

  std::cerr << rang::fg::cyan << "restore: zfs recv ← " << args.restoreFile
            << " into " << args.restoreDataset
            << rang::style::reset << std::endl;
  // `zfs recv <destDataset>` reads stdin from the file.
  Util::execPipeline({BackupPure::buildRecvArgv(args.restoreDataset)},
                     "zfs recv from file", args.restoreFile, "");

  std::cout << rang::fg::green << "restore: " << args.restoreDataset
            << " recovered from " << args.restoreFile
            << rang::style::reset << std::endl;
  return true;
}
