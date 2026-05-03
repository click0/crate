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

namespace {

// Resolve jail name -> ZFS dataset by looking up the live jail and
// asking Util::Fs::getZfsDataset for its path.
std::string datasetForJail(const std::string &name) {
  auto j = JailQuery::getJailByName(name);
  if (!j) ERR("jail '" << name << "' not found or not running")
  if (!Util::Fs::isOnZfs(j->path))
    ERR("jail '" << name << "' is not on ZFS — backup requires ZFS")
  return Util::Fs::getZfsDataset(j->path);
}

// Find the most-recent backup-* snapshot suffix on `dataset`, by
// querying `zfs list -H -t snapshot -o name -r <dataset>` and
// filtering. Returns the lexicographically-largest suffix, or
// empty if none found. (snapshotSuffix() is lexicographically
// monotone with time, so newest = largest.)
std::string findLatestBackupSuffix(const std::string &dataset) {
  std::string out;
  try {
    auto raw = Util::execCommandGetOutput(
      {"/sbin/zfs", "list", "-H", "-t", "snapshot",
       "-o", "name", "-r", dataset},
      "list ZFS snapshots");
    std::istringstream is(raw);
    std::string line;
    std::regex re(R"(^.+@(backup-.+)$)");
    while (std::getline(is, line)) {
      std::smatch m;
      if (std::regex_match(line, m, re)) {
        std::string suffix = m[1].str();
        if (suffix > out) out = suffix;
      }
    }
  } catch (...) {
    // No snapshots, or ZFS error — caller treats as "no prior".
  }
  return out;
}

} // anon

bool backupCrate(const Args &args) {
  if (auto e = BackupPure::validateJailName(args.backupTarget); !e.empty())
    ERR(e)
  if (auto e = BackupPure::validateOutputDir(args.backupOutputDir); !e.empty())
    ERR(e)
  if (!args.backupSince.empty())
    if (auto e = BackupPure::validateSinceName(args.backupSince); !e.empty())
      ERR(e)

  auto dataset = datasetForJail(args.backupTarget);

  BackupPure::Inputs in;
  in.sinceProvided = !args.backupSince.empty();
  in.sinceName     = args.backupSince;
  if (!in.sinceProvided && args.backupAutoIncremental) {
    auto prev = findLatestBackupSuffix(dataset);
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
