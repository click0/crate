// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "zfs_ops.h"
#include "pathnames.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

#include <unistd.h>

#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

#define ERR(msg...) \
  ERR2("snapshot", msg)

static std::string autoSnapshotName() {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::ostringstream ss;
  ss << std::put_time(std::gmtime(&time), "%Y%m%dT%H%M%S");
  return ss.str();
}

bool snapshotCrate(const Args &args) {
  auto &ds = args.snapshotDataset;
  auto &subcmd = args.snapshotSubcmd;

  if (subcmd == "create") {
    auto name = args.snapshotName.empty() ? autoSnapshotName() : args.snapshotName;
    auto snapName = STR(ds << "@" << name);
    ZfsOps::snapshot(snapName);
    std::cout << rang::fg::green << "Snapshot created: " << snapName << rang::style::reset << std::endl;

  } else if (subcmd == "list") {
    auto snaps = ZfsOps::listSnapshots(ds);
    if (snaps.empty()) {
      std::cout << "No snapshots found for " << ds << std::endl;
    } else {
      std::cout << "NAME" << std::string(40, ' ') << "CREATION" << std::string(16, ' ')
                << "USED" << std::string(8, ' ') << "REFER" << std::endl;
      for (auto &s : snaps)
        std::cout << s.name << std::string(std::max(1, 44 - (int)s.name.size()), ' ')
                  << s.creation << std::string(std::max(1, 24 - (int)s.creation.size()), ' ')
                  << s.used << std::string(std::max(1, 12 - (int)s.used.size()), ' ')
                  << s.refer << std::endl;
    }

  } else if (subcmd == "restore") {
    auto snapName = STR(ds << "@" << args.snapshotName);
    std::cerr << rang::fg::yellow << "WARNING: rolling back to " << snapName
              << " will destroy all changes since that snapshot" << rang::style::reset << std::endl;
    ZfsOps::rollback(snapName);
    std::cout << rang::fg::green << "Restored to: " << snapName << rang::style::reset << std::endl;

  } else if (subcmd == "delete") {
    auto snapName = STR(ds << "@" << args.snapshotName);
    ZfsOps::destroy(snapName);
    std::cout << rang::fg::green << "Deleted: " << snapName << rang::style::reset << std::endl;

  } else if (subcmd == "diff") {
    auto snap1 = STR(ds << "@" << args.snapshotName);
    auto snap2 = args.snapshotName2.empty() ? ds : STR(ds << "@" << args.snapshotName2);
    ZfsOps::diff(snap1, snap2, STDOUT_FILENO);

  } else {
    ERR("unknown snapshot subcommand: " << subcmd)
  }

  return true;
}
