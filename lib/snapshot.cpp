// Copyright (C) 2019 by Yuri Victorovich <github.com/yurivict>. All rights reserved.
// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

#include "args.h"
#include "autoname_pure.h"
#include "snapshot_pure.h"
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

// autoSnapshotName moved to lib/autoname_pure.cpp (AutoNamePure::snapshotName).
static inline std::string autoSnapshotName() { return AutoNamePure::snapshotName(); }

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
    std::vector<SnapshotPure::Entry> entries;
    entries.reserve(snaps.size());
    for (auto &s : snaps)
      entries.push_back({s.name, s.used, s.refer, s.creation});
    SnapshotPure::renderTable(std::cout, ds, entries);

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
