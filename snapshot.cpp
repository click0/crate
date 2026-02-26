// Copyright (C) 2019 by Yuri Victorovich. All rights reserved.

#include "args.h"
#include "util.h"
#include "err.h"

#include <rang.hpp>

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
    Util::execCommand({"zfs", "snapshot", snapName},
      CSTR("create ZFS snapshot " << snapName));
    std::cout << rang::fg::green << "Snapshot created: " << snapName << rang::style::reset << std::endl;

  } else if (subcmd == "list") {
    auto output = Util::execCommandGetOutput(
      {"zfs", "list", "-t", "snapshot", "-r", "-o", "name,creation,used,refer", ds},
      "list ZFS snapshots");
    std::cout << output;

  } else if (subcmd == "restore") {
    auto snapName = STR(ds << "@" << args.snapshotName);
    std::cerr << rang::fg::yellow << "WARNING: rolling back to " << snapName
              << " will destroy all changes since that snapshot" << rang::style::reset << std::endl;
    Util::execCommand({"zfs", "rollback", snapName},
      CSTR("rollback to ZFS snapshot " << snapName));
    std::cout << rang::fg::green << "Restored to: " << snapName << rang::style::reset << std::endl;

  } else if (subcmd == "delete") {
    auto snapName = STR(ds << "@" << args.snapshotName);
    Util::execCommand({"zfs", "destroy", snapName},
      CSTR("delete ZFS snapshot " << snapName));
    std::cout << rang::fg::green << "Deleted: " << snapName << rang::style::reset << std::endl;

  } else if (subcmd == "diff") {
    auto snap1 = STR(ds << "@" << args.snapshotName);
    std::vector<std::string> diffCmd;
    if (args.snapshotName2.empty()) {
      // diff snapshot vs current state
      diffCmd = {"zfs", "diff", snap1, ds};
    } else {
      // diff two snapshots
      diffCmd = {"zfs", "diff", snap1, STR(ds << "@" << args.snapshotName2)};
    }
    auto output = Util::execCommandGetOutput(diffCmd, "diff ZFS snapshots");
    std::cout << output;

  } else {
    ERR("unknown snapshot subcommand: " << subcmd)
  }

  return true;
}
