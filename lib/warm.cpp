// Copyright (C) 2026 by Vladyslav V. Prodan <github.com/click0>. All rights reserved.

//
// `crate template warm <jail> --output <dataset>` — capture the
// on-disk state of a running jail as a ZFS clone the operator can
// later pass to `crate run --warm-base <dataset>` (planned for
// 0.7.6) to skip cold-create work like pkg install or profile
// init. See lib/warm_pure.h for the scope discussion (memory
// snapshot is intentionally NOT in scope — that needs CRIU/bhyve).
//

#include "args.h"
#include "commands.h"
#include "jail_query.h"
#include "util.h"
#include "warm_pure.h"
#include "err.h"

#include <rang.hpp>

#include <ctime>
#include <iostream>
#include <string>

#define ERR(msg...) ERR2("template warm", msg)

bool templateWarmCommand(const Args &args) {
  if (args.warmTarget.empty())
    ERR("the 'template warm' command requires a jail name (positional arg)")
  if (args.warmOutputDataset.empty())
    ERR("the 'template warm' command requires --output <dataset>")
  if (auto e = WarmPure::validateTemplateDataset(args.warmOutputDataset);
      !e.empty())
    ERR("--output: " << e)

  auto jail = JailQuery::getJailByName(args.warmTarget);
  if (!jail) ERR("jail '" << args.warmTarget << "' not found or not running")
  if (!Util::Fs::isOnZfs(jail->path))
    ERR("jail '" << args.warmTarget << "' is not on ZFS — warm templates require ZFS")
  auto sourceDataset = Util::Fs::getZfsDataset(jail->path);

  auto suffix = WarmPure::warmSnapshotSuffix(::time(nullptr));

  std::cerr << rang::fg::cyan
            << "template warm: snapshotting " << sourceDataset
            << "@" << suffix
            << rang::style::reset << std::endl;
  Util::execCommand(WarmPure::buildSnapshotArgv(sourceDataset, suffix),
                    "zfs snapshot");

  std::cerr << rang::fg::cyan
            << "template warm: cloning into " << args.warmOutputDataset
            << rang::style::reset << std::endl;
  Util::execCommand(
    WarmPure::buildCloneArgv(sourceDataset, suffix, args.warmOutputDataset),
    "zfs clone");

  // Optional promotion — only when the operator asks for it.
  // Default keeps the clone graph intact so retention pruning of
  // old warm snapshots is independent of template usage.
  if (args.warmPromote) {
    std::cerr << rang::fg::cyan
              << "template warm: promoting clone to break parent link"
              << rang::style::reset << std::endl;
    Util::execCommand(
      WarmPure::buildPromoteArgv(args.warmOutputDataset),
      "zfs promote");
  }

  std::cout << rang::fg::green
            << "template warm: " << args.warmTarget
            << " -> " << args.warmOutputDataset
            << " (snapshot " << suffix << ")"
            << rang::style::reset << std::endl;
  return true;
}
